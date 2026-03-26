# Pipeline Design

## `PipelineStage` Trait

```rust
pub trait PipelineStage: Send + Sync + 'static {
    async fn process(&self, ctx: PacketContext) -> Result<Action, DropReason>;
}

// For dynamic dispatch (runtime-configurable stages):
pub type BoxedStage = Box<dyn Fn(PacketContext) -> BoxFuture<'static, Result<Action>> + Send + Sync>;
```

Native `async fn` in traits (stable since Rust 1.75) gives clean ergonomics and zero allocation when the pipeline is monomorphized — which it is for built-in stages. The `BoxedStage` alias pays the allocation cost only for stages that genuinely need dynamic dispatch (e.g., custom research stages loaded at startup).

## `Action` Enum

```rust
pub enum Action {
    Continue(PacketContext),
    Send(PacketContext, SmallVec<[FaceId; 4]>),
    Satisfy(Data),
    Drop(DropReason),
    Nack(NackReason),
}
```

The runner loop drives dispatch — no `next` closure threading:

```rust
async fn run_pipeline(stages: &[BoxedStage], mut ctx: PacketContext) -> Result<()> {
    for stage in stages {
        match stage.process(ctx).await? {
            Action::Continue(next_ctx) => ctx = next_ctx,
            Action::Send(ctx, faces)   => return dispatch_to_faces(ctx, faces).await,
            Action::Satisfy(data)      => return satisfy_pit(data).await,
            Action::Drop(reason)       => return Ok(log_drop(reason)),
            Action::Nack(reason)       => return send_nack(reason).await,
        }
    }
    Ok(())
}
```

This is cleaner than Tower's nested-future model for NDN because NDN pipelines are **linear with early exits**, not bidirectional HTTP middleware.

## `ForwardingAction` Enum

Returned by strategies, translated to `Action` by `StrategyStage`:

```rust
pub enum ForwardingAction {
    Forward(SmallVec<[FaceId; 2]>),
    ForwardAfter { faces: SmallVec<[FaceId; 2]>, delay: Duration },
    Nack(NackReason),
    Suppress,
}
```

`ForwardAfter` enables probe-and-fallback without the strategy spawning its own timers. `after_receive_interest` may return `SmallVec<[ForwardingAction; 2]>` for strategies that issue a primary forward and a probe simultaneously.

## Interest Pipeline Stage Sequence

```
1. FaceCheckStage      — validate face_id is in FaceTable
2. TlvDecodeStage      — Raw → Interest/Data/Nack; sets ctx.name
3. CsLookupStage       — CS hit → Action::Satisfy (skips PIT entirely)
4. PitCheckStage       — loop suppression (nonce check), PIT insert/aggregate
5. StrategyStage       — FIB + strategy lookup → ForwardingAction → Action
6. DispatchStage       — sends Interest on selected faces
```

**CS before PIT**: A CS hit lets you skip PIT insertion entirely. You never record the Interest if you can satisfy it immediately.

## Data Pipeline Stage Sequence

```
1. FaceCheckStage      — validate face_id
2. TlvDecodeStage      — Raw → Data
3. PitMatchStage       — find matching PIT entries; no match → drop
4. MeasurementsStage   — update EWMA RTT per face before strategy call
5. StrategyStage       — strategy.after_receive_data() → ForwardingAction
6. CsInsertStage       — insert Data into CS (after strategy decision)
7. DispatchStage       — fan Data back to PIT InRecord faces
```

**Measurements before strategy**: The strategy's `after_receive_data` can read the freshly updated RTT sample to make its forwarding decision. Updating after would leave the strategy one sample behind.

**CS insert after strategy**: The strategy decides whether to forward first; cached copy is available for immediately following Interests but the strategy still controls forwarding.

## StrategyStage — Integration Point

`StrategyStage` holds `Arc<StrategyTable>` and calls the per-prefix strategy:

```rust
impl PipelineStage for StrategyStage {
    async fn process(&self, ctx: PacketContext) -> Result<Action> {
        let strategy = self.strategy_table.lpm(&ctx.name);
        let mut sctx = StrategyContext::from(&ctx, &self.fib, &self.pit, ...);
        let actions = match &ctx.packet {
            DecodedPacket::Interest(_) => strategy.after_receive_interest(&mut sctx).await,
            DecodedPacket::Data(_)     => strategy.after_receive_data(&mut sctx).await,
            _ => return Ok(Action::Continue(ctx)),
        };
        forwarding_actions_to_pipeline_action(actions, ctx, &self.face_table, &self.pit)
    }
}
```

## `ForwardAfter` — Delayed Probe Scheduling

`ForwardAfter` is translated to a spawned Tokio timer in `StrategyStage`:

```rust
ForwardingAction::ForwardAfter { faces, delay } => {
    let token = ctx.pit_token;
    tokio::spawn(async move {
        tokio::time::sleep(delay).await;
        // re-check PIT — only send if entry still unsatisfied
        if pit.get(&token).map(|e| !e.is_satisfied).unwrap_or(false) {
            for face_id in faces {
                if let Some(f) = face_table.get(&face_id) {
                    let _ = f.send(ctx.raw_bytes.clone()).await;
                }
            }
        }
    });
    Action::Continue(ctx) // primary forwarding handled via Forward action
}
```

## Timeout Handling

PIT expiry is handled outside the pipeline. When the expiry wheel fires a `PitToken`, a dedicated task calls `strategy.interest_timeout(&mut sctx)` directly — bypassing the full pipeline. The strategy returns `ForwardingAction::Forward` to retry on another face or `ForwardingAction::Suppress` to let the entry die.

## Hot-Swappable Strategies

`StrategyTable` stores `Arc<dyn Strategy>`. Updating a strategy at runtime writes a new `Arc` to the trie under a write lock. In-flight packets hold their own `Arc` clone and finish with the old strategy naturally. No in-flight packet disruption.

## Pipeline Stage Sequence is Fixed at Build Time

```rust
fn build_interest_pipeline(engine: &EngineInner) -> Vec<BoxedStage> {
    vec![
        Box::new(FaceCheckStage::new(engine.face_table.clone())),
        Box::new(TlvDecodeStage),
        Box::new(CsLookupStage::new(engine.cs.clone())),
        Box::new(PitCheckStage::new(engine.pit.clone())),
        Box::new(StrategyStage::new(...)),
        Box::new(DispatchStage::new(engine.face_table.clone())),
    ]
}
```

Fixed at build time (not runtime-configurable) means the compiler can inline and optimize the dispatch loop. It also eliminates bugs from misconfigured stage ordering.

## Research Extension Point: Custom Pipeline Stages

Insert a `FlowObserverStage` early in both pipelines for research data collection:

```rust
pub struct FlowObserverStage {
    tx:           mpsc::Sender<FlowEvent>,
    sampling_rate: f32,  // randomly drop events when < 1.0 to avoid becoming bottleneck
}

impl PipelineStage for FlowObserverStage {
    async fn process(&self, ctx: PacketContext) -> Result<Action> {
        if should_sample(self.sampling_rate) {
            let _ = self.tx.try_send(FlowEvent::from(&ctx)); // non-blocking, drops if receiver behind
        }
        Ok(Action::Continue(ctx))
    }
}
```

`try_send` is a single atomic operation when the receiver is keeping up. When the receiver falls behind, events are dropped rather than blocking the forwarding pipeline — the right tradeoff for research logging.
