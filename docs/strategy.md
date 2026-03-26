# Forwarding Strategy

## `Strategy` Trait

```rust
pub trait Strategy: Send + Sync + 'static {
    fn name(&self) -> &Name;

    async fn after_receive_interest(
        &self, ctx: &mut StrategyContext
    ) -> SmallVec<[ForwardingAction; 2]>;

    async fn after_receive_data(
        &self, ctx: &mut StrategyContext
    ) -> SmallVec<[ForwardingAction; 2]>;

    // optional hooks — default to no-ops:
    async fn interest_timeout(&self, ctx: &mut StrategyContext) -> ForwardingAction {
        ForwardingAction::Suppress
    }
    async fn after_receive_nack(&self, ctx: &mut StrategyContext) -> ForwardingAction {
        ForwardingAction::Suppress
    }
}
```

Two required methods, not one per event. Simple strategies implement only what they need. Returning `SmallVec<[ForwardingAction; 2]>` handles the common case of one action with no allocation, and two actions (primary + probe) still inline.

## `StrategyContext`

```rust
pub struct StrategyContext<'a> {
    pub name:        &'a Name,
    pub face_id:     FaceId,
    pub fib_entry:   Option<&'a FibEntry>,
    pub pit_entry:   &'a PitEntry,
    pub measurements: &'a MeasurementsEntry,
    // mutable strategy scratch pad:
    pub state:       &'a mut StrategyState,
}
```

The strategy does **not** own the PIT entry, FIB entry, or face table. It gets immutable references through `StrategyContext`. Only `state` is mutable — the strategy's scratch pad.

This is a deliberate constraint: strategies cannot modify forwarding tables directly, preventing a class of bugs in NFD where strategies mutated state in ways the pipeline did not expect.

`state` is keyed by **name prefix**, not PIT token. Adaptive strategies like ASF track RTT measurements and face rankings across many Interests for the same prefix, not within a single Interest's lifetime.

## `BestRouteStrategy`

```rust
impl Strategy for BestRouteStrategy {
    async fn after_receive_interest(
        &self, ctx: &mut StrategyContext
    ) -> SmallVec<[ForwardingAction; 2]> {
        let nexthops = ctx.fib_entry
            .map(|e| e.nexthops_excluding(ctx.face_id))
            .unwrap_or_default();
        match nexthops.first() {
            Some(nh) => smallvec![ForwardingAction::Forward(smallvec![nh.face_id])],
            None     => smallvec![ForwardingAction::Nack(NackReason::NoRoute)],
        }
    }

    async fn after_receive_data(
        &self, ctx: &mut StrategyContext
    ) -> SmallVec<[ForwardingAction; 2]> {
        let faces = ctx.pit_entry.in_record_faces().collect();
        smallvec![ForwardingAction::Forward(faces)]
    }
}
```

## `ForwardAfter` — Probe and Fallback

Strategies like ASF forward on a primary face immediately and probe a secondary face after a delay. The pipeline runner schedules the delayed send via a spawned Tokio timer:

```rust
// ASF strategy: forward on best face immediately, probe second face after measured RTT
smallvec![
    ForwardingAction::Forward(smallvec![best_face]),
    ForwardingAction::ForwardAfter { faces: smallvec![probe_face], delay: measured_rtt },
]
```

The re-check before the delayed send is critical — Data may arrive during the delay window and the Interest will already be satisfied.

## `MeasurementsTable`

Separate from `StrategyState`. Holds read-mostly EWMA statistics updated by the pipeline on every Data arrival:

```rust
pub struct MeasurementsEntry {
    pub rtt_per_face:      HashMap<FaceId, EwmaRtt>,
    pub satisfaction_rate: f32,   // EWMA over last N interests
    pub last_updated:      u64,
}

pub struct EwmaRtt {
    pub srtt_ns:   u64,
    pub rttvar_ns: u64,
    pub samples:   u32,
}
```

Kept in a separate `DashMap<Name, MeasurementsEntry>` so RTT updates don't contend with strategy state reads.

**Updated before strategy call** on the Data pipeline side (see `docs/pipeline.md`) — the strategy reads freshly updated RTT.

## `StrategyTable`

A second instance of `NameTrie<Arc<dyn Strategy>>`. Uses `Arc<dyn Strategy>` so multiple name prefixes can share the same strategy instance without copying. Combined FIB + strategy lookup does two trie walks but shares the same `Name` component iteration.

## `MultiRadioStrategy` (Research Extension)

For wireless research, augment the strategy with `Arc<DashMap<FaceId, LinkMetrics>>` populated by a nl80211 task:

```rust
pub struct MultiRadioStrategy {
    radio_table:  Arc<DashMap<FaceId, LinkMetrics>>,
    flow_table:   Arc<DashMap<Name, FlowEntry>>,
}

pub struct FlowEntry {
    prefix:         Name,
    preferred_face: FaceId,
    observed_tput:  f32,    // EWMA bytes/sec
    observed_rtt:   f32,    // EWMA ms
    last_updated:   u64,
}
```

The strategy populates `FlowEntry` on every Data arrival. Established flows for `/video/stream` are sent directly to the preferred face without consulting the FIB. The FIB is the fallback for names with no flow history.

A `Probe` channel — `mpsc::Sender<Interest>` — allows strategies to initiate autonomous Interests (for probing, measurement) that feed back into the pipeline as if arriving on a synthetic internal face. The strategy remains a pure decision function; the channel is the controlled escape hatch.

## Autonomous Research Control

The recommended architecture for wireless NDN research:

```
nl80211 task ──→ Arc<DashMap<FaceId, LinkMetrics>> ──→ WirelessStrategy (Point A)

pipeline ──→ FlowObserverStage ──→ mpsc ──→ analysis task
                                              ↓
                                         InfluxDB / file / Python

analysis task ──→ management commands ──→ Arc<FaceTable> / Arc<NameTrie<FibEntry>>
```

The nl80211 task, analysis task, and strategy are all Tokio tasks in the same process. They communicate with the engine through `Arc` handles — no IPC, microsecond latency between observation and action. Critical for wireless where link conditions change on millisecond timescales.

**Caution**: Experimental code runs in the same address space as the forwarder. Panics are caught by `JoinSet`; deadlocks are not prevented by Rust. For production, move the controller to a separate process. For research, in-process is the right tradeoff.
