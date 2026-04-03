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

## Strategy Extensibility Tiers

ndn-rs provides three tiers of strategy extensibility, each with different tradeoffs:

| Tier | Mechanism | Use Case | Hot Path Cost |
|------|-----------|----------|---------------|
| Built-in | `impl Strategy` in Rust | Production strategies | ~100ns (sync fast path) |
| Composed | `ComposedStrategy` with `StrategyFilter` chain | Cross-layer filtering without forking base strategies | +~50ns per filter |
| Scripted | WASM module via `WasmStrategy` (`ndn-strategy-wasm`) | Research prototyping, field hot-patching | ~1-5us |

### Which approach should I use?

- **Modifying forwarding logic** (new algorithm, new heuristic) → Built-in Rust strategy or WASM strategy
- **Filtering/reordering existing decisions** (prefer faces with good RSSI, avoid congested faces) → `ComposedStrategy` + `StrategyFilter`
- **Rapid prototyping without recompiling** → WASM strategy
- **Routing protocol / topology discovery** → External app via AppFace/ShmFace (see below)

## Cross-Layer Context Enrichment

Strategies receive cross-layer data through `StrategyContext::extensions`, a type-keyed `AnyMap`. Data sources register as `ContextEnricher` implementations via `EngineBuilder::context_enricher()`.

```rust
// In a strategy:
fn decide(&self, ctx: &StrategyContext) -> Option<SmallVec<[ForwardingAction; 2]>> {
    if let Some(snapshot) = ctx.extensions.get::<LinkQualitySnapshot>() {
        for lq in &snapshot.per_face {
            // lq.rssi_dbm, lq.retransmit_rate, lq.observed_rtt_ms, lq.observed_tput
        }
    }
    // ...
}
```

### Adding a new data source

1. Define a DTO struct in `ndn-strategy::cross_layer` (e.g. `LocationSnapshot`).
2. Implement `ContextEnricher` — read your data source, build the DTO, insert it into the `AnyMap`.
3. Register via `EngineBuilder::context_enricher(Arc::new(YourEnricher { ... }))`.

No changes to `StrategyContext`, `StrategyStage`, or existing enrichers are needed.

## Strategy Composition

`ComposedStrategy` wraps an inner strategy (via `ErasedStrategy`) and applies a chain of `StrategyFilter` implementations to its output.

```rust
let composed = ComposedStrategy::new(
    Name::from("/localhost/nfd/strategy/best-route-rssi"),
    Arc::new(BestRouteStrategy::new()) as Arc<dyn ErasedStrategy>,
    vec![Arc::new(RssiFilter::new(-60))],
);
```

The `RssiFilter` removes faces with RSSI below -60 dBm from `Forward` actions. If all faces are filtered out, the filter drops the `Forward` action entirely and the strategy falls through to the next action (e.g. `Nack`).

### Writing a `StrategyFilter`

```rust
impl StrategyFilter for MyFilter {
    fn name(&self) -> &str { "my-filter" }

    fn filter(
        &self,
        ctx: &StrategyContext,
        actions: SmallVec<[ForwardingAction; 2]>,
    ) -> SmallVec<[ForwardingAction; 2]> {
        // Inspect ctx.extensions, reorder/remove faces, return modified actions
    }
}
```

## WASM Strategies (`ndn-strategy-wasm`)

Hot-load strategy logic from compiled WASM modules without recompiling the router.

### Host-Guest ABI

WASM modules import functions from the `"ndn"` namespace:

| Function | Signature | Description |
|----------|-----------|-------------|
| `get_in_face` | `() -> u32` | Face the Interest arrived on |
| `get_nexthop_count` | `() -> u32` | Number of FIB nexthops |
| `get_nexthop` | `(index, out_face_id, out_cost) -> u32` | Read nexthop into guest memory |
| `get_rtt_ns` | `(face_id) -> f64` | RTT in ns (-1.0 if unavailable) |
| `get_rssi` | `(face_id) -> i32` | RSSI in dBm (-128 if unavailable) |
| `get_satisfaction` | `(face_id) -> f32` | Satisfaction rate (-1.0 if unavailable) |
| `forward` | `(face_ids_ptr, count)` | Forward to specified faces |
| `nack` | `(reason)` | Send Nack (0=NoRoute, 1=Duplicate, 2=Congestion, 3=NotYet) |
| `suppress` | `()` | Suppress the Interest |

WASM modules must export `on_interest()` (and optionally `on_nack()`).

### Performance safeguards

- **Fuel limit**: 10,000 instructions per invocation (~50us worst case)
- **Memory limit**: configurable, default 1 MB per module
- **No I/O**: modules cannot access filesystem, network, or clock

### Example (Rust compiled to WASM)

```rust
// strategy.rs — compile with `cargo build --target wasm32-unknown-unknown`
extern "C" {
    fn get_nexthop_count() -> u32;
    fn get_nexthop(index: u32, out_face_id: *mut u32, out_cost: *mut u32) -> u32;
    fn forward(face_ids_ptr: *const u32, count: u32);
    fn nack(reason: u32);
}

#[no_mangle]
pub extern "C" fn on_interest() {
    unsafe {
        let count = get_nexthop_count();
        if count == 0 { nack(0); return; }
        let mut best_face: u32 = 0;
        let mut best_cost: u32 = u32::MAX;
        for i in 0..count {
            let (mut fid, mut cost) = (0u32, 0u32);
            get_nexthop(i, &mut fid, &mut cost);
            if cost < best_cost { best_face = fid; best_cost = cost; }
        }
        forward(&best_face, 1);
    }
}
```

## External Strategy Apps — When NOT to Embed

Not everything belongs in the forwarder. Some routing logic is better as an external app connected via AppFace/ShmFace:

| Embed in Forwarder (Strategy) | External App (AppFace/ShmFace) |
|-------------------------------|-------------------------------|
| Per-packet forwarding decisions | Routing protocol convergence (NLSR) |
| Sub-millisecond latency required | Periodic route computation (seconds) |
| Reads FIB/PIT/measurements | Writes FIB routes via management |
| Stateless or small per-prefix state | Large state (routing tables, LSDBs) |
| Cross-layer filtering (RSSI, RTT) | Topology discovery, name mapping |

**Key principle:** Strategies answer "which face for THIS Interest?" Routing apps answer "what should the FIB look like?" The FIB is the interface between them.

## Autonomous Research Control

The recommended architecture for wireless NDN research:

```
nl80211 task ──→ ContextEnricher ──→ StrategyContext::extensions
                                         ↓
                                    Strategy / ComposedStrategy + Filters

pipeline ──→ FlowObserverStage ──→ mpsc ──→ analysis task
                                              ↓
                                         InfluxDB / file / Python

analysis task ──→ management commands ──→ Arc<FaceTable> / Arc<NameTrie<FibEntry>>
```

The nl80211 task, analysis task, and strategy are all Tokio tasks in the same process. They communicate with the engine through `Arc` handles — no IPC, microsecond latency between observation and action. Critical for wireless where link conditions change on millisecond timescales.

**Caution**: Experimental code runs in the same address space as the forwarder. Panics are caught by `JoinSet`; deadlocks are not prevented by Rust. For production, move the controller to a separate process. For research, in-process is the right tradeoff.
