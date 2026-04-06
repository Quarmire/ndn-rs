# Implementing a Strategy

This guide covers how to write a custom forwarding strategy for ndn-rs. Strategies are pure decision functions -- they read state through an immutable `StrategyContext` and return `ForwardingAction` values telling the pipeline what to do.

## The Strategy Trait

The trait lives in `ndn-strategy` (`crates/ndn-strategy/src/strategy.rs`):

```rust
pub trait Strategy: Send + Sync + 'static {
    /// Canonical name identifying this strategy (e.g. /localhost/nfd/strategy/my-strategy).
    fn name(&self) -> &Name;

    /// Synchronous fast path. Return Some(actions) to skip the async overhead.
    fn decide(&self, _ctx: &StrategyContext) -> Option<SmallVec<[ForwardingAction; 2]>> {
        None // default: fall through to async path
    }

    /// Called when an Interest needs a forwarding decision.
    fn after_receive_interest(
        &self,
        ctx: &StrategyContext,
    ) -> impl Future<Output = SmallVec<[ForwardingAction; 2]>> + Send;

    /// Called when Data arrives and needs forwarding.
    fn after_receive_data(
        &self,
        ctx: &StrategyContext,
    ) -> impl Future<Output = SmallVec<[ForwardingAction; 2]>> + Send;

    /// Called when a PIT entry times out. Default: Suppress.
    fn on_interest_timeout(
        &self,
        _ctx: &StrategyContext,
    ) -> impl Future<Output = ForwardingAction> + Send {
        async { ForwardingAction::Suppress }
    }

    /// Called when a Nack arrives. Default: Suppress.
    fn on_nack(
        &self,
        _ctx: &StrategyContext,
        _reason: NackReason,
    ) -> impl Future<Output = ForwardingAction> + Send {
        async { ForwardingAction::Suppress }
    }
}
```

### Synchronous vs. async path

Most strategies make decisions synchronously -- they just look at the FIB entry and measurements. Override `decide()` to return `Some(actions)` in this case. The engine's `ErasedStrategy` wrapper skips the `Box::pin` heap allocation when `decide()` returns `Some`.

Only use the async `after_receive_interest()` path if you genuinely need to `await` something (e.g., a remote lookup or a timer for delayed probing).

> **⚠️ Important:** Strategies are **immutable** -- `StrategyContext` provides only shared (`&`) references to engine state. A strategy cannot modify the FIB, PIT, or CS. If your strategy needs mutable state (e.g., a packet counter or a round-robin index), use `AtomicU64` or other atomic types within the strategy struct itself. Do not use `Mutex` unless you must protect complex state -- atomics avoid lock contention on the hot path.

## StrategyContext

The context provides a read-only view of engine state:

```rust
pub struct StrategyContext<'a> {
    /// The name being forwarded.
    pub name: &'a Arc<Name>,
    /// The face the packet arrived on.
    pub in_face: FaceId,
    /// FIB entry for the longest matching prefix (None = no route).
    pub fib_entry: Option<&'a FibEntry>,
    /// PIT token for the current Interest.
    pub pit_token: Option<PitToken>,
    /// EWMA RTT and satisfaction measurements per (prefix, face).
    pub measurements: &'a MeasurementsTable,
    /// Cross-layer enrichment data (radio metrics, flow stats, etc.).
    pub extensions: &'a AnyMap,
}
```

The `FibEntry` contains a `Vec<FibNexthop>` where each nexthop has a `face_id` and `cost`. Use `fib_entry.nexthops_excluding(ctx.in_face)` for split-horizon filtering.

## ForwardingAction Variants

```rust
pub enum ForwardingAction {
    /// Forward to these faces immediately.
    Forward(SmallVec<[FaceId; 4]>),
    /// Forward after a delay (enables probe-and-fallback).
    ForwardAfter { faces: SmallVec<[FaceId; 4]>, delay: Duration },
    /// Send a Nack back to the requester.
    Nack(NackReason),
    /// Suppress -- do not forward (loop or policy decision).
    Suppress,
}
```

A strategy can return multiple actions in its `SmallVec`. For example, a probing strategy might return a primary `Forward` and a `ForwardAfter` probe simultaneously.

`NackReason` variants: `NoRoute`, `Duplicate`, `Congestion`, `NotYet`.

## MeasurementsTable

The `MeasurementsTable` tracks per-(prefix, face) performance data:

- **EWMA RTT** (`EwmaRtt`): smoothed RTT in nanoseconds, variance, sample count. Updated on every Data arrival.
- **Satisfaction rate**: EWMA of Interest satisfaction (0.0--1.0). Updated on Data arrival and PIT timeout.

Access it from the strategy context:

```rust
if let Some(entry) = ctx.measurements.get(ctx.name) {
    for (face_id, rtt) in &entry.rtt_per_face {
        tracing::debug!(%face_id, srtt_ms = rtt.srtt_ns / 1e6, "RTT measurement");
    }
    tracing::debug!(rate = entry.satisfaction_rate, "satisfaction");
}
```

The table is updated automatically by the `MeasurementsUpdateStage` in the Data pipeline. Strategies only read from it.

> **🔧 Implementation note:** The `MeasurementsTable` is the primary mechanism for strategies to maintain state *without* being stateful themselves. Instead of tracking RTT in the strategy struct, read it from the measurements table -- it is updated automatically on every satisfied Interest. This keeps strategies pure and composable: swapping a strategy at a prefix preserves the accumulated measurements.

## Example: Round-Robin Load Balancer

This strategy distributes Interests across FIB nexthops using round-robin selection:

```rust
use std::sync::atomic::{AtomicU64, Ordering};
use smallvec::{SmallVec, smallvec};
use ndn_packet::Name;
use ndn_pipeline::{ForwardingAction, NackReason};
use ndn_strategy::{Strategy, StrategyContext};

pub struct RoundRobinStrategy {
    name: Name,
    counter: AtomicU64,
}

impl RoundRobinStrategy {
    pub fn new() -> Self {
        Self {
            name: "/localhost/nfd/strategy/round-robin".parse().unwrap(),
            counter: AtomicU64::new(0),
        }
    }
}

impl Strategy for RoundRobinStrategy {
    fn name(&self) -> &Name {
        &self.name
    }

    fn decide(&self, ctx: &StrategyContext) -> Option<SmallVec<[ForwardingAction; 2]>> {
        let Some(fib) = ctx.fib_entry else {
            return Some(smallvec![ForwardingAction::Nack(NackReason::NoRoute)]);
        };

        let nexthops = fib.nexthops_excluding(ctx.in_face);
        if nexthops.is_empty() {
            return Some(smallvec![ForwardingAction::Nack(NackReason::NoRoute)]);
        }

        let idx = self.counter.fetch_add(1, Ordering::Relaxed) as usize % nexthops.len();
        Some(smallvec![ForwardingAction::Forward(
            smallvec![nexthops[idx].face_id]
        )])
    }

    async fn after_receive_interest(
        &self,
        ctx: &StrategyContext<'_>,
    ) -> SmallVec<[ForwardingAction; 2]> {
        // Unreachable when decide() always returns Some.
        self.decide(ctx).unwrap()
    }

    async fn after_receive_data(
        &self,
        _ctx: &StrategyContext<'_>,
    ) -> SmallVec<[ForwardingAction; 2]> {
        // Fan-back to PIT in-record faces is handled by the engine.
        SmallVec::new()
    }
}
```

A complete runnable example is in `examples/strategy-custom/`.

## Registration via StrategyTable

### Using EngineBuilder (recommended)

The simplest way to register a strategy:

```rust
let (_engine, shutdown) = EngineBuilder::new(EngineConfig::default())
    .strategy(RoundRobinStrategy::new())
    .build()
    .await?;
```

This registers the strategy at its `name()` prefix. Interests whose names match that prefix (via longest-prefix match) will use this strategy.

### Direct StrategyTable access

For dynamic registration at runtime, use the `StrategyTable` directly:

```rust
use ndn_store::StrategyTable;

let table: StrategyTable<dyn Strategy> = StrategyTable::new();

// Register for a specific prefix.
let prefix: Name = "/app/video".parse().unwrap();
table.insert(&prefix, Arc::new(RoundRobinStrategy::new()));

// Register as the default (root prefix).
table.insert(&Name::root(), Arc::new(BestRouteStrategy::new()));
```

The `StrategyTable` is a `NameTrie` that performs longest-prefix match, just like the FIB. The most specific matching strategy wins. If no strategy matches, the engine uses the strategy registered at the root prefix.

## Design Guidelines

> **📝 Note:** Following these guidelines ensures your strategy works correctly with hot-swap, WASM loading, and strategy composition via `StrategyFilter`. Violating them (e.g., holding `Arc` references to engine internals) may cause subtle bugs when strategies are replaced at runtime.

1. **Keep strategies pure.** A strategy should not mutate global state. It reads from `StrategyContext` and returns actions. Side effects belong in pipeline stages.

2. **Prefer `decide()` over `after_receive_interest()`.** The synchronous path avoids a heap allocation per packet.

3. **Always handle the no-FIB case.** Return `Nack(NackReason::NoRoute)` when `ctx.fib_entry` is `None`.

4. **Always apply split-horizon.** Use `fib_entry.nexthops_excluding(ctx.in_face)` to avoid sending an Interest back out the face it arrived on.

5. **Use measurements for adaptive strategies.** The `MeasurementsTable` provides RTT and satisfaction data per face. An RTT-aware strategy might prefer the face with the lowest smoothed RTT.

6. **Return empty `SmallVec` from `after_receive_data()`.** Data fan-back to PIT consumers is handled by the engine. Only override this if your strategy needs to intercept Data (rare).

7. **Name your strategy following NFD convention.** Use `/localhost/nfd/strategy/<name>` so NFD management tools can discover and display it.

## Built-in Strategies

| Strategy | Behavior |
|----------|----------|
| `BestRouteStrategy` | Forward on the lowest-cost FIB nexthop (default) |
| `MulticastStrategy` | Forward on all FIB nexthops (flood) |

See `crates/ndn-strategy/src/` for the implementations.
