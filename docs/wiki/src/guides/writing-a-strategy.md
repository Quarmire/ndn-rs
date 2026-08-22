# Writing a strategy

A forwarding strategy decides which face an Interest goes out on,
when it retransmits, and how it reacts to Nacks and timeouts. This
guide walks through writing a third-party strategy, registering it,
and pinning it under a prefix.

The trait surface is [Extend tier → Strategy](../api/extend.md#strategy);
the contract lives at `crates/forwarding/ndn-strategy/src/strategy.rs:56`.

## When to write a strategy

- Your protocol needs a forwarding rule the built-ins don't cover
  (e.g. weighted round-robin, latency-aware, energy-aware).
- You're researching strategy behaviour and want a measurement fixture.
- You're building a sandboxed strategy (WASM); see
  `ndn-ext/crates/strategies/ndn-strategy-wasm/`.

For everything else the built-ins (`BestRouteStrategy`,
`MulticastStrategy`, `ComposedStrategy`) are usually correct.

## The decision model

A `Strategy` does **not** send Interests or mutate forwarding tables.
It is a pure decision function: each method reads an immutable
a `StrategyContext` and *returns* one or more `ForwardingAction` values
(`Forward`, `ForwardAfter`, `Nack`, `Suppress`, `Broadcast`) that the
engine then executes. This keeps strategies side-effect-free and testable
in isolation. `ForwardingAction` and `NackReason` live in `ndn-transport`
(re-exported as `ndn_engine::pipeline`).

## The skeleton

```rust,ignore
use std::sync::Arc;
use smallvec::{SmallVec, smallvec};
use ndn_packet::Name;
use ndn_transport::{ForwardingAction, NackReason};
use ndn_strategy::{ErasedStrategy, Strategy, StrategyContext, register_strategy};

type Actions = SmallVec<[ForwardingAction; 2]>;

// macro args: a `static` ident, short name, behaviour version, and a
// capture-free builder (the entry lives in a `static`).
register_strategy!(
    RANDOM_REG, b"random", 1,
    || Arc::new(RandomNexthopStrategy::new()) as Arc<dyn ErasedStrategy>,
);

pub struct RandomNexthopStrategy {
    name: Name, // /localhost/nfd/strategy/random
    counter: std::sync::atomic::AtomicU64,
}

impl Strategy for RandomNexthopStrategy {
    // `&Name`, not `&'static str` — a strategy name is an NDN name.
    fn name(&self) -> &Name { &self.name }

    // Synchronous fast path; `Some(_)` short-circuits the async hooks.
    fn decide(&self, ctx: &StrategyContext) -> Option<Actions> {
        let nexthops = ctx.fib_entry?.nexthops_excluding(ctx.in_face); // split horizon
        if nexthops.is_empty() {
            return Some(smallvec![ForwardingAction::Nack(NackReason::NoRoute)]);
        }
        let i = self.counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed) as usize
            % nexthops.len();
        Some(smallvec![ForwardingAction::Forward(smallvec![nexthops[i].face_id])])
    }

    // Required. Implement the body when a decision must `.await`.
    async fn after_receive_interest(&self, ctx: &StrategyContext<'_>) -> Actions {
        self.decide(ctx).unwrap()
    }

    async fn after_receive_data(&self, _ctx: &StrategyContext<'_>) -> Actions {
        SmallVec::new() // pipeline forwards Data to PIT in-records
    }
}
```

`register_strategy!` collects entries at link time via `linkme` on native
targets; the engine reads the slice at startup. On `wasm32` it defines a
`pub static` and external crates call `ndn_strategy::registry::register`
during engine setup.

## Methods you can implement

| Method | When called | Default |
|---|---|---|
| `name(&self) -> &Name` | Registration / strategy-choice lookup | Required. |
| `decide(&self, ctx)` | Synchronous fast path, before the async hooks | `None` (fall through). |
| `after_receive_interest(&self, ctx)` | Each Interest on the matching prefix | Required. |
| `after_receive_data(&self, ctx)` | Each incoming Data (bookkeeping / egress) | No actions. |
| `on_interest_timeout(&self, ctx)` | A pending Interest times out | `Suppress`. |
| `on_nack(&self, ctx, reason)` | A Nack arrives | `Suppress`. |
| `schedule(&self, ctx, delay, callback)` | Run code later | Cancellable `ScheduledEvent`. |

Every hook takes `&self` and `&StrategyContext` — never `&mut`, and the
Interest/Data are read off the context, not passed as arguments. Full
contracts are on the `Strategy` trait docstring.

## Pinning under a prefix

A strategy doesn't take over the whole forwarder; it owns a *prefix*.
Operators pin one via the `strategy-choice` management module — with
`nfdc`-style tooling:

```sh
nfdc strategy set /research /localhost/nfd/strategy/random
```

The strategy name resolves through the registry by its short name
(`random`), running the registered builder. Strategies coexist by
namespace; the engine uses the longest-prefix match for each Interest.

## Using the StrategyContext

`StrategyContext` is an *immutable* view of engine state. A strategy
reads it and returns actions; it has no `send_*` methods. The fields:

- `ctx.fib_entry: Option<&FibEntry>` — the matched FIB entry (`None` =
  no route). Pick nexthops via `.nexthops` or
  `.nexthops_excluding(ctx.in_face)` for split horizon.
- `ctx.in_face: FaceId` — the face the packet arrived on.
- `ctx.name: &Arc<Name>` — the packet name.
- `ctx.pit_token`, `ctx.measurements` — PIT token, measurements table.
- `ctx.signals`, `ctx.extensions` — cross-layer inputs (see below).
- `ctx.runtime` — spawn/sleep handle backing `schedule()`.

Forwarding is expressed by *returning* actions, not by calling the
context. The full surface is in `crates/forwarding/ndn-strategy/src/context.rs`.

## Cross-layer signals

`ctx.signals` exposes external/environmental inputs — radio link quality
(RSSI, SNR, congestion) and node state (GPS position, battery) — distinct
from `ctx.measurements` (derived from observed traffic):

```rust,ignore
// Prefer the nexthop with the strongest signal.
let best = nexthops.iter().copied().max_by_key(|n| {
    ctx.signals.link(n.face_id).and_then(|l| l.rssi_dbm).unwrap_or(i8::MIN)
});
```

Signals are *pushed* by **signal sources** (a background driver feeds a
shared store), so reading them never blocks: register a source with
`EngineBuilder::signal_source(...)` from `ndn-signal-sources` (radio
metrics, GPS; pluggable hardware/mock backends). A measured strategy can
share one decision kernel across native and embedded sans-IO targets;
`ndn-strategy-cclf` is the worked example, with taxonomy and units in
[`docs/signals.md`](https://github.com/Quarmire/ndn-rs/blob/main/docs/signals.md).

## Testing

The in-process engine is the right fixture; `EngineBuilder::strategy(...)`
takes the strategy value directly and installs it as the default:

```rust,ignore
let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
    .strategy(RandomNexthopStrategy::new())
    .build()
    .await?;
```

To pin under a *specific* prefix instead, install via the
`strategy-choice` module at runtime (see Pinning, above). Because every
hook is a pure function of `&StrategyContext`, you can also
unit-test decision logic by constructing a `StrategyContext` with a
hand-built `FibEntry` and asserting on the returned `ForwardingAction`s —
the in-tree strategies' `#[cfg(test)]` modules do exactly this.
[`examples/strategy-custom/`](https://github.com/Quarmire/ndn-rs/tree/main/examples/strategy-custom)
shows the end-to-end shape.

## Built-in references

- `crates/forwarding/ndn-strategy/src/best_route.rs` — lowest-cost nexthop with
  split horizon; `on_nack` retries the next-best nexthop.
- `crates/forwarding/ndn-strategy/src/multicast.rs` — fan out to every nexthop.
- `crates/forwarding/ndn-strategy/src/filter.rs` — chain a strategy with filters.

A WASM strategy targets `wasm32-unknown-unknown` and loads at runtime via
`ndn-wasm-strategy` (same `Strategy` trait); see `examples/wasm-strategy/`.

## Conventions

- A strategy `name()` is itself an NDN name; the registry keys on the
  short component (`random`).
- A strategy may hold internal state; the engine never serialises it.
- Strategies are `Send + Sync`; hooks may be called concurrently.

## See also

- [Extend tier → Strategy](../api/extend.md#strategy) — trait inventory.
- [Interest and Data lifecycle](../concepts/interest-data-lifecycle.md).
- [Management verbs](../reference/mgmt-verbs.md) — `strategy set`/`unset`.
- Examples:
  [`strategy-custom`](https://github.com/Quarmire/ndn-rs/tree/main/examples/strategy-custom),
  [`strategy-composed`](https://github.com/Quarmire/ndn-rs/tree/main/examples/strategy-composed),
  [`context-enricher`](https://github.com/Quarmire/ndn-rs/tree/main/examples/context-enricher).
