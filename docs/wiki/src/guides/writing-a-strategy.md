# Writing a strategy

A forwarding strategy decides which face an Interest goes out on,
when it retransmits, and how it reacts to NACKs and timeouts. This
guide walks through writing a third-party strategy, registering it,
and pinning it under a prefix.

The trait surface is [Extend tier → Strategy](../api/extend.md#strategy);
the contract lives at `crates/ndn-strategy/src/strategy.rs:7`.

## When to write a strategy

- Your protocol needs a forwarding rule the built-ins don't cover
  (e.g. weighted round-robin, latency-aware, energy-aware).
- You're researching strategy behaviour and want a measurement
  fixture under your control.
- You're building a sandboxed strategy (WASM); see
  `crates/ndn-wasm-strategy/`.

For everything else the built-ins (`BestRouteStrategy`,
`MulticastStrategy`, `ComposedStrategy`) are usually correct.

## The skeleton

```rust,ignore
use ndn_strategy::{Strategy, StrategyContext, register_strategy};
use ndn_packet::Interest;

pub struct RandomNexthopStrategy;

#[async_trait::async_trait]
impl Strategy for RandomNexthopStrategy {
    fn name(&self) -> &'static str { "/strategy/random" }

    async fn after_receive_interest(
        &self,
        ctx: &mut StrategyContext<'_>,
        interest: &Interest,
    ) {
        let candidates = ctx.fib_lookup(interest.name());
        if let Some(face) = candidates.random_nexthop() {
            ctx.send_interest(face, interest).await;
        }
    }
}

register_strategy!(RandomNexthopStrategy);
```

`register_strategy!` uses `linkme` to put the strategy in a
distributed slice. At engine startup the slice is read and each
registered strategy is available for installation.

## Methods you can implement

| Method | When called | Default |
|---|---|---|
| `name()` | At registration | Required. |
| `after_receive_interest(ctx, interest)` | Each incoming Interest on the matching prefix | Required. |
| `after_receive_data(ctx, data, in_face)` | Each incoming Data | Forward to all in-records. |
| `after_receive_nack(ctx, nack, in_face)` | NACK arrives | Forward NACK to all in-records. |
| `before_satisfy_pending_interest(ctx, pit_entry, data)` | Just before a PIT entry is satisfied | No-op. |
| `schedule(at, event)` (default) | Strategy wants to wake up later | Cancellable timer wired into the engine loop. |

Full method list and contracts are on the `Strategy` trait docstring.

## Pinning under a prefix

A strategy doesn't take over the whole forwarder; it owns a *prefix*.
Operators pin a strategy under a prefix via the management protocol:

```sh
ndn-ctl strategy set /research/random /strategy/random
```

Multiple strategies coexist by namespace. The engine looks up the
longest-prefix-match strategy for each Interest.

## Using the StrategyContext

`StrategyContext` is the strategy's view of the engine:

- `ctx.fib_lookup(name)` — candidate faces for a name.
- `ctx.send_interest(face, interest)` — forward (records out-record).
- `ctx.send_nack(face, reason)` — send a NACK.
- `ctx.schedule(at, event)` — wake up at a future time with an event.
- `ctx.measurements()` — read/write per-prefix measurement state.

The full surface is in `crates/ndn-strategy/src/context.rs`.

## Cross-layer signals

`ctx.signals` exposes external/environmental inputs — radio link quality
(RSSI, SNR, congestion) and node state (GPS position, battery) — distinct from
`ctx.measurements` (which are derived from observed traffic):

```rust,ignore
// Prefer the nexthop with the strongest signal.
let best = nexthops.iter().copied().max_by_key(|f| {
    ctx.signals.link(*f).and_then(|l| l.rssi_dbm).unwrap_or(i8::MIN)
});
```

Signals are *pushed* by **signal sources** (a background driver feeds a shared
store), so reading them never blocks: register a source with
`EngineBuilder::signal_source(...)` from `ndn-signal-sources` (radio metrics,
GPS; pluggable hardware/mock backends).

A measured strategy can share **one decision kernel across native and
embedded**: write a pure `fn(&dyn SignalView<F>, nexthops, incoming, emit)` and
call it from both the native `Strategy` adapter and the embedded sans-IO
`Strategy`. `ndn-strategy-cclf` is the worked example.

The taxonomy, trait contracts, units, and the read-only
`/localhost/nfd/faces/link-quality` dataset are specified in
[`docs/signals.md`](https://github.com/Quarmire/ndn-rs/blob/main/docs/signals.md).

## Testing

The in-process engine is the right testing fixture:

```rust,ignore
use ndn_engine::{EngineBuilder, EngineConfig};
use ndn_strategy::StrategyChoice;

# async fn test() -> anyhow::Result<()> {
let (engine, _shutdown) = EngineBuilder::new(EngineConfig::default())
    .strategy(StrategyChoice::for_prefix("/research", "/strategy/random"))
    .build()
    .await?;
// drive traffic, assert behaviour via engine.measurements() etc.
# Ok(()) }
```

The reference example at [`examples/strategy-custom/`](https://github.com/Quarmire/ndn-rs/tree/main/examples/strategy-custom)
shows the end-to-end shape (engine wired with a custom strategy
implementation).

## Built-in references

Read these for working templates:

- `crates/ndn-strategy/src/best_route.rs` — probe primary, fall
  back to alternates on NACK/timeout. Demonstrates `schedule()`.
- `crates/ndn-strategy/src/multicast.rs` — fan out to every
  matching nexthop.
- `crates/ndn-strategy/src/composed.rs` — chain strategies by
  prefix.

## WASM strategies

A WASM strategy is compiled to `wasm32-unknown-unknown` and loaded
at runtime via `ndn-wasm-strategy`. The same `Strategy` trait
applies; the loader handles the host/guest boundary. See
`crates/ndn-wasm-strategy/` for the host API and
`examples/wasm-strategy/` for a guest example.

## Conventions

- A strategy `name()` is itself an NDN name. The `/strategy/...`
  prefix is by convention; nothing enforces it.
- A strategy may hold state internal to the impl; the engine never
  serialises it. Persist anything you need via `measurements()` or
  an external store.
- Strategies are `Send + Sync`. The engine may call methods
  concurrently for different Interests.

## See also

- [Extend tier → Strategy](../api/extend.md#strategy) — trait
  inventory.
- [Interest and Data lifecycle](../concepts/interest-data-lifecycle.md) —
  what the strategy is in the middle of.
- [Management verbs](../reference/mgmt-verbs.md) — `strategy set` /
  `strategy unset` verbs.
- [`examples/strategy-custom/`](https://github.com/Quarmire/ndn-rs/tree/main/examples/strategy-custom),
  [`examples/strategy-composed/`](https://github.com/Quarmire/ndn-rs/tree/main/examples/strategy-composed),
  [`examples/context-enricher/`](https://github.com/Quarmire/ndn-rs/tree/main/examples/context-enricher).
