# Add a forwarding strategy

A **forwarding strategy** owns the per-prefix decision the pipeline makes for a
fresh Interest: which next-hop(s) to forward to, whether to wait, whether to
Nack. This page is the terse contributor recipe. For the fuller walkthrough —
`StrategyContext` fields, cross-layer signals, pinning under a prefix — read the
Part I guide [Writing a strategy](../../guides/writing-a-strategy.md); this page
assumes you have skimmed it and focuses on getting a new strategy compiled,
registered, and tested in-tree.

The trait lives in `ndn-strategy/src/strategy.rs`; the registry macro in
`ndn-strategy/src/registry.rs`. A complete, compiled example is
`examples/strategy-custom/src/main.rs` — the snippets below are `{{#include}}`d
straight from it, so what you read here is what the CI `book` job builds.

## The decision model

A `Strategy` is a **pure, synchronous decision function**. It does not send
Interests, mutate the FIB, or touch I/O. Each hook reads an immutable
[`StrategyContext`] and *returns* `SmallVec<[ForwardingAction; 2]>`; the engine
executes the returned actions. `ForwardingAction` (`Forward`, `ForwardAfter`,
`Nack`, `Suppress`, `Broadcast`) and `NackReason` live in `ndn-transport` and
are re-exported as `ndn_engine::pipeline`.

> **Sans-IO / no-block rule.** The hooks are synchronous and must not block or
> `.await`. Defer any timed work through `ForwardingAction::ForwardAfter` (for
> deferred forwarding) or `Strategy::schedule` (for arbitrary strategy code such
> as probing or RTT sampling). The clock behind `schedule` is the injected
> engine `Runtime`, which is what lets timeout-sensitive strategy tests run
> under a virtual clock — see [ADR 0004](../adr/0004-virtualize-the-clock.md).

## The trait surface

| Method | When called | Default |
|---|---|---|
| `name(&self) -> &Name` | Registration / strategy-choice lookup | Required |
| `decide(&self, ctx)` | Synchronous fast path, before `after_receive_interest` | `None` (fall through) |
| `after_receive_interest(&self, ctx)` | Each fresh Interest on the matching prefix | Required |
| `after_receive_data(&self, ctx)` | Each satisfying Data (bookkeeping / egress) | Required |
| `on_interest_timeout(&self, ctx)` | A pending Interest times out | `Suppress` |
| `on_nack(&self, ctx, reason)` | A Nack arrives | `Suppress` |
| `schedule(&self, ctx, delay, cb)` | Run strategy code later | Cancellable `ScheduledEvent` |

`decide` is the cheap fast path: `Some(actions)` short-circuits and
`after_receive_interest` is never reached; `None` falls through to it. A strategy
that is fully synchronous (most are) can put all its logic in `decide` and leave
`after_receive_interest` unreachable.

## The implementation

From `examples/strategy-custom/src/main.rs` — a round-robin next-hop picker with
split horizon:

```rust
{{#include ../../../../../examples/strategy-custom/src/main.rs:impl}}
```

Points worth noting:

- `name()` returns `&Name`, not a string — a strategy name is an NDN name under
  `/localhost/nfd/strategy/<name>`.
- `nexthops_excluding(ctx.in_face)` implements **split horizon** (never forward
  back out the arrival face). `ctx.fib_entry` is `None` when there is no route —
  answer that with `Nack(NoRoute)`.
- Actions are *returned*, never sent. The engine performs the egress.

## Registration

`register_strategy!` (`ndn-strategy/src/registry.rs`) records a `StrategyEntry`
into a `linkme::distributed_slice` at link time on native targets; the engine
reads the slice at startup and resolves names through it. On `wasm32` (no
life-before-main) it defines a `pub static` that an external crate hands to
`ndn_strategy::registry::register` during engine setup. The macro takes a
`static` ident, the NFD short name, a behaviour version, and a capture-free
builder:

```rust,ignore
use std::sync::Arc;
use ndn_strategy::{ErasedStrategy, register_strategy};

register_strategy!(
    RANDOM_REG, b"random", 1,
    || Arc::new(RandomStrategy::new()) as Arc<dyn ErasedStrategy>,
);
```

The name follows the NFD strategy-name convention:
`/localhost/nfd/strategy/<name>/v=N`, where `<name>` is the registered short
component (`random`) and `N` is the version. `create_by_name` and
`create_by_name_version` resolve it; the built-in `best-route` registers as
`/localhost/nfd/strategy/best-route/v=5`, for example.

## Installing and testing

The in-process engine is the fixture. `EngineBuilder::strategy(...)` takes the
strategy value directly and installs it as the default — this is what the
example's `main` does:

```rust
{{#include ../../../../../examples/strategy-custom/src/main.rs:register}}
```

To pin a strategy under a *specific* prefix instead of the default, use the
`strategy-choice` management module (see
[Add a management module](./add-a-mgmt-module.md) and the Part I guide's
"Pinning under a prefix").

Because every hook is a pure function of `&StrategyContext`, you can unit-test
decision logic without an engine at all: build a `StrategyContext` with a
hand-made `FibEntry` and assert on the returned actions. The built-in
strategies' `#[cfg(test)]` modules do exactly this. Run the suite with
`cargo nextest run -p ndn-strategy` (see [the testing guide](../testing.md)).

## Built-in references

| Strategy | File | Behaviour |
|---|---|---|
| `best-route` | `ndn-strategy/src/best_route.rs` | Lowest-cost next-hop, split horizon; `on_nack` retries the next-best |
| `multicast` | `ndn-strategy/src/multicast.rs` | Fan out to every next-hop |
| `composed` | `ndn-strategy/src/composed.rs` | Chain a strategy with context filters |

`congestion_aware` and `self_learning` ship as additional built-ins in the same
crate. A sandboxed WASM strategy targets `wasm32-unknown-unknown` and loads at
runtime through `ndn-wasm-strategy` (same `Strategy` trait).

## See also

- [Writing a strategy](../../guides/writing-a-strategy.md) — the full Part I guide.
- [The forwarding pipeline](../architecture/forwarding-pipeline.md) — where the
  strategy stage sits.
- [ADR 0004 · Virtualize the clock](../adr/0004-virtualize-the-clock.md) — why
  `schedule` goes through the injected runtime.

[`StrategyContext`]: https://github.com/Quarmire/ndn-rs/blob/main/crates/forwarding/ndn-strategy/src/context.rs
