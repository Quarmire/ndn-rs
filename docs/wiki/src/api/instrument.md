# Instrument tier — researcher / measurement surface

The Instrument tier exposes engine internals (PIT, FIB, CS,
strategy table, measurements) and packet-tap primitives for
researchers, measurement tooling, and in-process tests. It sits
below the [Extend tier](./extend.md): protocol authors implement
traits; researchers read engine state directly.

**Stability:** Instrument items are feature-gated behind
`experimental-instrument`. The shape of the feature surface follows
SemVer; individual items inside may move between patch releases.
Out-of-feature use is intentionally inconvenient (see §"gating"
below).

## When to reach for this tier

- You're measuring forwarding behaviour and want PIT / CS hit
  counts at the source.
- You're writing a researcher experiment that wires two in-process
  engines back-to-back and observes wire packets between them.
- You're building tooling (dashboard, OpenTelemetry bridge,
  packet sniffer) that needs structured engine state.

## Inventory

| Item | Crate path | Purpose |
|---|---|---|
| `ForwarderEngine::fib()` / `rib()` / `pit()` / `cs()` / `strategy_table()` / `measurements()` / `routing()` / `discovery_ctx()` | `ndn_engine::engine` (`crates/forwarding/ndn-engine/src/engine.rs`) | Direct table access. |
| `ContextEnricher` | `ndn_engine::enricher` | Pipeline-stage hook for cross-layer enrichment. |
| `observability::targets` | `ndn_engine::observability::targets` | Tracing target taxonomy. |
| `InProcFace::new_kind` | `ndn_face::local::InProcFace` | Synthesize an in-process face with a custom `FaceKind`. |
| `CallbackFace` | `ndn_face::callback::CallbackFace` | Virtual face whose send-path is a Rust callback. |
| `TapFace` | `ndn_face::callback::TapFace` | Records every wire packet sent to it without participating in forwarding. |


## Gating

Each carrier crate declares the feature:

```toml
# crates/forwarding/ndn-engine/Cargo.toml — and likewise for ndn-face
[features]
experimental-instrument = []
```

Items carry `#[cfg_attr(not(feature = "experimental-instrument"), doc(hidden))]`
so they remain `pub` (the workspace itself calls them) but are
absent from `cargo doc` output unless the consuming crate opts in.

To use the tier in your own crate:

```toml
[dependencies]
ndn-engine = { version = "0.1", features = ["experimental-instrument"] }
ndn-face  = { version = "0.1", features = ["experimental-instrument"] }
```

## TapFace

`TapFace` is the workhorse for wire-packet tracing.

```rust,ignore
use ndn_face::callback::TapFace;
use ndn_engine::{EngineBuilder, EngineConfig};
use ndn_transport::FaceId;

# async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
let tap = TapFace::new(FaceId(99));
// `.face()` consumes the transport, so grab a shared handle to the
// capture buffer first:
let buf = tap.capture_handle(); // Arc<Mutex<Vec<Bytes>>>
let (_engine, _shutdown) = EngineBuilder::new(EngineConfig::default())
    .face(tap)
    .build()
    .await?;

// Drive traffic, then read every wire packet the engine routed to FaceId(99).
// The handle's `Mutex` is `tokio::sync::Mutex`, so the lock is `.await`ed:
for bytes in buf.lock().await.iter() {
    // parse / inspect / log
}
# Ok(()) }
```

When the tap is not handed to the builder, drain the buffer in one
shot with the async `captured()` method, which returns `Vec<Bytes>`
and clears the tap:

```rust,ignore
# use ndn_face::callback::TapFace;
# use ndn_transport::FaceId;
# async fn run() {
let tap = TapFace::new(FaceId(99));
// ... drive traffic ...
let packets: Vec<bytes::Bytes> = tap.captured().await;
# }
```

`TapFace` does not participate in forwarding: the engine sends to
it, the bytes accumulate, and nothing is returned. Use it alongside
real faces to record what the engine *would have* sent over them.

In-tree reference: `crates/faces/ndn-face/src/callback.rs`.

## Engine table access

With the feature enabled, the engine exposes its tables:

```rust,ignore
use ndn_engine::{EngineBuilder, EngineConfig};
use ndn_store::pit::{PitKeyDiscriminator, PitToken};
# async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
let (engine, _shutdown) = EngineBuilder::new(EngineConfig::default())
    .build()
    .await?;

// FIB inspection. `dump()` returns a `Vec<(Name, Arc<FibEntry>)>`
// snapshot of every installed prefix; `nexthops` is a field on
// `FibEntry`, each carrying a `face_id` and a `cost`:
for (name, entry) in engine.fib().dump() {
    let faces: Vec<_> = entry.nexthops.iter().map(|n| n.face_id).collect();
    println!("{name} -> {faces:?}");
}

// PIT inspection. The PIT is a sharded `DashMap` keyed by `PitToken`,
// so there is no global iterator on the hot path. Read live size with
// `len()`, and inspect a known name under a closure with
// `with_named_entry` (which holds the shard lock for the call):
println!("pending interests: {}", engine.pit().len());

let name: ndn_packet::Name = "/probe".parse()?;
engine.pit().with_named_entry(
    &name,
    PitKeyDiscriminator::Classical,
    |entry| {
        println!(
            "{} has {} in-records",
            entry.name,
            entry.in_records.len(),
        );
    },
);
# Ok(()) }
```

These accessors expose live tables. The PIT closures
(`with_entry`, `with_entry_mut`, `with_named_entry`) hold the
relevant shard lock for the duration of the call, so keep the body
short. Mutating PIT state for injection experiments (e.g. fabricating
in-records) is filed for v0.1.x.

## CallbackFace

`CallbackFace` builds a virtual face whose send-path runs an
application callback: the engine routes an `Interest` to it, the
callback returns `Some(Data)` to satisfy it or `None` to emit a
`NoRoute` Nack. Use it when a function can directly produce `Data`
for any name.

The callback is async — it returns a
`BoxFuture<'static, Option<Data>>`:

```rust,ignore
use ndn_face::callback::CallbackFace;
use ndn_packet::{Data, Interest};
use ndn_transport::FaceId;

let face = CallbackFace::new(FaceId(7), |interest: Interest| {
    Box::pin(async move {
        // ... look up / synthesize Data for `interest.name` ...
        None::<Data>
    })
});
```

When the lookup is synchronous, `CallbackFace::from_fn` takes a
plain `Fn(Interest) -> Option<Data>` and wraps it for you:

```rust,ignore
# use ndn_face::callback::CallbackFace;
# use ndn_packet::{Data, Interest};
# use ndn_transport::FaceId;
let face = CallbackFace::from_fn(FaceId(7), |_interest: Interest| {
    None::<Data>
});
```

## Two-engine experiments

A common Instrument-tier pattern is wiring two engines through
in-process faces. `InProcFace::new(id, buffer)` returns a linked
`(InProcFace, InProcHandle)`: the engine holds the face, and the
handle drives the recv/send channels from the other side. (Use
`InProcFace::new_kind` to stamp a non-default `FaceKind` on the
engine side.)

```rust,ignore
use ndn_face::local::InProcFace;
use ndn_engine::{EngineBuilder, EngineConfig};
use ndn_transport::FaceId;

# async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
// Each engine gets its own InProcFace; the test harness owns both
// handles and shuttles wire bytes between them.
let (face_a, handle_a) = InProcFace::new(FaceId(1), 64);
let (face_b, handle_b) = InProcFace::new(FaceId(2), 64);

let (_engine_a, _s_a) = EngineBuilder::new(EngineConfig::default()).face(face_a).build().await?;
let (_engine_b, _s_b) = EngineBuilder::new(EngineConfig::default()).face(face_b).build().await?;

// Forward whatever engine A emits into engine B (and vice-versa):
while let Some(bytes) = handle_a.recv().await {
    handle_b.send(bytes).await.ok();
}
# Ok(()) }
```

The audit witness at `testbed/tests/audit/phase3_fetch_object_rdr.sh`
uses this shape to verify segmented `fetch_object` end-to-end without
opening any network sockets.

## What this tier does not expose

- Structured packet-trace export (jsonl, OTLP, pcap). `TapFace`
  ships raw bytes only; export formats are v0.2 candidates.
- PIT injection / fake in-records. v0.1.x.
- Strategy injection at runtime (bypass `register_strategy!`).
  v0.1.x if a use case appears.

## See also

- [Develop tier](./develop.md) — application-author surface.
- [Extend tier](./extend.md) — protocol-author trait surface.
- [Logging](../operations/logging.md) — `observability::targets` is
  the same taxonomy the operator-facing logging page uses.
