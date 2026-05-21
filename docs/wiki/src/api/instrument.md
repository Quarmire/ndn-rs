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
| `ForwarderEngine::fib()` / `rib()` / `pit()` / `cs()` / `strategy_table()` / `measurements()` / `routing()` / `discovery_ctx()` | `ndn_engine::engine` (`crates/spec/ndn-engine/src/engine.rs`) | Direct table access. |
| `ContextEnricher` | `ndn_engine::enricher` | Pipeline-stage hook for cross-layer enrichment. |
| `observability::targets` | `ndn_engine::observability::targets` | Tracing target taxonomy. |
| `InProcFace::new_kind` | `ndn_faces::local::InProcFace` | Synthesize an in-process face with a custom `FaceKind`. |
| `CallbackFace` | `ndn_faces::callback::CallbackFace` | Virtual face whose send-path is a Rust callback. |
| `TapFace` | `ndn_faces::callback::TapFace` | Records every wire packet sent to it without participating in forwarding. |


## Gating

Each carrier crate declares the feature:

```toml
# crates/spec/ndn-engine/Cargo.toml — and likewise for ndn-faces
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
ndn-faces  = { version = "0.1", features = ["experimental-instrument"] }
```

## TapFace

`TapFace` is the workhorse for wire-packet tracing.

```rust,ignore
use ndn_faces::callback::TapFace;
use ndn_engine::{EngineBuilder, EngineConfig};
use ndn_transport::FaceId;

let tap = TapFace::new(FaceId(99));
let captured = tap.captured(); // Arc<Mutex<Vec<Bytes>>>
let (_engine, _shutdown) = EngineBuilder::new(EngineConfig::default())
    .face(tap)
    .build()
    .await?;

// Drive traffic, then read every wire packet the engine routed to FaceId(99):
for bytes in captured.lock().unwrap().iter() {
    // parse / inspect / log
}
```

`TapFace` does not participate in forwarding: the engine sends to
it, the bytes accumulate, and nothing is returned. Use it alongside
real faces to record what the engine *would have* sent over them.

In-tree reference: `crates/spec/ndn-faces/src/callback.rs`.

## Engine table access

With the feature enabled, the engine exposes its tables:

```rust,ignore
use ndn_engine::{EngineBuilder, EngineConfig};
# async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
let (engine, _shutdown) = EngineBuilder::new(EngineConfig::default())
    .build()
    .await?;

// Snapshot of pit state at this instant:
for entry in engine.pit().iter() {
    println!("{} pending: {} in-records", entry.name(), entry.in_records().len());
}

// FIB inspection:
for entry in engine.fib().iter() {
    println!("{} -> {:?}", entry.name(), entry.nexthops());
}
# Ok(()) }
```

These accessors return read-only views by default. Mutating PIT
state (e.g. injecting fake in-records) is filed for v0.1.x.

## CallbackFace

`CallbackFace` builds a face whose send-path runs a Rust closure
and whose recv-path is fed from outside. Use it to splice an
external test harness into the engine's pipeline.

```rust,ignore
use ndn_faces::callback::CallbackFace;
use ndn_transport::FaceId;

let face = CallbackFace::new(FaceId(7), |bytes| {
    println!("engine sent {} bytes", bytes.len());
});
// face.feed(bytes) drives the recv path.
```

## Two-engine experiments

A common Instrument-tier pattern is wiring two engines through a
pair of in-process faces:

```rust,ignore
use ndn_faces::local::InProcFace;
use ndn_engine::{EngineBuilder, EngineConfig};
use ndn_transport::FaceId;

# async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
let (face_a, handle_a) = InProcFace::new(FaceId(1), 64);
let (face_b, _handle_b) = InProcFace::pair_with(&handle_a, FaceId(2), 64);

let (_engine_a, _s_a) = EngineBuilder::new(EngineConfig::default()).face(face_a).build().await?;
let (_engine_b, _s_b) = EngineBuilder::new(EngineConfig::default()).face(face_b).build().await?;
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
