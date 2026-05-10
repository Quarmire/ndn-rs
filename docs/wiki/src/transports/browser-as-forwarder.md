# Browser as Forwarder

Phase 7 lands the full `ndn_engine::ForwarderEngine` on
`wasm32-unknown-unknown`. Every browser tab that loads the
`shared-engine` bundle is a real NDN forwarder — the same PIT, FIB,
RIB, Content Store, strategy chain, dispatcher, and pipeline tasks
that run inside `ndn-fwd` natively, hosted by a per-origin
SharedWorker.

> **The dashboard ships this too.** Loading
> `ndn-dashboard?engine=local` (built with `--features browser-engine`)
> hosts a `ForwarderEngine` directly in the dashboard tab — the
> management UI *is* the forwarder. See
> [Dashboard → Browser-engine mode](../guides/dashboard.md#browser-engine-mode-phase-7).

Crate: `ndn-engine` (the existing crate, now wasm-buildable). Public
API: [`WasmEngineBuilder`] + [`WasmEngineConfig`] mirroring the
native [`EngineBuilder`]; [`ForwarderEngine`] is identical on both
targets.

## What you get

The wasm-side engine is the same engine. Specifically:

- **PIT** — exact same `ndn_store::Pit` used natively. Inbound
  Interests create entries, Data satisfies them, expired entries
  drain via the periodic expiry task.
- **FIB / RIB** — same `Fib` and `Rib`; longest-prefix-match
  lookup; per-face-down cleanup; route TTL expiry.
- **Content Store** — `LruCs` (default) bounded by total bytes,
  with implicit-digest verification, name-based exact match,
  CanBePrefix descendant lookup, and MustBeFresh respect.
- **Strategy chain** — `BestRouteStrategy` by default; pluggable
  via `with_strategy(...)`. The strategy runs in the same
  pipeline order as native (decode → CS lookup → PIT check →
  strategy → forward → PIT match → CS insert).
- **Dispatcher pipeline** — single-threaded on wasm
  (`pipeline_threads = 1` is hardcoded; `wasm32-unknown-unknown`
  has no thread pool), but otherwise the same ingress / egress
  logic.
- **Per-face reader / sender tasks** — each face attached via
  `add_face` gets its own pair of tasks driven by the runtime
  abstraction.
- **Expiry tasks** — `run_expiry_task`, `run_rib_expiry_task`,
  `run_idle_face_task` all run on wasm via `Runtime::sleep`.

## What you don't get

- **No security** — `EngineInner.security` and `EngineInner.validator`
  are `cfg`-gated out of the wasm build. `ndn-security` doesn't
  build on wasm32 (`ring`, `libsqlite3-sys`); the wasm
  `ValidationStage` is a permissive stub
  (`ValidationStage::disabled`) that marks every Data verified.
  Production wasm callers that need real verification must
  perform it at the application layer (e.g. NDF composition,
  app-side `Validator` reachable through application code).
- **No multi-thread pipeline** — `pipeline_threads = 1`. The
  wasm event loop doesn't have threads to spread packet
  processing across; the option is fixed.
- **No discovery tick** — the wasm builder skips the
  `discovery.on_tick` loop because the only wasm-buildable
  `DiscoveryProtocol` is `NoDiscovery` (which no-ops on tick
  anyway). Browser-side discovery is application-layer, not
  link-layer.
- **No native routing protocols** — NLSR and friends pull
  ndn-security and ndn-app, neither wasm-buildable today. Wasm
  callers can install a wasm-friendly routing impl after
  construction via `engine.routing().enable(...)`.

## Architecture

```
                     ┌────────── per-origin SharedWorker ──────────┐
                     │                                              │
                     │   ForwarderEngine                            │
                     │       │                                     │
   tab A ── port ────┼─→ WorkerPortFace (face#2) ──┐                │
                     │                              │               │
   tab B ── port ────┼─→ WorkerPortFace (face#3) ──┼─ pipeline ─→ FIB lookup ─→ AppFace (face#1)
                     │                              │               │            (producer-served names)
                     │   BrowserWebTransportFace ──┘               │       └─→ upstream WT face
                     │   (optional upstream)                        │            (default `/` route)
                     │                                              │
                     └─────────────────────────────────────────────┘
```

The dioxus-demo's wrapper `Engine` (in
`crates/tooling/dioxus-demo/src/engine.rs`) keeps an internal
`AppFace` plumbed into the engine for application-tier I/O. Tabs
that connect through `SharedWorkerProxyFace` become `WorkerPortFace`
instances inside the engine; producers, the demo's CA flow, and
the local consumer share `AppFace` for their pipeline traffic.

## Witness

The phase-6 two-tab cache-hit witness — `testbed/tests/browser/sharedworker_cache_hit.spec.ts`
— now runs against the real `ForwarderEngine`, not the previous
hand-rolled mini-engine. Tab A expresses `/cache-test/counter`
twice; tab B expresses once; tab B's response equals tab A's
second response, proving:

- The shared engine is shared (same producer counter advances
  across tabs).
- The CS short-circuits a fresh producer mint on cache hit
  (tab B's response matches tab A's last cached value rather
  than minting `n+1`).

## Security caveats

- A malicious tab can poison its own engine's CS with arbitrary
  Data — but since each origin gets its own SharedWorker, this
  affects only that origin's tabs. Cross-origin tabs run
  independent engines.
- The wasm engine doesn't validate signatures
  (`ValidationStage::disabled`); applications that require
  signature verification must layer it on top (see NDF's
  composition pipeline as a reference). Without app-layer
  validation, a peer face can inject any byte sequence and the
  engine will route it.
- WebRTC peering doesn't yet plug into the wasm engine's face
  table — the worker entrypoint accepts `WorkerPortFace`s only.
  Phase-5's `WebRtcFace` works tab-side but isn't yet
  integrated into the worker's face graph; that wiring is a
  follow-on (browser-as-transit witness deferred).

## Wiring (sketch)

```rust,ignore
// Inside the SharedWorker entrypoint:
let runtime = ndn_runtime::default_runtime();

// Optional upstream — empty string skips the dial.
let upstream: Option<Arc<dyn ErasedFace>> = if !upstream_url.is_empty() {
    let face = BrowserWebTransportFace::connect(
        FaceId(1), &upstream_url, &[], runtime.clone(),
    ).await?;
    Some(Arc::new(face))
} else {
    None
};

// Build the engine via the wasm builder.
let mut builder = WasmEngineBuilder::new(WasmEngineConfig::default())
    .with_runtime(runtime.clone());
if let Some(face) = upstream.as_ref() {
    builder = builder.add_face(Arc::clone(face));
}
let (engine, _shutdown) = builder.build()?;

// Optionally install a default `/` → upstream route.
if let Some(face) = upstream.as_ref() {
    engine.fib().set_nexthops(
        &Name::root(),
        vec![FibNexthop { face_id: face.id(), cost: 1 }],
    );
}

// Accept tab MessagePorts as new inbound faces.
let listener = init_worker_scope()?;
loop {
    let id = engine.faces().alloc_id();   // important: shared allocator
    let port_face = listener.accept_one(id, runtime.clone()).await?;
    engine.add_face(port_face, CancellationToken::new());
}
```

## Next steps

Phase 7 lands the engine. The remaining browser-tier work for the
NDF-readiness ladder:

- WebRTC face integration inside the worker (peer-to-peer transit
  through the shared engine).
- IndexedDB-backed PIB persistence so the engine's signing
  identity survives the SharedWorker dying when the last tab
  closes.
- Wasm-side `Validator` for app-tier signature verification (or
  reuse NDF's composition pipeline).

[`WasmEngineBuilder`]: ../../../ndn_engine/struct.WasmEngineBuilder.html
[`WasmEngineConfig`]: ../../../ndn_engine/struct.WasmEngineConfig.html
[`EngineBuilder`]: ../../../ndn_engine/struct.EngineBuilder.html
[`ForwarderEngine`]: ../../../ndn_engine/struct.ForwarderEngine.html
