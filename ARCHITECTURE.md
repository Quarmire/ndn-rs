# Architecture

> **Notice: primarily AI-authored, not yet proven correct.** The
> code described below is primarily written by an AI coding
> assistant and contains spec-compliance bugs catalogued in
> [`docs/notes/spec-compliance-audit-2026-04-20.md`](docs/notes/spec-compliance-audit-2026-04-20.md).
> Architectural *intent* is described here; actual *behaviour* may
> not match until the audit findings are resolved. See the
> [honest spec-compliance summary](docs/wiki/src/reference/spec-compliance.md)
> and [`testbed/EXPECTED_FAILURES.md`](testbed/EXPECTED_FAILURES.md).
> Do not cite this document as evidence of wire-level NDN
> compatibility.

NDN-RS models Named Data Networking as **composable async pipelines with trait-based polymorphism** — not class hierarchies. The engine is a library, not a daemon.

## Crate Map

Crates are organised into subdirectories that mirror the dependency layers.
Dependencies flow strictly downward; no layer may import from a layer above it.

```
binaries/                      Deployable executables
  ndn-fwd                      Standalone forwarder (TOML config, management socket)
  ndn-tools                    CLI tools: ndn-peek, ndn-put, ndn-ping, ndn-iperf, ndn-sec, …
  ndn-bench                    Throughput and latency benchmarks

testbed/                       Multi-forwarder compliance + benchmark testbed
  docker-compose.yml           ndn-fwd + NFD + yanfd on 172.30.0.0/24
  tests/compliance/            Protocol compliance tests (forwarding, PIT, CS, mgmt)
  bench/                       Throughput (ndn-iperf) and latency (ndn-ping) scripts
  report/compare.py            Markdown comparison table generator

tools/
  ndn-dashboard                Dioxus desktop management UI

crates/support/                Shared libraries used by binaries and dashboard
  ndn-tools-core               Embeddable tool logic (ping, iperf, peek, put)

crates/protocols/              Higher-level protocols built on the engine
  ndn-routing                  Routing algorithms: StaticProtocol, DvrProtocol, NlsrProtocol
  ndn-sync                     Dataset sync: SVS, PSync
  ndn-did                      NDN-native Decentralised Identifiers (W3C DID)
  ndn-cert                     NDNCERT 0.3 — certificate issuance and management
  ndn-identity                 Key management, identity bootstrapping

crates/engine/                 Forwarding core — pipeline, strategies, security, app API
  ndn-engine                   ForwarderEngine, EngineBuilder, pipeline stages, task topology
  ndn-strategy                 BestRoute, Multicast, ASF, and composed strategies
  ndn-security                 KeyChain, Signer/Verifier, TrustSchema, Validator, SafeData
  ndn-app                      Application API: Consumer, Producer, Subscriber
  ndn-ipc                      ForwarderClient, BlockingForwarderClient, chunked transfer
  ndn-config                   TOML config parsing, NFD management protocol
  ndn-discovery                Pluggable discovery: NDN AutoConfig hub-discovery,
                               per-neighbor liveness probe, SVS service discovery

crates/faces/                  All face implementations in one consolidated crate
  ndn-faces                    Feature-gated face types:
    net                        UdpFace, TcpFace, MulticastUdpFace (default)
    websocket                  WebSocketFace (default); websocket-tls adds TLS listener
    local                      InProcFace/InProcHandle, UnixFace (default)
    spsc-shm                   ShmFace/ShmHandle zero-copy ring (Unix)
    serial                     SerialFace with COBS framing (embedded/IoT)
    l2                         NamedEtherFace (AF_PACKET/PF_NDRV/Npcap), WfbFace
    bluetooth                  BleFace GATT stub
    virtual                    CallbackFace — virtual face driven by a Rust closure (e.g., CS prewarm hooks)
  ndn-face-webtransport        Server-side WebTransport listener (HTTP/3 + QUIC datagrams) — issue #14
  ndn-face-webtransport-wasm   Browser-side WebTransport client face; pure Rust→WASM via xwt-web,
                               also compiles natively via xwt-wtransport for unit witnesses — issue #14 phase 3

crates/foundation/ndn-acme     ACME (RFC 8555) DNS-01 cert provisioning for the WS-TLS face (issue #3) and the WT listener (issue #14)

crates/foundation/             Zero-NDN-dep building blocks — compile no_std compatible
  ndn-foundation-types         Name, NameComponent, canonical Ord — shared with ndf-rs
  ndn-transport                Face trait, FaceId, FaceTable, StreamFace, TlvCodec
  ndn-store                    NameTrie, Fib, PIT, ContentStore (LruCs/ShardedCs/FjallCs), DeadNonceList
  ndn-packet                   Interest, Data, Nack — lazy decode, no_std; re-exports ndn-foundation-types
  ndn-tlv                      TlvReader, TlvWriter, varu64 — no_std
  ndn-runtime                  Spawn/Sleep/Now trait abstraction; TokioRuntime (native) / WasmRuntime (browser)

crates/sim/                    Simulation and WebAssembly targets
  ndn-sim                      SimFace, SimLink, topology builder, event tracer
  ndn-wasm                     In-browser simulation via wasm-bindgen
  ndn-strategy-wasm            Hot-loadable WASM forwarding strategies

crates/research/               Experimental extensions
  ndn-research                 FlowObserverStage, FlowTable, ChannelManager (nl80211)
  ndn-compute                  ComputeFace, ComputeRegistry for named-function execution

crates/platform/               Special deployment targets (not built by default)
  ndn-embedded                 Minimal no_std forwarder for bare-metal MCUs
  ndn-mobile                   Android/iOS forwarder with AppFace IPC

bindings/                      FFI to other languages (not built by default)
  ndn-python                   PyO3 Python bindings
  ndn-boltffi                  BoltFFI — Kotlin/JVM and Swift bindings
```

## Key Abstractions

| Trait / Type | Crate | Role |
|---|---|---|
| `Face` | ndn-transport | Async send/recv over any transport |
| `PipelineStage` | ndn-engine | Single processing step; returns `Action` |
| `Strategy` | ndn-strategy | Forwarding decision per Interest |
| `ContentStore` | ndn-store | Pluggable cache backend |
| `KeyChain` | ndn-security | Identity, signing, and trust anchors; `--identity`/`--pib` flags in ndn-ctl |
| `Signer` / `Verifier` | ndn-security | Cryptographic operations; dispatched on `SignatureType` (RSA/ECDSA/HMAC/Digest/BLAKE3) |
| `DiscoveryProtocol` | ndn-discovery | Neighbor/service discovery |
| `RoutingProtocol` | ndn-routing | RIB population from routing algorithms |
| `ForwarderClient` | ndn-ipc | App-to-forwarder IPC (async or blocking) |
| `ComputeHandler` | ndn-compute | Named function execution |

## Pipeline Flow

```
Interest: FaceCheck → TlvDecode → CsLookup → PitCheck → Strategy → Dispatch
Data:     FaceCheck → TlvDecode → PitMatch  → Validation → CsInsert → Dispatch
```

`PacketContext` passes **by value** — ownership transfer makes short-circuits compiler-enforced. Each stage returns `Action`: `Continue`, `Send`, `Satisfy`, `Drop`, or `Nack`.

`ValidationStage` sets `ctx.verified = true` on the valid path. `CsInsertStage` gates on `ctx.verified` — unverified Data is never cached. Local-face Data is trusted by the OS-level IPC credential and also sets `ctx.verified`. When `validator_enabled = false`, the validator is permissive and still sets `ctx.verified` so the CS admission invariant holds in dev mode.

## Core Data Structures

- **FIB** — `NameTrie` with per-node `RwLock`; concurrent longest-prefix match
- **PIT** — `DashMap<PitToken, PitEntry>`; sharded, no global lock on hot path
- **Content Store** — trait-based; `LruCs` (in-memory), `ShardedCs` (parallel), `FjallCs` (disk)
- **Strategy Table** — name trie mapping prefixes to `Arc<dyn Strategy>`

## Task Topology

```
face_task (one per Face)
   │  RawPacket { bytes, face_id, arrival }
   ▼
pipeline_runner → per-packet processing inline
                  stages → dispatch → face_table.get(id).send(bytes)

expiry_task → drains expired PIT entries (1 ms tick)
```

## Security

`ndn-fwd` always has a signing identity. At startup it reads (or generates) a
key from the PIB path configured under `[security]`. The `[security.mgmt]` block
controls signed-command enforcement: `require_signed_commands = true` (default)
rejects management Interests without valid `InterestSignatureInfo`; a
`trust_anchor_pib` path points at the anchor certificates that management clients
must chain to. The `ndn-ctl --identity`/`--pib` flags pick the signing key for
command Interests.

`Validator` dispatches on `SignatureType`: Ed25519, ECDSA-SHA-256, RSA-SHA-256,
HMAC-SHA-256, DigestSha256, and BLAKE3 plain/keyed verifiers are all wired.
Certificate Format v2 names (`/<identity>/KEY/<KeyId>/<IssuerId>/<Version>`) are
enforced by `KeyChain::ephemeral` and `ndn-sec keygen`.

## Routing

The `RoutingProtocol` trait populates the RIB. Three implementations ship:

- **`StaticProtocol`** — TOML-configured static routes.
- **`DvrProtocol`** — experimental distance-vector protocol (ndn-rs-specific; no
  cross-implementation peer).
- **`NlsrProtocol`** — Named-data Link State Routing; implements the NDN testbed
  routing protocol. Runs `NeighborProbeProtocol` for liveness, PSync-based LSA flooding, and
  Dijkstra-based routing-table computation. Enabled via `[routing.nlsr]` in
  `ndnd.toml`. See `docs/wiki/src/protocols/nlsr.md` for operator guidance.

## Testbed

`testbed/docker-compose.yml` spins up an `ndn-fwd` instance, a C++ NFD instance,
and a YaNFD instance on a `172.30.0.0/24` network plus an `interop` container
with ndn-cxx tooling. The harness supports two test classes:

- **`testbed/tests/audit/<id>_<slug>.sh`** — per-finding witnesses. Each script
  exits 1 against a broken codebase and 0 after the fix. RUST-UNIT witnesses
  drive `cargo test`; GREP-PROOF witnesses verify code absence; INTEROP witnesses
  exchange packets across containers.
- **`testbed/tests/interop/`** — cross-implementation packet exchange tests
  (ndn-rs app vs NFD forwarder, ndn-cxx consumer vs ndn-rs forwarder, etc.).

Testbed CI runs on push to `testbed/**` and weekly via cron
(`.github/workflows/testbed.yml`).

## Browser target

The engine compiles to `wasm32-unknown-unknown` via the
[`ndn-runtime`](crates/foundation/ndn-runtime/) `Spawn`/`Sleep`/`Now` trait
abstraction (see the readiness audit at
`docs/notes/wasm-readiness-audit-2026-05-07.md`). The wasm-safe trait
shapes used by the engine — `DiscoveryProtocol`, `DiscoveryContext`,
`NeighborTable`, scope helpers — live in
[`crates/engine/ndn-discovery-core/`](crates/engine/ndn-discovery-core/);
[`ndn-discovery`](crates/engine/ndn-discovery/) re-exports them and adds
the native-only protocols (autoconfig, gossip, ether-ND, probe,
service-discovery). On wasm `ndn-engine` drops `ndn-security` (pulls
`ring`) entirely and substitutes a permissive [`ValidationStage`
stub](crates/engine/ndn-engine/src/stages/validation_stub.rs); the
[`builder`](crates/engine/ndn-engine/src/builder.rs) is also
non-wasm-only, so wasm callers construct `ForwarderEngine`
programmatically.

The browser-side
WebTransport client face lives in
[`crates/faces/ndn-face-webtransport-wasm/`](crates/faces/ndn-face-webtransport-wasm/);
the wiki page [`transports/webtransport-browser`](docs/wiki/src/transports/webtransport-browser.md)
walks through wiring it into a Rust→WASM application. The crate compiles
on both targets — wasm32 uses `xwt-web` (`web-sys::WebTransport`), other
targets use `xwt-wtransport` (`quinn` + `wtransport`) so loopback witnesses
can run without a real browser.

## Demos

| Demo | Crate | Notes |
| --- | --- | --- |
| In-browser ndn-rs (Dioxus + WebTransport) | [`crates/research/dioxus-demo/`](crates/research/dioxus-demo/) | Phase 4 deliverable; see [`docs/wiki/src/getting-started/browser-demo.md`](docs/wiki/src/getting-started/browser-demo.md). Pure Rust→WASM (no JS), uses [`BrowserWebTransportFace`](crates/faces/ndn-face-webtransport-wasm/) and [`ndn-runtime::default_runtime`](crates/foundation/ndn-runtime/src/lib.rs). Witnesses live at `testbed/tests/browser/dioxus_demo_*.spec.ts`. |

## Design Docs

| Document | Contents |
|---|---|
| [`docs/architecture.md`](docs/architecture.md) | Design philosophy, key decisions, task topology |
| [`docs/tlv-encoding.md`](docs/tlv-encoding.md) | varu64, TlvReader, partial decode, COBS |
| [`docs/packet-types.md`](docs/packet-types.md) | Name, Interest, Data, PacketContext |
| [`docs/pipeline.md`](docs/pipeline.md) | PipelineStage, Action, stage sequences |
| [`docs/forwarding-tables.md`](docs/forwarding-tables.md) | FIB, PIT, Content Store implementations |
| [`docs/faces.md`](docs/faces.md) | Face trait, task topology, all face types |
| [`docs/strategy.md`](docs/strategy.md) | Strategy trait, BestRoute, measurements |
| [`docs/engine.md`](docs/engine.md) | ForwarderEngine, EngineBuilder, tracing |
| [`docs/security.md`](docs/security.md) | Signing, trust schema, SafeData |
| [`docs/ipc.md`](docs/ipc.md) | Transport tiers, chunked transfer, service registry |
| [`docs/discovery.md`](docs/discovery.md) | NDN AutoConfig, neighbor liveness probe, service discovery |
| [`docs/protocols/routing.md`](docs/protocols/routing.md) | DVR algorithm, static routes, RIB lifecycle |
| [`docs/wireless.md`](docs/wireless.md) | Multi-radio, nl80211, wfb-ng |
| [`docs/compute.md`](docs/compute.md) | In-network compute levels |
| [`docs/spsc-shm-spec.md`](docs/spsc-shm-spec.md) | Shared memory ring buffer spec |
