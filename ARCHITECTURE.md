# Architecture

> **Notice: primarily AI-authored, not yet proven correct.** The
> code described below is primarily written by an AI coding
> assistant and contains spec-compliance bugs catalogued in the
> internal audit log. Architectural *intent* is described here;
> actual *behaviour* may not match until the audit findings are
> resolved. See the
> [honest spec-compliance summary](docs/wiki/src/reference/spec-compliance.md)
> and [`testbed/EXPECTED_FAILURES.md`](testbed/EXPECTED_FAILURES.md).
> Do not cite this document as evidence of wire-level NDN
> compatibility.

NDN-RS models Named Data Networking as **composable async pipelines with trait-based polymorphism** — not class hierarchies. The engine is a library, not a daemon.

## Scope policy

Every crate in the workspace has one of four scope buckets, recorded
in each crate's `Cargo.toml` `[package.metadata.scope]` field. `spec`
and `extension` crates live flat under `crates/`; `tooling/` and
`draft/` remain as subdirectories:

- **`spec`** — implements an authoritative NDN community spec
  (Packet Format v0.3, NFD architecture, NDNCERT 0.3, did:ndn,
  NLSR, SVS, Certificate Format v2, SafeBag). Witness-first;
  cross-referenced; reverify-recipe per the existing audit
  conventions.
- **`extension`** — pragmatic engineering without a spec basis:
  browser-tier transports, IndexedDB PIB, ACME, simulation,
  embedded/mobile ports, FFI bindings.
- **`tooling`** — operator-facing CLIs and shared tool libs;
  CLI surface stable between releases.
- **`draft`** — author-led, exploratory; compiles + honest README
  is the bar.

Dependency-direction rule (`draft` → `tooling` → `extension` →
`spec`): a `spec` crate may not depend on anything to its right.
Honored by convention today; a future commit will add a
workspace-level lint.

## Crate Map

Crates are organised by **scope**, recorded per crate in
`[package.metadata.scope] classification` (all crates live flat under
`crates/`; the former `spec/` and `extension/` directories were removed).
The dependency-direction rule still holds: `draft` → `tooling` →
`extension` → `spec`. A `spec`-scope crate may not depend on anything to
its right.

```
scope = spec   (flat under crates/)   NDN community specs implemented faithfully
  ndn-tlv                       TlvReader, TlvWriter, varu64 — no_std
  ndn-foundation-types          Name, NameComponent, canonical Ord — shared with downstream NDN-stack crates
  ndn-packet                    Interest, Data, Nack (Packet Format v0.3) — lazy decode, no_std
  ndn-transport                 Transport + LinkService traits, Face struct
                                (NFD-style split), FaceId, FaceTable,
                                StreamFace, TlvCodec
  ndn-store                     NameTrie, Fib, PIT, ContentStore (LruCs/ShardedCs/FjallCs), DeadNonceList
  ndn-safebag                   SafeBag (cert + PKCS#5-encrypted key) — wasm-buildable carve-out of safe_bag.rs
  ndn-face-native                     Feature-gated native face types (UDP, TCP, WebSocket, Unix, SHM,
                                serial, ethernet, virtual; BLE central via `ble://` + peripheral
                                via `[listeners.ble]`, NDNts web-bluetooth GATT profile)
  ndn-face-webtransport         Server-side WebTransport listener (HTTP/3 + QUIC datagrams)
  ndn-strategy                  BestRoute, Multicast, ASF, composed strategies
  ndn-security                  KeyChain, Signer/Verifier, TrustSchema, Validator, SafeData
  ndn-engine                    ForwarderEngine, EngineBuilder/WasmEngineBuilder, pipeline, task topology
  ndn-app                       Application API: Consumer, Producer, Subscriber
  ndn-ipc                       ForwarderClient, BlockingForwarderClient, chunked transfer
  ndn-discovery, ndn-discovery-core
                                NDN AutoConfig, per-neighbor probe, SVS service discovery
  ndn-routing                   StaticProtocol, DvrProtocol, NlsrProtocol
  ndn-sync                      Dataset sync: SVS, PSync
  ndn-did                       NDN-native Decentralised Identifiers (W3C DID + did:ndn method)
  ndn-cert                      NDNCERT 0.3 — INFO/NEW/CHALLENGE + IssuancePolicy hook + challenge attestations
  ndn-identity                  Bridges KeyChain + DID + NDNCERT

scope = extension   (flat under crates/)   Pragmatic engineering, no NDN spec basis
  ndn-runtime                   Spawn/Sleep/Now trait abstraction; TokioRuntime / WasmRuntime
  ndn-acme                      ACME (RFC 8555) DNS-01 for the WT listener
  ndn-config                    TOML config + NFD management protocol
  ndn-pib-idb                   IndexedDB-backed PIB (browser persistence)
  ndn-face-webtransport-wasm    Browser-side WebTransport client face
  ndn-face-webrtc               Peer-to-peer datachannel face (browser-as-peer)
  ndn-face-shared-worker        Per-origin SharedWorker face (one engine across tabs)
  ndn-face-webble               Browser-side Web Bluetooth central face (dials NDN-BLE peripherals)
  ndn-rtc-signaling-relay       HTTP rendezvous server for browser↔browser WebRTC
  ndn-sim                       SimFace, SimLink, topology builder, event tracer
  ndn-wasm                      In-browser simulation via wasm-bindgen
  ndn-strategy-wasm             Hot-loadable WASM forwarding strategies
  ndn-embedded                  Minimal no_std forwarder for bare-metal MCUs
  ndn-mobile                    Android/iOS forwarder with AppFace IPC
  ndn-dashboard                 Dioxus desktop / web mgmt UI; runtime profile selection
                                across ndn-fwd / NFD / YaNFD; in-page engine via
                                `--features browser-engine` + `?engine=local`
  ndn-dashboard-next            Repo-split-ready rewrite scaffold with browser-first
                                deployment, compact responsive operator UI,
                                Operations Home entry spine, typed attach/probe
                                adapters, dashboard run / attach state /
                                engine ownership lifecycle models, capability profiles,
                                compact Trust security cockpit and dialog view models with ndn-security/identity snapshot adapters,
                                TOFU adoption, NDNCERT enrollment, validation/DID framing,
                                Observe/Tools slices, read-only Engine
                                dataset view models, live desktop Observe span
                                fetch/OTLP decode, span tree/PIT fan-out view
                                models, trace-correlated log evidence, bridge
                                export posture, configurable Tools workflow
                                adapters with focused run management,
                                mutation preflight gates, typed mutation
                                replay, first-screen attach controls,
                                focused Start Router workflow with structured
                                config/TOML/preset/diff handling, local
                                ndn-fwd launch/stop controls, live desktop face, route,
                                strategy, CS, and lifecycle mutation adapters, and
                                NFD / YaNFD compatibility
  ndn-python                    PyO3 Python bindings
  ndn-boltffi                   BoltFFI — Kotlin/JVM and Swift bindings
  ndn-compute                   In-network compute: ComputeService (tiered API),
                                ComputeFace, ComputeRegistry, ComputeHandler
  ndn-coding                    Network coding (F1 FEC): CodedProducer / CodedFetcher
                                endpoint API, GF(2^8) K-of-N codec, coding policy table
  ndn-abe                       Attribute-based encryption: CP-ABE (BSW) +
                                MA-ABE (AW11) via rabe (BN-254); versioned
                                NDN-TLV AbeCiphertext container. One-to-many
                                confidentiality tier above the ndn-crypto-core
                                AEAD baseline; producer / capable-node only

crates/tooling/                 Operator-facing tools and shared tool libs
  ndn-tools-core                Embeddable tool logic (ping, iperf, peek, put)
  dioxus-demo                   In-browser demo (TransitHost/Peer + JoinClient + SharedClient)

crates/draft/                   Author-led, no stability promise
  ndn-research                  FlowObserverStage, FlowTable, ChannelManager (nl80211)

binaries/ (flat)                Standalone executables
  ndn-fwd                       The forwarder (NFD-comparable; TOML config, management socket)
  ndn-fwd-tokens                Invite-token mint + QR codes for onboarding-link UX
binaries/tooling/               Operator CLIs
  ndn-tools                     ndn-peek, ndn-put, ndn-ping, ndn-iperf, ndn-sec, …
  ndn-bench                     Throughput + latency benchmarks
  did-ndn-driver                DIF Universal Resolver target for did:ndn
  enroll-ndncert                NDNCERT enrollment client

deploy/                         Operator-facing self-host bundle
  docker-compose.yml            ndn-fwd + signaling-relay + opt-in watchtower
  examples/ndn-fwd.example.toml          Annotated config template (WT+ACME pre-filled)
  install.sh, backup.sh         Interactive installer + cron-friendly backup

testbed/                        Multi-forwarder compliance + Playwright browser tests
  tests/audit/*.sh              Spec-compliance witness scripts (exit 1 today / 0 after)
  tests/browser/*.spec.ts       Phase-6/7/onboarding witnesses (Chromium-only)

examples/                       Documentation-grade examples (strategy, discovery, BLE)
```

## Key Abstractions

| Trait / Type | Crate | Role |
|---|---|---|
| `Face` | ndn-transport | Async send/recv over any transport (`Transport` + `LinkService` composition; see [Face system](#face-system) below) |
| `LinkServiceFeature` | ndn-transport | Per-LP-frame extension point — Reliability, CongestionMarking, TraceContext, IncomingFaceId, … |
| `FaceSink` | ndn-transport | Seam between face *provisioning* (interface enumeration, auto-multicast, hotplug — `ndn-face-native::provision`) and the engine that owns the face table; implemented by `ForwarderEngine`, so any embedding engine reuses the same provisioner |
| `PipelineStage` | ndn-engine | Single processing step; returns `Action` |
| `Strategy` | ndn-strategy | Forwarding decision per Interest |
| `ContentStore` | ndn-store | Pluggable cache backend |
| `KeyChain` | ndn-security | Identity, signing, and trust anchors; `--identity`/`--pib` flags in ndn-ctl |
| `Signer` / `Verifier` | ndn-security | Cryptographic operations; dispatched on `SignatureType` (RSA/ECDSA/HMAC/Digest/BLAKE3) |
| `DiscoveryProtocol` | ndn-discovery | Neighbor/service discovery |
| `RoutingProtocol` | ndn-routing | RIB population from routing algorithms |
| `ForwarderClient` | ndn-ipc | App-to-forwarder IPC (async or blocking) |
| `ComputeHandler` | ndn-compute | Named function execution |
| `CodedProducer` / `CodedFetcher` | ndn-coding | End-to-end K-of-N FEC over named Data |

## Pipeline Flow

```
Interest: FaceCheck → TlvDecode → CsLookup → PitCheck → Strategy → Dispatch
Data:     FaceCheck → TlvDecode → PitMatch  → Validation → CsInsert → Dispatch
```

`PacketContext` passes **by value** — ownership transfer makes short-circuits compiler-enforced. Each stage returns `Action`: `Continue`, `Send`, `Satisfy`, `Drop`, or `Nack`.

`ValidationStage` sets `ctx.verified = true` on the valid path. `CsInsertStage` gates on `ctx.verified` — unverified Data is never cached. Local-face Data is trusted by the OS-level IPC credential and also sets `ctx.verified`. When `validator_enabled = false`, the validator is permissive and still sets `ctx.verified` so the CS admission invariant holds in dev mode.

## Core Data Structures

- **FIB** — `NameTrie` with per-node `RwLock`; concurrent longest-prefix match
- **PIT** — `DashMap<PitToken, PitEntry>`; sharded, no global lock on hot path; PIT key tuple is `(LogicalName, ForwardingHint, PitKeyDiscriminator)` where the discriminator separates classical from persistent-attach entries (see substrate doctrine below)
- **Content Store** — trait-based; `LruCs` (in-memory), `ShardedCs` (parallel), `FjallCs` (disk)
- **Strategy Table** — name trie mapping prefixes to `Arc<dyn Strategy>`
- **SubscriptionRequest** — `ndn-packet` sub-TLV (type `0x230`) inside `ApplicationParameters`; enables persistent Interests that survive multiple Data deliveries; degrades gracefully on unsigned or unvalidated Interests

### PIT substrate-extension doctrine

ndn-rs deliberately diverges from NFD-spec PIT semantics on three
points to support persistent-attach subscribers. The decisions are
recorded in the internal substrate-extension PIT doctrine.

- **Universal strip-at-insert.** PIT and CS keys remove a trailing
  `ParametersSha256DigestComponent` (`0x02`) or
  `ImplicitSha256DigestComponent` (`0x01`) symmetrically on both
  sides. PSDC is *not* a multiplexing key in ndn-rs. Future
  signed-Interest RPC patterns must disambiguate concurrent calls
  via a request-id-class name component, not via
  `ApplicationParameters` digest. All current callers (`MgmtClient`,
  NDNCERT) already comply.
- **Marker gates persistence only.** `SubscriptionRequest` is the
  substrate marker. It installs `PersistentState` on the in-record
  and routes the entry through `PitKeyDiscriminator::PersistentAttach`,
  so marker-bearing and non-marker Interests at the same logical
  name occupy distinct entries. The marker does not gate
  strip-at-insert (which is universal).
- **Per-`InRecord` credit.** `PersistentState` lives on each
  `InRecord`, not on the entry. Each subscriber owns its own
  credit pool, deadline, and lifecycle. Trust-model consequence:
  revocation, expiry, and ACL evaluation are per-subscriber.
- **Replay guard is the integrity floor.** Once PSDC is no longer
  a multiplexing key, the `ndn_security::ReplayGuard` (per-key
  nonce/timestamp/seq-num LRU) is structurally required to prevent
  replayed signed Interests from coalescing into one PIT entry.
  Both `EngineBuilder::build()` and `WasmEngineBuilder::build()`
  wire it by default (`ReplayGuardConfig::default()` is `enabled,
  per_key_capacity=64, monotonic=false`).  Wasm engines forward
  signed Interests (NDNCERT in-browser, dashboard mgmt) and need
  the same integrity floor as native.  `monotonic=false` is the safe default because
  legitimate signed-Interest emitters re-attach after clock skew,
  device sleep, or process restart; hardened deployments can opt
  into `ReplayGuardConfig::monotonic()`.  Disabling the guard via
  `EngineBuilder::replay_guard_disabled()` is a test-only escape
  hatch.

## Face system

Each face is a `Transport` (raw bytes — UDP, TCP, Shm, InProc, Ethernet,
WebTransport, …) paired with a `LinkService` (NDNLPv2 framing, runtime
options, per-LP-frame feature pipeline). The `Face = Transport + LinkService`
split mirrors NFD's `daemon/face/face.hpp`.

Two `LinkService` impls ship: `PassthroughLinkService` for local-scope faces
(no LP framing; carries in-process source-face provenance) and
`LpLinkService` for non-local faces (LP-wraps every outbound packet; runs the
feature pipeline below).

**The default `LpLinkService` feature pipeline:**

| Order | Feature                     | Owns                                                    |
| ---   | ---                         | ---                                                     |
| 1     | `FragmentationFeature`      | LP fragmentation policy.                                |
| 2     | `ReassemblyFeature`         | Reassembly buffers on ingress.                          |
| 3     | `LocalFieldsFeature`        | Gate for `IncomingFaceId` egress stamping.              |
| 4     | `IncomingFaceIdFeature`     | Stamps source face id when LocalFields bit on.          |
| 5     | `NackFeature`               | Nack-on-ingress / passthrough on egress.                |
| 6     | `TraceContextFeature`       | LP `TraceContext` (0x520) codec; Phase-3 OTel hook.     |
| 7     | `ReliabilityFeature`        | NDNLPv2 reliability state machine — runtime ON/OFF.     |
| 8     | `CongestionMarkingFeature`  | CoDel egress marking; emits LP `CongestionMark` (0x340). |

**Runtime knobs**: `LinkService::apply(FaceOption)` flips per-feature
switches; `Transport::set_send_mtu` / `set_persistency` mutate transport-
level state. The `faces/update` mgmt handler dispatches each option to its
right home and surfaces failure with a named-field error body
(`field=<option> reason=<machine-readable>`). Status codes:

- `200 OK` — applied.
- `400 BAD_PARAMS` — value out of range.
- `404 NOT_FOUND` — no such face.
- `409 CONFLICT` — option exists but is immutable on this face / transport.
- `423 LOCKED` — management-face protection (you can never do this from
  this role; distinct from `401 UNAUTHORIZED`).
- `503 SERVICE_UNAVAILABLE` — transport / LinkService doesn't support it.

**Face notifications** publish on `/localhost/nfd/faces/notifications`.
`FaceEventKind = 0xC1` codepoints:

| Kind  | Variant                | NFD?    |
| ---   | ---                    | ---     |
| 1     | `Created`              | ✓       |
| 2     | `Destroyed`            | ✓       |
| 3     | `Up`                   | ✓       |
| 4     | `Down`                 | ✓       |
| 5     | `MtuChanged`           | ndn-rs  |
| 6     | `PersistencyChanged`   | ndn-rs  |
| 7     | `ReliabilityBackoff`   | ndn-rs  |
| 8     | `CongestionMark`       | ndn-rs  |
| 9     | `OptionRefused`        | ndn-rs  |

NFD clients ignoring kind > 4 see the lifecycle subset; ndn-rs clients
(`ndn-ctl`, `ndn-dashboard`) read every kind.

References: [`docs/wiki/src/operations/faces.md`](docs/wiki/src/operations/faces.md)
(operator guide), [`docs/wiki/src/design/link-service.md`](docs/wiki/src/design/link-service.md)
(design reference).

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

## Observability

ndn-fwd ships an OpenTelemetry-compatible span pipeline. The substrate is
**NDN**, not OTLP/gRPC: completed `tracing` spans are encoded as OTLP `Span`
protobufs and published as Data under a configurable prefix (default
`/localhost/nfd/observability`). Consumers — the dashboard, an `ndn-ctl
trace` CLI, or a small `ndn-otel-bridge` sidecar that forwards to standard
OTel backends — Interest by trace_id / span_id. PIT aggregation, CS caching,
NAC, and per-span signing all apply at no extra cost.

The publisher lives in
[`crates/ndn-observability/`](crates/ndn-observability/); the
`tracing::Subscriber` Layer is attached during
[`init_tracing`](binaries/ndn-fwd/src/tracing_init.rs) when
`[observability] publish_to_ndn = true` in the forwarder TOML. Cross-router
trace stitching uses the [`TraceContext` LP TLV](crates/ndn-packet/src/lp/trace_context.rs)
(type `0x520`, 33-byte value matching the W3C trace-context binary form
plus an 8-byte single-hop timestamp); see
[`docs/wiki/src/operations/opentelemetry.md`](docs/wiki/src/operations/opentelemetry.md)
for the operator guide.

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
[`ndn-runtime`](crates/ndn-runtime/) `Spawn`/`Sleep`/`Now` trait
abstraction. The wasm-safe trait
shapes used by the engine — `DiscoveryProtocol`, `DiscoveryContext`,
`NeighborTable`, scope helpers — live in
[`crates/ndn-discovery-core/`](crates/ndn-discovery-core/);
[`ndn-discovery`](crates/ndn-discovery/) re-exports them and adds
the native-only protocols (autoconfig, gossip, ether-ND, probe,
service-discovery). On wasm `ndn-engine` drops `ndn-security` (pulls
`ring`) entirely and substitutes a permissive [`ValidationStage`
stub](crates/ndn-engine/src/stages/validation_stub.rs); the
[`builder`](crates/ndn-engine/src/builder.rs) is also
non-wasm-only, so wasm callers construct `ForwarderEngine`
programmatically.

The browser-side
WebTransport client face lives in
[`crates/ndn-face-webtransport-wasm/`](crates/ndn-face-webtransport-wasm/);
the wiki page [`transports/webtransport-browser`](docs/wiki/src/transports/webtransport-browser.md)
walks through wiring it into a Rust→WASM application. The crate compiles
on both targets — wasm32 uses `xwt-web` (`web-sys::WebTransport`), other
targets use `xwt-wtransport` (`quinn` + `wtransport`) so loopback witnesses
can run without a real browser.

## Demos

| Demo | Crate | Notes |
| --- | --- | --- |
| In-browser ndn-rs (Dioxus + WebTransport) | [`crates/tooling/dioxus-demo/`](crates/tooling/dioxus-demo/) | Phase 7: full `ForwarderEngine` (PIT, FIB, CS, dispatcher, pipeline) running in the browser via [`WasmEngineBuilder`](crates/ndn-engine/src/wasm_builder.rs) — same code path as native `ndn-fwd` modulo `ValidationStage::disabled`. Tab-side `BrowserWebTransportFace`; SharedWorker hosts the engine ([Phase 6](docs/wiki/src/transports/shared-worker.md)). Pure Rust→WASM. Witnesses: `testbed/tests/browser/{dioxus_demo,sharedworker_cache_hit}_*.spec.ts`. See [`docs/wiki/src/transports/browser-as-forwarder.md`](docs/wiki/src/transports/browser-as-forwarder.md). |

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
| [`docs/compute.md`](docs/compute.md) | In-network compute: tiered API, determinism, wire spec |
| [`docs/coding.md`](docs/coding.md) | Network coding: F1 FEC, CodedProducer/CodedFetcher, wire spec |
| [`docs/spsc-shm-spec.md`](docs/spsc-shm-spec.md) | Shared memory ring buffer spec |
