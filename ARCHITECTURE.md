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

Every crate in the workspace has one of the scope buckets recorded
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
- **`research`** — legacy label for exploratory research crates;
  treated like `draft` for release-boundary decisions until it is
  either promoted or renamed.

Dependency-direction rule (`draft` → `tooling` → `extension` →
`spec`): a `spec` crate may not depend on anything to its right.
Honored by convention today; a future commit will add a
workspace-level lint.

For the first stable release, only the `spec` crates and the subset of
`tooling` needed to run and verify them are in the v0.1.0 stability
boundary. `extension`, `draft`, and `research` crates may build and
ship in the repository without carrying the same SemVer promise.

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
  ndn-store                     NameTrie, Fib, PIT, ContentStore (LruCs/ShardedCs/FjallCs/SqliteCs), DeadNonceList
  ndn-safebag                   SafeBag (cert + PKCS#5-encrypted key) — wasm-buildable carve-out of safe_bag.rs
  ndn-face                      Standard face types (NFD/ndnd set): UDP, TCP, Unix,
                                in-process/IPC, Ethernet (uni/multicast), callback/tap
  ndn-frame-io                  Backend-agnostic link-layer frame I/O (FrameIo trait, FrameFormat
                                framing, AF_PACKET + loopback backends) — substrate for the radio faces
  ndn-face-serial               Serial/UART face (COBS framing) — extension
  ndn-face-shm                  Zero-copy SPSC shared-memory IPC face (desktop Unix) — extension
  ndn-face-websocket            WebSocket face (browser-reachable peering) — extension
  ndn-face-bluetooth            BLE GATT central (`ble://`) + peripheral (`[listeners.ble]`) — extension
  ndn-face-afxdp                AF_XDP kernel-bypass Ethernet backend (Linux) — extension
  ndn-face-webtransport         Server-side WebTransport listener (HTTP/3 + QUIC datagrams)
  ndn-strategy                  BestRoute, Multicast, ASF, composed strategies
  ndn-security                  KeyChain, Signer/Verifier, TrustSchema, Validator, SafeData, Keyring/TrustContext
  ndn-engine                    ForwarderEngine, EngineBuilder/WasmEngineBuilder, pipeline, task topology
  ndn-app                       Application API: Node (unified entry: fetch/serve/object/publish/subscribe/query) over Consumer/Producer/Publisher/Subscriber/Queryable
  ndn-ipc                       ForwarderClient, BlockingForwarderClient, chunked transfer
  ndn-discovery, ndn-discovery-core
                                NDN AutoConfig, per-neighbor probe, NDNSD-style service discovery (announce + browse)
  ndn-routing                   StaticProtocol, DvrProtocol, NlsrProtocol
  ndn-sync                      Dataset sync: SVS (layered — notification core w/ suppression FSM + HMAC-signed Sync Interests + V2/V3 wire dialects → SvSync data plane w/ DataStore + windowed fetch/serve → SvsPubSub named pub/sub + MappingProvider late-join backfill), PSync (Full: bounded versioned-prefix IBF set w/ relay-capable learned names; Partial: asymmetric PartialProducer + Bloom-filter subscription consumer; large replies segmented through a shared windowed-transfer module)
  ndn-repo                      Persistent named-data repository (third-party durable custody, network-layer/app-agnostic), runnable as the `ndn-repo` daemon (`--features bin`, Unix-socket IPC). RepoCmd wire codec byte-compatible with ndnd (SyncJoin/SyncLeave/BlobFetch); RepoService demuxes a forwarder connection into command handling (reply RepoCmdRes), store serving (answers for a whole joined group), and per-group SVS ingestion. Pluggable DataStore — MemoryStore (ndn-sync) or on-disk FjallStore; `SvSync::ingest_publication`/`ingest_name` store raw wires (resume-aware: skip already-stored). **Fail-closed trust**: `Repo::with_validator` gates ingestion on an `ndn_security::Validator`, so the repo never durably re-serves data it can't authenticate. Distributed replication/failover (cf. a-thieme/repo) is a layer above.
  ndn-repo-cluster              Distributed coordination layer above ndn-repo (cf. a-thieme/repo features). Fully decentralised: nodes gossip heartbeats + job claims over an SVS coordination group and fold them into an identical, converging ClusterState; each runs the same deterministic, capacity-aware placement (lowest-utilisation live nodes are designated to reach replication_factor; excess claimants beyond the lowest-util keepers shed). A node failing → missed heartbeats → its claims stop counting → a survivor re-replicates. Pure coord core + TLV msg codec + ClusterNode tick/observe driver; multi-node simulation proves convergence + failover. Not a wire standard — composes above the ndnd-compatible single-node repo.
  ndn-did                       NDN-native Decentralised Identifiers (W3C DID + did:ndn method)
  ndn-cert                      NDNCERT 0.3 — INFO/NEW/CHALLENGE + IssuancePolicy hook + challenge attestations + BootstrapTicket/hub onboarding
  ndn-custodian                 Custodian trait (InPage/OsKeyring/Fob/BrowserExtension) + KeyId + CustodianSigner (Custodian→Signer adapter); wasm-safe (no PIB/sqlite) so dashboard/extension/mobile can use it
  ndn-identity                  Bridges KeyChain + DID + NDNCERT; re-exports ndn-custodian

scope = extension   (flat under crates/)   Pragmatic engineering, no NDN spec basis
  ndn-runtime                   Spawn/Sleep/Now trait abstraction; TokioRuntime / WasmRuntime
  ndn-acme                      ACME (RFC 8555) DNS-01 for the WT listener
  ndn-config                    TOML config + NFD management protocol
  ndn-pib-idb                   IndexedDB-backed PIB (browser persistence)
  ndn-face-webtransport-wasm    Browser-side WebTransport client face
  ndn-face-webrtc               Peer-to-peer datachannel face (browser-as-peer)
  ndn-face-shared-worker        Per-origin SharedWorker face (one engine across tabs)
  ndn-face-webble               Browser-side Web Bluetooth central face (dials NDN-BLE peripherals)
  ndn-face-monitor-wifi         802.11 monitor-mode raw-injection face (named-radio bearer; per-frame MCS, no association/ARQ)
  ndn-face-wifi-aware           Connectionless Wi-Fi Aware (NAN) coordination face (AP-less peer Wi-Fi);
                                NanBackend trait (platform radio) + LoopbackNanBus; follow-up MTU 255,
                                NDP-for-bulk by `request_ndp` (UdpFace); service pub/sub → routes
  ndn-face-ble-adv              Connectionless BLE advertising face (pairless broadcast, near-universal);
                                AdvBackend trait + LoopbackAdvBus; NDNLPv2 (245 B ext-adv) or NDNts (1-byte) framing
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
                                compact Operations command surface, typed attach/probe
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
                                config/TOML/preset/diff handling, auto-attach
                                for dashboard-started local routers, local
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
| `FaceSink` | ndn-transport | Seam between face *provisioning* (interface enumeration, auto-multicast, hotplug — `ndn-face::provision`) and the engine that owns the face table; implemented by `ForwarderEngine`, so any embedding engine reuses the same provisioner |
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
Nacks are treated as point-to-point feedback: the dispatcher suppresses
generated Nacks on multi-access/ad-hoc ingress faces, ignores incoming Nacks
from shared-medium faces, and skips Nack propagation to shared-medium
downstream in-records.

`ValidationStage` sets `ctx.verified = true` on the valid path. `CsInsertStage` gates on `ctx.verified` — unverified Data is never cached. Local-face Data is trusted by the OS-level IPC credential and also sets `ctx.verified`. When `validator_enabled = false`, the validator is permissive and still sets `ctx.verified` so the CS admission invariant holds in dev mode.

## Core Data Structures

- **FIB** — `NameTrie` with per-node `RwLock`; concurrent longest-prefix match
- **PIT** — `DashMap<PitToken, PitEntry>`; sharded, no global lock on hot path; PIT key tuple is `(LogicalName, ForwardingHint, PitKeyDiscriminator)` where the discriminator separates classical from persistent-attach entries (see substrate doctrine below)
- **LP reassembly** — per-face `ReassemblyBuffer` keys pending fragments by
  `(endpoint_id, sequence)`. Shared-medium transports surface `FaceAddr`
  (UDP sender or MAC), which the dispatcher turns into stable nonzero endpoint
  ids before decode so overlapping fragment sequences from different senders do
  not collide.
- **Dead Nonce List** — engine-owned `DeadNonceList` retaining `(name_hash, nonce)` fingerprints after PIT erasure; `PitCheckStage` consults it before aggregation, while `PitMatchStage` and the PIT expiry task insert retiring nonces.
- **Content Store** — trait-based; `LruCs` (in-memory), `ShardedCs` (parallel), `FjallCs` (disk, `fjall` feature), `SqliteCs` (disk, bundled SQLite, `sqlite-cs` feature — the Android backend, where fjall's directory lock is unsupported). The two disk backends share the same NDN-lexicographic key encoding (`cs_keycodec`) so `CanBePrefix` lookups are range scans. Entries carry an absolute `stale_at` derived from `FreshnessPeriod`; `MustBeFresh` Interests miss stale entries at both the store and `CsLookupStage`, while non-`MustBeFresh` Interests may still use stale cached Data.
- **Unsolicited Data policy** — `DropAll` by default, with `AdmitLocal`, `AdmitNetwork`, and `AdmitAll` available for operators that want NFD-style opportunistic caching on shared media. Admitted unsolicited Data is cache-only and still must pass validation before CS insertion.
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

References: [`docs/wiki/src/reference/face-transports.md`](docs/wiki/src/reference/face-transports.md)
(operator catalog) and [`docs/wiki/src/guides/implementing-a-face.md`](docs/wiki/src/guides/implementing-a-face.md)
(extension guide).

### Connectionless named-radio faces & the multi-radio mobile node — *extension*

A family of faces carry NDN over **connectionless broadcast radios** where the
NDN *name* is the only addressing — no association, no pairing, no host
addresses: `ndn-face-wifi-aware` (Wi-Fi Aware / NAN, AP-less peer Wi-Fi),
`ndn-face-ble-adv` (BLE advertising, near-universal), `ndn-face-monitor-wifi`
(802.11 injection). Each reports `link_type() == AdHoc` and a small
`send_mtu`, so the `LpLinkService` fragments NDN across the radio's tiny frames
automatically; per-frame RSSI is published to a `SignalStore` for measured
strategies. The physical radio sits behind a **backend trait**
(`NanBackend`, `AdvBackend`) with a hardware-free `Loopback*Bus` for host
tests — the face logic is unit-tested without a radio, and a platform
(Android JNI, BlueZ, an MCU) supplies the radio by implementing the trait.

**Multi-radio is the default, not a mode.** A mobile node holds a *set* of
these faces at once (multicast + NAN + BLE + an uplink); they are not mutually
exclusive and fill each other's gaps (BLE everywhere + low power; Wi-Fi Aware
high-throughput). `ndn-mobile`'s `attach_wifi_aware` / `attach_ble` add a radio
at runtime (the radio is often only available after start), install a `/`
default route, and switch the node to `MulticastStrategy` — a mesh peer can't
know which radio reaches a given peer, so it fans every not-locally-served
Interest over all of them. Trust stays end-to-end: producers sign, the
forwarder *relays* (its data-path validation is permissive — it is not the
trust authority), and the end consumer verifies against a pinned cert.

`ndn-boltffi` exposes each radio as a two-way FFI seam: an app-implemented
`NdnNanBackend` / `NdnBleBackend` (engine → radio: broadcast/publish) plus
`NdnEngine::{nan_deliver_followup, ble_deliver_frame}` (radio → engine, since
opaque handles aren't passable across the FFI).

**Two-tier Wi-Fi Aware: coordination follow-ups + an NDP bulk path (extension).**
The named-radio faces above are connectionless and small-frame (NAN follow-ups
≤255 B, BLE advertisements ≤~245 B) — fine for presence, discovery, and small
Interest/Data, but lossy for multi-fragment objects. The high-throughput tier is
a **NAN NDP** (Network Data Path): a real IPv6 link-local Wi-Fi connection
between two peers, over which the node runs UDP. The platform negotiates the NDP
(`WifiAwareManager.requestNetwork` on Android), binds a UDP socket on the
resulting network, and hands the bound socket's fd + the peer's address to
`NdnEngine::attach_ndp_face` (fd-passing, like the seam's `mount_app_fd`). The
engine adopts it as a [`UdpFace`](crates/ndn-face) and adds a UDP-cost
(10) nexthop on the peer's `/ndn/node/<id>` prefix, so the measured best-route
strategy (below) moves the peer's bulk traffic onto the reliable, fast NDP link
while the connectionless coordination radios stay for discovery + fallback. The
Rust seam (`NanBackend::request_ndp` → `NdpLink` → `UdpFace::from_socket`) is
exercised by `crates/ndn-face-wifi-aware/tests/ndp_bulk.rs`; on Android the
`NanRadio` runs the data-path negotiation (a node-id tiebreak picks the publisher
as server/responder and the subscriber as client/initiator, per the Android
Wi-Fi Aware guide). A NAN data path **tears down when idle**, so the engine runs
a periodic **keepalive** on the NDP `UdpFace` to keep it warm; on a genuine loss
the platform's `onLost` calls `NdnEngine::detach_ndp_face` →
`ForwarderEngine::remove_face`, which drops the face and its FIB nexthops so
routing falls back to the coordination radios (rather than black-holing the stale
low-cost nexthop) until the NDP re-establishes.

**Wi-Fi Direct bulk upgrade (extension).** The NAN NDP is duty-cycled, so its
throughput plateaus (~90 Mbps on Wi-Fi 5 hardware) — RTT-bound, not
window-bound. The higher-ceiling tier is **Wi-Fi Direct**: discover over Wi-Fi
Aware / BLE, then form a Wi-Fi P2P group (5 GHz) for bulk — the same
discover-then-upgrade pattern as Quick Share / AirDrop. It stays data-centric:
once the group forms it is just a multi-access IP subnet (the group owner runs
DHCP on `192.168.49.0/24`), so the host-centric group-owner election lives
*below* the Face. Above it, `FaceKind::WifiDirect` faces carry only names —
a unicast [`UdpFace`](crates/ndn-face) for 1:1 bulk (full MCS rate;
`LinkProfile` cost 8, preferred over the NDP/LAN UDP cost 10) attached via
`attach_wifi_direct_face`, or a `MulticastUdpFace` for one-to-many over the
group's broadcast domain (`MulticastStrategy` + PIT aggregation) via
`attach_wifi_direct_multicast_face`. No new transport code — the existing UDP
faces re-tagged to the real radio (`UdpFace::with_kind`). The same shape maps to
a Wi-Fi SoftAP "portable router" and to Apple's Wi-Fi Aware framework on iOS
(the same NAN standard behind `NanBackend`).

**Measured best-route (extension).** The per-peer `/ndn/node/<id>` routes use
`MeasuredStrategy` rather than plain `BestRoute`: it ranks nexthops by a blend of
the static [`LinkProfile`](crates/ndn-transport) cost *prior* and live signals —
prefix-level EWMA RTT (`MeasurementsTable`) plus per-face `LinkSignals` (link
RTT, throughput, congestion, retransmit rate, RSSI from the
[signals](#cross-layer-signals) layer). With no samples yet it is identical to
`BestRoute` (static cost only); as measurements accrue it shifts traffic toward
the better-performing face — preferring a warm NDP, but moving off it if it
degrades even though its static cost is lower.

**Discovery conventions (extension).** Nearby-peer discovery is tiered:

- **Tier-1 presence** — each node beacons a tiny `{id, label}` over its broadcast
  faces (Wi-Fi Aware service-info, BLE advertisement). Wire form: UTF-8 `id`, a
  `\n`, then UTF-8 `label`; neither contains a newline. `id` is a stable
  per-device id, `label` a human name (e.g. the device model).
- **Routable node prefix** — a peer with id `X` is reachable at `/ndn/node/X`.
  Discovery installs a cost-aware route to it (see *cost-aware forwarding* above),
  and a node's served content carries a `ForwardingHint` to its own
  `/ndn/node/<id>` so it routes there over the best face.
- **Peer dataset** — the node serves the observed-peer table the NDN-native way
  at `/localhost/discovery/peers` (localhost-scoped JSON: `self` + `peers[]` with
  `label`, `faces`, `rssi`, `age_ms`); a leaf fetches that name to render a
  "nearby" list. Trust (the operator cert) is resolved on demand when a peer is
  tapped — not carried per beacon.

**Tap-to-share (extension).** Sharing a file to a tapped peer composes the
routable node prefix with NDNLPv2 `ForwardingHint`, so content keeps an
*identity-stable* name while still routing to a specific peer (`ndn-boltffi`'s
*offer board*, served by the leaf over the seam):

- **Rendezvous (routable).** The offerer serves its certificate at
  `/ndn/node/<id>/cert` (the TOFU pin target) and a signed JSON **manifest** at
  `/ndn/node/<id>/offers` (each entry: display name, MIME, size, and the file's
  routable object name). Both sit under the node prefix, so the cost-aware
  per-peer route reaches them with no hint.
- **Content (identity-stable).** Each offered file is a signed RDR object under
  the offerer's *own identity*, `/<identity>/file/<fileId>` — location-independent
  (forward-compatible with a durable repo), not coupled to the node id.
- **Steer + strip.** The consumer fetches a file with `ForwardingHint =
  /ndn/node/<peerId>`. Forwarders route toward that delegation (the per-peer
  route) until the Interest reaches the producer's node, which has declared
  `/ndn/node/<id>` in its **`NetworkRegionTable`** (at discovery start) — there
  the hint is stripped and the Interest forwarded by name to the local producer.
  Verification is end-to-end against the pinned cert; the forwarder only relays.

*Tracked refactor:* this presence table duplicates `ndn_discovery_core::NeighborTable`
(which already tracks `node_name` + per-face reachability + a quality metric);
the intended de-dup is to make the dataset a view over that one shared table,
adding only the human label, and to install the discovery route via the general
`DiscoveryProtocol`/`add_fib_entry` path rather than a mobile-specific helper.

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
The audit witnesses now exercise RSA/ECDSA with valid signatures, wrong
signatures, malformed keys, and validator dispatch instead of source scans.
Certificate Format v2 names (`/<identity>/KEY/<KeyId>/<IssuerId>/<Version>`) are
enforced by `KeyChain::ephemeral` and `ndn-sec keygen`.
SafeBag export/import uses CertificateV2 plus encrypted PKCS#8 private keys;
the encrypted-key profile is PBES2 with PBKDF2-HMAC-SHA256 and AES-256-CBC so
reference `ndnsec import/export` can round-trip ndn-rs SafeBags.
`ConfigPolicy` models the release-relevant configuration-validator behavior:
ordered first-match rules, no-match denial, exact KeyLocator-prefix checks, and
hierarchical checking. It is not a full ndn-cxx `validator.conf` parser.
LVS binary schemas with unsupported user functions fail closed: import rejects
them for trust-schema enforcement, and direct model/policy evaluation treats the
unsupported function constraint as non-matching.

Management command Interests are signed by `ndn-ipc` before they are LP-wrapped:
the default localhost path emits DigestSha256 over the decoded spec signed
region, and `MgmtClient::with_signer` emits key-backed command Interests for
NFD `localhop_security` deployments.
Management dataset Interests are unsigned but set both CanBePrefix and
MustBeFresh: CanBePrefix matches versioned/segmented dataset Data, while
MustBeFresh prevents a cached management segment from hiding a just-applied
change such as a newly registered RIB entry.
Trust-anchor insertion fails closed on expired or not-yet-valid certificates:
invalid anchors do not enter the anchor set, cert cache, or PIB anchor store.

### TrustContext keyring (per-namespace dispatch)

A node holds a `Keyring` — a set of adopted `TrustContext`s, each binding a
`namespace` to its own anchor set and trust schema — rather than one flat
anchor pile. The `Validator` is keyring-backed and dispatches every packet to
the context selected by *its name's* namespace (longest-prefix match); it is
validated only against that context's schema **and** anchors, never "any
anchor I hold." Hierarchical contexts (the default) additionally enforce the
`keyLocator.isPrefixOf(name)` floor — the signing key's identity must prefix
the signed name — which closes the skeleton-key authorization gap (NFD #2856).
The flat-anchor API (`Validator::new` / `with_chain` / `add_trust_anchor` /
`set_schema`) targets an ambient root-namespace context, so existing
single-anchor callers are unchanged. A `TrustContext` is also a signed,
versioned NDN object (`/<ns>/32=trust-context/v=N`, TLV `0x0410–0x041F`); the
keyring refuses a strictly older version (anti-rollback). Onboarding lives in
`ndn-cert`: a `BootstrapTicket` (QR/deep-link fragment) carries the namespace + root
anchor *fingerprint*, and `adopt_with_tofu` is the only sanctioned path from
"received a context" to "trusted" — adoption is never automatic. The chain walk
also honours a context's `revocations`, so an issuing-CA compromise is
contained by a pulled context bump (no re-bootstrap).

## Routing

The `RoutingProtocol` trait populates the RIB. Three implementations ship:

- **`StaticProtocol`** — TOML-configured static routes.
- **`DvProtocol`** — ndn-dv distance-vector routing implemented to
  [`ndnd/dv/SPEC.md`](https://github.com/named-data/ndnd) (reference impl: ndnd, Go;
  *Distance-Vector Routing for Named Data Networking*, CoNEXT '24,
  DOI `10.1145/3680121.3699885`). Documented divergences from ndnd in
  `crates/ndn-routing/src/protocols/dv/mod.rs`. Trust modes: `insecure`
  (default, ndnd-compatible), `static`, `lvs`. A live ndnd-dv interop
  witness (mirroring G.04's shape) is not yet wired — the SPEC-compliance
  claim currently has no cross-implementation leg.
- **`NlsrProtocol`** — Named-data Link State Routing; implements the NDN testbed
  routing protocol. Runs `NeighborProbeProtocol` for liveness, PSync-based LSA flooding, and
  Dijkstra-based routing-table computation. Enabled via `[routing.nlsr]` in
  `ndnd.toml`. The G.04 Docker witness runs this implementation against C++
  NLSR and requires bidirectional route convergence; live interop status is
  tracked by the audit witnesses and
  [`testbed/EXPECTED_FAILURES.md`](testbed/EXPECTED_FAILURES.md).

The RIB computes FIB entries with NFD-style **CHILD_INHERIT/CAPTURE
inheritance** (`Rib::effective_nexthops`): a child prefix merges its own
routes with `CHILD_INHERIT` routes from ancestors, unless it or a nearer
ancestor `CAPTURE`s. **Readvertise** (`ndn-engine/src/readvertise.rs`,
NFD `rib/readvertise`) closes the loop the other way: a locally-originated
`rib/register` (app/client/static origin — never a routing-learned route, to
avoid announce loops) is pushed to a `ReadvertiseDestination`. `NlsrProtocol`
registers one and folds the readvertised prefixes into its own NameLSA,
re-originating (bumped seq) on change so peers learn an app's prefix without
manual config.

The self-learning strategy broadcasts discovery Interests when no route exists.
When Data returns with an LP `PrefixAnnouncement`, the engine validates the
signed announcement, installs a PrefixAnnouncement-origin route toward the
announcing face, and later Interests under that prefix forward on the learned
route. Tampered or untrusted announcements install no route.

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
[`docs/wiki/src/operations/logging.md`](docs/wiki/src/operations/logging.md)
for the current operator-facing logging and tracing guide.

## Testbed

`testbed/docker-compose.yml` spins up an `ndn-fwd` instance, a C++ NFD instance,
and a YaNFD instance on a `172.30.0.0/24` network plus an `interop` container
with ndn-cxx tooling. The interop image also carries targeted reference-side
fixtures such as the deterministic C++ PSync FullProducer used by the G.03
witness, reference NFD `nfdc` for management dataset decoding, plus the matching
ndn-rs `ndn-psync-consumer` CLI, `ndn-mgmt-response-verify` trust-anchor
witness, and `ndn-mgmt-notification-fetch` event-stream witness. NDNts coverage
uses `ndncat` on Node 24 and the image build smoke-checks the CLI so
runtime-package drift is caught before packet interop begins. Heavy reference
tool builds are capped by `NDN_TESTBED_BUILD_JOBS` (default `2`), and
`testbed/tools/up-g06-low-memory.sh` brings up the AutoConfig witness topology
sequentially for Docker Desktop hosts with limited VM memory. The harness
supports two test classes:

- **`testbed/tests/audit/<id>_<slug>.sh`** — per-finding witnesses. Each script
  exits 1 against a broken codebase and 0 after the fix. RUST-UNIT witnesses
  drive `cargo test`; INTEROP witnesses exchange packets across containers.
  Grep checks may remain as source-regression guards, but they are not sufficient
  evidence for protocol-compliance claims unless paired with behavioral or wire
  witnesses.
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
the face catalog [`docs/wiki/src/reference/face-transports.md`](docs/wiki/src/reference/face-transports.md)
summarises the WebTransport variants. The crate compiles
on both targets — wasm32 uses `xwt-web` (`web-sys::WebTransport`), other
targets use `xwt-wtransport` (`quinn` + `wtransport`) so loopback witnesses
can run without a real browser.

## Demos

| Demo | Crate | Notes |
| --- | --- | --- |
| In-browser ndn-rs (Dioxus + WebTransport) | [`crates/tooling/dioxus-demo/`](crates/tooling/dioxus-demo/) | Phase 7: full `ForwarderEngine` (PIT, FIB, CS, dispatcher, pipeline) running in the browser via [`WasmEngineBuilder`](crates/ndn-engine/src/wasm_builder.rs) — same code path as native `ndn-fwd` modulo `ValidationStage::disabled`. Tab-side `BrowserWebTransportFace`; SharedWorker hosts the engine. Pure Rust→WASM. Witnesses: `testbed/tests/browser/{dioxus_demo,sharedworker_cache_hit}_*.spec.ts`. This remains outside the v0.1.0 stable boundary unless promoted by release notes. |

## Design Docs

Current user-facing docs live in [`docs/wiki/src/`](docs/wiki/src/).
Pre-v0.1 design essays that were archived during the documentation
rewrite live under `.claude/docs-archive-pre-v0.1.0/` and
`.claude/wiki-archive-pre-v0.1.0/`; treat them as design history, not
current behavior.

| Document | Contents |
|---|---|
| [`docs/wiki/src/`](docs/wiki/src/) | Current mdBook: quickstarts, API tiers, operations, reference, release boundary |
| [`docs/wiki/src/reference/spec-compliance.md`](docs/wiki/src/reference/spec-compliance.md) | Reader-facing map to audit witnesses and release blockers |
| [`docs/wiki/src/releases/v0.1.0.md`](docs/wiki/src/releases/v0.1.0.md) | Candidate v0.1.0 stability boundary |
| [`docs/specs/`](docs/specs/) | ndn-rs-specific wire specs and extension TLVs |
| [`docs/compute.md`](docs/compute.md) | In-network compute: tiered API, determinism, wire spec |
| [`docs/coding.md`](docs/coding.md) | Network coding: F1 FEC, CodedProducer/CodedFetcher, wire spec |
| [`docs/abe.md`](docs/abe.md) | Attribute-based encryption extension notes |
| [`docs/cclf.md`](docs/cclf.md) | CCLF strategy notes |
| [`docs/doctrine/`](docs/doctrine/) | Design doctrine notes that are still intentionally retained |
