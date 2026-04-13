# Changelog

All notable changes are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Releases are tagged on `main` and published as [GitHub Releases](https://github.com/Quarmire/ndn-rs/releases).

For the narrative behind each release — design decisions, rejected approaches, and benchmarks — see the [Releases section of the wiki](https://quarmire.github.io/ndn-rs/wiki/releases/).

---

## [Unreleased]

### Added

- **LightVerSec (LVS) binary trust schema import** (#9). `TrustSchema` now
  has a `from_lvs_binary(&[u8])` constructor that parses the compiled LVS
  TLV binary format used by python-ndn, NDNts `@ndn/lvs`, and ndnd, plus
  a new `lvs_model()` accessor for inspecting the parsed graph. Supports
  `ValueEdge` (literal) and `PatternEdge` (captures) dispatch per the LVS
  spec, `SignConstraint` graph walks, and `ConstraintOption::Value` /
  `ConstraintOption::Tag` constraint options. User functions (`$eq`,
  `$regex`, …) parse cleanly but do not dispatch in v0.1.0 — any rule
  that depends on one will never match a packet, and the loaded schema
  raises its `LvsModel::uses_user_functions()` flag so strict callers
  can refuse to use it. Native `SchemaRule`s and an imported LVS model
  can coexist in a single `TrustSchema` — `allows()` checks both sources
  and returns `true` if either accepts. Binary format version
  `0x00011000` is accepted; other versions raise
  `LvsError::UnsupportedVersion`.

### Security

- **BLAKE3 signature types split into distinct plain and keyed codes** (#12).
  Previously `Blake3Signer` and `Blake3KeyedSigner` both emitted
  `SignatureType::Other(6)` on the wire, which is unsafe: an attacker could
  strip a keyed signature and substitute a plain BLAKE3 digest over forged
  content, and a verifier dispatching on type code alone would accept the
  forgery because both modes are indistinguishable in the TLV. The
  implementation now uses two distinct experimental codes —
  `SIGNATURE_TYPE_DIGEST_BLAKE3_PLAIN = 6` for plain digest and
  `SIGNATURE_TYPE_DIGEST_BLAKE3_KEYED = 7` for keyed — mirroring the
  existing NDN pattern (`DigestSha256` = 0 vs. `SignatureHmacWithSha256`
  = 4). The old `SIGNATURE_TYPE_DIGEST_BLAKE3` constant has been removed;
  external callers should import the new split constants.

  Both values remain **experimental** and require manual reservation on
  the [NDN TLV SignatureType registry](https://redmine.named-data.net/projects/ndn-tlv/wiki/SignatureType)
  before being considered stable. This is a one-time maintainer action
  tracked as part of #12.

### Fixed

- **BLE face wire format now matches NDNts and esp8266ndn exactly** (#10).
  The previous implementation used swapped CS/SC characteristic UUIDs, had
  typo'd byte suffixes, and prefixed oversized packets with a non-standard
  1-byte fragmentation header that neither NDNts nor esp8266ndn understand.
  The CS/SC UUIDs are now `cc5abb89-a541-46d8-a351-2f95a6a81f49` and
  `972f9527-0d83-4261-b95d-b1b2fc73bde4` (verified against yoursunny/NDNts
  and yoursunny/esp8266ndn upstream source), and oversized packets are
  fragmented with NDNLPv2 at the Face layer — the same code path used by
  UDP, multicast, and Ethernet faces. The NDN-BLE protocol itself defines
  no framing; this matches the NDNts README which states that BLE "can be
  used with existing NDN fragmentation schemes such as NDNLPv2."

- **Docker image now publishes a `:latest` tag on main** (#11). `docker pull
  ghcr.io/quarmire/ndn-fwd` (without an explicit tag) now resolves to the
  current main build. Once a semver tag is pushed, `:latest` tracks that
  release via `docker/metadata-action`'s `latest=auto` flavor.

### Docs

- **Wiki spec-compliance page**: fixed the mdbook `edit-url-template`
  double-`src/` 404, replaced the dead NDNCERT 0.3 link, corrected the
  misattributed NFD Developer Guide reference (now NDN-0021), reframed
  NDN-0001 as the architecture vision rather than a forwarding spec, and
  added a "Not Yet Implemented" section documenting the partial forwarding
  hint and PIT token support (#13 — link/reference half).

---

## [0.1.0] — 2026-04-11

Stable 0.1.0. Finalizes all public names, fills ergonomic gaps, and wires
remaining stub features. Detailed narrative in the
[0.1.0 wiki page](https://quarmire.github.io/ndn-rs/wiki/releases/v0-1-0.html).

### Breaking Changes

- **`ndn-router` binary renamed to `ndn-fwd`** — update scripts and Docker images.
- **`ndn-packet` default features** changed from `["std"]` to `[]`. Downstream
  crates that rely on the old default must add `features = ["std"]` to their
  `ndn-packet` dependency.
- **`AppError` variants** replaced with typed enum — `AppError::Engine(anyhow)` is
  gone; use `Connection(ForwarderError)`, `Closed`, `Protocol(String)` instead.
- **`Producer::serve`** handler signature changed from `Fn(Interest) -> Option<Bytes>`
  to `Fn(Interest, Responder) -> Future<Output = ()>` — use `Responder` to reply.
- **Crate consolidation** — `ndn-face-net`, `ndn-face-local`, `ndn-face-serial`,
  `ndn-face-l2`, and `ndn-pipeline` are removed. Use `ndn-faces` (feature-gated
  modules) and `ndn-engine::pipeline` respectively.
- **`RouterClient` / `RouterError`** renamed to `ForwarderClient` / `ForwarderError`.
- **`AppFace` / `AppHandle`** renamed to `InProcFace` / `InProcHandle`.

### Added

#### API ergonomics (ndn-app)
- `Responder` — single-use reply builder for `Producer::serve` handlers; supports
  `respond()`, `respond_bytes()`, and `nack(reason)`.
- `Consumer::fetch_all()` — parallel multi-name fetch.
- `Consumer::fetch_with_retry()` — retry with exponential backoff.
- `Consumer::fetch_segmented()` — auto-segmented fetch (FinalBlockId-aware).
- `Consumer::get_verified()` — fetch + signature verification in one call.
- `Producer::publish_large()` — auto-segments large content via `ChunkedProducer`.
- `Subscriber::connect_psync()` / `connect_psync_with_config()` — PSync variant.

#### Security (ndn-security)
- `KeyChain::trust_only(prefix)` — build a validator trusting only one anchor.
- `KeyChain::sign_data(builder)` — sign a Data packet in one call.
- `KeyChain::sign_interest(builder)` — sign an Interest in one call.
- `KeyChain::build_validator()` — alias for `validator()` for API symmetry.

#### IPC (ndn-ipc)
- `BlockingForwarderClient` — synchronous wrapper; useful for FFI and Python bindings.
- `ForwarderError` now publicly exported.
- `ChunkedConsumer`, `ChunkedProducer`, `NDN_DEFAULT_SEGMENT_SIZE` re-exported.

#### Config (ndn-config)
- `ForwarderConfig` parses `${VAR}` environment variable references in TOML values.
- `ForwarderConfig::validate()` checks face addresses, route prefixes, and CS size.

#### Packets (ndn-packet)
- `Name` and `NameComponent` implement `PartialOrd` + `Ord` (NDN canonical ordering).

#### Faces (ndn-faces)
- New `websocket-tls` feature: TLS WebSocket server listener via `WebSocketFace::listen_tls`.
  Supports `TlsConfig::SelfSigned` (rcgen-generated cert) and `UserSupplied` (PEM files).
  ACME / SVS fleet cert distribution deferred to v0.2.0.

#### Operations
- `binaries/ndn-fwd/Dockerfile` — multi-stage Debian image for `ndn-fwd`.
- `binaries/ndn-fwd/ndn-fwd.default.toml` — ready-to-run default config.
- **Testbed infrastructure** (`testbed/`): Docker Compose multi-forwarder
  environment running `ndn-fwd`, NFD, and yanfd on a `172.30.0.0/24` subnet.
- **Protocol compliance tests** (`testbed/tests/compliance/`): basic
  forwarding, PIT aggregation, Content Store behavior, and NFD management
  protocol compatibility — run against all three forwarders.
- **Forwarder benchmarks** (`testbed/bench/`): sustained throughput
  (ndn-iperf, 10 s) and round-trip latency (ndn-ping, 200 pings, p50/p95/p99)
  for all forwarders via UDP. Only `ndn-fwd` is tested over SHM face; NFD and
  yanfd use UDP. Results are emitted as a Markdown table.
- **CI testbed workflow** (`.github/workflows/testbed.yml`): weekly cron +
  `workflow_dispatch` + push to `testbed/**`; publishes bench table on `main`.

#### Security and identity
- **Ephemeral identity**: `ndn-fwd` always has a signing identity. When none
  is configured, an in-memory ephemeral Ed25519 key is generated at startup;
  name derived from `security.ephemeral_prefix`, `$HOSTNAME`, or `pid-<pid>`.
- **PIB error recovery**: interactive TTY menu (generate / ephemeral / abort)
  or structured log + ephemeral fallback in daemon mode.
- **`security.pib_type`** and **`security.ephemeral_prefix`** config fields.
- **`/localhost/nfd/security/identity-status`** management dataset: returns
  `identity=<name> is_ephemeral=<bool> pib_path=<path>` regardless of PIB state.
- **`MgmtClient::security_identity_status()`** in `ndn-ipc`.
- **`ndn-sec keygen --skip-if-exists`**: idempotent key generation.
- **NixOS flake module**: `identity`, `pibPath`, and `generateIdentity` options;
  `ExecStartPre` runs idempotent key generation on every boot; stable
  `ndn-router` user/group replacing `DynamicUser = true`.
- **Dashboard identity status**: Security view shows ephemeral warning (yellow)
  or persistent identity info bar (green).

### Fixed
- Validator chain-walk connected to `CertCache` on `Pending` result.
- Spec compliance gaps documented in `docs/unimplemented.md`.

---

## [0.1.0-alpha] — 2026-04-06

First tagged alpha. The full stack compiles, forwards packets, and interoperates
with NFD. All public APIs should be considered unstable until 0.2.0.

See the [0.1.0-alpha wiki page](https://quarmire.github.io/ndn-rs/wiki/releases/v0-1-0-alpha.html) for the full narrative.

### Added

#### Wire format and packet layer
- `InterestBuilder` / `DataBuilder` — configurable packet encoders with signing support (sync and async paths)
- Signed Interest (NDN v0.3 §5.4) — `InterestSignatureInfo`, `InterestSignatureValue`, auto-generated anti-replay fields
- `name!()` macro, `Name::append()`, `Name::from_str()` — ergonomic name construction
- NDNLPv2 `LpPacket` encode/decode — Nack header, CongestionMark, Fragment fields
- NDNLPv2 fragmentation and reassembly — automatic MTU-based splitting for UDP faces
- `ForwardingHint`, `HopLimit`, `ParametersSha256DigestComponent` — spec-compliant encode/decode
- Implicit SHA-256 digest, link object support, anti-replay fields on `SignatureInfo`
- Nack encoding (`encode_nack`) — spec-compliant NDNLPv2-framed Nack
- 34-item spec compliance audit against RFC 8569 / NDN Packet Format v0.3 / NDNLPv2; all tracked items resolved; 5 minor gaps remain (see [Spec Compliance](https://quarmire.github.io/ndn-rs/wiki/reference/spec-compliance.html))
- Wire-format interop tests verifying byte-exact output matching ndnd/ndn-cxx

#### Pipeline and engine
- `PacketContext` passed by value through fixed `PipelineStage` trait objects; `Action` enum drives dispatch
- Interest pipeline: `TlvDecodeStage → CsLookupStage → PitCheckStage → StrategyStage → PacketDispatcher`
- Data pipeline: `TlvDecodeStage → PitMatchStage → ValidationStage → CsInsertStage → PacketDispatcher`
- `ValidationStage` — drops Data that fails trust-chain verification; no-op when no validator is configured
- Per-face bounded send queues (512-slot mpsc) — pipeline never blocked by face I/O
- Configurable `pipeline_threads` — inline (lowest latency) or per-packet tokio tasks (highest throughput)
- `EngineBuilder` — fluent API: `.strategy()`, `.validator()`, `.content_store()`, `.discovery()`, `.security()`
- Per-prefix `StrategyTable` — LPM dispatch to registered strategies; default strategy at root
- `ForwardAfter` delay scheduling — timer-gated probe-and-fallback forwarding
- Inbound Nack pipeline — strategy-driven retry or propagation
- Per-packet `trace!` instrumentation across all stages (`RUST_LOG=ndn_engine=trace`)

#### Content store
- `ContentStore` trait — pluggable backends with `len()`, `current_bytes()`, `set_capacity()`, `evict_prefix()`
- `ShardedCs<C>` — shards any CS by first name component; reduces lock contention
- `FjallCs` — persistent LSM-tree-backed CS (fjall); survives process restart; `ndn-store/fjall` feature
- `ObservableCs` — wraps any CS with atomic hit/miss/insert/eviction counters and optional observer callback
- NFD management commands: `cs/config`, `cs/info`, `cs/erase`

#### Security
- `Validator` — schema check → cert-cache lookup → Ed25519/HMAC verify; returns `Valid(SafeData)` / `Invalid` / `Pending`
- `CertFetcher` — async cert fetching with deduplication (concurrent requests for the same cert share one Interest)
- `Validator::validate_chain()` — walks cert chain to trust anchor; cycle detection; configurable depth limit
- `SecurityProfile` enum — `Default` / `AcceptSigned` / `Disabled` / `Custom`; engine auto-wires from `SecurityManager`
- `TrustSchema::hierarchical()` — default schema; `accept_all()` for testing
- `SecurityManager::auto_init()` — first-run Ed25519 identity generation; `auto_init = true` in TOML config
- `HmacSha256Signer` — symmetric authentication; ~10× faster than Ed25519
- Sync fast-paths: `Signer::sign_sync()`, `DataBuilder::sign_sync()` — eliminate per-packet `Box::pin` heap allocation
- `PIB` (Public Information Base) — `FilePib` key/cert storage; `KeyChain` facade in `ndn-app`
- `ndn-ctl security` subcommands — `init`, `trust`, `export`, `info` (no running router required)

#### Discovery
- `UdpNeighborDiscovery` + `EtherNeighborDiscovery` — SWIM direct and indirect probing, K-gossip piggyback
- Spec-compliant `HelloPayload` TLV — `NODE-NAME`, `SERVED-PREFIX`, `CAPABILITIES`, `NEIGHBOR-DIFF` (0xC1–0xC4)
- `EpidemicGossip` — pull-gossip over `/ndn/local/nd/gossip/`; propagates unknown neighbors via probing state machine
- `SvsServiceDiscovery` — SVS-backed push service record notifications
- `DiscoveryProtocol::tick_interval()` — per-protocol cadence (20 ms–1 s)
- Auto-FIB TTL expiry for discovery-installed routes; configurable `auto_fib_ttl_multiplier`
- `/ndn/local/` link-local scope enforcement — packets never leave local faces

#### Sync
- `ndn-sync`: `SvsNode` (state-vector sync) and `PSyncNode` / `Ibf` (invertible Bloom filter partial sync)
- `join_svs_group()` / `join_psync_group()` — background sync tasks; `SyncHandle` for publish/recv
- `Subscriber` (`ndn-app`) — high-level SVS subscription returning `Sample` stream; optional auto-fetch

#### Network faces (ndn-face-net, ndn-face-l2)
- UDP/TCP network listeners on port 6363 (default); per-peer `UdpFace` auto-created on first datagram
- `MulticastUdpFace` — NDN IPv4 multicast (`224.0.23.170:6363`)
- NDNLPv2 per-hop reliability on unicast UDP — `LpReliability` state machine; adaptive RTO (RFC 6298/9002)
- `NamedEtherFace` / `MulticastEtherFace` — Linux (`AF_PACKET` + TPACKET_V2 zero-copy mmap rings)
- `NamedEtherFace` / `MulticastEtherFace` — macOS (`PF_NDRV` socket, EtherType 0x8624)
- `NamedEtherFace` / `MulticastEtherFace` — Windows (Npcap/`pcap`, background bridge threads)
- `WebSocketFace` — NDN-over-WebSocket (binary frames); client and server sides; `tokio-tungstenite`
- `SerialFace` with COBS framing — UART, LoRa, RS-485; `tokio-serial`
- `StreamFace<R, W, C>` generic — eliminates TCP/Unix/Serial duplication; type aliases for all three
- `FaceKind` unified enum with `Display`, `FromStr`, serde — single source of truth across `ndn-transport` and `ndn-config`
- `FacePersistency` (`OnDemand` / `Persistent` / `Permanent`) — NFD-compatible face lifecycle
- Idle face timeout — background sweep removes on-demand faces idle > 5 minutes
- `FaceScope` (`Local` / `NonLocal`) — `/localhost` scope boundary enforced inbound and outbound
- `ReliabilityConfig` presets — `default()`, `local()`, `ethernet()`, `wifi()`; `RtoStrategy` enum

#### Local faces (ndn-face-local)
- `SpscFace` / `SpscHandle` — zero-copy SHM ring (256 slots) with named-FIFO wakeup (`AsyncFd`-based, no blocking threads)
- `UnixFace` — domain socket face with TLV codec framing
- `AppFace` / `AppHandle` — in-process mpsc-channel face pair

#### Application API (ndn-app, ndn-ipc)
- `Consumer` — `connect()`, `fetch()`, `get()`, `fetch_verified()`
- `Producer` — `connect()`, `serve()` with async handler
- `Queryable` — register prefix, serve request/response via `query.reply()`
- `NdnConnection` — unified enum over embedded `AppFace` and external `RouterClient`
- `KeyChain` — `create_identity()`, `signer()`, `validator()`; wraps `SecurityManager` + `FilePib`
- `blocking` module — `BlockingConsumer` / `BlockingProducer`; internal runtime hidden from callers
- `ChunkedProducer` / `ChunkedConsumer` — segmented large-content transfer
- `RouterClient` — app-side abstraction; SHM data plane preferred, Unix fallback
- `CongestionController` — AIMD, CUBIC (RFC 8312), and Fixed window algorithms

#### Strategy
- `ComposedStrategy` — wraps any strategy with a filter chain; `StrategyFilter` trait
- `RssiFilter` — example filter removing faces below an RSSI threshold
- `ContextEnricher` trait — inserts typed cross-layer data into `AnyMap` for strategies
- `LinkQualitySnapshot` / `FaceLinkQuality` — per-face RSSI, retransmit rate, RTT, throughput
- `WasmStrategy` (`ndn-strategy-wasm`) — hot-loadable WASM forwarding strategies via wasmtime; fuel-limited

#### Management (NFD-compatible)
- NFD TLV protocol — `ControlParameters` (0x68) / `ControlResponse` (0x65) over `/localhost/nfd/`
- Modules: `rib`, `faces`, `fib`, `strategy-choice`, `cs`, `status`
- `ndn-ctl` CLI — NFD TLV transport; `rib`, `faces`, `fib`, `strategy-*`, `cs-*`, `security` subcommands

#### Embedded
- `ndn-embedded` — `#![no_std]` forwarder for ARM Cortex-M, RISC-V, ESP32; const-generic `Pit<N>`, `Fib<N>`, `Forwarder`
- COBS framing (`cobs.rs`), slice-based TLV encoder (`wire.rs`), SPSC app channel (`ipc.rs`) — all no-alloc
- `ndn-tlv` / `ndn-packet` `no_std` support — `alloc::` path for both crates

#### Python bindings
- `ndn-python` (`bindings/ndn-python`) — PyO3 extension; `Consumer.get()` / `Consumer.fetch()` / `Producer.serve()`; no asyncio required

#### WASM browser simulation
- `ndn-wasm` crate — standalone WASM simulation with `WasmPipeline`, `WasmTopology`, TLV encode/decode
- `ndn-explorer` static web app — interactive crate map, pipeline trace, topology sandbox, TLV inspector, discovery walkthrough
- GitHub Pages deployment via `wiki.yml`; WASM badge shows live build status

#### Benchmarks and tooling
- Criterion suites for `ndn-engine`, `ndn-packet`, `ndn-store`, `ndn-security`, `ndn-face-local`
- Benchmark results auto-committed to wiki on every CI run; `pipeline-benchmarks.md` updated in-place
- `ndn-bench` binary — embedded engine load driver; reports p50/p95/p99 latency
- mdBook wiki with deep-dive articles, simulation guide, wasm-browser-simulation page

### Changed

- `FaceConfig` converted to `#[serde(tag = "kind")]` enum — invalid field combinations rejected at parse time
- `dispatch_action()` and `satisfy()` made synchronous — use `enqueue_send()` (non-blocking `try_send`)
- `DataBuilder::build()` omits MetaInfo when no freshness is set (semantically correct; previously emitted `FreshnessPeriod=0`)
- NonNegativeInteger encoding uses minimal lengths (1/2/4/8 bytes); previously always 8 bytes
- Pipeline runner: fragment sieve single-threaded, per-packet tokio tasks for parallel stage processing
- `ndn-iperf`, `ndn-ping` — rewritten against application library API; real network I/O

### Fixed

- UDP face replies from wrong source port on listener-created faces (now shares listener socket via `Arc<UdpSocket>`)
- UDP face `EPIPE` on macOS — switched from connected to unconnected socket (`send_to` / `recv_from`)
- NDNLPv2 framing on outbound UDP/TCP — bare TLV was silently dropped by NFD; now wrapped in LpPacket
- SHM wakeup unified to named FIFO + `AsyncFd` on all platforms — eliminates `spawn_blocking` thread transitions
- SHM liveness detection — `CancellationToken` cascade from control face; `SpscHandle::send()` uses wall-clock deadline
- Stale FIB routes on face disconnect — `Fib::remove_face` purges all nexthops pointing to removed face
- Pipeline overload backpressure cascade killing SHM apps — face reader uses `try_send` (drops, not blocks)
- Consecutive iperf runs colliding on stale PIT entries — per-run flow ID prefix; `Pit::remove_face()` on disconnect
- AIMD/CUBIC unbounded slow start and per-packet loss event inflation — fixed ssthresh and single loss event per check
- NDNLPv2 reliability drain after flow end — `MAX_UNACKED=256` cap bounds post-flow retransmit window
- Idle sweep killing SHM faces — local faces (`App`, `Shm`, `Internal`) excluded from idle timeout

---

## [0.0.2] — Layer 5 tests (89cb5e1)

### Added

- Comprehensive test suites for `ndn-tlv` (33 tests) and `ndn-packet` (61 tests).

### Fixed

- `Data::sig_value()` returned full SignatureValue TLV instead of just the value bytes.
- `Nack::decode` expected a full outer INTEREST TLV; reconstructed from raw bytes.
- `#[derive(Debug)]` added to `Interest`, `Data`, `Nack`.

---

## [0.0.1] — Initial workspace (1e85c1f / d4e89f1 / 19d6d48)

### Added

- Cargo workspace: `resolver = "2"`, 17 library crates + 3 binary crates across 6 dependency layers.
- `ndn-tlv`: `TlvReader` (zero-copy `Bytes`), `TlvWriter` (nested encoding), `read_varu64` / `write_varu64`.
- `ndn-packet`: `Name`, `NameComponent`, `Interest` (lazy `OnceLock` fields), `Data` (signed region offsets), `MetaInfo`, `SignatureInfo`, `Nack`.
- `ndn-store`: `NameTrie` (per-node `RwLock` LPM), `Pit` / `PitEntry`, `ContentStore` trait, `LruCs`.
- `ndn-transport`: `Face` trait, `FaceId`, `FaceKind`, `FaceTable` (DashMap + `ErasedFace`).
- Design documentation in `docs/`; `README.md` landing page.
