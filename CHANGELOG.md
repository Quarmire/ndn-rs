# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project does not yet follow Semantic Versioning — the codebase is in active
bootstrapping phase and all APIs should be considered unstable.

---

## [Unreleased]

### Added

#### Configurable per-face reliability (`ReliabilityConfig`, `RtoStrategy`)

All NDNLPv2 reliability knobs are now runtime-tunable per face via a
`ReliabilityConfig` struct with presets for common link types.

- **`ReliabilityConfig`** — bundles `max_retries`, `max_unacked`,
  `max_retx_per_tick`, and `rto_strategy` into a single config struct.
  Presets: `default()` (RFC 6298), `local()`, `ethernet()`, `wifi()`.
- **`RtoStrategy` enum** — switchable RTO algorithm per face:
  - `Rfc6298` — EWMA with 200ms floor, 1s initial (default).
  - `Quic` — RFC 9002-style, 333ms initial, no floor.
  - `MinRtt` — minimum observed RTT + configurable margin.
  - `Fixed` — constant RTO for known-latency links (Unix, SHM).
- **`LpReliability::from_config(mtu, config)`** — construct from config.
- **`LpReliability::apply_config(config)`** — reconfigure at runtime.

#### Consumer-side congestion control (`CongestionController`)

New `ndn_transport::CongestionController` enum with three algorithms for
regulating how many Interests a consumer keeps in flight.

- **AIMD** — additive-increase multiplicative-decrease, matches
  `ndncatchunks` behavior.  Slow-start then linear growth, ×0.5 on loss.
- **CUBIC** — RFC 8312 cubic function ramp-up, ×0.7 decrease.  Better
  for high-bandwidth, long-RTT links.
- **Fixed** — constant window, no adaptation (for benchmarks).
- All algorithms support slow-start, min/max window bounds, and `reset()`.
- Builder-style parameter tuning: `with_max_window()`,
  `with_additive_increase()`, `with_decrease_factor()`, `with_cubic_c()`.

#### ndn-iperf adaptive congestion control

The iperf client now uses `CongestionController` instead of a fixed
sliding window, with full CLI configurability.

- **`--cc <algorithm>`** — select `aimd` (default), `cubic`, or `fixed`.
- **`--ai`** — AIMD additive increase per RTT.
- **`--md`** — multiplicative decrease factor.
- **`--cubic-c`** — CUBIC scaling constant.
- **`--min-window`** / **`--max-window`** — window bounds.
- Window now grows on successful Data and shrinks on timeout/congestion.

#### Sync protocol network layer and pub/sub API

Integrated sync and query primitives into the application API, inspired by
Zenoh's pub/sub/queryable model but built on NDN's Interest/Data machinery.

- **`ndn-sync` network layer** — `join_svs_group()` runs SVS as a background
  task: periodic Sync Interests with state vector encoding, gap detection,
  and `SyncUpdate` notifications.  `SyncHandle` provides `recv()` for updates
  and `publish()` to announce local data.  Configurable via `SvsConfig`
  (interval, jitter, channel capacity).
- **`Subscriber`** (`ndn-app`) — high-level subscription API.
  `Subscriber::connect(socket, "/chat/room1")` joins an SVS group and
  returns a stream of `Sample`s (name, publisher, seq, optional payload).
- **`Queryable`** (`ndn-app`) — register a prefix and serve queries via
  `queryable.serve(|interest| { ... })`.  Cleaner alternative to `Producer`
  for request/response patterns.
- **`SyncProtocol` abstraction** — `SyncHandle`, `SyncUpdate`, `SyncError`
  types in `ndn-sync::protocol` for future protocol backends (PSync network
  layer planned).
- Added to `ndn-app` prelude: `Subscriber`, `Queryable`.

#### Completed sync/query integration

- **`AppHandle` now supports `&self` for `recv()`** — the receiver is wrapped
  in a `Mutex`, enabling shared ownership and concurrent send/recv from
  different tasks.  `NdnConnection::recv()` likewise takes `&self`.
- **`Queryable::recv()`** — returns `Query` objects that carry the incoming
  Interest plus an `Arc<NdnConnection>` sender, so the application can reply
  from any task via `query.reply(data)`.
- **Subscriber auto-fetch** — when `auto_fetch` is enabled (default), the
  subscriber expresses Interests for each `SyncUpdate` and populates
  `Sample.payload` with the fetched Data content.  Configurable
  `fetch_timeout` (default 4s).
- **Subscriber recv pump** — incoming packets from the network connection
  are forwarded to the SVS task, closing the gap that previously required
  the caller to manually feed sync packets.
- **PSync network layer** (`ndn-sync::psync_sync`) — `join_psync_group()`
  runs PSync as a background task: periodic Sync Interests carrying IBF
  encoding, peer IBF subtraction and difference decoding, Data replies with
  missing hash sets.  Configurable via `PSyncConfig` (interval, jitter,
  IBF size).  `Ibf::from_cells()` / `Ibf::cells()` added for wire encoding.

### Fixed

#### Pipeline overload kills SHM applications via backpressure cascade

Under heavy load (e.g. CUBIC retransmit floods), the pipeline channel
(4096 slots) could fill up, causing face readers to block on
`tx.send()`.  This cascaded through the SHM ring (256 slots) to the
application, where `SpscHandle::send()` hit its yield limit and
returned `Closed` — killing the app even though the connection was
alive.  All subsequent runs got 0 throughput until the router restarted.

- **Face reader uses `try_send`** — inbound packets are dropped (not
  blocked) when the pipeline channel is full, same as outbound
  `enqueue_send`.  Prevents face readers from stalling, which broke
  the SHM backpressure chain that killed applications.
- **`SpscHandle::send()` uses wall-clock deadline** (5s) instead of a
  yield counter (100k iterations).  The old yield counter was
  system-speed-dependent and could falsely fire under Tokio contention,
  killing the app on transient load spikes.
- **iperf retransmit budget** — capped at `window/2` per check interval
  to prevent retransmit floods from overwhelming the pipeline in the
  first place.
- **iperf per-Interest retry limit** (`MAX_RETRIES = 3`) — Interests
  that fail 3 retransmits are marked as timed out and removed from the
  in-flight map, freeing window capacity for new Interests.

#### Consecutive iperf runs fail with PIT suppression (0 throughput)

Running `ndn-iperf client` a second time immediately after the first run
produced 0 throughput because Interest names `/iperf/0`, `/iperf/1`, ...
collided with stale PIT entries from the previous run.

- **Per-run flow ID** — each iperf client run now uses a unique flow prefix
  (`/iperf/<flow-id>/<seq>`) so names never collide between runs or
  concurrent clients.
- **PIT cleanup on face disconnect** — `Pit::remove_face()` drains PIT
  entries whose sole in-record consumer is the closed face, preventing stale
  entries from suppressing future Interests.  Called from `run_face_reader`
  on face close, before FIB cleanup.

#### AIMD/CUBIC congestion control produces inflated loss reports

Adaptive congestion control (aimd, cubic) nearly saturated the link but
reported 34–50% loss due to three compounding issues.

- **Unbounded slow start** — `ssthresh` defaulted to `f64::MAX`, so the
  window doubled every RTT and overshot link capacity in milliseconds on
  low-RTT links (SHM, localhost).  Now `--window` sets both the initial
  window and ssthresh, starting directly in congestion avoidance.
- **Per-packet loss events** — each stale Interest called `on_timeout()`
  individually, halving the window N times then re-inflating via slow
  start in rapid oscillation.  Now all stale Interests in a single
  retransmit check trigger one loss event.
- **In-flight inflation** — Interests still in the pipeline at test end
  were counted as lost.  Loss is now `(sent − in_flight_at_end − received)`
  with in-flight reported separately.
- **`CongestionController::with_ssthresh()`** — new builder method for
  explicit slow-start threshold control.

#### NDNLPv2 reliability lingering traffic after flow completion

High-throughput flows accumulated thousands of unacked entries that drained
at ~160 pkt/sec for minutes after the flow ended, flooding the remote with
retransmitted fragments ("unsolicited data").

- **Unacked map cap** (`MAX_UNACKED = 256`) — oldest entries evicted when
  the map is full.  Post-flow drain limited to ~1.6 seconds.

#### NDNLPv2 per-hop reliability for unicast UDP faces

Unicast UDP faces now implement NDNLPv2 per-hop reliability, fixing throughput
instability (400–850 Mbps variance) caused by unrecovered UDP packet loss.

- **LpPacket Ack field** — decode/encode Ack TLVs (0x0344), `fragment` is now
  `Option<Bytes>` to support bare Ack-only packets.
- **Per-fragment unique sequence** — each fragment gets `Sequence = base_seq + i`;
  reassembly key is `Sequence - FragIndex`.
- **`LpReliability` struct** (`ndn-face-net/src/reliability.rs`) — pure
  synchronous state machine: `on_send()` fragments + assigns TxSequences +
  piggybacks Acks; `on_receive()` queues Acks + measures RTT; `check_retransmit()`
  drives retransmits with adaptive RTO (RFC 6298, Karn's algorithm).
- **Engine integration** — `FaceState` holds optional `LpReliability` for UDP
  faces; `run_face_sender` has a 50ms retransmit tick; `run_face_reader` feeds
  inbound packets to `on_receive()`.
- **`FaceKind::Multicast`** — multicast UDP now has its own `FaceKind` variant
  (no reliability, no single peer to Ack).
- **UdpFace passthrough** — packets already wrapped as LpPackets (from the
  reliability layer) are sent directly, bypassing the face's own LpPacket
  wrapping and fragmentation.

#### Network listeners — UDP and TCP on port 6363

The router now listens for incoming network traffic at startup, matching NFD's
default behavior.

- **UDP listener** (`run_udp_listener`) — binds an unconnected socket on the
  configured address (default `0.0.0.0:6363`). Auto-creates a per-peer `UdpFace`
  on the first datagram from each new source address. Subsequent packets from
  that peer are injected directly into the pipeline.
- **TCP listener** (`run_tcp_listener`) — accepts incoming TCP connections and
  creates a `TcpFace` per connection with TLV length-prefix framing.
- **Default listeners** — when no `[[face]]` entries are present in the config
  (or no config file is given), the router automatically starts both UDP and TCP
  listeners on `0.0.0.0:6363`.
- **Config-driven** — `[[face]]` entries with `kind = "udp"` or `kind = "tcp"`
  and optional `bind` address are instantiated at startup.
- **`ForwarderEngine::inject_packet()`** — public method to push raw packets
  directly into the pipeline channel, used by listener tasks that manage their
  own recv loop.
- **`ndn_config::FaceKind`** re-exported from `ndn-config` crate root.

#### Ergonomic application library API

**ndn-packet (Name ergonomics):**
- **`impl FromStr for Name`** — parse NDN URI strings (`"/edu/ucla/data".parse()`)
  with percent-decoding; roundtrips with `Display`.
- **`Name::append()`, `append_component()`, `append_segment()`** — by-value builder
  methods for chaining: `prefix.clone().append("data").append_segment(42)`.
- **`name!()` macro** — compile-time name construction: `name!("/iperf/data")`.
- **`impl From<&str>` / `From<String>` for `Name`** — enables `InterestBuilder::new("/test")`.
- **`SEGMENT` TLV type constant** (`0x32`).

**ndn-packet (Packet builders):**
- **`InterestBuilder`** — configurable Interest encoder with `lifetime()`,
  `can_be_prefix()`, `must_be_fresh()`, `hop_limit()`, `app_parameters()`.
- **`DataBuilder`** — configurable Data encoder with `freshness()` and async
  `.sign(sig_type, key_locator, sign_fn)` for cryptographic signing.

**ndn-app (Consumer/Producer):**
- **`Consumer`** — high-level fetch API: `connect()`, `fetch()`, `get()`,
  `fetch_verified()` (with `Validator` integration).
- **`Producer`** — high-level serve API: `connect()`, `serve()` with async handler.
- **`NdnConnection`** — unified enum over `AppHandle` (embedded) and `RouterClient`
  (external).
- **`KeyChain`** — simplified security facade: `create_identity()`, `signer()`,
  `validator()`. Wraps `SecurityManager` + `FilePib`.
- **`blocking` module** — `BlockingConsumer` / `BlockingProducer` behind `blocking`
  feature flag; internal tokio runtime hidden from users (reqwest-style pattern).
- **`prelude` module** — ergonomic imports: `Name`, `Interest`, `Data`,
  `InterestBuilder`, `DataBuilder`, `Consumer`, `Producer`, `KeyChain`, `AppError`.

**ndn-security:**
- **`Signer::public_key()`** — optional trait method returning raw public key bytes.
- **`SecurityManager::get_signer_sync()`** — synchronous signer lookup for non-async
  contexts.
- **`MemKeyStore::get_signer_sync()`** — made public.

#### Face scope enforcement

`/localhost` prefix security boundary — packets with names starting with
`/localhost` are confined to local faces only, matching NFD behavior.

- **`FaceScope` enum** (`Local`, `NonLocal`) in `ndn-transport` — derived from
  `FaceKind` (`Unix`/`App`/`Shm`/`Internal` → Local, all others → NonLocal).
- **`FaceKind::scope()`** method for querying face locality.
- **Inbound filtering** — `TlvDecodeStage` drops `/localhost` Interest, Data, and
  Nack packets arriving on non-local faces (`DropReason::ScopeViolation`).
- **Outbound filtering** — `PacketDispatcher` skips non-local faces when forwarding
  or satisfying `/localhost`-prefixed packets.

#### Face persistence (on-demand / persistent / permanent)

NFD-compatible face lifecycle management with three persistence levels.

- **`FacePersistency` enum** (`OnDemand`, `Persistent`, `Permanent`) in
  `ndn-transport` — mirrors NFD semantics with `from_u64()` constructor.
- **`FaceState`** replaces bare `CancellationToken` per face — tracks cancel token,
  persistency level, and last-activity timestamp (`AtomicU64` nanoseconds).
- **Persistency-aware cleanup** in `run_face_reader`:
  - *Permanent*: retries on recv errors indefinitely (only cancellation stops it).
  - *Persistent*: stops the recv loop on error but retains the face in table/FIB.
  - *OnDemand*: fully removes face from table and cleans FIB routes (existing behavior).
- **Idle face timeout** — background sweep task (`run_idle_face_task`) runs every 30s,
  removing on-demand faces idle for >5 minutes.
- **Management integration** — `faces/create` uses `Persistent` by default;
  listener-accepted faces use `OnDemand`; `faces/list` shows persistency level.
- **Per-face outbound send queue** — each face now has a bounded `mpsc` channel
  (128 slots) with a dedicated send task, matching NFD's `GenericLinkService`
  output queue model.  The pipeline runner enqueues packets via non-blocking
  `try_send` and is never blocked by face I/O.  Benefits:
  - *TCP ordering preserved*: per-face sequential sends prevent interleaved TLV
    framing corruption that `tokio::spawn`-per-send would cause.
  - *Bounded backpressure*: full queues drop packets (congestion drop semantics —
    consumers re-express Interests).
  - *Pipeline decoupled from I/O*: fragmented UDP sends (~35 µs for 7 fragments)
    no longer block all other packet processing.
  - *Persistency-aware error handling*: `run_face_sender` retries on permanent
    faces, cleans up on-demand faces on send error.

#### NDNLPv2 fragmentation and reassembly

Automatic fragmentation/reassembly for packets exceeding the UDP MTU (~1400 bytes),
enabling reliable transport of large NDN Data packets (~8800 bytes) over UDP.

- **`ndn_packet::fragment` module** (new):
  - `fragment_packet()` — splits a packet into MTU-sized NDNLPv2 LpPacket fragments
    with `Sequence`, `FragIndex`, and `FragCount` fields.
  - `ReassemblyBuffer` — per-peer stateful reassembly keyed by sequence number,
    with configurable timeout and `purge_expired()` for cleanup.
  - `DEFAULT_UDP_MTU` constant (1400 bytes).
- **Outbound fragmentation** — `UdpFace` and `MulticastUdpFace` automatically
  fragment packets larger than the MTU before sending. Each face maintains an
  atomic sequence counter for fragment identification.
- **Inbound reassembly** — `TlvDecodeStage` maintains a per-face
  `DashMap<FaceId, ReassemblyBuffer>`. Fragmented LpPackets are reassembled in
  the pipeline before TLV decoding, keeping the Face layer protocol-agnostic and
  avoiding duplicate reassembly logic in listeners and individual face types.

#### Multicast LpPacket wrapping

- **`MulticastUdpFace::send()`** now wraps outgoing packets in NDNLPv2 LpPacket
  framing, consistent with `UdpFace` and `TcpFace`.

### Fixed

#### UDP listener faces reply from wrong source port

Listener-created UDP faces used a dedicated ephemeral-port socket for sending.
When the remote peer's face filters by source address (expecting replies from
port 6363), replies from an ephemeral port were silently dropped — causing
cross-machine ndn-ping to timeout even though Interests reached the server.

This mirrors NFD's UdpChannel design: the listener owns a single socket and
all per-peer faces share it for sending via `send_to`.  No recv loop is
spawned for these faces — the listener demuxes inbound datagrams and injects
them into the pipeline via `inject_packet`.

- **`UdpFace::from_shared_socket()`** — new constructor accepting an
  `Arc<UdpSocket>` so listener-created faces share the listener's socket.
- **`ForwarderEngine::add_face_send_only()`** — registers a face without
  spawning a recv loop (the listener handles inbound demux).
- **UDP listener** uses both to create per-peer faces that reply from the
  well-known listener port.

#### SHM wakeup: unified FIFO path, eliminated `spawn_blocking` on Linux

The Linux futex + `spawn_blocking` wakeup path routed every park/unpark
through Tokio's blocking thread pool.  At 100K+ packets/sec this caused
Linux SHM throughput to be 2–4× lower than macOS (which used named FIFOs
with `AsyncFd` integrated directly into the epoll loop).

- **Unified wakeup mechanism** — both Linux and macOS now use named FIFO pipes
  wrapped in `tokio::io::unix::AsyncFd`, integrating directly into Tokio's
  epoll/kqueue loop with zero thread transitions.
- **Removed all `#[cfg(target_os = "linux")]` branching** from `spsc.rs` —
  the entire SPSC face implementation is now platform-agnostic.
- **Removed futex syscall helpers** — `futex_wait()` and `futex_wake_one()`
  no longer needed.

#### Cross-process SHM futex on Linux

The `atomic-wait` crate uses `FUTEX_PRIVATE_FLAG`, which keys on virtual
addresses and only works within a single process.  SHM faces share memory
across processes via POSIX `shm_open`, so the futex must key on the physical
page offset — requiring plain `FUTEX_WAIT` / `FUTEX_WAKE` without the private
flag.

- **Replaced `atomic-wait` with direct futex syscalls** — `futex_wait()` and
  `futex_wake_one()` call `libc::SYS_futex` without `FUTEX_PRIVATE_FLAG`.
- **Timed futex wait (100ms)** — prevents `spawn_blocking` threads from hanging
  indefinitely during shutdown (Ctrl+C), since tokio waits for all blocking
  tasks before the runtime drops.
- **Removed `atomic-wait` dependency** from workspace and `ndn-face-local`.

#### SHM face cleanup on app disconnect

- **SHM faces now use `OnDemand` persistency** instead of `Persistent`.  When
  the control face disconnects (app exits), the child cancel token fires and
  the SHM face is fully cleaned up: SHM region unlinked, FIB routes removed,
  face removed from table.

#### Pipeline stage tracing

Per-packet `trace!`-level instrumentation across all forwarding pipeline stages,
enabling end-to-end packet journey debugging with `RUST_LOG=ndn_engine=trace,ndn_face_net=trace`.

**ndn-engine:**
- **TlvDecodeStage** — traces Interest/Data/Nack decode results, LpPacket unwrap,
  HopLimit exceeded, malformed packets, and unknown TLV types.
- **CsLookupStage** — traces cache HIT / MISS per Interest.
- **CsInsertStage** — traces Data insertion with freshness period and admission
  policy rejections.
- **PitCheckStage** — traces loop detection (duplicate nonce), Interest aggregation
  (suppression), and new PIT entry creation with nonce and lifetime.
- **PitMatchStage** — traces PIT satisfaction (with out-faces list) and unsolicited
  Data drops.
- **StrategyStage** — traces FIB LPM result (hit with nexthops / miss), strategy
  selection (name), and forwarding decision (Forward, ForwardAfter, Nack, Suppress).
- **PacketDispatcher** — traces packet arrival (face, length), pipeline routing
  (Interest/Data/Nack), dispatch actions (Send with target faces, Satisfy with
  out-faces and CS hit flag, Nack with reason), per-face send success, and face-
  not-found warnings.

**ndn-face-net:**
- **UdpFace** — traces send/recv with face ID, peer address, and packet length.
- **TcpFace** — traces send/recv with face ID, remote address, and packet length.

### Changed

- **`ndn-iperf` rewritten** to use the new application library API:
  - Server uses `DataBuilder` (with optional `.sign()` via `KeyChain`) instead of
    raw `encode_data_unsigned()`.
  - Client uses `InterestBuilder` with configurable `.lifetime()` instead of
    `encode_interest()`.
  - New `--sign` flag on server: generates ephemeral Ed25519 identity and signs
    every Data packet (for measuring signing overhead).
  - New `--freshness` option on server for configurable Data freshness period.
  - New `--lifetime` option on client for configurable Interest lifetime.
  - New `--interval` option on both sides for reporting period (default 1s).
  - New `--quiet` / `-q` flag to suppress periodic status reports.
  - Live per-interval throughput/packet-rate/RTT reporting via lock-free atomics.
  - Richer final summary: human-readable sizes, loss percentage, min/max/percentile
    RTT, timeout count.
  - Status output on stderr, final results on stdout (allows piping/parsing).
  - Shared `ConnectOpts` struct via `#[command(flatten)]`.
- **`ndn-ping` rewritten** to use the application library API and real network I/O:
  - Replaced simulated ping loop with actual `RouterClient` communication.
  - Server mode: registers prefix, responds to ping Interests with `DataBuilder`,
    optional Ed25519 signing (`--sign`), configurable freshness.
  - Client mode: sends ping Interests with `InterestBuilder`, measures real RTT,
    prints per-packet timing and statistical summary (min/avg/max/p50/p99/stddev).
  - Uses clap for CLI parsing with `ConnectOpts` (`--face-socket`, `--no-shm`).
  - Supports unlimited pings (`--count 0`), configurable interval and lifetime.
- All tools (`ndn-iperf`, `ndn-traffic`, `ndn-ping`, `ndn-peek`, `ndn-put`,
  `ndn-ctl`, `ndn-sec`, `ndn-bench`, `ndn-router`) now use `Name::from_str()`
  instead of duplicated `parse_name()` functions, and `Name::Display` instead of
  duplicated `format_name()` functions.
- Tool name-building code simplified with `Name::append()` (e.g.,
  `prefix.clone().append(format!("{seq}"))` replaces iterator chains).

#### Embedded engine integration tests (Android/mobile readiness)

- **`crates/ndn-app/tests/embedded.rs`** — end-to-end tests demonstrating the
  embedded forwarding pattern: `ForwarderEngine` + `AppFace` + `Consumer`/`Producer`
  running entirely in-process with no external router, Unix sockets, or SHM.
- Three tests: single fetch, sequential multi-fetch, and `Consumer::get()`.
- Module-level documentation on `ndn-app` with code examples for both connection
  modes (external router and embedded engine).
- Verified: all pure-Rust crates cross-check for `aarch64-linux-android`; crates
  using `ring` require Android NDK (ring tier-1 target, no code changes needed).

### Fixed

- **UDP face broken pipe on macOS** — `UdpFace` switched from a connected socket
  (`connect()` + `send`/`recv`) to an unconnected socket (`send_to`/`recv_from`).
  On macOS/BSD, a connected UDP socket that receives ICMP port-unreachable enters a
  permanent error state where all subsequent `send()` calls fail with `EPIPE`
  (broken pipe). The unconnected approach makes each datagram independent at the
  kernel level. `recv_from` filters by peer address to maintain single-peer semantics.
- **NDNLPv2 framing on outbound network packets** — `UdpFace::send()` and
  `TcpFace::send()` now wrap bare Interest/Data in an NDNLPv2 `LpPacket(Fragment(...))`
  envelope via `encode_lp_packet()`. NFD and ndn-cxx require LpPacket framing on
  unicast links; bare TLV type 0x05/0x06 was silently dropped by remote forwarders.

**Wire-format interoperability (ndnd/ndn-cxx compatibility):**
- **NonNegativeInteger encoding now uses minimal lengths** (1, 2, 4, or 8 bytes
  per NDN Packet Format v0.3 §1.2). Previously always used 8 bytes for
  InterestLifetime and FreshnessPeriod, wasting 6 bytes per packet.
- **`DataBuilder::build()` omits MetaInfo** when no freshness is set, instead of
  emitting `FreshnessPeriod=0` (which means "immediately stale" — semantically
  different from absent MetaInfo).
- **SignatureType and NackReason encoding** now uses valid NNI lengths. Previously
  stripped leading zeros without rounding up to {1,2,4,8}, which could produce
  invalid 3/5/6/7-byte encodings for values ≥256.
- Added 14 wire-format interop tests verifying byte-exact encoding output and
  successful decoding of hand-crafted packets matching ndnd/ndn-cxx wire format.

### Removed

- 8 duplicated `parse_name()` functions across tool binaries.
- 3 duplicated `format_name()` functions (replaced by `Name`'s `Display` impl).

### Added

#### NFD-compatible management protocol

Full NFD management protocol implementation using binary TLV encoding
(ControlParameters 0x68, ControlResponse 0x65) with standard NFD name
conventions (`/localhost/nfd/<module>/<verb>/<ControlParameters>`).

**ndn-config:**
- **ControlParameters TLV codec** (`control_parameters.rs`) — encode/decode all
  NFD ControlParameters fields: Name, FaceId, Uri, Origin, Cost, Flags, Mask,
  ExpirationPeriod, FacePersistency, Strategy, Mtu.
- **ControlResponse TLV codec** (`control_response.rs`) — encode/decode
  StatusCode, StatusText, and optional ControlParameters body. Standard status
  codes: 200 OK, 400 bad params, 403 unauthorized, 404 not found, 409 conflict.
- **NFD command name builder/parser** (`nfd_command.rs`) — `command_name()`,
  `dataset_name()`, and `parse_command_name()` for constructing and parsing
  management Interest names. Module/verb constants for all NFD modules.

**ndn-engine:**
- **Per-prefix strategy table** — `StrategyTable<dyn ErasedStrategy>` wired into
  `EngineInner`. `StrategyStage` performs LPM on the strategy table before
  dispatching to the matched strategy. Default strategy seeded at root.
- **`ErasedStrategy::name()`** — added to the object-safe strategy trait so
  management handlers can report strategy names.
- **`ForwarderEngine::strategy_table()`** — public accessor for the engine's
  strategy table.
- **`ForwarderEngine::source_face_id()`** — resolves the originating face of an
  Interest via PIT in-record lookup, enabling "FaceId defaults to requesting
  face" NFD behavior.

**ndn-store:**
- **`StrategyTable` `?Sized` support** — type parameter accepts trait objects
  (`dyn ErasedStrategy`).
- **`StrategyTable::dump()`** — returns all (prefix, strategy) entries for status
  reporting.
- **`LruCs::len()`, `is_empty()`, `current_bytes()`** — public accessors for CS
  status reporting.

**ndn-strategy:**
- **NFD-style strategy names** — `BestRouteStrategy::strategy_name()` returns
  `/localhost/nfd/strategy/best-route`; `MulticastStrategy::strategy_name()`
  returns `/localhost/nfd/strategy/multicast`.

**ndn-router (`mgmt_ndn.rs`):**
- **RIB module** — `rib/register`, `rib/unregister`, `rib/list`. FaceId defaults
  to requesting face when omitted. Routes use NFD origin/flags/cost semantics.
- **Faces module** — `faces/create` (supports `shm://`, `unix://`, `tcp4://`,
  `udp4://` URIs), `faces/destroy`, `faces/list` (reports face IDs and kinds).
- **FIB module** — `fib/add-nexthop`, `fib/remove-nexthop`, `fib/list` (reports
  prefix and nexthops).
- **Strategy-choice module** — `strategy-choice/set` (creates strategy by name,
  inserts into strategy table), `strategy-choice/unset` (blocks unsetting root),
  `strategy-choice/list` (shows prefix→strategy mappings).
- **CS module** — `cs/config` (reports capacity), `cs/info` (reports capacity,
  entries, memory usage).
- **Status module** — `status/general` (faces/fib/pit/cs counts),
  `status/shutdown`.

**ndn-ipc:**
- **`RouterClient`** (`router_client.rs`) — app-side abstraction for connecting
  to ndn-router. Connects via UnixFace, optionally creates SHM data plane face.
  Provides `register_prefix()`, `unregister_prefix()`, `send()`, `recv()`.

**ndn-tools (`ndn-ctl`):**
- **NFD TLV transport** — primary transport sends ControlParameters-encoded
  Interests over UnixFace. Legacy JSON bypass retained with `--bypass` flag.
- **New commands** — `strategy-set`, `strategy-unset`, `strategy-list`, `cs-info`.

**ndn-tools (`ndn-iperf`):**
- **External mode** — rewritten as external server/client that connects to a
  running ndn-router via `RouterClient`. SHM data plane preferred, Unix socket
  fallback.

### Changed

- **ndn-engine pipeline architecture** — the pipeline runner performs fragment
  sieve and channel drain inline (single-threaded), then spawns per-packet
  tokio tasks for full pipeline processing across multiple cores.  This
  replaced an earlier fully-inline design that saturated a single core at
  ~850 Mbps on UDP workloads with fragmentation.
- **ndn-router management prefix** changed from custom to `/localhost/nfd` (NFD
  standard).
- **ndn-engine `StrategyStage`** now uses `strategy_table` + `default_strategy`
  instead of a single global strategy.
- **ndn-engine dispatcher nack pipeline** updated to use strategy table LPM for
  per-prefix strategy dispatch on Nack.
- **`dispatch_action()` and `satisfy()` are now synchronous** — no longer async;
  use `enqueue_send()` (non-blocking `try_send` to per-face channel) instead of
  awaiting `face.send_bytes()`.  The nack pipeline's retry-forward and
  nack-propagation paths also use `enqueue_send`.
- **Configurable parallel pipeline processing** — `pipeline_threads` setting
  in `[engine]` config (default `0` = auto-detect).  `1` runs all processing
  inline in the pipeline runner (lowest latency, deterministic ordering).
  `N > 1` spawns per-packet tokio tasks so up to N pipeline passes run in
  parallel across cores (highest throughput with fragmented UDP traffic).
  The fragment sieve always runs single-threaded.  `PacketDispatcher` is
  `Arc`-wrapped for shared access; all pipeline stages are concurrent-safe
  (DashMap for PIT, Mutex for CS, Arc for shared tables).
- **PIT match order swapped** — `PitMatchStage` now tries the default-selector
  token first (common case for most Interests), then falls back to the
  None-selector token.  Eliminates a wasted DashMap probe + hash computation
  per Data packet.
- **Send queue capacity** increased from 128 to 512 to absorb bursts from
  parallel pipeline tasks dispatching to the same face near-simultaneously.
- **CS empty-check bypass** — `LruCs` maintains an atomic entry count.
  `get()` returns `None` immediately when the count is zero, skipping
  the global Mutex entirely.  Eliminates the main serialization point for
  parallel pipeline tasks on workloads that don't cache (e.g. iperf).
- **Strategy sync fast-path** — `ErasedStrategy::decide_sync()` lets
  strategies return a forwarding decision without `Box::pin` heap
  allocation.  `BestRouteStrategy` and `MulticastStrategy` implement
  this, avoiding one allocation per Interest on the hot path.
- **Synchronous signing fast-path** — `Signer::sign_sync()` method
  eliminates `Box::pin` + async state machine overhead for CPU-only
  signers.  `Ed25519Signer` and `HmacSha256Signer` implement this
  directly, removing one heap allocation per Data packet when signing.
- **`DataBuilder::sign_sync()`** — synchronous single-buffer packet
  encoding.  The async `sign()` path allocated 3–4 intermediate buffers
  (two `TlvWriter`s, one concatenation `Vec`, one final `TlvWriter`)
  and copied the entire signed region to satisfy lifetime constraints.
  `sign_sync()` builds the signed region incrementally in one pre-sized
  buffer, snapshots it for the signing closure, then writes the outer
  Data TLV — eliminating ~1.2M allocations/sec at line rate.
- **HMAC-SHA256 signer** — `HmacSha256Signer` in `ndn-security` for
  symmetric (pre-shared key) authentication using `ring::hmac`.
  Significantly faster than Ed25519 (~10×) for scenarios where
  asymmetric key distribution is unnecessary.
- **`ndn-iperf` signing fast-path** — server `--sign` and `--hmac`
  modes now use inline `sign_sync` + `DataBuilder::sign_sync()`,
  eliminating per-packet `Box::pin`, 8 KB `region.to_vec()` copy, and
  3 intermediate buffer allocations from the async signing path.
- **`ndn-iperf --hmac` flag** — server-side HMAC-SHA256 signing mode
  for benchmarking signing overhead without the cost of elliptic curve
  math.

### Fixed

- **Stale FIB routes on face disconnect** — when a face is removed from the face
  table, `Fib::remove_face` now purges all nexthops pointing to that face across
  all prefixes. Previously, stale nexthops accumulated when applications
  reconnected with new face IDs, causing `BestRouteStrategy` to forward Interests
  to dead faces (0 Mbps throughput when switching between SHM and Unix modes).
- **SHM face cleanup on app disconnect** — each accepted connection now gets a
  per-connection `CancellationToken` (child of the global token). SHM faces
  created via `faces/create` use a child of the control face's token. When the
  control face disconnects, the token cascade cancels the SHM face reader,
  triggering FIB and face table cleanup. Previously, SHM faces on macOS stayed
  blocked forever on FIFOs that never signaled EOF.
- **SHM spin-before-park** — added a 64-iteration spin loop in both `SpscFace`
  and `SpscHandle` recv before falling through to the pipe/futex sleep. Avoids
  expensive wakeup syscalls when packets arrive within microseconds of each other.
- **SHM ring capacity** increased from 64 to 256 slots — reduces backpressure
  during burst traffic and gives headroom for pipeline processing jitter.
- **SHM liveness detection for dead router** — `SpscHandle::recv()` races the
  pipe wakeup against a `CancellationToken` propagated from the control face.
  When the router dies, the token fires and recv returns `None` promptly.
  `SpscHandle::send()` uses a bounded yield loop (100K iterations) that returns
  `ShmError::Closed` if the ring stays full or the token fires. `pipe_await`
  now returns `Err` on EOF (n==0) instead of looping forever.
- **`RouterClient` liveness tracking** — `RouterClient` now carries a
  `CancellationToken` and `dead` flag. SHM handles receive a child token from the
  control face. `probe_alive()` sends a probe Interest on the control face and
  cancels the token on failure, causing SHM recv/send to abort promptly.
- **Idle sweep skips local faces** — `run_idle_face_task` now skips App, Shm, and
  Internal faces when checking for idle timeouts. Previously SHM faces were killed
  after 5 minutes of apparent inactivity (the idle sweep didn't track local face
  activity), causing iperf sessions to fail at ~324 seconds.

#### NDN spec compliance — SPEC-GAPS.md tracker and fixes

25-item spec compliance audit against RFC 8569, NDN Packet Format v0.3, and
NDNLPv2. Created `SPEC-GAPS.md` checklist. All 25 gaps resolved:

**ndn-tlv:**
- **VarNumber shortest-encoding validation** — `read_varu64` rejects non-minimal
  VarNumber forms (e.g. 3-byte encoding for values < 253).
- **TlvWriter minimal nested encoding** — `write_nested` now uses a temporary
  buffer and writes minimal-length encoding instead of a fixed 5-byte placeholder.
- **Types 0–31 grandfathered as critical** — `skip_unknown` treats types 0–31 as
  critical regardless of LSB parity, per NDN Packet Format v0.3 §1.3.

**ndn-packet:**
- **Ed25519 signature type code** — fixed from 7 to 5 per spec §10.3.
- **HopLimit decode** — `Interest::hop_limit()` lazily decodes TLV 0x22.
- **Nonce insertion** — `ensure_nonce()` adds a generated Nonce to Interests
  that lack one; called in TlvDecodeStage.
- **Zero-component Name rejection** — Interest and Data decoders reject empty Names.
- **ForwardingHint decode** — `Interest::forwarding_hint()` parses delegation Names
  from TLV 0x1E.
- **NDNLPv2 LpPacket module** (`lp.rs`) — decode/encode for LpPacket (0x64) with
  Nack header, CongestionMark, and Fragment fields.
- **Nack LpPacket framing** — `encode_nack` produces NDNLPv2-compliant LpPacket
  instead of bare 0x0320 TLV. `Nack::decode` accepts both formats.
- **ParametersSha256DigestComponent** — encoder computes SHA-256 digest; decoder
  validates both presence and correctness against ApplicationParameters.
- **`PacketError::MalformedPacket`** variant added for semantic validation errors.
- **Signed Interest support** — `Interest::sig_info()`, `sig_value()`, and
  `signed_region()` decode InterestSignatureInfo (0x2C) and InterestSignatureValue
  (0x2E) lazily; signed region covers Name through SigInfo for verification.
- **Signed Interest TLV constants** — `INTEREST_SIGNATURE_INFO`, `INTEREST_SIGNATURE_VALUE`,
  `SIGNATURE_NONCE`, `SIGNATURE_TIME`, `SIGNATURE_SEQ_NUM` added to `tlv_type`.
- **Anti-replay fields** — `SignatureInfo` decodes `sig_nonce` (0x26), `sig_time`
  (0x28), and `sig_seq_num` (0x2A) for signed Interest anti-replay protection.
- **Implicit SHA-256 digest** — `Data::implicit_digest()` computes SHA-256 of
  full wire encoding for exact Data retrieval via ImplicitSha256DigestComponent.
- **Link object support** — `Data::link_delegations()` parses delegation Names
  from Content field when ContentType=LINK.
- **NDNLPv2 fragmentation fields** — `LpPacket` decodes Sequence (0x51),
  FragIndex (0x52), and FragCount (0x53); `is_fragmented()` helper method.

**ndn-store:**
- **CS implicit digest lookup** — `LruCs::get` handles Interests with
  ImplicitSha256DigestComponent (type 0x01) by stripping the digest, looking up
  the Data name, and verifying the hash matches.
- **CS admission policy** — `CsAdmissionPolicy` trait with `DefaultAdmissionPolicy`
  (rejects FreshnessPeriod=0 Data) and `AdmitAllPolicy`. `CsInsertStage` consults
  the policy before caching.

**ndn-pipeline:**
- **`DropReason::HopLimitExceeded`** variant for HopLimit=0 enforcement.

**ndn-engine:**
- **TlvDecodeStage** — unwraps NDNLPv2 LpPackets, enforces HopLimit=0 drop,
  inserts Nonce, propagates CongestionMark via pipeline tags.
- **PIT aggregation** — `PitToken::from_interest_full` includes ForwardingHint
  in the hash key per RFC 8569 §4.2.

**ndn-store:**
- **`PitToken::from_interest_full`** — hashes (Name, Selector, ForwardingHint).

#### `ndn-security` — TLV certificate encoding and engine wiring

- **`certify()` full TLV encoding** — `SecurityManager::certify` now encodes a
  complete NDN certificate Data packet and signs it with the issuer's key:
  - Name: the subject key name
  - MetaInfo: `ContentType = KEY (2)`, `FreshnessPeriod = 3600000 ms`
  - Content: raw public key bytes + `ValidityPeriod` sub-TLV with
    `NotBefore`/`NotAfter` timestamps
  - SignatureInfo: `SignatureEd25519` with `KeyLocator` pointing to the issuer
  - SignatureValue: Ed25519 signature over the signed region

  The `MemKeyStoreExt` stub that always returned `CertNotFound` is replaced with
  `MemKeyStore::get_signer_sync`, a `pub(crate)` synchronous accessor that reads
  the DashMap directly.

  Helper: `encode_cert_data` builds the signed region, signs it, and wraps the
  result in an outer Data TLV.

- **`TlvWriter::write_raw`** — new method for embedding pre-encoded bytes
  (e.g., a signed region) into an outer TLV without re-framing.

- **`ndn-tlv` promoted to regular dependency** of `ndn-security` (was dev-only).

- **Engine wiring** — `EngineBuilder::security(mgr)` stores an
  `Arc<SecurityManager>` in `EngineInner`.  `ForwarderEngine::security()` exposes
  it.  `ndn-engine` now depends on `ndn-security`.

- **Router wiring** — `load_security` now returns `Option<SecurityManager>`
  instead of discarding it.  When a PIB identity is configured, the manager is
  passed to `EngineBuilder::security()`.

  Tests: `certify_produces_signed_cert`, `certify_fails_with_unknown_issuer`.

#### `ndn-packet` — Nack encoding

- **`encode_nack(reason, interest_wire)`** — encodes a Nack TLV (`0x0320`)
  wrapping the original Interest with the given `NackReason`. The Interest TLV
  is stripped of its outer wrapper and embedded as a child — matching the format
  expected by `Nack::decode`. Tests: `nack_roundtrip`, `nack_congestion_roundtrip`.

#### `ndn-engine` — NACK handling and ForwardAfter delay scheduling

- **Inbound NACK pipeline** — `nack_pipeline` in `PacketDispatcher` handles
  incoming Nack packets end-to-end:
  1. Looks up the PIT entry by the nacked Interest's name/selectors.
  2. Builds a `StrategyContext` and calls `on_nack_erased` on the strategy.
  3. If the strategy returns `Forward(faces)` — retries on alternate nexthops.
  4. If the strategy returns `Nack` — propagates the Nack to all in-record
     consumers and removes the PIT entry.
  5. `Suppress` / `ForwardAfter` — drops silently.

- **Outbound NACK dispatch** — `Action::Nack` now carries `PacketContext`
  (breaking change to the enum variant). `dispatch_action` encodes a Nack TLV
  via `encode_nack` and sends it back to `ctx.face_id`.

- **`ErasedStrategy::on_nack_erased`** — object-safe boxed-future wrapper for
  `Strategy::on_nack`, added alongside the existing `after_receive_interest_erased`.

- **ForwardAfter delay scheduling** — `StrategyStage` now spawns a Tokio timer
  for `ForwardAfter { faces, delay }` instead of forwarding immediately.  The
  delayed task re-checks the PIT before sending: if the entry was already
  satisfied or expired, the Interest is not forwarded.  The `StrategyStage`
  struct now holds `Arc<Pit>` and `Arc<FaceTable>` for this purpose.

#### `ndn-face-wireless` — NamedEtherFace with TPACKET_V2 mmap ring buffers

- **`NamedEtherFace`** — NDN face over raw Ethernet (`AF_PACKET` + `SOCK_DGRAM`,
  Ethertype `0x8624`).  Uses TPACKET_V2 mmap'd ring buffers for zero-copy packet
  I/O instead of per-packet `recvfrom`/`sendto` syscalls.

  **Ring buffer design:**
  - `PacketRing` struct manages the mmap'd region (RX ring at offset 0, TX ring
    immediately after).  Ring geometry: 2048 B frames, 4 KiB blocks, 32 blocks
    per ring → 64 frames × 2 rings = 256 KiB total.
  - `try_pop_rx()` — checks `tp_status & TP_STATUS_USER` with Acquire ordering,
    reads payload at `frame + tp_mac`, releases frame with `TP_STATUS_KERNEL`.
  - `try_push_tx()` — Mutex-protected; writes payload at `frame + TX_DATA_OFFSET`
    (52 bytes: `TPACKET_ALIGN(sizeof(tpacket2_hdr))` + `sizeof(sockaddr_ll)`),
    sets `TP_STATUS_SEND_REQUEST` with Release ordering.
  - `Face::recv` polls `try_pop_rx()`, falling back to `AsyncFd::readable()` +
    `clear_ready()` when the ring is empty.
  - `Face::send` polls `try_push_tx()`, then calls `sendto(fd, NULL, 0, ...)`
    to flush all pending TX frames to the kernel.

  **Helpers:** `MacAddr` (6-byte address with `Display`), `get_ifindex` (via
  `SIOCGIFINDEX`), `make_sockaddr_ll`, `open_packet_socket` (non-blocking,
  `SOCK_CLOEXEC`), `setup_packet_ring` (TPACKET_V2 + RX/TX ring config + mmap).

  Requires `CAP_NET_RAW` or root.  Linux only (`#[cfg(target_os = "linux")]`).

  Tests: `mac_addr_display`, `mac_addr_broadcast`, `sockaddr_ll_layout`,
  `ring_geometry`, `tx_data_offset_is_correct`, `new_fails_without_cap_net_raw`,
  `loopback_roundtrip` (ignored — needs root).

#### `ndn-sync` — Dataset synchronisation protocols

- **`SvsNode`** — State Vector Sync node. Maintains a `HashMap<String, u64>` state vector
  (node key → highest seen sequence number). `advance()` increments the local seq;
  `merge(received)` updates entries and returns `(node, gap_from, gap_to)` tuples for
  missing data; `snapshot()` serialises the full vector.

- **`PSyncNode` / `Ibf`** — Partial Sync via Invertible Bloom Filters. `Ibf` implements
  insert, remove, subtract, and `decode()` with a per-cell `hash_sum` checksum (splitmix64
  finalizer) to distinguish genuine pure cells from coincidental `xor_sum` collisions.
  Cell selection uses the splitmix64 finalizer seeded with the element value XOR'd with the
  hash-function index, giving good distribution even for structurally similar name hashes.
  `PSyncNode::reconcile(peer_ibf)` returns the symmetric difference as two `HashSet<u64>`
  values — hashes the local node has that the peer lacks, and vice versa.

#### `ndn-compute` — In-network compute

- **`ComputeRegistry`** — `NameTrie`-backed longest-prefix dispatch to
  `Arc<dyn ErasedHandler>`. `register<H: ComputeHandler>(prefix, handler)` adds a handler;
  `dispatch(interest)` does an LPM lookup and returns the handler's async result.
- **`ComputeFace`** — `Face` implementation that forwards Interests to the `ComputeRegistry`.
  `recv()` returns `pending()` (this face only injects Data, never receives from the network).

#### `ndn-research` — Research extensions

- **`FlowTable`** — `DashMap`-backed per-prefix flow entry (preferred face, EWMA throughput,
  EWMA RTT). `flush_interface(face_id)` atomically removes all entries for a face (called on
  radio channel switch).
- **`FlowObserverStage`** — Non-blocking `PipelineStage` that emits `FlowEvent`s via
  `try_send`. Optional `sampling_rate` (0.0–1.0) limits observer overhead on high-rate
  testbeds. Never slows the forwarding path.
- **`ChannelManager`** — nl80211 channel switch stub. `switch(face_id, channel)` returns
  `Err(SwitchError::NotImplemented)` until netlink integration is added.

#### Binaries

- **`ndn-router`** — Standalone forwarder: initialises tracing, builds engine with
  `EngineConfig::default()`, waits for Ctrl-C, then shuts down cleanly.
- **`ndn-peek`** — Parses `<name>` and `--timeout-ms` arguments, constructs an `Interest`,
  and prints the fetch plan. Forwarder connection not yet wired.
- **`ndn-ping`** — Sends `count` probe Interests to `prefix/ping/<seq>` at `interval-ms`
  spacing, measures RTT, and prints min/avg/max. Forwarder connection not yet wired.
- **`ndn-put`** — Reads a file, segments it with `ChunkedProducer`, and logs per-segment
  sizes. Accepts `--chunk-size`. Forwarder connection not yet wired.
- **`ndn-bench`** — Embeds an engine, drives Interest/Data load via `AppFace` channel pairs
  across `--concurrency` workers, and reports throughput and latency percentiles (p50/p95/p99).

#### `ndn-engine` — Layer 1 forwarding engine

- **`Fib` / `FibEntry` / `FibNexthop`** — engine-layer FIB wrapping `NameTrie<Arc<FibEntry>>`.
  Uses `FaceId` (not `u32`) directly. `add_nexthop` upserts by face; `remove_nexthop` removes
  the entry entirely when the last nexthop is removed.

- **`ForwarderEngine`** — `Arc<EngineInner>` handle. Cheaply cloneable; clones share the same
  FIB, PIT, and `FaceTable`. Exposes `fib()`, `pit()`, `faces()` accessors.

- **`EngineBuilder` / `EngineConfig`** — constructs and wires the engine. `face<F: Face>` adds
  pre-configured faces before startup. `build()` spawns the PIT expiry task and returns
  `(ForwarderEngine, ShutdownHandle)`.

- **`ShutdownHandle`** — `CancellationToken` + `JoinSet<()>`. `shutdown()` cancels all engine
  tasks and joins them, logging any panics at `WARN` level.

- **`run_expiry_task`** — background task that drains expired PIT entries every millisecond.
  Exits cleanly on `CancellationToken` cancellation.

#### `ndn-app` — Layer 1 application API

- **`AppFace::new(face_id, capacity) -> (AppFace, Receiver<OutboundRequest>)`** — factory that
  creates the application-side face and the engine-side request receiver as a linked pair.

- **`OutboundRequest`** — `pub` enum (`Interest { interest, reply }` and
  `RegisterPrefix { prefix, handler }`) that flows from `AppFace` to the engine runner over
  `mpsc`. Made public so the engine can match on received requests.

- **`AppError`** — `Timeout`, `Nacked { reason }`, `Engine(anyhow::Error)`.

#### `ndn-ipc` — Layer 1 IPC utilities

- **`ChunkedProducer`** — segments an arbitrary `Bytes` payload into fixed-size chunks
  (`NDN_DEFAULT_SEGMENT_SIZE = 8192`). `segment(index)` returns individual chunks for
  prefix-registered Data production; `segment_count()` supplies FinalBlockId.

- **`ChunkedConsumer`** — reassembles out-of-order segments by index. `receive_segment(i, data)`
  stores each chunk; `is_complete()` and `reassemble()` drive the consumer state machine.

- **`IpcClient`** — wraps `Arc<AppFace>` with a namespace `Name` for ergonomic Interest
  expression.

- **`IpcServer`** — wraps `Arc<AppFace>` with a prefix `Name` for handler registration.

- **`ServiceRegistry`** — in-memory service registry keyed by name string. `register`,
  `lookup`, `unregister`, `service_count`. Mirrors the `/local/services/<name>/info` namespace
  pattern for single-process deployments.

#### `ndn-store` — Layer 4 data structures

- **`NameTrie::first_descendant(prefix: &Name) -> Option<V>`** — depth-first
  search from a prefix node to find any value stored at or below that position.
  Used by `LruCs` for `CanBePrefix` lookups.

- **`Fib` / `FibEntry` / `FibNexthop`** — Forwarding Information Base wrapping
  `NameTrie<Arc<FibEntry>>`. Exposes `lpm`, `get`, `insert`, `add_nexthop`, and
  `remove`. Uses `u32` for `face_id` (consistent with `PIT`) to avoid a
  same-layer cross-dependency on `ndn-transport`.

- **`StrategyTable<S>`** — generic newtype over `NameTrie<Arc<S>>` for
  longest-prefix strategy dispatch. Decoupled from the concrete `Strategy` trait
  (defined in `ndn-strategy`) so it can live in the foundational store layer.

- **`ShardedCs<C: ContentStore>`** — shards any `ContentStore` across `N`
  instances. Shard selection is by first name component so that related content
  (`/video/seg/1`, `/video/seg/2`) lands in the same shard, preserving LRU
  locality for sequential access patterns. `capacity()` aggregates all shards.

#### `ndn-store` — `LruCs` improvements

- **`CanBePrefix` support** — `LruInner` now carries a
  `prefix_index: NameTrie<Arc<Name>>` secondary index. Every insert adds the
  name to the trie; every eviction (explicit or LRU-triggered) removes it.
  `get()` uses `first_descendant` for `CanBePrefix` interests.

- **Fixed linear-scan evict bug** — `evict()` previously did an O(n) scan to
  reconstruct an `Arc<Name>` key. It now calls `cache.pop(name: &Name)` directly
  via `Arc<Name>: Borrow<Name>`.

- **Fixed entry-count limit** — the `LruCache` cap was `capacity_bytes / 64`
  (minimum 1), which starved small capacities of entries before byte-based
  eviction could kick in. Changed to `capacity_bytes.max(1)` so the byte loop
  is always the sole eviction control.

#### `ndn-transport` — Layer 4 transport utilities

- **`TlvCodec`** — `tokio_util::codec` `Decoder` / `Encoder` for NDN TLV stream
  framing. Handles all `varu64` type and length widths. Used by `TcpFace`,
  `UnixFace`, and `SerialFace` (implemented in Layer 3 face crates).

- **`FacePairTable`** — `DashMap`-backed rx→tx `FaceId` mapping for asymmetric
  wfb-ng links. The dispatch stage calls `get_tx_for_rx(in_face).unwrap_or(in_face)`
  so symmetric faces (no table entry) fall through unchanged.

- **`FaceEvent`** — `Opened(FaceId)` / `Closed(FaceId)` lifecycle events.
  Face tasks emit `Closed` when `recv()` returns `FaceError::Closed`; the face
  manager uses this to clean up PIT `OutRecord` entries.

#### `ndn-pipeline` — Layer 2 packet pipeline

- **`PipelineStage` trait** — `async fn process(&self, ctx: PacketContext) -> Result<Action, DropReason>` with `BoxedStage` alias for dynamic dispatch.
- **`PacketContext`** — per-packet value type carrying raw bytes, face ID, decoded name, decoded packet, PIT token, out-face list, cs_hit / verified flags, arrival timestamp, and a typed `AnyMap` escape hatch for inter-stage communication.
- **`Action`** — ownership-based enum (`Continue`, `Send`, `Satisfy`, `Drop`, `Nack`). Returning `Continue` hands the context to the next stage; all other variants consume it — use-after-hand-off is a compile error.
- **`ForwardingAction`** — strategy return type (`Forward`, `ForwardAfter`, `Nack`, `Suppress`). `ForwardAfter` carries a `Duration` for probe-and-fallback scheduling.
- **`DropReason` / `NackReason`** — typed enums, not stringly-typed codes.

#### `ndn-strategy` — Layer 2 forwarding strategies

- **`Strategy` trait** — `after_receive_interest`, `after_receive_data`, `on_interest_timeout`, `on_nack` (last two default to `Suppress`). Returns `SmallVec<[ForwardingAction; 2]>` — two actions inline for probe-and-fallback without allocation.
- **`StrategyContext`** — immutable view of engine state (`name`, `in_face`, `fib_entry`, `pit_token`, `measurements`). Strategies cannot mutate forwarding tables directly.
- **`FibEntry` / `FibNexthop`** — local strategy-layer types using `FaceId` (not `u32`) to allow direct face dispatch without cross-layer dependency confusion.
- **`BestRouteStrategy`** — lowest-cost nexthop, split-horizon (`nexthops_excluding(in_face)`). Falls back to `Nack(NoRoute)` when no nexthop exists.
- **`MulticastStrategy`** — fans Interest to all nexthops except the incoming face. Returns all face IDs in a single `Forward` action.
- **`MeasurementsTable`** — `DashMap`-backed EWMA RTT and satisfaction rate per (prefix, face). Updated before strategy call so strategies read fresh RTT. `EwmaRtt::rto_ns()` = srtt + 4×rttvar.

#### `ndn-security` — Layer 2 security

- **`Signer` / `Ed25519Signer`** — `BoxFuture`-based async signing (enables `Arc<dyn Signer>` storage). `Ed25519Signer::from_seed(&[u8; 32], key_name)` for deterministic construction.
- **`Verifier` / `Ed25519Verifier` / `VerifyOutcome`** — `Invalid` is `Ok(VerifyOutcome::Invalid)` not `Err`, since a bad signature is an expected outcome, not an exception.
- **`TrustSchema` / `NamePattern` / `PatternComponent`** — rule-based data-name / key-name pattern matching with named capture groups. `Capture` binds one component; `MultiCapture` consumes trailing components. Captured variables must be consistent between data and key patterns.
- **`CertCache`** — `DashMap`-backed in-memory certificate cache. Certificates are named Data packets fetched via Interest.
- **`KeyStore` trait / `MemKeyStore`** — async key store trait; `MemKeyStore` for testing.
- **`SafeData`** — wraps `Data` + `TrustPath` + `verified_at`. `pub(crate)` constructors prevent application code from bypassing verification.
- **`Validator`** — schema check → cert cache lookup → cryptographic verification. Returns `Valid(SafeData)`, `Invalid(TrustError)`, or `Pending` (cert not yet cached). Exposes `cert_cache()` accessor for pre-population in tests.

#### `ndn-face-net` — Layer 3 network faces

- **`UdpFace`** — unicast UDP face. The socket is `connect()`-ed to the peer at
  construction, so the kernel filters inbound datagrams. `from_socket` wraps a
  pre-configured socket; `bind` creates and connects one atomically.

- **`TcpFace`** — TCP face with `TlvCodec` stream framing. Stream is split into
  `FramedRead` / `FramedWrite` halves, each behind a `tokio::sync::Mutex`.
  `from_stream` wraps an accepted stream; `connect` opens a new connection.

- **`MulticastUdpFace`** — NDN IPv4 multicast face. Publishes `NDN_MULTICAST_V4`
  (`224.0.23.170`) and `NDN_PORT` (`6363`) constants. `recv` captures datagrams
  from any sender (neighbor discovery); `send` multicasts to the group. The
  multicast loopback roundtrip test is best-effort and skips gracefully in
  sandboxed CI environments.

#### `ndn-engine` — Pipeline dispatcher (new)

- **`TlvDecodeStage`** — decodes `ctx.raw_bytes` into `DecodedPacket::Interest`,
  `Data`, or `Nack`; sets `ctx.packet` and `ctx.name`. Returns
  `Action::Drop(MalformedPacket)` on any parse failure.

- **`CsLookupStage`** — CS hit path: inserts `CsEntry` into `ctx.tags`, sets
  `ctx.cs_hit`, appends `ctx.face_id` to `ctx.out_faces`, and returns
  `Action::Satisfy` — bypassing PIT/FIB entirely. Miss path returns
  `Action::Continue`.

- **`CsInsertStage`** — stores received Data in the CS after PIT fan-back.
  Derives `stale_at` from `MetaInfo::freshness_period`; defaults to immediately
  stale when absent.

- **`PitCheckStage`** — Interest path: detects loop (nonce already in
  `nonces_seen` → `Drop(LoopDetected)`), aggregates (existing PIT entry, new
  in-record → `Drop(Suppressed)`), or creates a new entry and continues to the
  strategy stage.

- **`PitMatchStage`** — Data path: removes PIT entry, populates `ctx.out_faces`
  from `in_record_faces()`, returns `Drop(Other)` for unsolicited Data.

- **`ErasedStrategy`** — object-safe wrapper over the `impl Future`-based
  `Strategy` trait. Blanket impl boxes the strategy future so the stage can be
  stored as `Arc<dyn ErasedStrategy>`.

- **`StrategyStage`** — converts engine `FibEntry` → strategy `FibEntry`,
  builds `StrategyContext`, calls `ErasedStrategy::after_receive_interest_erased`,
  and translates `ForwardingAction` into `Action`. `ForwardAfter` forwards
  immediately (delay scheduling not yet implemented).

- **`PacketDispatcher`** — owns all stages and the face table. `spawn()` creates
  a bounded `mpsc` channel, starts one reader task per registered face, and runs
  the pipeline runner. The runner spawns a Tokio task per packet for parallel
  processing. Interest path: decode → CS lookup → PIT check → strategy → send.
  Data path: decode → PIT match → CS insert → satisfy.

- **`run_face_reader`** — async loop calling `ErasedFace::recv_bytes()`,
  wrapping results into `InboundPacket`, and forwarding to the pipeline channel.
  Exits cleanly on `FaceError::Closed` or `CancellationToken`.

- **`ErasedFace::recv_bytes()`** added to `ndn-transport::FaceTable` —
  object-safe boxed future wrapping `Face::recv()`, allowing the dispatcher to
  read from any face stored in the `FaceTable` without knowing its concrete type.

- **`EngineInner`** extended with `cs: Arc<LruCs>` and
  `measurements: Arc<MeasurementsTable>`; `ForwarderEngine` exposes `cs()` accessor.

- **`EngineBuilder::build()`** now wires all stages, constructs `PacketDispatcher`,
  and spawns it. `EngineBuilder::strategy<S: ErasedStrategy>` overrides the
  default `BestRouteStrategy`.

#### `ndn-security` — `SecurityManager` (new)

- **`SecurityManager`** — high-level orchestrator over `MemKeyStore` and
  `CertCache`. Operations:
  - `generate_ed25519(key_name)` — generates an Ed25519 key pair and stores it.
  - `generate_ed25519_from_seed(key_name, &[u8; 32])` — deterministic variant for testing.
  - `issue_self_signed(key_name, public_key_bytes, validity_ms)` — creates a
    `Certificate`, inserts it into both the cert cache and the trust-anchor set.
  - `certify(subject_key_name, public_key, issuer_key_name, validity_ms)` —
    issues a CA-signed certificate (full TLV cert encoding deferred).
  - `add_trust_anchor(cert)` — registers a pre-existing cert as implicitly trusted.
  - `trust_anchor(key_name)` / `trust_anchor_names()` — anchor lookup.
  - `get_signer(key_name)` — delegates to the key store.
  - `cert_cache()` — exposes the cache for passing to `Validator`.

#### `ndn-config` — new crate (Layer 1)

- **`ForwarderConfig`** — TOML-serialisable top-level config struct. Parsed with
  `from_str(s)` or `from_file(path)`; round-tripped with `to_toml_string()`.

  Fields:
  - `[engine]` → `EngineConfig { cs_capacity_mb, pipeline_channel_cap }` (defaults: 64 MB, 1024).
  - `[[face]]` → `FaceConfig { kind, bind?, remote?, group?, port?, interface?, path? }`.
    `kind` is one of `"udp"`, `"tcp"`, `"multicast"`, `"unix"`.
  - `[[route]]` → `RouteConfig { prefix, face, cost }` (`cost` defaults to 10).
  - `[security]` → `SecurityConfig { trust_anchor?, key_dir?, require_signed }`.

- **`ManagementRequest`** / **`ManagementResponse`** — JSON-tagged enums for the
  Unix-socket management protocol. Commands: `add_route`, `remove_route`,
  `list_routes`, `list_faces`, `get_stats`, `shutdown`. Responses: `Ok`,
  `OkData { data }`, `Error { message }`.

- **`ManagementServer`** — holds the socket path; `decode_request(line)` and
  `encode_response(resp)` handle newline-delimited JSON serialisation.

#### `ndn-router` — config and management wiring

- Accepts `-c <path>` to load a `ForwarderConfig` TOML file; uses defaults when
  omitted.
- Applies `[[route]]` entries from the config to the live FIB at startup.
- Spawns a Unix-socket management server (`-m <path>`, default
  `/tmp/ndn-router.sock`) that handles `ManagementRequest` JSON commands: route
  add/remove are reflected into the engine FIB immediately; `get_stats` returns
  live PIT size; `list_faces` enumerates registered face IDs; `shutdown` fires the
  `CancellationToken`.

#### `ndn-face-local` — Layer 3 local faces

- **`UnixFace`** — Unix domain socket face with `TlvCodec` framing. Same
  `FramedRead`/`FramedWrite` + `Mutex` design as `TcpFace`. `connect` opens a
  new connection; `from_stream` wraps an accepted stream. Carries the socket path
  for diagnostics. Tests use a `process::id() + AtomicU64` counter for socket
  paths (replacing `subsec_nanos()`) to prevent path collisions between parallel
  tests, and `loopback_pair` is guarded by a 5-second timeout so a mis-bound
  listener never causes a silent hang.

- **`AppFace` / `AppHandle`** — in-process face backed by a pair of
  `tokio::sync::mpsc` channels. `AppFace::new(id, buffer)` returns both halves.
  The pipeline holds `AppFace`; the application holds `AppHandle`. Drop either
  side to signal closure (`FaceError::Closed` / `None`).

### Tests added

| Crate | Module | Count |
|-------|--------|------:|
| `ndn-sync` | `svs` | 7 |
| `ndn-sync` | `psync` | 7 |
| `ndn-compute` | `registry` | 4 |
| `ndn-research` | `flow_table` | 5 |
| `ndn-research` | `observer` | 3 |
| `ndn-research` | `channel_manager` | 2 |
| `ndn-engine` | `fib` | 8 |
| `ndn-engine` | `builder` | 3 |
| `ndn-engine` | `expiry` | 2 |
| `ndn-app` | `app_face` | 6 |
| `ndn-ipc` | `chunked` | 7 |
| `ndn-ipc` | `client` | 1 |
| `ndn-ipc` | `server` | 1 |
| `ndn-ipc` | `registry` | 5 |
| `ndn-store` | `trie` | 14 |
| `ndn-store` | `fib` | 8 |
| `ndn-store` | `strategy_table` | 7 |
| `ndn-store` | `lru_cs` | 17 |
| `ndn-store` | `sharded_cs` | 9 |
| `ndn-transport` | `tlv_codec` | 8 |
| `ndn-transport` | `face_pair_table` | 6 |
| `ndn-transport` | `face_event` | 2 |
| `ndn-pipeline` | `action` | 8 |
| `ndn-pipeline` | `context` | 6 |
| `ndn-strategy` | `measurements` | 6 |
| `ndn-strategy` | `best_route` | 5 |
| `ndn-strategy` | `multicast` | 4 |
| `ndn-security` | `trust_schema` | 8 |
| `ndn-security` | `signer` | 6 |
| `ndn-security` | `verifier` | 5 |
| `ndn-security` | `key_store` | 4 |
| `ndn-security` | `safe_data` | 3 |
| `ndn-security` | `validator` | 5 |
| `ndn-face-net` | `udp` | 4 |
| `ndn-face-net` | `tcp` | 6 |
| `ndn-face-net` | `multicast` | 4 |
| `ndn-face-local` | `unix` | 5 |
| `ndn-face-local` | `app` | 7 |
| `ndn-engine` | `stages` (decode, cs, pit, strategy) | — |
| `ndn-security` | `manager` | 7 |
| `ndn-config` | `config` | 6 |
| `ndn-config` | `mgmt` | 10 |
| **Total new** | | **243** |

Running total across all crates: **337 tests**, all passing.

### Investigated and rejected

#### Multi-threaded pipeline dispatcher

Prototyped three `EngineConfig` knobs for parallelising the pipeline:

- **`pipeline_runners`** — N tasks sharing the inbound `mpsc::Receiver` via
  `Arc<Mutex<Receiver>>`, each competing to drain packets.
- **`max_concurrent_packets`** — `tokio::sync::Semaphore` gating in-flight
  `process_packet` spawns (0 = unlimited).
- **`pit_shards`** — `Pit::with_shard_amount(n)` passed through to
  `DashMap::with_shard_amount`.

Benchmarked 1000-packet batches through the full dispatcher (AppFace →
decode → CS miss → PIT → strategy Nack → fan-back) on a 4-thread Tokio
runtime:

| Config | Throughput | Time / 1000 pkts |
|--------|-----------|-----------------|
| 1 runner, unlimited | **668 Kpps** | 1.50 ms |
| 1 runner, 512 limit | **708 Kpps** | 1.41 ms |
| 2 runners, unlimited | 380 Kpps | 2.63 ms |
| 4 runners, unlimited | 340 Kpps | 2.94 ms |
| 4 runners, 512 limit | 335 Kpps | 2.97 ms |

**Conclusion:** The pipeline bottleneck is not the single runner's
`recv → spawn` loop — it's the per-packet decode/PIT/strategy work, which
already runs in parallel via `tokio::spawn`. Adding multiple runners only
adds `Arc<Mutex<Receiver>>` contention (≈2× slower). The semaphore had
negligible overhead and marginally improved throughput by bounding scheduler
pressure, but the benefit is too small to justify the complexity.

All three knobs reverted. The single-runner, unlimited-spawn design remains
the default. If a future workload (e.g., per-packet crypto verification)
makes the runner loop itself the bottleneck, this can be revisited.

---

## [Unreleased — SPSC futex / pipe wakeup]

### Changed

#### `ndn-face-local` — platform-native wakeup replaces `UnixDatagram`

The per-packet wakeup mechanism in `SpscFace` / `SpscHandle` now uses the
fastest primitive available on each platform.  The parked-flag protocol
(SeqCst store → second ring check → sleep) is unchanged; only the
sleep/wake primitive changes.

**Linux — futex via `atomic-wait`**

`atomic_wait::wait(parked, 1)` blocks the OS thread while `parked == 1`;
the producer calls `atomic_wait::wake_one(parked)` to unblock.  The futex
syscall keys on the physical SHM page offset, so it works cross-process
without any additional file descriptor.  The wait runs inside
`tokio::task::spawn_blocking` to keep the async executor responsive.

**macOS / other Unix — named FIFO pair**

`SpscFace::create` creates two named FIFOs
(`/tmp/.ndn-{name}.a2e.pipe`, `.e2a.pipe`) and opens them with
`O_RDWR | O_NONBLOCK` (avoids the blocking-open problem: neither side
needs to wait for the other to open).  The consumer awaits readability via
`tokio::io::unix::AsyncFd` (backed by kqueue); the producer writes 1 byte
via a direct non-blocking `libc::write`.  Silently ignores `EAGAIN` on the
write — if the pipe buffer is full the consumer already has a pending
wakeup.

**Removed**: `tokio::net::UnixDatagram` fields (`sock`, `sock_path`,
`app_path` / `eng_path`) from both `SpscFace` and `SpscHandle`.  On Linux
those structs now carry **no extra fields** beyond the SHM region.

#### Dependency

- `atomic-wait = "1"` added to workspace dependencies and to the
  `ndn-face-local` `spsc-shm` feature (`spsc-shm = ["dep:libc",
  "dep:atomic-wait"]`).  The crate is compiled on all platforms but its
  symbols are only referenced under `#[cfg(target_os = "linux")]`.

#### Tests

All four `shm::spsc` tests updated to
`#[tokio::test(flavor = "multi_thread", worker_threads = 2)]` — required
because `spawn_blocking` panics in a `current_thread` runtime.
`rt-multi-thread` added to `ndn-face-local` dev-dependency tokio features.

---

## [Unreleased — SPSC parked-flag optimization, iceoryx2 bridge redesign]

### Removed

- **`iceoryx2` dependency dropped** — removed from the entire workspace.
  `SpscFace` with the parked-flag optimization is now the sole SHM backend and
  is faster in every measured dimension.  The removed code:
  - `crates/ndn-face-local/src/shm/iox2.rs` — `Iox2Face` / `Iox2Handle`
  - `iceoryx2-shm` Cargo feature in `ndn-face-local`
  - `iceoryx2-mgmt` Cargo feature in `ndn-router` and `ndn-tools`
  - `binaries/ndn-router/src/mgmt_ipc.rs` — iceoryx2 management server
  - `iceoryx2` bypass path in `ndn-tools/src/ctl.rs`
  - `iceoryx2 = "0.8.1"` workspace dependency

  `ShmFace` / `ShmHandle` type aliases in `shm/mod.rs` now always resolve to
  `SpscFace` / `SpscHandle`.  The bypass management transport in `ndn-router`
  and `ndn-ctl` retains its Unix-socket path; the iceoryx2 bypass path is gone.

### Changed

#### `ndn-face-local` — SPSC parked-flag wakeup optimization

Eliminated per-packet wakeup syscalls during bursts by adding two atomic
parked-flag fields to the SHM header.

**Protocol** (SeqCst total-order fence prevents the ABA race):
1. Consumer sets `parked = 1` with `SeqCst` store.
2. Consumer re-checks the ring; if non-empty, clears the flag and returns.
3. Consumer sleeps on `UnixDatagram::recv`.
4. Producer checks `parked` with `SeqCst` load; sends wakeup datagram only if
   non-zero.

**Header layout change** — two new cache-line-aligned fields extend the header
from 5 to 7 cache lines (320 → 448 bytes):

| Cache line | Contents |
|-----------|---------|
| 0 | magic, capacity, slot\_size |
| 1 | a2e head/tail ring indices |
| 2 | e2a head/tail ring indices |
| 3 | (reserved padding) |
| 4 | (reserved padding) |
| 5 | `a2e_parked` flag (engine / a2e consumer) |
| 6 | `e2a_parked` flag (app / e2a consumer) |

#### `ndn-face-local` — iceoryx2 bridge redesign

Replaced the WaitSet + event-service design (which hung on macOS during
benchmarks) with a simpler `recv_timeout` poll:

- Bridge threads sleep on `std::sync::mpsc::Receiver::recv_timeout(200 µs)`.
- Tokio send path immediately wakes the bridge via `SyncSender<()>::try_send`
  stored as `KickFn = Box<dyn Fn() + Send + Sync + 'static>`.
- `ipc::Service` (single-threaded) replaces `ipc_threadsafe::Service`; the kick
  channel is `Send + Sync` so no thread-safety upgrade is needed.
- Fixed `ZeroCopySend` derive: added `use iceoryx2::prelude::ZeroCopySend;` so
  the plain `#[derive(ZeroCopySend)]` compiles without the path-qualified form.
- Fixed `ServiceName::try_into`: iceoryx2 implements `TryFrom<&str>` not
  `TryFrom<String>`; helper fns now call `.as_str().try_into()`.
- Benchmark fixed to reuse a single service pair across all payload sizes, avoiding
  iceoryx2 node-registry exhaustion on macOS when pairs are rapidly created and
  torn down.

### Benchmark results (macOS, release build, after SPSC parked-flag optimization)

Run: `cargo bench -p ndn-face-local --features spsc-shm,iceoryx2-shm`

| Benchmark | p50 latency / throughput | vs. before | Notes |
|-----------|--------------------------|------------|-------|
| `appface/latency/64` | 142 ns | — | reference (unchanged) |
| `appface/latency/1024` | 143 ns | — | |
| `appface/latency/8192` | 144 ns | — | |
| `appface/throughput/64` | 2.82 Mpkt/s | — | |
| `appface/throughput/1024` | 2.83 Mpkt/s | — | |
| `appface/throughput/8192` | 2.82 Mpkt/s | — | |
| `unix/latency/64` | 2.10 µs | — | |
| `unix/latency/1024` | 2.32 µs | — | |
| `unix/latency/8192` | 6.92 µs | — | |
| `unix/throughput/64` | 2.53 Mpkt/s | — | |
| `unix/throughput/1024` | 1.51 Mpkt/s | — | |
| `unix/throughput/8192` | 404 Kpkt/s | — | |
| `spsc/latency/64` | **124 ns** | **−95 %** (was 2.57 µs) | parked-flag eliminates wakeup |
| `spsc/latency/1024` | **200 ns** | **−93 %** (was 2.69 µs) | |
| `spsc/latency/8192` | **678 ns** | **−80 %** (was 3.41 µs) | copy cost visible at 8 KiB |
| `spsc/throughput/64` | **34.4 Mpkt/s** | **+42×** (was 810 Kpkt/s) | no syscall during burst |
| `spsc/throughput/1024` | **15.7 Mpkt/s** | **+20×** (was 776 Kpkt/s) | |
| `spsc/throughput/8192` | **3.30 Mpkt/s** | **+5×** (was 645 Kpkt/s) | |
| `iox2/latency` | pending | — | bench infra stabilised; macOS IPC quirks under investigation |
| `iox2/throughput` | pending | — | |

**Key findings after SPSC optimization:**

- `SpscFace` now beats `UnixFace` latency by **17×** at 64 B (124 ns vs 2.10 µs)
  and is on par with `AppFace` (142 ns) at small sizes.  The wakeup datagram cost
  was entirely dominating before; it is now paid only when the consumer genuinely
  sleeps between packets.

- `SpscFace` throughput leaps from sub-`UnixFace` to **14× faster** at 64 B
  (34.4 Mpkt/s vs 2.53 Mpkt/s), making it the fastest transport for burst traffic.

- At 8 192 B the `memcpy` into the fixed SHM slot (65 520 bytes per slot)
  begins to appear, but latency is still 10× better than before optimization
  and 10× better than `UnixFace`.

- `AppFace` and `UnixFace` numbers are stable within noise (< 2 % variance),
  confirming no regression in those paths.

---

## [Unreleased — NDN management, face lifecycle, SHM faces, benchmarks]

### Added

#### `ndn-router` — NDN-native management transport

- **NDN management over Interest/Data** (`mgmt_ndn` module) — replaces the
  bootstrap-only Unix-socket bypass as the primary management path.
  - `run_ndn_mgmt_handler` — async task that receives `Interest` packets from an
    `AppHandle`, decodes the `ApplicationParameters` TLV payload as JSON
    `ManagementRequest`, dispatches via `handle_request`, and writes the
    `ManagementResponse` back as a `Data` packet.
  - `run_face_listener` — async task that binds a `UnixFace` listener at the
    path configured in `[management].face_socket`; for each accepted connection
    it calls `ForwarderEngine::add_face` so the face participates in normal
    forwarding.
  - `mgmt_prefix()` — returns `/localhost/ndn-ctl` as a `Name`.
  - The management `AppFace` is pre-registered with the `EngineBuilder` (FaceId
    `0xFFFF_0001`) and its prefix `/localhost/ndn-ctl/…` is installed in the FIB
    before startup so management Interests are routed without any special-casing
    in the pipeline.
- **Transport selection** — `[management].transport = "ndn"` (default) activates
  NDN-over-face; `"bypass"` falls back to the Unix-socket or iceoryx2 path.
- **`ndn_face_local::AppFace` / `AppHandle`** used throughout — `ndn_app::AppFace`
  does not implement the `Face` trait and cannot be registered with the engine;
  all engine-adjacent code was updated to use `ndn_face_local`.

#### `ndn-config` — management config extended

- Added `[management]` section with `transport` (default `"ndn"`),
  `face_socket` (Unix socket path for NDN face listener), and `bypass_socket`
  (path for raw JSON bypass socket).

#### `ndn-tools` — `ndn-ctl` NDN transport

- `ndn-ctl` now sends management commands as NDN Interests over a `UnixFace`
  connection to the router's face listener (default `/tmp/ndn-face.sock`).
  `ApplicationParameters` TLV carries the JSON request; the first Data packet
  back is decoded as the JSON response.  The iceoryx2 path is preserved when the
  `iceoryx2-mgmt` feature is enabled.
- Added missing `ndn-face-local` and `ndn-transport` workspace dependencies to
  `binaries/ndn-tools/Cargo.toml`.

#### `ndn-store` — `NameTrie::dump`

- **`NameTrie::dump() -> Vec<(Name, V)>`** — depth-first traversal of the entire
  trie returning all stored entries as `(Name, value)` pairs.  Releases each
  node's `RwLock` before recursing into children to avoid deadlock on the
  concurrent trie.

#### `ndn-engine` — `Fib::dump`

- **`Fib::dump() -> Vec<(Name, Arc<FibEntry>)>`** — delegates to
  `NameTrie::dump()` so the management handler can serialise the full FIB.

#### `ndn-transport` — face table improvements

- **`FaceTable::face_entries() -> Vec<(FaceId, FaceKind)>`** — returns all
  registered faces with their kind, used by `list-faces` to show human-readable
  face types instead of raw IDs.
- **`ErasedFace::kind()`** — `kind()` method added to the object-safe
  `ErasedFace` trait (and its blanket `impl<F: Face> ErasedFace for F`) so the
  face table can expose kind without knowing the concrete type.
- **Face ID recycling** — `FaceTable` now holds a `Mutex<Vec<u32>>` free list.
  `alloc_id()` pops from the free list before bumping the atomic counter, so IDs
  are reused after face teardown instead of monotonically growing.
- **Reserved ID range** — `RESERVED_FACE_ID_MIN = 0xFFFF_0000`; IDs at or above
  this value are never allocated by `alloc_id()` and are never added to the free
  list.  The management `AppFace` uses `0xFFFF_0001`.

#### `ndn-transport` — `FaceKind::Shm`

- New variant `FaceKind::Shm` for shared-memory faces.  Appears in
  `list-faces` output; treated as a transient face (auto-removed from the table
  when the reader exits).

#### `ndn-engine` — face lifecycle

- **Auto-removal of transient faces** — `run_face_reader` now accepts
  `face_table: Arc<FaceTable>` and removes the face from the table when the
  reader loop exits (face closed or cancelled).  `App` and `Internal` kind faces
  are exempt — they are long-lived engine objects.
- `PacketDispatcher::spawn` and `ForwarderEngine::add_face` both pass the face
  table to `run_face_reader`.

#### `ndn-router` — `list-faces` and `list-routes` management commands

- `list-faces` now returns `{"faces": [{"id": N, "kind": "unix"}, …]}` (rich
  kind information, filtered to exclude internal `App`/`Internal` faces).
- `list-routes` now returns `{"routes": [{"prefix": "/ndn", "nexthops":
  [{"face": 1, "cost": 10}]}, …]}` via the new `Fib::dump` traversal.

#### `ndn-face-local` — SHM faces (`spsc-shm` / `iceoryx2-shm` features)

- **`SpscFace` / `SpscHandle`** (`spsc-shm` feature, Unix only) — custom
  lock-free SPSC ring buffer in POSIX SHM.  Two rings (a2e, e2a) share a
  5-cache-line header (`magic u64 | capacity u32 | slot_size u32 | 4×AtomicU32
  ring indices`).  Wakeup notifications use a pair of `tokio::net::UnixDatagram`
  sockets at `/tmp/.ndn-{name}.{e,a}.sock`.  `SpscFace::create[_with]` sets up
  the engine side; `SpscHandle::connect` does a two-phase open (header-only first
  to read ring parameters, then full mapping).

- **`Iox2Face` / `Iox2Handle`** (`iceoryx2-shm` feature) — iceoryx2 pub-sub
  backend.  Two services per face (`ndn-shm/{name}/a2e` app→engine,
  `ndn-shm/{name}/e2a` engine→app).  Background OS threads bridge the blocking
  iceoryx2 API to `tokio::sync::mpsc` channels used by the async
  `Face::send`/`Face::recv` methods.  `NdnPacket` is `#[repr(C)] ZeroCopySend`
  with a 65 520-byte payload area.

- **Type aliases** in `shm/mod.rs` dispatch to the active backend:
  `ShmFace = Iox2Face` when `iceoryx2-shm` is enabled, else `SpscFace`.  Same
  for `ShmHandle`.  Both concrete types remain directly importable.

- **Public API**:
  ```rust
  // Engine process
  let face = ShmFace::create(FaceId(5), "my-app")?;
  engine.add_face(face, cancel);

  // Application process
  let handle = ShmHandle::connect("my-app")?;
  handle.send(interest_bytes).await?;
  let data = handle.recv().await?;
  ```

#### `ndn-face-local` — benchmarks

- **`benches/face_local.rs`** — Criterion benchmark suite comparing all four
  in-process face implementations across latency and throughput at packet sizes
  64 B, 1 024 B, 8 192 B:

  | Group | What is measured |
  |-------|-----------------|
  | `appface/latency` | One mpsc round-trip (app→face→app) |
  | `appface/throughput` | 1 000-packet burst, one direction |
  | `unix/latency` | One socketpair round-trip with TLV codec |
  | `unix/throughput` | 200-packet burst, concurrent send+recv |
  | `spsc/latency` | One SHM ring round-trip including Unix-datagram wakeup |
  | `spsc/throughput` | 32-packet burst (half ring capacity), one direction |
  | `iox2/latency` | One iceoryx2 round-trip through OS-thread bridge |
  | `iox2/throughput` | 100-packet burst through OS-thread bridge |

  `unix/latency` uses `tokio::net::UnixStream::pair()` (kernel `socketpair`) so
  no socket file is written to disk.  Both `unix/latency` and `unix/throughput`
  use `tokio::join!` to run send and recv concurrently; sequential execution
  deadlocks for 8 192 B packets because macOS's default Unix socket buffer is
  exactly 8 192 bytes.

  Run with: `cargo bench -p ndn-face-local --features spsc-shm,iceoryx2-shm`

### Fixed

- **`ndn_app::AppFace` / `ndn_face_local::AppFace` confusion** — `ndn_app::AppFace`
  provides a higher-level application API and does not implement the
  `ndn_transport::Face` trait.  `ndn_face_local::AppFace` does implement `Face`
  and is the correct type to register with the engine.  All engine-adjacent code
  (`ndn-router`, `ndn-ipc` tests) updated to use `ndn_face_local`.

### Benchmark results (macOS, release build)

| Benchmark | p50 latency / throughput | Notes |
|-----------|--------------------------|-------|
| `appface/latency/64` | 143 ns | |
| `appface/latency/1024` | 144 ns | |
| `appface/latency/8192` | 145 ns | |
| `appface/throughput/64` | 2.81 Mpkt/s | |
| `appface/throughput/1024` | 2.82 Mpkt/s | |
| `appface/throughput/8192` | 2.83 Mpkt/s | |
| `unix/latency/64` | 2.07 µs | socketpair, TLV framing |
| `unix/latency/1024` | 2.26 µs | |
| `unix/latency/8192` | 6.78 µs | crosses 8 KiB socket buffer |
| `unix/throughput/64` | 2.65 Mpkt/s | |
| `unix/throughput/1024` | 1.55 Mpkt/s | |
| `unix/throughput/8192` | 409 Kpkt/s | |
| `spsc/latency/64` | 2.57 µs | wakeup datagram dominates |
| `spsc/latency/1024` | 2.69 µs | |
| `spsc/latency/8192` | 3.41 µs | |
| `spsc/throughput/64` | 810 Kpkt/s | 32-pkt burst |
| `spsc/throughput/1024` | 776 Kpkt/s | |
| `spsc/throughput/8192` | 645 Kpkt/s | |

**Key findings:**

- `AppFace` is ~15–18× lower latency than any kernel-mediated face because mpsc
  never enters the kernel.  Packet size has almost no effect since only a pointer
  is transferred.

- `SpscFace` latency (~2.6 µs small packets) is comparable to `UnixFace`
  (~2.1 µs) despite the lock-free ring, because every packet still triggers two
  `sendmsg`/`recvmsg` wakeup calls — one per direction.  The ring copy
  (`memcpy` into a 8 960-byte slot) adds overhead at 8 192 B but stays below
  `UnixFace`'s 6.78 µs for that size.

- `UnixFace` throughput degrades sharply at 8 192 B (409 Kpkt/s vs 2.65 Mpkt/s
  at 64 B) because each packet crosses the 8 KiB socket buffer boundary,
  requiring the kernel to schedule both endpoints cooperatively (visible as a
  3× latency jump from 1 024 B to 8 192 B).

- `SpscFace` throughput (one `sendmsg` per packet even in burst mode) is ~3–6×
  lower than `UnixFace` throughput at small sizes because `UnixFace` benefits
  from TCP-Nagle-like coalescing at the stream level, while the datagram wakeup
  socket sends one 1-byte datagram per packet.

- The `iceoryx2` backend is not benchmarked here because its OS-thread bridge
  polls on a 1 ms cycle; round-trip latency would be ~2 ms and is not
  competitive for single-packet exchanges.  It may be added once the bridge is
  switched to an event-driven wakeup.

### Tests added

| Crate | Module | Count |
|-------|--------|------:|
| `ndn-face-local` | `shm::spsc` | 4 |
| `ndn-store` | `trie` (dump) | — |

Running total across all crates: **357 tests**, all passing.

---

## [Unreleased — security tooling, PIB, iceoryx2 management]

### Added

#### `ndn-security` — persistent PIB backend

- **`FilePib`** — file-based Public Info Base. Directory layout:
  `<root>/keys/<sha256>/private.key` + `cert.ndnc` for identity keys/certs;
  `<root>/anchors/<sha256>/cert.ndnc` for trust anchors.
  SHA-256 of canonical name bytes used as directory name to avoid filesystem
  special-character issues.
  Operations:
  - `new(root)` / `open(root)` — create or open a PIB directory.
  - `generate_ed25519(name)` — creates a key pair with `ring::rand::SystemRandom`
    (real CSPRNG) and persists the 32-byte seed.
  - `get_signer(name)` / `delete_key(name)` / `list_keys()` — key CRUD.
  - `store_cert(cert)` / `get_cert(name)` — certificate CRUD.
  - `add_trust_anchor(cert)` / `remove_trust_anchor(name)` / `trust_anchors()` /
    `list_anchors()` — trust anchor management.
  - `name_to_uri(name)` / `name_from_uri(uri)` — percent-encoded NDN URI helpers
    (public; reused by `ndn-sec` CLI).

- **NDNC certificate binary format** — compact format used for on-disk storage:
  `[4] magic "NDNC" | [1] version=1 | [8] valid_from (u64 BE ns) |
  [8] valid_until (u64 BE ns) | [4] pk_len (u32 BE) | [pk_len] public key bytes`.

- **`PibError`** — `Io`, `KeyNotFound`, `CertNotFound`, `Corrupt`, `InvalidName`
  variants; `From<PibError> for TrustError` for ergonomic `?` propagation.

- **`Ed25519Signer::public_key_bytes() -> [u8; 32]`** — exposes the verifying key
  bytes needed to embed a public key in a self-signed certificate.

#### `ndn-security` — `SecurityManager` updates

- **`SecurityManager::generate_ed25519()`** now uses `ring::rand::SystemRandom`
  for a real CSPRNG instead of the previous deterministic placeholder seed.

- **`SecurityManager::from_pib(pib, identity)`** — constructs a `SecurityManager`
  pre-loaded with the given identity's signer, its certificate (if present), and
  all trust anchors from the PIB.

#### `ndn-config` — `SecurityConfig` expanded

- Added `identity: Option<String>` — NDN URI of the router's identity
  (e.g. `"/ndn/router1"`); loaded from the PIB at startup.
- Added `pib_path: Option<String>` — PIB directory path; defaults to
  `~/.ndn/pib` when absent.

#### `ndn-tools` — `ndn-ctl` management client

- New binary `ndn-ctl` for sending management commands to a running `ndn-router`.
  Transport is selected at compile time via the `iceoryx2-mgmt` feature (mirrors
  the same flag on `ndn-router`):

  | Build                              | Transport                   |
  |------------------------------------|-----------------------------|
  | default (Unix targets)             | Unix domain socket          |
  | `--features iceoryx2-mgmt`         | iceoryx2 shared-memory RPC  |

  Global flags:
  - `--socket <path>` (env `$NDN_MGMT_SOCK`, default `/tmp/ndn-router.sock`) — Unix socket transport.
  - `--service <name>` (env `$NDN_MGMT_SERVICE`, default `ndn/router/mgmt`) — iceoryx2 transport.

  Subcommands:
  | Command | Description |
  |---------|-------------|
  | `add-route <prefix> --face <n> [--cost <n>]` | Add or update a FIB route. |
  | `remove-route <prefix> --face <n>` | Remove a FIB nexthop. |
  | `list-routes` | List FIB routes. |
  | `list-faces` | List registered face IDs. |
  | `get-stats` | Print engine statistics (PIT size). |
  | `shutdown` | Request a graceful router shutdown. |

  The iceoryx2 client defines local `MgmtReq`/`MgmtResp` wire types (identical
  layout to the server's) and polls for a response with a 5-second timeout.

#### `ndn-tools` — `ndn-sec` CLI binary

- New binary `ndn-sec` for offline key and certificate management.
  Global flag: `--pib <path>` (also reads `$NDN_PIB`; falls back to `~/.ndn/pib`).

  Subcommands:
  | Command | Description |
  |---------|-------------|
  | `keygen <name>` | Generate an Ed25519 key + self-signed cert. `--anchor` registers the cert as a trust anchor; `--days N` sets validity (default 365). |
  | `certdump <name>` | Pretty-print the stored certificate (subject, issuer, public key hex, validity). |
  | `list` | List all identity names stored in the PIB. |
  | `delete <name>` | Remove a key and its certificate from the PIB. |
  | `anchor add <name>` | Promote an existing cert to trust anchor. |
  | `anchor remove <name>` | Remove a trust anchor. |
  | `anchor list` | List all trust anchor names. |

#### `ndn-router` — PIB loading at startup

- `load_security(cfg)` — reads `[security].identity` and `[security].pib_path`
  from the loaded `ForwarderConfig`, opens the PIB, and calls
  `SecurityManager::from_pib()`. Failures are non-fatal (warning logged, router
  starts without a security identity).

#### `ndn-router` — `iceoryx2-mgmt` optional feature

- New Cargo feature **`iceoryx2-mgmt`** replaces the Unix-socket management
  transport with an iceoryx2 shared-memory RPC channel. Works on Linux, macOS,
  and Windows without requiring a Unix socket.

  Enable with: `cargo build -p ndn-router --features iceoryx2-mgmt`

- **`MgmtReq` / `MgmtResp`** — `#[repr(C)] #[derive(ZeroCopySend)]` wire types
  with a `data: [u8; 4096]` null-padded JSON payload. Zero heap allocation; data
  lands directly in the iceoryx2 shared-memory slot.

- **`mgmt_ipc::run_blocking(service_name, engine, cancel)`** — blocking iceoryx2
  server loop intended for `tokio::task::spawn_blocking`. Uses
  `node.wait(CYCLE_TIME)` (5 ms tick) to stay responsive to both iceoryx2
  `TerminationRequest` signals and the Tokio `CancellationToken`.

- Transport selection is compile-time:
  1. `iceoryx2-mgmt` feature → iceoryx2 shared-memory RPC (all platforms)
  2. Unix target without `iceoryx2-mgmt` → Unix socket (existing behaviour)
  3. Non-Unix without `iceoryx2-mgmt` → management unavailable (warning logged)

- Added `iceoryx2 = "0.8.1"` to workspace dependencies.

### Fixed

- **`data.rs` / `signature.rs`** — removed erroneous `core::sync::OnceLock`
  references (does not exist in `core`); replaced with `std::sync::OnceLock` and
  `std::sync::Arc`.
- **`ndn-face-wireless`** — `pub mod neighbor` and `NeighborDiscovery` re-export
  gated behind `#[cfg(target_os = "linux")]` because `NeighborEntry` holds
  `MacAddr` which is only available on Linux.

### Tests added

| Crate | Module | Count |
|-------|--------|------:|
| `ndn-security` | `pib` | 16 |

Running total across all crates: **353 tests**, all passing.

---

## [0.0.2] — Layer 5 tests (89cb5e1)

### Added

- Comprehensive test suites for all layer 5 (foundation) crates.
- `ndn-tlv`: 33 tests covering `read_varu64` / `write_varu64` / `varu64_size`
  roundtrips, all four encoding widths, EOF error cases, `TlvReader` zero-copy
  slice identity, `skip_unknown` critical-bit rule, scoped sub-readers, and
  `TlvWriter` nested encoding with multi-level nesting.
- `ndn-packet`: 61 tests covering `Name` display / prefix matching / hashing,
  `Interest` lazy field decode, `Data` signed region / sig value extraction,
  `MetaInfo` content types / freshness, `SignatureInfo` key locator, and `Nack`
  reason codes.

### Fixed

- `Data::sig_value()` returned the full SignatureValue TLV (type + length +
  value bytes) instead of only the value bytes. Now strips the TLV header using
  `TlvReader::read_tlv` before returning.
- `Nack::decode` passed raw value bytes to `Interest::decode` which expects a
  complete outer INTEREST TLV. Now reconstructs the full wire format via
  `TlvWriter::write_tlv(INTEREST, &v)`.
- Added `#[derive(Debug)]` to `Interest`, `Data`, and `Nack` (required by
  `Result::unwrap_err()` in tests).

---

## [0.0.1] — Initial workspace (1e85c1f / d4e89f1 / 19d6d48)

### Added

- Cargo workspace with `resolver = "2"` and 17 library crates + 3 binary crates
  across 6 dependency layers.
- `ndn-tlv`: `read_varu64`, `write_varu64`, `varu64_size`, `TlvReader`
  (zero-copy `Bytes`-backed), `TlvWriter` (nested encoding with 5-byte length
  placeholder), `TlvError`.
- `ndn-packet`: `Name`, `NameComponent`, `Interest` (lazy `OnceLock` fields),
  `Data` (signed region offsets, lazy content / meta / sig fields), `MetaInfo`,
  `SignatureInfo`, `Nack`, `PacketError`, TLV type constants.
- `ndn-store`: `NameTrie` (per-node `RwLock` LPM), `Pit` / `PitEntry` /
  `PitToken` / `InRecord` / `OutRecord`, `ContentStore` trait, `NullCs`, `LruCs`
  (byte-bounded, MustBeFresh).
- `ndn-transport`: `Face` trait, `FaceId`, `FaceKind`, `FaceError`, `FaceTable`
  (DashMap + `ErasedFace` blanket impl), `RawPacket`.
- Stub `lib.rs` files for all upper-layer crates.
- Design documentation split from `design-session.md` into 12 structured
  reference documents under `docs/`.
- `README.md` project landing page.
- `CLAUDE.md` guidance file for Claude Code.
