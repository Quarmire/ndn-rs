# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project does not yet follow Semantic Versioning — the codebase is in active
bootstrapping phase and all APIs should be considered unstable.

---

## [Unreleased]

### Added

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
