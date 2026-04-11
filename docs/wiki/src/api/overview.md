# API Reference

This page enumerates all public API surfaces in ndn-rs, organized by crate. Each crate serves a distinct layer of the stack; most application developers will only need `ndn-app` and occasionally `ndn-packet`.

---

## `ndn-app` — Application API (highest-level)

The recommended entry point for application developers. Wraps the engine, IPC, and security layers behind a simple, ergonomic interface. The same API works whether you connect to an external `ndn-fwd` process or embed the engine directly in your binary (see [Building NDN Applications](../guides/building-ndn-apps.md)).

| Type / Function | Description |
|---|---|
| `Consumer::connect(socket)` | Connect to an external router via Unix socket |
| `Consumer::from_handle(handle)` | Connect via an in-process `InProcFace` handle (embedded mode) |
| `Consumer::get(name)` | Fetch content bytes by name (convenience wrapper) |
| `Consumer::fetch(name)` | Fetch the full `Data` packet |
| `Consumer::fetch_wire(wire, timeout)` | Send a hand-built Interest wire and await `Data` |
| `Consumer::fetch_verified(name, validator)` | Fetch and cryptographically verify; returns `SafeData` |
| `Producer::connect(socket, prefix)` | Register a prefix and connect to an external router |
| `Producer::from_handle(handle, prefix)` | Register a prefix against an in-process `InProcFace` handle |
| `Producer::serve(handler)` | Run the serve loop with an async `Interest → Option<Bytes>` handler |
| `Subscriber::connect(socket, prefix, config)` | Join an SVS sync group and receive a `Sample` stream |
| `Subscriber::recv()` | Await the next `Sample` from the sync group |
| `Queryable::connect(socket, prefix)` | Register a prefix for request-response handling |
| `Queryable::recv()` | Await the next `Query`; call `query.reply(wire)` to respond |
| `KeyChain` | Re-exported from `ndn-security` — see that crate for the full API |
| `NdnConnection` | Enum unifying external (`ForwarderClient`) and embedded (`InProcFace`) connections |
| `blocking::BlockingConsumer` | Synchronous wrapper — no async required |
| `blocking::BlockingProducer` | Synchronous serve loop — plain `Fn(Interest) → Option<Bytes>` |
| `ChunkedConsumer` | Reassemble multi-segment content transparently |
| `ChunkedProducer` | Segment and serve large content automatically |

> **Note:** This is the recommended entry point for application developers.

---

## `ndn-packet` — Wire Format

Encode and decode NDN packets. Zero-copy parsing built on `bytes::Bytes`; lazy field decoding via `OnceLock`.

| Type / Function | Description |
|---|---|
| `Name::parse(s)` / `Name::from_str(s)` | Parse a URI-encoded NDN name |
| `Name::append(component)` | Append a component, returning a new `Name` |
| `Name::components()` | Iterator over `NameComponent` |
| `Name::has_prefix(prefix)` | Prefix test |
| `NameComponent` | Typed variants: `GenericNameComponent`, `Segment`, `Version`, `Timestamp`, `KeywordNameComponent`, `ParametersSha256DigestComponent`, etc. |
| `Interest::decode(bytes)` | Decode an Interest packet |
| `Interest::name()` | Borrowed `Name` |
| `Interest::nonce()` | 4-byte nonce (decoded lazily) |
| `Interest::lifetime()` | `Duration` from `InterestLifetime` |
| `Interest::can_be_prefix()` | Whether CanBePrefix flag is set |
| `Interest::must_be_fresh()` | Whether MustBeFresh flag is set |
| `Data::decode(bytes)` | Decode a Data packet |
| `Data::name()` | Borrowed `Name` |
| `Data::content()` | `Option<Bytes>` content |
| `Data::implicit_digest()` | Compute or return cached SHA-256 implicit digest |
| `InterestBuilder::new(name)` | Start building an Interest |
| `InterestBuilder::lifetime(duration)` | Set `InterestLifetime` |
| `InterestBuilder::must_be_fresh(bool)` | Set MustBeFresh |
| `InterestBuilder::can_be_prefix(bool)` | Set CanBePrefix |
| `InterestBuilder::build()` | Encode to wire `Bytes` |
| `DataBuilder::new(name)` | Start building a Data packet |
| `DataBuilder::content(bytes)` | Set content |
| `DataBuilder::freshness(duration)` | Set `FreshnessPeriod` in MetaInfo |
| `DataBuilder::sign_sync(signer)` | Sign and finalize (sync fast-path, no heap allocation) |
| `DataBuilder::build_unsigned()` | Encode without a signature (testing / internal use) |
| `name!()` | Macro for compile-time name construction |
| `Nack::decode(bytes)` | Decode an NDNLPv2-framed Nack |
| `Nack::reason()` | `NackReason` enum |

---

## `ndn-engine` — Forwarder Engine

The core forwarding engine. Used directly when embedding the engine in a binary or when building custom tooling. Most application code reaches this layer only through `ndn-app`.

| Type / Function | Description |
|---|---|
| `EngineBuilder::new(config)` | Create a new builder |
| `EngineBuilder::face(face)` | Register a `Face` implementation |
| `EngineBuilder::strategy(prefix, strategy)` | Install a strategy for a name prefix |
| `EngineBuilder::validator(validator)` | Set the data-plane validator |
| `EngineBuilder::content_store(cs)` | Plug in a custom `ContentStore` backend |
| `EngineBuilder::discovery(protocol)` | Register a discovery protocol |
| `EngineBuilder::security(profile)` | Set the `SecurityProfile` |
| `EngineBuilder::build()` | Spawn Tokio tasks; returns `(ForwarderEngine, ShutdownHandle)` |
| `ForwarderEngine::fib()` | Access the `Fib` for manual route installation |
| `ForwarderEngine::shutdown()` | Gracefully stop all pipeline tasks |
| `EngineConfig` | Serde-deserializable config: `pipeline_threads`, `cs_capacity`, `pit_capacity`, `idle_face_timeout`, etc. |
| `PipelineStage` trait | Implement to insert a custom stage into the fixed pipeline |

---

## `ndn-security` — Signing and Validation

Cryptographic signing, trust-chain validation, and identity management. The `SafeData` newtype is the compiler-enforced proof that a `Data` packet has been verified. `KeyChain` is the single entry point for NDN security in both applications and the forwarder.

| Type / Function | Description |
|---|---|
| `KeyChain::ephemeral(name)` | Create an in-memory, self-signed identity (tests / short-lived producers) |
| `KeyChain::open_or_create(path, name)` | Load from a file-backed PIB, generating on first run |
| `KeyChain::from_parts(mgr, name, key_name)` | Construct from a pre-built `SecurityManager` (framework use) |
| `KeyChain::signer()` | Obtain an `Arc<dyn Signer>` for the local identity |
| `KeyChain::validator()` | Build a `Validator` pre-configured with this identity's trust anchors |
| `KeyChain::add_trust_anchor(cert)` | Add an external trust anchor certificate |
| `KeyChain::manager_arc()` | Escape hatch to the underlying `Arc<SecurityManager>` |
| `SignWith` trait | `.sign_with_sync(&signer)` — synchronous signing extension for `DataBuilder` / `InterestBuilder` |
| `Validator::new(schema)` | Create a validator from a `TrustSchema` |
| `Validator::validate(data)` | Async validate; returns `Valid(SafeData)` / `Invalid` / `Pending` |
| `Validator::validate_chain(data)` | Walk and verify the full certificate chain to a trust anchor |
| `Signer` trait | `sign(&self, region)` — async; `sign_sync` for CPU-only signers |
| `Ed25519Signer` | Ed25519 signing (default identity type) |
| `HmacSha256Signer` | Symmetric HMAC-SHA-256 (~10× faster than Ed25519) |
| `TrustSchema::new()` | Empty schema — rejects everything (explicit strict configuration) |
| `TrustSchema::hierarchical()` | Data and key must share the same first name component |
| `TrustSchema::accept_all()` | Accept any correctly-signed packet (no namespace check) |
| `SafeData` | Newtype wrapping a verified `Data` — compiler-enforced proof of validation |
| `SecurityManager::auto_init()` | First-run identity generation; driven by `auto_init = true` in TOML |
| `CertFetcher` | Async cert fetching with deduplication (concurrent requests for the same cert share one Interest) |
| `SecurityProfile` | `Default` / `AcceptSigned` / `Disabled` / `Custom` — engine auto-wires the validation stage |
| `did::name_to_did(name)` | Encode an NDN `Name` as a `did:ndn:` URI string |
| `did::did_to_name(did)` | Decode a `did:ndn:` URI back to a `Name` |
| `did::cert_to_did_document(cert)` | Convert an NDN `Certificate` to a W3C `DidDocument` |
| `did::UniversalResolver` | Multi-method DID resolver: `did:ndn`, `did:key`, `did:web` |

---

## `ndn-sync` — State Synchronization

Distributed state synchronization. Two protocols are provided: SVS (State Vector Sync) and PSync (partial sync via invertible Bloom filters).

| Type / Function | Description |
|---|---|
| `join_svs_group(engine, group_prefix, node_name)` | Start an SVS sync participant; returns `SyncHandle` |
| `join_psync_group(engine, group_prefix, node_name)` | Start a PSync participant; returns `SyncHandle` |
| `SyncHandle::publish(data)` | Publish a local update to the group |
| `SyncHandle::recv()` | Await the next `SyncUpdate` from a remote member |
| `SvsNode` | Low-level SVS node (state-vector sync) |
| `PSyncNode` | Low-level PSync node with `Ibf` (invertible Bloom filter) |

---

## `ndn-discovery` — Discovery Protocols

Pluggable link-local neighbor discovery and service discovery. Protocols run inside the engine and observe face lifecycle events and inbound packets through a narrow context interface.

| Type / Trait | Description |
|---|---|
| `DiscoveryProtocol` trait | `protocol_id`, `claimed_prefixes`, `on_face_up`, `on_face_down`, `on_inbound`, `on_tick`, `tick_interval` |
| `DiscoveryContext` trait | `add_fib_entry`, `remove_fib_entry`, `remove_fib_entries_by_owner`, `update_neighbor`, `send_on`, `neighbors`, `add_face`, `remove_face`, `now` |
| `UdpNeighborDiscovery` | SWIM-based neighbor discovery over UDP; direct and indirect probing with K-gossip piggyback |
| `EtherNeighborDiscovery` | SWIM-based neighbor discovery over raw Ethernet |
| `SvsServiceDiscovery` | SVS-backed push service record notifications |
| `CompositeDiscovery` | Multiplexes multiple protocols; verifies non-overlapping prefix claims at construction |
| `ProtocolId` | `&'static str` tag identifying a protocol; used to label and bulk-remove FIB routes |
| `NeighborUpdate` | `Upsert`, `SetState`, `Remove` variants applied to the neighbor table |
| `NeighborEntry` | A record in the neighbor table (name, face, capabilities, last-seen) |

---

## `ndn-transport` — Face Abstraction

The `Face` trait and face lifecycle types. Consumed by `ndn-engine`; implement this trait to add a new link-layer transport.

| Type / Trait | Description |
|---|---|
| `Face` trait | `async fn recv(&self) -> Result<Bytes>` and `async fn send(&self, pkt: Bytes) -> Result<()>` |
| `ErasedFace` | Object-safe erasure of `Face` for storage in `FaceTable` |
| `FaceId` | Opaque numeric face identifier |
| `FaceKind` | Enum: `Udp`, `Tcp`, `Ether`, `App`, `Shm`, `WebSocket`, `Serial`, `Internal`, etc. |
| `FaceTable` | `DashMap`-backed registry of all active faces |
| `FacePersistency` | `OnDemand` / `Persistent` / `Permanent` — NFD-compatible face lifecycle |
| `FaceScope` | `Local` / `NonLocal` — enforces `/localhost` scope boundary |

---

## `ndn-store` — Data Plane Tables

The PIT, FIB, and Content Store. The `ContentStore` trait is pluggable; the FIB and PIT are the canonical implementations used by the engine.

| Type / Trait | Description |
|---|---|
| `ContentStore` trait | `insert`, `lookup`, `evict_prefix`, `len`, `current_bytes`, `set_capacity` |
| `LruCs` | LRU eviction content store (default) |
| `ShardedCs<C>` | Shards any `ContentStore` by first name component to reduce lock contention |
| `FjallCs` | Persistent LSM-tree content store via fjall (feature: `fjall`); survives process restart |
| `ObservableCs` | Wraps any CS with atomic hit/miss/insert/eviction counters and an optional observer callback |
| `NameTrie` | Per-node `RwLock` longest-prefix-match trie; used by FIB and strategy table |
| `Pit` | Pending Interest Table; `DashMap`-backed with hierarchical timing-wheel expiry |
| `PitEntry` | A single pending Interest record (name, selector, incoming faces, expiry) |
| `Fib` | Forwarding Information Base; `NameTrie<Vec<NextHop>>` |

---

## `ndn-strategy` — Forwarding Strategy

Forwarding decision logic. Strategies receive an immutable `StrategyContext` and return a `ForwardingAction`.

| Type / Trait | Description |
|---|---|
| `Strategy` trait | `on_interest`, `on_nack`, `on_data_in` |
| `StrategyFilter` trait | Compose pre/post-processing around any strategy |
| `ContextEnricher` trait | Insert typed cross-layer data into the packet's `AnyMap` |
| `BestRouteStrategy` | Forward to the lowest-cost FIB nexthop; retry on Nack |
| `MulticastStrategy` | Forward to all FIB nexthops simultaneously |
| `ComposedStrategy` | Wraps any strategy with a `StrategyFilter` chain |
| `ForwardingAction` | `Forward(faces)`, `ForwardAfter(delay, faces)`, `Nack(reason)`, `Suppress` |
| `StrategyContext` | Immutable view: FIB lookup, measurements, face table |
| `MeasurementsTable` | `DashMap` of EWMA RTT and satisfaction rate per face/prefix |
| `WasmStrategy` | Hot-loadable WASM forwarding strategy via wasmtime; fuel-limited (feature: `wasm`) |

---

## `ndn-sim` — Simulation

Topology-based simulation for integration tests and the WASM browser sandbox. No external processes or network interfaces required.

| Type | Description |
|---|---|
| `Simulation::new()` | Create a new simulation environment |
| `Simulation::add_router(name)` | Add a router node |
| `Simulation::add_link(a, b, config)` | Connect two nodes with a `SimLink` |
| `Simulation::add_consumer(name, ...)` | Add a consumer node |
| `Simulation::add_producer(name, prefix)` | Add a producer node |
| `Simulation::run()` | Drive the simulation to completion |
| `SimLink` | A link between two nodes (bandwidth, latency, loss) |
| `LinkConfig` | Configuration for a `SimLink`: `bandwidth`, `latency`, `loss_rate` |
| `SimTracer` | Collects trace events for post-run inspection |

> **Note:** Used for integration tests and the WASM browser simulation.

---

## `ndn-ipc` — App-to-Router IPC

The low-level transport between application processes and the router. Application developers should use `ndn-app` instead.

| Type | Description |
|---|---|
| `ForwarderClient::connect(socket)` | Connect to an `ndn-fwd` Unix socket |
| `ForwarderClient::send_interest(wire)` | Send an Interest and await the response |
| `ForwarderClient::register_prefix(prefix)` | Register a name prefix for inbound Interests |
| `InProcFace` | In-process channel face (engine side of the pair) |
| `InProcHandle` | In-process channel handle (application side of the pair) |
| `SpscFace` | Zero-copy SHM ring face (engine side); 256-slot SPSC buffer |
| `SpscHandle` | Application-side handle for the SHM ring |
| `UnixFace` | Domain socket face with TLV codec framing |

---

## `ndn-embedded` — no_std Forwarder

A minimal, no_std, no_alloc forwarder for microcontrollers. Sizing is entirely compile-time via const generics.

| Type | Description |
|---|---|
| `Forwarder<N>` | Const-generic forwarder; `N` is the maximum simultaneous pending Interests |
| `Pit<N>` | no_std, no_alloc Pending Interest Table |
| `Fib<N>` | no_std, no_alloc Forwarding Information Base |

Targets: ARM Cortex-M, RISC-V, ESP32. Uses COBS framing for serial link layers.

---

## `ndn-wasm` — Browser Simulation

A wasm-bindgen wrapper exposing the forwarding engine to JavaScript for the interactive browser simulation in `ndn-explorer`.

| Type | Description |
|---|---|
| `WasmTopology` | JavaScript-accessible simulation topology |
| `WasmPipeline` | JavaScript-accessible pipeline trace runner |

---

## `ndn-config` — Configuration

Serde-deserializable configuration types. Used by `ndn-fwd` to load TOML config files.

| Type | Description |
|---|---|
| `RouterConfig` | Top-level TOML config; deserializes the full router configuration |
| `FaceConfig` | `#[serde(tag = "kind")]` enum — one variant per face type; invalid combinations rejected at parse time |
| `EngineConfig` | Pipeline threads, CS capacity, PIT capacity, idle face timeout |
| `SecurityConfig` | `auto_init`, trust anchor paths, `SecurityProfile` selection |

---

For a guided introduction to the application-level API, see [Building NDN Applications](../guides/building-ndn-apps.md). For pattern-based API selection, see [Application Patterns](./patterns.md).
