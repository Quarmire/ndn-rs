# Architecture

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
  ndn-routing                  Routing algorithms: StaticProtocol, DvrProtocol (DVR)
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
  ndn-discovery                Pluggable neighbour (SWIM) and service discovery

crates/faces/                  All face implementations in one consolidated crate
  ndn-faces                    Feature-gated face types:
    net                        UdpFace, TcpFace, MulticastUdpFace (default)
    websocket                  WebSocketFace (default); websocket-tls adds TLS listener
    local                      InProcFace/InProcHandle, UnixFace (default)
    spsc-shm                   ShmFace/ShmHandle zero-copy ring (Unix)
    serial                     SerialFace with COBS framing (embedded/IoT)
    l2                         NamedEtherFace (AF_PACKET/PF_NDRV/Npcap), WfbFace
    bluetooth                  BleFace GATT stub

crates/foundation/             Zero-NDN-dep building blocks — compile no_std compatible
  ndn-transport                Face trait, FaceId, FaceTable, StreamFace, TlvCodec
  ndn-store                    NameTrie, Fib, PIT, ContentStore (LruCs/ShardedCs/FjallCs)
  ndn-packet                   Name, Interest, Data, Nack — lazy decode, no_std
  ndn-tlv                      TlvReader, TlvWriter, varu64 — no_std

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
| `KeyChain` | ndn-security | Identity, signing, and trust anchors |
| `Signer` / `Verifier` | ndn-security | Cryptographic operations |
| `DiscoveryProtocol` | ndn-discovery | Neighbor/service discovery |
| `RoutingProtocol` | ndn-routing | RIB population from routing algorithms |
| `ForwarderClient` | ndn-ipc | App-to-forwarder IPC (async or blocking) |
| `ComputeHandler` | ndn-compute | Named function execution |

## Pipeline Flow

```
Interest: FaceCheck → TlvDecode → CsLookup → PitCheck → Strategy → Dispatch
Data:     FaceCheck → TlvDecode → PitMatch  → Strategy → CsInsert → Dispatch
```

`PacketContext` passes **by value** — ownership transfer makes short-circuits compiler-enforced. Each stage returns `Action`: `Continue`, `Send`, `Satisfy`, `Drop`, or `Nack`.

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
| [`docs/discovery.md`](docs/discovery.md) | SWIM protocol, service discovery |
| [`docs/protocols/routing.md`](docs/protocols/routing.md) | DVR algorithm, static routes, RIB lifecycle |
| [`docs/wireless.md`](docs/wireless.md) | Multi-radio, nl80211, wfb-ng |
| [`docs/compute.md`](docs/compute.md) | In-network compute levels |
| [`docs/spsc-shm-spec.md`](docs/spsc-shm-spec.md) | Shared memory ring buffer spec |
