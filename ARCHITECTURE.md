# Architecture

NDN-RS models Named Data Networking as **composable async pipelines with trait-based polymorphism** — not class hierarchies. The engine is a library, not a daemon.

## Crate Map

```
Layer 0 — Binaries
  ndn-fwd             Standalone forwarder with TOML config and management socket
  ndn-tools           ndn-peek, ndn-put, ndn-ping, ndn-traffic, ndn-iperf
  ndn-bench           Throughput and latency benchmarking

Layer 1 — Engine & Application
  ndn-engine          ForwarderEngine, EngineBuilder, pipeline wiring, task topology
                      (includes ndn-pipeline: PipelineStage, PacketContext, Action)
  ndn-app             Application API: Consumer, Producer, Subscriber
  ndn-ipc             ForwarderClient, BlockingForwarderClient, chunked transfer, registry
  ndn-config          TOML config parsing, NFD management protocol
  ndn-discovery       Pluggable neighbor (SWIM) and service discovery
  ndn-routing         Pluggable routing protocols: StaticProtocol, DvrProtocol (DVR)

Layer 2 — Strategy & Security
  ndn-strategy        BestRoute, Multicast, ASF, composed strategies
  ndn-security        KeyChain, Signer/Verifier, TrustSchema, Validator, SafeData

Layer 3 — Face Implementations
  ndn-faces           All face types under feature flags:
    net               UdpFace, TcpFace, MulticastUdpFace (default)
    websocket         WebSocketFace (default); websocket-tls adds TLS server listener
    local             InProcFace/InProcHandle, UnixFace (default)
    spsc-shm          ShmFace/ShmHandle zero-copy ring (optional, Unix)
    serial            SerialFace with COBS framing (optional)
    l2                NamedEtherFace (AF_PACKET/PF_NDRV/Npcap), WfbFace
    bluetooth         BleFace GATT stub (interop with NDNts web-bluetooth-transport)

Layer 4 — Foundation
  ndn-transport       Face trait, FaceId, FaceTable, StreamFace, TlvCodec
  ndn-store           NameTrie, Fib, Pit, ContentStore (LruCs/ShardedCs/FjallCs)
  ndn-packet          Name, Interest, Data, Nack — lazy decode, no_std
  ndn-tlv             TlvReader, TlvWriter, varu64 — no_std

Simulation
  ndn-sim             SimFace, SimLink, topology builder, event tracer

Research Extensions
  ndn-research        FlowObserverStage, FlowTable, ChannelManager (nl80211)
  ndn-compute         ComputeFace, ComputeRegistry for named function execution
  ndn-sync            SVS, PSync dataset synchronisation
  ndn-strategy-wasm   Hot-loadable WASM forwarding strategies

Embedded
  ndn-embedded        Minimal no_std forwarder for bare-metal targets
```

Dependencies flow strictly downward. `ndn-tlv` and `ndn-packet` compile `no_std` for embedded.

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
