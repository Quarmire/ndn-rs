# ndn-rs

A [Named Data Networking (NDN)](https://named-data.net/) forwarder stack written in Rust (edition 2024).

NDN is a content-centric networking architecture where packets are named data objects rather than addressed to endpoints. Consumers express **Interests** by name; the network routes them toward producers and returns **Data** along the reverse path, with in-network caching at every hop.

This stack takes a Rust-idiomatic approach: composable async pipelines with trait-based polymorphism rather than class hierarchies. It targets both standalone forwarder deployments and embedded use within research applications — the engine is a library, not a daemon.

## Status

Early development. The workspace skeleton and core data structures compile. Active design and implementation in progress.

## Features

- **Zero-copy packet handling** — `bytes::Bytes` slicing throughout; CS hits serve data directly from receive buffers
- **Composable pipeline stages** — `PipelineStage` trait with `PacketContext` passed by value; compiler-enforced short-circuit semantics
- **Pluggable forwarding strategies** — name-trie dispatch to `Arc<dyn Strategy>`; hot-swappable at runtime
- **Pluggable content store** — `ContentStore` trait with `NullCs`, `LruCs`, `ShardedCs`, `PersistentCs` (redb/RocksDB)
- **Link-layer NDN** — `NamedEtherFace` over `AF_PACKET` with NDN Ethertype `0x8624`; no IP dependency for local wireless
- **Multi-radio / multi-channel** — `RadioTable` + `MultiRadioStrategy` + nl80211 `ChannelManager`
- **wfb-ng support** — `WfbFace` + `FacePairTable` for asymmetric broadcast links (FPV / long-range)
- **Serial and Bluetooth** — `SerialFace` (COBS framing), Bluetooth Classic (RFCOMM), BLE (L2CAP CoC)
- **In-network compute** — `ComputeFace` + `ComputeRegistry` for named function execution with CS memoization
- **NDN as IPC** — `AppFace` with in-process `mpsc` or cross-process iceoryx2; service registry; push via standing Interests
- **Type-safe security** — `SafeData` newtype enforces verified status at compile time; trust schema with named capture groups
- **Structured tracing** — `tracing` spans per packet; OTLP export for distributed traces across forwarder hops

## Workspace

```
ndn-rs/
├── crates/
│   ├── ndn-tlv          # varu64, TlvReader/Writer, COBS framing
│   ├── ndn-packet       # Name, Interest, Data, Nack — no async, embeddable
│   ├── ndn-transport    # Face trait, FaceId, FaceTable
│   ├── ndn-store        # NameTrie, Pit, ContentStore + LruCs/ShardedCs
│   ├── ndn-pipeline     # PipelineStage, PacketContext, Action
│   ├── ndn-strategy     # BestRoute, Multicast, ASF, MultiRadio strategies
│   ├── ndn-security     # Signer, Verifier, TrustSchema, Validator, SafeData
│   ├── ndn-engine       # ForwarderEngine, EngineBuilder, task topology
│   ├── ndn-app          # AppFace, express(), produce(), subscribe()
│   ├── ndn-ipc          # IpcServer/Client, ChunkedTransfer, ServiceRegistry
│   ├── ndn-face-net     # UdpFace, TcpFace, MulticastUdpFace
│   ├── ndn-face-local   # AppFace (iceoryx2 / Unix socket)
│   ├── ndn-face-serial  # SerialFace (COBS), BluetoothFace
│   ├── ndn-face-wireless # NamedEtherFace (AF_PACKET), WfbFace
│   ├── ndn-compute      # ComputeFace, ComputeRegistry
│   ├── ndn-sync         # SVS, PSync dataset synchronisation
│   └── ndn-research     # FlowObserverStage, RadioTable, nl80211
└── binaries/
    ├── ndn-router       # Standalone forwarder
    ├── ndn-tools        # ndn-peek, ndn-put, ndn-ping, ndn-ls
    └── ndn-bench        # Throughput and latency benchmarking
```

Dependency layers flow strictly downward: `ndn-tlv` and `ndn-packet` have no async dependency and can compile `no_std` for embedded sensor nodes.

## Quick Start

```bash
cargo build
cargo test
cargo run --bin ndn-router
```

## Design Documentation

| Document | Contents |
|----------|----------|
| [`docs/architecture.md`](docs/architecture.md) | Design philosophy, key decisions, crate layer graph, task topology, phased build order |
| [`docs/tlv-encoding.md`](docs/tlv-encoding.md) | varu64, TlvReader zero-copy design, OnceLock partial decode, critical-bit rule, TlvWriter, COBS |
| [`docs/packet-types.md`](docs/packet-types.md) | Name, Interest, Data signed region, PacketContext fields with rationale, AnyMap |
| [`docs/pipeline.md`](docs/pipeline.md) | PipelineStage trait, Action enum, Interest/Data stage sequences, StrategyStage integration, ForwardAfter scheduling |
| [`docs/forwarding-tables.md`](docs/forwarding-tables.md) | FIB trie LPM, PIT structure and PitToken, CS trait and all implementations |
| [`docs/faces.md`](docs/faces.md) | Face trait, task topology, FaceTable, EtherFace, MAC resolution, wfb-ng, serial, BLE |
| [`docs/strategy.md`](docs/strategy.md) | Strategy trait, StrategyContext, BestRoute, ForwardAfter probing, MeasurementsTable, MultiRadioStrategy |
| [`docs/engine.md`](docs/engine.md) | ForwarderEngine, ShutdownHandle, EngineBuilder, tracing and logging setup |
| [`docs/security.md`](docs/security.md) | Signed region, Signer/Verifier traits, trust schema pattern matching, cert cache, SafeData, KeyStore |
| [`docs/ipc.md`](docs/ipc.md) | Transport tiers, iceoryx2, chunked transfer, push notification approaches, service registry, local trust |
| [`docs/wireless.md`](docs/wireless.md) | Reverse path constraint, discovery approaches, multi-radio architecture, ChannelManager, tc eBPF, named MAC |
| [`docs/compute.md`](docs/compute.md) | Levels 1–4 in-network compute, ComputeFace, aggregation PIT |

The full design conversation that produced this architecture is preserved in [`docs/design-session.md`](docs/design-session.md).

## Architecture at a Glance

```
application
    │  Arc<DecodedPacket> (~20 ns, same process)
    ▼
AppFace ──────────────────────────────────────────────┐
                                                       │
face tasks (one per Face)                              │
    │  RawPacket { bytes, face_id, arrival_ns }        │
    ▼                                                  │
pipeline runner ──┬── per-packet task                  │
                  │   FaceCheck → TlvDecode → ...      │
                  │   ... → Strategy → Dispatch ───────┘
                  └── expiry task (PIT drain, 1 ms)

FaceTable: DashMap<FaceId, Arc<dyn Face>>
FIB:       NameTrie<Arc<FibEntry>>         (RwLock per node, concurrent LPM)
PIT:       DashMap<PitToken, PitEntry>     (no global lock on hot path)
CS:        dyn ContentStore                (NullCs / LruCs / ShardedCs / PersistentCs)
```

## Research Extensions

The `ndn-research` crate provides extension points for wireless and networking research:

- **`FlowObserverStage`** — non-blocking packet observation at pipeline entry/exit; feeds `mpsc` channel to external analysis tasks
- **`RadioTable`** — nl80211 link metrics per face (RSSI, MCS, channel utilization, retransmission rate)
- **`ChannelManager`** — reads nl80211 survey data, publishes as named NDN content, subscribes to neighbor state; handles channel switching with FIB/PIT consistency

The engine exposes `Arc` handles to all internal tables, so a research controller is just another Tokio task — no IPC boundary, microsecond observation-to-action latency.

## License

MIT OR Apache-2.0
