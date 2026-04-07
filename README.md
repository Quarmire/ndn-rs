# ndn-rs

A [Named Data Networking (NDN)](https://named-data.net/) forwarder stack written in Rust (edition 2024). NDN routes packets by name rather than address: consumers express **Interests**; the network routes them toward producers and returns **Data** along the reverse path, caching at every hop.

ndn-rs takes a Rust-idiomatic approach — composable async pipelines with trait-based polymorphism — and targets both standalone forwarder deployments and embedded use within research applications. The engine is a library, not a daemon.

**Version:** 0.1.0-alpha · **[Releases](https://github.com/Quarmire/ndn-rs/releases)** · **[Wiki](https://quarmire.github.io/ndn-rs/wiki/)** · **[Explorer](https://quarmire.github.io/ndn-rs/explorer/)**

---

## Quick Start

```bash
# Build
cargo build --release

# Run the forwarder (default: UDP + TCP listeners on port 6363)
cargo run --release --bin ndn-router

# With a config file
cargo run --release --bin ndn-router -- -c ndn-router.toml
```

Set `RUST_LOG=info` for status output, `RUST_LOG=ndn_engine=trace` to trace individual pipeline stages.

### Management

```bash
# Add a FIB route
ndn-ctl rib register /ndn/example --face 1 --cost 10

# List faces
ndn-ctl faces list

# Content store info
ndn-ctl cs info

# Graceful shutdown
ndn-ctl status shutdown
```

`ndn-ctl` speaks the NFD management protocol (TLV over `/localhost/nfd/`), so any NFD-compatible tool works as well.

### Measure throughput

```bash
# Start a router, then:
ndn-iperf server --prefix /bench
ndn-iperf client --prefix /bench --duration 10
```

---

## Documentation

The wiki covers everything from installation to deep dives into each subsystem:

| | |
|--|--|
| **[Getting Started](https://quarmire.github.io/ndn-rs/wiki/getting-started/installation.html)** | Install, first run, config reference |
| **[Architecture](https://quarmire.github.io/ndn-rs/wiki/design/overview.html)** | Pipeline design, crate layers, key data structures |
| **[Deep Dives](https://quarmire.github.io/ndn-rs/wiki/deep-dive/pipeline-walkthrough.html)** | TLV encoding, forwarding pipeline, security, simulation, WASM |
| **[Guides](https://quarmire.github.io/ndn-rs/wiki/guides/implementing-face.html)** | Implementing a Face, Strategy, embedded targets, CLI tools |
| **[Benchmarks](https://quarmire.github.io/ndn-rs/wiki/benchmarks/pipeline-benchmarks.html)** | Pipeline stage costs, methodology, latest CI results |
| **[0.1.0-alpha release notes](https://quarmire.github.io/ndn-rs/wiki/releases/v0-1-0-alpha.html)** | What's in this release, design decisions, roadmap |

The [`ARCHITECTURE.md`](ARCHITECTURE.md) file has a crate map and dependency layer diagram for quick offline reference.

---

## Crates at a Glance

| Crate | Role |
|-------|------|
| `ndn-tlv` | Zero-copy TLV codec (`no_std`) |
| `ndn-packet` | Name, Interest, Data, Nack — lazy decode |
| `ndn-transport` | `Face` trait, `FaceId`, `FaceTable` |
| `ndn-store` | `NameTrie`, FIB, PIT, ContentStore (LRU / Sharded / Fjall) |
| `ndn-pipeline` | `PipelineStage`, `PacketContext`, `Action` |
| `ndn-strategy` | BestRoute, Multicast, composed strategies, measurements |
| `ndn-security` | Signer, Verifier, TrustSchema, Validator, PIB |
| `ndn-engine` | `ForwarderEngine`, `EngineBuilder`, task topology |
| `ndn-app` | Consumer, Producer, Subscriber, Queryable, KeyChain |
| `ndn-ipc` | RouterClient, ChunkedTransfer, ServiceRegistry |
| `ndn-config` | TOML config, NFD management protocol |
| `ndn-discovery` | SWIM neighbor discovery, epidemic gossip, SVS service discovery |
| `ndn-sync` | SVS and PSync dataset synchronisation |
| `ndn-face-net` | UDP, TCP, Multicast, WebSocket |
| `ndn-face-local` | AppFace, UnixFace, SHM (SpscFace) |
| `ndn-face-serial` | SerialFace with COBS framing |
| `ndn-face-l2` | Raw Ethernet (Linux / macOS / Windows) |
| `ndn-sim` | In-process simulation: SimFace, SimLink, topology builder |
| `ndn-wasm` | WASM simulation for the browser explorer |
| `ndn-embedded` | `no_std` forwarder for bare-metal MCUs |
| `ndn-strategy-wasm` | Hot-loadable WASM forwarding strategies |
| `ndn-compute` | In-network compute: ComputeFace, ComputeRegistry |
| `ndn-research` | FlowObserverStage, FlowTable, ChannelManager |

---

## Acknowledgments

This project builds on the [Named Data Networking](https://named-data.net/) architecture developed by the NDN research team led by Lixia Zhang at UCLA, with contributions from NIST, University of Memphis, University of Arizona, and others. The protocol specifications, packet format, and forwarding semantics are defined by the NDN team's RFCs and technical reports. This implementation aims for compatibility with [NFD](https://github.com/named-data/NFD) and [ndn-cxx](https://github.com/named-data/ndn-cxx) where applicable.

## License

MIT OR Apache-2.0
