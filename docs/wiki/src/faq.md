# FAQ

## General

### Is ndn-rs production-ready?

ndn-rs is a research and development platform. The core forwarding pipeline, face implementations, and management protocol are functional. It is suitable for research deployments, prototyping, and embedded NDN applications. Production use should evaluate stability and feature completeness for the specific use case.

### How does ndn-rs relate to NFD?

NFD (NDN Forwarding Daemon) is the reference C++ implementation maintained by the NDN project. ndn-rs is an independent Rust implementation that follows the same NDN specifications (RFC 8569, RFC 8609) but takes different architectural approaches -- most notably being a library rather than a daemon, and using Rust's ownership model for pipeline safety.

### Can ndn-rs interoperate with NFD?

Yes. ndn-rs uses the standard NDN TLV wire format and NDNLPv2 link protocol. UDP, TCP, and WebSocket faces can connect to NFD nodes. The management protocol follows NFD's command format for compatibility.

### Does ndn-rs support no_std / embedded?

The `ndn-tlv` and `ndn-packet` crates compile with `no_std` (with `alloc`). The `ndn-embedded` crate provides a minimal forwarding engine for Cortex-M and similar targets. See the [embedded CI workflow](https://github.com/user/ndn-rs/actions) for tested targets.

## Architecture

### Why is ndn-rs a library instead of a daemon?

The library approach means the forwarding engine can be embedded directly in applications. In-process `AppFace` communication via `mpsc` channels has ~20 ns latency vs ~2 us for Unix socket IPC. For standalone use, `ndn-router` is a thin binary that instantiates the library.

### Why DashMap for the PIT instead of a single Mutex?

The PIT is on the hot path of every packet. A single `Mutex` serializes all pipeline tasks. `DashMap` provides sharded concurrent access -- multiple pipeline tasks can insert/lookup PIT entries in parallel as long as they hash to different shards.

### Why does the CS store wire-format Bytes?

A Content Store hit sends the cached Data directly to the requesting face. Storing wire-format `Bytes` means a CS hit is a `face.send(cached_bytes.clone())` -- one atomic reference count increment. No re-encoding from a decoded `Data` struct back to wire format.

### Why Arc\<Name\> everywhere?

A single Interest creates references to its name in the PIT entry, FIB lookup, CS lookup, and pipeline context. `Arc<Name>` shares one allocation across all of these without copying the name's component bytes.

## Performance

### What throughput can ndn-rs achieve?

Run `cargo bench -p ndn-engine` for pipeline throughput numbers on your hardware. Key factors: TLV decode cost scales with name length, CS lookup depends on backend and hit rate, PIT operations are O(1) via DashMap hash lookup.

### How do I profile ndn-rs?

The library uses `tracing` for structured logging. Enable `RUST_LOG=ndn_engine=trace` for per-packet traces. For CPU profiling, use `cargo flamegraph` or `perf record` on the router binary.

## Development

### How do I add a new face type?

See the [Implementing a Face](./guides/implementing-face.md) guide. Implement the `Face` trait, add a `FaceKind` variant, and register with the `FaceTable`.

### How do I add a custom forwarding strategy?

See the [Implementing a Strategy](./guides/implementing-strategy.md) guide. Implement the `Strategy` trait and register via the `StrategyTable`.

### How do I run the benchmarks?

```bash
cargo bench -p ndn-packet    # Name operations
cargo bench -p ndn-store     # Content Store (LRU, Sharded, Fjall)
cargo bench -p ndn-engine    # Full pipeline
cargo bench -p ndn-face-local  # Face latency/throughput
cargo bench -p ndn-security  # Signing and validation
```

See [Benchmark Methodology](./benchmarks/methodology.md) for details.
