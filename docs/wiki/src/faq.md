# FAQ

## General

### Is ndn-rs production-ready?

ndn-rs is a research and development platform. The core forwarding pipeline, face implementations, and management protocol are all functional, and the stack is suitable for research deployments, prototyping, and embedded NDN applications. If you are considering production use, evaluate stability and feature completeness against your specific requirements -- the codebase is moving quickly and APIs may still shift.

### How does ndn-rs relate to NFD and ndn-cxx?

The mapping is straightforward once you see the two layers:

- **ndn-rs** (the library) is analogous to **ndn-cxx** (the C++ library). Both provide the core data structures, TLV codec, forwarding engine, and face abstractions that applications link against.
- **ndn-fwd** (the standalone binary) is analogous to **NFD** (the daemon). Both are thin executables that instantiate the library, open network faces, and run a forwarding loop.

Both implement the same NDN protocol (NDN Packet Format v0.3, NDNLPv2), so they interoperate on the wire.

### What's the difference between ndn-rs and ndn-fwd?

ndn-rs is the library crate -- it contains the forwarding engine, PIT, FIB, Content Store, face abstractions, strategies, and the management protocol. You can embed it directly in your application.

ndn-fwd is a standalone binary that depends on ndn-rs. It reads a configuration file, opens network faces (UDP, TCP, Ethernet, etc.), starts the management listener, and runs the forwarding pipeline. If you just want a forwarder running on a machine, ndn-fwd is what you install. If you want to build NDN into your own application, you depend on ndn-rs as a library.

### Can I use ndn-rs in my application without running ndn-fwd?

Absolutely -- this is one of the main design goals. Your application can instantiate the forwarding engine directly, create in-process `InProcFace` channels, and exchange Interests and Data without any IPC overhead. The latency for an in-process `InProcFace` round-trip is on the order of ~20 ns via `mpsc` channels, compared to ~2 us for Unix socket IPC to a separate daemon.

That said, if your application needs to talk to remote NDN nodes or other local applications, you will want either ndn-fwd running as a forwarder, or your application opening its own network faces through the library.

### Can ndn-rs interoperate with NFD?

Yes. ndn-rs uses the standard NDN TLV wire format and NDNLPv2 link protocol, so UDP, TCP, and WebSocket faces can connect to NFD nodes without any translation layer. The management protocol follows NFD's command format for compatibility, meaning tools written for NFD (like nfdc) can also manage ndn-fwd.

### How does ndn-rs handle security?

NDN's security model is baked into the data itself -- every Data packet carries a signature, and consumers validate signatures against a trust schema. ndn-rs implements the same signing and validation algorithms (ECDSA, RSA, HMAC-SHA256).

The `ndn-security` crate provides the trust schema engine and keychain, using pure-Rust cryptography crates (`ring`, `p256`).

### Does ndn-rs support no_std / embedded?

The `ndn-tlv` and `ndn-packet` crates compile with `no_std` (with `alloc`). The `ndn-embedded` crate provides a minimal forwarding engine for Cortex-M and similar targets. See the [embedded CI workflow](https://github.com/Quarmire/ndn-rs/actions) for tested targets.

## Architecture

### Why is ndn-rs a library instead of a daemon?

The analogy to draw is with ndn-cxx, not NFD. ndn-cxx is the C++ library that applications link against; NFD is one particular binary built on top of it. ndn-rs takes the same approach: the forwarding engine is a library, and ndn-fwd is one binary that uses it.

This means applications can embed the full forwarding engine directly. In-process communication through `InProcFace` channels avoids IPC serialization, and applications that need custom forwarding behavior (novel strategies, application-layer caching) can extend the engine in-process.

For users who just want a standalone forwarder, ndn-fwd provides exactly that -- a thin binary that reads a config file and runs the engine.

### Why DashMap for the PIT instead of a single Mutex?

The PIT sits on the hot path of every packet. `DashMap` provides sharded concurrent access so that multiple pipeline tasks can insert and look up PIT entries in parallel as long as they hash to different shards.

### Why does the CS store wire-format Bytes?

Storing wire-format `Bytes` means a CS hit boils down to `face.send(cached_bytes.clone())` -- one atomic reference count increment. There is no re-encoding step from a decoded `Data` struct back to TLV wire format.

### Why Arc\<Name\> everywhere?

A single Interest creates references to its name in the PIT entry, the FIB lookup, the CS lookup, and the pipeline context. `Arc<Name>` shares one heap allocation across all of them without copying the name's component bytes.

## Performance

### What throughput can ndn-rs achieve?

Run `cargo bench -p ndn-engine` for pipeline throughput numbers on your hardware. The main cost centers are TLV decode (scales with name length), CS lookup (depends on backend and hit rate), and PIT operations (O(1) via DashMap hash lookup). The pipeline is designed so that a CS hit short-circuits before most of the Interest pipeline runs, which is where the zero-copy `Bytes` storage pays off the most.

### How do I profile ndn-rs?

The library uses the `tracing` crate for structured logging with per-packet spans. Set `RUST_LOG=ndn_engine=trace` for detailed per-packet traces, or `RUST_LOG=ndn_engine=debug` for a less verbose view of forwarding decisions. For CPU profiling, `cargo flamegraph` or `perf record` on the ndn-fwd binary will show you where time is spent.

## Development

### How do I add a new face type?

See the [Implementing a Face](./guides/implementing-face.md) guide. The short version: implement the `Face` trait (`recv` and `send`), add a `FaceKind` variant, and register with the `FaceTable`.

### How do I add a custom forwarding strategy?

See the [Implementing a Strategy](./guides/implementing-strategy.md) guide. Implement the `Strategy` trait, which receives an immutable `StrategyContext` and returns a `ForwardingAction`, then register via the `StrategyTable`.

### How do I run the benchmarks?

```bash
cargo bench -p ndn-packet    # Name operations
cargo bench -p ndn-store     # Content Store (LRU, Sharded, Fjall)
cargo bench -p ndn-engine    # Full pipeline
cargo bench -p ndn-faces  # Face latency/throughput
cargo bench -p ndn-security  # Signing and validation
```

See [Benchmark Methodology](./benchmarks/methodology.md) for details.
