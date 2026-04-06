# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
cargo build                    # build
cargo test                     # run all tests
cargo test <test_name>         # run a single test
cargo clippy -- -D warnings    # lint
cargo fmt                      # format
```

## Testing policy

**Do not run `cargo test` automatically** after making changes. The workspace is large (~50K lines) and a full test run takes 2–3 minutes. Instead:

- Use `cargo build` or `cargo clippy` to verify changes compile and are lint-clean.
- Only run tests when explicitly asked, or when fixing a bug where a specific test is needed to confirm the fix.
- When tests are needed, run them scoped to the affected crate: `cargo test -p <crate-name>` rather than `cargo test --workspace`.

## Project Overview

**ndn-rs** is a Named Data Networking (NDN) forwarder stack written in Rust (edition 2024). NDN is a content-centric networking architecture where packets are named data objects rather than addressed to endpoints.

The architecture is documented in `ARCHITECTURE.md` (root) and detailed design docs live in `docs/`.

## Architecture

The key insight driving this design: Rust's ownership model and trait system model NDN as **composable data pipelines with trait-based polymorphism**, not class hierarchies (unlike ndn-cxx/NFD in C++ or ndnd in Go).

### Core Data Structures

- **FIB** (Forwarding Information Base): Name trie with `HashMap<Component, Arc<RwLock<TrieNode>>>` per level — concurrent longest-prefix match without holding parent locks.
- **PIT** (Pending Interest Table): `DashMap<(Name, Option<Selector>), PitEntry>` — concurrent hash access, expiry via hierarchical timing wheel (O(1)).
- **Content Store**: Trait-based (`ContentStore`) with pluggable backends — `LruCs`, `ShardedCs<C>`, `PersistentCs` (RocksDB/redb). Stores wire-format `Bytes` for zero-copy cache hits.

### Pipeline Architecture

`PacketContext` is passed **by value** through a fixed sequence of `PipelineStage` trait objects (fixed at build time for compiler optimization).

**Interest pipeline:** FaceCheck → TlvDecode → CsLookup (short-circuit on hit) → PitCheck → Strategy (FIB lookup + forwarding decision) → Dispatch

**Data pipeline:** FaceCheck → TlvDecode → PitMatch → Strategy → MeasurementsUpdate → CsInsert → Dispatch

Each stage returns an `Action` enum (`Continue`, `Send`, `Satisfy`, `Drop`, `Nack`) to drive dispatch.

### Face Abstraction

```rust
trait Face: Send + Sync {
    async fn recv(&self) -> Result<Bytes>;
    async fn send(&self, pkt: Bytes) -> Result<()>;
}
```

Each face runs its own Tokio task pushing to a shared `mpsc` channel. One pipeline runner drains the channel and spawns per-packet tasks. Face types include: `UdpFace`, `TcpFace`, `NamedEtherFace` (raw Ethernet via `AF_PACKET`), `AppFace` (in-process channel pair), `MulticastUdpFace`, `SerialFace`, `BluetoothFace`, `WfbFace` (Wifibroadcast NG), `ComputeFace`.

### Key Design Decisions

- **`Arc<Name>`** — names are shared across PIT/FIB/pipeline without copying
- **`bytes::Bytes`** — zero-copy slicing for TLV parsing and CS storage
- **Partial decode via `OnceLock<T>`** — fields decoded lazily (CS hit may short-circuit before nonce/lifetime are accessed)
- **`SmallVec<[NameComponent; 8]>`** for names — stack allocation for typical 4–8 component names
- **`DashMap`** for PIT — no global lock on the hot path
- **`SafeData` vs `Data` types** — compiler enforces that only verified data is forwarded
- **No daemon/client split** — engine is a library; can run embedded or as standalone forwarder
- **Engine owns global FIB, PIT, CS and all external faces** — Interest aggregation requires a single PIT; applications get a thin `AppFace` (shared memory ring buffer + Unix socket control channel)

### Strategy System

A second name trie (parallel to FIB) maps prefixes to `Arc<dyn Strategy>`. Strategies receive an immutable `StrategyContext` (cannot mutate global state) and return `ForwardingAction`: `Forward`, `ForwardAfter` (enables probe-and-fallback), `Nack`, `Suppress`. `MeasurementsTable` (DashMap) tracks EWMA RTT and satisfaction rate per face/prefix.

### Async Runtime

Built on Tokio throughout. Tracing (`tracing` crate, not `log`) with structured spans per packet. The library never initializes a tracing subscriber — that's the binary's responsibility.
