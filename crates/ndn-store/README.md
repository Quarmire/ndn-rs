# ndn-store

Forwarding-plane data structures for the ndn-rs engine: FIB, PIT, Content Store, and strategy table. All structures support concurrent access via `DashMap` or sharding and are designed for the packet-processing hot path.

## Key Types

| Type | Role |
|------|------|
| `NameTrie<V>` | Generic name-prefix trie; foundation for FIB and strategy table |
| `Fib` / `FibEntry` / `FibNexthop` | Forwarding Information Base — longest-prefix match |
| `Pit` / `PitEntry` / `InRecord` / `OutRecord` | Pending Interest Table with per-face in/out records |
| `PitToken` | Opaque token linking Data replies back to PIT entries |
| `ContentStore` | Pluggable cache trait (stores wire-format `Bytes` for zero-copy hits) |
| `LruCs` | Single-threaded LRU content store |
| `ShardedCs<C>` | Sharded wrapper enabling concurrent access to any `ContentStore` |
| `FjallCs` | Persistent on-disk content store via `fjall` (requires feature flag) |
| `NullCs` | No-op store for testing or cache-less deployments |
| `ObservableCs` / `CsEvent` | Decorator emitting cache insert/evict events |
| `CsAdmissionPolicy` | Trait controlling which Data packets are admitted to the cache |
| `StrategyTable` | Prefix-to-strategy mapping (parallel trie alongside FIB) |

## Feature Flags

| Flag | Default | Description |
|------|---------|-------------|
| `fjall` | off | Enables `FjallCs`, a persistent LSM-tree-backed content store |

## Usage

```rust
use ndn_store::{Fib, Pit, ShardedCs, LruCs};

let fib = Fib::new();
let pit = Pit::new();
// Wrap LruCs in ShardedCs for concurrent access
let cs = ShardedCs::new(8, || LruCs::new(1024));
```

Part of the [ndn-rs](../../README.md) workspace.
