# Performance Tuning

This guide covers the key tuning knobs in ndn-rs and when to adjust them.

> **🎯 Tip:** The three highest-impact tuning knobs are, in order: (1) **ShardedCs** on multi-threaded runtimes (eliminates CS lock contention), (2) **pipeline channel capacity** (prevents face reader stalls), and (3) **Tokio worker threads** (scales forwarding across cores). Start with these before touching anything else.

## Pipeline Channel Capacity

The engine uses a shared `mpsc` channel to funnel packets from all face reader tasks into the pipeline runner. The channel capacity determines how many packets can be buffered before face readers block.

```rust
let config = EngineConfig {
    pipeline_channel_capacity: 4096, // default: 1024
    ..Default::default()
};
```

- **Too small:** face readers block frequently, starving throughput on high-fanout workloads.
- **Too large:** adds memory overhead and increases worst-case latency (packets sit in the queue longer during bursts).

Start with the default (1024) and increase if you observe face reader tasks spending significant time blocked on channel sends. Monitor with `tracing` spans on the inbound path.

## Content Store Sizing

The `LruCs` is sized in **bytes**, not entry count. This means the CS adapts automatically to varying Data packet sizes.

```rust
let cs = LruCs::new(256 * 1024 * 1024); // 256 MiB
```

Rules of thumb:

- **Router with diverse traffic:** 256 MiB -- 1 GiB depending on available RAM.
- **Edge device / IoT gateway:** 16 -- 64 MiB.
- **Embedded (no CS):** use a no-op CS implementation.

The CS tracks total byte usage of stored wire-format `Bytes`. When the limit is exceeded, the least-recently-used entries are evicted.

### ShardedCs for Concurrent Access

Under high concurrency (many pipeline tasks hitting the CS simultaneously), lock contention on a single `LruCs` can become a bottleneck. `ShardedCs` distributes entries across multiple independent shards:

```rust
use ndn_store::ShardedCs;

// 16 shards, 256 MiB total (16 MiB per shard).
let cs = ShardedCs::<LruCs>::new(16, 256 * 1024 * 1024);
```

Each shard is a separate `LruCs` with its own lock. Name hashing determines shard assignment. This reduces contention at the cost of slightly less optimal global LRU ordering.

Use `ShardedCs` when:
- You are running a multi-threaded Tokio runtime (`multi_thread`)
- Benchmark or profiling shows CS lock contention
- Pipeline throughput plateaus despite available CPU

For single-threaded runtimes or low-throughput scenarios, plain `LruCs` is sufficient.

> **📊 Performance:** In benchmarks, `ShardedCs` with 16 shards on an 8-core machine shows 3-5x throughput improvement over plain `LruCs` when the CS hit rate is high. The tradeoff is slightly less optimal LRU ordering (each shard maintains its own LRU list), which can marginally reduce hit rates. For most workloads, the concurrency gain far outweighs the eviction accuracy loss.

## FIB Lookup Optimization

The FIB is a name trie with `HashMap<Component, Arc<RwLock<TrieNode>>>` per level. Longest-prefix match traverses from the root to the deepest matching node.

**Shorter prefixes are faster.** A lookup for `/a/b` touches 2 trie levels; `/a/b/c/d/e/f` touches 6. If your application can use shorter prefixes without ambiguity, do so.

**Number of routes matters less than depth.** The trie fans out at each level, so 1000 routes under `/app` with 2-component names is fast. 10 routes with 10-component names is slower per lookup.

For FIB sizes above ~10,000 routes, monitor LPM latency via the benchmark suite (see [Pipeline Benchmarks](../benchmarks/pipeline-benchmarks.md)).

## PIT Expiry Interval

PIT entries are expired using a hierarchical timing wheel with O(1) insert and cancel. The expiry check interval controls how frequently the wheel is ticked:

- **Default:** entries expire based on their Interest Lifetime (typically 4 seconds).
- The timing wheel granularity is 1 ms, which is sufficient for most workloads.

If you have extremely high Interest rates (>1M/s), ensure the timing wheel's tick task is not starved by pipeline work. Dedicate a Tokio worker thread or use `spawn_blocking` for the expiry sweep if needed.

## Face Buffer Sizes

Each face uses bounded `mpsc` channels for inbound and outbound packet buffering. The buffer size affects throughput and latency:

```rust
// In your face constructor:
let (tx, rx) = mpsc::channel(256); // 256 packets
```

| Scenario | Suggested size |
|----------|---------------|
| Local face (App, SHM, Unix) | 128 -- 256 |
| Network face (UDP, TCP) | 256 -- 512 |
| High-throughput link (10G Ethernet) | 512 -- 2048 |
| Low-bandwidth link (Serial, BLE) | 16 -- 64 |

Larger buffers absorb bursts but consume more memory (each slot holds a `Bytes` handle, ~32 bytes plus the packet data).

## Tokio Runtime Configuration

ndn-rs is built on Tokio. The runtime configuration significantly impacts performance.

### Multi-threaded runtime (recommended for routers)

```rust
let rt = tokio::runtime::Builder::new_multi_thread()
    .worker_threads(4)       // match available cores
    .max_blocking_threads(2) // for CS persistence, crypto
    .enable_all()
    .build()?;
```

- **`worker_threads`**: set to the number of cores you want dedicated to forwarding. On a 4-core router, use 4. On a shared system, use fewer.
- **`max_blocking_threads`**: used by `PersistentCs` (RocksDB/redb) and signature validation. 2 is usually enough.

### Current-thread runtime (embedded / testing)

```rust
let rt = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()?;
```

Use this for embedded deployments, single-threaded benchmarks, or tests. All tasks run cooperatively on one thread -- no synchronization overhead, but no parallelism.

### Thread pinning

For maximum throughput on NUMA systems, pin Tokio workers to specific cores:

```rust
let rt = tokio::runtime::Builder::new_multi_thread()
    .worker_threads(4)
    .on_thread_start(|| {
        // Pin to core using core_affinity or similar crate.
    })
    .build()?;
```

## Benchmark Suite

ndn-rs includes a Criterion-based benchmark suite in `crates/ndn-engine/benches/pipeline.rs`. Use it to measure the impact of tuning changes:

```bash
# Run all benchmarks
cargo bench -p ndn-engine

# Run a specific benchmark group
cargo bench -p ndn-engine -- "cs/"

# Generate HTML reports (in target/criterion/)
cargo bench -p ndn-engine
open target/criterion/report/index.html
```

Key benchmarks to watch:

| Benchmark | What it measures |
|-----------|-----------------|
| `decode/interest` | TLV decode cost per Interest |
| `cs/hit`, `cs/miss` | Content Store lookup latency |
| `pit/new_entry`, `pit/aggregate` | PIT insert and aggregation |
| `fib/lpm` | FIB longest-prefix match at 10/100/1000 routes |
| `interest_pipeline/no_route` | Full Interest pipeline (decode + CS miss + PIT new) |
| `data_pipeline` | Full Data pipeline (decode + PIT match + CS insert) |

See [Pipeline Benchmarks](../benchmarks/pipeline-benchmarks.md) for detailed results and [Methodology](../benchmarks/methodology.md) for how measurements are collected.

## Quick Checklist

> **⚠️ Important:** Always profile before tuning. The most common mistake is optimizing the wrong thing. Run `cargo flamegraph` or `perf record` on a realistic workload first -- the actual bottleneck is often not where you expect. The Criterion benchmark suite measures individual components in isolation, but production bottlenecks emerge from the interaction between components under load.

1. **Profile first.** Use `cargo flamegraph` or `perf` before tuning. Bottlenecks are often not where you expect.
2. **Size the CS in bytes.** Do not count entries -- a 1 KiB Data and a 100 B Data have very different footprints.
3. **Use ShardedCs on multi-threaded runtimes.** If CS lock contention shows up in profiles, shard.
4. **Keep FIB prefixes short.** Fewer trie levels = faster LPM.
5. **Match face buffer sizes to link speed.** Over-buffering wastes memory; under-buffering wastes throughput.
6. **Benchmark after every change.** The Criterion suite catches regressions automatically.
