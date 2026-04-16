# High-Throughput Forwarding: Design Notes

Status: **draft** — exploring what Rust-idiomatic techniques can bring
ndn-fwd's throughput closer to NDN-DPDK's architecture without importing
its DPDK dependency or abandoning our trait-based, modular design.

## Background and attribution

NDN-DPDK (NIST, <https://github.com/usnistgov/ndn-dpdk>) is the
reference high-throughput NDN forwarder.  It achieves >100 Gbps on
commodity hardware by combining DPDK kernel-bypass I/O with an
architecture designed around **state partitioning** and **hash-based
dispatch**.

> Shi, J., Pesavento, D., & Benmohamed, L. (2021). *NDN-DPDK: NDN
> Forwarding at 100 Gbps on Commodity Hardware.* In Proc. 8th ACM
> Conference on Information-Centric Networking (ICN '21).
> <https://doi.org/10.1145/3460417.3482971>

The key insight from that work: **throughput comes from partitioning
state so every core owns its data, not from raw I/O speed alone.**
DPDK makes it faster, but the architecture is what makes it scale.

This document proposes adaptations of those ideas to ndn-rs, using Rust
ownership, lock-free data structures, and the existing trait-based
pipeline rather than copying NDN-DPDK's Go/C implementation.

---

## Completed: name-hash memoization

**Problem.** `PitMatchStage` probes up to 5 + 3*(N-1) selector
combinations per Data packet (N = name component count).  Each probe
previously called `PitToken::from_interest`, which hashed all name
components from scratch and, for CanBePrefix prefix probes, allocated a
temporary `Name` (SmallVec + Bytes ref-count bumps).

**Solution.** `NameHashes` computes cumulative prefix hashes once at
`TlvDecodeStage` and stores them in `PacketContext::name_hashes`.
Downstream stages call `PitToken::from_name_hash(prefix_hash, selector,
hint)` — a single `DefaultHasher` round over two `u64`s — instead of
re-hashing name components.

Cost model (5-component name, default selector probes):
| | Before | After |
|---|--------|-------|
| Name hashes computed | 5 + 3×4 = 17 | 1 (at decode) |
| Temporary `Name` allocations | 4 | 0 |
| `DefaultHasher` rounds per probe | ~5 component hashes | 1 (two u64s) |

Inspired by NDN-DPDK's memoized name hashing at the RX layer (§3.1 of
the ICN 2020 paper).

Files changed:
- `ndn-store/pit.rs` — `NameHashes`, `PitToken::from_name_hash`
- `ndn-engine/pipeline/context.rs` — `PacketContext::name_hashes`
- `ndn-engine/stages/decode.rs` — compute at decode
- `ndn-engine/stages/pit.rs` — use in PitCheck/PitMatch

---

## Proposed: 2-stage LPM for FIB

**Problem.** The current `NameTrie` FIB walks component-by-component,
acquiring a per-node `RwLock` read-lock at each level.  For an
N-component name this is N lock acquisitions.

**NDN-DPDK approach.** Instead of walking a trie, hash the first *M*
components (`startDepth`, tuned to the p90 of name lengths in the
deployment) and probe a flat hash table.  On hit, walk longer prefixes
via hash probes.  On miss, walk shorter.  "Virtual entries" (synthesized
on insert for intermediate prefixes) ensure every "anything longer?"
question is a single hash probe.  Result: ~2 hash lookups amortized
instead of O(N) trie nodes.

> Ref: NDN-DPDK `container/fib` package — startDepth tuning, virtual
> entries, 2-stage lookup.
> <https://pkg.go.dev/github.com/usnistgov/ndn-dpdk/container/fib>

**Rust design.**

```
pub struct HashFib {
    /// Primary table: keyed by hash of first `start_depth` components.
    primary: HashMap<u64, HashFibEntry>,
    /// start_depth: tuned to p90 of prefix lengths.
    start_depth: usize,
}

struct HashFibEntry {
    /// Actual FIB entry (nexthops) if this depth is a registered prefix.
    entry: Option<Arc<FibEntry>>,
    /// Longer prefixes reachable from here (hash → entry).
    extensions: HashMap<u64, Arc<FibEntry>>,
    /// Height > 0 means this is a virtual entry (no nexthops of its own).
    height: u32,
}
```

Wrap in `ArcSwap<HashFib>` for lock-free reads + copy-on-write rebuilds
on routing updates.  Expose behind the existing `Fib` trait so the
engine doesn't need to change.

Keep `NameTrie` for:
- RIB (needs iteration, descendants)
- CS prefix index (needs `first_descendant`)
- Strategy table (low traffic, trie walk is fine)

**Dependencies:** `NameHashes` (completed) provides the prefix hashes
needed for 2-stage lookup keys.

**Risk:** startDepth tuning requires deployment-specific prefix-length
histograms.  A bad startDepth degrades to 3+ hash probes instead of 2.
Mitigation: auto-tune from FIB contents at startup; expose as config
knob.

---

## Proposed: NDT + partitioned PIT

**Problem.** The PIT is currently a `DashMap<PitToken, PitEntry>` with
16 internal shards.  While this avoids a global lock, each shard still
uses atomic operations on every insert/remove.  Under high throughput
with many cores, shard contention becomes measurable.

**NDN-DPDK approach.** The **Name Dispatch Table (NDT)** is a flat
power-of-2 lookup table (e.g. 64K entries) indexed by
`SipHash(name[..M]) % table_size`.  Each slot holds a FWD (forwarding
thread) index.  Each FWD owns a **private** PIT partition — no
synchronization needed because only one thread ever touches it.
Returning Data/Nack packets skip the NDT and use an 8-bit owner tag
embedded in the PIT token to route back to the correct partition.

> Ref: NDN-DPDK `app/fwdp` package — NDT dispatch, PIT token owner tag,
> per-FWD PCCT.
> <https://pkg.go.dev/github.com/usnistgov/ndn-dpdk/app/fwdp>

**Rust design.**

```
/// Name Dispatch Table: maps name-hash → partition index.
struct Ndt {
    table: ArcSwap<Box<[u8]>>,  // power-of-2 length
    mask: usize,                 // table.len() - 1
}

impl Ndt {
    fn lookup(&self, name_hash: u64) -> u8 {
        let guard = self.table.load();
        guard[(name_hash as usize) & self.mask]
    }
}

/// Each partition owns its own PIT (HashMap, not DashMap).
struct PitPartition {
    entries: HashMap<PitToken, PitEntry>,
    inbox: crossbeam::channel::Receiver<PartitionMsg>,
}
```

The lower 8 bits of `PitToken` encode the owning partition.  Data/Nack
packets read this tag and send directly to the partition's inbox without
NDT lookup.

**Threading model.**  Gate behind `cfg(feature = "partitioned-fwd")`:
- N core-pinned `std::thread` workers (one per partition), each owning
  a private PIT + CS partition.
- Workers communicate via `crossbeam::channel` bounded MPSC rings.
- Control plane (mgmt, routing, discovery) stays on tokio.
- Face reader tasks dispatch Interests via NDT; Data/Nack via PIT token
  owner tag.

The current `DashMap` + tokio model remains the default for single-core,
WASM, and embedded builds.

**Risks:**
- NDT partition changes mid-flight break PIT aggregation.  Need an
  "NDT epoch" in the PIT token or a quiescence protocol.
- 8-bit owner tag limits to 256 partitions (sufficient for any
  foreseeable deployment).
- This is a second data-plane runtime, not a drop-in replacement.
  Separate benchmark suite needed.

---

## Proposed: `ArcSwap` for read-mostly FIB

**Problem.** `NameTrie` uses per-node `RwLock` for concurrent access.
The FIB is written rarely (routing updates, seconds apart) but read on
every packet.  Per-node lock acquisition adds ~15-20 ns × N components
of overhead on the read path.

**Solution.** Replace the FIB's internal `NameTrie` with an
`ArcSwap<FibSnapshot>` where `FibSnapshot` is a frozen, read-only
structure (either a `HashFib` from the 2-stage proposal or a frozen
trie).  Readers load the `Arc` (one atomic load, ~1 ns) and traverse
without any locks.  Writers build a new snapshot and swap it in.

```
use arc_swap::ArcSwap;

pub struct SwappableFib {
    current: ArcSwap<FibSnapshot>,
}

impl SwappableFib {
    pub fn lpm(&self, name: &Name, hashes: &NameHashes) -> Option<Arc<FibEntry>> {
        let snap = self.current.load();
        snap.lpm(name, hashes)
    }

    pub fn update(&self, f: impl FnOnce(&mut FibSnapshot)) {
        let mut new = (**self.current.load()).clone();
        f(&mut new);
        self.current.store(Arc::new(new));
    }
}
```

This is analogous to NDN-DPDK's liburcu-based lock-free FIB reads with
NUMA-local replicas, adapted to Rust's `arc-swap` ecosystem.

**Dependency:** new crate dep `arc-swap` (zero-unsafe, widely used).

**Can land independently** of 2-stage LPM — even a frozen `NameTrie`
snapshot eliminates per-node locks on the read path.

---

## Proposed: software prefetch in batch loop

**Problem.** The pipeline batch loop (`dispatcher/pipeline.rs:31-50`)
drains up to 64 packets, then processes them sequentially.  Each
packet's first PIT/FIB access is a cache miss (~50-100 ns L3 latency)
because the name bytes haven't been touched yet.

**NDN-DPDK approach.** Issue a software prefetch on packet N+1's name
bytes before entering the hot path for packet N.  This overlaps the
cache-line fetch with useful work and is cited as a measurable win in
the ICN 2020 paper.

**Rust implementation.**

```rust
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::{_MM_HINT_T0, _mm_prefetch};

for i in 0..batch.len() {
    // Prefetch next packet's raw bytes into L1 cache.
    if i + 1 < batch.len() {
        let next = &batch[i + 1].raw;
        #[cfg(target_arch = "x86_64")]
        unsafe {
            _mm_prefetch(next.as_ptr() as *const i8, _MM_HINT_T0);
        }
    }
    // Process current packet.
    self.process_packet(batch[i]).await;
}
```

For aarch64, use `core::arch::aarch64::_prefetch` with equivalent
semantics.

**Risk:** Minimal.  Prefetch is a hint; wrong predictions are harmless.
The `unsafe` block is a single intrinsic with no memory-safety
implications.  Should be benchmarked to confirm the win on the actual
pipeline (async task boundaries may absorb the latency).

---

## Proposed: batched face egress

**Problem.** The current outbound path enqueues one packet per
`try_send()` call to each face's `mpsc` channel.  For UDP faces, the
kernel `sendto()` syscall is also per-packet.

**Solution.**

1. Add `send_batch(&self, pkts: &[Bytes])` to the `Face` trait with a
   default impl that loops over `send`.  UDP faces override with
   `sendmmsg` (Linux) / `sendmsg_x` (macOS) for a single syscall per
   burst.

2. In `run_face_sender`, drain the `mpsc` receiver in bursts (like the
   inbound batch loop) and call `send_batch`.

3. In strategy dispatch, group `ForwardingAction::Forward(faces)` by
   face before enqueueing to reduce per-face queue contention.

**Expected gain:** 2-5× reduction in syscall overhead for UDP multicast
and best-route-with-probes scenarios.

---

## Proposed: `io_uring` / AF_XDP face transports

For deployments targeting >10 Gbps per socket face, standard
`tokio::net::UdpSocket` with `recvfrom`/`sendto` becomes the
bottleneck.  Two escalation paths:

1. **`tokio-uring` or `glommio`** — io_uring-backed async I/O.
   `glommio`'s thread-per-core model maps naturally to the partitioned
   PIT design.  Provides 10-40 Gbps on UDP without kernel bypass.

2. **AF_XDP via `xsk-rs`** — XDP socket for near-kernel-bypass
   performance without full DPDK.  Requires `CAP_NET_RAW` and XDP
   program loading.

3. **Full DPDK via `capsule`** — last resort for 100 Gbps line rate.
   Large dependency; only justified by benchmarks.

These are implemented as new `Face` trait implementations in `ndn-face-*`
crates — **zero pipeline changes** required.

---

## Sequencing

| Phase | Change | Risk | Depends on |
|-------|--------|------|------------|
| ✅ Done | Name-hash memoization | Low | — |
| Next | `ArcSwap` FIB | Low | `arc-swap` dep |
| Next | 2-stage LPM `HashFib` | Medium | NameHashes, benchmarks |
| Next | Batched face egress | Low | — |
| Later | Software prefetch | Low | Benchmarks |
| Later | NDT + partitioned PIT | High | Design review, feature flag |
| Later | io_uring / AF_XDP faces | Medium | Deployment needs |

---

## What we intentionally do NOT do

- **Don't replace `bytes::Bytes`** with custom arenas.  Arc refcount
  cost is negligible; ecosystem compatibility is valuable.
- **Don't SIMD-vectorize FIB/PIT lookup.**  NDN-DPDK doesn't either.
  SIMD helps at TLV parse and hash, which ring/ahash already exploit.
- **Don't break `PipelineStage` or `PacketContext`-by-value.**  These
  are the clearest design win; ownership-enforced short-circuits are
  better than NDN-DPDK's convention-based flags.
- **Don't port DPDK bindings without benchmarks** proving socket I/O
  is the bottleneck.
