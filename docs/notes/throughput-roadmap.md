# Throughput Roadmap — Where the next 2× comes from

**Status:** Design notes and measurements from the April 2026 matrix
run. Not a promise of future work — this is a map of the shortest
paths from the current honest ceiling to the next one, written so a
future contributor (or a future me) can pick any of them up without
re-measuring.

## The honest ceiling today

`testbed/tests/chunked/matrix.sh` (run with release binaries,
SHM → SHM faces, on an Apple Silicon host) measures the complete
`ndn-put` → `ndn-fwd` → `ndn-peek` pipeline across 43 cells covering
signature modes, segment sizes, pipeline depths, CC algorithms, and
transport combinations. The top three throughput cells are all
Merkle-verified segmented fetches of a 64 MiB file:

| cell | segment | crypto | throughput |
|---|---:|---|---:|
| `rayon-1024k-merkle-sha` | 1 MiB | SHA-256 Merkle | **6413 Mbps** |
| `rayon-1024k-merkle-blake` | 1 MiB | BLAKE3 Merkle | 6139 Mbps |
| `rayon-256k-merkle-blake` | 256 KiB | BLAKE3 Merkle | 6133 Mbps |

The rest of the matrix clusters in two regimes depending on segment
size: a ~3 Gbps regime at 4 KiB segments (small-segment bottleneck —
send-bound) and a ~4.5–6.5 Gbps regime at 64 KiB + (large-segment
bottleneck — verify-bound).

The crypto ceiling observed here is ~7 Gbps (an extrapolation of the
1 MiB row if verify were free); the send-bound ceiling at 4 KiB is
~3.8 Gbps. These two ceilings are independent and need independent
optimisations to break through.

## The stage breakdown that told us where the time goes

Consumer-side `ndn-peek --metrics` splits `fetch_wall_us` into four
accumulators covering the inner pipeline loop: `recv_wall_us`,
`decode_wall_us`, `verify_wall_us`, `store_wall_us`. The four stages
cover ~95% of the fetch wall for large-segment Merkle cells and
~55% for 4 KiB cells; the unaccounted share is Interest send,
per-call tokio overhead, and CC / in-flight bookkeeping — the
things a future optimisation pass needs to eliminate.

Representative breakdowns from the April 2026 run:

| cell | fetch wall | verify % | recv % | other % |
|---|---:|---:|---:|---:|
| `rayon-1024k-merkle-sha` | 83.7 ms | **76%** | 20% | 4% |
| `rayon-1024k-merkle-blake` | 87.5 ms | **83%** | 12% | 5% |
| `seg-256k-merkle-sha` | 28.9 ms | **71%** | 22% | 7% |
| `size-64mb-digest` (4 KiB × 16 384) | 152.5 ms | 14% | 48% | **38%** |
| `base-digest` (4 KiB × 4 096) | 37.8 ms | 19% | 35% | **46%** |

For large segments, verify *is* the wall. For small segments, the
"other" category — Interest send + tokio yield-points + HashMap
bookkeeping — is the wall.

## Lever 1 — SIMD / rayon parallel verify for Merkle segments

**Target:** collapse the 64–73 ms verify wall of the 1 MiB rayon
cells by running leaf verifies across idle cores.

**What we measured.** At 1 MiB / 64 MiB SHA-256 Merkle, verify is
76% of the fetch wall and runs strictly sequentially, one leaf at a
time, on whichever tokio worker happens to wake up first. On a
10-core Apple Silicon host that's at least 8 cores idle while the
consumer is crypto-bound.

**Why it's the next win.** The Merkle verify for a segment is:

1. Recompute the leaf hash over the segment content bytes (~1 ms
   per leaf at 1 MiB on this host for SHA-256, faster for smaller
   leaves).
2. Walk the proof path: `log₂(N)` parent-hash recomputations, each
   a ~200 ns node hash.
3. Compare the computed root against the cached manifest root.

Step 1 is 99% of the per-leaf work and is embarrassingly parallel
across leaves. The cached manifest is already immutable. The
consumer already receives segment responses out of order. Spawning
a blocking-pool task per segment (or batching M segments at a time
through `rayon::iter::par_iter`) moves verify off the tokio worker
thread and lets N leaves verify concurrently.

**Expected impact.** At 10 cores and a 64-ms verify wall, the
theoretical floor is 64 / 10 = 6.4 ms. Real-world (cache pressure,
stolen time, syscall overhead in `par_iter`) probably lands at
10–15 ms. That moves `rayon-1024k-merkle-sha` from:

- fetch wall 83.7 ms → ~30 ms
- throughput 6.4 Gbps → **~17–18 Gbps**

This would be the first cell in the matrix to beat the SHM/SHM
iperf number of ~30 Gbps by a factor less than 2 — i.e. it makes
our pipeline cost a recognisable fraction of raw SHM bandwidth.

**Why BLAKE3 still doesn't pull ahead in this regime.** Its
advantage is per-primitive parallelism (`Hasher::update_rayon`
inside a *single* hash call), not across independent calls. The
`publish_segmented_merkle` path uses `blake3::keyed_hash` — a
one-shot API — which never engages the streaming / rayon path. See
[why-blake3.md](./why-blake3.md) for the full argument. A parallel
leaf-verify pass helps SHA-256 and BLAKE3 equally, so the
proportional gap persists.

**Complications.**

- Short-circuit on first failure. Sequential verify gives up
  instantly when a leaf fails; a parallel pass has to cancel
  outstanding work. `rayon::iter::par_iter_mut().find_map_any`
  handles this.
- Out-of-order delivery. `drive_pipeline` already feeds segments to
  the verify stage as they arrive; moving to a batch-at-a-time
  model (verify a batch of N once N have arrived) slightly delays
  fail-fast detection. Acceptable trade.
- `CachedManifest` needs to be `Arc<_>` / `Send + Sync` so worker
  threads can borrow it. It already is.

## Lever 2 — Reducing per-Interest tokio surface

**Target:** collapse the 46% "other" share on `base-digest` (and
similar small-segment cells) to single digits.

**What the 46% actually is.** Looking at `drive_pipeline`'s inner
window-fill loop:

```rust
while in_flight.len() < window && next_seg < end {
    client.send(make_interest(next_seg)).await?;
    in_flight.insert(seq, (next_seg, Instant::now()));
    seq += 1;
    next_seg += 1;
}
```

Per Interest, the per-cost components are approximately:

| step | cost | notes |
|---|---:|---|
| `make_interest(seg)` allocates a fresh `Bytes` | ~200 ns | `InterestBuilder::new(name).lifetime(l).build()` — name clone + vec alloc + serialize |
| `ForwarderClient::send` method dispatch | ~20 ns | method dispatch + enum match |
| `SpscHandle::send` cancel / size / atomic loads | ~50 ns | three atomic ops, one `Instant::now()` |
| `try_push_a2e` | ~80 ns | tail load, head load, 60-byte memcpy into ring, tail release store |
| parked-flag load + (usually no) pipe write | ~10 ns | `SeqCst` load, branch-not-taken |
| tokio `.await` point (Ready future) | ~100–300 ns | poll, return Ready, don't actually yield |
| `in_flight.insert(seq, …)` | ~80 ns | HashMap insert w/ re-hash |
| loop back-edge bookkeeping | ~20 ns | branch, counter bumps |

Call it ~600–800 ns per Interest on the fast path. For a 4 KiB /
16 MiB cell with 4096 Interests, that's 2.5–3.3 ms of pure send
overhead. But we see ~17 ms unaccounted, so either my per-cost
estimate is low by 5× or there's a second-order effect I'm missing.

**The missing cost is almost certainly yield-driven rescheduling
when `try_push_a2e` returns false.** With a 32-slot ring and a
64-Interest window, the consumer tries to push 32 Interests into a
ring the engine hasn't drained yet; the ring fills; `try_push_a2e`
returns false; we `tokio::task::yield_now().await`; scheduler
round trip ~5–20 µs; the engine picks the ring up; we retry.
Steady state with window=64 and capacity=32 pushes the consumer
into the yield loop on every other Interest. At ~20 µs per yield
and ~2 000 yields per 4 KiB cell, that's the missing 40 ms of
scheduler time — which means the 17 ms figure in the measurements
is actually a lower bound because the scheduler runs the consumer
across multiple cores and some of its time is spent waiting for
wake-ups rather than blocked on a semaphore.

**Lever 2a — batch the SHM send path.** Add
`SpscHandle::send_batch(pkts: &[Bytes])` that acquires the tail
once, writes N slots, publishes once. Collapses N × (atomic load,
slot memcpy, atomic release store) to 1 × (atomic load,
N × memcpy, atomic release store). Saves ~70% of the per-Interest
cost when the window is wider than the batch size. More
importantly, it eliminates the scheduler round trip between
consecutive pushes — when the ring has space for N, all N go in
one call.

Expected impact on `base-digest` alone: fetch wall from 37.8 ms →
~25 ms, throughput from 3.55 Gbps → ~5.4 Gbps. Compounds with
lever 2b.

**Lever 2b — ring capacity bump for bursty small-Interest
workloads.** Our `DEFAULT_CAPACITY = 32` was chosen to keep default
ring memory reasonable at the new (266 KiB) slot size. For small
Interests (<1 KiB), the capacity ceiling bites long before the
memory ceiling does. A `capacity = 256` variant for Interest-heavy
workloads (~80 KiB of extra ring memory at default slot size) would
let a 64-Interest window fit entirely in the ring without yield
loops.

This is one line of API plumbing (`ConnectConfig::ring_capacity:
Option<u32>` → `faces/create.capacity` — same pattern as `mtu`) and
zero algorithmic change. It's strictly a better default for
Interest-heavy workloads and at most a wash for Data-heavy ones.

**Lever 2c — pre-built Interest wire templates.** Segmented fetch
builds every Interest from the same versioned prefix with only the
trailing segment number differing. A template with a fixed offset
for the segment-component bytes would cut `make_interest` from
~200 ns to ~30 ns. Smaller win than 2a but independent of it.

## Lever 3 — Interest Bundling (BLEnD-style)

**Context.** BLEnD (Akinwumi et al., *Improving NDN Performance Over
Wireless Links Using Interest Bundling*) shows that batching
multiple Interests into one wire frame can recover ≥2× throughput
over 802.11 by amortising wake-ups, MAC framing, and ACK overhead
across many Interests. The wire-level optimisation they describe is
a clean fit for the wireless links layer, but the *principle*
("when per-packet fixed cost ≫ per-packet payload work, batch")
applies to any face where there is a measurable per-packet
overhead — including our local SHM and Unix faces.

For local faces our per-Interest fixed cost is scheduler
round-trips, atomic operations, and allocation, not MAC framing;
the win shape is the same but the numbers are smaller.

This lever overlaps with lever 2a above — the two are not
alternatives but different framings of the same optimisation:

- **Lever 2a** keeps the wire format identical. Each Interest is
  still a separate NDN Interest TLV. The batching happens inside
  `SpscHandle::send_batch` and is invisible to the forwarder. No
  protocol change, trivially interoperable with any NDN-cxx or
  NDNts consumer that doesn't speak the batch API.

- **Lever 3 proper (BLEnD-style)** introduces a new "Interest
  Bundle" wire TLV that contains N inner Interests. The ingress
  forwarder decodes it once, dispatches N PIT / FIB lookups, and
  may reply with a matching "Data Bundle" in the reverse direction.

Lever 3 proper is the right choice for cross-forwarder wireless
links where MAC framing cost is hundreds of microseconds per frame.
Lever 2a is the right choice for local SHM where the savings are
within a single process pair and we don't need to touch the wire
format.

**On the question "what are the major downsides of Interest
Bundling?" — the honest list:**

1. **Latency coupling on the first Interest in a batch.** If the
   consumer waits for the batch to fill before sending, the first
   Interest's round-trip time is delayed by the fill time. The
   right mitigation is an adaptive batch-fill timeout (send after
   min(N, elapsed > T)), but picking T is a flow-control problem
   that every batching system has to re-solve from scratch. BLEnD
   handles this with a "max batch delay" parameter — they picked
   it empirically for 802.11. Local SHM has no serious latency
   concern at window ≥ 16 because the window is almost always full
   of outstanding segments and batches fill instantly.

2. **Loss of independent expiry.** Each Interest has its own
   `InterestLifetime`. A bundle can contain Interests with
   different lifetimes, and the forwarder's PIT must still expire
   each entry on its own timer. Bundling is a framing optimisation
   only; it does not change PIT semantics. The cost is a bit of
   bookkeeping complexity in the bundle decoder — it needs to
   thread each inner Interest's lifetime through to PIT insertion
   as a distinct entry. Conceptually fine, in practice a source of
   off-by-one-second bugs if the implementation ever tries to
   aggregate expiry.

3. **Independent NACK semantics.** NDN Nack is per-Interest. A
   Nack for "the third Interest in a bundle" requires either (a)
   sending back an un-bundled Nack with the single matching
   Interest's nonce, which is cheap, or (b) a new "Nack Bundle"
   TLV, which is more wire-format surface but matches the
   upstream pattern. Both work; option (a) is simpler and is what
   BLEnD does.

4. **Strategy granularity.** Forwarding strategies run per-name.
   A bundle containing Interests for 16 different prefixes hits
   16 different FIB entries and potentially 16 different
   strategies. The bundle has to be decoded-and-unbundled at
   strategy-dispatch time; the CPU win is in the pre-strategy
   stages (ingress decode, PIT insert, FIB lookup can be batched
   with a multi-key radix walk). Downside: any optimisation that
   assumed "a batch of 16 Interests all take the same strategy
   path" is an over-reach and will break with realistic workloads
   that mix prefixes.

5. **Congestion control signal coupling.** Current CC algorithms
   (AIMD, CUBIC) react per-ack. If 16 Interests' worth of Data
   arrive as one Data Bundle, the CC sees 1 ack instead of 16.
   The straightforward fix is to multiply the ack signal by the
   batch size (i.e. `cc.on_data_n(16)`); we already have that
   signal pathway implicitly in how `drive_pipeline` calls
   `cc.on_data()`. More subtly, loss becomes coarser too — a
   dropped bundle is a loss of N, which overreacts AIMD's
   multiplicative decrease. Mitigation: treat a bundle-loss as
   one loss event regardless of size, same as a TCP segment loss
   in a jumbo frame. This is a small but real change to every CC
   implementation.

6. **Wire format negotiation.** A forwarder that doesn't speak
   "Interest Bundle" will reject the frame. Bundling is
   therefore a *face-level opt-in feature* that must be
   negotiated at face creation (or advertised in a HELLO / face
   capability exchange). Our `faces/create` control parameters
   already have a `Features` field in spirit; adding
   `Features.BundleInterest = true` is the natural fit. This is
   not a small change — it's the reason BLEnD is a *protocol
   extension* and not a drop-in replacement.

7. **Security surface.** Signed Interests inside a bundle still
   sign individually; the bundle itself has no signature. The
   only new thing is that a forwarder that decodes a bundle
   needs to enforce a per-inner-Interest size cap to prevent an
   amplification-style attack ("bundle with 10 000 tiny
   Interests that all hit the PIT max"). Bounded by a simple
   per-bundle max count at decode time.

8. **Observability and tracing.** Our `tracing` spans are
   per-Interest today. A bundle of 16 becomes 1 ingress span
   that fans out to 16 internal spans. Not a blocker, but any
   future "per-Interest latency histogram" needs to be aware
   that the clock starts at bundle ingress, not inner-Interest
   ingress.

**None of these are blockers.** The BLEnD paper demonstrates that
a competent implementation can handle all of them. The cost is
protocol complexity: Interest Bundling is a permanent feature of
the wire format once it lands, not a performance knob that can
be reverted if it turns out to be the wrong call.

**Recommended sequencing.**

1. Do Lever 2a first (intra-face SHM batching — no wire format
   change). Measure. If that gives us >2× on small-segment cells
   and clears the send-bound regime entirely, Lever 3 proper is
   not needed for local IPC. If the wire format doesn't change,
   nothing external can break.

2. Do Lever 1 (SIMD parallel verify) second. This is strictly a
   consumer-side change with no wire or face impact. Measure.

3. Revisit Lever 3 once we actually have a wireless face
   implementation and can measure the BLEnD regime directly. At
   that point the protocol cost is justified by the link type,
   not by local IPC micro-optimisations.

## What not to do

- **Don't tune AIMD / CUBIC for small-segment cells.** The CC
  sweep in the matrix already shows all three algorithms within
  ~5% at the send-bound ceiling. CC is not the bottleneck when
  the consumer is yielding every other push.
- **Don't add LPv2 fragmentation to the SHM face.** SHM already
  does per-packet framing via the ring's length prefix; LP is
  for link layers that fragment at the MTU. Adding LP to SHM
  costs per-packet overhead we are explicitly trying to remove.
- **Don't replace `HashMap<u64, (usize, Instant)>` with
  `VecDeque` until you measure the HashMap cost.** The stage
  breakdown attributes <5% to store + bookkeeping combined; a
  different data structure is a micro-optimisation on top of
  whatever wins Lever 2 gives us.

## References

- Akinwumi et al., *BLEnD: Improving NDN Performance Over
  Wireless Links Using Interest Bundling.* The paper introduced
  Interest Bundling as a wireless-link optimisation; the design
  considerations above are informed by its discussion of
  batching trade-offs.
- `testbed/tests/chunked/matrix.sh` — the benchmark harness
  whose April 2026 run produced the numbers in this document.
- [why-blake3.md](./why-blake3.md) — explains why BLAKE3 Merkle
  doesn't pull ahead at large leaves and why Lever 1 (parallel
  verify) helps SHA-256 and BLAKE3 equally.
- `crates/foundation/ndn-transport/src/congestion.rs` — where
  any future bundle-aware CC changes would land.
- `crates/faces/ndn-faces/src/local/shm/spsc.rs` — where
  `send_batch` for Lever 2a would be added.
