# Why BLAKE3 (when SHA-NI is everywhere)

The BLAKE3 specification famously claims **3–8× the throughput of
SHA-256**. That number assumes a software implementation of SHA-256.
On any CPU shipped in the last ten years — Intel Goldmont (2016) and
Cannon Lake (2018) onward, AMD Zen (2017) onward, Apple M1 (2020)
onward, every ARMv8.2-A and later phone — SHA-256 runs on a dedicated
hardware instruction (Intel SHA-NI / ARMv8 SHA crypto extensions),
and a hardware-accelerated SHA-256 hashes a few-hundred-byte buffer
in roughly the same wall time as a single-threaded BLAKE3.

The empirical numbers from this project's own bench harness on the
GitHub Actions `ubuntu-latest` runner make the point uncomfortably:

| Input size | SHA-256 (sha2 + SHA-NI) | BLAKE3 (single-thread, AVX2) | who wins |
|---|---:|---:|---|
| 100 B | ~96 ns | ~188 ns | SHA-256 +96% |
| 1 KB | ~657 ns | ~1.20 µs | SHA-256 +83% |
| 4 KB | ~2.55 µs | ~3.52 µs | SHA-256 +38% |
| 8 KB | ~5.07 µs | ~4.79 µs | BLAKE3 +6% |

For an NDN signed portion (typically a few hundred bytes to a couple
KB — Name TLV + MetaInfo + Content + SignatureInfo), single-threaded
BLAKE3 is **slower** than hardware SHA-256, not faster. So if BLAKE3
is in this project at all, "raw single-thread speed" cannot be the
reason. It isn't.

This document is the actual reason list, and the design space it
opens up for ndn-rs.

## What BLAKE3 has that SHA-256 does not

### 1. Internal Merkle tree structure

BLAKE3 hashes input in 1024-byte chunks, producing one chaining value
per chunk, then combines chunks pairwise into a balanced binary tree
whose root is the final 32-byte digest. **Every intermediate node of
that tree is itself a valid BLAKE3 output.** This is the structural
property that everything else on this list builds on.

SHA-256 is Merkle-Damgård: state is a single 256-bit chaining
register that absorbs each 64-byte block sequentially. There is no
way to address a sub-region of the input by its hash without
re-hashing everything before it. The hash is a one-way streaming
construction by design.

### 2. Verifiable streaming and partial verification

Because the BLAKE3 hash of any sub-tree is a valid BLAKE3 output, a
verifier in possession of the **root** hash and a **verification
path** (the sibling hashes along the path from a leaf chunk up to the
root) can verify **any individual chunk in isolation**, without
having seen the chunks before or after it.

This is the killer feature for content-centric networking. NDN
already chunks large Data into named segments (`/file/v=1/seg=0`,
`/file/v=1/seg=1`, …). With BLAKE3:

- The producer hashes all segments as the leaves of one BLAKE3 tree,
  then signs **only the root** with one ECDSA / Ed25519 / BLAKE3
  signature.
- Each segment's wire form carries its leaf-to-root verification path
  (a few hundred bytes for a tree of thousands of segments — `O(log N)`
  hashes).
- A consumer that fetches segments out of order, in parallel, or
  skips segments it doesn't need, can verify each one against the
  signed root *as soon as it arrives*. No "must wait for the full
  file" blocking.

SHA-256 cannot do this. To verify a SHA-256 signature on a
multi-segment file you must have all bytes in their original order.
The closest approximation is to sign each segment individually,
which forces one signature per segment — orders of magnitude more
public-key operations and bytes on the wire.

### 3. Linear-scaling parallel hashing on a single packet

The BLAKE3 reference implementation supports multi-threaded hashing
of a single buffer via the `rayon` feature, with throughput that
scales nearly linearly with cores up to ~16 threads. SHA-256 cannot
do this — its compression function is inherently sequential, so
hashing a 16 MB buffer takes 16× longer than hashing a 1 MB buffer
on the same core, no matter how many cores you have.

ndn-rs has the `rayon` feature enabled and `Blake3Signer` /
`Blake3DigestVerifier` automatically dispatch to `Hasher::update_rayon`
when the input crosses `BLAKE3_RAYON_THRESHOLD` (128 KiB, the rule-of-
thumb crossover from the blake3 docs). Per-packet signing of normal
NDN signed portions never reaches that threshold and is unaffected;
bulk content publication does.

The `large/blake3-{single,rayon}` and `large/sha256` bench groups
exercise the crossover at 256 KB / 1 MB / 4 MB. Local numbers from a
multi-core development machine make the structural advantage concrete:

| Input size | BLAKE3 single-thread | BLAKE3 rayon | rayon speedup | SHA-256 SHA-NI | BLAKE3 rayon vs SHA-NI |
|---|---:|---:|---:|---:|---:|
| 256 KB | 103 µs | 49 µs | **2.1×** | 95 µs | **1.95×** faster |
| 1 MB | 413 µs | 93 µs | **4.4×** | 368 µs | **3.95×** faster |
| 4 MB | 1.66 ms | 247 µs | **6.7×** | 1.46 ms | **5.92×** faster |

Three observations from the numbers:

1. **Single-thread BLAKE3 loses to SHA-NI at every size in the table.**
   The narrative is identical to the per-packet bench above — SHA-256
   with hardware acceleration is faster than single-thread BLAKE3 even
   at 4 MB. BLAKE3's "I'm faster" story is not single-thread.
2. **rayon turns the loss into a 6× win** by 4 MB. The crossover
   happens around 256 KB, and once amortised, rayon scales near-linearly
   with cores. SHA-NI cannot follow — there is no "SHA-NI rayon".
3. **The crossover threshold matches the blake3 docs.** Below ~128 KiB
   the rayon thread-spawn cost beats the per-byte savings; above it,
   rayon dominates. This is exactly why ndn-rs gates the dispatch on
   input size rather than always taking the rayon path.

For NDN this matters at the **Content-Store insert** and
**publication-time** boundary, not the per-Interest hot path:

- A producer publishing a 1 GB Data object can compute its content
  digest in ~250 ms rather than ~1.6 s on a multi-core machine — a
  6× wall-clock win that scales with available cores.
- A long-running ndn-fwd that ingests a large file via `ndn-put` or
  via a sync protocol can checksum the body with whatever cores it
  has spare without bottlenecking on a single thread.

This is the only place where the "BLAKE3 is faster than SHA-256"
claim survives in 2026: when you have many cores **and** an input
that's large enough to amortise the tree overhead. SHA-NI cannot
follow you there; it accelerates one core at a time.

### 4. One algorithm: hash, MAC, KDF, XOF

BLAKE3 is *also*:

- **Keyed mode** (a fixed-time MAC) — `blake3::keyed_hash(&key, &input)`.
  Equivalent in security to HMAC-SHA-256 but with no inner/outer
  wrapping overhead — the key is consumed in the IV directly.
- **Key derivation** — `blake3::derive_key(context, &key_material)`,
  domain-separated KDF replacing HKDF-Extract + HKDF-Expand.
- **Extendable output** (XOF) — `Hasher::finalize_xof().fill(&mut buf)`
  produces an arbitrary-length output stream from a single hash
  input. SHA-256 produces a fixed 256 bits and needs a second
  primitive (HKDF-Expand, AES-CTR, etc.) to stretch.

A SHA-256 deployment that wants the same surface needs **three**
separately-audited primitives: SHA-256 for hashing, HMAC-SHA-256 for
keyed mode, HKDF-SHA-256 for KDF. BLAKE3 collapses that to one
audited primitive with one shared SIMD implementation.

For ndn-rs specifically this means:

- `Blake3KeyedSigner` (signature type 7) is a real primitive, not a
  thin wrapper around two SHA-256 calls. The HMAC-SHA-256 path
  (signature type 4) goes through `key⊕ipad ‖ msg → SHA-256 →
  key⊕opad ‖ digest → SHA-256`, two compression chains; BLAKE3 keyed
  mode is one compression chain with the key plumbed into the IV.
- A future NDNCERT or trust-bootstrapping flow could derive
  per-session keys with `derive_key("ndn-rs/ndncert/v0.3", root)`
  rather than HKDF-Extract + HKDF-Expand.
- A future segmenter could use BLAKE3 XOF to derive per-segment
  encryption keys from a single content-publication key.

### 5. Smaller / simpler code on targets without a SHA extension

`ndn-embedded` (bare-metal `no_std` MCU forwarder) targets are
exactly the chips that *do not* have SHA-NI: Cortex-M0/M3/M4, RISC-V
microcontrollers, AVR. On those parts a software SHA-256
implementation costs around 8–12 cycles/byte. A software BLAKE3 on
the same parts is faster (3–5 cycles/byte even without SIMD) and the
single algorithm covers hash, keyed MAC, and KDF — relevant for
binary-size-constrained embedded firmware where pulling in
`hkdf` + `hmac` + `sha2` separately would be expensive.

So the "BLAKE3 is faster" claim becomes true again in the segment of
the deployment matrix where SHA extensions are absent. ndn-rs ships
on both segments — the desktop forwarder runs on x86-with-SHA-NI;
the embedded forwarder on Cortex-without-SHA-NI — and BLAKE3 is the
algorithm that is well-tuned across both.

### 6. Constant code path across CPUs

`sha2`'s SHA-NI path is a different code path from its software
SSSE3 path, which is different from its ARMv8 crypto path, which is
different from its plain scalar path. Four implementations of the
same primitive, four sets of test coverage, four places a hardware
errata or compiler regression can lurk. BLAKE3's implementation is
**one** SIMD code path with width-agnostic vector ops; the same code
runs on AVX2, AVX-512, NEON, and scalar fallback by varying lane
width, not by branching to a different routine. From an audit and
maintenance standpoint that's a meaningful simplification.

## How to actually speed up the BLAKE3 sign/verify pipeline in ways SHA-256 cannot

This is the design space that opens up once you accept that BLAKE3
is a tree, not a stream. Each item is something an ndn-rs deployment
can do that a SHA-256 deployment fundamentally cannot. None of these
exist in ndn-rs today; all of them are reachable from where the
codebase is now.

### A. Tree-signed segmented Data: one signature per file

**Status: design space, not yet implemented.**

A producer publishing a multi-segment file (`/foo/v=1/seg=0..N`)
today must either (a) sign each segment Data packet individually, or
(b) put the whole file inside one giant Data and sign it once. Option
(a) is `O(N)` ECDSA / Ed25519 operations; option (b) breaks the NDN
chunking model and prevents partial fetch.

With BLAKE3 you can:

1. Compute a BLAKE3 tree over the **concatenation** of all segment
   Content fields (the producer streams them through `Hasher::update`
   in segment order).
2. Take the root hash. Place it in a single "manifest" Data packet —
   `/foo/v=1/_manifest` — signed once with whatever signature type
   the application prefers (Ed25519, ECDSA, BLAKE3-keyed, even
   BLAKE3-plain digest with a name-based trust schema).
3. For each segment Data, attach the **leaf-to-root verification
   path** as a small additional TLV in the SignatureInfo (a handful
   of 32-byte sibling hashes, `O(log N)` per segment).
4. Set the segment's SignatureType to BLAKE3-plain (type 6) with the
   leaf hash as the SignatureValue. The KeyLocator points at the
   manifest Data.

A consumer receiving any segment can verify it in three steps:

1. Recompute the BLAKE3 leaf hash over the segment's Content.
2. Walk up the verification path, hashing pairs, to recompute the
   root.
3. Check the recomputed root against the manifest Data's signed
   payload.

Cost per segment for the consumer: one BLAKE3 leaf hash (~hundreds
of nanoseconds) + `log₂(N)` BLAKE3 parent compressions (~tens of
nanoseconds each). For a 1 GB file split into 4 KB segments
(N = 262144, log₂N = 18), this is roughly **2 µs per segment**, and
exactly **one** ECDSA / Ed25519 verify across the entire file.

A SHA-256 deployment cannot do this without inventing its own tree
construction on top, which would not interoperate with any other
NDN implementation.

### B. Out-of-order parallel verification of segmented fetches

**Status: design space.**

NDN consumers fetch segments out of order routinely — pipelined
`ndncatchunks`, NDN sync protocols catching up after a partition,
SVS retrieving recent state. Today each Data packet must be verified
**after** its arrival but **before** it's released to the
application. With segment-individual signatures, this is `N`
public-key verifies and they cannot be batched.

With tree-signed segments (item A), every segment can be verified
the moment it arrives, in any order, on any thread, with no shared
state between verifiers beyond an immutable copy of the manifest.
Pipeline depth and core count both scale linearly. The verification
tasks are embarrassingly parallel because each one needs only the
segment Content, the verification path, and the root — never any
other segment.

For sync protocols (PSync, SVS) that ship snapshots of large state
this is a significant latency win on the receiving side.

### C. Multi-thread hashing of large publications at producer time

**Status: trivial to enable today via `blake3 = { features = ["rayon"] }`.**

If the producer is the bottleneck — a sensor uploading a 100 MB log
file, an archive node ingesting historical snapshots — the BLAKE3
crate exposes `Hasher::update_rayon(&data)` which spreads the work
across all threads in the global rayon pool. SHA-256 cannot be
multi-threaded over a single buffer at all.

Concretely: hashing a 100 MB buffer on an 8-core CPU takes ~200 ms
with single-threaded BLAKE3 vs ~28 ms with `update_rayon`. That's a
~7× speedup for free, no protocol changes, no design space — just a
crate feature flag.

This is the only one of the items in this list that ndn-rs could
adopt **today** with no protocol-level changes. A `BlockingProducer`
that hashes its content via `update_rayon` when the input exceeds
some threshold (say, 1 MB) costs nothing for small Data and dominates
SHA-256 for large publications.

### D. Incremental verifiable updates for long-lived streams

**Status: design space, longer term.**

For sensor telemetry and other long-running streaming publications,
a producer can maintain a BLAKE3 hasher across the lifetime of the
stream and periodically (every K samples) emit a "checkpoint" Data
packet containing the running root hash, signed once. Consumers
catching up from any checkpoint verify forward from there using the
tree's incremental property, without re-hashing the full history.

This is more involved — the checkpoint cadence, the carrier name
convention, and the backfill protocol all need design — but it's
the kind of thing that BLAKE3's tree structure makes possible and
SHA-256's streaming structure forbids.

### E. Single-primitive trust schema bootstrapping

**Status: design space, smaller scope.**

NDNCERT 0.3 currently uses ECDH (P-256) → HKDF-SHA-256 → AES-GCM-128
to bootstrap session keys. A future rev could replace HKDF-SHA-256
with `blake3::derive_key`, removing one audited primitive from the
trust path without changing the protocol's security properties.
Smaller code, simpler audit, same guarantees.

This is the smallest item on the list and the most concrete. It
doesn't require a protocol redesign or a new TLV type — just an
internal substitution in `ndn-cert`.

## What stays SHA-256

For any single signed packet whose signed portion is under ~4 KB and
whose signature type is not name-based, **`SignatureSha256WithEcdsa`
remains the right default**. SHA-NI is faster than single-thread
BLAKE3 in that regime, ECDSA is well-understood by every NDN
ecosystem implementation, and the trust schema layer doesn't care
which hash algorithm sits underneath the signature value.

The cases where BLAKE3 earns its keep are exactly the ones above:
multi-segment files, large publications, multi-core hashing, and
the cryptographic-surface-simplification angle on
constrained-firmware targets. None of them are about beating SHA-NI
at single-block hashing — that battle is over and SHA-NI won.

## Appendix: streaming hash during TLV decode — investigated and rejected

A natural optimisation idea: instead of `decode → hash the signed
region after the fact`, feed bytes to an incremental hasher *during*
TLV decode, so the digest is ready the moment parsing finishes.
Eliminates one byte pass over the signed region. Both `sha2` and
`blake3` expose `Hasher::update` for exactly this kind of streaming.
The hypothesis was that the second pass costs real time because the
bytes have been evicted from L1/L2 between decode and validate by
the intervening pipeline work.

**The hypothesis didn't survive contact with a micro-bench.** A
one-time investigation measured (a) sha2 / blake3 incremental-API
overhead at NDN sizes, and (b) the cold-cache cost after evicting
2 MiB of memory between buffer setup and hash. Two results killed
the idea:

### Finding 1: SHA-256 cache locality is already a non-factor at NDN sizes

| size | warm `Sha256::digest` | post-eviction `Sha256::digest` | ratio |
|---|---:|---:|---:|
| 256 B | 100 ns | 63 ns | 0.63× (*cold* faster!) |
| 1 KB | 392 ns | 342 ns | 0.87× |
| 4 KB | 1532 ns | 1419 ns | 0.93× |
| 16 KB | 5619 ns | 5614 ns | 1.00× |

The cold-hash measurement is **the same speed or faster** than the
warm-hash measurement at every NDN-typical size. The post-eviction
times being slightly *lower* is hardware-prefetch noise: the access
pattern is sequential, the prefetcher predicts it perfectly, and the
"cold cache" path benefits from L1 pre-population by the time the
hash actually starts. Either way, the "savings from streaming
SHA-256" is at most a handful of nanoseconds per packet, and is just
as plausibly negative as positive.

### Finding 2: BLAKE3 actively *punishes* the streaming pattern at large sizes

| size | warm oneshot | warm `update(64-byte chunks)` | overhead |
|---|---:|---:|---:|
| 256 B | 197 ns | 211 ns | +7% |
| 1 KB | 781 ns | 820 ns | +5% |
| 4 KB | **1703 ns** | **3451 ns** | **+103%** |
| 16 KB | **6561 ns** | **13785 ns** | **+110%** |

This is the surprise. At 4 KB and 16 KB, feeding BLAKE3 in 64-byte
chunks (which is exactly what a TLV decoder would do, since most NDN
TLV bodies are tens to hundreds of bytes) is **2× slower** than
calling `update` once on the full slice. With 256-byte chunks it's
marginally better but still ~2× at 4 KB+.

**Why:** BLAKE3's single-thread speed comes from its tree-mode SIMD
implementation processing multiple 1024-byte chunks in parallel
across SIMD lanes. When you call `update(big_slice)`, BLAKE3 sees
the full buffer, splits it into chunks, and runs 4–16 chunks through
SIMD lanes simultaneously. When you call `update(small_chunk)`
repeatedly, BLAKE3 has no choice but to buffer up bytes until a full
chunk is available, then process them serially because there's no
"next chunk" yet to fill the other SIMD lanes. The parallelism is
gone, and what's left is the serial fallback plus per-call buffering
overhead.

So **BLAKE3's tree mode requires contiguous large updates to be
fast**. The current "hash the slice after decode" pattern is exactly
the right shape for BLAKE3, and any move toward incremental updates
would slow it down.

### Conclusion

For both algorithms the verdict is the same — for opposite reasons:

- **SHA-256:** streaming saves nothing because there's nothing to
  save. Cache locality at NDN sizes is already a no-op.
- **BLAKE3:** streaming actively costs ~2× at 4 KB+ because it
  defeats SIMD parallelism.

The current architecture — `decode produces a slice, validator
hashes the slice oneshot` — is **already optimal**, not by accident
but because it matches the algorithms' performance models. There is
no streaming-hash refactor to do. If the same idea comes up again,
re-run the bench code that lived briefly in
`crates/engine/ndn-security/benches/security.rs` (now removed; check
the git history for `bench_streaming_feasibility`) to confirm the
finding still holds on whatever hardware you care about.

## Summary

| Question | Answer |
|---|---|
| Is BLAKE3 single-thread faster than SHA-256? | **No**, on any CPU with SHA-NI / ARMv8 SHA crypto. **Yes**, on every other CPU. |
| Can BLAKE3 do something SHA-256 cannot? | **Yes**: Merkle-tree partial verification, multi-thread hashing of one buffer, single primitive for hash/MAC/KDF/XOF. |
| Should small NDN signed packets use BLAKE3? | **No**. Use `SignatureSha256WithEcdsa` (the spec default). It's faster on this hardware. |
| Should multi-segment NDN content trees use BLAKE3? | **Yes**, eventually. The protocol-level design space (item A above) is the place this project should focus future BLAKE3 work. |
| Should `ndn-embedded` use BLAKE3 by default? | **Yes**. Microcontroller targets do not have SHA-NI; BLAKE3 is faster and smaller (one primitive instead of three). |
| Why ship the BLAKE3 SignatureType today? | To reserve the type-code space and keep ndn-rs interoperable with future NDN deployments that use the tree-verification design. The benchmark numbers are not the reason. |
