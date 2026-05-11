# Pipeline Benchmarks

ndn-rs ships a Criterion-based benchmark suite that measures individual pipeline stage costs and end-to-end forwarding latency. The benchmarks live in `crates/spec/ndn-engine/benches/pipeline.rs`.

## Running Benchmarks

```bash
# Run the full suite
cargo bench -p ndn-engine

# Run a specific benchmark group
cargo bench -p ndn-engine -- "cs/"
cargo bench -p ndn-engine -- "fib/lpm"
cargo bench -p ndn-engine -- "interest_pipeline"

# View HTML reports after a run
open target/criterion/report/index.html
```

Criterion generates HTML reports with statistical analysis, throughput charts, and comparison against previous runs in `target/criterion/`.

## Approximate Relative Cost of Pipeline Stages

```mermaid
%%{init: {'theme': 'default'}}%%
pie title Pipeline Stage Cost Breakdown (approximate)
    "TLV Decode" : 30
    "CS Lookup (miss)" : 10
    "PIT Check" : 15
    "FIB LPM" : 20
    "Strategy" : 10
    "Dispatch" : 15
```

The chart above shows approximate relative costs for a typical Interest pipeline traversal (CS miss path). TLV decode and FIB longest-prefix match dominate because they involve parsing variable-length names and traversing trie nodes. CS lookup on a miss and strategy execution are comparatively cheap. Actual proportions depend on name length, table sizes, and cache state -- run the benchmarks to get precise numbers for your workload.

## Benchmark Harness Architecture

```mermaid
graph LR
    subgraph "Setup (per iteration)"
        PB["Pre-built wire packets<br/>(realistic names, ~100 B content)"]
    end

    subgraph "Benchmark Loop (Criterion)"
        PB --> S1["Stage under test<br/>(e.g. TlvDecodeStage)"]
        S1 --> M["Measure:<br/>latency (ns/op)<br/>throughput (ops/sec, bytes/sec)"]
    end

    subgraph "Full Pipeline Benchmarks"
        PB --> FP["All stages in sequence<br/>(decode -> CS -> PIT -> FIB -> strategy -> dispatch)"]
        FP --> M2["End-to-end latency"]
    end

    RT["Tokio current-thread runtime<br/>(no I/O, no scheduling jitter)"] -.->|"runs"| S1
    RT -.->|"runs"| FP

    style PB fill:#e8f4fd,stroke:#2196F3
    style M fill:#c8e6c9,stroke:#4CAF50
    style M2 fill:#c8e6c9,stroke:#4CAF50
    style RT fill:#fff3e0,stroke:#FF9800
```

## What Is Benchmarked

### TLV Decode

**Groups:** `decode/interest`, `decode/data`

Measures the cost of `TlvDecodeStage` -- parsing raw wire bytes into a decoded `Interest` or `Data` struct and setting `ctx.name`. Tested with 4-component and 8-component names to show scaling with name length.

Throughput is reported in bytes/sec to make comparisons across packet sizes meaningful.

### Content Store Lookup

**Group:** `cs`

- **`cs/hit`**: lookup of a name that exists in the CS. Measures the fast path where a cached Data is returned and the Interest pipeline short-circuits (no PIT or strategy involved).
- **`cs/miss`**: lookup of a name not in the CS. Measures the overhead added to every Interest that proceeds past the CS stage.

Uses a 64 MiB `LruCs` with a pre-populated entry for the hit case.

### PIT Check

**Group:** `pit`

- **`pit/new_entry`**: inserting a new PIT entry for a never-seen name. Uses a fresh PIT per iteration to isolate insert cost.
- **`pit/aggregate`**: second Interest with a different nonce hitting an existing PIT entry. This is the aggregation path where the Interest is suppressed (returned as `Action::Drop`).

### FIB Longest-Prefix Match

**Group:** `fib/lpm`

Measures LPM lookup time with 10, 100, and 1000 routes in the FIB. Routes have 2-component prefixes; the lookup name has 4 components (2 matching + 2 extra). This isolates trie traversal cost from name parsing.

### PIT Match (Data Path)

**Group:** `pit_match`

- **`pit_match/hit`**: Data arriving that matches an existing PIT entry. Seeds the PIT with a matching Interest, then measures the match and entry extraction.
- **`pit_match/miss`**: Data arriving with no matching PIT entry (unsolicited Data, dropped).

### CS Insert

**Group:** `cs_insert`

- **`cs_insert/insert_replace`**: steady-state replacement of an existing CS entry (same name, new Data). Measures the cost when the CS is warm.
- **`cs_insert/insert_new`**: inserting a unique name on each iteration. Measures cold-path cost including NameTrie node creation.

### Validation Stage

**Group:** `validation_stage`

- **`validation_stage/disabled`**: passthrough when no `Validator` is configured. Measures the baseline overhead of the stage itself.
- **`validation_stage/cert_via_anchor`**: full Ed25519 signature verification using a trust anchor. Includes schema check, key lookup, and cryptographic verify.

### Full Interest Pipeline

**Groups:** `interest_pipeline`, `interest_pipeline/cs_hit`

- **`interest_pipeline/no_route`**: decode + CS miss + PIT new entry. Stops before the strategy stage to isolate pure pipeline overhead. Tested with 4 and 8 component names.
- **`interest_pipeline/cs_hit`**: decode + CS hit. Measures the fast path where a cached Data satisfies the Interest immediately.

### Full Data Pipeline

**Group:** `data_pipeline`

Decode + PIT match + CS insert. Seeds the PIT with a matching Interest, then runs the full Data path. Tested with 4 and 8 component names. Throughput is reported in bytes/sec.

### Decode Throughput

**Group:** `decode_throughput`

Batch decoding of 1000 Interests in a tight loop. Reports throughput in elements/sec rather than latency, giving a peak-rate estimate for the decode stage.

## Benchmark Design Notes

- All async benchmarks use a **current-thread Tokio runtime** with no I/O, isolating CPU cost from scheduling jitter.
- Packet wire bytes are built with realistic name lengths (4 and 8 components) and ~100 B Data content.
- The PIT is cleared between iterations where noted to ensure consistent starting state.
- Each benchmark group uses Criterion's `Throughput` annotations so reports show both latency and throughput.

## Interpreting Results

Criterion reports **median** latency by default. Look for:

- **Regression alerts**: Criterion flags changes >5% from the baseline. CI uses a 10% threshold (see [Methodology](./methodology.md)).
- **Outliers**: high outlier percentages suggest contention or GC pauses. The current-thread runtime minimizes this.
- **Throughput numbers**: useful for capacity planning. If `decode_throughput` shows 2M Interest/sec, that is the ceiling before other stages are considered.

The HTML report at `target/criterion/report/index.html` includes violin plots, PDFs, and regression analysis for each benchmark.

### SHA-256 vs BLAKE3 in this bench

`signing/sha256-digest` uses `sha2::Sha256` (rustcrypto), which on
both x86_64 and aarch64 ships runtime CPUID dispatch through the
[`cpufeatures`](https://docs.rs/cpufeatures) crate and uses Intel
SHA-NI / ARMv8 SHA crypto when the CPU exposes them. **Effectively
every modern CI runner and consumer CPU does**, so the absolute
SHA-256 numbers in this table are SHA-NI numbers — there is no
practical "software SHA" baseline left to compare against.

That makes BLAKE3 a comparison between a hardware-accelerated SHA-256
and an AVX2/NEON-vectorised BLAKE3, and it shows: BLAKE3 is **not**
single-thread faster than SHA-256 on these CPUs at the input sizes a
typical NDN signed portion has (a few hundred bytes to a few KB). The
"BLAKE3 is 3–8× faster than SHA-256" claim refers to BLAKE3 vs *plain
software* SHA-256 — true on chips without SHA extensions, but no
longer the common case. See [Why BLAKE3](../deep-dive/why-blake3.md)
for the actual reasons ndn-rs supports BLAKE3 (Merkle-tree partial
verification of segmented Data, multi-thread hashing, single algorithm
for hash + MAC + KDF + XOF) — none of which are about raw single-
thread throughput.

## Latest CI Results

<!-- BENCH_RESULTS_START -->
*Last updated by CI on 2026-05-11 (ubuntu-latest, stable Rust)*

| Benchmark | Median | ± Variance |
|-----------|--------|------------|
| `cs/hit` | 819 ns | ±5 ns |
| `cs/miss` | 579 ns | ±3 ns |
| | | |
| `cs_insert/insert_new` | 1.33 µs | ±21 ns |
| `cs_insert/insert_replace` | 699 ns | ±4 ns |
| | | |
| `data_pipeline/4` | 1.78 µs | ±6 ns |
| `data_pipeline/8` | 2.17 µs | ±27 ns |
| | | |
| `decode/data/4` | 621 ns | ±21 ns |
| `decode/data/8` | 822 ns | ±1 ns |
| `decode/interest/4` | 997 ns | ±15 ns |
| `decode/interest/8` | 1.26 µs | ±5 ns |
| | | |
| `decode_throughput/4` | 1.00 ms | ±13.91 µs |
| `decode_throughput/8` | 1.28 ms | ±4.58 µs |
| | | |
| `fib/lpm/10` | 29 ns | ±0 ns |
| `fib/lpm/100` | 94 ns | ±0 ns |
| `fib/lpm/1000` | 94 ns | ±0 ns |
| | | |
| `interest_pipeline/cs_hit` | 1.49 µs | ±2 ns |
| `interest_pipeline/no_route/4` | 2.24 µs | ±33 ns |
| `interest_pipeline/no_route/8` | 2.65 µs | ±7 ns |
| | | |
| `large/blake3-rayon/hash/1MB` | 118.34 µs | ±1.68 µs |
| `large/blake3-rayon/hash/256KB` | 37.02 µs | ±656 ns |
| `large/blake3-rayon/hash/4MB` | 439.14 µs | ±16.69 µs |
| `large/blake3-single/hash/1MB` | 250.68 µs | ±680 ns |
| `large/blake3-single/hash/256KB` | 61.27 µs | ±2.63 µs |
| `large/blake3-single/hash/4MB` | 998.76 µs | ±8.70 µs |
| `large/sha256/hash/1MB` | 659.89 µs | ±603 ns |
| `large/sha256/hash/256KB` | 164.70 µs | ±106 ns |
| `large/sha256/hash/4MB` | 2.64 ms | ±1.12 µs |
| | | |
| `lru/evict` | 196 ns | ±1 ns |
| `lru/evict_prefix` | 1.98 µs | ±2.07 µs |
| `lru/get_can_be_prefix` | 293 ns | ±0 ns |
| `lru/get_hit` | 209 ns | ±0 ns |
| `lru/get_miss_empty` | 140 ns | ±0 ns |
| `lru/get_miss_populated` | 186 ns | ±0 ns |
| `lru/insert_new` | 2.31 µs | ±1.56 µs |
| `lru/insert_replace` | 365 ns | ±5 ns |
| | | |
| `name/display/components/4` | 455 ns | ±8 ns |
| `name/display/components/8` | 877 ns | ±11 ns |
| `name/eq/eq_match` | 28 ns | ±0 ns |
| `name/eq/eq_miss_first` | 1 ns | ±0 ns |
| `name/eq/eq_miss_last` | 27 ns | ±0 ns |
| `name/has_prefix/prefix_len/1` | 6 ns | ±0 ns |
| `name/has_prefix/prefix_len/4` | 18 ns | ±0 ns |
| `name/has_prefix/prefix_len/8` | 31 ns | ±0 ns |
| `name/hash/components/4` | 86 ns | ±1 ns |
| `name/hash/components/8` | 163 ns | ±0 ns |
| `name/parse/components/12` | 695 ns | ±11 ns |
| `name/parse/components/4` | 238 ns | ±27 ns |
| `name/parse/components/8` | 477 ns | ±46 ns |
| `name/tlv_decode/components/12` | 277 ns | ±3 ns |
| `name/tlv_decode/components/4` | 125 ns | ±0 ns |
| `name/tlv_decode/components/8` | 190 ns | ±1 ns |
| | | |
| `pit/aggregate` | 2.89 µs | ±130 ns |
| `pit/new_entry` | 1.76 µs | ±32 ns |
| | | |
| `pit_match/hit` | 1.85 µs | ±22 ns |
| `pit_match/miss` | 800 ns | ±3 ns |
| | | |
| `sharded/get_hit/1` | 223 ns | ±0 ns |
| `sharded/get_hit/16` | 222 ns | ±1 ns |
| `sharded/get_hit/4` | 223 ns | ±3 ns |
| `sharded/get_hit/8` | 223 ns | ±2 ns |
| `sharded/insert/1` | 2.57 µs | ±1.61 µs |
| `sharded/insert/16` | 1.86 µs | ±1.58 µs |
| `sharded/insert/4` | 2.50 µs | ±1.73 µs |
| `sharded/insert/8` | 2.04 µs | ±1.54 µs |
| | | |
| `signing/blake3-keyed/sign_sync/100B` | 182 ns | ±0 ns |
| `signing/blake3-keyed/sign_sync/1KB` | 1.20 µs | ±2 ns |
| `signing/blake3-keyed/sign_sync/2KB` | 2.40 µs | ±2 ns |
| `signing/blake3-keyed/sign_sync/4KB` | 3.53 µs | ±60 ns |
| `signing/blake3-keyed/sign_sync/500B` | 618 ns | ±16 ns |
| `signing/blake3-keyed/sign_sync/8KB` | 4.79 µs | ±10 ns |
| `signing/blake3-plain/sign_sync/100B` | 188 ns | ±0 ns |
| `signing/blake3-plain/sign_sync/1KB` | 1.20 µs | ±0 ns |
| `signing/blake3-plain/sign_sync/2KB` | 2.40 µs | ±1 ns |
| `signing/blake3-plain/sign_sync/4KB` | 3.53 µs | ±50 ns |
| `signing/blake3-plain/sign_sync/500B` | 624 ns | ±2 ns |
| `signing/blake3-plain/sign_sync/8KB` | 4.79 µs | ±2 ns |
| `signing/ed25519/sign_sync/100B` | 20.61 µs | ±335 ns |
| `signing/ed25519/sign_sync/1KB` | 24.04 µs | ±55 ns |
| `signing/ed25519/sign_sync/2KB` | 27.88 µs | ±48 ns |
| `signing/ed25519/sign_sync/4KB` | 35.03 µs | ±71 ns |
| `signing/ed25519/sign_sync/500B` | 22.10 µs | ±108 ns |
| `signing/ed25519/sign_sync/8KB` | 50.09 µs | ±328 ns |
| `signing/hmac/sign_sync/100B` | 286 ns | ±0 ns |
| `signing/hmac/sign_sync/1KB` | 849 ns | ±2 ns |
| `signing/hmac/sign_sync/2KB` | 1.48 µs | ±1 ns |
| `signing/hmac/sign_sync/4KB` | 2.75 µs | ±2 ns |
| `signing/hmac/sign_sync/500B` | 530 ns | ±1 ns |
| `signing/hmac/sign_sync/8KB` | 5.26 µs | ±5 ns |
| `signing/sha256-digest/sign_sync/100B` | 101 ns | ±0 ns |
| `signing/sha256-digest/sign_sync/1KB` | 665 ns | ±1 ns |
| `signing/sha256-digest/sign_sync/2KB` | 1.29 µs | ±14 ns |
| `signing/sha256-digest/sign_sync/4KB` | 2.54 µs | ±3 ns |
| `signing/sha256-digest/sign_sync/500B` | 340 ns | ±0 ns |
| `signing/sha256-digest/sign_sync/8KB` | 5.07 µs | ±6 ns |
| | | |
| `spawn_overhead/runtime_trait_boxed` | 48.88 µs | ±429 ns |
| `spawn_overhead/spawn_boxed` | 31.00 µs | ±424 ns |
| `spawn_overhead/spawn_concrete` | 28.99 µs | ±356 ns |
| | | |
| `validation/cert_missing` | 233 ns | ±0 ns |
| `validation/schema_mismatch` | 186 ns | ±0 ns |
| `validation/single_hop` | 402 ns | ±1 ns |
| | | |
| `validation_stage/cert_via_anchor` | 43.79 µs | ±123 ns |
| `validation_stage/disabled` | 751 ns | ±1 ns |
| | | |
| `verification/blake3-keyed/verify/100B` | 285 ns | ±0 ns |
| `verification/blake3-keyed/verify/1KB` | 1.30 µs | ±0 ns |
| `verification/blake3-keyed/verify/2KB` | 2.50 µs | ±8 ns |
| `verification/blake3-keyed/verify/4KB` | 3.63 µs | ±13 ns |
| `verification/blake3-keyed/verify/500B` | 721 ns | ±1 ns |
| `verification/blake3-keyed/verify/8KB` | 4.90 µs | ±4 ns |
| `verification/blake3-plain/verify/100B` | 310 ns | ±0 ns |
| `verification/blake3-plain/verify/1KB` | 1.32 µs | ±31 ns |
| `verification/blake3-plain/verify/2KB` | 2.50 µs | ±3 ns |
| `verification/blake3-plain/verify/4KB` | 3.64 µs | ±6 ns |
| `verification/blake3-plain/verify/500B` | 737 ns | ±0 ns |
| `verification/blake3-plain/verify/8KB` | 4.90 µs | ±8 ns |
| `verification/ed25519-batch/1` | 53.48 µs | ±1.28 µs |
| `verification/ed25519-batch/10` | 248.74 µs | ±407 ns |
| `verification/ed25519-batch/100` | 2.26 ms | ±6.52 µs |
| `verification/ed25519-batch/1000` | 18.54 ms | ±83.90 µs |
| `verification/ed25519-per-sig-loop/1` | 42.27 µs | ±126 ns |
| `verification/ed25519-per-sig-loop/10` | 420.94 µs | ±538 ns |
| `verification/ed25519-per-sig-loop/100` | 4.29 ms | ±97.36 µs |
| `verification/ed25519-per-sig-loop/1000` | 43.05 ms | ±511.57 µs |
| `verification/ed25519/verify/100B` | 42.03 µs | ±152 ns |
| `verification/ed25519/verify/1KB` | 44.11 µs | ±224 ns |
| `verification/ed25519/verify/2KB` | 45.88 µs | ±82 ns |
| `verification/ed25519/verify/4KB` | 49.59 µs | ±1.03 µs |
| `verification/ed25519/verify/500B` | 43.24 µs | ±1.11 µs |
| `verification/ed25519/verify/8KB` | 57.97 µs | ±260 ns |
| `verification/sha256-digest/verify/100B` | 104 ns | ±0 ns |
| `verification/sha256-digest/verify/1KB` | 666 ns | ±0 ns |
| `verification/sha256-digest/verify/2KB` | 1.30 µs | ±4 ns |
| `verification/sha256-digest/verify/4KB` | 2.55 µs | ±1 ns |
| `verification/sha256-digest/verify/500B` | 341 ns | ±0 ns |
| `verification/sha256-digest/verify/8KB` | 5.08 µs | ±57 ns |
<!-- BENCH_RESULTS_END -->
