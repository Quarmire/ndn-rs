# Pipeline Benchmarks

ndn-rs ships a Criterion-based benchmark suite that measures individual pipeline stage costs and end-to-end forwarding latency. The benchmarks live in `crates/engine/ndn-engine/benches/pipeline.rs`.

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
*Last updated by CI on 2026-04-16 (ubuntu-latest, stable Rust)*

| Benchmark | Median | ± Variance |
|-----------|--------|------------|
| `cs/hit` | 892 ns | ±12 ns |
| `cs/miss` | 595 ns | ±3 ns |
| | | |
| `cs_insert/insert_new` | 26.40 µs | ±37.86 µs |
| `cs_insert/insert_replace` | 1.03 µs | ±16 ns |
| | | |
| `data_pipeline/4` | 2.18 µs | ±89 ns |
| `data_pipeline/8` | 2.65 µs | ±118 ns |
| | | |
| `decode/data/4` | 549 ns | ±4 ns |
| `decode/data/8` | 737 ns | ±6 ns |
| `decode/interest/4` | 615 ns | ±4 ns |
| `decode/interest/8` | 810 ns | ±6 ns |
| | | |
| `decode_throughput/4` | 615.17 µs | ±4.39 µs |
| `decode_throughput/8` | 817.82 µs | ±6.93 µs |
| | | |
| `fib/lpm/10` | 37 ns | ±0 ns |
| `fib/lpm/100` | 104 ns | ±1 ns |
| `fib/lpm/1000` | 104 ns | ±0 ns |
| | | |
| `interest_pipeline/cs_hit` | 1.19 µs | ±13 ns |
| `interest_pipeline/no_route/4` | 1.63 µs | ±16 ns |
| `interest_pipeline/no_route/8` | 1.79 µs | ±35 ns |
| | | |
| `large/blake3-rayon/hash/1MB` | 130.39 µs | ±5.22 µs |
| `large/blake3-rayon/hash/256KB` | 40.94 µs | ±737 ns |
| `large/blake3-rayon/hash/4MB` | 481.96 µs | ±13.46 µs |
| `large/blake3-single/hash/1MB` | 271.00 µs | ±2.34 µs |
| `large/blake3-single/hash/256KB` | 66.61 µs | ±538 ns |
| `large/blake3-single/hash/4MB` | 1.10 ms | ±8.72 µs |
| `large/sha256/hash/1MB` | 717.79 µs | ±4.57 µs |
| `large/sha256/hash/256KB` | 179.51 µs | ±1.25 µs |
| `large/sha256/hash/4MB` | 2.87 ms | ±19.47 µs |
| | | |
| `lru/evict` | 208 ns | ±5 ns |
| `lru/evict_prefix` | 2.25 µs | ±2.38 µs |
| `lru/get_can_be_prefix` | 319 ns | ±2 ns |
| `lru/get_hit` | 225 ns | ±1 ns |
| `lru/get_miss_empty` | 149 ns | ±2 ns |
| `lru/get_miss_populated` | 198 ns | ±2 ns |
| `lru/insert_new` | 3.38 µs | ±2.11 µs |
| `lru/insert_replace` | 407 ns | ±3 ns |
| | | |
| `name/display/components/4` | 504 ns | ±8 ns |
| `name/display/components/8` | 981 ns | ±18 ns |
| `name/eq/eq_match` | 40 ns | ±1 ns |
| `name/eq/eq_miss_first` | 3 ns | ±0 ns |
| `name/eq/eq_miss_last` | 38 ns | ±0 ns |
| `name/has_prefix/prefix_len/1` | 7 ns | ±0 ns |
| `name/has_prefix/prefix_len/4` | 21 ns | ±0 ns |
| `name/has_prefix/prefix_len/8` | 45 ns | ±2 ns |
| `name/hash/components/4` | 93 ns | ±1 ns |
| `name/hash/components/8` | 180 ns | ±2 ns |
| `name/parse/components/12` | 712 ns | ±7 ns |
| `name/parse/components/4` | 255 ns | ±3 ns |
| `name/parse/components/8` | 465 ns | ±9 ns |
| `name/tlv_decode/components/12` | 323 ns | ±3 ns |
| `name/tlv_decode/components/4` | 151 ns | ±1 ns |
| `name/tlv_decode/components/8` | 225 ns | ±2 ns |
| | | |
| `pit/aggregate` | 2.42 µs | ±139 ns |
| `pit/new_entry` | 1.37 µs | ±15 ns |
| | | |
| `pit_match/hit` | 1.86 µs | ±12 ns |
| `pit_match/miss` | 1.30 µs | ±13 ns |
| | | |
| `sharded/get_hit/1` | 250 ns | ±2 ns |
| `sharded/get_hit/16` | 246 ns | ±3 ns |
| `sharded/get_hit/4` | 258 ns | ±2 ns |
| `sharded/get_hit/8` | 248 ns | ±2 ns |
| `sharded/insert/1` | 4.34 µs | ±2.32 µs |
| `sharded/insert/16` | 3.48 µs | ±2.27 µs |
| `sharded/insert/4` | 4.07 µs | ±2.34 µs |
| `sharded/insert/8` | 3.93 µs | ±2.19 µs |
| | | |
| `signing/blake3-keyed/sign_sync/100B` | 198 ns | ±1 ns |
| `signing/blake3-keyed/sign_sync/1KB` | 1.31 µs | ±9 ns |
| `signing/blake3-keyed/sign_sync/2KB` | 2.59 µs | ±25 ns |
| `signing/blake3-keyed/sign_sync/4KB` | 3.81 µs | ±32 ns |
| `signing/blake3-keyed/sign_sync/500B` | 666 ns | ±5 ns |
| `signing/blake3-keyed/sign_sync/8KB` | 5.18 µs | ±46 ns |
| `signing/blake3-plain/sign_sync/100B` | 204 ns | ±2 ns |
| `signing/blake3-plain/sign_sync/1KB` | 1.30 µs | ±10 ns |
| `signing/blake3-plain/sign_sync/2KB` | 2.60 µs | ±24 ns |
| `signing/blake3-plain/sign_sync/4KB` | 3.82 µs | ±35 ns |
| `signing/blake3-plain/sign_sync/500B` | 674 ns | ±6 ns |
| `signing/blake3-plain/sign_sync/8KB` | 5.22 µs | ±44 ns |
| `signing/ed25519/sign_sync/100B` | 22.56 µs | ±173 ns |
| `signing/ed25519/sign_sync/1KB` | 26.19 µs | ±196 ns |
| `signing/ed25519/sign_sync/2KB` | 30.40 µs | ±204 ns |
| `signing/ed25519/sign_sync/4KB` | 38.20 µs | ±305 ns |
| `signing/ed25519/sign_sync/500B` | 24.23 µs | ±136 ns |
| `signing/ed25519/sign_sync/8KB` | 54.33 µs | ±610 ns |
| `signing/hmac/sign_sync/100B` | 292 ns | ±2 ns |
| `signing/hmac/sign_sync/1KB` | 903 ns | ±8 ns |
| `signing/hmac/sign_sync/2KB` | 1.62 µs | ±12 ns |
| `signing/hmac/sign_sync/4KB` | 2.96 µs | ±29 ns |
| `signing/hmac/sign_sync/500B` | 548 ns | ±4 ns |
| `signing/hmac/sign_sync/8KB` | 5.73 µs | ±50 ns |
| `signing/sha256-digest/sign_sync/100B` | 113 ns | ±0 ns |
| `signing/sha256-digest/sign_sync/1KB` | 720 ns | ±6 ns |
| `signing/sha256-digest/sign_sync/2KB` | 1.41 µs | ±15 ns |
| `signing/sha256-digest/sign_sync/4KB` | 2.76 µs | ±25 ns |
| `signing/sha256-digest/sign_sync/500B` | 370 ns | ±3 ns |
| `signing/sha256-digest/sign_sync/8KB` | 5.50 µs | ±43 ns |
| | | |
| `validation/cert_missing` | 211 ns | ±1 ns |
| `validation/schema_mismatch` | 158 ns | ±1 ns |
| `validation/single_hop` | 46.22 µs | ±359 ns |
| | | |
| `validation_stage/cert_via_anchor` | 48.59 µs | ±324 ns |
| `validation_stage/disabled` | 744 ns | ±6 ns |
| | | |
| `verification/blake3-keyed/verify/100B` | 321 ns | ±2 ns |
| `verification/blake3-keyed/verify/1KB` | 1.41 µs | ±13 ns |
| `verification/blake3-keyed/verify/2KB` | 2.73 µs | ±19 ns |
| `verification/blake3-keyed/verify/4KB` | 3.96 µs | ±24 ns |
| `verification/blake3-keyed/verify/500B` | 788 ns | ±7 ns |
| `verification/blake3-keyed/verify/8KB` | 5.32 µs | ±38 ns |
| `verification/blake3-plain/verify/100B` | 328 ns | ±2 ns |
| `verification/blake3-plain/verify/1KB` | 1.43 µs | ±12 ns |
| `verification/blake3-plain/verify/2KB` | 2.71 µs | ±20 ns |
| `verification/blake3-plain/verify/4KB` | 3.93 µs | ±32 ns |
| `verification/blake3-plain/verify/500B` | 799 ns | ±6 ns |
| `verification/blake3-plain/verify/8KB` | 5.29 µs | ±49 ns |
| `verification/ed25519-batch/1` | 58.58 µs | ±408 ns |
| `verification/ed25519-batch/10` | 271.64 µs | ±2.58 µs |
| `verification/ed25519-batch/100` | 2.64 ms | ±44.95 µs |
| `verification/ed25519-batch/1000` | 21.25 ms | ±166.76 µs |
| `verification/ed25519-per-sig-loop/1` | 46.34 µs | ±281 ns |
| `verification/ed25519-per-sig-loop/10` | 459.99 µs | ±3.14 µs |
| `verification/ed25519-per-sig-loop/100` | 4.66 ms | ±38.76 µs |
| `verification/ed25519-per-sig-loop/1000` | 46.89 ms | ±363.00 µs |
| `verification/ed25519/verify/100B` | 46.44 µs | ±422 ns |
| `verification/ed25519/verify/1KB` | 49.02 µs | ±328 ns |
| `verification/ed25519/verify/2KB` | 50.30 µs | ±362 ns |
| `verification/ed25519/verify/4KB` | 54.59 µs | ±439 ns |
| `verification/ed25519/verify/500B` | 47.82 µs | ±494 ns |
| `verification/ed25519/verify/8KB` | 64.27 µs | ±429 ns |
| `verification/sha256-digest/verify/100B` | 113 ns | ±1 ns |
| `verification/sha256-digest/verify/1KB` | 724 ns | ±5 ns |
| `verification/sha256-digest/verify/2KB` | 1.41 µs | ±11 ns |
| `verification/sha256-digest/verify/4KB` | 2.75 µs | ±29 ns |
| `verification/sha256-digest/verify/500B` | 369 ns | ±3 ns |
| `verification/sha256-digest/verify/8KB` | 5.48 µs | ±46 ns |
<!-- BENCH_RESULTS_END -->
