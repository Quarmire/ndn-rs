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
| `cs/hit` | 702 ns | ±2 ns |
| `cs/miss` | 507 ns | ±1 ns |
| | | |
| `cs_insert/insert_new` | 6.62 µs | ±11.47 µs |
| `cs_insert/insert_replace` | 917 ns | ±2 ns |
| | | |
| `data_pipeline/4` | 1.87 µs | ±47 ns |
| `data_pipeline/8` | 2.23 µs | ±27 ns |
| | | |
| `decode/data/4` | 469 ns | ±3 ns |
| `decode/data/8` | 632 ns | ±1 ns |
| `decode/interest/4` | 545 ns | ±6 ns |
| `decode/interest/8` | 699 ns | ±1 ns |
| | | |
| `decode_throughput/4` | 540.90 µs | ±1.20 µs |
| `decode_throughput/8` | 696.71 µs | ±8.11 µs |
| | | |
| `fib/lpm/10` | 26 ns | ±0 ns |
| `fib/lpm/100` | 72 ns | ±0 ns |
| `fib/lpm/1000` | 74 ns | ±0 ns |
| | | |
| `interest_pipeline/cs_hit` | 1.04 µs | ±1 ns |
| `interest_pipeline/no_route/4` | 1.36 µs | ±4 ns |
| `interest_pipeline/no_route/8` | 1.52 µs | ±6 ns |
| | | |
| `large/blake3-rayon/hash/1MB` | 80.10 µs | ±820 ns |
| `large/blake3-rayon/hash/256KB` | 25.80 µs | ±397 ns |
| `large/blake3-rayon/hash/4MB` | 299.45 µs | ±2.34 µs |
| `large/blake3-single/hash/1MB` | 160.74 µs | ±207 ns |
| `large/blake3-single/hash/256KB` | 39.80 µs | ±45 ns |
| `large/blake3-single/hash/4MB` | 648.18 µs | ±992 ns |
| `large/sha256/hash/1MB` | 581.87 µs | ±739 ns |
| `large/sha256/hash/256KB` | 145.21 µs | ±5.25 µs |
| `large/sha256/hash/4MB` | 2.33 ms | ±1.15 µs |
| | | |
| `lru/evict` | 156 ns | ±3 ns |
| `lru/evict_prefix` | 1.65 µs | ±1.27 µs |
| `lru/get_can_be_prefix` | 244 ns | ±3 ns |
| `lru/get_hit` | 170 ns | ±1 ns |
| `lru/get_miss_empty` | 114 ns | ±0 ns |
| `lru/get_miss_populated` | 148 ns | ±0 ns |
| `lru/insert_new` | 2.24 µs | ±1.36 µs |
| `lru/insert_replace` | 279 ns | ±2 ns |
| | | |
| `name/display/components/4` | 341 ns | ±0 ns |
| `name/display/components/8` | 639 ns | ±0 ns |
| `name/eq/eq_match` | 32 ns | ±0 ns |
| `name/eq/eq_miss_first` | 1 ns | ±0 ns |
| `name/eq/eq_miss_last` | 30 ns | ±0 ns |
| `name/has_prefix/prefix_len/1` | 5 ns | ±0 ns |
| `name/has_prefix/prefix_len/4` | 15 ns | ±0 ns |
| `name/has_prefix/prefix_len/8` | 28 ns | ±0 ns |
| `name/hash/components/4` | 73 ns | ±0 ns |
| `name/hash/components/8` | 127 ns | ±0 ns |
| `name/parse/components/12` | 477 ns | ±2 ns |
| `name/parse/components/4` | 180 ns | ±5 ns |
| `name/parse/components/8` | 312 ns | ±1 ns |
| `name/tlv_decode/components/12` | 248 ns | ±16 ns |
| `name/tlv_decode/components/4` | 113 ns | ±0 ns |
| `name/tlv_decode/components/8` | 174 ns | ±2 ns |
| | | |
| `pit/aggregate` | 2.04 µs | ±159 ns |
| `pit/new_entry` | 1.12 µs | ±2 ns |
| | | |
| `pit_match/hit` | 1.55 µs | ±15 ns |
| `pit_match/miss` | 1.06 µs | ±2 ns |
| | | |
| `sharded/get_hit/1` | 193 ns | ±1 ns |
| `sharded/get_hit/16` | 193 ns | ±1 ns |
| `sharded/get_hit/4` | 191 ns | ±0 ns |
| `sharded/get_hit/8` | 191 ns | ±3 ns |
| `sharded/insert/1` | 2.71 µs | ±1.35 µs |
| `sharded/insert/16` | 1.66 µs | ±1.69 µs |
| `sharded/insert/4` | 2.68 µs | ±1.50 µs |
| `sharded/insert/8` | 2.34 µs | ±1.69 µs |
| | | |
| `signing/blake3-keyed/sign_sync/100B` | 168 ns | ±0 ns |
| `signing/blake3-keyed/sign_sync/1KB` | 1.09 µs | ±0 ns |
| `signing/blake3-keyed/sign_sync/2KB` | 2.14 µs | ±4 ns |
| `signing/blake3-keyed/sign_sync/4KB` | 3.15 µs | ±1 ns |
| `signing/blake3-keyed/sign_sync/500B` | 554 ns | ±0 ns |
| `signing/blake3-keyed/sign_sync/8KB` | 4.35 µs | ±3 ns |
| `signing/blake3-plain/sign_sync/100B` | 181 ns | ±0 ns |
| `signing/blake3-plain/sign_sync/1KB` | 1.08 µs | ±0 ns |
| `signing/blake3-plain/sign_sync/2KB` | 2.14 µs | ±1 ns |
| `signing/blake3-plain/sign_sync/4KB` | 3.15 µs | ±17 ns |
| `signing/blake3-plain/sign_sync/500B` | 568 ns | ±23 ns |
| `signing/blake3-plain/sign_sync/8KB` | 4.35 µs | ±2 ns |
| `signing/ed25519/sign_sync/100B` | 17.98 µs | ±68 ns |
| `signing/ed25519/sign_sync/1KB` | 20.93 µs | ±128 ns |
| `signing/ed25519/sign_sync/2KB` | 24.29 µs | ±45 ns |
| `signing/ed25519/sign_sync/4KB` | 30.53 µs | ±654 ns |
| `signing/ed25519/sign_sync/500B` | 19.25 µs | ±359 ns |
| `signing/ed25519/sign_sync/8KB` | 43.70 µs | ±816 ns |
| `signing/hmac/sign_sync/100B` | 243 ns | ±0 ns |
| `signing/hmac/sign_sync/1KB` | 739 ns | ±0 ns |
| `signing/hmac/sign_sync/2KB` | 1.31 µs | ±1 ns |
| `signing/hmac/sign_sync/4KB` | 2.41 µs | ±1 ns |
| `signing/hmac/sign_sync/500B` | 455 ns | ±0 ns |
| `signing/hmac/sign_sync/8KB` | 4.61 µs | ±3 ns |
| `signing/sha256-digest/sign_sync/100B` | 97 ns | ±1 ns |
| `signing/sha256-digest/sign_sync/1KB` | 584 ns | ±0 ns |
| `signing/sha256-digest/sign_sync/2KB` | 1.14 µs | ±0 ns |
| `signing/sha256-digest/sign_sync/4KB` | 2.24 µs | ±2 ns |
| `signing/sha256-digest/sign_sync/500B` | 298 ns | ±0 ns |
| `signing/sha256-digest/sign_sync/8KB` | 4.48 µs | ±4 ns |
| | | |
| `validation/cert_missing` | 165 ns | ±8 ns |
| `validation/schema_mismatch` | 123 ns | ±0 ns |
| `validation/single_hop` | 35.19 µs | ±67 ns |
| | | |
| `validation_stage/cert_via_anchor` | 36.09 µs | ±169 ns |
| `validation_stage/disabled` | 638 ns | ±5 ns |
| | | |
| `verification/blake3-keyed/verify/100B` | 270 ns | ±0 ns |
| `verification/blake3-keyed/verify/1KB` | 1.17 µs | ±1 ns |
| `verification/blake3-keyed/verify/2KB` | 2.24 µs | ±2 ns |
| `verification/blake3-keyed/verify/4KB` | 3.25 µs | ±3 ns |
| `verification/blake3-keyed/verify/500B` | 654 ns | ±1 ns |
| `verification/blake3-keyed/verify/8KB` | 4.45 µs | ±4 ns |
| `verification/blake3-plain/verify/100B` | 275 ns | ±0 ns |
| `verification/blake3-plain/verify/1KB` | 1.18 µs | ±1 ns |
| `verification/blake3-plain/verify/2KB` | 2.24 µs | ±1 ns |
| `verification/blake3-plain/verify/4KB` | 3.25 µs | ±2 ns |
| `verification/blake3-plain/verify/500B` | 662 ns | ±1 ns |
| `verification/blake3-plain/verify/8KB` | 4.45 µs | ±4 ns |
| `verification/ed25519-batch/1` | 44.14 µs | ±124 ns |
| `verification/ed25519-batch/10` | 207.51 µs | ±3.06 µs |
| `verification/ed25519-batch/100` | 1.87 ms | ±2.55 µs |
| `verification/ed25519-batch/1000` | 15.50 ms | ±33.81 µs |
| `verification/ed25519-per-sig-loop/1` | 34.71 µs | ±68 ns |
| `verification/ed25519-per-sig-loop/10` | 345.59 µs | ±4.14 µs |
| `verification/ed25519-per-sig-loop/100` | 3.46 ms | ±8.33 µs |
| `verification/ed25519-per-sig-loop/1000` | 35.65 ms | ±26.52 µs |
| `verification/ed25519/verify/100B` | 34.69 µs | ±78 ns |
| `verification/ed25519/verify/1KB` | 36.45 µs | ±610 ns |
| `verification/ed25519/verify/2KB` | 38.01 µs | ±70 ns |
| `verification/ed25519/verify/4KB` | 41.26 µs | ±62 ns |
| `verification/ed25519/verify/500B` | 35.71 µs | ±80 ns |
| `verification/ed25519/verify/8KB` | 48.51 µs | ±70 ns |
| `verification/sha256-digest/verify/100B` | 97 ns | ±0 ns |
| `verification/sha256-digest/verify/1KB` | 592 ns | ±0 ns |
| `verification/sha256-digest/verify/2KB` | 1.16 µs | ±0 ns |
| `verification/sha256-digest/verify/4KB` | 2.25 µs | ±36 ns |
| `verification/sha256-digest/verify/500B` | 311 ns | ±0 ns |
| `verification/sha256-digest/verify/8KB` | 4.48 µs | ±2 ns |
<!-- BENCH_RESULTS_END -->
