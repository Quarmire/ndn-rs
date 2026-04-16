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
| `cs/hit` | 736 ns | ±36 ns |
| `cs/miss` | 547 ns | ±12 ns |
| | | |
| `cs_insert/insert_new` | 9.08 µs | ±16.34 µs |
| `cs_insert/insert_replace` | 930 ns | ±22 ns |
| | | |
| `data_pipeline/4` | 1.76 µs | ±43 ns |
| `data_pipeline/8` | 2.15 µs | ±52 ns |
| | | |
| `decode/data/4` | 407 ns | ±7 ns |
| `decode/data/8` | 455 ns | ±14 ns |
| `decode/interest/4` | 451 ns | ±13 ns |
| `decode/interest/8` | 512 ns | ±13 ns |
| | | |
| `decode_throughput/4` | 415.33 µs | ±6.92 µs |
| `decode_throughput/8` | 490.90 µs | ±4.73 µs |
| | | |
| `fib/lpm/10` | 34 ns | ±1 ns |
| `fib/lpm/100` | 91 ns | ±2 ns |
| `fib/lpm/1000` | 91 ns | ±2 ns |
| | | |
| `interest_pipeline/cs_hit` | 849 ns | ±10 ns |
| `interest_pipeline/no_route/4` | 1.29 µs | ±14 ns |
| `interest_pipeline/no_route/8` | 1.44 µs | ±20 ns |
| | | |
| `large/blake3-rayon/hash/1MB` | 111.36 µs | ±3.07 µs |
| `large/blake3-rayon/hash/256KB` | 35.73 µs | ±1.46 µs |
| `large/blake3-rayon/hash/4MB` | 412.32 µs | ±9.31 µs |
| `large/blake3-single/hash/1MB` | 233.71 µs | ±3.77 µs |
| `large/blake3-single/hash/256KB` | 56.90 µs | ±664 ns |
| `large/blake3-single/hash/4MB` | 927.87 µs | ±15.18 µs |
| `large/sha256/hash/1MB` | 610.87 µs | ±8.12 µs |
| `large/sha256/hash/256KB` | 152.39 µs | ±2.20 µs |
| `large/sha256/hash/4MB` | 2.45 ms | ±33.56 µs |
| | | |
| `lru/evict` | 178 ns | ±3 ns |
| `lru/evict_prefix` | 1.90 µs | ±2.13 µs |
| `lru/get_can_be_prefix` | 279 ns | ±8 ns |
| `lru/get_hit` | 191 ns | ±4 ns |
| `lru/get_miss_empty` | 134 ns | ±4 ns |
| `lru/get_miss_populated` | 173 ns | ±5 ns |
| `lru/insert_new` | 1.82 µs | ±1.36 µs |
| `lru/insert_replace` | 369 ns | ±9 ns |
| | | |
| `name/display/components/4` | 435 ns | ±13 ns |
| `name/display/components/8` | 830 ns | ±23 ns |
| `name/eq/eq_match` | 34 ns | ±2 ns |
| `name/eq/eq_miss_first` | 2 ns | ±0 ns |
| `name/eq/eq_miss_last` | 34 ns | ±0 ns |
| `name/has_prefix/prefix_len/1` | 6 ns | ±0 ns |
| `name/has_prefix/prefix_len/4` | 18 ns | ±0 ns |
| `name/has_prefix/prefix_len/8` | 41 ns | ±3 ns |
| `name/hash/components/4` | 82 ns | ±2 ns |
| `name/hash/components/8` | 155 ns | ±4 ns |
| `name/parse/components/12` | 631 ns | ±16 ns |
| `name/parse/components/4` | 217 ns | ±3 ns |
| `name/parse/components/8` | 434 ns | ±8 ns |
| `name/tlv_decode/components/12` | 289 ns | ±8 ns |
| `name/tlv_decode/components/4` | 135 ns | ±4 ns |
| `name/tlv_decode/components/8` | 203 ns | ±5 ns |
| | | |
| `pit/aggregate` | 2.25 µs | ±208 ns |
| `pit/new_entry` | 1.19 µs | ±30 ns |
| | | |
| `pit_match/hit` | 1.52 µs | ±42 ns |
| `pit_match/miss` | 1.76 µs | ±25 ns |
| | | |
| `sharded/get_hit/1` | 214 ns | ±5 ns |
| `sharded/get_hit/16` | 208 ns | ±2 ns |
| `sharded/get_hit/4` | 219 ns | ±5 ns |
| `sharded/get_hit/8` | 210 ns | ±3 ns |
| `sharded/insert/1` | 2.44 µs | ±1.62 µs |
| `sharded/insert/16` | 1.68 µs | ±1.41 µs |
| `sharded/insert/4` | 2.25 µs | ±1.61 µs |
| `sharded/insert/8` | 1.75 µs | ±1.43 µs |
| | | |
| `signing/blake3-keyed/sign_sync/100B` | 170 ns | ±1 ns |
| `signing/blake3-keyed/sign_sync/1KB` | 1.11 µs | ±13 ns |
| `signing/blake3-keyed/sign_sync/2KB` | 2.23 µs | ±50 ns |
| `signing/blake3-keyed/sign_sync/4KB` | 3.27 µs | ±30 ns |
| `signing/blake3-keyed/sign_sync/500B` | 575 ns | ±8 ns |
| `signing/blake3-keyed/sign_sync/8KB` | 4.46 µs | ±70 ns |
| `signing/blake3-plain/sign_sync/100B` | 175 ns | ±3 ns |
| `signing/blake3-plain/sign_sync/1KB` | 1.12 µs | ±14 ns |
| `signing/blake3-plain/sign_sync/2KB` | 2.23 µs | ±29 ns |
| `signing/blake3-plain/sign_sync/4KB` | 3.30 µs | ±59 ns |
| `signing/blake3-plain/sign_sync/500B` | 577 ns | ±13 ns |
| `signing/blake3-plain/sign_sync/8KB` | 4.44 µs | ±54 ns |
| `signing/ed25519/sign_sync/100B` | 19.22 µs | ±242 ns |
| `signing/ed25519/sign_sync/1KB` | 22.36 µs | ±263 ns |
| `signing/ed25519/sign_sync/2KB` | 26.01 µs | ±474 ns |
| `signing/ed25519/sign_sync/4KB` | 32.57 µs | ±539 ns |
| `signing/ed25519/sign_sync/500B` | 20.59 µs | ±256 ns |
| `signing/ed25519/sign_sync/8KB` | 46.63 µs | ±593 ns |
| `signing/hmac/sign_sync/100B` | 251 ns | ±3 ns |
| `signing/hmac/sign_sync/1KB` | 770 ns | ±12 ns |
| `signing/hmac/sign_sync/2KB` | 1.38 µs | ±16 ns |
| `signing/hmac/sign_sync/4KB` | 2.53 µs | ±27 ns |
| `signing/hmac/sign_sync/500B` | 470 ns | ±6 ns |
| `signing/hmac/sign_sync/8KB` | 4.88 µs | ±79 ns |
| `signing/sha256-digest/sign_sync/100B` | 96 ns | ±1 ns |
| `signing/sha256-digest/sign_sync/1KB` | 624 ns | ±10 ns |
| `signing/sha256-digest/sign_sync/2KB` | 1.21 µs | ±17 ns |
| `signing/sha256-digest/sign_sync/4KB` | 2.36 µs | ±40 ns |
| `signing/sha256-digest/sign_sync/500B` | 316 ns | ±7 ns |
| `signing/sha256-digest/sign_sync/8KB` | 4.70 µs | ±79 ns |
| | | |
| `validation/cert_missing` | 181 ns | ±2 ns |
| `validation/schema_mismatch` | 136 ns | ±1 ns |
| `validation/single_hop` | 39.47 µs | ±466 ns |
| | | |
| `validation_stage/cert_via_anchor` | 45.20 µs | ±725 ns |
| `validation_stage/disabled` | 577 ns | ±17 ns |
| | | |
| `verification/blake3-keyed/verify/100B` | 283 ns | ±6 ns |
| `verification/blake3-keyed/verify/1KB` | 1.22 µs | ±14 ns |
| `verification/blake3-keyed/verify/2KB` | 2.33 µs | ±26 ns |
| `verification/blake3-keyed/verify/4KB` | 3.38 µs | ±40 ns |
| `verification/blake3-keyed/verify/500B` | 685 ns | ±11 ns |
| `verification/blake3-keyed/verify/8KB` | 4.55 µs | ±56 ns |
| `verification/blake3-plain/verify/100B` | 284 ns | ±4 ns |
| `verification/blake3-plain/verify/1KB` | 1.23 µs | ±15 ns |
| `verification/blake3-plain/verify/2KB` | 2.33 µs | ±32 ns |
| `verification/blake3-plain/verify/4KB` | 3.38 µs | ±39 ns |
| `verification/blake3-plain/verify/500B` | 687 ns | ±8 ns |
| `verification/blake3-plain/verify/8KB` | 4.58 µs | ±59 ns |
| `verification/ed25519-batch/1` | 53.03 µs | ±1.13 µs |
| `verification/ed25519-batch/10` | 237.27 µs | ±3.49 µs |
| `verification/ed25519-batch/100` | 2.19 ms | ±60.28 µs |
| `verification/ed25519-batch/1000` | 18.40 ms | ±391.35 µs |
| `verification/ed25519-per-sig-loop/1` | 39.53 µs | ±573 ns |
| `verification/ed25519-per-sig-loop/10` | 393.53 µs | ±5.16 µs |
| `verification/ed25519-per-sig-loop/100` | 4.01 ms | ±65.45 µs |
| `verification/ed25519-per-sig-loop/1000` | 40.69 ms | ±1.74 ms |
| `verification/ed25519/verify/100B` | 45.96 µs | ±760 ns |
| `verification/ed25519/verify/1KB` | 47.75 µs | ±1.42 µs |
| `verification/ed25519/verify/2KB` | 49.20 µs | ±620 ns |
| `verification/ed25519/verify/4KB` | 52.63 µs | ±822 ns |
| `verification/ed25519/verify/500B` | 46.81 µs | ±676 ns |
| `verification/ed25519/verify/8KB` | 60.66 µs | ±1.03 µs |
| `verification/sha256-digest/verify/100B` | 96 ns | ±1 ns |
| `verification/sha256-digest/verify/1KB` | 621 ns | ±17 ns |
| `verification/sha256-digest/verify/2KB` | 1.21 µs | ±17 ns |
| `verification/sha256-digest/verify/4KB` | 2.37 µs | ±39 ns |
| `verification/sha256-digest/verify/500B` | 317 ns | ±5 ns |
| `verification/sha256-digest/verify/8KB` | 4.74 µs | ±82 ns |
<!-- BENCH_RESULTS_END -->
