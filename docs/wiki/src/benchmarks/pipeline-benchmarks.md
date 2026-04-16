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
| `cs/hit` | 698 ns | ±2 ns |
| `cs/miss` | 495 ns | ±1 ns |
| | | |
| `cs_insert/insert_new` | 6.30 µs | ±11.27 µs |
| `cs_insert/insert_replace` | 896 ns | ±4 ns |
| | | |
| `data_pipeline/4` | 1.84 µs | ±24 ns |
| `data_pipeline/8` | 2.18 µs | ±29 ns |
| | | |
| `decode/data/4` | 490 ns | ±3 ns |
| `decode/data/8` | 637 ns | ±2 ns |
| `decode/interest/4` | 561 ns | ±1 ns |
| `decode/interest/8` | 704 ns | ±4 ns |
| | | |
| `decode_throughput/4` | 556.54 µs | ±9.46 µs |
| `decode_throughput/8` | 699.74 µs | ±7.07 µs |
| | | |
| `fib/lpm/10` | 26 ns | ±0 ns |
| `fib/lpm/100` | 73 ns | ±1 ns |
| `fib/lpm/1000` | 73 ns | ±0 ns |
| | | |
| `interest_pipeline/cs_hit` | 1.05 µs | ±13 ns |
| `interest_pipeline/no_route/4` | 1.39 µs | ±22 ns |
| `interest_pipeline/no_route/8` | 1.52 µs | ±15 ns |
| | | |
| `large/blake3-rayon/hash/1MB` | 80.22 µs | ±631 ns |
| `large/blake3-rayon/hash/256KB` | 25.76 µs | ±788 ns |
| `large/blake3-rayon/hash/4MB` | 297.13 µs | ±3.98 µs |
| `large/blake3-single/hash/1MB` | 161.31 µs | ±1.75 µs |
| `large/blake3-single/hash/256KB` | 39.93 µs | ±238 ns |
| `large/blake3-single/hash/4MB` | 648.30 µs | ±7.12 µs |
| `large/sha256/hash/1MB` | 581.80 µs | ±402 ns |
| `large/sha256/hash/256KB` | 145.22 µs | ±92 ns |
| `large/sha256/hash/4MB` | 2.33 ms | ±1.42 µs |
| | | |
| `lru/evict` | 156 ns | ±1 ns |
| `lru/evict_prefix` | 1.64 µs | ±1.34 µs |
| `lru/get_can_be_prefix` | 248 ns | ±1 ns |
| `lru/get_hit` | 170 ns | ±0 ns |
| `lru/get_miss_empty` | 116 ns | ±0 ns |
| `lru/get_miss_populated` | 150 ns | ±0 ns |
| `lru/insert_new` | 2.08 µs | ±1.13 µs |
| `lru/insert_replace` | 281 ns | ±4 ns |
| | | |
| `name/display/components/4` | 363 ns | ±1 ns |
| `name/display/components/8` | 681 ns | ±1 ns |
| `name/eq/eq_match` | 32 ns | ±1 ns |
| `name/eq/eq_miss_first` | 1 ns | ±0 ns |
| `name/eq/eq_miss_last` | 30 ns | ±0 ns |
| `name/has_prefix/prefix_len/1` | 5 ns | ±0 ns |
| `name/has_prefix/prefix_len/4` | 15 ns | ±0 ns |
| `name/has_prefix/prefix_len/8` | 28 ns | ±0 ns |
| `name/hash/components/4` | 73 ns | ±0 ns |
| `name/hash/components/8` | 127 ns | ±0 ns |
| `name/parse/components/12` | 483 ns | ±10 ns |
| `name/parse/components/4` | 180 ns | ±4 ns |
| `name/parse/components/8` | 316 ns | ±1 ns |
| `name/tlv_decode/components/12` | 256 ns | ±3 ns |
| `name/tlv_decode/components/4` | 118 ns | ±1 ns |
| `name/tlv_decode/components/8` | 179 ns | ±1 ns |
| | | |
| `pit/aggregate` | 2.05 µs | ±141 ns |
| `pit/new_entry` | 1.12 µs | ±3 ns |
| | | |
| `pit_match/hit` | 1.53 µs | ±2 ns |
| `pit_match/miss` | 1.07 µs | ±2 ns |
| | | |
| `sharded/get_hit/1` | 191 ns | ±0 ns |
| `sharded/get_hit/16` | 191 ns | ±1 ns |
| `sharded/get_hit/4` | 191 ns | ±1 ns |
| `sharded/get_hit/8` | 191 ns | ±0 ns |
| `sharded/insert/1` | 2.54 µs | ±1.26 µs |
| `sharded/insert/16` | 1.67 µs | ±1.61 µs |
| `sharded/insert/4` | 2.62 µs | ±1.44 µs |
| `sharded/insert/8` | 1.90 µs | ±1.55 µs |
| | | |
| `signing/blake3-keyed/sign_sync/100B` | 168 ns | ±1 ns |
| `signing/blake3-keyed/sign_sync/1KB` | 1.07 µs | ±2 ns |
| `signing/blake3-keyed/sign_sync/2KB` | 2.14 µs | ±2 ns |
| `signing/blake3-keyed/sign_sync/4KB` | 3.15 µs | ±3 ns |
| `signing/blake3-keyed/sign_sync/500B` | 555 ns | ±0 ns |
| `signing/blake3-keyed/sign_sync/8KB` | 4.35 µs | ±98 ns |
| `signing/blake3-plain/sign_sync/100B` | 184 ns | ±0 ns |
| `signing/blake3-plain/sign_sync/1KB` | 1.09 µs | ±1 ns |
| `signing/blake3-plain/sign_sync/2KB` | 2.14 µs | ±1 ns |
| `signing/blake3-plain/sign_sync/4KB` | 3.15 µs | ±3 ns |
| `signing/blake3-plain/sign_sync/500B` | 570 ns | ±0 ns |
| `signing/blake3-plain/sign_sync/8KB` | 4.35 µs | ±30 ns |
| `signing/ed25519/sign_sync/100B` | 18.01 µs | ±53 ns |
| `signing/ed25519/sign_sync/1KB` | 20.97 µs | ±79 ns |
| `signing/ed25519/sign_sync/2KB` | 24.33 µs | ±59 ns |
| `signing/ed25519/sign_sync/4KB` | 30.56 µs | ±110 ns |
| `signing/ed25519/sign_sync/500B` | 19.30 µs | ±27 ns |
| `signing/ed25519/sign_sync/8KB` | 43.73 µs | ±88 ns |
| `signing/hmac/sign_sync/100B` | 242 ns | ±0 ns |
| `signing/hmac/sign_sync/1KB` | 739 ns | ±0 ns |
| `signing/hmac/sign_sync/2KB` | 1.31 µs | ±6 ns |
| `signing/hmac/sign_sync/4KB` | 2.41 µs | ±1 ns |
| `signing/hmac/sign_sync/500B` | 456 ns | ±3 ns |
| `signing/hmac/sign_sync/8KB` | 4.62 µs | ±2 ns |
| `signing/sha256-digest/sign_sync/100B` | 96 ns | ±0 ns |
| `signing/sha256-digest/sign_sync/1KB` | 580 ns | ±0 ns |
| `signing/sha256-digest/sign_sync/2KB` | 1.14 µs | ±14 ns |
| `signing/sha256-digest/sign_sync/4KB` | 2.24 µs | ±1 ns |
| `signing/sha256-digest/sign_sync/500B` | 299 ns | ±1 ns |
| `signing/sha256-digest/sign_sync/8KB` | 4.48 µs | ±2 ns |
| | | |
| `validation/cert_missing` | 165 ns | ±6 ns |
| `validation/schema_mismatch` | 123 ns | ±0 ns |
| `validation/single_hop` | 35.12 µs | ±127 ns |
| | | |
| `validation_stage/cert_via_anchor` | 36.03 µs | ±82 ns |
| `validation_stage/disabled` | 598 ns | ±1 ns |
| | | |
| `verification/blake3-keyed/verify/100B` | 267 ns | ±0 ns |
| `verification/blake3-keyed/verify/1KB` | 1.17 µs | ±6 ns |
| `verification/blake3-keyed/verify/2KB` | 2.24 µs | ±8 ns |
| `verification/blake3-keyed/verify/4KB` | 3.24 µs | ±2 ns |
| `verification/blake3-keyed/verify/500B` | 652 ns | ±1 ns |
| `verification/blake3-keyed/verify/8KB` | 4.45 µs | ±75 ns |
| `verification/blake3-plain/verify/100B` | 272 ns | ±0 ns |
| `verification/blake3-plain/verify/1KB` | 1.18 µs | ±3 ns |
| `verification/blake3-plain/verify/2KB` | 2.23 µs | ±9 ns |
| `verification/blake3-plain/verify/4KB` | 3.23 µs | ±22 ns |
| `verification/blake3-plain/verify/500B` | 659 ns | ±0 ns |
| `verification/blake3-plain/verify/8KB` | 4.44 µs | ±28 ns |
| `verification/ed25519-batch/1` | 49.76 µs | ±74 ns |
| `verification/ed25519-batch/10` | 220.64 µs | ±1.17 µs |
| `verification/ed25519-batch/100` | 2.20 ms | ±61.62 µs |
| `verification/ed25519-batch/1000` | 17.31 ms | ±33.74 µs |
| `verification/ed25519-per-sig-loop/1` | 34.88 µs | ±78 ns |
| `verification/ed25519-per-sig-loop/10` | 347.00 µs | ±1.17 µs |
| `verification/ed25519-per-sig-loop/100` | 3.47 ms | ±86.29 µs |
| `verification/ed25519-per-sig-loop/1000` | 35.77 ms | ±375.47 µs |
| `verification/ed25519/verify/100B` | 38.55 µs | ±210 ns |
| `verification/ed25519/verify/1KB` | 40.46 µs | ±69 ns |
| `verification/ed25519/verify/2KB` | 41.95 µs | ±46 ns |
| `verification/ed25519/verify/4KB` | 45.14 µs | ±80 ns |
| `verification/ed25519/verify/500B` | 39.69 µs | ±322 ns |
| `verification/ed25519/verify/8KB` | 52.62 µs | ±65 ns |
| `verification/sha256-digest/verify/100B` | 98 ns | ±0 ns |
| `verification/sha256-digest/verify/1KB` | 590 ns | ±2 ns |
| `verification/sha256-digest/verify/2KB` | 1.15 µs | ±1 ns |
| `verification/sha256-digest/verify/4KB` | 2.25 µs | ±9 ns |
| `verification/sha256-digest/verify/500B` | 309 ns | ±0 ns |
| `verification/sha256-digest/verify/8KB` | 4.48 µs | ±24 ns |
<!-- BENCH_RESULTS_END -->
