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
| `cs/hit` | 844 ns | ±3 ns |
| `cs/miss` | 590 ns | ±2 ns |
| | | |
| `cs_insert/insert_new` | 7.71 µs | ±12.67 µs |
| `cs_insert/insert_replace` | 1.07 µs | ±3 ns |
| | | |
| `data_pipeline/4` | 2.31 µs | ±35 ns |
| `data_pipeline/8` | 2.78 µs | ±37 ns |
| | | |
| `decode/data/4` | 605 ns | ±1 ns |
| `decode/data/8` | 813 ns | ±1 ns |
| `decode/interest/4` | 682 ns | ±10 ns |
| `decode/interest/8` | 867 ns | ±3 ns |
| | | |
| `decode_throughput/4` | 686.28 µs | ±1.11 µs |
| `decode_throughput/8` | 874.40 µs | ±1.67 µs |
| | | |
| `fib/lpm/10` | 33 ns | ±0 ns |
| `fib/lpm/100` | 96 ns | ±0 ns |
| `fib/lpm/1000` | 94 ns | ±0 ns |
| | | |
| `interest_pipeline/cs_hit` | 1.26 µs | ±2 ns |
| `interest_pipeline/no_route/4` | 1.71 µs | ±8 ns |
| `interest_pipeline/no_route/8` | 1.89 µs | ±9 ns |
| | | |
| `large/blake3-rayon/hash/1MB` | 128.55 µs | ±1.09 µs |
| `large/blake3-rayon/hash/256KB` | 40.06 µs | ±281 ns |
| `large/blake3-rayon/hash/4MB` | 485.14 µs | ±8.12 µs |
| `large/blake3-single/hash/1MB` | 300.89 µs | ±334 ns |
| `large/blake3-single/hash/256KB` | 74.58 µs | ±58 ns |
| `large/blake3-single/hash/4MB` | 1.22 ms | ±1.84 µs |
| `large/sha256/hash/1MB` | 746.43 µs | ±580 ns |
| `large/sha256/hash/256KB` | 186.21 µs | ±134 ns |
| `large/sha256/hash/4MB` | 2.98 ms | ±3.38 µs |
| | | |
| `lru/evict` | 197 ns | ±2 ns |
| `lru/evict_prefix` | 2.17 µs | ±2.32 µs |
| `lru/get_can_be_prefix` | 316 ns | ±1 ns |
| `lru/get_hit` | 217 ns | ±0 ns |
| `lru/get_miss_empty` | 149 ns | ±0 ns |
| `lru/get_miss_populated` | 193 ns | ±0 ns |
| `lru/insert_new` | 2.18 µs | ±1.28 µs |
| `lru/insert_replace` | 358 ns | ±1 ns |
| | | |
| `name/display/components/4` | 440 ns | ±1 ns |
| `name/display/components/8` | 830 ns | ±2 ns |
| `name/eq/eq_match` | 38 ns | ±1 ns |
| `name/eq/eq_miss_first` | 2 ns | ±0 ns |
| `name/eq/eq_miss_last` | 38 ns | ±0 ns |
| `name/has_prefix/prefix_len/1` | 7 ns | ±0 ns |
| `name/has_prefix/prefix_len/4` | 19 ns | ±0 ns |
| `name/has_prefix/prefix_len/8` | 40 ns | ±0 ns |
| `name/hash/components/4` | 94 ns | ±0 ns |
| `name/hash/components/8` | 164 ns | ±1 ns |
| `name/parse/components/12` | 613 ns | ±22 ns |
| `name/parse/components/4` | 231 ns | ±3 ns |
| `name/parse/components/8` | 412 ns | ±1 ns |
| `name/tlv_decode/components/12` | 322 ns | ±2 ns |
| `name/tlv_decode/components/4` | 139 ns | ±0 ns |
| `name/tlv_decode/components/8` | 219 ns | ±1 ns |
| | | |
| `pit/aggregate` | 2.55 µs | ±141 ns |
| `pit/new_entry` | 1.42 µs | ±10 ns |
| | | |
| `pit_match/hit` | 1.92 µs | ±3 ns |
| `pit_match/miss` | 1.33 µs | ±2 ns |
| | | |
| `sharded/get_hit/1` | 247 ns | ±0 ns |
| `sharded/get_hit/16` | 254 ns | ±1 ns |
| `sharded/get_hit/4` | 247 ns | ±0 ns |
| `sharded/get_hit/8` | 247 ns | ±0 ns |
| `sharded/insert/1` | 2.75 µs | ±1.41 µs |
| `sharded/insert/16` | 1.98 µs | ±1.91 µs |
| `sharded/insert/4` | 2.57 µs | ±1.60 µs |
| `sharded/insert/8` | 2.11 µs | ±1.69 µs |
| | | |
| `signing/blake3-keyed/sign_sync/100B` | 228 ns | ±1 ns |
| `signing/blake3-keyed/sign_sync/1KB` | 1.45 µs | ±1 ns |
| `signing/blake3-keyed/sign_sync/2KB` | 2.90 µs | ±2 ns |
| `signing/blake3-keyed/sign_sync/4KB` | 4.25 µs | ±3 ns |
| `signing/blake3-keyed/sign_sync/500B` | 747 ns | ±1 ns |
| `signing/blake3-keyed/sign_sync/8KB` | 5.84 µs | ±5 ns |
| `signing/blake3-plain/sign_sync/100B` | 245 ns | ±0 ns |
| `signing/blake3-plain/sign_sync/1KB` | 1.46 µs | ±1 ns |
| `signing/blake3-plain/sign_sync/2KB` | 2.89 µs | ±2 ns |
| `signing/blake3-plain/sign_sync/4KB` | 4.25 µs | ±3 ns |
| `signing/blake3-plain/sign_sync/500B` | 765 ns | ±0 ns |
| `signing/blake3-plain/sign_sync/8KB` | 5.84 µs | ±3 ns |
| `signing/ed25519/sign_sync/100B` | 23.19 µs | ±261 ns |
| `signing/ed25519/sign_sync/1KB` | 26.98 µs | ±49 ns |
| `signing/ed25519/sign_sync/2KB` | 31.33 µs | ±61 ns |
| `signing/ed25519/sign_sync/4KB` | 39.33 µs | ±95 ns |
| `signing/ed25519/sign_sync/500B` | 24.86 µs | ±67 ns |
| `signing/ed25519/sign_sync/8KB` | 56.32 µs | ±104 ns |
| `signing/hmac/sign_sync/100B` | 304 ns | ±0 ns |
| `signing/hmac/sign_sync/1KB` | 944 ns | ±0 ns |
| `signing/hmac/sign_sync/2KB` | 1.68 µs | ±1 ns |
| `signing/hmac/sign_sync/4KB` | 3.09 µs | ±6 ns |
| `signing/hmac/sign_sync/500B` | 578 ns | ±1 ns |
| `signing/hmac/sign_sync/8KB` | 5.95 µs | ±7 ns |
| `signing/sha256-digest/sign_sync/100B` | 127 ns | ±1 ns |
| `signing/sha256-digest/sign_sync/1KB` | 756 ns | ±2 ns |
| `signing/sha256-digest/sign_sync/2KB` | 1.47 µs | ±2 ns |
| `signing/sha256-digest/sign_sync/4KB` | 2.88 µs | ±2 ns |
| `signing/sha256-digest/sign_sync/500B` | 400 ns | ±1 ns |
| `signing/sha256-digest/sign_sync/8KB` | 5.73 µs | ±3 ns |
| | | |
| `validation/cert_missing` | 223 ns | ±0 ns |
| `validation/schema_mismatch` | 164 ns | ±1 ns |
| `validation/single_hop` | 45.27 µs | ±75 ns |
| | | |
| `validation_stage/cert_via_anchor` | 46.30 µs | ±80 ns |
| `validation_stage/disabled` | 743 ns | ±1 ns |
| | | |
| `verification/blake3-keyed/verify/100B` | 350 ns | ±0 ns |
| `verification/blake3-keyed/verify/1KB` | 1.57 µs | ±1 ns |
| `verification/blake3-keyed/verify/2KB` | 3.01 µs | ±2 ns |
| `verification/blake3-keyed/verify/4KB` | 4.37 µs | ±3 ns |
| `verification/blake3-keyed/verify/500B` | 871 ns | ±1 ns |
| `verification/blake3-keyed/verify/8KB` | 5.96 µs | ±4 ns |
| `verification/blake3-plain/verify/100B` | 360 ns | ±0 ns |
| `verification/blake3-plain/verify/1KB` | 1.58 µs | ±2 ns |
| `verification/blake3-plain/verify/2KB` | 3.01 µs | ±2 ns |
| `verification/blake3-plain/verify/4KB` | 4.36 µs | ±4 ns |
| `verification/blake3-plain/verify/500B` | 884 ns | ±1 ns |
| `verification/blake3-plain/verify/8KB` | 5.96 µs | ±5 ns |
| `verification/ed25519-batch/1` | 65.84 µs | ±126 ns |
| `verification/ed25519-batch/10` | 291.04 µs | ±422 ns |
| `verification/ed25519-batch/100` | 2.60 ms | ±2.86 µs |
| `verification/ed25519-batch/1000` | 21.09 ms | ±31.08 µs |
| `verification/ed25519-per-sig-loop/1` | 44.72 µs | ±76 ns |
| `verification/ed25519-per-sig-loop/10` | 445.34 µs | ±661 ns |
| `verification/ed25519-per-sig-loop/100` | 4.45 ms | ±5.72 µs |
| `verification/ed25519-per-sig-loop/1000` | 45.95 ms | ±53.44 µs |
| `verification/ed25519/verify/100B` | 45.53 µs | ±78 ns |
| `verification/ed25519/verify/1KB` | 47.91 µs | ±86 ns |
| `verification/ed25519/verify/2KB` | 49.74 µs | ±104 ns |
| `verification/ed25519/verify/4KB` | 54.11 µs | ±110 ns |
| `verification/ed25519/verify/500B` | 47.03 µs | ±184 ns |
| `verification/ed25519/verify/8KB` | 63.54 µs | ±84 ns |
| `verification/sha256-digest/verify/100B` | 129 ns | ±0 ns |
| `verification/sha256-digest/verify/1KB` | 771 ns | ±0 ns |
| `verification/sha256-digest/verify/2KB` | 1.48 µs | ±1 ns |
| `verification/sha256-digest/verify/4KB` | 2.89 µs | ±4 ns |
| `verification/sha256-digest/verify/500B` | 404 ns | ±0 ns |
| `verification/sha256-digest/verify/8KB` | 5.75 µs | ±4 ns |
<!-- BENCH_RESULTS_END -->
