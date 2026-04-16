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
| `cs/hit` | 770 ns | ±5 ns |
| `cs/miss` | 558 ns | ±1 ns |
| | | |
| `cs_insert/insert_new` | 10.39 µs | ±17.77 µs |
| `cs_insert/insert_replace` | 997 ns | ±8 ns |
| | | |
| `data_pipeline/4` | 1.97 µs | ±36 ns |
| `data_pipeline/8` | 2.37 µs | ±55 ns |
| | | |
| `decode/data/4` | 542 ns | ±3 ns |
| `decode/data/8` | 724 ns | ±4 ns |
| `decode/interest/4` | 583 ns | ±1 ns |
| `decode/interest/8` | 762 ns | ±2 ns |
| | | |
| `decode_throughput/4` | 579.91 µs | ±1.25 µs |
| `decode_throughput/8` | 753.69 µs | ±1.24 µs |
| | | |
| `fib/lpm/10` | 30 ns | ±0 ns |
| `fib/lpm/100` | 94 ns | ±0 ns |
| `fib/lpm/1000` | 94 ns | ±0 ns |
| | | |
| `interest_pipeline/cs_hit` | 1.12 µs | ±11 ns |
| `interest_pipeline/no_route/4` | 1.51 µs | ±10 ns |
| `interest_pipeline/no_route/8` | 1.68 µs | ±12 ns |
| | | |
| `large/blake3-rayon/hash/1MB` | 117.45 µs | ±1.64 µs |
| `large/blake3-rayon/hash/256KB` | 37.61 µs | ±825 ns |
| `large/blake3-rayon/hash/4MB` | 443.61 µs | ±18.82 µs |
| `large/blake3-single/hash/1MB` | 250.04 µs | ±554 ns |
| `large/blake3-single/hash/256KB` | 61.52 µs | ±148 ns |
| `large/blake3-single/hash/4MB` | 1.00 ms | ±2.80 µs |
| `large/sha256/hash/1MB` | 660.41 µs | ±503 ns |
| `large/sha256/hash/256KB` | 164.67 µs | ±2.84 µs |
| `large/sha256/hash/4MB` | 2.64 ms | ±124.31 µs |
| | | |
| `lru/evict` | 197 ns | ±1 ns |
| `lru/evict_prefix` | 1.98 µs | ±2.03 µs |
| `lru/get_can_be_prefix` | 294 ns | ±1 ns |
| `lru/get_hit` | 208 ns | ±2 ns |
| `lru/get_miss_empty` | 138 ns | ±0 ns |
| `lru/get_miss_populated` | 185 ns | ±3 ns |
| `lru/insert_new` | 2.10 µs | ±1.53 µs |
| `lru/insert_replace` | 373 ns | ±1 ns |
| | | |
| `name/display/components/4` | 454 ns | ±1 ns |
| `name/display/components/8` | 886 ns | ±84 ns |
| `name/eq/eq_match` | 31 ns | ±0 ns |
| `name/eq/eq_miss_first` | 1 ns | ±0 ns |
| `name/eq/eq_miss_last` | 24 ns | ±0 ns |
| `name/has_prefix/prefix_len/1` | 6 ns | ±0 ns |
| `name/has_prefix/prefix_len/4` | 16 ns | ±0 ns |
| `name/has_prefix/prefix_len/8` | 32 ns | ±0 ns |
| `name/hash/components/4` | 87 ns | ±0 ns |
| `name/hash/components/8` | 162 ns | ±1 ns |
| `name/parse/components/12` | 645 ns | ±4 ns |
| `name/parse/components/4` | 228 ns | ±2 ns |
| `name/parse/components/8` | 417 ns | ±2 ns |
| `name/tlv_decode/components/12` | 345 ns | ±1 ns |
| `name/tlv_decode/components/4` | 163 ns | ±0 ns |
| `name/tlv_decode/components/8` | 248 ns | ±0 ns |
| | | |
| `pit/aggregate` | 2.26 µs | ±132 ns |
| `pit/new_entry` | 1.30 µs | ±3 ns |
| | | |
| `pit_match/hit` | 1.66 µs | ±4 ns |
| `pit_match/miss` | 1.19 µs | ±3 ns |
| | | |
| `sharded/get_hit/1` | 225 ns | ±7 ns |
| `sharded/get_hit/16` | 225 ns | ±0 ns |
| `sharded/get_hit/4` | 224 ns | ±0 ns |
| `sharded/get_hit/8` | 224 ns | ±0 ns |
| `sharded/insert/1` | 2.59 µs | ±1.67 µs |
| `sharded/insert/16` | 1.88 µs | ±1.57 µs |
| `sharded/insert/4` | 2.65 µs | ±1.93 µs |
| `sharded/insert/8` | 2.19 µs | ±1.75 µs |
| | | |
| `signing/blake3-keyed/sign_sync/100B` | 182 ns | ±0 ns |
| `signing/blake3-keyed/sign_sync/1KB` | 1.20 µs | ±2 ns |
| `signing/blake3-keyed/sign_sync/2KB` | 2.40 µs | ±2 ns |
| `signing/blake3-keyed/sign_sync/4KB` | 3.53 µs | ±5 ns |
| `signing/blake3-keyed/sign_sync/500B` | 617 ns | ±0 ns |
| `signing/blake3-keyed/sign_sync/8KB` | 4.79 µs | ±31 ns |
| `signing/blake3-plain/sign_sync/100B` | 188 ns | ±0 ns |
| `signing/blake3-plain/sign_sync/1KB` | 1.20 µs | ±1 ns |
| `signing/blake3-plain/sign_sync/2KB` | 2.40 µs | ±2 ns |
| `signing/blake3-plain/sign_sync/4KB` | 3.53 µs | ±4 ns |
| `signing/blake3-plain/sign_sync/500B` | 623 ns | ±0 ns |
| `signing/blake3-plain/sign_sync/8KB` | 4.79 µs | ±5 ns |
| `signing/ed25519/sign_sync/100B` | 20.71 µs | ±925 ns |
| `signing/ed25519/sign_sync/1KB` | 24.14 µs | ±377 ns |
| `signing/ed25519/sign_sync/2KB` | 28.00 µs | ±262 ns |
| `signing/ed25519/sign_sync/4KB` | 35.17 µs | ±550 ns |
| `signing/ed25519/sign_sync/500B` | 22.21 µs | ±45 ns |
| `signing/ed25519/sign_sync/8KB` | 50.24 µs | ±178 ns |
| `signing/hmac/sign_sync/100B` | 268 ns | ±0 ns |
| `signing/hmac/sign_sync/1KB` | 830 ns | ±0 ns |
| `signing/hmac/sign_sync/2KB` | 1.49 µs | ±0 ns |
| `signing/hmac/sign_sync/4KB` | 2.73 µs | ±2 ns |
| `signing/hmac/sign_sync/500B` | 510 ns | ±1 ns |
| `signing/hmac/sign_sync/8KB` | 5.26 µs | ±26 ns |
| `signing/sha256-digest/sign_sync/100B` | 101 ns | ±1 ns |
| `signing/sha256-digest/sign_sync/1KB` | 666 ns | ±1 ns |
| `signing/sha256-digest/sign_sync/2KB` | 1.29 µs | ±81 ns |
| `signing/sha256-digest/sign_sync/4KB` | 2.54 µs | ±2 ns |
| `signing/sha256-digest/sign_sync/500B` | 339 ns | ±0 ns |
| `signing/sha256-digest/sign_sync/8KB` | 5.07 µs | ±5 ns |
| | | |
| `validation/cert_missing` | 194 ns | ±3 ns |
| `validation/schema_mismatch` | 144 ns | ±0 ns |
| `validation/single_hop` | 43.67 µs | ±206 ns |
| | | |
| `validation_stage/cert_via_anchor` | 43.53 µs | ±109 ns |
| `validation_stage/disabled` | 635 ns | ±2 ns |
| | | |
| `verification/blake3-keyed/verify/100B` | 294 ns | ±0 ns |
| `verification/blake3-keyed/verify/1KB` | 1.31 µs | ±3 ns |
| `verification/blake3-keyed/verify/2KB` | 2.51 µs | ±1 ns |
| `verification/blake3-keyed/verify/4KB` | 3.64 µs | ±9 ns |
| `verification/blake3-keyed/verify/500B` | 729 ns | ±1 ns |
| `verification/blake3-keyed/verify/8KB` | 4.91 µs | ±4 ns |
| `verification/blake3-plain/verify/100B` | 299 ns | ±0 ns |
| `verification/blake3-plain/verify/1KB` | 1.31 µs | ±1 ns |
| `verification/blake3-plain/verify/2KB` | 2.51 µs | ±12 ns |
| `verification/blake3-plain/verify/4KB` | 3.64 µs | ±4 ns |
| `verification/blake3-plain/verify/500B` | 734 ns | ±1 ns |
| `verification/blake3-plain/verify/8KB` | 4.91 µs | ±8 ns |
| `verification/ed25519-batch/1` | 53.48 µs | ±169 ns |
| `verification/ed25519-batch/10` | 249.23 µs | ±414 ns |
| `verification/ed25519-batch/100` | 2.27 ms | ±7.60 µs |
| `verification/ed25519-batch/1000` | 18.63 ms | ±54.15 µs |
| `verification/ed25519-per-sig-loop/1` | 42.26 µs | ±105 ns |
| `verification/ed25519-per-sig-loop/10` | 420.61 µs | ±677 ns |
| `verification/ed25519-per-sig-loop/100` | 4.29 ms | ±8.28 µs |
| `verification/ed25519-per-sig-loop/1000` | 43.11 ms | ±177.68 µs |
| `verification/ed25519/verify/100B` | 41.96 µs | ±1.89 µs |
| `verification/ed25519/verify/1KB` | 44.08 µs | ±247 ns |
| `verification/ed25519/verify/2KB` | 45.84 µs | ±97 ns |
| `verification/ed25519/verify/4KB` | 49.52 µs | ±112 ns |
| `verification/ed25519/verify/500B` | 43.16 µs | ±90 ns |
| `verification/ed25519/verify/8KB` | 57.88 µs | ±586 ns |
| `verification/sha256-digest/verify/100B` | 104 ns | ±0 ns |
| `verification/sha256-digest/verify/1KB` | 665 ns | ±0 ns |
| `verification/sha256-digest/verify/2KB` | 1.30 µs | ±0 ns |
| `verification/sha256-digest/verify/4KB` | 2.55 µs | ±6 ns |
| `verification/sha256-digest/verify/500B` | 340 ns | ±6 ns |
| `verification/sha256-digest/verify/8KB` | 5.08 µs | ±5 ns |
<!-- BENCH_RESULTS_END -->
