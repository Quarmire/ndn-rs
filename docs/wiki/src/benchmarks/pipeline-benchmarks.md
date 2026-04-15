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
*Last updated by CI on 2026-04-15 (ubuntu-latest, stable Rust)*

| Benchmark | Median | ± Variance |
|-----------|--------|------------|
| `cs/hit` | 760 ns | ±1 ns |
| `cs/miss` | 532 ns | ±4 ns |
| | | |
| `cs_insert/insert_new` | 10.37 µs | ±20.42 µs |
| `cs_insert/insert_replace` | 951 ns | ±26 ns |
| | | |
| `data_pipeline/4` | 1.85 µs | ±28 ns |
| `data_pipeline/8` | 2.24 µs | ±36 ns |
| | | |
| `decode/data/4` | 390 ns | ±6 ns |
| `decode/data/8` | 470 ns | ±1 ns |
| `decode/interest/4` | 461 ns | ±3 ns |
| `decode/interest/8` | 533 ns | ±2 ns |
| | | |
| `decode_throughput/4` | 444.68 µs | ±2.20 µs |
| `decode_throughput/8` | 527.96 µs | ±792 ns |
| | | |
| `fib/lpm/10` | 34 ns | ±0 ns |
| `fib/lpm/100` | 96 ns | ±0 ns |
| `fib/lpm/1000` | 97 ns | ±0 ns |
| | | |
| `interest_pipeline/cs_hit` | 913 ns | ±5 ns |
| `interest_pipeline/no_route/4` | 1.40 µs | ±11 ns |
| `interest_pipeline/no_route/8` | 1.55 µs | ±8 ns |
| | | |
| `large/blake3-rayon/hash/1MB` | 117.22 µs | ±2.06 µs |
| `large/blake3-rayon/hash/256KB` | 36.78 µs | ±893 ns |
| `large/blake3-rayon/hash/4MB` | 437.90 µs | ±8.34 µs |
| `large/blake3-single/hash/1MB` | 248.67 µs | ±573 ns |
| `large/blake3-single/hash/256KB` | 61.39 µs | ±92 ns |
| `large/blake3-single/hash/4MB` | 993.96 µs | ±4.26 µs |
| `large/sha256/hash/1MB` | 659.62 µs | ±595 ns |
| `large/sha256/hash/256KB` | 164.65 µs | ±115 ns |
| `large/sha256/hash/4MB` | 2.64 ms | ±1.42 µs |
| | | |
| `lru/evict` | 189 ns | ±7 ns |
| `lru/evict_prefix` | 2.12 µs | ±3.01 µs |
| `lru/get_can_be_prefix` | 293 ns | ±0 ns |
| `lru/get_hit` | 208 ns | ±0 ns |
| `lru/get_miss_empty` | 138 ns | ±0 ns |
| `lru/get_miss_populated` | 185 ns | ±0 ns |
| `lru/insert_new` | 2.15 µs | ±1.53 µs |
| `lru/insert_replace` | 380 ns | ±1 ns |
| | | |
| `name/display/components/4` | 455 ns | ±2 ns |
| `name/display/components/8` | 874 ns | ±21 ns |
| `name/eq/eq_match` | 37 ns | ±0 ns |
| `name/eq/eq_miss_first` | 2 ns | ±0 ns |
| `name/eq/eq_miss_last` | 36 ns | ±0 ns |
| `name/has_prefix/prefix_len/1` | 7 ns | ±0 ns |
| `name/has_prefix/prefix_len/4` | 23 ns | ±0 ns |
| `name/has_prefix/prefix_len/8` | 46 ns | ±0 ns |
| `name/hash/components/4` | 85 ns | ±1 ns |
| `name/hash/components/8` | 163 ns | ±0 ns |
| `name/parse/components/12` | 644 ns | ±36 ns |
| `name/parse/components/4` | 230 ns | ±1 ns |
| `name/parse/components/8` | 416 ns | ±2 ns |
| `name/tlv_decode/components/12` | 323 ns | ±1 ns |
| `name/tlv_decode/components/4` | 146 ns | ±0 ns |
| `name/tlv_decode/components/8` | 227 ns | ±1 ns |
| | | |
| `pit/aggregate` | 2.29 µs | ±135 ns |
| `pit/new_entry` | 1.22 µs | ±4 ns |
| | | |
| `pit_match/hit` | 1.57 µs | ±10 ns |
| `pit_match/miss` | 1.90 µs | ±181 ns |
| | | |
| `sharded/get_hit/1` | 227 ns | ±0 ns |
| `sharded/get_hit/16` | 226 ns | ±0 ns |
| `sharded/get_hit/4` | 227 ns | ±0 ns |
| `sharded/get_hit/8` | 229 ns | ±0 ns |
| `sharded/insert/1` | 2.50 µs | ±1.59 µs |
| `sharded/insert/16` | 1.85 µs | ±1.50 µs |
| `sharded/insert/4` | 2.51 µs | ±1.81 µs |
| `sharded/insert/8` | 2.00 µs | ±1.63 µs |
| | | |
| `signing/blake3-keyed/sign_sync/100B` | 181 ns | ±0 ns |
| `signing/blake3-keyed/sign_sync/1KB` | 1.20 µs | ±8 ns |
| `signing/blake3-keyed/sign_sync/2KB` | 2.40 µs | ±2 ns |
| `signing/blake3-keyed/sign_sync/4KB` | 3.53 µs | ±3 ns |
| `signing/blake3-keyed/sign_sync/500B` | 617 ns | ±0 ns |
| `signing/blake3-keyed/sign_sync/8KB` | 4.79 µs | ±12 ns |
| `signing/blake3-plain/sign_sync/100B` | 188 ns | ±0 ns |
| `signing/blake3-plain/sign_sync/1KB` | 1.20 µs | ±1 ns |
| `signing/blake3-plain/sign_sync/2KB` | 2.40 µs | ±7 ns |
| `signing/blake3-plain/sign_sync/4KB` | 3.53 µs | ±2 ns |
| `signing/blake3-plain/sign_sync/500B` | 622 ns | ±0 ns |
| `signing/blake3-plain/sign_sync/8KB` | 4.79 µs | ±6 ns |
| `signing/ed25519/sign_sync/100B` | 21.24 µs | ±34 ns |
| `signing/ed25519/sign_sync/1KB` | 24.86 µs | ±130 ns |
| `signing/ed25519/sign_sync/2KB` | 28.86 µs | ±84 ns |
| `signing/ed25519/sign_sync/4KB` | 36.37 µs | ±106 ns |
| `signing/ed25519/sign_sync/500B` | 22.81 µs | ±724 ns |
| `signing/ed25519/sign_sync/8KB` | 52.20 µs | ±228 ns |
| `signing/hmac/sign_sync/100B` | 271 ns | ±1 ns |
| `signing/hmac/sign_sync/1KB` | 830 ns | ±0 ns |
| `signing/hmac/sign_sync/2KB` | 1.49 µs | ±33 ns |
| `signing/hmac/sign_sync/4KB` | 2.73 µs | ±2 ns |
| `signing/hmac/sign_sync/500B` | 511 ns | ±0 ns |
| `signing/hmac/sign_sync/8KB` | 5.26 µs | ±25 ns |
| `signing/sha256-digest/sign_sync/100B` | 101 ns | ±0 ns |
| `signing/sha256-digest/sign_sync/1KB` | 664 ns | ±0 ns |
| `signing/sha256-digest/sign_sync/2KB` | 1.30 µs | ±1 ns |
| `signing/sha256-digest/sign_sync/4KB` | 2.54 µs | ±3 ns |
| `signing/sha256-digest/sign_sync/500B` | 340 ns | ±0 ns |
| `signing/sha256-digest/sign_sync/8KB` | 5.07 µs | ±3 ns |
| | | |
| `validation/cert_missing` | 203 ns | ±0 ns |
| `validation/schema_mismatch` | 155 ns | ±5 ns |
| `validation/single_hop` | 42.64 µs | ±487 ns |
| | | |
| `validation_stage/cert_via_anchor` | 43.40 µs | ±348 ns |
| `validation_stage/disabled` | 613 ns | ±0 ns |
| | | |
| `verification/blake3-keyed/verify/100B` | 298 ns | ±0 ns |
| `verification/blake3-keyed/verify/1KB` | 1.31 µs | ±2 ns |
| `verification/blake3-keyed/verify/2KB` | 2.51 µs | ±5 ns |
| `verification/blake3-keyed/verify/4KB` | 3.65 µs | ±11 ns |
| `verification/blake3-keyed/verify/500B` | 733 ns | ±1 ns |
| `verification/blake3-keyed/verify/8KB` | 4.91 µs | ±35 ns |
| `verification/blake3-plain/verify/100B` | 299 ns | ±1 ns |
| `verification/blake3-plain/verify/1KB` | 1.31 µs | ±1 ns |
| `verification/blake3-plain/verify/2KB` | 2.51 µs | ±6 ns |
| `verification/blake3-plain/verify/4KB` | 3.64 µs | ±22 ns |
| `verification/blake3-plain/verify/500B` | 735 ns | ±0 ns |
| `verification/blake3-plain/verify/8KB` | 4.90 µs | ±36 ns |
| `verification/ed25519/verify/100B` | 43.34 µs | ±63 ns |
| `verification/ed25519/verify/1KB` | 45.66 µs | ±123 ns |
| `verification/ed25519/verify/2KB` | 47.46 µs | ±94 ns |
| `verification/ed25519/verify/4KB` | 51.30 µs | ±1.34 µs |
| `verification/ed25519/verify/500B` | 44.65 µs | ±139 ns |
| `verification/ed25519/verify/8KB` | 60.19 µs | ±1.67 µs |
| `verification/sha256-digest/verify/100B` | 102 ns | ±0 ns |
| `verification/sha256-digest/verify/1KB` | 662 ns | ±0 ns |
| `verification/sha256-digest/verify/2KB` | 1.30 µs | ±13 ns |
| `verification/sha256-digest/verify/4KB` | 2.55 µs | ±3 ns |
| `verification/sha256-digest/verify/500B` | 341 ns | ±0 ns |
| `verification/sha256-digest/verify/8KB` | 5.08 µs | ±5 ns |
<!-- BENCH_RESULTS_END -->
