# Pipeline Benchmarks

ndn-rs ships a Criterion-based benchmark suite that measures individual pipeline stage costs and end-to-end forwarding latency. The benchmarks live in `crates/ndn-engine/benches/pipeline.rs`.

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

## Latest CI Results

<!-- BENCH_RESULTS_START -->
*Last updated by CI on 2026-04-07 (ubuntu-latest, stable Rust)*

| Benchmark | Median | ± Variance |
|-----------|--------|------------|
| `appface/latency/1024` | 386 ns | ±1 ns |
| `appface/latency/64` | 386 ns | ±3 ns |
| `appface/latency/8192` | 387 ns | ±1 ns |
| `appface/throughput/1024` | 132.71 µs | ±551 ns |
| `appface/throughput/64` | 133.60 µs | ±636 ns |
| `appface/throughput/8192` | 132.62 µs | ±889 ns |
| | | |
| `cs/hit` | 815 ns | ±8 ns |
| `cs/miss` | 528 ns | ±2 ns |
| | | |
| `cs_insert/insert_new` | 11.48 µs | ±20.41 µs |
| `cs_insert/insert_replace` | 934 ns | ±3 ns |
| | | |
| `data_pipeline/4` | 1.90 µs | ±31 ns |
| `data_pipeline/8` | 2.29 µs | ±39 ns |
| | | |
| `decode/data/4` | 398 ns | ±11 ns |
| `decode/data/8` | 474 ns | ±1 ns |
| `decode/interest/4` | 507 ns | ±0 ns |
| `decode/interest/8` | 588 ns | ±1 ns |
| | | |
| `decode_throughput/4` | 488.35 µs | ±1.51 µs |
| `decode_throughput/8` | 562.29 µs | ±1.04 µs |
| | | |
| `fib/lpm/10` | 33 ns | ±0 ns |
| `fib/lpm/100` | 94 ns | ±0 ns |
| `fib/lpm/1000` | 95 ns | ±0 ns |
| | | |
| `interest_pipeline/cs_hit` | 967 ns | ±22 ns |
| `interest_pipeline/no_route/4` | 1.43 µs | ±6 ns |
| `interest_pipeline/no_route/8` | 1.57 µs | ±6 ns |
| | | |
| `lru/evict` | 191 ns | ±1 ns |
| `lru/evict_prefix` | 2.01 µs | ±2.21 µs |
| `lru/get_can_be_prefix` | 293 ns | ±1 ns |
| `lru/get_hit` | 207 ns | ±0 ns |
| `lru/get_miss_empty` | 138 ns | ±1 ns |
| `lru/get_miss_populated` | 186 ns | ±0 ns |
| `lru/insert_new` | 2.04 µs | ±1.51 µs |
| `lru/insert_replace` | 383 ns | ±2 ns |
| | | |
| `name/display/components/4` | 453 ns | ±1 ns |
| `name/display/components/8` | 959 ns | ±6 ns |
| `name/eq/eq_match` | 38 ns | ±1 ns |
| `name/eq/eq_miss_first` | 2 ns | ±0 ns |
| `name/eq/eq_miss_last` | 36 ns | ±0 ns |
| `name/has_prefix/prefix_len/1` | 8 ns | ±0 ns |
| `name/has_prefix/prefix_len/4` | 21 ns | ±0 ns |
| `name/has_prefix/prefix_len/8` | 40 ns | ±0 ns |
| `name/hash/components/4` | 84 ns | ±0 ns |
| `name/hash/components/8` | 161 ns | ±1 ns |
| `name/parse/components/12` | 629 ns | ±16 ns |
| `name/parse/components/4` | 219 ns | ±1 ns |
| `name/parse/components/8` | 439 ns | ±4 ns |
| `name/tlv_decode/components/12` | 315 ns | ±1 ns |
| `name/tlv_decode/components/4` | 144 ns | ±0 ns |
| `name/tlv_decode/components/8` | 229 ns | ±5 ns |
| | | |
| `pit/aggregate` | 2.47 µs | ±139 ns |
| `pit/new_entry` | 1.29 µs | ±4 ns |
| | | |
| `pit_match/hit` | 1.63 µs | ±2 ns |
| `pit_match/miss` | 1.04 µs | ±2 ns |
| | | |
| `sharded/get_hit/1` | 246 ns | ±3 ns |
| `sharded/get_hit/16` | 245 ns | ±6 ns |
| `sharded/get_hit/4` | 245 ns | ±4 ns |
| `sharded/get_hit/8` | 245 ns | ±6 ns |
| `sharded/insert/1` | 2.69 µs | ±1.62 µs |
| `sharded/insert/16` | 1.85 µs | ±1.52 µs |
| `sharded/insert/4` | 2.64 µs | ±1.77 µs |
| `sharded/insert/8` | 1.96 µs | ±1.71 µs |
| | | |
| `signing/ed25519/sign_sync/100B` | 20.67 µs | ±272 ns |
| `signing/ed25519/sign_sync/500B` | 22.21 µs | ±69 ns |
| `signing/hmac/sign_sync/100B` | 266 ns | ±0 ns |
| `signing/hmac/sign_sync/500B` | 506 ns | ±0 ns |
| | | |
| `unix/latency/1024` | 8.43 µs | ±144 ns |
| `unix/latency/64` | 7.99 µs | ±69 ns |
| `unix/latency/8192` | 13.14 µs | ±49 ns |
| `unix/throughput/1024` | 494.94 µs | ±1.45 µs |
| `unix/throughput/64` | 442.60 µs | ±1.21 µs |
| `unix/throughput/8192` | 938.69 µs | ±4.14 µs |
| | | |
| `validation/cert_missing` | 199 ns | ±0 ns |
| `validation/schema_mismatch` | 151 ns | ±0 ns |
| `validation/single_hop` | 42.46 µs | ±100 ns |
| | | |
| `validation_stage/cert_via_anchor` | 43.31 µs | ±172 ns |
| `validation_stage/disabled` | 628 ns | ±1 ns |
| | | |
| `verification/ed25519/verify/100B` | 45.96 µs | ±59 ns |
| `verification/ed25519/verify/500B` | 47.25 µs | ±100 ns |
<!-- BENCH_RESULTS_END -->
