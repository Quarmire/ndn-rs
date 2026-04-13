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

## Latest CI Results

<!-- BENCH_RESULTS_START -->
*Last updated by CI on 2026-04-13 (ubuntu-latest, stable Rust)*

| Benchmark | Median | ± Variance |
|-----------|--------|------------|
| `cs/hit` | 888 ns | ±3 ns |
| `cs/miss` | 581 ns | ±0 ns |
| | | |
| `cs_insert/insert_new` | 7.72 µs | ±12.40 µs |
| `cs_insert/insert_replace` | 1.03 µs | ±33 ns |
| | | |
| `data_pipeline/4` | 2.19 µs | ±34 ns |
| `data_pipeline/8` | 2.60 µs | ±34 ns |
| | | |
| `decode/data/4` | 459 ns | ±5 ns |
| `decode/data/8` | 553 ns | ±2 ns |
| `decode/interest/4` | 606 ns | ±2 ns |
| `decode/interest/8` | 696 ns | ±1 ns |
| | | |
| `decode_throughput/4` | 622.29 µs | ±5.88 µs |
| `decode_throughput/8` | 711.10 µs | ±1.36 µs |
| | | |
| `fib/lpm/10` | 31 ns | ±1 ns |
| `fib/lpm/100` | 93 ns | ±0 ns |
| `fib/lpm/1000` | 94 ns | ±1 ns |
| | | |
| `interest_pipeline/cs_hit` | 1.13 µs | ±2 ns |
| `interest_pipeline/no_route/4` | 1.66 µs | ±8 ns |
| `interest_pipeline/no_route/8` | 1.83 µs | ±14 ns |
| | | |
| `lru/evict` | 196 ns | ±15 ns |
| `lru/evict_prefix` | 2.42 µs | ±3.12 µs |
| `lru/get_can_be_prefix` | 316 ns | ±7 ns |
| `lru/get_hit` | 219 ns | ±1 ns |
| `lru/get_miss_empty` | 149 ns | ±0 ns |
| `lru/get_miss_populated` | 192 ns | ±9 ns |
| `lru/insert_new` | 2.27 µs | ±1.31 µs |
| `lru/insert_replace` | 358 ns | ±7 ns |
| | | |
| `name/display/components/4` | 439 ns | ±1 ns |
| `name/display/components/8` | 821 ns | ±8 ns |
| `name/eq/eq_match` | 44 ns | ±0 ns |
| `name/eq/eq_miss_first` | 2 ns | ±0 ns |
| `name/eq/eq_miss_last` | 41 ns | ±2 ns |
| `name/has_prefix/prefix_len/1` | 8 ns | ±0 ns |
| `name/has_prefix/prefix_len/4` | 22 ns | ±0 ns |
| `name/has_prefix/prefix_len/8` | 42 ns | ±1 ns |
| `name/hash/components/4` | 95 ns | ±2 ns |
| `name/hash/components/8` | 166 ns | ±2 ns |
| `name/parse/components/12` | 604 ns | ±4 ns |
| `name/parse/components/4` | 226 ns | ±4 ns |
| `name/parse/components/8` | 406 ns | ±5 ns |
| `name/tlv_decode/components/12` | 326 ns | ±1 ns |
| `name/tlv_decode/components/4` | 141 ns | ±1 ns |
| `name/tlv_decode/components/8` | 225 ns | ±1 ns |
| | | |
| `pit/aggregate` | 2.59 µs | ±321 ns |
| `pit/new_entry` | 1.47 µs | ±19 ns |
| | | |
| `pit_match/hit` | 1.93 µs | ±3 ns |
| `pit_match/miss` | 2.20 µs | ±6 ns |
| | | |
| `sharded/get_hit/1` | 243 ns | ±0 ns |
| `sharded/get_hit/16` | 243 ns | ±3 ns |
| `sharded/get_hit/4` | 243 ns | ±4 ns |
| `sharded/get_hit/8` | 240 ns | ±2 ns |
| `sharded/insert/1` | 2.86 µs | ±1.00 µs |
| `sharded/insert/16` | 2.10 µs | ±2.05 µs |
| `sharded/insert/4` | 2.93 µs | ±1.10 µs |
| `sharded/insert/8` | 3.37 µs | ±1.78 µs |
| | | |
| `signing/ed25519/sign_sync/100B` | 23.18 µs | ±45 ns |
| `signing/ed25519/sign_sync/500B` | 24.85 µs | ±203 ns |
| `signing/hmac/sign_sync/100B` | 312 ns | ±1 ns |
| `signing/hmac/sign_sync/500B` | 586 ns | ±1 ns |
| | | |
| `validation/cert_missing` | 210 ns | ±4 ns |
| `validation/schema_mismatch` | 158 ns | ±7 ns |
| `validation/single_hop` | 45.16 µs | ±163 ns |
| | | |
| `validation_stage/cert_via_anchor` | 46.03 µs | ±105 ns |
| `validation_stage/disabled` | 690 ns | ±1 ns |
| | | |
| `verification/ed25519/verify/100B` | 52.27 µs | ±660 ns |
| `verification/ed25519/verify/500B` | 53.83 µs | ±267 ns |
<!-- BENCH_RESULTS_END -->
