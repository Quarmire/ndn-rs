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
| `cs/hit` | 761 ns | ±3 ns |
| `cs/miss` | 525 ns | ±3 ns |
| | | |
| `cs_insert/insert_new` | 11.58 µs | ±20.43 µs |
| `cs_insert/insert_replace` | 956 ns | ±2 ns |
| | | |
| `data_pipeline/4` | 1.86 µs | ±34 ns |
| `data_pipeline/8` | 2.25 µs | ±25 ns |
| | | |
| `decode/data/4` | 400 ns | ±6 ns |
| `decode/data/8` | 477 ns | ±1 ns |
| `decode/interest/4` | 478 ns | ±4 ns |
| `decode/interest/8` | 552 ns | ±1 ns |
| | | |
| `decode_throughput/4` | 460.45 µs | ±1.37 µs |
| `decode_throughput/8` | 546.31 µs | ±1.14 µs |
| | | |
| `fib/lpm/10` | 33 ns | ±0 ns |
| `fib/lpm/100` | 96 ns | ±0 ns |
| `fib/lpm/1000` | 95 ns | ±0 ns |
| | | |
| `interest_pipeline/cs_hit` | 949 ns | ±1 ns |
| `interest_pipeline/no_route/4` | 1.40 µs | ±7 ns |
| `interest_pipeline/no_route/8` | 1.55 µs | ±9 ns |
| | | |
| `lru/evict` | 189 ns | ±2 ns |
| `lru/evict_prefix` | 1.99 µs | ±2.15 µs |
| `lru/get_can_be_prefix` | 309 ns | ±0 ns |
| `lru/get_hit` | 215 ns | ±0 ns |
| `lru/get_miss_empty` | 146 ns | ±0 ns |
| `lru/get_miss_populated` | 192 ns | ±0 ns |
| `lru/insert_new` | 2.34 µs | ±1.64 µs |
| `lru/insert_replace` | 380 ns | ±1 ns |
| | | |
| `name/display/components/4` | 452 ns | ±5 ns |
| `name/display/components/8` | 881 ns | ±5 ns |
| `name/eq/eq_match` | 39 ns | ±0 ns |
| `name/eq/eq_miss_first` | 2 ns | ±0 ns |
| `name/eq/eq_miss_last` | 36 ns | ±0 ns |
| `name/has_prefix/prefix_len/1` | 8 ns | ±0 ns |
| `name/has_prefix/prefix_len/4` | 23 ns | ±0 ns |
| `name/has_prefix/prefix_len/8` | 42 ns | ±2 ns |
| `name/hash/components/4` | 84 ns | ±1 ns |
| `name/hash/components/8` | 163 ns | ±0 ns |
| `name/parse/components/12` | 657 ns | ±3 ns |
| `name/parse/components/4` | 230 ns | ±2 ns |
| `name/parse/components/8` | 432 ns | ±9 ns |
| `name/tlv_decode/components/12` | 314 ns | ±0 ns |
| `name/tlv_decode/components/4` | 138 ns | ±1 ns |
| `name/tlv_decode/components/8` | 217 ns | ±1 ns |
| | | |
| `pit/aggregate` | 2.37 µs | ±130 ns |
| `pit/new_entry` | 1.21 µs | ±3 ns |
| | | |
| `pit_match/hit` | 1.56 µs | ±27 ns |
| `pit_match/miss` | 1.96 µs | ±8 ns |
| | | |
| `sharded/get_hit/1` | 229 ns | ±0 ns |
| `sharded/get_hit/16` | 227 ns | ±0 ns |
| `sharded/get_hit/4` | 229 ns | ±0 ns |
| `sharded/get_hit/8` | 227 ns | ±0 ns |
| `sharded/insert/1` | 2.75 µs | ±1.85 µs |
| `sharded/insert/16` | 1.85 µs | ±1.60 µs |
| `sharded/insert/4` | 2.46 µs | ±1.85 µs |
| `sharded/insert/8` | 2.61 µs | ±1.97 µs |
| | | |
| `signing/ed25519/sign_sync/100B` | 20.61 µs | ±295 ns |
| `signing/ed25519/sign_sync/500B` | 22.16 µs | ±258 ns |
| `signing/hmac/sign_sync/100B` | 268 ns | ±0 ns |
| `signing/hmac/sign_sync/500B` | 509 ns | ±0 ns |
| | | |
| `validation/cert_missing` | 194 ns | ±0 ns |
| `validation/schema_mismatch` | 145 ns | ±0 ns |
| `validation/single_hop` | 46.22 µs | ±57 ns |
| | | |
| `validation_stage/cert_via_anchor` | 46.46 µs | ±55 ns |
| `validation_stage/disabled` | 646 ns | ±3 ns |
| | | |
| `verification/ed25519/verify/100B` | 41.62 µs | ±130 ns |
| `verification/ed25519/verify/500B` | 42.87 µs | ±138 ns |
<!-- BENCH_RESULTS_END -->
