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
*Last updated by CI on 2026-04-10 (ubuntu-latest, stable Rust)*

| Benchmark | Median | ± Variance |
|-----------|--------|------------|
| `appface/latency/1024` | 409 ns | ±1 ns |
| `appface/latency/64` | 407 ns | ±6 ns |
| `appface/latency/8192` | 410 ns | ±0 ns |
| `appface/throughput/1024` | 143.46 µs | ±947 ns |
| `appface/throughput/64` | 143.60 µs | ±679 ns |
| `appface/throughput/8192` | 143.60 µs | ±2.85 µs |
| | | |
| `cs/hit` | 894 ns | ±3 ns |
| `cs/miss` | 567 ns | ±1 ns |
| | | |
| `cs_insert/insert_new` | 9.44 µs | ±13.82 µs |
| `cs_insert/insert_replace` | 1.03 µs | ±5 ns |
| | | |
| `data_pipeline/4` | 2.17 µs | ±30 ns |
| `data_pipeline/8` | 2.63 µs | ±34 ns |
| | | |
| `decode/data/4` | 455 ns | ±1 ns |
| `decode/data/8` | 548 ns | ±8 ns |
| `decode/interest/4` | 612 ns | ±1 ns |
| `decode/interest/8` | 710 ns | ±1 ns |
| | | |
| `decode_throughput/4` | 604.83 µs | ±1.48 µs |
| `decode_throughput/8` | 693.48 µs | ±1.63 µs |
| | | |
| `fib/lpm/10` | 30 ns | ±1 ns |
| `fib/lpm/100` | 94 ns | ±0 ns |
| `fib/lpm/1000` | 96 ns | ±0 ns |
| | | |
| `interest_pipeline/cs_hit` | 1.09 µs | ±2 ns |
| `interest_pipeline/no_route/4` | 1.71 µs | ±36 ns |
| `interest_pipeline/no_route/8` | 1.84 µs | ±7 ns |
| | | |
| `lru/evict` | 199 ns | ±1 ns |
| `lru/evict_prefix` | 2.17 µs | ±3.08 µs |
| `lru/get_can_be_prefix` | 313 ns | ±0 ns |
| `lru/get_hit` | 216 ns | ±1 ns |
| `lru/get_miss_empty` | 152 ns | ±1 ns |
| `lru/get_miss_populated` | 196 ns | ±1 ns |
| `lru/insert_new` | 2.25 µs | ±1.32 µs |
| `lru/insert_replace` | 357 ns | ±2 ns |
| | | |
| `name/display/components/4` | 448 ns | ±1 ns |
| `name/display/components/8` | 840 ns | ±8 ns |
| `name/eq/eq_match` | 39 ns | ±1 ns |
| `name/eq/eq_miss_first` | 2 ns | ±0 ns |
| `name/eq/eq_miss_last` | 41 ns | ±1 ns |
| `name/has_prefix/prefix_len/1` | 7 ns | ±0 ns |
| `name/has_prefix/prefix_len/4` | 22 ns | ±0 ns |
| `name/has_prefix/prefix_len/8` | 42 ns | ±0 ns |
| `name/hash/components/4` | 90 ns | ±0 ns |
| `name/hash/components/8` | 162 ns | ±0 ns |
| `name/parse/components/12` | 592 ns | ±4 ns |
| `name/parse/components/4` | 216 ns | ±2 ns |
| `name/parse/components/8` | 418 ns | ±3 ns |
| `name/tlv_decode/components/12` | 324 ns | ±1 ns |
| `name/tlv_decode/components/4` | 143 ns | ±1 ns |
| `name/tlv_decode/components/8` | 224 ns | ±1 ns |
| | | |
| `pit/aggregate` | 2.57 µs | ±137 ns |
| `pit/new_entry` | 1.46 µs | ±3 ns |
| | | |
| `pit_match/hit` | 1.88 µs | ±15 ns |
| `pit_match/miss` | 1.18 µs | ±9 ns |
| | | |
| `sharded/get_hit/1` | 243 ns | ±3 ns |
| `sharded/get_hit/16` | 243 ns | ±1 ns |
| `sharded/get_hit/4` | 242 ns | ±1 ns |
| `sharded/get_hit/8` | 241 ns | ±3 ns |
| `sharded/insert/1` | 2.83 µs | ±1.01 µs |
| `sharded/insert/16` | 1.99 µs | ±1.86 µs |
| `sharded/insert/4` | 2.84 µs | ±1.13 µs |
| `sharded/insert/8` | 2.52 µs | ±1.61 µs |
| | | |
| `signing/ed25519/sign_sync/100B` | 23.23 µs | ±129 ns |
| `signing/ed25519/sign_sync/500B` | 24.84 µs | ±430 ns |
| `signing/hmac/sign_sync/100B` | 303 ns | ±0 ns |
| `signing/hmac/sign_sync/500B` | 577 ns | ±0 ns |
| | | |
| `unix/latency/1024` | 10.59 µs | ±215 ns |
| `unix/latency/64` | 10.03 µs | ±155 ns |
| `unix/latency/8192` | 15.47 µs | ±96 ns |
| `unix/throughput/1024` | 551.11 µs | ±6.06 µs |
| `unix/throughput/64` | 493.14 µs | ±3.85 µs |
| `unix/throughput/8192` | 1.07 ms | ±2.52 µs |
| | | |
| `validation/cert_missing` | 225 ns | ±1 ns |
| `validation/schema_mismatch` | 164 ns | ±1 ns |
| `validation/single_hop` | 53.11 µs | ±111 ns |
| | | |
| `validation_stage/cert_via_anchor` | 46.16 µs | ±71 ns |
| `validation_stage/disabled` | 702 ns | ±4 ns |
| | | |
| `verification/ed25519/verify/100B` | 44.42 µs | ±72 ns |
| `verification/ed25519/verify/500B` | 45.73 µs | ±94 ns |
<!-- BENCH_RESULTS_END -->
