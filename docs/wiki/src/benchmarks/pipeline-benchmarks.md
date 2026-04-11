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
*Last updated by CI on 2026-04-11 (ubuntu-latest, stable Rust)*

| Benchmark | Median | ± Variance |
|-----------|--------|------------|
| `appface/latency/1024` | 416 ns | ±2 ns |
| `appface/latency/64` | 414 ns | ±1 ns |
| `appface/latency/8192` | 416 ns | ±1 ns |
| `appface/throughput/1024` | 142.53 µs | ±649 ns |
| `appface/throughput/64` | 139.75 µs | ±475 ns |
| `appface/throughput/8192` | 139.94 µs | ±1.35 µs |
| | | |
| `cs/hit` | 915 ns | ±2 ns |
| `cs/miss` | 571 ns | ±2 ns |
| | | |
| `cs_insert/insert_new` | 9.89 µs | ±14.44 µs |
| `cs_insert/insert_replace` | 1.04 µs | ±6 ns |
| | | |
| `data_pipeline/4` | 2.21 µs | ±29 ns |
| `data_pipeline/8` | 2.62 µs | ±36 ns |
| | | |
| `decode/data/4` | 485 ns | ±3 ns |
| `decode/data/8` | 577 ns | ±6 ns |
| `decode/interest/4` | 641 ns | ±6 ns |
| `decode/interest/8` | 733 ns | ±1 ns |
| | | |
| `decode_throughput/4` | 611.59 µs | ±15.71 µs |
| `decode_throughput/8` | 702.08 µs | ±1.17 µs |
| | | |
| `fib/lpm/10` | 31 ns | ±4 ns |
| `fib/lpm/100` | 93 ns | ±0 ns |
| `fib/lpm/1000` | 96 ns | ±0 ns |
| | | |
| `interest_pipeline/cs_hit` | 1.12 µs | ±14 ns |
| `interest_pipeline/no_route/4` | 1.69 µs | ±16 ns |
| `interest_pipeline/no_route/8` | 1.86 µs | ±32 ns |
| | | |
| `lru/evict` | 199 ns | ±2 ns |
| `lru/evict_prefix` | 2.31 µs | ±3.09 µs |
| `lru/get_can_be_prefix` | 314 ns | ±8 ns |
| `lru/get_hit` | 219 ns | ±1 ns |
| `lru/get_miss_empty` | 148 ns | ±2 ns |
| `lru/get_miss_populated` | 193 ns | ±1 ns |
| `lru/insert_new` | 2.62 µs | ±1.56 µs |
| `lru/insert_replace` | 358 ns | ±1 ns |
| | | |
| `name/display/components/4` | 440 ns | ±2 ns |
| `name/display/components/8` | 849 ns | ±32 ns |
| `name/eq/eq_match` | 39 ns | ±1 ns |
| `name/eq/eq_miss_first` | 2 ns | ±0 ns |
| `name/eq/eq_miss_last` | 41 ns | ±0 ns |
| `name/has_prefix/prefix_len/1` | 7 ns | ±0 ns |
| `name/has_prefix/prefix_len/4` | 20 ns | ±0 ns |
| `name/has_prefix/prefix_len/8` | 42 ns | ±0 ns |
| `name/hash/components/4` | 90 ns | ±2 ns |
| `name/hash/components/8` | 167 ns | ±1 ns |
| `name/parse/components/12` | 591 ns | ±14 ns |
| `name/parse/components/4` | 217 ns | ±3 ns |
| `name/parse/components/8` | 415 ns | ±6 ns |
| `name/tlv_decode/components/12` | 319 ns | ±2 ns |
| `name/tlv_decode/components/4` | 138 ns | ±0 ns |
| `name/tlv_decode/components/8` | 221 ns | ±0 ns |
| | | |
| `pit/aggregate` | 2.65 µs | ±140 ns |
| `pit/new_entry` | 1.56 µs | ±11 ns |
| | | |
| `pit_match/hit` | 1.89 µs | ±4 ns |
| `pit_match/miss` | 1.16 µs | ±16 ns |
| | | |
| `sharded/get_hit/1` | 242 ns | ±2 ns |
| `sharded/get_hit/16` | 250 ns | ±0 ns |
| `sharded/get_hit/4` | 245 ns | ±1 ns |
| `sharded/get_hit/8` | 249 ns | ±21 ns |
| `sharded/insert/1` | 3.13 µs | ±1.11 µs |
| `sharded/insert/16` | 2.45 µs | ±1.77 µs |
| `sharded/insert/4` | 3.37 µs | ±1.42 µs |
| `sharded/insert/8` | 3.25 µs | ±1.18 µs |
| | | |
| `signing/ed25519/sign_sync/100B` | 23.17 µs | ±176 ns |
| `signing/ed25519/sign_sync/500B` | 24.81 µs | ±78 ns |
| `signing/hmac/sign_sync/100B` | 333 ns | ±0 ns |
| `signing/hmac/sign_sync/500B` | 606 ns | ±0 ns |
| | | |
| `unix/latency/1024` | 10.72 µs | ±210 ns |
| `unix/latency/64` | 9.93 µs | ±174 ns |
| `unix/latency/8192` | 15.57 µs | ±208 ns |
| `unix/throughput/1024` | 567.38 µs | ±1.03 µs |
| `unix/throughput/64` | 513.17 µs | ±7.10 µs |
| `unix/throughput/8192` | 1.07 ms | ±12.43 µs |
| | | |
| `validation/cert_missing` | 220 ns | ±1 ns |
| `validation/schema_mismatch` | 166 ns | ±0 ns |
| `validation/single_hop` | 45.51 µs | ±67 ns |
| | | |
| `validation_stage/cert_via_anchor` | 50.87 µs | ±1.09 µs |
| `validation_stage/disabled` | 691 ns | ±1 ns |
| | | |
| `verification/ed25519/verify/100B` | 50.38 µs | ±338 ns |
| `verification/ed25519/verify/500B` | 51.69 µs | ±316 ns |
<!-- BENCH_RESULTS_END -->
