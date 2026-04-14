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
*Last updated by CI on 2026-04-14 (ubuntu-latest, stable Rust)*

| Benchmark | Median | ± Variance |
|-----------|--------|------------|
| `cs/hit` | 768 ns | ±4 ns |
| `cs/miss` | 534 ns | ±8 ns |
| | | |
| `cs_insert/insert_new` | 10.21 µs | ±18.22 µs |
| `cs_insert/insert_replace` | 994 ns | ±9 ns |
| | | |
| `data_pipeline/4` | 1.91 µs | ±33 ns |
| `data_pipeline/8` | 2.27 µs | ±40 ns |
| | | |
| `decode/data/4` | 390 ns | ±1 ns |
| `decode/data/8` | 463 ns | ±1 ns |
| `decode/interest/4` | 453 ns | ±1 ns |
| `decode/interest/8` | 531 ns | ±3 ns |
| | | |
| `decode_throughput/4` | 458.37 µs | ±935 ns |
| `decode_throughput/8` | 543.02 µs | ±1.66 µs |
| | | |
| `fib/lpm/10` | 33 ns | ±0 ns |
| `fib/lpm/100` | 96 ns | ±0 ns |
| `fib/lpm/1000` | 95 ns | ±0 ns |
| | | |
| `interest_pipeline/cs_hit` | 925 ns | ±21 ns |
| `interest_pipeline/no_route/4` | 1.39 µs | ±4 ns |
| `interest_pipeline/no_route/8` | 1.55 µs | ±15 ns |
| | | |
| `lru/evict` | 189 ns | ±2 ns |
| `lru/evict_prefix` | 2.00 µs | ±2.20 µs |
| `lru/get_can_be_prefix` | 319 ns | ±3 ns |
| `lru/get_hit` | 210 ns | ±0 ns |
| `lru/get_miss_empty` | 138 ns | ±0 ns |
| `lru/get_miss_populated` | 186 ns | ±2 ns |
| `lru/insert_new` | 1.98 µs | ±1.44 µs |
| `lru/insert_replace` | 404 ns | ±3 ns |
| | | |
| `name/display/components/4` | 452 ns | ±2 ns |
| `name/display/components/8` | 884 ns | ±3 ns |
| `name/eq/eq_match` | 38 ns | ±0 ns |
| `name/eq/eq_miss_first` | 2 ns | ±0 ns |
| `name/eq/eq_miss_last` | 36 ns | ±0 ns |
| `name/has_prefix/prefix_len/1` | 7 ns | ±0 ns |
| `name/has_prefix/prefix_len/4` | 19 ns | ±0 ns |
| `name/has_prefix/prefix_len/8` | 36 ns | ±0 ns |
| `name/hash/components/4` | 85 ns | ±1 ns |
| `name/hash/components/8` | 163 ns | ±0 ns |
| `name/parse/components/12` | 658 ns | ±5 ns |
| `name/parse/components/4` | 233 ns | ±1 ns |
| `name/parse/components/8` | 421 ns | ±2 ns |
| `name/tlv_decode/components/12` | 287 ns | ±1 ns |
| `name/tlv_decode/components/4` | 126 ns | ±0 ns |
| `name/tlv_decode/components/8` | 198 ns | ±0 ns |
| | | |
| `pit/aggregate` | 2.27 µs | ±136 ns |
| `pit/new_entry` | 1.23 µs | ±3 ns |
| | | |
| `pit_match/hit` | 1.60 µs | ±4 ns |
| `pit_match/miss` | 1.97 µs | ±18 ns |
| | | |
| `sharded/get_hit/1` | 228 ns | ±6 ns |
| `sharded/get_hit/16` | 225 ns | ±3 ns |
| `sharded/get_hit/4` | 228 ns | ±1 ns |
| `sharded/get_hit/8` | 227 ns | ±0 ns |
| `sharded/insert/1` | 2.60 µs | ±1.61 µs |
| `sharded/insert/16` | 1.92 µs | ±1.58 µs |
| `sharded/insert/4` | 2.41 µs | ±1.73 µs |
| `sharded/insert/8` | 2.08 µs | ±1.60 µs |
| | | |
| `signing/blake3-keyed/sign_sync/100B` | 182 ns | ±0 ns |
| `signing/blake3-keyed/sign_sync/1KB` | 1.20 µs | ±2 ns |
| `signing/blake3-keyed/sign_sync/2KB` | 2.39 µs | ±9 ns |
| `signing/blake3-keyed/sign_sync/4KB` | 3.52 µs | ±1 ns |
| `signing/blake3-keyed/sign_sync/500B` | 616 ns | ±0 ns |
| `signing/blake3-keyed/sign_sync/8KB` | 4.79 µs | ±3 ns |
| `signing/blake3-plain/sign_sync/100B` | 188 ns | ±0 ns |
| `signing/blake3-plain/sign_sync/1KB` | 1.20 µs | ±0 ns |
| `signing/blake3-plain/sign_sync/2KB` | 2.39 µs | ±29 ns |
| `signing/blake3-plain/sign_sync/4KB` | 3.53 µs | ±3 ns |
| `signing/blake3-plain/sign_sync/500B` | 621 ns | ±0 ns |
| `signing/blake3-plain/sign_sync/8KB` | 4.79 µs | ±6 ns |
| `signing/ed25519/sign_sync/100B` | 20.64 µs | ±1.11 µs |
| `signing/ed25519/sign_sync/1KB` | 24.09 µs | ±85 ns |
| `signing/ed25519/sign_sync/2KB` | 27.91 µs | ±72 ns |
| `signing/ed25519/sign_sync/4KB` | 35.04 µs | ±92 ns |
| `signing/ed25519/sign_sync/500B` | 22.16 µs | ±47 ns |
| `signing/ed25519/sign_sync/8KB` | 50.13 µs | ±123 ns |
| `signing/hmac/sign_sync/100B` | 268 ns | ±0 ns |
| `signing/hmac/sign_sync/1KB` | 830 ns | ±1 ns |
| `signing/hmac/sign_sync/2KB` | 1.49 µs | ±1 ns |
| `signing/hmac/sign_sync/4KB` | 2.73 µs | ±3 ns |
| `signing/hmac/sign_sync/500B` | 512 ns | ±2 ns |
| `signing/hmac/sign_sync/8KB` | 5.26 µs | ±26 ns |
| `signing/sha256-digest/sign_sync/100B` | 146 ns | ±0 ns |
| `signing/sha256-digest/sign_sync/1KB` | 708 ns | ±0 ns |
| `signing/sha256-digest/sign_sync/2KB` | 1.36 µs | ±0 ns |
| `signing/sha256-digest/sign_sync/4KB` | 2.61 µs | ±1 ns |
| `signing/sha256-digest/sign_sync/500B` | 385 ns | ±0 ns |
| `signing/sha256-digest/sign_sync/8KB` | 5.14 µs | ±3 ns |
| | | |
| `validation/cert_missing` | 195 ns | ±0 ns |
| `validation/schema_mismatch` | 146 ns | ±0 ns |
| `validation/single_hop` | 46.25 µs | ±132 ns |
| | | |
| `validation_stage/cert_via_anchor` | 43.15 µs | ±123 ns |
| `validation_stage/disabled` | 608 ns | ±1 ns |
| | | |
| `verification/blake3-keyed/verify/100B` | 293 ns | ±0 ns |
| `verification/blake3-keyed/verify/1KB` | 1.31 µs | ±1 ns |
| `verification/blake3-keyed/verify/2KB` | 2.50 µs | ±2 ns |
| `verification/blake3-keyed/verify/4KB` | 3.63 µs | ±19 ns |
| `verification/blake3-keyed/verify/500B` | 727 ns | ±1 ns |
| `verification/blake3-keyed/verify/8KB` | 4.90 µs | ±3 ns |
| `verification/blake3-plain/verify/100B` | 299 ns | ±1 ns |
| `verification/blake3-plain/verify/1KB` | 1.32 µs | ±5 ns |
| `verification/blake3-plain/verify/2KB` | 2.50 µs | ±2 ns |
| `verification/blake3-plain/verify/4KB` | 3.64 µs | ±7 ns |
| `verification/blake3-plain/verify/500B` | 732 ns | ±0 ns |
| `verification/blake3-plain/verify/8KB` | 4.91 µs | ±10 ns |
| `verification/ed25519/verify/100B` | 41.85 µs | ±73 ns |
| `verification/ed25519/verify/1KB` | 43.94 µs | ±77 ns |
| `verification/ed25519/verify/2KB` | 45.69 µs | ±58 ns |
| `verification/ed25519/verify/4KB` | 49.42 µs | ±166 ns |
| `verification/ed25519/verify/500B` | 43.08 µs | ±129 ns |
| `verification/ed25519/verify/8KB` | 57.76 µs | ±161 ns |
| `verification/sha256-digest/verify/100B` | 146 ns | ±0 ns |
| `verification/sha256-digest/verify/1KB` | 708 ns | ±0 ns |
| `verification/sha256-digest/verify/2KB` | 1.36 µs | ±0 ns |
| `verification/sha256-digest/verify/4KB` | 2.61 µs | ±14 ns |
| `verification/sha256-digest/verify/500B` | 385 ns | ±0 ns |
| `verification/sha256-digest/verify/8KB` | 5.14 µs | ±2 ns |
<!-- BENCH_RESULTS_END -->
