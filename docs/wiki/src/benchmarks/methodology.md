# Benchmark Methodology

This page describes how ndn-rs benchmarks are collected, what is measured, and how regressions are tracked in CI.

## Framework: Criterion.rs

ndn-rs uses [Criterion.rs](https://github.com/bheisler/criterion.rs) for all microbenchmarks. Criterion provides:

- **Statistical rigor**: each benchmark runs a configurable number of samples (default: 100) after a warmup period. Results are analyzed for statistical significance before reporting changes.
- **Stable baselines**: results are persisted in `target/criterion/` across runs. Subsequent runs compare against the baseline and report whether performance changed.
- **HTML reports**: violin plots, PDFs, and linear regression charts for visual inspection.

### Default configuration

| Parameter | Value |
|-----------|-------|
| Warmup time | 3 seconds |
| Measurement time | 5 seconds |
| Sample size | 100 iterations per sample |
| Noise threshold | 1% (changes below this are not reported) |
| Confidence level | 95% |

These are Criterion defaults. Individual benchmark groups may override them (e.g., increasing measurement time for high-variance benchmarks).

## What Is Measured

### Latency (primary metric)

Each benchmark measures the **wall-clock time** to execute a single operation (e.g., one TLV decode, one CS lookup, one full pipeline pass). Criterion reports:

- **Median**: the primary metric. More robust to outliers than mean.
- **Mean**: reported alongside median for completeness.
- **Standard deviation**: indicates measurement stability.
- **MAD (Median Absolute Deviation)**: robust spread estimate.

### Throughput (derived)

Benchmarks annotated with `Throughput::Bytes(n)` or `Throughput::Elements(n)` also report throughput in bytes/sec or operations/sec. This is derived from the latency measurement.

## Isolation

Benchmarks are designed to isolate CPU cost from external factors:

### Current-thread Tokio runtime

All async benchmarks use `tokio::runtime::Builder::new_current_thread()`. This eliminates:

- Cross-thread scheduling jitter
- Work-stealing overhead
- Cache line bouncing between cores

The measured latency reflects pure single-threaded processing cost.

### No I/O

Benchmarks operate on in-memory data structures only. No network sockets, no disk I/O. Face tables are created fresh or stubbed. The CS uses in-memory `LruCs`, not `PersistentCs`.

### Pre-built wire bytes

Packet wire bytes are constructed once before the benchmark loop using `encode_interest()` / `encode_data_unsigned()`. The benchmark measures only the decode and processing path, not encoding.

### Fresh state per iteration (where applicable)

Benchmarks that measure "new entry" paths (PIT insert, CS insert) create fresh data structures per iteration or call `.clear()` to avoid measuring eviction or resizing costs mixed with the target operation.

## Hardware Notes

Benchmark results are hardware-dependent. When reporting numbers:

- State the CPU model, core count, and clock speed.
- State the memory configuration (DDR4/DDR5, speed).
- Note whether the system was idle during the run.
- Note the OS and kernel version (scheduler behavior varies).

For reproducible comparisons, always run benchmarks on the same hardware or use relative changes (% regression) rather than absolute numbers.

Criterion's statistical model accounts for some system noise, but co-located workloads (VMs, containers, browser tabs) can still skew results. For best accuracy, run on a quiet machine.

## CI Regression Tracking

### github-action-benchmark

CI runs the benchmark suite on every push to `main` and on pull requests. Results are tracked using [github-action-benchmark](https://github.com/benchmark-action/github-action-benchmark), which:

1. Parses Criterion's JSON output.
2. Stores historical data in a dedicated branch (`gh-pages` or `benchmarks`).
3. Compares the current run against the stored baseline.
4. Comments on the PR with a summary of changes.

### Alert threshold

The CI alert threshold is **10%**. If any benchmark regresses by more than 10% compared to the baseline:

- The CI check is marked as failed.
- A comment is posted on the PR identifying the regressed benchmarks.
- The PR author is expected to investigate before merging.

The 10% threshold is intentionally generous to avoid false positives from system noise while still catching meaningful regressions. Criterion's own statistical test (95% confidence) provides a secondary guard.

### Baseline management

- The baseline is updated on every merge to `main`.
- Pull request runs compare against the `main` baseline but do not update it.
- To manually update the baseline locally: `cargo bench -p ndn-engine -- --save-baseline main`.

## Running Benchmarks Locally

```bash
# Full suite
cargo bench -p ndn-engine

# Specific group
cargo bench -p ndn-engine -- "cs/"

# Compare against a saved baseline
cargo bench -p ndn-engine -- --baseline main

# Save a new baseline
cargo bench -p ndn-engine -- --save-baseline my-branch

# Open the HTML report
open target/criterion/report/index.html
```

### Tips for reliable local results

1. Close background applications (browsers, IDEs with indexing, etc.).
2. Disable CPU frequency scaling if possible (`cpupower frequency-set -g performance` on Linux).
3. Run the full suite twice -- the first run warms caches and establishes a baseline, the second gives you the comparison.
4. Use `--sample-size 300` for high-variance benchmarks if the default 100 is insufficient.
