# bench-charts

Python script that reads Criterion benchmark output and produces SVG comparison
charts. Run the relevant benchmarks first, then run this script to generate charts
in `tools/bench-charts/charts/`.

## Usage

```sh
# Step 1: run the benchmarks
cargo bench -p ndn-engine
cargo bench -p ndn-packet
cargo bench -p ndn-store
cargo bench -p ndn-face-local
cargo bench -p ndn-security

# Step 2: generate charts
python3 tools/bench-charts/generate.py
```

Charts are written to `tools/bench-charts/charts/` as SVG files, one per benchmark
group. Requires Python 3.10+ with no additional dependencies beyond the standard
library.

## How it works

`generate.py` walks `target/criterion/` for `new/estimates.json` files, reads the
accompanying `benchmark.json` for the benchmark ID, and renders bar charts
comparing mean execution times across runs. Multiple runs (e.g. before/after a
change) can be compared by copying `target/criterion/` snapshots into separate
subdirectories.
