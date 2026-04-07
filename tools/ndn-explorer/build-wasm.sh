#!/usr/bin/env bash
# Build the ndn-wasm crate and place the output in tools/ndn-explorer/wasm/.
# Run from the repository root:
#
#   bash tools/ndn-explorer/build-wasm.sh
#
# Requires wasm-pack (https://rustwasm.github.io/wasm-pack/):
#   cargo install wasm-pack

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT_DIR="$REPO_ROOT/tools/ndn-explorer/wasm"

echo "==> Building ndn-wasm for wasm32-unknown-unknown …"
cd "$REPO_ROOT"

wasm-pack build crates/ndn-wasm \
  --target web \
  --out-dir "$OUT_DIR" \
  --out-name ndn_wasm \
  --no-typescript \
  --release

echo "==> Output written to: $OUT_DIR"
echo "    $(ls -1 "$OUT_DIR")"
echo ""
echo "Open tools/ndn-explorer/index.html in a browser — the WASM badge in the"
echo "nav will show 'WASM ✓' confirming the Rust simulation is active."
