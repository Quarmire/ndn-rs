#!/usr/bin/env bash
# Witness — C-COMPUTE-01: ndn-compute promoted to a first-class extension crate
# with accurate docs.
#
# Finding:   docs/notes/compute-design-2026-05-21.md § 12 (C-COMPUTE-01)
# Severity:  DOCS
# Witness:   GREP-PROOF — the crate lives under crates/extension, declares
#            extension scope, ships a README that documents the real
#            ComputeService API (not the pre-promotion async_trait `handle`
#            stub), and docs/compute.md (linked from ARCHITECTURE.md) exists.
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

CRATE=crates/extension/ndn-compute
fail=0

if [ ! -d "$CRATE" ]; then
    echo "FAIL: $CRATE does not exist (crate not promoted to extension scope)" >&2
    fail=1
fi
if [ -d crates/draft/ndn-compute ]; then
    echo "FAIL: crates/draft/ndn-compute still present (move incomplete)" >&2
    fail=1
fi
if ! grep -q 'classification = "extension"' "$CRATE/Cargo.toml" 2>/dev/null; then
    echo "FAIL: $CRATE/Cargo.toml does not declare extension scope" >&2
    fail=1
fi
# The stale pre-promotion README documented `async fn handle` on an
# `#[async_trait]` ComputeHandler returning Option<Data>; the real trait is
# `compute(&Interest) -> Result<Data, ComputeError>`.
if grep -q 'async fn handle' "$CRATE/README.md" 2>/dev/null; then
    echo "FAIL: README still documents the stale `handle` method" >&2
    fail=1
fi
if ! grep -q 'ComputeService' "$CRATE/README.md" 2>/dev/null; then
    echo "FAIL: README does not mention ComputeService" >&2
    fail=1
fi
if [ ! -f docs/compute.md ]; then
    echo "FAIL: docs/compute.md missing (dead ARCHITECTURE.md link)" >&2
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "=== C-COMPUTE-01 PASS — crate promoted, docs accurate ==="
    exit 0
fi
echo "=== C-COMPUTE-01 FAIL ==="
exit 1
