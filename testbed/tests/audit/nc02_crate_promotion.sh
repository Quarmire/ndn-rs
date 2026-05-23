#!/usr/bin/env bash
# Witness — NC.02: ndn-coding promoted to a first-class extension crate
# with the ergonomic endpoint API and accurate docs.
#
# Finding:   docs/notes/coding-design-2026-05-22.md (first-class treatment)
# Severity:  DOCS
# Witness:   GREP-PROOF — the crate lives under crates/extension, declares
#            extension scope, exposes the CodedProducer / CodedFetcher
#            endpoint API, ships a README that documents it (not the stale
#            "skeleton, no logic" framing), and docs/coding.md (linked from
#            ARCHITECTURE.md) exists.
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

CRATE=crates/ndn-coding
fail=0

if [ ! -d "$CRATE" ]; then
    echo "FAIL: $CRATE does not exist (crate not promoted to extension scope)" >&2
    fail=1
fi
if [ -d crates/draft/ndn-coding ]; then
    echo "FAIL: crates/draft/ndn-coding still present (move incomplete)" >&2
    fail=1
fi
if ! grep -q 'classification = "extension"' "$CRATE/Cargo.toml" 2>/dev/null; then
    echo "FAIL: $CRATE/Cargo.toml does not declare extension scope" >&2
    fail=1
fi
if [ ! -f "$CRATE/src/endpoint.rs" ]; then
    echo "FAIL: endpoint module (CodedProducer / CodedFetcher) missing" >&2
    fail=1
fi
if ! grep -q 'CodedProducer' "$CRATE/src/endpoint.rs" 2>/dev/null \
        || ! grep -q 'CodedFetcher' "$CRATE/src/endpoint.rs" 2>/dev/null; then
    echo "FAIL: endpoint module does not define CodedProducer/CodedFetcher" >&2
    fail=1
fi
# The stale pre-promotion README/lib framed the crate as a logic-free skeleton.
if grep -qi 'skeleton, no logic' "$CRATE/README.md" 2>/dev/null; then
    echo "FAIL: README still frames the crate as a logic-free skeleton" >&2
    fail=1
fi
if ! grep -q 'CodedProducer\|CodedFetcher' "$CRATE/README.md" 2>/dev/null; then
    echo "FAIL: README does not document the endpoint API" >&2
    fail=1
fi
if [ ! -f docs/coding.md ]; then
    echo "FAIL: docs/coding.md missing (dead ARCHITECTURE.md link)" >&2
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "=== NC.02 PASS — crate promoted, endpoint API present, docs accurate ==="
    exit 0
fi
echo "=== NC.02 FAIL ==="
exit 1
