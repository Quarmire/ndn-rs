#!/usr/bin/env bash
# Witness recipe for G.04 partial — NLSR LSA TLV codec round-trip.
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § G.04
# Severity:    MAJOR (partial fix — LSA wire format only)
# Spec ref:    NLSR/src/lsa/*.{hpp,cpp}, NLSR/tests/lsa/*.cpp
#              TLV registry: NLSR/src/tlv-nlsr.hpp
# Witnesses:   RUST-UNIT — decode(C++ golden bytes) → encode == original bytes,
#              covering AdjacencyLsa (single + multi-entry), NameLsa, CoordinateLsa,
#              and negative inputs (truncated, wrong type, missing fields).
#
# Expected today: FAIL (exit 1) — test not yet present.
# After phase 1 lands: exit 0.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

fail=0

# 1. Verify the roundtrip test module exists in the source.
if grep -rq 'mod roundtrip' crates/protocols/ndn-routing/src/protocols/nlsr/lsa/mod.rs 2>/dev/null; then
    echo "ok: roundtrip test module present in lsa/mod.rs"
else
    echo "FAIL: roundtrip test module not found in lsa/mod.rs"
    fail=1
fi

# 2. Run the roundtrip tests (scoped to ndn-routing, filter on nlsr::lsa::roundtrip).
cargo test -p ndn-routing "nlsr::lsa::roundtrip" >"$REPO_ROOT/target/g04_lsa_roundtrip.log" 2>&1 || true
log="$REPO_ROOT/target/g04_lsa_roundtrip.log"
cat "$log"

if grep -qE '^test result: ok' "$log"; then
    echo "ok: nlsr::lsa::roundtrip tests pass"
elif grep -qE 'FAILED|^error' "$log"; then
    echo "FAIL: one or more nlsr::lsa::roundtrip tests failed or build failed"
    fail=1
else
    echo "FAIL: test filter produced no output (tests absent or build failed)"
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo
    echo "=== G.04 partial PASS — LSA TLV round-trip witnessed against C++ golden bytes ==="
    exit 0
else
    echo
    echo "=== G.04 partial FAIL — LSA TLV codec not yet implemented ==="
    exit 1
fi
