#!/usr/bin/env bash
# Witness — CTX.17: schema-in-context round-trips as stock LVS binary.
#
# A published context carries its trust schema as the exact
# python-ndn/NDNts-compatible LightVerSec binary (SchemaFormat=2). Encoding
# then decoding a context preserves the LVS bytes byte-for-byte, so
# cross-implementation verifiers read the identical model.
#
# Fixture: tests/fixtures/lvs_ndnd_test_model.tlv (ndnd TEST_MODEL).
# See trust-context-model-2026-05-25.md §16 (N6).
# Witness (RUST-UNIT, ndn-security, tests/trust_context_phase1.rs):
#   - ctx17_schema_roundtrips_as_stock_lvs
#
# Expected before Phase 2: FAIL (exit 1). After Phase 2: exit 0.
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
command -v cargo >/dev/null 2>&1 || { echo "SKIP: cargo missing" >&2; exit 2; }

if cargo test -p ndn-security --test trust_context_phase1 --quiet -- \
        ctx17_schema_roundtrips_as_stock_lvs \
        >/tmp/ctx17_witness.log 2>&1 && grep -qE "result: ok\. [1-9]" /tmp/ctx17_witness.log; then
    echo "=== CTX.17 PASS — schema round-trips as stock LVS binary ==="
    grep -E "test result|running" /tmp/ctx17_witness.log | tail -n 2
    exit 0
else
    echo "=== CTX.17 FAIL — schema blob not stock-LVS-clean ==="
    cat /tmp/ctx17_witness.log
    exit 1
fi
