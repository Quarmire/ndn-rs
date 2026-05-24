#!/usr/bin/env bash
# Witness — NC.24: delegated recoder verified by full cert-chain resolution.
#
# A recoded coded Data's signer key is resolved (KeyLocator → cert cache) and
# its certificate chain is walked to a configured trust anchor by the engine's
# Validator (validate_chain), plus the producer TrustSchema and the descriptor
# delegation namespace. Authorized recoder (cert chains to anchor) accepted;
# namespace mismatch and un-anchored signer rejected. Two-level chain
# (data → recoder cert → producer anchor).
#
# Witness (RUST-UNIT, feature `f2-recode-face`):
#   - recode_face::tests::chained_verify_resolves_cert_to_anchor
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
command -v cargo >/dev/null 2>&1 || { echo "SKIP: cargo missing" >&2; exit 2; }
if cargo test -p ndn-coding --features f2-recode-face --quiet -- \
        chained_verify_resolves_cert_to_anchor \
        >/tmp/nc24_witness.log 2>&1 && grep -qE "result: ok\. [1-9]" /tmp/nc24_witness.log; then
    echo "=== NC.24 PASS — recoded Data verified by cert-chain resolution to anchor ==="
    grep -E "test result|running" /tmp/nc24_witness.log | tail -n 2
    exit 0
else
    echo "=== NC.24 FAIL ==="; cat /tmp/nc24_witness.log; exit 1
fi
