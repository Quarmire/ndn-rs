#!/usr/bin/env bash
# Witness test for C.21 — IssuancePolicy gating on challenge attestations.
#
# Follow-up:   .claude/notes/ndn-cert-challenge-attestation-NEXT.md
# Claim:       An IssuancePolicy can gate issuance on *how* a challenge was
#              satisfied, not just its type — e.g. names under /high-trust
#              require a device-approval leaf, optionally an independently
#              *signed* one (the cross-process case). The satisfied challenge's
#              AttestationSet is exposed to IssuancePolicy via IssuanceContext.
# Witnesses:   ndn-cert policy::issuance_tests::require_attestation_* and
#              require_signed_rejects_unsigned_leaf.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi
if cargo test -p ndn-cert --lib --quiet policy::issuance_tests::require_ \
        >/tmp/c21_witness.log 2>&1; then
    echo "=== C.21 RESOLVED — IssuancePolicy gates on attestation kind/signed-ness ==="
    exit 0
else
    echo "=== C.21 EXPECTED-FAIL — attestation-gating IssuancePolicy broken ==="
    cat /tmp/c21_witness.log
    exit 1
fi
