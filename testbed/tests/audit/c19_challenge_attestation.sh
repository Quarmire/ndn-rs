#!/usr/bin/env bash
# Witness test for C.19 — NDNCERT challenge attestations.
#
# Follow-up:   .claude/notes/ndn-cert-challenge-attestation-NEXT.md
# Spec ref:    Certificate Format v2 SignatureInfo->AdditionalDescription
#              (TLV 0x0102), the non-critical extension point ndn-cxx uses
#              for cert metadata (security/v2/additional-description.cpp).
# Claim:       A CA built with `emit_attestations(true)` issues certs whose
#              signed region carries a parseable AttestationSet recording how
#              the challenge was satisfied; the default CA embeds none.
# Witnesses:   ndn-cert `attestation_emission` integration tests, which drive
#              a full NEW->CHALLENGE enrollment and parse the served cert.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi
if cargo test -p ndn-cert --test attestation_emission --quiet \
        >/tmp/c19_witness.log 2>&1; then
    echo "=== C.19 RESOLVED — opt-in challenge attestations round-trip in issued certs ==="
    exit 0
else
    echo "=== C.19 EXPECTED-FAIL — attestation embedding/parsing broken ==="
    cat /tmp/c19_witness.log
    exit 1
fi
