#!/usr/bin/env bash
# Witness test for audit findings A.02 / A.21 —
# `ParametersSha256DigestComponent` (PSDC) structural validation missing.
#
# Finding:     testbed/EXPECTED_FAILURES.md § A.02 / A.21
# Severity:    MAJOR
# Spec ref:    NDN Packet Format v0.3 `name.html#parameters-digest-component`
#              and `signed-interest.html`. ndn-cxx `interest.cpp:171-173,303,
#              692-710` (decode rejects >1 PSDC; auto-checks
#              `isParametersDigestValid` so AppParams-without-PSDC is rejected).
#              ndnd `std/ndn/spec_2022/spec.go:513-518` rejects when the *last*
#              component isn't PSDC and AppParams is present.
# Witnesses:   RUST-UNIT in `ndn-packet`:
#                - a02_decode_rejects_app_params_without_psdc
#                - a02_a21_decode_rejects_psdc_not_last
#                - a02_decode_rejects_multiple_psdc
#              Each builds a malformed wire and asserts `Interest::decode`
#              returns `PacketError::MalformedPacket`. Before the fix: all three
#              currently *accept* the malformed shapes (decode returns Ok),
#              consistent with the `_ => {}` skip pattern at the body level
#              and the explicit "no structural validation" comment at
#              `interest.rs:82-87`. After fix: the structural check at
#              decode-time rejects all three.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

fail=0
if cargo test -p ndn-packet --features std --lib --quiet a02_ \
        >/tmp/a02_witness.log 2>&1; then
    echo "ok: ndn-packet rejects malformed PSDC structure on decode"
else
    echo "FAIL: ndn-packet accepts malformed PSDC structure on decode"
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo
    echo "=== A.02 / A.21 RESOLVED — Interest::decode enforces PSDC structure ==="
    exit 0
else
    echo
    echo "=== A.02 / A.21 EXPECTED-FAIL — PSDC structural validation missing ==="
    cat /tmp/a02_witness.log
    exit 1
fi
