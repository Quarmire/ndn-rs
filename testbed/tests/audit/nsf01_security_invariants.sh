#!/usr/bin/env bash
# Witness test for the O4 gate — preserving NDNSF's security invariants across
# the ndn-rs reimplementation.
#
# Finding:     O4 (service-layer.md §9). A reimplementation silently loses its
#              audited properties unless the invariants are extracted into
#              witnesses. This pins the subset of NDNSF's SECURITY_INVARIANTS.md
#              that maps to shipped ndn-rs primitives (content-key + capability).
# Severity:    SECURITY / gate
# Spec ref:    docs/specs/ndnsf-invariants.md (the full catalogue + the gate:
#              ndn-nacabe / ndn-ndnsf MUST NOT land until the invariants mapped
#              to them — marked ⛔ — also have passing witnesses).
# Witnesses:   RUST-INTEGRATION in `ndn-security`,
#              tests/ndnsf_invariants_witness.rs:
#                - nsf_t2_capability_expires_after_window   (token TTL boundary)
#                - nsf_t4_expired_capability_rejected        (expired token fails)
#                - nsf_t5_unknown_grantee_rejected           (unknown token fails)
#                - nsf_f3_decryption_failure_yields_no_plaintext (no plaintext leak)
#                - nsf_f4_malformed_payload_rejected_at_decode   (no partial state)
#                - nsf_f5_primitives_fail_closed             (negative paths closed)
#
# Expected today: PASS (exit 0) for the primitive-level invariants. The
# protocol-level invariants (⛔ in the catalogue) gate the future ndn-nacabe /
# ndn-ndnsf layers and are not yet runnable.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi
if ! cargo metadata --no-deps --format-version 1 2>/dev/null | grep -q '"name":"ndn-security"'; then
    echo "SKIP: ndn-security crate not present" >&2
    exit 2
fi

if cargo test -p ndn-security --test ndnsf_invariants_witness --quiet \
        >/tmp/nsf01_invariants.log 2>&1; then
    echo "ok: NDNSF primitive-level invariants held (token TTL/expiry/binding, fail-closed)"
    echo
    echo "=== NDNSF security invariants (primitive subset): CONTRACT HELD ==="
    exit 0
else
    echo "FAIL: NDNSF invariant witness failed"
    cat /tmp/nsf01_invariants.log 2>/dev/null || true
    echo
    echo "=== NDNSF invariant witness FAILED ==="
    exit 1
fi
