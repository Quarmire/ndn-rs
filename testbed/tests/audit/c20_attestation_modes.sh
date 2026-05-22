#!/usr/bin/env bash
# Witness test for C.20 — NDNCERT attestation composites + signed leaves.
#
# Follow-up:   .claude/notes/ndn-cert-challenge-attestation-NEXT.md (v1.5)
# Design ref:  dashboard-security-design-2026-05-13.md §5.5 (cross-process
#              device-approval), §5.6 (combinators incl. NofM).
# Claims:
#   - Composites (all-of / any-of / nofm) emit one attestation leaf per
#     satisfied sub-challenge, carrying that sub's own evidence, tagged with
#     the composite's Combinator shape.
#   - The device-approval challenge verifies an approver's signature over the
#     canonical approval statement and records it on the leaf; a forged
#     signature is denied.
# Witnesses:   ndn-cert combinator + device_approval unit tests.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

# `cargo test` takes one filter substring per run; the module-path filters
# below cover the combinator (incl. NofM + per-sub-leaf) and device-approval
# (incl. signed + forged) tests.
if {
    cargo test -p ndn-cert --lib --quiet challenge::combinator::tests &&
    cargo test -p ndn-cert --lib --quiet challenge::device_approval::tests
} >/tmp/c20_witness.log 2>&1; then
    echo "=== C.20 RESOLVED — composite + signed attestation leaves verified ==="
    exit 0
else
    echo "=== C.20 EXPECTED-FAIL — composite/signed attestation modes broken ==="
    cat /tmp/c20_witness.log
    exit 1
fi
