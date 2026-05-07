#!/usr/bin/env bash
# Witness test for audit finding C.04 — BLAKE3 SignatureType codes 6/7
# officially registered on the NDN TLV registry.
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § C.04
# Severity:    MAJOR (was); now DOCS
# Spec ref:    NDN TLV SignatureType registry issue #12 (closed);
#              ndn-cxx/ndn-cxx/security/impl/openssl-helper.hpp —
#              see also docs/wiki/src/reference/blake3-signature-spec.md
# Witnesses:   GREP-PROOF — signer.rs comment says "registered", not
#              "reserved"; blake3-signature-spec.md says "registered".
#              Any remaining "experimental" language for type codes 6/7
#              is a failure.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"

fail=0

# signer.rs must say "registered" not "reserved" for the BLAKE3 type codes
if grep -q "Both are registered on the NDN TLV SignatureType registry" \
    "$REPO_ROOT/crates/engine/ndn-security/src/signer.rs"; then
    echo "ok: signer.rs uses 'registered'"
else
    echo "FAIL: signer.rs still says 'reserved' or lacks 'registered' comment"
    fail=1
fi

# blake3-signature-spec.md must say "registered"
if grep -q "Both type codes are registered on the" \
    "$REPO_ROOT/docs/wiki/src/reference/blake3-signature-spec.md"; then
    echo "ok: blake3-signature-spec.md uses 'registered'"
else
    echo "FAIL: blake3-signature-spec.md does not say 'registered'"
    fail=1
fi

# No "experimental" language for type codes 6 or 7
if grep -rn "experimental.*\(type 6\|type 7\|6.*7\)" \
    "$REPO_ROOT/crates/engine/ndn-security/src/" \
    "$REPO_ROOT/docs/wiki/src/reference/blake3-signature-spec.md" 2>/dev/null \
    | grep -v "^Binary file"; then
    echo "FAIL: found 'experimental' language for BLAKE3 type codes"
    fail=1
else
    echo "ok: no 'experimental' language for BLAKE3 type codes"
fi

if [ "$fail" -eq 0 ]; then
    echo
    echo "=== C.04 RESOLVED — BLAKE3 type codes described as registered ==="
    exit 0
else
    echo
    echo "=== C.04 EXPECTED-FAIL — stale 'reserved' or 'experimental' language present ==="
    exit 1
fi
