#!/usr/bin/env bash
# Witness test for audit finding A.17 — BLAKE3 SignatureType codes 6 and 7
# documented as "experimental / pending assignment" when they are registered
# on the NDN TLV registry (issue #12, closed).
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § A.17
# Severity:    MAJOR (was); reclassified DOCS after registration confirmed.
# Spec ref:    NDN TLV SignatureType registry, issue #12 (closed);
#              docs/wiki/src/reference/blake3-signature-spec.md §0.
# Witnesses:   GREP-PROOF — no "experimental" text near BLAKE3 type-code
#              references in crates/ or docs/wiki/src/.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

fail=0

# encode/data.rs must not say "experimental" for BLAKE3 constant or method
for file in \
    "$REPO_ROOT/crates/ndn-packet/src/encode/data.rs" \
    "$REPO_ROOT/crates/tooling/ndn-tools-core/src/iperf.rs"; do
    if grep -qE "experimental" "$file" 2>/dev/null; then
        echo "FAIL: 'experimental' still present in $file"
        grep -n "experimental" "$file"
        fail=1
    else
        echo "ok: no 'experimental' in $(basename "$file")"
    fi
done

# No "not yet in the NDN Packet Format spec" language for BLAKE3 type codes
if grep -rn "not yet.*spec\|pending.*assign" \
        "$REPO_ROOT/crates" \
        "$REPO_ROOT/docs/wiki/src" \
        2>/dev/null \
        | grep -i "blake3\|DigestBlake3\|SIGINFO_DIGEST" \
        | grep -v "^Binary"; then
    echo "FAIL: 'not yet in spec' or 'pending assignment' language near BLAKE3"
    fail=1
else
    echo "ok: no 'pending assignment' near BLAKE3 type codes"
fi

# blake3-signature-spec.md must confirm registration
if grep -q "Both type codes are registered on the" \
        "$REPO_ROOT/docs/wiki/src/reference/blake3-signature-spec.md"; then
    echo "ok: blake3-signature-spec.md confirms registration"
else
    echo "FAIL: blake3-signature-spec.md does not confirm registration"
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo
    echo "=== A.17 RESOLVED — BLAKE3 type codes described as registered ==="
    exit 0
else
    echo
    echo "=== A.17 EXPECTED-FAIL — stale 'experimental' or 'pending' language ==="
    exit 1
fi
