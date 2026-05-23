#!/usr/bin/env bash
# Witness recipe for ARCH-19 — no sentinel `u64::MAX` face ids in ndn-fwd.
#
# Finding:     docs/notes/architecture-gap-inventory-2026-05-20.md § ARCH-19
# Severity:    Phase 2 architectural cleanup (pre-v0.1.0)
# Witnesses:   `binaries/ndn-fwd/src/` contains zero occurrences
#              of `FaceId(u64::MAX...)`. The old NLSR private-face
#              workaround stamped `FaceId(u64::MAX)` and
#              `FaceId(u64::MAX - 1)` on UDP sockets it deliberately
#              kept *outside* the engine table; ARCH-1 deletes those
#              faces, which closes ARCH-19 by construction.
#
# Reverify recipe: GREP-PROOF.
#
# Exit codes:
#   0 — PASS
#   1 — FAIL (sentinel face id still present)
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

FWD_DIR=binaries/ndn-fwd/src

# Match `u64::MAX` inside any `FaceId(...)` constructor — catches both
# `FaceId(u64::MAX)` and `FaceId(u64::MAX - 1)`.
hits=$(grep -rnE 'FaceId\([^)]*u64::MAX' "$FWD_DIR" || true)
if [ -n "$hits" ]; then
    echo "FAIL: sentinel u64::MAX FaceId(...) still present in $FWD_DIR:" >&2
    echo "$hits" >&2
    exit 1
fi

echo "PASS: ARCH-19 — no sentinel u64::MAX face ids in $FWD_DIR."
exit 0
