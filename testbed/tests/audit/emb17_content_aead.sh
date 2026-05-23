#!/usr/bin/env bash
# Witness for EMB-17 — no_std content-confidentiality baseline (ChaCha20-Poly1305).
#
# Severity:    embedded security baseline (pre-v0.2.0)
# Witnesses:
#   (a) GREP-PROOF — ndn-crypto-core exposes seal_in_place / open_in_place
#       (in-place detached AEAD, no alloc).
#   (b) RUST-UNIT — round-trips and rejects tampered ciphertext / wrong key / AAD.
# Reverify recipe: GREP-PROOF + RUST-UNIT.
# Exit codes: 0 PASS · 1 FAIL · 2 SKIP (cargo missing)
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
command -v cargo >/dev/null 2>&1 || { echo "SKIP: cargo not in PATH" >&2; exit 2; }
fail=0
CORE=$(find crates -type d -name ndn-crypto-core 2>/dev/null | head -1)
grep -rqE 'fn seal_in_place' "$CORE/src" 2>/dev/null || { echo "FAIL: no seal_in_place" >&2; fail=1; }
grep -rqE 'fn open_in_place' "$CORE/src" 2>/dev/null || { echo "FAIL: no open_in_place" >&2; fail=1; }
if [ "$fail" -eq 0 ]; then
    cargo test --quiet -p ndn-crypto-core >/dev/null 2>&1 || { echo "FAIL: crypto-core tests" >&2; fail=1; }
fi
[ "$fail" -eq 0 ] && echo "PASS: EMB-17 — no_std ChaCha20-Poly1305 content AEAD in the shared core."
exit "$fail"
