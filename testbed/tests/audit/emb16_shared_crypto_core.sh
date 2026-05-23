#!/usr/bin/env bash
# Witness for EMB-16 — shared no_std security core (no per-platform crypto dup).
#
# Severity:    embedded security baseline + anti-divergence (pre-v0.2.0)
# Spec ref:    NDN Packet Format v0.3 SignatureEd25519 (type 5), KeyLocator.
# Witnesses:
#   (a) GREP-PROOF — ndn-crypto-core (no_std) defines sign_data_ed25519 +
#       verify_data_ed25519 (the signed-Data wire ops live ONCE).
#   (b) GREP-PROOF — the embedded crate does NOT re-derive them; it re-exports
#       ndn-crypto-core (no sign_data_ed25519 defined in ndn-embedded/src).
#   (c) RUST-UNIT — ndn-crypto-core round-trips/tamper-rejects/decodes, and
#       ndn-embedded builds with `--features crypto`.
#
# Reverify recipe: GREP-PROOF + RUST-UNIT. Runs in any checkout; no Docker.
#
# Exit codes: 0 PASS · 1 FAIL · 2 SKIP (cargo missing)
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

command -v cargo >/dev/null 2>&1 || { echo "SKIP: cargo not in PATH" >&2; exit 2; }

fail=0
CORE=$(find crates -type d -name ndn-crypto-core 2>/dev/null | head -1)

# (a) the core owns the signed-Data ops.
[ -n "$CORE" ] || { echo "FAIL: ndn-crypto-core crate missing" >&2; fail=1; }
grep -rqE 'fn sign_data_ed25519' "$CORE/src" 2>/dev/null || { echo "FAIL: core lacks sign_data_ed25519" >&2; fail=1; }
grep -rqE 'fn verify_data_ed25519' "$CORE/src" 2>/dev/null || { echo "FAIL: core lacks verify_data_ed25519" >&2; fail=1; }

# (b) embedded does NOT re-derive the signed-Data wire.
if grep -rqE 'fn sign_data_ed25519' crates/ndn-embedded/src 2>/dev/null; then
    echo "FAIL: ndn-embedded re-derives sign_data_ed25519 (use the shared core)" >&2
    fail=1
fi
grep -qE 'pub use ndn_crypto_core' crates/ndn-embedded/src/lib.rs \
    || { echo "FAIL: ndn-embedded does not re-export the shared crypto core" >&2; fail=1; }

# (c) tests/build.
if [ "$fail" -eq 0 ]; then
    echo "→ cargo test -p ndn-crypto-core && cargo build -p ndn-embedded --features crypto"
    if ! cargo test --quiet -p ndn-crypto-core >/dev/null 2>&1 \
        || ! cargo build --quiet -p ndn-embedded --features crypto >/dev/null 2>&1; then
        echo "FAIL: crypto-core tests / embedded crypto build did not pass" >&2
        fail=1
    fi
fi

[ "$fail" -eq 0 ] && echo "PASS: EMB-16 — shared no_std ndn-crypto-core; embedded uses it, no crypto duplication."
exit "$fail"
