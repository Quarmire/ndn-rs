#!/usr/bin/env bash
# Witness — the Custodian trait is wasm-safe (extracted into ndn-custodian).
#
# The Custodian trait + KeyId were extracted from ndn-identity into the
# standalone ndn-custodian crate so wasm surfaces (the dashboard, the future
# browser extension, mobile) can depend on them without ndn-identity's native
# CA/PIB graph (rusqlite / libsqlite3, which does not target wasm). This
# witness locks:
#   1. ndn-custodian builds for wasm32 (the whole point of the extraction).
#   2. Its custodian unit tests pass (behavior survived the move).
#   3. ndn-identity still re-exports the Custodian types (consumers unbroken).
#
# Pre-extraction this exits 1 (no ndn-custodian crate; ndn-identity fails wasm).
# Post-extraction it exits 0.
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

if ! command -v cargo >/dev/null 2>&1; then
    echo "SKIP: cargo missing" >&2
    exit 2
fi
if ! rustup target list --installed 2>/dev/null | grep -q wasm32-unknown-unknown; then
    echo "SKIP: wasm32-unknown-unknown target not installed" >&2
    exit 2
fi

if ! cargo build -p ndn-custodian --target wasm32-unknown-unknown \
    >/tmp/custodian_wasm.log 2>&1; then
    echo "FAIL: ndn-custodian does not build for wasm32" >&2
    tail -20 /tmp/custodian_wasm.log >&2
    exit 1
fi
echo "ok: ndn-custodian builds for wasm32"

if ! cargo test -p ndn-custodian --quiet >/tmp/custodian_test.log 2>&1; then
    echo "FAIL: ndn-custodian unit tests failed" >&2
    cat /tmp/custodian_test.log >&2
    exit 1
fi
echo "ok: ndn-custodian unit tests pass"

# ndn-identity must still re-export the trait for existing consumers.
if ! grep -q 'pub use ndn_custodian::' crates/ndn-identity/src/lib.rs; then
    echo "FAIL: ndn-identity no longer re-exports ndn-custodian" >&2
    exit 1
fi
echo "ok: ndn-identity re-exports the Custodian types"
