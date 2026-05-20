#!/usr/bin/env bash
# Witness recipe for ARCH-7 / S15 — NDNSD-shape service-discovery
# adapter.
#
# Finding:     docs/notes/architecture-gap-inventory-2026-05-20.md § ARCH-7
# Severity:    Phase 2 architectural cleanup (pre-v0.1.0)
# Witnesses:
#   (a) GREP-PROOF — `ndnsd_adapter` module exists in ndn-mgmt;
#       `mount_ndnsd_discovery` helper + `NdnsdServiceInfo` type are
#       publicly exported.
#   (b) RUST-INTEG — `crates/spec/ndn-mgmt/tests/ndnsd_adapter.rs`
#       round-trips two published service records through the
#       persistent Producer at `<root>/NDNSD/discovery`: subscriber
#       Interest goes out, Data Content matches the encoded list.
#
# Reverify recipe: GREP-PROOF + RUST-INTEG. No NDNSD reference impl
# exists in ndnd / ndn-cxx / NFD today, so the witness is in-proc
# only (within ndn-rs).
#
# Exit codes:
#   0 — PASS (adapter mounted; round-trip witness green)
#   1 — FAIL
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

fail=0

check_grep() {
    local pattern="$1" path="$2" label="$3"
    if ! grep -rqnE "$pattern" "$path"; then
        echo "FAIL: $label — \"$pattern\" not found under $path" >&2
        fail=1
    fi
}

MGMT=crates/spec/ndn-mgmt

# (1) Adapter primitive lives in ndn-mgmt + is re-exported.
check_grep 'pub fn mount_ndnsd_discovery'     "$MGMT/src/ndnsd_adapter.rs" 'mount_ndnsd_discovery helper'
check_grep 'pub struct NdnsdServiceInfo'      "$MGMT/src/ndnsd_adapter.rs" 'NdnsdServiceInfo type'
check_grep 'pub use ndnsd_adapter::\{NdnsdServiceInfo, encode_service_list, mount_ndnsd_discovery\}' \
    "$MGMT/src/lib.rs" 'mgmt re-exports the NDNSD adapter API'

# (2) Adapter mounts under the NDNSD layout (`/NDNSD/discovery`).
check_grep 'NDNSD' "$MGMT/src/ndnsd_adapter.rs" 'NDNSD prefix component'
check_grep 'discovery' "$MGMT/src/ndnsd_adapter.rs" 'discovery sub-component'

# (3) RUST-INTEG — the publish/browse round-trip is green.
echo "→ cargo test -p ndn-mgmt --test ndnsd_adapter"
if ! cargo test --quiet -p ndn-mgmt --test ndnsd_adapter >/dev/null 2>&1; then
    echo "FAIL: cargo test -p ndn-mgmt --test ndnsd_adapter did not pass" >&2
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "PASS: ARCH-7 — NDNSD adapter mounted; in-proc round-trip witness green."
fi
exit "$fail"
