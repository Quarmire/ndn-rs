#!/usr/bin/env bash
# Witness recipe for ARCH-6 / S11 — /localhost/<proto>/status bridge.
#
# Finding:     docs/notes/architecture-gap-inventory-2026-05-20.md § ARCH-6
# Severity:    Phase 2 architectural cleanup (pre-v0.1.0)
# Witnesses:
#   (a) GREP-PROOF — `mount_routing_status` helper exists in
#       ndn-mgmt and is exported.
#   (b) GREP-PROOF — `DvInstaller::install` calls
#       `mount_routing_status` with a DV-shape `Status` TLV provider
#       at `/localhost/nlsr/status` (wire-compat with ndnd `dvc`).
#   (c) RUST-INTEG — `crates/spec/ndn-mgmt/tests/status_bridge.rs`
#       exercises the full install → build → apply → Producer-serve
#       path: a subscriber face sends an Interest at the status
#       prefix, the producer task replies with the bytes the
#       status_provider produced.
#
# Reverify recipe: GREP-PROOF + RUST-INTEG. Runs in any checkout of
# ndn-rs; no Docker required.
#
# Note: a true live-interop witness would run `ndnd dv status`
# against an ndn-rs forwarder serving at /localhost/nlsr/status and
# parse the binary Status TLV. That's queued as Phase-2b — the
# in-process round-trip below covers the architectural primitive.
#
# Exit codes:
#   0 — PASS (status_bridge mounted; DV installer uses it; in-proc
#       round-trip green)
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
FWD=binaries/spec/ndn-fwd

# (1) The bridge helper exists + is re-exported.
check_grep 'pub fn mount_routing_status'             "$MGMT/src/status_bridge.rs" 'mount_routing_status helper'
check_grep 'pub use status_bridge::mount_routing_status' \
    "$MGMT/src/lib.rs" 'mgmt re-exports mount_routing_status'

# (2) DV installer mounts the bridge with the ndnd-shape Status TLV.
check_grep 'mount_routing_status\(builder, post_build, status_prefix' \
    "$FWD/src/installs/dv.rs" 'DvInstaller calls mount_routing_status'
check_grep '/localhost/nlsr/status'                  "$FWD/src/installs/dv.rs" 'DV status prefix matches ndnd dvc'
check_grep 'Status::encode_content|s\.encode_content' \
    "$FWD/src/installs/dv.rs" 'DV status uses Status::encode_content'

# (3) RUST-INTEG — the producer serves the status_provider bytes.
echo "→ cargo test -p ndn-mgmt --test status_bridge"
if ! cargo test --quiet -p ndn-mgmt --test status_bridge >/dev/null 2>&1; then
    echo "FAIL: cargo test -p ndn-mgmt --test status_bridge did not pass" >&2
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "PASS: ARCH-6 — /localhost/<proto>/status bridge mounted; DV installer uses it; in-proc witness green."
fi
exit "$fail"
