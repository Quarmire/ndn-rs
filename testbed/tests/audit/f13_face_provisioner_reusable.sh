#!/usr/bin/env bash
# Witness for finding F.13 — multicast face auto-provisioning (interface
# enumeration + auto-create + hotplug) is reusable across engines, not locked
# inside the ndn-fwd binary.
#
# Finding:    auto_multicast enumeration + the netlink hotplug reactor lived
#             only in binaries/ndn-fwd/src/face_setup.rs, so the mobile and
#             in-browser engines could not reuse it (ndn-mobile already
#             hand-rolls MulticastUdpFace creation). Violates the project's
#             multi-engine design principle.
# Severity:   MINOR (architecture / reuse).
# Type:       GREP-PROOF (+ build: cargo build -p ndn-fwd)
# Design:     A `FaceSink` seam in ndn-transport (the crate every engine shares)
#             lets the provisioner add/remove faces without depending on a
#             concrete engine. ForwarderEngine implements it; the provisioner
#             lives in ndn-face-native (it owns the multicast faces + iface
#             watcher) and is generic over FaceSink.
#
# What this pins:
#   1. FaceSink trait defined + exported in ndn-transport.
#   2. ForwarderEngine implements FaceSink in ndn-engine.
#   3. The reusable provisioner module exists in ndn-face-native...
#   4. ...and is config-agnostic (ndn-face-native does not depend on ndn-config).
#   5. ndn-fwd's face_setup delegates to provision:: instead of inlining the
#      watcher (the old inline netlink reactor is gone).
#
# Reverify recipe:
#   bash testbed/tests/audit/f13_face_provisioner_reusable.sh
#   cargo build -p ndn-fwd
#   Pre-fix:  exit 1 (no FaceSink / no provision module / inline watcher).
#   Post-fix: exit 0.
#
# Exit codes: 0 PASS / 1 FAIL
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

fail=0
check() { local desc="$1"; shift; if grep -qE "$@"; then echo "ok: $desc"; else echo "FAIL: $desc"; fail=1; fi; }
absent() { local desc="$1"; shift; if grep -qE "$@"; then echo "FAIL: $desc"; fail=1; else echo "ok: $desc"; fi; }

# (1) FaceSink seam in ndn-transport.
check "FaceSink trait defined"  'pub trait FaceSink' crates/ndn-transport/src/face_sink.rs
check "FaceSink re-exported"    'pub use face_sink::FaceSink' crates/ndn-transport/src/lib.rs
# (2) Engine implements it.
check "ForwarderEngine impls FaceSink" 'impl ndn_transport::FaceSink for ForwarderEngine' crates/ndn-engine/src/engine.rs
# (3) Reusable provisioner in ndn-face-native.
check "provision module present" 'pub fn provision' crates/ndn-face-native/src/provision.rs
check "hotplug watcher is reusable" 'pub fn spawn_hotplug_watcher' crates/ndn-face-native/src/provision.rs
# (4) Config-agnostic.
if grep -qE '^ndn-config' crates/ndn-face-native/Cargo.toml; then
    echo "FAIL: ndn-face-native depends on ndn-config (provisioner not config-agnostic)"
    fail=1
else
    echo "ok: ndn-face-native is config-agnostic (no ndn-config dep)"
fi
# (5) ndn-fwd delegates; the inline netlink reactor is gone.
check  "face_setup delegates to provision::" 'ndn_face_native::provision::' binaries/ndn-fwd/src/face_setup.rs
absent "old inline hotplug reactor removed from face_setup" 'hotplug: multicast ethernet face added' binaries/ndn-fwd/src/face_setup.rs

echo
if [ "$fail" -eq 0 ]; then
    echo "=== F.13 PASS — face provisioning is reusable across engines ==="
    exit 0
else
    echo "=== F.13 FAIL — provisioning still binary-locked ==="
    exit 1
fi
