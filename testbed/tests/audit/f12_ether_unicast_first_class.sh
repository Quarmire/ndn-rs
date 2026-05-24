#!/usr/bin/env bash
# Witness for finding F.12 — Ethernet *unicast* faces are first-class:
# configurable (TOML), runtime-creatable (NFD faces/create), and self-
# describing (remote/local URI), at parity with udp4:// faces.
#
# Finding:    NamedEtherFace was Rust-API-only — no FaceConfig variant, no
#             ether:// arm in /localhost/nfd/faces/create, and no remote_uri/
#             local_uri (so faces/list showed it blank). udp4:// had all three.
# Severity:   MINOR (ergonomics / operability parity gap).
# Type:       GREP-PROOF + RUST-UNIT
# Spec refs:  NFD nfdc face create accepts ether://[<mac>]/<iface>
#             (NFD tools/nfdc, ndn-cxx ethernet FaceUri). Peer MAC is
#             explicit; neighbor discovery remains a separate path.
#
# What this pins:
#   1. ndn-config exposes a `kind = "ether"` FaceConfig with `peer-mac`.
#   2. validate_face_config validates the peer-mac shape.
#   3. faces/create dispatches `ether://` (gated on the `l2` feature).
#   4. All three NamedEtherFace impls emit `ether://[..]/..` remote URIs.
#   5. The pure URI parser has unit coverage (parse_ether_uri).
#
# Reverify recipe:
#   bash testbed/tests/audit/f12_ether_unicast_first_class.sh
#   cargo test -p ndn-mgmt --features l2 --lib ether_uri   # the RUST-UNIT
#   Pre-fix:  exit 1 (no ether config variant / no ether:// arm / no URIs).
#   Post-fix: exit 0.
#
# Exit codes: 0 PASS / 1 FAIL
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

CFG="crates/ndn-config/src/config.rs"
FACES="crates/ndn-mgmt/src/modules/faces.rs"
L2_DIR="crates/ndn-face-native/src/l2"

fail=0
check() { # <description> <grep-args...>
    local desc="$1"; shift
    if grep -qE "$@"; then
        echo "ok: $desc"
    else
        echo "FAIL: $desc"
        fail=1
    fi
}

# (1) FaceConfig::Ether with peer-mac.
check "FaceConfig has an Ether variant"        'Ether \{' "$CFG"
check "Ether config carries peer-mac"          'rename = "peer-mac"' "$CFG"
# (2) Config validation of the peer MAC shape.
check "validate_face_config validates ether peer-mac" 'ether face peer-mac must be' "$CFG"
# (3) faces/create ether:// dispatch + handler.
check "faces/create dispatches ether://"       'uri.starts_with\("ether://"\)' "$FACES"
check "faces_create_ether handler present"     'fn faces_create_ether' "$FACES"
check "ether:// arm gated on l2 feature"        'feature = "l2"' "$FACES"
# (4) remote_uri on all three NamedEtherFace impls.
for f in ether.rs ether_macos.rs ether_windows.rs; do
    check "$f NamedEtherFace emits remote_uri" 'ether://\[\{\}\]/\{\}' "$L2_DIR/$f"
done
# (5) pure parser exists for unit coverage.
check "parse_ether_uri pure helper present"    'fn parse_ether_uri' "$FACES"

echo
if [ "$fail" -eq 0 ]; then
    echo "=== F.12 PASS — Ethernet unicast is config + mgmt + URI first-class ==="
    exit 0
else
    echo "=== F.12 FAIL — Ethernet unicast parity gap ==="
    exit 1
fi
