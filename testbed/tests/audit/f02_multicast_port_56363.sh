#!/usr/bin/env bash
# Audit witness — F.02.
#
# Finding:     `MulticastUdpFace::ndn_default` bound the multicast group on
#              UDP/6363 (the unicast port).  NFD uses 56363 for the
#              multicast group per `daemon/face/multicast-udp-factory.cpp`
#              constant `DEFAULT_MULTICAST_PORT`; the historical co-located
#              port broke when a unicast face and the multicast group
#              tried to bind the same address.
# Witness:     RUST-UNIT — `cargo test -p ndn-faces --lib
#              ndn_multicast_port_is_56363`.  GREP-PROOF —
#              `MulticastUdpFace::ndn_default` references
#              `NDN_MULTICAST_PORT`, not `NDN_PORT`.
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

fail=0

if ! cargo test -p ndn-faces --lib \
        net::multicast::tests::ndn_multicast_port_is_56363 \
        --quiet 2>&1 | tail -3; then
    echo "FAIL: F.02 port-constant unit test"
    fail=1
fi

# GREP-PROOF: `ndn_default` uses the new multicast-port constant.
if ! grep -q "Self::new(iface, NDN_MULTICAST_PORT, NDN_MULTICAST_V4" \
        "$REPO_ROOT/crates/spec/ndn-faces/src/net/multicast.rs"; then
    echo "FAIL: ndn_default still uses the unicast port"
    fail=1
fi

if [ "$fail" -ne 0 ]; then
    exit 1
fi

echo "=== F.02 RESOLVED — multicast UDP face defaults to 56363 ==="
