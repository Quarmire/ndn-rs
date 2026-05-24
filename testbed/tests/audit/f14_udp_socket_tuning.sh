#!/usr/bin/env bash
# Witness for finding F.14 — UDP receive-path tuning.
#
# Two parts:
#   A. Socket buffers are enlarged on bind (shipped, default, cross-platform).
#   B. The recvmmsg batch path exists but is OFF by default and Linux-gated, so
#      the production receive path is unchanged until it is benchmarked on Linux.
#
# Severity:   ENHANCEMENT (throughput).
# Type:       GREP-PROOF (+ RUST-UNIT: net::udp::tests::bind_enlarges_recv_buffer)
# Rationale:  recvmmsg is unsafe FFI whose active path is the production target;
#             landing it default-on without a Linux benchmark would be reckless.
#             See .claude/notes/udp-batched-io-2026-05-24.md.
#
# Reverify recipe:
#   bash testbed/tests/audit/f14_udp_socket_tuning.sh
#   cargo test -p ndn-face-native --lib bind_enlarges_recv_buffer   # part A
#   cargo check -p ndn-face-native --features udp-recvmmsg \
#       --target x86_64-unknown-linux-gnu                            # part B compiles
#
# Exit codes: 0 PASS / 1 FAIL
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

NF="crates/ndn-face-native"
fail=0
check()  { local d="$1"; shift; if grep -qE "$@"; then echo "ok: $d"; else echo "FAIL: $d"; fail=1; fi; }

# A. Buffer tuning applied on both UDP faces.
check "sockopt helper exists"            'fn tune_datagram_socket' "$NF/src/net/sockopt.rs"
check "udp face tunes on bind"           'sockopt::tune_datagram_socket' "$NF/src/net/udp.rs"
check "multicast face tunes on bind"     'sockopt::tune_datagram_socket' "$NF/src/net/multicast.rs"

# B. recvmmsg batch path present, Linux-gated, OFF by default.
check "udp-recvmmsg feature declared"    'udp-recvmmsg = ' "$NF/Cargo.toml"
check "recvmmsg module Linux+feature gated" 'cfg\(all\(feature = "udp-recvmmsg", target_os = "linux"\)\)' "$NF/src/net/recvmmsg.rs"
# The default feature set must NOT pull in udp-recvmmsg.
default_line=$(grep -E '^default = ' "$NF/Cargo.toml" || true)
if echo "$default_line" | grep -q "udp-recvmmsg"; then
    echo "FAIL: udp-recvmmsg is in the default feature set (must stay opt-in)"; fail=1
else
    echo "ok: udp-recvmmsg is OFF by default ($default_line)"
fi
# The single-recv path remains the default (non-feature) receive path.
check "default single-recv path retained" 'fn recv_bytes_single' "$NF/src/net/udp.rs"

echo
if [ "$fail" -eq 0 ]; then
    echo "=== F.14 PASS — UDP buffers tuned; recvmmsg batch path opt-in + Linux-gated ==="
    exit 0
else
    echo "=== F.14 FAIL ==="
    exit 1
fi
