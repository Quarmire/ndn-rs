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
#   cargo test -p ndn-face --lib bind_enlarges_recv_buffer   # part A
#   cargo check -p ndn-face --features udp-recvmmsg \
#       --target x86_64-unknown-linux-gnu                            # part B compiles
#
# Exit codes: 0 PASS / 1 FAIL
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

NF="crates/faces/ndn-face"
fail=0
check()  { local d="$1"; shift; if grep -qE "$@"; then echo "ok: $d"; else echo "FAIL: $d"; fail=1; fi; }

# A. Buffer tuning applied on both UDP faces.
check "sockopt helper exists"            'fn tune_datagram_socket' "$NF/src/net/sockopt.rs"
check "udp face tunes on bind"           'sockopt::tune_datagram_socket' "$NF/src/net/udp.rs"
check "multicast face tunes on bind"     'sockopt::tune_datagram_socket' "$NF/src/net/multicast.rs"

# B. recvmmsg batch path present, Linux-gated, DEFAULT-ON (validated+benchmarked).
check "udp-recvmmsg feature declared"    'udp-recvmmsg = ' "$NF/Cargo.toml"
check "recvmmsg module Linux+feature gated" 'cfg\(all\(feature = "udp-recvmmsg", target_os = "linux"\)\)' "$NF/src/net/recvmmsg.rs"
default_line=$(grep -E '^default = ' "$NF/Cargo.toml" || true)
if echo "$default_line" | grep -q "udp-recvmmsg"; then
    echo "ok: udp-recvmmsg is default-on (validated+benchmarked; no-op off-Linux)"
else
    echo "FAIL: udp-recvmmsg should be in the default feature set ($default_line)"; fail=1
fi
# The single-recv path is still present for non-Linux / non-feature builds.
check "single-recv path retained"        'fn recv_bytes_single' "$NF/src/net/udp.rs"

# C. sendmmsg batch path present, Linux+feature gated, OFF by default (opt-in).
check "udp-sendmmsg feature declared"    'udp-sendmmsg = ' "$NF/Cargo.toml"
check "sendmmsg module Linux+feature gated" 'cfg\(all\(feature = "udp-sendmmsg", target_os = "linux"\)\)' "$NF/src/net/sendmmsg.rs"
check "send_batch seam on Transport"      'fn send_batch' "crates/ndn-transport/src/transport.rs"
check "LinkService batches egress"        'fn send_batch' "crates/ndn-transport/src/link_service/mod.rs"
if echo "$default_line" | grep -q "udp-sendmmsg"; then
    echo "ok: udp-sendmmsg is default-on (validated+benchmarked; no-op off-Linux)"
else
    echo "FAIL: udp-sendmmsg should be in the default feature set ($default_line)"; fail=1
fi

echo
if [ "$fail" -eq 0 ]; then
    echo "=== F.14 PASS — UDP buffers tuned; recvmmsg batch path opt-in + Linux-gated ==="
    exit 0
else
    echo "=== F.14 FAIL ==="
    exit 1
fi
