#!/usr/bin/env bash
# Witness test for audit findings F.01 / F.03 / F.06 — Face URI schemes
# diverge from NFD's FaceUri registry.
#
# Finding:     testbed/EXPECTED_FAILURES.md § F.01 / F.03 / F.06
# Severity:    MAJOR (mgmt FaceUri parsers reject malformed scheme strings)
# Spec ref:    NFD `wiki/FaceUri` registry —
#                udp4/udp6/tcp4/tcp6 (per IP family),
#                wsclient/wsserver (per direction),
#                wssclient/wss (TLS variants).
# Witnesses:   RUST-UNIT in `ndn-transport` (`f01_ip_face_uri_*`) and in
#              `ndn-face` (`f06_ws_direction_scheme_*`,
#              `f06_websocket_face_uri_distinguishes_client_and_server`).
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

fail=0
if cargo test -p ndn-transport --lib --quiet f01_ \
        >/tmp/f01_witness.log 2>&1; then
    echo "ok: ip_face_uri emits udp4/udp6 + tcp4/tcp6 per family"
else
    echo "FAIL: ip_face_uri scheme dispatch"; fail=1
fi
if cargo test -p ndn-face --lib --quiet f06_ \
        >>/tmp/f01_witness.log 2>&1; then
    echo "ok: WebSocket face emits wsclient/wsserver per direction"
else
    echo "FAIL: WebSocket face URI direction"; fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo
    echo "=== F.01 / F.03 / F.06 RESOLVED — FaceUri schemes match NFD registry ==="
    exit 0
else
    echo
    echo "=== F.01 / F.03 / F.06 EXPECTED-FAIL — FaceUri schemes diverge ==="
    [ -f /tmp/f01_witness.log ] && cat /tmp/f01_witness.log
    exit 1
fi
