#!/usr/bin/env bash
# Witness for issue #14 — server-side WebTransport listener.
#
# Spec ref:    https://www.w3.org/TR/webtransport/
#              https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3
# ndnd ref:    fw/face/http3-listener.go, fw/face/http3-transport.go (datagram path)
# Witnesses:   ndn-rs ships a `WebTransportListener` that accepts an inbound
#              wtransport client session, wraps it in a `WebTransportFace`,
#              and round-trips one Interest / one Data via QUIC datagrams.
#
# Today: FAIL (exit 1) — the crate doesn't exist.
# After fix: PASS (exit 0) — the integration test in
#            crates/ndn-face-webtransport/tests/loopback.rs goes green.
set -euo pipefail

cd "$(dirname "$0")/../../.."

if ! cargo metadata --format-version=1 --no-deps 2>/dev/null \
        | grep -q '"name":"ndn-face-webtransport"'; then
    echo "FAIL: ndn-face-webtransport crate is not yet in the workspace" >&2
    exit 1
fi

cargo test -p ndn-face-webtransport --test loopback -- --nocapture
