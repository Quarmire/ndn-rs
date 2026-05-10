#!/usr/bin/env bash
# Witness for Phase 3 of issue #14 — browser-side WebTransport client face.
#
# Spec ref:    https://www.w3.org/TR/webtransport/
# NDNts ref:   ~/Documents/Dev/NDNts/packages/quic-transport (one NDN packet
#              per QUIC datagram, no streams).
# ndnd ref:    fw/face/http3-transport.go (mirror framing on the server).
# Witnesses:   `BrowserWebTransportFace` (in `ndn-face-webtransport-wasm`)
#              connects via xwt-wtransport on native to the Phase 2
#              `WebTransportListener`, exchanges Interest/Data over a QUIC
#              datagram, and the wire bytes match the NDNLPv2 framing.
#
# Today: FAIL (exit 1) — the `ndn-face-webtransport-wasm` crate doesn't exist
#                        and `cargo metadata` returns no match.
# After fix: PASS (exit 0) — the integration test in
#            crates/extension/ndn-face-webtransport-wasm/tests/native_xwt_roundtrip.rs
#            goes green.
set -euo pipefail

cd "$(dirname "$0")/../../.."

if ! cargo metadata --format-version=1 --no-deps 2>/dev/null \
        | grep -q '"name":"ndn-face-webtransport-wasm"'; then
    echo "FAIL: ndn-face-webtransport-wasm crate is not yet in the workspace" >&2
    exit 1
fi

cargo test -p ndn-face-webtransport-wasm --test native_xwt_roundtrip -- --nocapture
