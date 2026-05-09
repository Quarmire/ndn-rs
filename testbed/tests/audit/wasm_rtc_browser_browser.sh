#!/usr/bin/env bash
# Witness for the Phase 5 WebRTC browser↔browser headline path.
#
# Finding:     docs/notes/webrtc-design-2026-05-07.md
# Severity:    FEATURE / HEADLINE
# Spec ref:    .claude/prompts/wasm/phase5-webrtc-peer.md (deliverable 4.iii)
# Witnesses:   two browser tabs exchange Interest/Data over a
#              peer-to-peer SCTP datachannel with no NDN forwarder
#              in the path; signaling is in-test paste between
#              the two pages.
#
# Layers:
#   1. Native↔native via the webrtc-rs `WebRtcConnector`:
#         cargo test -p ndn-face-webrtc --test native_loopback
#      (Already a hard dependency of the relay test below, so this
#      script just runs the headline browser-only path.)
#   2. Native↔native via the HTTP relay:
#         cargo test -p ndn-rtc-signaling-relay --test native_via_relay
#      Runs as part of the same suite the per-crate tests target.
#   3. Browser↔browser (headline): playwright spec at
#         testbed/tests/browser/rtc_browser_browser.spec.ts
#
# The browser layer needs a live `dx serve` (or static build of
# the dioxus-demo) reachable at $DEMO_URL. The default targets
# `dx serve --release` on its default port.
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

# ── Layer 1+2 — in-process native witnesses ──────────────────────────────────

echo ">>> running native↔native WebRTC witnesses (in-process + relay)"
if ! cargo test --quiet \
        -p ndn-face-webrtc --test native_loopback \
        -p ndn-rtc-signaling-relay --test native_via_relay 2>&1; then
    echo "FAIL: native witnesses failed"
    exit 1
fi

# ── Layer 3 — browser↔browser playwright spec ────────────────────────────────

if ! command -v node >/dev/null 2>&1; then
    echo "SKIP: node not available; cannot run playwright"
    exit 2
fi

# DEMO_URL must point at a live dioxus-demo bundle. We don't try
# to boot `dx serve` from the script — that's the operator's
# responsibility (it watches sources, holds a port, and survives
# multiple test runs).
if [[ -z "${DEMO_URL:-}" ]]; then
    if curl --silent --max-time 1 "http://127.0.0.1:8080/" >/dev/null 2>&1; then
        export DEMO_URL="http://127.0.0.1:8080/"
    else
        echo "SKIP: DEMO_URL unset and no dioxus-demo bundle reachable at"
        echo "      http://127.0.0.1:8080/. Run \`cd crates/research/dioxus-demo &&"
        echo "      dx serve --release\` in another terminal first."
        exit 2
    fi
fi

cd testbed/tests/browser
npx playwright test rtc_browser_browser.spec.ts
