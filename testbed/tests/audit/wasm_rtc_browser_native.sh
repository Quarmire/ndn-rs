#!/usr/bin/env bash
# Witness for the Phase 5 WebRTC browser↔native path.
#
# Finding:     docs/notes/webrtc-design-2026-05-07.md
# Severity:    FEATURE / HEADLINE
# Spec ref:    .claude/prompts/wasm/phase5-webrtc-peer.md (deliverable 4.ii)
# Witnesses:   a browser tab and a native ndn-fwd peer establish
#              a peer-to-peer SCTP datachannel via the HTTP
#              signaling relay; ndn-fwd accepts the offer through
#              its [listeners.webrtc] config and registers the
#              resulting WebRtcFace with the engine.
#
# Layers (already proven independently):
#   1. tests/listener_accepts.rs — the listener's accept_one
#      surface against a real RelayServer. Cheap, runs on every
#      cargo test.
#   2. testbed/tests/browser/rtc_browser_native.spec.ts — the
#      browser side, proves the dioxus-demo panel can rendezvous
#      with a native ndn-fwd through the relay.
#
# Operator prereqs (we don't start them — long-running infra
# is the operator's responsibility):
#   - ndn-rtc-signaling-relay running at $RELAY_URL
#         (default http://127.0.0.1:8888)
#   - ndn-fwd running with [listeners.webrtc] enabled and the
#     same signaling_url, plus session_ids = ["browser-native-test"]
#     (or any value matching $SESSION_ID).
#   - dx serve running for dioxus-demo at $DEMO_URL
#         (default http://127.0.0.1:8080/).
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

# ── Layer 1 — in-process listener_accepts ────────────────────────────────────

echo ">>> running native↔native listener witness"
if ! cargo test --quiet \
        -p ndn-rtc-signaling-relay --test listener_accepts 2>&1; then
    echo "FAIL: listener_accepts witness failed"
    exit 1
fi

# ── Layer 2 — browser↔native playwright ──────────────────────────────────────

if ! command -v node >/dev/null 2>&1; then
    echo "SKIP: node not available; cannot run playwright"
    exit 2
fi

cd testbed/tests/browser

# Playwright needs @playwright/test from the local package.  When CI runs
# this witness without the audit-witnesses workflow having installed the
# browser test deps, `npx playwright` falls back to a global fetch that
# can't resolve the config's `import { test } from '@playwright/test'`.
# `npm install --silent --no-audit --no-fund` is idempotent: a fresh
# checkout populates node_modules; a cached one no-ops in ~1s.
if [ ! -d node_modules/@playwright/test ]; then
    npm install --silent --no-audit --no-fund
fi

# Playwright needs the Chromium browser binary cached under
# ~/.cache/ms-playwright.  On a fresh CI runner the audit-witnesses
# workflow has not yet downloaded it (the browser.yml workflow does, but
# this witness runs from audit-witnesses.yml).  `playwright install
# chromium` is idempotent: it's a no-op when the cache already has the
# matching version.
npx playwright install --with-deps chromium 2>&1 | grep -vE "^\s*$" | tail -5

npx playwright test rtc_browser_native.spec.ts
