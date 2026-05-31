#!/usr/bin/env bash
# Witness — ndn-dashboard Trust Context summary view (Identity-axis MVP, slice 1).
#
# A read-only Identity-bucket entry point framing the node's security state as
# the trust context: trusted roots (anchors), the CA, and local identities with
# cert-expiry up front. This witness locks:
#   1. The trust_context view module exists.
#   2. It is the first view in the Identity bucket.
#   3. Both shells render it.
#   4. The nav bucket mappings stay consistent (unit tests).
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

if ! command -v cargo >/dev/null 2>&1; then
    echo "SKIP: cargo missing" >&2
    exit 2
fi

DASH="crates/tooling/ndn-dashboard/src"

if [ ! -f "$DASH/views/trust_context.rs" ]; then
    echo "FAIL: trust_context view module missing" >&2
    exit 1
fi

# Identity bucket leads with Trust Context.
if ! grep -qE 'Bucket::Identity => &\[View::TrustContext' "$DASH/views/mod.rs"; then
    echo "FAIL: Trust Context is not the first Identity-bucket view" >&2
    exit 1
fi

for f in app.rs app_web.rs; do
    if ! grep -q 'trust_context::TrustContext' "$DASH/$f"; then
        echo "FAIL: $f does not render the Trust Context view" >&2
        exit 1
    fi
done

if cargo test -p ndn-dashboard --bins nav_tests --quiet \
    >/tmp/dash_trust_ctx_tests.log 2>&1; then
    cat /tmp/dash_trust_ctx_tests.log
    echo "ok: Trust Context summary view (Identity-axis slice 1)"
else
    echo "FAIL: nav bucket unit tests failed" >&2
    cat /tmp/dash_trust_ctx_tests.log >&2
    exit 1
fi
