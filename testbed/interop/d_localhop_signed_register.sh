#!/usr/bin/env bash
# Witness for the /localhop signed prefix-registration path.
#
# Finding:     docs/notes/localhop-prefix-registration-2026-05-09.md
# Severity:    FEATURE / TESTBED-PARITY
# Spec ref:    NFD daemon/mgmt/rib-manager.cpp:340-355
#              (LOCALHOP_TOP_PREFIX, m_localhopValidator)
# Witnesses:   end-to-end signed `/localhop/nfd/rib/register` from a
#              cert-authenticated requester reaches the management
#              handler, validates against the configured trust
#              anchor, and installs a route in the FIB.
#
# Two layers:
#   1. In-process: `cargo test -p ndn-fwd localhop` runs the D.01-D.03
#      witnesses against the management handler directly. Fast, no
#      Docker required, runs in CI.
#   2. End-to-end: the dioxus-demo browser flow exercises the same
#      path over a real WebTransport face and confirms the FIB
#      update is observable via `nfdc route list`. Currently a
#      manual run; this script gates the in-process layer and
#      points at the manual recipe.
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

# ── Layer 1 — in-process unit witnesses (D.01 / D.02 / D.03) ─────────────────

echo ">>> running in-process /localhop authorization witnesses"
if ! cargo test -p ndn-fwd --quiet -- --test-threads=1 \
        d01_localhop_unsigned_rejected \
        d02_localhop_signed_accepted \
        d03_localhop_disabled_without_anchor 2>&1; then
    echo "FAIL: in-process witnesses failed"
    exit 1
fi

# ── Layer 2 — end-to-end browser/demo recipe ─────────────────────────────────
#
# The dioxus-demo flow is the load-bearing E2E witness. To re-run it
# manually (Docker not required, just a host with rust + dx + Chrome):
#
#   1. Boot the demo forwarder with the embedded /demo/CA:
#         sudo target/release/ndn-fwd -c testbed/configs/dioxus-demo-fwd.toml
#      It prints a copy-paste-ready URL like
#         https://127.0.0.1:4433/ndn?cert=<spki-hash>
#   2. In a second terminal:
#         cd crates/tooling/dioxus-demo
#         dx serve --release
#   3. Open the printed URL in Chrome. The browser console should
#      log "NDNCERT issued cert: …" then "signed /localhop register
#      Interest sent".
#   4. Confirm the route is installed:
#         sudo target/release/ndn-ctl --socket /run/ndn-fwd/ndn-fwd.sock route list
#      Expect a row like
#         /demo/<random>    2   0
#      next to /demo and /demo/CA.
#   5. Round-trip the in-browser counter from a host peek:
#         ndn-tools peek --face-uri udp://127.0.0.1:6363 /demo/<random>/counter
#      The counter increments on every call.
#
# This is documented as a recipe rather than executed inline because
# Chrome WebTransport drives the WT face; automating headless-Chrome
# WT is a separate testbed scope and not yet wired in this repo.

echo "PASS: in-process /localhop witnesses; see script body for the manual E2E recipe"
exit 0
