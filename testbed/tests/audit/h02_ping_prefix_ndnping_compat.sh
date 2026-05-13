#!/usr/bin/env bash
# Audit witness — H.02.
#
# Finding:     `ndn-ping` server registered the bare `--prefix` and
#              the client probed `<prefix>/ping/<seq>`.  ndn-cxx
#              `ndnping` registers `<prefix>/ping` (see
#              ndn-tools/tools/ping/server/ping-server.cpp:43) so an
#              ndn-cxx client at the same `<prefix>` would land on a
#              FIB entry the ndn-rs server never registered.
# Witness:     GREP-PROOF — server appends "ping" to the user-
#              supplied prefix before register_prefix(); default
#              `--prefix` is now `/ndn` so the registered name is
#              `/ndn/ping`, matching the ndnping convention.
# Spec ref:    ndn-tools README.md tools/ping/README.md lines 54-78.
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

CORE="crates/tooling/ndn-tools-core/src/ping.rs"
BIN="binaries/tooling/ndn-tools/src/ping.rs"

if ! grep -q 'parent.clone().append("ping")' "$CORE"; then
    echo "FAIL: server does not append 'ping' to user-supplied prefix"
    exit 1
fi
if grep -q 'default_value = "/ping"' "$BIN"; then
    echo "FAIL: ndn-ping CLI still defaults --prefix to /ping"
    exit 1
fi
if ! grep -q 'default_value = "/ndn"' "$BIN"; then
    echo "FAIL: ndn-ping CLI default --prefix not set to /ndn"
    exit 1
fi

echo "=== H.02 RESOLVED — ndn-ping registers <prefix>/ping per ndn-cxx convention ==="
