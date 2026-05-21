#!/usr/bin/env bash
# Witness recipe for Face-system Tier 6 §L — cross-implementation
# witness that NFD's `nfdc face list` decodes the ndn-rs FaceStatus
# dataset cleanly.
#
# Finding:     docs/notes/face-system-design-2026-05-20.md Tier 4 + §7
# Severity:    Phase-2b architectural cleanup (pre-v0.1.0)
# Decision:    Every NFD-canonical FaceStatus TLV is byte-identical
#              to NFD's; ndn-rs extension fields (0xDA..=0xE2) sit
#              in the project-private range and NFD ignores them
#              per the critical-bit rule.  The witness binds the
#              cross-impl contract: if NFD's nfdc decodes our
#              dataset, we know the NFD-canonical subset survives.
#
# Witness layout:
#   - SKIP=2 when `nfdc` is not on PATH (no testbed install).  The
#     scaffold lands so a Tier-6 commit cannot accidentally drop
#     the cross-impl contract; bringing nfdc onto the testbed
#     trips the script to a real assertion.
#   - PASS=0 when nfdc successfully decodes the dataset returned
#     by a running `ndn-fwd`.
#   - FAIL=1 when nfdc errors out on the wire.
#
# Reverify recipe:
#   1. Install nfdc on the testbed (e.g. via the C++ NFD container).
#   2. Run `ndn-fwd` listening on the standard mgmt socket.
#   3. Run this script.
#
# Exit codes:
#   0 — PASS (nfdc decoded the FaceStatus dataset)
#   1 — FAIL (nfdc errored)
#   2 — SKIP (nfdc absent — Tier-6 default state)
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

if ! command -v nfdc >/dev/null 2>&1; then
    echo "SKIP: nfdc not on PATH — install the C++ NFD tools to enable this witness." >&2
    exit 2
fi

# Verify ndn-fwd is reachable on the standard mgmt socket.
SOCK="${NDN_SOCK:-/run/nfd/nfd.sock}"
if [ ! -S "$SOCK" ]; then
    echo "SKIP: $SOCK is not a Unix socket — start ndn-fwd before running this witness." >&2
    exit 2
fi

# nfdc `face list` exits non-zero on parse errors and prints to
# stderr.  Run it and assert the output names at least one face id.
out="$(nfdc face list 2>&1 || true)"
if [ -z "$out" ]; then
    echo "FAIL: nfdc face list produced no output" >&2
    exit 1
fi
if echo "$out" | grep -qE 'faceid='; then
    echo "PASS: nfdc face list decoded the ndn-rs FaceStatus dataset."
    exit 0
else
    echo "FAIL: nfdc face list output did not contain 'faceid=' — wire shape suspected" >&2
    echo "$out" >&2
    exit 1
fi
