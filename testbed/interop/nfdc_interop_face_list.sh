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
#   - PASS=0 when reference NFD's `nfdc` successfully decodes the
#     dataset returned by a running `ndn-fwd`.
#   - FAIL=1 when nfdc errors out on the wire.
#   - SKIP=2 only when neither the Docker interop container nor a
#     local `nfdc` + ndn-fwd socket is available.
#
# Reverify recipe:
#   1. `docker compose -f testbed/docker-compose.yml up -d ndn-fwd interop`
#   2. Run this script.
#
# Exit codes:
#   0 — PASS (nfdc decoded the FaceStatus dataset)
#   1 — FAIL (nfdc errored)
#   2 — SKIP (nfdc absent — Tier-6 default state)
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

run_nfdc_face_list() {
    if command -v docker >/dev/null 2>&1; then
        local compose="docker compose -f testbed/docker-compose.yml"
        local services
        services="$($compose ps --status running --services ndn-fwd interop 2>/dev/null || true)"
        if [[ "$services" == *"ndn-fwd"* && "$services" == *"interop"* ]]; then
            $compose exec -T interop bash -lc \
                'NDN_CLIENT_TRANSPORT=unix:///run/ndn-fwd/ndn-fwd.sock nfdc face list' 2>&1
            return
        fi
    fi

    if ! command -v nfdc >/dev/null 2>&1; then
        echo "SKIP: nfdc not on PATH and Docker interop is not running." >&2
        return 2
    fi

    local sock="${NDN_SOCK:-/run/ndn-fwd/ndn-fwd.sock}"
    if [ ! -S "$sock" ]; then
        echo "SKIP: $sock is not a Unix socket — start ndn-fwd before running this witness." >&2
        return 2
    fi

    NDN_CLIENT_TRANSPORT="unix://$sock" nfdc face list 2>&1
}

# nfdc `face list` exits non-zero on parse errors and prints to
# stderr.  Run it and assert the output names at least one face id.
set +e
out="$(run_nfdc_face_list)"
rc=$?
set -e
if [ "$rc" -eq 2 ]; then
    echo "$out" >&2
    exit 2
fi
if [ "$rc" -ne 0 ]; then
    echo "FAIL: nfdc face list exited $rc" >&2
    echo "$out" >&2
    exit 1
fi
if [ -z "$out" ]; then
    echo "FAIL: nfdc face list produced no output" >&2
    exit 1
fi
if echo "$out" | grep -qE 'faceid='; then
    echo "PASS: nfdc face list decoded the ndn-rs FaceStatus dataset."
    echo "$out" | sed -n '1,8p'
    exit 0
else
    echo "FAIL: nfdc face list output did not contain 'faceid=' — wire shape suspected" >&2
    echo "$out" >&2
    exit 1
fi
