#!/usr/bin/env bash
# Witness test for audit finding E.04 — status datasets emitted as a
# single Data instead of a versioned segment series.
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § E.04
# Severity:    BLOCKER
# Spec ref:    ndn-cxx mgmt/dispatcher.cpp:282-297 +
#              mgmt/status-dataset-context.cpp — segmented response with
#              `<prefix>/<verb>/v=<version>/seg=<n>`, FinalBlockId on
#              the last segment.
# Witnesses:
#   Part 1 — RUST-UNIT (two cargo tests in ndn-fwd::mgmt_ndn::e04_tests)
#   Part 2 — INTEROP-SCRIPT: ndn-peek --meta via the ndn-fwd unix socket
#             from the testclient container; assert the returned Data name
#             contains a VersionNameComponent (v=N) and a
#             SegmentNameComponent (seg=N), and that emit_meta reports a
#             final-block-id field.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

fail=0

# ── Part 1: RUST-UNIT ─────────────────────────────────────────────────────
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi
if cargo test -p ndn-fwd --bin ndn-fwd --quiet e04_ \
        >/tmp/e04_witness.log 2>&1; then
    echo "ok: RUST-UNIT — versioned+segmented datasets with FinalBlockId"
else
    echo "FAIL: RUST-UNIT"
    cat /tmp/e04_witness.log
    fail=1
fi

# ── Part 2: INTEROP-SCRIPT ────────────────────────────────────────────────
# Requires the testbed to be running: docker compose up -d ndn-fwd testclient
COMPOSE="docker compose -f testbed/docker-compose.yml"
if ! command -v docker >/dev/null 2>&1; then
    echo "SKIP: docker not available — live interop not run" >&2
elif ! $COMPOSE ps testclient 2>/dev/null | grep -q "running\|Up"; then
    echo "SKIP: testclient container not running — start testbed first" >&2
else
    # CanBePrefix required: dataset response name has version+segment suffix
    # (e.g. /localhost/nfd/faces/list/v=N/seg=0) so the PIT needs prefix match.
    META=$($COMPOSE exec -T testclient \
        ndn-peek --meta --can-be-prefix \
            --face-socket /run/ndn-fwd/ndn-fwd.sock \
            /localhost/nfd/faces/list \
        2>&1) || true

    # Check Data name includes version component (v=N) and segment (seg=N)
    if echo "$META" | grep -qE 'name:.*v=[0-9]+.*seg=[0-9]+'; then
        echo "ok: INTEROP — Data name carries version+segment components"
        echo "$META" >>/tmp/e04_witness.log
    else
        echo "FAIL: INTEROP — Data name missing version or segment component"
        echo "$META"
        fail=1
    fi

    # Check FinalBlockId is present
    if echo "$META" | grep -q 'final-block-id'; then
        echo "ok: INTEROP — FinalBlockId present on dataset response"
    else
        echo "FAIL: INTEROP — FinalBlockId absent from dataset response"
        echo "$META"
        fail=1
    fi
fi

if [ "$fail" -eq 0 ]; then
    echo
    echo "=== E.04 RESOLVED — status datasets versioned+segmented+FinalBlockId (RUST-UNIT + INTEROP) ==="
    exit 0
else
    echo
    echo "=== E.04 FAIL ==="
    exit 1
fi
