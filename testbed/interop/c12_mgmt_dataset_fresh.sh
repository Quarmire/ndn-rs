#!/usr/bin/env bash
# Follow-up witness for C.12 management interop - dataset reads must not be
# satisfied by stale cached management Data after a mutating command.
#
# Finding:     follow-up from C.12 signed management command interop
# Severity:    RELEASE-BLOCKING regression guard
# Spec ref:    NFD management status datasets are fetched with selector
#              semantics that require fresh dataset segments after updates.
# Witness:     RUST-UNIT + INTEROP-SCRIPT - first proves MgmtClient dataset
#              Interests set CanBePrefix and MustBeFresh; then registers a
#              route against Docker NFD and verifies `ndn-ctl route rib-list`
#              sees that newly-added prefix immediately.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

if ! command -v cargo >/dev/null 2>&1; then
    echo "SKIP: cargo missing" >&2
    exit 2
fi

if cargo test -p ndn-ipc --lib --quiet dataset_interest_uses_can_be_prefix_and_must_be_fresh \
        >/tmp/c12_dataset_fresh_unit.log 2>&1; then
    echo "ok: dataset Interest selector test"
else
    echo "FAIL: dataset Interest selector test"
    cat /tmp/c12_dataset_fresh_unit.log
    exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
    echo "SKIP: docker unavailable - unit witness passed" >&2
    exit 2
fi

COMPOSE="docker compose -f testbed/docker-compose.yml"
PS_OUT=$($COMPOSE ps --status running --services nfd testclient 2>/dev/null || true)
if [[ "$PS_OUT" != *"nfd"* || "$PS_OUT" != *"testclient"* ]]; then
    echo "SKIP: Docker NFD/testclient are not running - unit witness passed" >&2
    exit 2
fi

if DOCKER_OUT=$($COMPOSE exec -T testclient bash -lc '
    set -euo pipefail
    WORK=$(mktemp -d)
    cleanup() { rm -rf "$WORK"; }
    trap cleanup EXIT

    ID="/ndn/test/router1"
    PREFIX="/test/c12-fresh-rib-$(date +%s)-$$"
    PIB="$WORK/pib"

    ndn-ctl security init --name "$ID" --pib "$PIB" >/tmp/c12_fresh_init.out
    ndn-ctl --socket /run/nfd/nfd.sock \
        --identity "$ID" --pib "$PIB" \
        route add "$PREFIX" --face 1 --cost 10 >/tmp/c12_fresh_add.out

    RIB_LIST=""
    for _ in $(seq 1 20); do
        RIB_LIST=$(ndn-ctl --socket /run/nfd/nfd.sock route rib-list)
        [[ "$RIB_LIST" == *"$PREFIX"* ]] && break
        sleep 0.2
    done

    echo "PREFIX=$PREFIX"
    cat /tmp/c12_fresh_add.out
    printf "%s\n" "$RIB_LIST"

    [[ "$RIB_LIST" == *"$PREFIX"* ]]
' 2>&1); then
    printf '%s\n' "$DOCKER_OUT"
    PREFIX=$(printf '%s\n' "$DOCKER_OUT" | sed -n 's/^PREFIX=//p' | tail -1)
    echo "ok: ndn-ctl route rib-list shows freshly-added $PREFIX"
    echo
    echo "=== C.12 FOLLOW-UP RESOLVED - management dataset reads use MustBeFresh ==="
    exit 0
else
    echo "FAIL: ndn-ctl route rib-list did not show the freshly-added route"
    printf '%s\n' "$DOCKER_OUT"
    exit 1
fi
