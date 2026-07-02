#!/usr/bin/env bash
# Witness recipe for audit finding G.05 — ndn-dv interop with ndnd's
# `dv run` daemon (the reference implementation).
#
# Finding:     testbed/EXPECTED_FAILURES.md § G.05
# Severity:    MAJOR / BLOCKED-BY-INTEROP
# Spec:        ~/Documents/Dev/ndnd/dv/SPEC.md
#
# What this script tests:
#   1. Boot ndn-fwd-dv (ndn-rs with [routing.dv]) at 172.30.0.40.
#   2. Boot ndnd-dv (ndnd's `dv run`, "insecure" mode) at 172.30.0.41.
#   3. Each side declares the other as its only static DV neighbour.
#   4. After ≤ 60 s of Adv Sync chatter, ndnd-dv's status report must
#      show `nNeighbors ≥ 1` and a non-zero NRibEntries count — proof
#      that it accepted ndn-rs's signed Sync Interests + Adv Data and
#      installed `/ndn/r-rs` into its destination-vector RIB.
#   5. ndn-fwd-dv's logs must show "Adv Data applied to RIB peer=/ndn/r-ndnd",
#      proof the reverse leg works (ndn-rs parsed ndnd's Adv Data wire).
#
# Docker host:
#   This script calls "docker compose …" with no --host or --context
#   flags. The calling environment supplies the Docker endpoint (see
#   `feedback_remote_docker_host`: SSH alias
#   `main.Docker.peterminhanle.coder` for the developer-owned host).
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP (docker not available)
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

COMPOSE="docker compose -f testbed/docker-compose.yml --profile dv-interop"
TRANSCRIPT_DIR="testbed/tests/audit/transcripts"
TXT_FILE="$TRANSCRIPT_DIR/g05_dv_interop_after.txt"
TIMEOUT=60
POLL=3

if ! command -v docker &>/dev/null; then
    echo "SKIP: docker not available"
    exit 2
fi

mkdir -p "$TRANSCRIPT_DIR"

cleanup() {
    echo ""
    echo "--- cleanup: stopping dv-interop services ---"
    $COMPOSE stop ndn-fwd-dv ndnd-dv 2>/dev/null || true
    $COMPOSE rm -f ndn-fwd-dv ndnd-dv 2>/dev/null || true
}
trap cleanup EXIT

echo "--- bringing up dv-interop topology ---"
$COMPOSE up -d ndn-fwd-dv ndnd-dv

echo "--- waiting up to ${TIMEOUT}s for convergence (poll every ${POLL}s) ---"
deadline=$(( $(date +%s) + TIMEOUT ))
rs_ok=0
ndnd_n_neighbors=0
ndnd_n_rib=0
ndnd_status_raw=""
while (( $(date +%s) < deadline )); do
    # ndn-rs side: log grep for the "Adv Data applied" line that
    # `fetch_and_apply_adv` emits when ndnd's Adv Data validates,
    # decodes as Advertisement TLV, and applies to DvRib.
    if docker logs ndn-fwd-dv 2>&1 \
        | grep -qE 'Adv Data applied to RIB.*peer="?/ndn/r-ndnd"?'; then
        rs_ok=1
    fi

    # ndnd side: query its DV mgmt prefix `/localhost/nlsr/status`
    # via `ndnd dv status`, which pretty-prints nNeighbors + nRibEntries.
    if ndnd_status_raw=$(docker exec ndnd-dv /ndnd dv status 2>&1); then
        # `ndnd dv status` prints `key=value` with leading spaces, e.g.
        # `      nNeighbors=1`. Accept either `=` or whitespace between
        # key and value to tolerate future formatting changes.
        ndnd_n_neighbors=$(echo "$ndnd_status_raw" \
            | grep -oE 'nNeighbors[=[:space:]]+[0-9]+' \
            | grep -oE '[0-9]+$' || echo 0)
        ndnd_n_rib=$(echo "$ndnd_status_raw" \
            | grep -oE 'nRibEntries[=[:space:]]+[0-9]+' \
            | grep -oE '[0-9]+$' || echo 0)
    fi

    echo "  rs_ok=$rs_ok ndnd_nNeighbors=$ndnd_n_neighbors ndnd_nRibEntries=$ndnd_n_rib"

    if (( rs_ok == 1 )) \
        && (( ndnd_n_neighbors >= 1 )) \
        && (( ndnd_n_rib >= 1 )); then
        echo "PASS: both sides converged"
        {
            echo "g05 dv-interop witness — PASS"
            echo "  ndn-rs (ndn-fwd-dv) Adv Data applied to RIB: yes"
            echo "  ndnd (ndnd-dv) status:"
            echo "$ndnd_status_raw" | sed 's/^/    /'
        } > "$TXT_FILE"
        exit 0
    fi
    sleep "$POLL"
done

# ── Failure path: dump diagnostic transcripts ─────────────────────────────
echo "FAIL: convergence did not complete inside ${TIMEOUT}s"
{
    echo "g05 dv-interop witness — FAIL"
    echo
    echo "Last ndnd dv status:"
    echo "$ndnd_status_raw" | sed 's/^/    /'
    echo
    echo "Tail of ndn-fwd-dv logs:"
    docker logs --tail 80 ndn-fwd-dv 2>&1 | sed 's/^/    /' || true
    echo
    echo "Tail of ndnd-dv logs:"
    docker logs --tail 80 ndnd-dv 2>&1 | sed 's/^/    /' || true
} | tee "$TXT_FILE"
exit 1
