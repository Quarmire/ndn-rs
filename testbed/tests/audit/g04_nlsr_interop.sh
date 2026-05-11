#!/usr/bin/env bash
# Witness recipe for audit finding G.04 — NLSR interop with C++ NLSR.
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § G.04
# Severity:    MAJOR / BLOCKED-BY-INTEROP
#
# What this script tests:
#   1. Stand up ndn-fwd-nlsr (ndn-rs with [routing.nlsr]) at 172.30.0.30.
#   2. Stand up nfd-nlsr (NFD sidecar) + nlsr-cxx (C++ NLSR) at 172.30.0.13/14.
#   3. Both routers peer over UDP.
#   4. ndn-fwd-nlsr advertises /test/r2/data.
#   5. nlsr-cxx advertises /test/r1/data.
#   6. After ≤ 90 s, each side's RIB must contain the other's prefix.
#   7. Wire traffic is captured via tshark and saved as transcripts.
#
# Docker host:
#   This script calls "docker compose …" with no --host or --context flags.
#   The calling environment supplies the Docker endpoint:
#     - GitHub Actions: uses the default Docker daemon.
#     - Developer machines: set DOCKER_HOST or "docker context use <name>"
#       before running.  Example for a remote host:
#         export DOCKER_HOST=ssh://main.Docker.peterminhanle.coder
#   Do NOT bake host-specific values into this file.
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP (docker not available)
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

COMPOSE="docker compose -f testbed/docker-compose.yml"
TRANSCRIPT_DIR="testbed/tests/audit/transcripts"
PCAP_FILE="$TRANSCRIPT_DIR/g04_nlsr_interop_after.pcap"
TXT_FILE="$TRANSCRIPT_DIR/g04_nlsr_interop_after.txt"
NDN_FWD_NLSR_PREFIX="/test/r2/data"
NLSR_CXX_PREFIX="/test/r1/data"
# C++ NLSR enforces hello-interval >= 30 (conf-file-processor). With the
# minimum hello-interval, first adjacency takes up to ~30s, then LSA
# propagation needs another ~30-60s. 180s budget gives convergence
# headroom on slow runners.
TIMEOUT=180
POLL=5

# ── Infra availability check ──────────────────────────────────────────────────

if ! command -v docker &>/dev/null; then
    echo "SKIP: docker not available"
    exit 2
fi

mkdir -p "$TRANSCRIPT_DIR"

# ── Cleanup function (runs on success and failure) ────────────────────────────

cleanup() {
    echo ""
    echo "--- cleanup: stopping nlsr services ---"
    $COMPOSE stop ndn-fwd-nlsr nfd-nlsr nlsr-cxx 2>/dev/null || true
    $COMPOSE rm -f ndn-fwd-nlsr nfd-nlsr nlsr-cxx 2>/dev/null || true
}
trap cleanup EXIT

# ── Start pcap capture in background ─────────────────────────────────────────
# Uses a sidecar container with tshark; falls back to skipping capture if
# tshark is not available on the Docker host.

start_pcap() {
    if docker run --rm --network ndn-testbed_ndn-net \
           --name g04-tshark \
           -v "$(pwd)/$TRANSCRIPT_DIR:/out" \
           --detach \
           nicolaka/netshoot \
           tshark -i any -w /out/g04_nlsr_interop_after.pcap \
           "host 172.30.0.30 or host 172.30.0.14" \
           >/dev/null 2>&1; then
        echo "tshark capture started (container: g04-tshark)"
        PCAP_STARTED=1
    else
        echo "WARNING: could not start tshark capture container — skipping pcap"
        PCAP_STARTED=0
    fi
}

stop_pcap() {
    if [[ "${PCAP_STARTED:-0}" -eq 1 ]]; then
        docker stop g04-tshark 2>/dev/null || true
        # Dump human-readable summary if pcap was written
        if [[ -f "$PCAP_FILE" ]]; then
            docker run --rm \
                -v "$(pwd)/$TRANSCRIPT_DIR:/out" \
                nicolaka/netshoot \
                tshark -r /out/g04_nlsr_interop_after.pcap \
                -Y "udp.port == 6363" \
                -V 2>/dev/null > "$TXT_FILE" || true
            echo "pcap saved: $PCAP_FILE"
            echo "text transcript: $TXT_FILE"
        fi
    fi
}

# ── Bring up NLSR services ────────────────────────────────────────────────────

echo "=== G.04 NLSR interop witness ==="
echo "Starting ndn-fwd-nlsr, nfd-nlsr, nlsr-cxx …"

# --build ensures ndn-fwd-nlsr is rebuilt if Rust sources changed.
$COMPOSE up -d --build --no-deps ndn-fwd-nlsr
$COMPOSE up -d --no-deps nfd-nlsr

# Wait for nfd-nlsr healthy before starting nlsr-cxx
echo "Waiting for nfd-nlsr to become healthy …"
WAIT=0
while [[ $WAIT -lt 30 ]]; do
    STATUS=$($COMPOSE ps nfd-nlsr --format "{{.Health}}" 2>/dev/null || echo "")
    if [[ "$STATUS" == "healthy" ]]; then break; fi
    sleep 2
    WAIT=$((WAIT + 2))
done

# Wait for ndn-fwd-nlsr healthy
WAIT=0
while [[ $WAIT -lt 30 ]]; do
    STATUS=$($COMPOSE ps ndn-fwd-nlsr --format "{{.Health}}" 2>/dev/null || echo "")
    if [[ "$STATUS" == "healthy" ]]; then break; fi
    sleep 2
    WAIT=$((WAIT + 2))
done

$COMPOSE up -d --no-deps nlsr-cxx

start_pcap

# ── Convergence poll ──────────────────────────────────────────────────────────

echo "Waiting up to ${TIMEOUT}s for route convergence …"

ELAPSED=0
RS_SEES_CXX=0
CXX_SEES_RS=0

while [[ $ELAPSED -lt $TIMEOUT ]]; do
    sleep $POLL
    ELAPSED=$((ELAPSED + POLL))

    # ndn-rs side: check debug logs for NLSR route install message.
    # ndn-ctl is not bundled in the ndn-fwd image; logs are the available signal.
    # NlsrProtocol emits:  debug!(prefix = %prefix, ... "NLSR route added")
    if docker logs ndn-fwd-nlsr 2>&1 \
            | grep -q "NLSR route added.*$NLSR_CXX_PREFIX\|$NLSR_CXX_PREFIX.*NLSR route added"; then
        RS_SEES_CXX=1
    fi

    # C++ NLSR side: NLSR's `nlsrc routing` only lists router-level
    # destinations.  The actual name-prefix install happens via NLSR's
    # NPT → NFD RIB: NLSR registers each NameLSA prefix in NFD's RIB
    # under origin=nlsr (see NLSR/src/nfd-rib-commands.cpp).  So the
    # authoritative check that nlsr-cxx has internalised our NameLSA is
    # `nfdc route list` showing `/test/r2/data` with `origin=nlsr`.
    if docker exec nfd-nlsr \
            env NDN_CLIENT_TRANSPORT=unix:///run/nfd-nlsr/nfd.sock \
            nfdc route list 2>/dev/null \
            | grep -F "prefix=$NDN_FWD_NLSR_PREFIX" \
            | grep -q "origin=nlsr"; then
        CXX_SEES_RS=1
    fi

    echo "  t=${ELAPSED}s: ndn-fwd-nlsr sees cxx-prefix=${RS_SEES_CXX}  nlsr-cxx sees rs-prefix=${CXX_SEES_RS}"

    if [[ $RS_SEES_CXX -eq 1 && $CXX_SEES_RS -eq 1 ]]; then
        break
    fi
done

stop_pcap

# ── Diagnostic dump on failure ────────────────────────────────────────────────

if [[ $RS_SEES_CXX -eq 0 || $CXX_SEES_RS -eq 0 ]]; then
    echo ""
    echo "--- ndn-fwd-nlsr logs (last 60 lines) ---"
    docker logs ndn-fwd-nlsr 2>&1 | tail -60 || true

    echo ""
    echo "--- nfd-nlsr logs (last 30 lines) ---"
    docker logs nfd-nlsr 2>&1 | tail -30 || true

    echo ""
    echo "--- nlsr-cxx logs (last 60 lines) ---"
    docker logs nlsr-cxx 2>&1 | tail -60 || true

    echo ""
    echo "--- ndn-fwd-nlsr NLSR route log entries ---"
    docker logs ndn-fwd-nlsr 2>&1 | grep -i "NLSR route\|nlsr.*prefix\|rib.*add" | tail -20 || true

    echo ""
    echo "--- nlsr-cxx routing table ---"
    docker exec nlsr-cxx \
        env NDN_CLIENT_TRANSPORT=unix:///run/nfd-nlsr/nfd.sock \
        nlsrc routing 2>/dev/null || true
fi

# ── Result ────────────────────────────────────────────────────────────────────

if [[ $RS_SEES_CXX -eq 0 ]]; then
    echo ""
    echo "FAIL: ndn-fwd-nlsr does not have ${NLSR_CXX_PREFIX} in its RIB after ${TIMEOUT}s."
    echo ""
    echo "Triage checklist (most-likely → least-likely):"
    echo "  1. nlsr-cxx config rejected — check its container logs for"
    echo "     'Invalid value for hello-interval' / 'Error in configuration"
    echo "     file processing'.  The C++ NLSR validator requires"
    echo "     hello-interval in [30, 90].  If it rejected the config, the"
    echo "     C++ side never started peering."
    echo "  2. Hello did not arrive — adjacency LSA never built.  Look for"
    echo "     'NLSR: received Hello' in ndn-fwd-nlsr logs and the matching"
    echo "     'Hello sent' / 'getting status' line in nlsr-cxx logs."
    echo "  3. PSync update arrived but LSA fetch failed — look in"
    echo "     ndn-fwd-nlsr logs for 'fetched LSA' (PASS) vs 'LSA Interest"
    echo "     timed out' (FAIL).  See crates/spec/ndn-routing/src/protocols/"
    echo "     nlsr/sync.rs::fetch_remote_lsa."
    echo "  4. NameLSA never advertised our prefix — confirm ndn-fwd-nlsr"
    echo "     logs show 'own NameLSA installed' with prefixes=1+."
    exit 1
fi

if [[ $CXX_SEES_RS -eq 0 ]]; then
    echo ""
    echo "FAIL: nlsr-cxx does not have ${NDN_FWD_NLSR_PREFIX} in its routing table after ${TIMEOUT}s."
    echo ""
    echo "Triage checklist:"
    echo "  1. Did the LSA serve path register?  Look in ndn-fwd-nlsr logs"
    echo "     for 'NLSR LSA producer registered' or similar."
    echo "  2. Did nlsr-cxx fetch the LSA?  Its logs show 'LSA interest sent'"
    echo "     and 'received Data' on success, 'timed out' on failure."
    echo "  3. nlsr-cxx config rejected — see RS_SEES_CXX checklist item #1."
    exit 1
fi

echo ""
echo "=== G.04 PASS — NLSR ↔ C++ NLSR route convergence witnessed ==="
echo "    ndn-fwd-nlsr : has ${NLSR_CXX_PREFIX}"
echo "    nlsr-cxx     : has ${NDN_FWD_NLSR_PREFIX}"
exit 0
