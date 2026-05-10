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
TIMEOUT=90
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

    # C++ NLSR side: query routing table for ndn-rs prefix.
    # nlsrc subcommand is "routing" (not "status routingtable").
    if docker exec nlsr-cxx \
            env NDN_CLIENT_TRANSPORT=unix:///run/nfd-nlsr/nfd.sock \
            nlsrc routing 2>/dev/null \
            | grep -qF "$NDN_FWD_NLSR_PREFIX"; then
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
    echo "Known root cause (G.04 BLOCKED-BY-INTEROP):"
    echo "  NlsrSync.run() installs remote LSAs only when PSync updates carry"
    echo "  mapping bytes (update.mapping is Some).  C++ NLSR's PSync sends seq"
    echo "  numbers only — no mapping bytes on the wire.  ndn-rs receives the"
    echo "  PSync update but skips LSA installation (update.mapping == None)."
    echo "  Separately, ndn-rs does not issue Interest/Data fetches for LSA"
    echo "  content (LSA fetching deferred in NlsrSync; see phase 5 comment)."
    echo ""
    echo "  Fix required: implement LSA content fetch in NlsrSync:"
    echo "    - On PSync update with no mapping bytes, send an Interest for the"
    echo "      LSA name (<lsa_prefix>/<router>/<type>/<seq>) via the sync face."
    echo "    - Serve own LSAs as NDN Data packets so C++ NLSR can fetch them."
    echo "    - This is a separate commit from G.04 phase 6 integration."
    echo ""
    echo "  See: crates/spec/ndn-routing/src/protocols/nlsr/sync.rs:196"
    echo "       (the 'Phase 5: install LSA if the PSync update carries the wire"
    echo "       bytes' block — the else branch is the missing implementation)."
    exit 1
fi

if [[ $CXX_SEES_RS -eq 0 ]]; then
    echo ""
    echo "FAIL: nlsr-cxx does not have ${NDN_FWD_NLSR_PREFIX} in its routing table after ${TIMEOUT}s."
    echo ""
    echo "Known root cause (G.04 BLOCKED-BY-INTEROP):"
    echo "  C++ NLSR issues an Interest for ndn-rs's LSA after seeing its seq"
    echo "  number via PSync.  ndn-rs does not serve LSAs as NDN Data packets,"
    echo "  so the Interest times out and C++ NLSR never learns the prefix."
    echo ""
    echo "  Fix required: ndn-rs must register and serve the LSA namespace"
    echo "    <network>/nlsr/LSA/<own_router>/NAME/<seq> as NDN Data (signed)."
    exit 1
fi

echo ""
echo "=== G.04 PASS — NLSR ↔ C++ NLSR route convergence witnessed ==="
echo "    ndn-fwd-nlsr : has ${NLSR_CXX_PREFIX}"
echo "    nlsr-cxx     : has ${NDN_FWD_NLSR_PREFIX}"
exit 0
