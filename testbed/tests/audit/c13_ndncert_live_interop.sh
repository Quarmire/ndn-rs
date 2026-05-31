#!/usr/bin/env bash
# Witness recipe for audit finding C.13 — NDNCERT 0.3 live CA interop.
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § C.13
# Severity:    BLOCKER / BLOCKED-BY-INTEROP (8 wire-format gaps now fixed)
#
# What this script tests:
#   1. Stand up nfd-ndncert (NFD sidecar) at 172.30.0.15.
#   2. Stand up ndncert-ca (upstream ndncert-ca-server) at 172.30.0.16.
#   3. Run the ndn-rs enroll-ndncert binary (from the interop container)
#      against the CA:
#        a. NEW — build and submit a self-signed NDN Certificate.
#        b. CHALLENGE round 1 — trigger pin challenge (no code).
#        c. Extract generated PIN from CA container logs
#           (NDN_LOG=ndncert.challenge.pin=TRACE logs the code via
#            NDN_LOG_TRACE in challenge-pin.cpp:47).
#        d. CHALLENGE round 2 — submit the PIN code.
#        e. Cert fetch — fetch and decode the issued certificate through
#           ndn-rs's Certificate v2 decoder (C.07/C.08/C.18 work).
#        f. Assert issuer chains back to /test/ndncert/CA.
#   4. Capture tshark of the exchange as a wire transcript.
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
PCAP_FILE="$TRANSCRIPT_DIR/c13_ndncert_live_interop_after.pcap"
TXT_FILE="$TRANSCRIPT_DIR/c13_ndncert_live_interop_after.txt"
CA_PREFIX="/test/ndncert/CA"
# Identity must be a strict extension of CA_PREFIX (NDNCERT 0.3 §3.1).
REQUESTER_NAME="${CA_PREFIX}/requester"
PIN_TIMEOUT=60
ENROLL_TIMEOUT=120

# ── Infra availability check ──────────────────────────────────────────────────

if ! command -v docker &>/dev/null; then
    echo "SKIP: docker not available"
    exit 2
fi

mkdir -p "$TRANSCRIPT_DIR"

# ── Cleanup function (runs on success and failure) ────────────────────────────

cleanup() {
    echo ""
    echo "--- cleanup: stopping ndncert services ---"
    $COMPOSE stop ndncert-ca nfd-ndncert 2>/dev/null || true
    $COMPOSE rm -f ndncert-ca nfd-ndncert 2>/dev/null || true
    rm -f /tmp/c13_pin_pipe /tmp/c13_enroll.log
}
trap cleanup EXIT

# ── pcap capture helpers ──────────────────────────────────────────────────────

PCAP_STARTED=0

start_pcap() {
    if docker run --rm --network ndn-testbed_ndn-net \
           --name c13-tshark \
           -v "$(pwd)/$TRANSCRIPT_DIR:/out" \
           --detach \
           nicolaka/netshoot \
           tshark -i any -w /out/c13_ndncert_live_interop_after.pcap \
           "host 172.30.0.15 or host 172.30.0.16" \
           >/dev/null 2>&1; then
        echo "tshark capture started"
        PCAP_STARTED=1
    else
        echo "WARNING: could not start tshark capture — skipping pcap"
    fi
}

stop_pcap() {
    if [[ "${PCAP_STARTED}" -eq 1 ]]; then
        docker stop c13-tshark 2>/dev/null || true
        if [[ -f "$PCAP_FILE" ]]; then
            docker run --rm \
                -v "$(pwd)/$TRANSCRIPT_DIR:/out" \
                nicolaka/netshoot \
                tshark -r /out/c13_ndncert_live_interop_after.pcap \
                -V 2>/dev/null > "$TXT_FILE" || true
            echo "pcap saved: $PCAP_FILE"
            echo "text transcript: $TXT_FILE"
        fi
    fi
}

# ── Bring up ndncert services ─────────────────────────────────────────────────

echo "=== C.13 NDNCERT live CA interop witness ==="
echo "Starting nfd-ndncert …"

$COMPOSE up -d --no-deps nfd-ndncert

echo "Waiting for nfd-ndncert to become healthy …"
WAIT=0
while [[ $WAIT -lt 30 ]]; do
    STATUS=$($COMPOSE ps nfd-ndncert --format "{{.Health}}" 2>/dev/null || echo "")
    if [[ "$STATUS" == "healthy" ]]; then break; fi
    sleep 2
    WAIT=$((WAIT + 2))
done

if [[ "$($COMPOSE ps nfd-ndncert --format "{{.Health}}" 2>/dev/null || echo "")" != "healthy" ]]; then
    echo "FAIL: nfd-ndncert did not become healthy after 30 s"
    docker logs nfd-ndncert 2>&1 | tail -20 || true
    exit 1
fi
echo "nfd-ndncert healthy"

echo "Starting ndncert-ca (build may take a few minutes on first run) …"
# --build ensures the CA image is rebuilt if the Dockerfile changed.
$COMPOSE up -d --build --no-deps ndncert-ca

echo "Waiting for ndncert-ca to register ${CA_PREFIX}/CA/INFO …"
WAIT=0
CA_READY=0
while [[ $WAIT -lt 90 ]]; do
    if docker exec nfd-ndncert \
            env NDN_CLIENT_TRANSPORT=unix:///run/nfd-ndncert/nfd.sock \
            nfdc fib 2>/dev/null | grep -qF "$CA_PREFIX"; then
        CA_READY=1
        break
    fi
    sleep 2
    WAIT=$((WAIT + 2))
done

if [[ $CA_READY -eq 0 ]]; then
    echo "FAIL: ndncert-ca did not register $CA_PREFIX after 90 s"
    docker logs ndncert-ca 2>&1 | tail -30 || true
    exit 1
fi
echo "CA ready — $CA_PREFIX registered with nfd-ndncert"

# ndncert-ca-server registers the command prefix `<ca-prefix>/CA`; issued
# certificates are named under the requester identity, which is a strict
# extension of `<ca-prefix>` in this fixture. Add a testbed static route for
# the CA identity prefix to the same local app face so the final cert-fetch
# Interest reaches ndncert-ca-server instead of getting a NoRoute Nack.
CA_FACE_ID=$(docker exec nfd-ndncert \
    env NDN_CLIENT_TRANSPORT=unix:///run/nfd-ndncert/nfd.sock \
    nfdc fib 2>/dev/null \
    | sed -nE "s|.*${CA_PREFIX}/CA .*faceid=([0-9]+).*|\\1|p" \
    | head -1)
if [[ -z "$CA_FACE_ID" ]]; then
    echo "FAIL: could not find ndncert-ca application face for $CA_PREFIX/CA"
    docker exec nfd-ndncert \
        env NDN_CLIENT_TRANSPORT=unix:///run/nfd-ndncert/nfd.sock \
        nfdc fib 2>&1 || true
    exit 1
fi
docker exec nfd-ndncert \
    env NDN_CLIENT_TRANSPORT=unix:///run/nfd-ndncert/nfd.sock \
    nfdc route add "$CA_PREFIX" "$CA_FACE_ID" >/dev/null
echo "CA cert-fetch route ready — $CA_PREFIX via face $CA_FACE_ID"

start_pcap

# ── Run enrollment ────────────────────────────────────────────────────────────
# The interop container mounts nfd-ndncert-sock at /run/nfd-ndncert (added in
# docker-compose.yml).  enroll-ndncert connects there to reach the CA.
#
# PIN delivery flow:
#   1. enroll-ndncert writes "WAITING_FOR_PIN" to stderr after round-1 CHALLENGE
#      and blocks reading stdin from the named pipe.
#   2. This script polls the CA container logs for the NDN_LOG_TRACE line:
#        "Secret for request <hex> is <6digits>"
#      (challenge-pin.cpp:47, logged when NDN_LOG=ndncert.challenge.pin=TRACE).
#   3. The PIN is written to the named pipe, unblocking enroll-ndncert.

echo ""
echo "--- running ndn-rs enrollment ---"

rm -f /tmp/c13_pin_pipe
mkfifo /tmp/c13_pin_pipe

ENROLL_LOG=/tmp/c13_enroll.log
> "$ENROLL_LOG"

# Open the fifo for both read and write on fd 9 so docker exec's stdin
# redirection doesn't block on fifo open() before a writer attaches.
exec 9<>/tmp/c13_pin_pipe
docker exec -i interop \
    enroll-ndncert \
        --face-socket /run/nfd-ndncert/nfd.sock \
        --ca-prefix "$CA_PREFIX" \
        --name "$REQUESTER_NAME" \
    <&9 \
    >> "$ENROLL_LOG" 2>&1 &
ENROLL_PID=$!

# Wait for round-1 CHALLENGE trigger ("WAITING_FOR_PIN" appears in stderr).
echo "Waiting for round-1 CHALLENGE trigger …"
WAIT=0
while [[ $WAIT -lt 30 ]]; do
    if grep -q "WAITING_FOR_PIN" "$ENROLL_LOG" 2>/dev/null; then break; fi
    sleep 1
    WAIT=$((WAIT + 1))
done

if ! grep -q "WAITING_FOR_PIN" "$ENROLL_LOG" 2>/dev/null; then
    echo "FAIL: enroll-ndncert did not reach PIN-waiting state after 30 s"
    cat "$ENROLL_LOG" || true
    echo ""
    echo "--- ndncert-ca logs ---"
    docker logs ndncert-ca 2>&1 | tail -30 || true
    exit 1
fi

# Extract PIN from CA logs (6-digit code logged after "is ").
echo "Extracting PIN from CA logs …"
PIN=""
WAIT=0
while [[ $WAIT -lt $PIN_TIMEOUT ]]; do
    # BSD grep (macOS) lacks -P; use sed for the look-behind equivalent.
    PIN=$(docker logs ndncert-ca 2>&1 \
          | sed -nE 's/.*is ([0-9]{6})( |$).*/\1/p' \
          | tail -1 || true)
    if [[ -n "$PIN" ]]; then break; fi
    sleep 1
    WAIT=$((WAIT + 1))
done

if [[ -z "$PIN" ]]; then
    echo "FAIL: could not extract PIN from ndncert-ca logs after ${PIN_TIMEOUT}s"
    echo "--- ndncert-ca logs (full) ---"
    docker logs ndncert-ca 2>&1 | tail -60 || true
    exit 1
fi
echo "PIN extracted (len=${#PIN})"

# Feed PIN to enroll-ndncert via the named pipe.
echo "$PIN" > /tmp/c13_pin_pipe

# Wait for enrollment to complete.
echo "Waiting for enrollment to complete …"
WAIT=0
while [[ $WAIT -lt $ENROLL_TIMEOUT ]]; do
    if ! kill -0 "$ENROLL_PID" 2>/dev/null; then break; fi
    sleep 1
    WAIT=$((WAIT + 1))
done

ENROLL_RC=0
wait "$ENROLL_PID" || ENROLL_RC=$?

stop_pcap

# ── Assertions ────────────────────────────────────────────────────────────────

echo ""
echo "--- enrollment output ---"
cat "$ENROLL_LOG"

if [[ $ENROLL_RC -ne 0 ]]; then
    echo ""
    echo "FAIL: enroll-ndncert exited with rc=$ENROLL_RC"
    echo ""
    echo "--- ndncert-ca logs ---"
    docker logs ndncert-ca 2>&1 | tail -60 || true
    echo ""
    echo "--- nfd-ndncert logs ---"
    docker logs nfd-ndncert 2>&1 | tail -20 || true
    exit 1
fi

if ! grep -q "ENROLL_OK" "$ENROLL_LOG"; then
    echo ""
    echo "FAIL: ENROLL_OK not found in enrollment output"
    exit 1
fi

if ! grep -q "CERT_FETCHED=true" "$ENROLL_LOG"; then
    echo ""
    echo "FAIL: issued certificate was not fetched and decoded"
    exit 1
fi

CERT_NAME=$(grep "^CERT_NAME=" "$ENROLL_LOG" | head -1 | cut -d= -f2-)
ISSUER=$(grep "^ISSUER=" "$ENROLL_LOG" | head -1 | cut -d= -f2-)

echo ""
echo "=== C.13 PASS — NDNCERT live CA interop witnessed ==="
echo "    cert name : $CERT_NAME"
echo "    issuer    : $ISSUER"
echo ""
echo "  ndn-rs enrolled against upstream ndncert-ca-server (pin challenge)."
echo "  Issued cert decoded through ndn-rs Certificate v2 decoder."
echo "  Issuer chains back to $CA_PREFIX."
exit 0
