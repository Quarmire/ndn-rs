#!/bin/bash
# G.04 witness entrypoint for nfd-nlsr container.
#
# Starts NFD, waits for its Unix socket to come up, then pre-registers
# the outbound UDP face + neighbor route that nlsr-cxx's
# `neighbor { ... }` block in nlsr.conf would otherwise expect NLSR to
# bootstrap itself.  Against the current `ghcr.io/named-data/nlsr:latest`
# image that bootstrap does not fire reliably — NLSR only adds the
# face/route after the first Hello adjacency, but the Hello itself
# NoRoutes without an existing route.  Pre-seeding breaks the cycle.
#
# NLSR's own later route adds are additive (different `origin=nlsr`
# tag alongside this script's `origin=static`).

set -e

NFD_SOCK="/run/nfd-nlsr/nfd.sock"
NEIGHBOR_NAME="/test/r-nlsr/%C1.Router/r2"
NEIGHBOR_FACE_URI="udp4://172.30.0.30:6363"
NEIGHBOR_COST=10

# Launch NFD in the background; we'll exec-wait on it at the end.
nfd --config /etc/ndn/nfd.conf &
NFD_PID=$!

# Wait until NFD is actually responding (socket may appear before NFD
# has finished initialising the dispatcher and the management
# datasets).  Probe with `nfdc status` rather than just checking the
# socket file — NFD can crash early (e.g. PIB-lock contention from a
# stale previous run) and leave a half-initialised socket behind.
export NDN_CLIENT_TRANSPORT="unix://${NFD_SOCK}"
for _ in $(seq 1 60); do
    if [ -S "$NFD_SOCK" ] && nfdc status 2>/dev/null | grep -q 'uptime'; then
        break
    fi
    # If NFD has exited, surface the failure instead of polling
    # forever — docker-compose will restart us cleanly.
    if ! kill -0 "$NFD_PID" 2>/dev/null; then
        echo "[entrypoint] FATAL: nfd exited during startup" >&2
        wait "$NFD_PID" || true
        exit 1
    fi
    sleep 0.5
done

if ! nfdc status 2>/dev/null | grep -q 'uptime'; then
    echo "[entrypoint] FATAL: nfd did not respond on $NFD_SOCK within 30s" >&2
    wait "$NFD_PID" || true
    exit 1
fi

# nfdc face create / route add are effectively idempotent — if a face
# to the same URI already exists NFD returns the existing face-id, and
# route add replaces or refreshes the matching (prefix, face) entry.
# Tolerate failures so a re-up against an already-bootstrapped NFD
# doesn't crash the container.
echo "[entrypoint] pre-registering neighbor face: $NEIGHBOR_FACE_URI"
nfdc face create "$NEIGHBOR_FACE_URI" persistency permanent \
    || echo "[entrypoint] WARN: nfdc face create failed" >&2
echo "[entrypoint] pre-registering neighbor route: $NEIGHBOR_NAME -> $NEIGHBOR_FACE_URI cost $NEIGHBOR_COST"
nfdc route add "$NEIGHBOR_NAME" "$NEIGHBOR_FACE_URI" cost "$NEIGHBOR_COST" \
    || echo "[entrypoint] WARN: nfdc route add failed" >&2

# Hand foreground back to NFD so docker observes the right PID 1
# lifetime semantics (SIGTERM forwarding, exit code, etc.).
wait "$NFD_PID"
