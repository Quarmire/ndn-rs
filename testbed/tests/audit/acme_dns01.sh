#!/usr/bin/env bash
# Witness for the ACME / DNS-01 path used by the WebTransport listener (issue
# #14) and the WebSocket-TLS face (issue #3).
#
# Spec ref:    RFC 8555 (ACME), RFC 8555 §8.4 (DNS-01).
# Pebble:      github.com/letsencrypt/pebble — ACME test server, runs in
#              Docker with a stub DNS resolver listening on :8053.
# Witnesses:   `ndn_acme::AcmeClient` against the Pebble directory completes a
#              DNS-01 challenge through a stub `DnsProvider` implementation
#              that updates Pebble's resolver, then returns a signed cert.
#
# Today: FAIL (exit 1) — the ndn-acme crate is empty / Pebble harness absent.
# After fix: PASS (exit 0) — `cargo test -p ndn-acme --test pebble_dns01` goes
#            green when Pebble is reachable on 127.0.0.1:14000.
set -euo pipefail

cd "$(dirname "$0")/../../.."

if ! command -v docker >/dev/null 2>&1; then
    echo "SKIP: docker not available — cannot run Pebble" >&2
    exit 2
fi

if ! cargo metadata --format-version=1 --no-deps 2>/dev/null \
        | grep -q '"name":"ndn-acme"'; then
    echo "FAIL: ndn-acme crate is not yet in the workspace" >&2
    exit 1
fi

# Start Pebble + challtestsrv (the stub DNS server it ships with).  These are
# the upstream-published test images; run on a private docker network so the
# ACME server can resolve _acme-challenge.* via challtestsrv.
NET="ndn-acme-pebble-net-$$"
docker network create "$NET" >/dev/null
trap 'docker network rm "$NET" >/dev/null 2>&1 || true' EXIT

CHALL=$(docker run -d --rm --network "$NET" --name "chall-$$" \
    -p 8055:8055 -p 8053:8053/udp -p 8053:8053 \
    ghcr.io/letsencrypt/pebble-challtestsrv:latest \
    pebble-challtestsrv -dns01 :8053 -management :8055 -http01 "" -tlsalpn01 "" -https01 "")

PEBBLE=$(docker run -d --rm --network "$NET" --name "pebble-$$" \
    -p 14000:14000 -p 15000:15000 \
    -e "PEBBLE_VA_DNSSERVER=chall-$$:8053" \
    ghcr.io/letsencrypt/pebble:latest \
    pebble -config /test/config/pebble-config.json -dnsserver "chall-$$:8053")

trap 'docker rm -f "$PEBBLE" "$CHALL" >/dev/null 2>&1 || true; docker network rm "$NET" >/dev/null 2>&1 || true' EXIT

# Wait for Pebble's directory to come up.
for _ in $(seq 1 30); do
    if curl -ks https://127.0.0.1:14000/dir >/dev/null; then break; fi
    sleep 1
done

PEBBLE_DIR_URL=https://127.0.0.1:14000/dir \
PEBBLE_CHALLTESTSRV_URL=http://127.0.0.1:8055 \
    cargo test -p ndn-acme --test pebble_dns01 -- --nocapture
