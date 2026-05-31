#!/usr/bin/env bash
# Witness recipe for audit finding G.06 — SWIM removed; NDN AutoConfig wired
# and interoperable with the reference ndn-autoconfig procedure.
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § G.06
# Severity:    RESOLVED 2026-05-08
# Type:        RUST-UNIT + LIVE-INTEROP when Docker is running
#
# Original finding: ndn-rs used SWIM-over-NDN for neighbor discovery;
# NDN AutoConfig (DNS-based hub finding + NeighborProbeProtocol) is the
# spec-aligned primitive.
#
# Resolution: SWIM hello/ machinery removed; replaced by:
#   - NeighborProbeProtocol (/ndn/local/nd/probe/ping) for liveness probing
#   - AutoConfigProtocol (/localhop/ndn-autoconf/hub) for hub discovery
#
# This script verifies SWIM artifacts are absent, NDN AutoConfig is wired,
# hub-discovery wire helpers round-trip, and reference ndn-autoconfig can use
# an NDN-FCH fixture to create an ndn-fwd hub face and register the NFD
# autoconfig prefixes.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

fail=0
live_ran=0
live_skipped=0

# 1. SWIM machinery is gone.
if grep -rqE '\bHelloProtocol\b|\bUdpNeighborDiscovery\b|\bSwimScheduler\b' \
        crates/ndn-discovery/src/ 2>/dev/null; then
    echo "FAIL: SWIM types still present"
    fail=1
else
    echo "ok: SWIM types absent"
fi

# 2. NeighborProbeProtocol is present.
if grep -rqE '\bNeighborProbeProtocol\b' \
        crates/ndn-discovery/src/ 2>/dev/null; then
    echo "ok: NeighborProbeProtocol present"
else
    echo "FAIL: NeighborProbeProtocol not found"
    fail=1
fi

# 3. AutoConfigDiscovery (hub discovery) is present.
if grep -rqE '\bAutoConfigDiscovery\b' \
        crates/ndn-discovery/src/ 2>/dev/null; then
    echo "ok: AutoConfigDiscovery present"
else
    echo "FAIL: AutoConfigDiscovery not found"
    fail=1
fi

# 4. AutoConfig hub-discovery wire helpers behave like the reference server.
if cargo test -p ndn-discovery "autoconfig::client::tests" --quiet \
        >/tmp/g06_autoconfig_unit.log 2>&1; then
    echo "ok: AutoConfig hub-discovery Rust witnesses passed"
else
    echo "FAIL: AutoConfig hub-discovery Rust witnesses"
    cat /tmp/g06_autoconfig_unit.log
    fail=1
fi

# 5. Live reference-client witness: ndn-autoconfig falls through to a local
# FCH fixture, creates a hub face on ndn-fwd, and registers / + /localhop/nfd.
if [ "$fail" -eq 0 ] && command -v docker >/dev/null 2>&1; then
    if docker compose -f testbed/docker-compose.yml exec -T interop true \
            >/dev/null 2>&1; then
        if ! docker compose -f testbed/docker-compose.yml exec -T interop \
                bash -lc "command -v ndn-autoconfig >/dev/null" >/dev/null 2>&1; then
            echo "SKIP: interop image does not yet ship reference ndn-autoconfig"
            live_skipped=1
        elif docker compose -f testbed/docker-compose.yml exec -T interop bash -lc '
            set -euo pipefail
            export NDN_CLIENT_TRANSPORT=unix:///run/ndn-fwd/ndn-fwd.sock
            node -e "require(\"http\").createServer((req,res)=>{res.writeHead(200,{\"Content-Type\":\"text/plain\"});res.end(\"nfd:6363\\n\")}).listen(18080,\"127.0.0.1\")" >/tmp/g06_fch.log 2>&1 &
            fch_pid=$!
            trap "kill ${fch_pid} >/dev/null 2>&1 || true" EXIT
            for _ in $(seq 1 30); do
              if curl -fsS http://127.0.0.1:18080/ >/tmp/g06_fch_probe.txt 2>/dev/null; then
                break
              fi
              sleep 0.1
            done
            grep -Fx "nfd:6363" /tmp/g06_fch_probe.txt >/dev/null
            ndn-autoconfig --ndn-fch-url http://127.0.0.1:18080/ >/tmp/g06_ndn_autoconfig.out 2>&1
            cat /tmp/g06_ndn_autoconfig.out
            grep -F "Stage NDN-FCH succeeded with udp://nfd:6363" /tmp/g06_ndn_autoconfig.out >/dev/null
            grep -F "Registered prefix /" /tmp/g06_ndn_autoconfig.out >/dev/null
            grep -F "Registered prefix /localhop/nfd" /tmp/g06_ndn_autoconfig.out >/dev/null
            nfdc route list >/tmp/g06_routes.out
            grep -F "origin=autoconf" /tmp/g06_routes.out >/dev/null
        ' >/tmp/g06_live_autoconfig.log 2>&1; then
            echo "ok: reference ndn-autoconfig created hub face and autoconf routes on ndn-fwd"
            cat /tmp/g06_live_autoconfig.log
            live_ran=1
        else
            echo "FAIL: live reference ndn-autoconfig witness"
            cat /tmp/g06_live_autoconfig.log
            fail=1
        fi
    else
        echo "SKIP: Docker interop services are not running; start with:"
        echo "      docker compose -f testbed/docker-compose.yml up -d interop ndn-fwd nfd yanfd"
        live_skipped=1
    fi
elif [ "$fail" -eq 0 ]; then
    echo "SKIP: docker missing; live reference ndn-autoconfig witness not run"
    live_skipped=1
fi

if [ "$fail" -eq 0 ] && [ "$live_ran" -eq 1 ]; then
    echo
    echo "=== G.06 RESOLVED 2026-05-28 — SWIM removed; NDN AutoConfig unit + live reference-client witness pass ==="
    exit 0
elif [ "$fail" -eq 0 ] && [ "$live_skipped" -eq 1 ]; then
    echo
    echo "=== G.06 PARTIAL — Rust witnesses pass; live ndn-autoconfig interop skipped ==="
    exit 2
else
    echo
    echo "=== G.06 — unexpected state; see above ==="
    exit 1
fi
