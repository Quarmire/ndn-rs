#!/usr/bin/env bash
# Witness recipe for audit finding G.04 — NLSR interop with C++ NLSR.
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § G.04
# Severity:    MAJOR
# Status:      BLOCKED-BY-INTEROP — C++ NLSR service not yet integrated
#              into the testbed Docker stack.
#
# What this script tests:
#   1. Stand up an ndn-rs router with NLSR enabled.
#   2. Stand up a C++ NLSR router in a separate container.
#   3. Both routers peer over UDP (172.30.0.30 ↔ 172.30.0.31).
#   4. ndn-rs advertises /ndn/test/ndn-rs-prefix.
#   5. C++ NLSR advertises /ndn/test/nlsr-cxx-prefix.
#   6. After ≤ 60 s, each side's RIB must contain the other's prefix.
#
# Blocking issue:
#   The `nlsr-cxx` Docker service needs a C++ NLSR container image.
#   The upstream Dockerfile at NLSR/Dockerfile builds from source;
#   a trimmed single-node image is pending.  Until it is added to
#   testbed/docker-compose.yml this script exits 1 with diagnosis.
#
# To run once the infra is ready:
#   docker compose -f testbed/docker-compose.yml up -d nlsr-rs nlsr-cxx
#   bash testbed/tests/audit/g04_nlsr_interop.sh
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP (infra not available)
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

# ── Infra availability check ──────────────────────────────────────────────────

if ! command -v docker &>/dev/null; then
    echo "SKIP: docker not available"
    exit 2
fi

# Check whether the nlsr-cxx and nlsr-rs services are running.
NLSR_CXX_UP=$(docker compose -f testbed/docker-compose.yml ps -q nlsr-cxx 2>/dev/null || true)
NLSR_RS_UP=$(docker compose -f testbed/docker-compose.yml ps -q nlsr-rs 2>/dev/null || true)

if [[ -z "$NLSR_CXX_UP" || -z "$NLSR_RS_UP" ]]; then
    echo "FAIL: nlsr-cxx or nlsr-rs service not running."
    echo "      BLOCKED-BY-INTEROP: add [nlsr-cxx] and [nlsr-rs] services to"
    echo "      testbed/docker-compose.yml, then re-run."
    echo ""
    echo "  Diagnosis:"
    echo "    - nlsr-cxx service: $(if [[ -n "$NLSR_CXX_UP" ]]; then echo UP; else echo MISSING; fi)"
    echo "    - nlsr-rs  service: $(if [[ -n "$NLSR_RS_UP" ]]; then echo UP; else echo MISSING; fi)"
    echo ""
    echo "  Required testbed additions:"
    echo "    services:"
    echo "      nlsr-rs:"
    echo "        image: ndn-rs:nlsr     # built from binaries/ndn-fwd/Dockerfile with NLSR config"
    echo "        ipv4_address: 172.30.0.30"
    echo "        config: testbed/configs/nlsr-rs.toml"
    echo "      nlsr-cxx:"
    echo "        image: ghcr.io/named-data/nlsr:latest  # or built from NLSR/Dockerfile"
    echo "        ipv4_address: 172.30.0.31"
    echo "        config: testbed/configs/nlsr-cxx.conf"
    echo ""
    echo "  ndn-rs NLSR config snippet (testbed/configs/nlsr-rs.toml):"
    echo "    [routing.nlsr]"
    echo "    enabled = true"
    echo "    network = \"/ndn\""
    echo "    router  = \"/ndn/testbed/nlsr-rs\""
    echo "    name_prefixes = [\"/ndn/test/ndn-rs-prefix\"]"
    echo "    permissive_validation = true"
    echo ""
    echo "    [[routing.nlsr.neighbor]]"
    echo "    name     = \"/ndn/testbed/nlsr-cxx\""
    echo "    face_uri = \"udp4://172.30.0.31:6363\""
    echo "    link_cost = 10.0"
    echo ""
    echo "  C++ NLSR config snippet (testbed/configs/nlsr-cxx.conf):"
    echo "    network /ndn"
    echo "    site /testbed"
    echo "    router /nlsr-cxx"
    echo "    prefix /ndn/test/nlsr-cxx-prefix"
    echo "    neighbor"
    echo "      name /ndn/testbed/nlsr-rs"
    echo "      face-uri udp4://172.30.0.30:6363"
    echo "      link-cost 10"
    echo "    end-neighbor"
    exit 1
fi

# ── Convergence check ─────────────────────────────────────────────────────────

echo "Both NLSR services running.  Waiting up to 60 s for route convergence..."

NDN_RS_ADDR="172.30.0.30"
NLSR_CXX_ADDR="172.30.0.31"
NDN_RS_PREFIX="/ndn/test/ndn-rs-prefix"
NLSR_CXX_PREFIX="/ndn/test/nlsr-cxx-prefix"
TIMEOUT=60
POLL=5
ELAPSED=0
RS_SEES_CXX=0
CXX_SEES_RS=0

while [[ $ELAPSED -lt $TIMEOUT ]]; do
    sleep $POLL
    ELAPSED=$((ELAPSED + POLL))

    # Check ndn-rs RIB for the C++ NLSR-originated prefix.
    if docker exec nlsr-rs ndn-ctl rib list 2>/dev/null | grep -qF "$NLSR_CXX_PREFIX"; then
        RS_SEES_CXX=1
    fi

    # Check C++ NLSR RIB for the ndn-rs-originated prefix.
    if docker exec nlsr-cxx nlsrc status routingtable 2>/dev/null | grep -qF "$NDN_RS_PREFIX"; then
        CXX_SEES_RS=1
    fi

    echo "  t=${ELAPSED}s: nlsr-rs sees cxx-prefix=${RS_SEES_CXX}  nlsr-cxx sees rs-prefix=${CXX_SEES_RS}"

    if [[ $RS_SEES_CXX -eq 1 && $CXX_SEES_RS -eq 1 ]]; then
        break
    fi
done

# ── Result ────────────────────────────────────────────────────────────────────

if [[ $RS_SEES_CXX -eq 0 ]]; then
    echo "FAIL: nlsr-rs does not have ${NLSR_CXX_PREFIX} in its RIB after ${TIMEOUT} s"
    echo "      Diagnosis: check LSA exchange on ndn-rs side:"
    echo "        docker logs nlsr-rs | grep -i 'nlsr\\|lsa\\|hello'"
    exit 1
fi

if [[ $CXX_SEES_RS -eq 0 ]]; then
    echo "FAIL: nlsr-cxx does not have ${NDN_RS_PREFIX} in its routing table after ${TIMEOUT} s"
    echo "      Diagnosis: check Hello/LSA on C++ NLSR side:"
    echo "        docker logs nlsr-cxx | grep -i 'hello\\|lsa\\|adjacency'"
    exit 1
fi

echo ""
echo "=== G.04 PASS — NLSR ↔ C++ NLSR route convergence witnessed ==="
echo "    ndn-rs   : has ${NLSR_CXX_PREFIX}"
echo "    nlsr-cxx : has ${NDN_RS_PREFIX}"
exit 0
