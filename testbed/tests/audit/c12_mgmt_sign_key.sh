#!/usr/bin/env bash
# Interop witness for audit finding C.12 (testbed leg) — key-backed
# command Interest accepted by NFD with rib.localhop_security.
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § C.12
# Severity:    BLOCKER for testbed NFD; BLOCKED-BY-INTEROP until this script exits 0
# Spec ref:    NFD Developer Guide §7; NFD command-authenticator.cpp:122-207
# Witness:     RUST-UNIT + INTEROP-SCRIPT — first proves the key-backed
#              MgmtClient signing policy emits a verifiable Ed25519 command
#              Interest; then uses the Docker NFD service when available
#              (or a host NFD fallback) to register a route with
#              `ndn-ctl --identity`, asserting StatusCode 200 and that the
#              RIB shows the entry.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"

# Prerequisites
if ! command -v cargo >/dev/null 2>&1; then
    echo "SKIP: cargo missing" >&2
    exit 2
fi

if cargo test -p ndn-ipc --lib --quiet c12_key_signer_ >/tmp/c12_key_unit.log 2>&1; then
    echo "ok: key-backed command Interest behavioral tests"
else
    echo "FAIL: key-backed command Interest behavioral tests"
    cat /tmp/c12_key_unit.log
    exit 1
fi

COMPOSE="docker compose -f testbed/docker-compose.yml"
if command -v docker >/dev/null 2>&1; then
    PS_OUT=$($COMPOSE ps nfd testclient 2>/dev/null || true)
    if [[ "$PS_OUT" == *"nfd"* && "$PS_OUT" == *"testclient"* && ( "$PS_OUT" == *"running"* || "$PS_OUT" == *"Up"* ) ]]; then
        if DOCKER_OUT=$($COMPOSE exec -T testclient bash -lc '
            set -euo pipefail
            WORK=$(mktemp -d)
            cleanup() { rm -rf "$WORK"; }
            trap cleanup EXIT

            ID="/ndn/test/router1"
            PREFIX="/test/c12-docker-$(date +%s)-$$"
            PIB="$WORK/pib"

            ndn-ctl security init --name "$ID" --pib "$PIB" >/tmp/c12_key_init.out
            ndn-ctl --socket /run/nfd/nfd.sock \
                --identity "$ID" --pib "$PIB" \
                route add "$PREFIX" --face 1 --cost 10 >/tmp/c12_key_add.out

            echo "PREFIX=$PREFIX"
            cat /tmp/c12_key_add.out
        ' 2>&1); then
            PREFIX=$(printf '%s\n' "$DOCKER_OUT" | sed -n 's/^PREFIX=//p' | tail -1)
            RIB_LIST=""
            for _ in $(seq 1 10); do
                RIB_LIST=$($COMPOSE exec -T nfd nfdc route list 2>&1 || true)
                [[ -n "$PREFIX" && "$RIB_LIST" == *"$PREFIX"* ]] && break
                sleep 0.2
            done
            if [[ -z "$PREFIX" || "$RIB_LIST" != *"$PREFIX"* ]]; then
                echo "FAIL: Docker NFD route was accepted but not observed in nfdc route list"
                printf '%s\n' "$DOCKER_OUT"
                printf '%s\n' "$RIB_LIST"
                exit 1
            fi

            printf '%s\n' "$DOCKER_OUT"
            echo "ok: NFD RIB shows $PREFIX"
            echo
            echo "=== C.12 RESOLVED (Docker NFD) — key-backed command Interest accepted by NFD ==="
            exit 0
        else
            echo "FAIL: Docker NFD key-backed interop failed"
            printf '%s\n' "$DOCKER_OUT"
            exit 1
        fi
    fi
fi

if ! command -v nfd >/dev/null 2>&1; then
    echo "SKIP: neither Docker testbed nor host 'nfd' available — unit witness passed" >&2
    exit 2
fi

# Build ndn-ctl
if ! cargo build -p ndn-tools --bin ndn-ctl --quiet 2>/tmp/c12_build.log; then
    echo "FAIL: ndn-ctl build failed"
    cat /tmp/c12_build.log
    exit 1
fi
NDN_CTL="$REPO_ROOT/target/debug/ndn-ctl"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"; kill "$NFD_PID" 2>/dev/null || true' EXIT

# NFD config with rib.localhop_security and a cert-file anchor
IDENTITY="/ndn/test/router1"
PIB="$WORK/pib"

# Generate identity and export cert
"$NDN_CTL" security init --name "$IDENTITY" --pib "$PIB" >/dev/null
"$NDN_CTL" security export --pib "$PIB" --output "$WORK/router1.ndnc" >/dev/null

cat >"$WORK/nfd.conf" <<EOF
general
{
  user ""
  group ""
}

log
{
  default_level WARN
}

tables
{
  cs_max_packets 8192
  pit_max_expressions 100
}

face_system
{
  unix
  {
    path "$WORK/nfd.sock"
  }
}

authorizations
{
  authorize
  {
    certfile "$WORK/router1.ndnc"
    privileges
    {
      faces
      fib
      rib
      cs
      strategy-choice
    }
  }
}

rib
{
  localhost_security
  {
    rule
    {
      id "Command Interest Rule"
      for interest
      filter
      {
        type name
        name /localhost/nfd
        relation is-prefix-of
      }
      checker
      {
        type customized
        sig-type ecdsa-sha256
        key-locator
        {
          type name
          hyper-relation
          {
            k-rr-type KEY
            k-name <key_name>
            p-rr-type <packet_name>
            p-name </ndn/test>
          }
        }
      }
    }
    trust-anchor
    {
      type dir
      dir "$PIB"
    }
  }
}
EOF

# Start NFD
nfd --config "$WORK/nfd.conf" &
NFD_PID=$!
sleep 1

NDN_SOCK="$WORK/nfd.sock"

# Try key-backed route registration
if "$NDN_CTL" --socket "$NDN_SOCK" route add /test/prefix \
        --face 1 --cost 10 --identity "$IDENTITY" --pib "$PIB" \
        >/tmp/c12_rib_output.txt 2>&1; then
    echo "ok: route add accepted by NFD with key-backed signer"
else
    echo "FAIL: route add rejected (StatusCode non-200)"
    cat /tmp/c12_rib_output.txt
    exit 1
fi

# Verify RIB has the entry.
RIB_LIST=$("$NDN_CTL" --socket "$NDN_SOCK" route rib-list 2>/tmp/c12_rib_list.txt || true)
if [[ "$RIB_LIST" == *"/test/prefix"* ]]; then
    echo "ok: RIB shows /test/prefix"
else
    echo "FAIL: /test/prefix not in RIB"
    printf '%s\n' "$RIB_LIST"
    cat /tmp/c12_rib_list.txt
    exit 1
fi

echo
echo "=== C.12 RESOLVED (testbed) — key-backed command Interest accepted by NFD ==="
exit 0
