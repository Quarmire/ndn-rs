#!/usr/bin/env bash
# Witness for SafeBag import/export portability against ndn-cxx `ndnsec`.
#
# SafeBag is a portability format, so local TLV round-trips are not enough.
# This script proves both directions through the reference CLI:
#   1. ndn-rs emits an ECDSA-P256 SafeBag.
#   2. ndn-cxx `ndnsec import` accepts it.
#   3. ndn-cxx `ndnsec export` re-emits the imported identity.
#   4. ndn-rs decodes the re-export and proves the encrypted private key
#      matches the embedded CertificateV2 public key.
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

if ! command -v docker >/dev/null 2>&1; then
    echo "SKIP: docker missing"
    exit 2
fi

if ! docker compose -f testbed/docker-compose.yml exec -T interop true >/dev/null 2>&1; then
    echo "SKIP: Docker interop service is not running"
    exit 2
fi

if ! docker compose -f testbed/docker-compose.yml exec -T interop \
        bash -lc 'command -v ndnsec >/dev/null && command -v ndn-safebag-witness >/dev/null' \
        >/dev/null 2>&1; then
    echo "SKIP: interop image lacks ndnsec or ndn-safebag-witness; rebuild interop"
    exit 2
fi

if docker compose -f testbed/docker-compose.yml exec -T interop bash -lc '
    set -euo pipefail
    work="$(mktemp -d)"
    export HOME="$work/home"
    mkdir -p "$HOME"
    pass="safebag-pass"
    identity="/interop/safebag/rs"

    ndn-safebag-witness export-ecdsa \
      --identity "$identity" \
      --password "$pass" \
      --out "$work/rs.ndnkey" \
      >"$work/rs-export.txt"

    # The ndnsec CLI stores SafeBag files as base64 text; ndn-rs verifies the
    # underlying raw TLV so both file conventions are exercised explicitly.
    base64 "$work/rs.ndnkey" >"$work/rs.ndnkey.b64"
    ndnsec import -P "$pass" -i "$work/rs.ndnkey.b64"
    ndnsec export -P "$pass" -i -o "$work/cxx.ndnkey.b64" "$identity"
    base64 -d "$work/cxx.ndnkey.b64" >"$work/cxx.ndnkey"

    ndn-safebag-witness import-verify \
      --identity "$identity" \
      --password "$pass" \
      --input "$work/cxx.ndnkey" \
      >"$work/rs-import.txt"

    cat "$work/rs-export.txt"
    cat "$work/rs-import.txt"
' > /tmp/c09_safebag_ndnsec_interop.log 2>&1; then
    cat /tmp/c09_safebag_ndnsec_interop.log
    echo
    echo "=== C.09 SafeBag PASS — ndn-rs export -> ndnsec import/export -> ndn-rs import verified ==="
    exit 0
else
    echo "FAIL: SafeBag ndnsec interop"
    cat /tmp/c09_safebag_ndnsec_interop.log
    exit 1
fi
