#!/usr/bin/env bash
# Interop: ndn-rs adopts a ndn-cxx (ndnsec) certificate as a trust-context
# anchor.
#
# A SignedTrustContext's wrapper is an ndn-rs extension, but its anchors are
# plain NDN Certificates (standard Data, /<id>/KEY/<keyid>/... naming —
# ndn-cxx security/certificate.hpp). This proves the cert wire ndn-cxx emits is
# parseable by ndn-rs's anchor decoder, so Data signed under a context's anchors
# validates cross-impl (Data interop itself is covered by fwd_cxx_*).
#
# Env-gated: skips cleanly when ndnsec (ndn-cxx) isn't installed.
set -euo pipefail

command -v ndnsec >/dev/null 2>&1 || {
  echo "SKIP: ndnsec (ndn-cxx) not installed — cross-impl anchor check not run"
  exit 0
}

REPO="$(cd "$(dirname "$0")/../../.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
ID="/interop/ctx/$$"

# ndn-cxx authors an ECDSA identity + self-signed cert, dumped as the raw wire.
ndnsec key-gen -t e "$ID" >/dev/null
ndnsec cert-dump -i "$ID" | base64 -d > "$TMP/anchor.cert"

# ndn-rs builds a trust context with that ndn-cxx cert as its anchor …
PAYLOAD="$(cd "$REPO" && cargo run -q -p ndn-trust-context -- \
  build --namespace "$ID" --version 1 --anchor "$TMP/anchor.cert")"

# … and decoding the join payload recovers exactly that one anchor.
ANCHORS="$(cd "$REPO" && cargo run -q -p ndn-trust-context -- \
  inspect "$PAYLOAD" | awk '/^anchors:/{print $2}')"

if [ "$ANCHORS" = "1" ]; then
  echo "PASS: ndn-rs adopted a ndn-cxx (ndnsec) certificate as a context anchor"
  exit 0
else
  echo "FAIL: expected 1 anchor after round-trip, got '${ANCHORS}'" >&2
  exit 1
fi
