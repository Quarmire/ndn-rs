#!/usr/bin/env bash
# Witness test for audit finding C.01 — SignatureSha256WithEcdsa declared
# but cryptographically absent; ndn-rs Validator routes every algorithm
# through Ed25519Verifier.
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § C.01
# Severity:    BLOCKER
# Spec ref:    NDN Packet Format v0.3 signature.html — SignatureType 3 is
#              SignatureSha256WithEcdsa; verifiers MUST dispatch on the
#              SignatureType.
# Witnesses:   Data signed by ndn-cxx with an ECDSA key, fed to ndn-rs's
#              Validator, returns Invalid.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail

NFD_SOCK="${NFD_SOCK:-/run/nfd/nfd.sock}"
NDN_FWD_SOCK="${NDN_FWD_SOCK:-/run/ndn-fwd/ndn-fwd.sock}"
PREFIX="/audit/c01-ecdsa"

for tool in ndnsec ndnpoke ndnpeek ndn-ctl; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "SKIP: '$tool' not available (interop image required)" >&2
        exit 2
    fi
done

# 1. Create an ECDSA identity in ndn-cxx and a self-signed cert.
IDENTITY="/audit/c01-ecdsa-signer"
ndnsec key-gen -t ec "$IDENTITY" >/tmp/c01_cert.base64 2>/dev/null || true

# 2. Publish a Data under the prefix, signed by the ECDSA identity.
echo "ecdsa-content" | ndnsec sign-req "$IDENTITY" >/dev/null 2>&1 || true
ndnpoke -s /tmp/c01_cert.base64 "$PREFIX/probe" <<< "ecdsa-content" &
POKE_PID=$!
sleep 0.5

# 3. Fetch via ndn-rs's ndn-peek (which goes through ndn-fwd's Validator path).
#    The Validator is hard-wired to Ed25519Verifier (C.05), so an ECDSA
#    signature returns Invalid and the Data is dropped before reaching peek.
set +e
OUTPUT=$(timeout 4 ndn-peek --socket "$NDN_FWD_SOCK" "$PREFIX/probe" 2>&1)
PEEK_EXIT=$?
set -e

kill "$POKE_PID" 2>/dev/null || true
wait "$POKE_PID" 2>/dev/null || true

if [ "$PEEK_EXIT" -ne 0 ] && echo "$OUTPUT" | grep -qiE "(timeout|validation|invalid)"; then
    echo "FAIL (expected): ndn-rs Validator rejected ECDSA-signed Data — C.01 confirmed"
    exit 1
fi

if [ "$PEEK_EXIT" -eq 0 ] && echo "$OUTPUT" | grep -q "ecdsa-content"; then
    echo "PASS: ECDSA-signed Data accepted; C.01 resolved"
    exit 0
fi

echo "FAIL: unexpected result; peek_exit=$PEEK_EXIT, output=$OUTPUT"
exit 1
