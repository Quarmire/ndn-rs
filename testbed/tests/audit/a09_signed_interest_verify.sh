#!/usr/bin/env bash
# Witness test for audit finding A.09 — Signed Interest signing computes
# the signature over placeholder bytes and patches the real
# ParametersSha256DigestComponent post-sign.
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § A.09
# Severity:    BLOCKER (pending spec confirmation)
# Spec ref:    NDN Packet Format v0.3 signed-interest.html — construction
#              step order: (3) Append InterestSignatureInfo; (5) Insert
#              InterestSignatureValue; (6) Compute and append
#              ParametersSha256DigestComponent. The implication is that
#              the signed region excludes the PSDC, otherwise step (6)
#              would circularly depend on step (5).
# Witnesses:   A signed Interest produced by `InterestBuilder::sign_sync`
#              does not verify in a reference NDN library (python-ndn or
#              ndn-cxx) because the bytes signed at step 5 differ from
#              the bytes the verifier recomputes after seeing the final
#              wire (with the real PSDC in place).
#
# Expected today: FAIL (signature does not verify).
# After fix:      PASS (signature verifies).
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail

if ! command -v python3 >/dev/null 2>&1 || ! python3 -c "import ndn" 2>/dev/null; then
    echo "SKIP: python-ndn not installed (needed as a spec-conformant signed-Interest verifier)" >&2
    exit 2
fi

# We need a small Rust helper that uses ndn-packet's InterestBuilder
# to emit a signed Interest with AppParameters to stdout as raw TLV.
# This helper does not yet exist in the tree — once the dev who picks up
# this test writes it, the path below will resolve. Until then, SKIP.
HELPER="/usr/local/bin/ndn-rs-emit-signed-interest"
if [ ! -x "$HELPER" ]; then
    cat >&2 <<EOF
SKIP: helper binary '$HELPER' not present.

This witness test requires a small Rust binary (to be added under
binaries/ndn-tools/src/ or as an example) that:

  1. Builds an ed25519 keypair in-process.
  2. Uses ndn_packet::encode::InterestBuilder with
     .app_parameters(<some bytes>)
     .sign_sync(SignatureType::SignatureEd25519, Some(&key_name), |region| {
         // Ed25519 sign
     })
  3. Writes the resulting Interest TLV bytes to stdout.

The python verifier below then:
  1. Reads the wire bytes from stdin.
  2. Parses InterestSignatureInfo and the Name's
     ParametersSha256DigestComponent.
  3. Reconstructs the expected signed region per spec.
  4. Verifies the Ed25519 signature against that region.

A.09 predicts verification fails. Once the helper lands, wire
this test up to it and run.
EOF
    exit 2
fi

INTEREST_BYTES=$("$HELPER" 2>/dev/null)

if ! python3 <<'PYEOF' <<< "$INTEREST_BYTES"
import sys, hashlib
from ndn.encoding import parse_interest

wire = sys.stdin.buffer.read()
name, params, app_params, sig_ptrs = parse_interest(wire, with_tl=True)

# Reconstruct the signed region per spec: Name-without-PSDC +
# ApplicationParameters + InterestSignatureInfo. Compare to what
# ndn-rs signed over. If they differ, A.09 is confirmed.
#
# python-ndn's parse_interest does the right thing internally — if
# the signature doesn't verify, it returns an error state we can read.

# The specific extraction API depends on python-ndn version; the
# implementer should consult `ndn.app_support.security.Validator`.

# Simplified: try to verify via the public key embedded in KeyLocator
# (or a known test public key). If verify returns False, A.09 holds.
#
# This block needs to be filled in by the implementer once the
# helper exists and emits a known test keypair.
print("TODO: fill in python-ndn signature verify; expected to fail today")
sys.exit(1)
PYEOF
then
    RC=$?
    if [ "$RC" = "1" ]; then
        echo "FAIL (expected): signature did not verify — A.09 confirmed"
        exit 1
    fi
    echo "FAIL: unexpected verifier error"
    exit 1
fi

echo "PASS: signed Interest verified successfully"
exit 0
