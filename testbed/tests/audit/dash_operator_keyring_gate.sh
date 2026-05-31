#!/usr/bin/env bash
# Witness — mgmt-command signing is gated on a dashboard-provisioned key,
# routed through a CustodianRegistry (the "gate on provisioned key").
#
# The dashboard now holds its own Ed25519 operator key in an InPageCustodian
# (operator_keyring) and signs mgmt commands through a CustodianSigner when one
# is provisioned; otherwise it falls back to DigestSha256 (the gate). This
# witness locks:
#   1. operator_keyring exists and the desktop command client gates on it.
#   2. The gate logic is correct (closed → command_signer None; open after
#      provisioning → a CustodianSigner with the right key/sig-type).
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

if ! command -v cargo >/dev/null 2>&1; then
    echo "SKIP: cargo missing" >&2
    exit 2
fi

DASH="crates/tooling/ndn-dashboard"

if [ ! -f "$DASH/src/operator_keyring.rs" ]; then
    echo "FAIL: operator_keyring module missing" >&2
    exit 1
fi
# The desktop command client must consult the gate.
if ! grep -q 'operator_keyring::command_signer' "$DASH/src/app.rs"; then
    echo "FAIL: app.rs command client does not gate on operator_keyring" >&2
    exit 1
fi
# A real source must feed the keyring — SafeBag import deposits the Ed25519 key.
if ! grep -q 'operator_keyring::provision_ed25519_pkcs8' "$DASH/src/views/safebag_import.rs"; then
    echo "FAIL: SafeBag import does not feed the operator keyring" >&2
    exit 1
fi

if cargo test -p ndn-dashboard --bins -q gate_opens >/tmp/dash_keyring.log 2>&1 \
   && cargo test -p ndn-custodian -q custodian_signer >>/tmp/dash_keyring.log 2>&1; then
    echo "ok: mgmt signing gated on a custodian-provisioned operator key"
else
    echo "FAIL: operator-keyring gate / CustodianSigner tests failed" >&2
    cat /tmp/dash_keyring.log >&2
    exit 1
fi
