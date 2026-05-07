#!/usr/bin/env bash
# Generate the testbed identity rig for E.01 signed-management testing.
#
# Creates (in ./pib/):
#   /test        — self-signed root anchor (trust anchor for ndn-fwd)
#   /test/admin  — key for ndn-ctl command signing (also a trust anchor
#                  so the mgmt validator can verify its self-signed cert)
#
# Idempotent: skips generation if both keys already exist with valid certs.
#
# Usage:
#   ./gen_identities.sh [--pib <path>]   (default: ./pib)
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PIB="${1:-$SCRIPT_DIR/pib}"

# Locate ndn-sec binary.
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
NDN_SEC=""
for candidate in \
    "$REPO_ROOT/target/debug/ndn-sec" \
    "$REPO_ROOT/target/release/ndn-sec" \
    "$(command -v ndn-sec 2>/dev/null || true)"; do
    if [ -x "$candidate" ]; then
        NDN_SEC="$candidate"
        break
    fi
done

if [ -z "$NDN_SEC" ]; then
    echo "ERROR: ndn-sec not found. Run: cargo build -p ndn-tools --bin ndn-sec" >&2
    exit 1
fi

echo "Using PIB: $PIB"
echo "Using ndn-sec: $NDN_SEC"

# /test root anchor — --skip-if-exists makes this idempotent.
"$NDN_SEC" --pib "$PIB" keygen --anchor --skip-if-exists /test
echo "  /test: trust anchor ready"

# /test/admin signing key — also registered as trust anchor so the mgmt
# validator accepts its self-signed cert without chain walking.
"$NDN_SEC" --pib "$PIB" keygen --anchor --skip-if-exists /test/admin
echo "  /test/admin: trust anchor ready"

echo
echo "Identity rig ready at: $PIB"
echo "Configure ndn-fwd with:"
echo "  [security.mgmt]"
echo "  require_signed_commands = true"
echo "  trust_anchor_pib = \"$PIB\""
echo
echo "Sign commands with:"
echo "  ndn-ctl --identity /test/admin --pib \"$PIB\" <command>"
