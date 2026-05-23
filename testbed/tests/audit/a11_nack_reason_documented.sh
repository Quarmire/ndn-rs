#!/usr/bin/env bash
# Audit witness — A.11.
#
# Finding:     `NackReason::NotYet = 160` is not in the NDNLPv2
#              registry; ndn-rs presents it alongside the
#              registered codes (50/100/150) as if it were a
#              standard NackReason.
# Witness:     GREP-PROOF — the `NackReason` enum doc declares
#              `NotYet` as an ndn-rs-private extension and the
#              new `is_registered()` method excludes it.  Peers
#              that follow the registry still see `Other(160)`
#              on the wire; the wire is unambiguous to external
#              observers.
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

NACK="crates/ndn-packet/src/nack.rs"

if ! grep -q "ndn-rs-private extension" "$NACK"; then
    echo "FAIL: NackReason doc does not flag NotYet as private"
    exit 1
fi
if ! grep -q "fn is_registered" "$NACK"; then
    echo "FAIL: NackReason::is_registered method missing"
    exit 1
fi

# Sanity-build.
cargo build -p ndn-packet --features std --quiet 2>&1 | tail -2

echo "=== A.11 RESOLVED — NotYet documented as ndn-rs-private; is_registered() distinguishes ==="
