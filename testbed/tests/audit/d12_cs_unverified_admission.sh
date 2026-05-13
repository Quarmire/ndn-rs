#!/usr/bin/env bash
# Audit witness — D.12.
#
# Finding:     `ContentStore` admitted Data without signature verification
#              when the engine was built without a `Validator` (the
#              default factory).  `ValidationStage`'s no-validator branch
#              set `ctx.verified = true` unconditionally, so a forged
#              Data injected over a network face would satisfy
#              subsequent Interests from the CS.
#
# Witness:     RUST-UNIT
#                d12_disabled_validator_does_not_verify_network_data
#                d12_cs_rejects_unverified_ctx
#                d12_validation_sets_verified_on_valid
#                d12_cs_admits_verified_ctx
#              The fix is fail-secure:
#                `ValidationStage::process` with `validator = None` now
#                returns `Action::Satisfy(ctx)` WITHOUT setting
#                `ctx.verified = true`.  Local-face Data is short-
#                circuited to `verified = true` upstream (in
#                `dispatcher/pipeline.rs`), so this branch only fires
#                for NonLocal-face inbound Data — exactly the path the
#                audit flagged as a CS-poisoning risk.
#
# Spec ref:    Audit D.12.  NFD's `daemon/fw/forwarder.cpp`'s
#              `onIncomingData` requires the validator chain before
#              `cs.insert`.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

if ! cargo test -p ndn-engine --lib --quiet \
        stages::cs::tests::d12_ 2>&1 | tail -3; then
    echo "FAIL: D.12 unit tests"
    exit 1
fi

echo "=== D.12 RESOLVED — CS refuses unverified network-face Data ==="
