#!/usr/bin/env bash
# Audit witness — D.06.
#
# Finding:     `StrategyStage` forwarded `ctx.raw_bytes` to each
#              chosen out-face without consulting the PIT entry's
#              out-records, so a repeat-Interest with the same
#              nonce within the lifetime would be re-sent on the
#              same upstream face.  PIT-level
#              `PitEntry::add_out_record` existed but no stage
#              called it.
# Witness:     RUST-UNIT
#                d06_pit_out_record_detects_duplicate_face_nonce
#              The fix lives in
#              crates/spec/ndn-engine/src/stages/strategy.rs:
#              after a `ForwardingAction::Forward` decision, every
#              effective out-face is filtered through the PIT
#              entry's out-records and admitted only when no
#              prior out-record matches `(face_id, nonce)`.
# Spec ref:    NFD Developer Guide §3.4 Outgoing Interest pipeline.
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

if ! cargo test -p ndn-engine --lib --quiet \
        d06_pit_out_record_detects_duplicate_face_nonce 2>&1 | tail -5; then
    echo "FAIL: D.06 unit test"
    exit 1
fi

# Anchor the prose claim: strategy stage must read out_records.
if ! grep -q "or.face_id == fid.0 && or.last_nonce == nonce" \
        crates/spec/ndn-engine/src/stages/strategy.rs; then
    echo "FAIL: StrategyStage no longer consults PIT out_records"
    exit 1
fi

echo "=== D.06 RESOLVED — outgoing Interest suppression by (face, nonce) ==="
