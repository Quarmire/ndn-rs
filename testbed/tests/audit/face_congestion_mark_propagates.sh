#!/usr/bin/env bash
# Witness recipe for Face-system Tier 3 §B — `CongestionMarkingFeature`
# observes egress queue depth (via an injected `queue_depth_fn`) and
# emits an LP `CongestionMark` TLV on outbound frames once depth
# crosses `def_cong_threshold`.
#
# Finding:     docs/notes/face-system-design-2026-05-20.md § Q3 + Tier 3
# Severity:    Phase-2b architectural cleanup (pre-v0.1.0)
# Decision:    Q3a — LP-layer fragment queue (`FaceState.send_tx`) is
#              the queue-depth source.  Q3b — CoDel-style algorithm:
#              when measured queue depth has stayed above
#              `def_cong_threshold` for at least
#              `base_congestion_marking_interval`, mark the next
#              outbound frame.  Feature receives a closure returning
#              current depth so ndn-transport need not depend on
#              ndn-engine's `EgressItem`.
#
# Witnesses:
#   (a) GREP-PROOF — `CongestionMarkingFeature` struct exists in
#       `features/congestion_marking.rs`.
#   (b) GREP-PROOF — feature stores `queue_depth_fn` and the two
#       CoDel-parameter fields `base_cong_interval` and
#       `def_cong_threshold` (with the typed FaceOption setters).
#   (c) GREP-PROOF — `n_lp_congestion_marked` counter on the feature.
#   (d) RUST-UNIT — `congestion_mark_propagates_on_saturation`:
#       - enable the feature with `def_cong_threshold = 4`
#       - inject a `queue_depth_fn` returning a saturated depth (e.g. 64)
#       - run on_egress against an OutboundLpFrame
#       - assert the wire bytes are mutated so an LP CongestionMark
#         TLV (0x340) appears
#       - assert `n_lp_congestion_marked` incremented
#   (e) RUST-UNIT — when the feature is disabled, no mark is emitted.
#
# Reverify recipe:
#   GREP-PROOF: this script (a-c).
#   RUST-UNIT: `cargo test -p ndn-transport --lib congestion_mark_`.
#
# Exit codes:
#   0 — PASS (Tier 3 §B congestion marking landed)
#   1 — FAIL
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

fail=0

check_grep() {
    local pattern="$1" path="$2" label="$3"
    if ! grep -rqnE "$pattern" "$path"; then
        echo "FAIL: $label — pattern \"$pattern\" not found under $path" >&2
        fail=1
    fi
}

CM=crates/ndn-transport/src/link_service/features/congestion_marking.rs

check_grep 'pub struct CongestionMarkingFeature' "$CM" 'CongestionMarkingFeature struct'
check_grep 'queue_depth_fn'                      "$CM" 'queue_depth_fn closure field'
check_grep 'base_cong_interval'                  "$CM" 'base_cong_interval CoDel param'
check_grep 'def_cong_threshold'                  "$CM" 'def_cong_threshold CoDel param'
check_grep 'n_lp_congestion_marked'              "$CM" 'n_lp_congestion_marked counter'

if ! cargo test -p ndn-transport --lib congestion_mark_ >/dev/null 2>&1; then
    echo "FAIL: RUST-UNIT congestion_mark_* tests in ndn-transport" >&2
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "PASS: face-system Tier 3 §B — CongestionMarkingFeature emits LP CongestionMark on saturated egress queue."
fi
exit "$fail"
