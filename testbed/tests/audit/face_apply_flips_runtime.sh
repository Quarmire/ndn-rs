#!/usr/bin/env bash
# Witness recipe for Face-system Tier 3 — `LpLinkService::apply()`
# actually flips the dataplane feature ON / OFF at runtime, not just
# the FaceState bitmap.
#
# Finding:     docs/notes/face-system-design-2026-05-20.md § Tier 3
# Severity:    Phase-2b architectural cleanup (pre-v0.1.0)
# Decision:    Move per-feature runtime mutability behind the
#              `LinkServiceFeature` trait. Each feature owns an
#              `AtomicBool` `enabled` switch; `LpLinkService::apply`
#              routes typed FaceOptions to the matching feature's
#              setter.  apply(LpReliability(true)) → ReliabilityFeature
#              starts tracking / retransmitting; apply(LpReliability(false))
#              stops.  Same for CongestionMarking.
#
# Witnesses:
#   (a) GREP-PROOF — `ReliabilityFeature` struct exists in
#       `crates/spec/ndn-transport/src/link_service/features/reliability.rs`.
#   (b) GREP-PROOF — `CongestionMarkingFeature` exists in
#       `crates/spec/ndn-transport/src/link_service/features/congestion_marking.rs`.
#   (c) GREP-PROOF — `LpLinkService::apply` dispatches to features
#       (looks for `feature.set_enabled` or `set_lp_reliability_enabled`).
#   (d) GREP-PROOF — `default_features_for_network_face` registers
#       both new features in addition to the original six.
#   (e) RUST-UNIT — `apply_flips_reliability_feature` and
#       `apply_flips_congestion_marking_feature` in `ndn-transport`
#       confirm that apply(true)/apply(false) flip the feature's
#       observable `is_enabled()`.
#
# Reverify recipe:
#   GREP-PROOF: this script (a-d).
#   RUST-UNIT: `cargo test -p ndn-transport --lib apply_flips_`.
#
# Exit codes:
#   0 — PASS (Tier 3 §A apply seam landed)
#   1 — FAIL (feature absent, apply does not route, or unit test fails)
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

FEATURES=crates/spec/ndn-transport/src/link_service/features
LP=crates/spec/ndn-transport/src/link_service/mod.rs

# (a) ReliabilityFeature impl on disk.
check_grep 'pub struct ReliabilityFeature'   "$FEATURES/reliability.rs"        'ReliabilityFeature struct'
check_grep 'impl LinkServiceFeature for ReliabilityFeature' \
    "$FEATURES/reliability.rs"        'ReliabilityFeature LinkServiceFeature impl'

# (b) CongestionMarkingFeature impl on disk.
check_grep 'pub struct CongestionMarkingFeature' \
    "$FEATURES/congestion_marking.rs" 'CongestionMarkingFeature struct'
check_grep 'impl LinkServiceFeature for CongestionMarkingFeature' \
    "$FEATURES/congestion_marking.rs" 'CongestionMarkingFeature LinkServiceFeature impl'

# (c) `LpLinkService::apply` actually flips features (not just Ok(())).
check_grep 'reliability_feature|reliability\.set_enabled|set_lp_reliability_enabled' \
    "$LP" 'LpLinkService::apply routes to ReliabilityFeature'
check_grep 'congestion_marking_feature|congestion_marking\.set_enabled|set_congestion_marking_enabled' \
    "$LP" 'LpLinkService::apply routes to CongestionMarkingFeature'

# (d) Both features registered in the default network-face pipeline.
check_grep 'ReliabilityFeature'        "$FEATURES/mod.rs" 'default pipeline includes ReliabilityFeature'
check_grep 'CongestionMarkingFeature'  "$FEATURES/mod.rs" 'default pipeline includes CongestionMarkingFeature'

# (e) RUST-UNIT — apply flips the feature observably.
if ! cargo test -p ndn-transport --lib apply_flips_ >/dev/null 2>&1; then
    echo "FAIL: RUST-UNIT apply_flips_* tests in ndn-transport" >&2
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "PASS: face-system Tier 3 §A — apply() flips ReliabilityFeature + CongestionMarkingFeature at runtime."
fi
exit "$fail"
