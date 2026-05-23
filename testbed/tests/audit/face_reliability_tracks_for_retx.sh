#!/usr/bin/env bash
# Witness recipe for Face-system Tier 3 §A — when enabled,
# `ReliabilityFeature` tracks outbound LP frames for retransmission
# and surfaces a `n_lp_resent_packets` counter increment on each
# retransmit.
#
# Finding:     docs/notes/face-system-design-2026-05-20.md § Tier 3
# Severity:    Phase-2b architectural cleanup (pre-v0.1.0)
# Decision:    `ReliabilityFeature` wraps the existing
#              `LpReliability` state machine from `reliability.rs`
#              (per Q2: "keep what's on disk").  `on_egress` tracks
#              every reliable LP frame for retx; `on_ingress` feeds
#              wire bytes back so Acks consume tracked frames; the
#              feature's tick produces retransmission wires whose
#              count drives `n_lp_resent_packets`.
#
# Witnesses:
#   (a) GREP-PROOF — `n_lp_resent_packets: AtomicU64` counter on
#       `ReliabilityFeature`.
#   (b) GREP-PROOF — `ReliabilityFeature` wraps a `Mutex<LpReliability>`
#       (reuses the state machine).
#   (c) RUST-UNIT — `reliability_feature_tracks_for_retx`:
#       - enable the feature
#       - push N outbound LP frames through `on_egress`
#       - simulate "no acks received" by calling `check_retransmit`
#         after time advances past the initial RTO
#       - assert `n_lp_resent_packets > 0`
#       - assert disabled feature does NOT track / NOT retransmit
#
# Reverify recipe:
#   GREP-PROOF: this script (a-b).
#   RUST-UNIT: `cargo test -p ndn-transport --lib reliability_feature_`.
#
# Exit codes:
#   0 — PASS (Tier 3 §A reliability tracking landed)
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

FEATURES=crates/ndn-transport/src/link_service/features

check_grep 'n_lp_resent_packets'        "$FEATURES/reliability.rs" 'n_lp_resent_packets counter'
check_grep 'Mutex<LpReliability>'       "$FEATURES/reliability.rs" 'wraps existing LpReliability state machine'

if ! cargo test -p ndn-transport --lib reliability_feature_ >/dev/null 2>&1; then
    echo "FAIL: RUST-UNIT reliability_feature_* tests in ndn-transport" >&2
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "PASS: face-system Tier 3 §A — ReliabilityFeature tracks egress + emits retx; counter increments."
fi
exit "$fail"
