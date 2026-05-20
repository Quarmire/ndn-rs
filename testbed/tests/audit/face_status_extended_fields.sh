#!/usr/bin/env bash
# Witness recipe for Face-system Tier 4 §A — `FaceStatus` carries the
# ndn-rs-specific extension TLVs (effective_mtu, feature_set,
# n_lp_resent_packets, congestion-marks-sent/received, rto_us, …)
# and the `faces/list` dataset writer populates them.
#
# Finding:     docs/notes/face-system-design-2026-05-20.md §4.3
# Severity:    Phase-2b architectural cleanup (pre-v0.1.0)
# Decision:    Extension TLVs in the app-private 0xDA..=0xE2 range
#              (see docs/notes/ndn-rs-tlv-allocations-2026-05-20.md);
#              NFD clients that don't decode the new codes ignore
#              them per the critical-bit rule.
#
# Witnesses:
#   (a) GREP-PROOF — `FaceStatus` struct in `ndn-config/nfd_dataset.rs`
#       carries the new typed fields.
#   (b) GREP-PROOF — TLV constants for `N_LP_RESENT_PACKETS`,
#       `N_CONGESTION_MARKS_SENT`, `N_CONGESTION_MARKS_RECEIVED`,
#       `EFFECTIVE_MTU`, `FEATURE_SET`, `FEATURE_NAME`, `RTO_MICROS`
#       live next to the existing `nfd_dataset::tlv` module.
#   (c) GREP-PROOF — `faces/list` writer in `ndn-mgmt` reads
#       `LpLinkService::snapshot()` and reliability / congestion-marking
#       feature counters to populate the new fields.
#   (d) RUST-UNIT — `face_status_extended_round_trips` confirms an
#       encode→decode loop preserves every new field.
#
# Reverify recipe:
#   GREP-PROOF: this script (a-c).
#   RUST-UNIT: `cargo test -p ndn-config face_status_extended_`.
#
# Exit codes:
#   0 — PASS (Tier 4 §A landed)
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

FS=crates/extension/ndn-config/src/nfd_dataset.rs
MGMT=crates/spec/ndn-mgmt/src/modules/faces.rs

# (a) Struct fields.
for field in n_lp_resent_packets n_congestion_marks_sent n_congestion_marks_received effective_mtu feature_set rto_micros; do
    check_grep "pub ${field}" "$FS" "FaceStatus.${field} field"
done

# (b) TLV constants for the new codes.
for c in N_LP_RESENT_PACKETS N_CONGESTION_MARKS_SENT N_CONGESTION_MARKS_RECEIVED EFFECTIVE_MTU FEATURE_SET FEATURE_NAME RTO_MICROS; do
    check_grep "${c}: u64 = 0x" "$FS" "tlv::${c} constant"
done

# (c) Mgmt writer reads LpLinkService::snapshot() + feature counters.
check_grep 'snapshot\(\)|n_lp_resent_packets\(\)|n_lp_congestion_marked\(\)' \
    "$MGMT" 'faces/list writer reads LpLinkService snapshot + feature counters'

# (d) RUST-UNIT — round-trip the extended fields.
if ! cargo test -p ndn-config face_status_extended_ >/dev/null 2>&1; then
    echo "FAIL: RUST-UNIT face_status_extended_* tests in ndn-config" >&2
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "PASS: face-system Tier 4 §A — FaceStatus extension TLVs encode + decode + populate from LinkService."
fi
exit "$fail"
