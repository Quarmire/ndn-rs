#!/usr/bin/env bash
# Witness recipe for Face-system Tier 4 §C — `ndn-ctl face list`
# renders the rich-field shape (flags, base_cong_interval,
# def_cong_threshold, feature_set, RTO, ndn-rs-specific counters)
# the design doc §8 calls out as the operator surface.
#
# Finding:     docs/notes/face-system-design-2026-05-20.md §8
# Severity:    Phase-2b architectural cleanup (pre-v0.1.0)
# Decision:    Match `nfdc face list`'s rendering shape on the
#              fields NFD knows; append ndn-rs-specific lines for
#              `features:`, `reliability:`, `congestion:`.
#
# Witnesses:
#   (a) GREP-PROOF — `print_face_list` in `binaries/tooling/ndn-tools`
#       renders the new fields by referring to `flags`,
#       `feature_set`, `n_lp_resent_packets`,
#       `n_congestion_marks_sent`, `rto_micros`.
#   (b) GREP-PROOF — flags rendering uses kebab-case strings
#       `local-fields`, `lp-reliability`, `congestion-marking`.
#   (c) RUST-UNIT — `ndnctl_renders_extended_fields` in `ndn-tools`
#       passes a populated `FaceStatus` through the renderer and
#       asserts the output contains every new field's label.
#
# Reverify recipe:
#   GREP-PROOF: this script (a-b).
#   RUST-UNIT: `cargo test -p ndn-tools ndnctl_renders_extended_`.
#
# Exit codes:
#   0 — PASS (Tier 4 §C landed)
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

CTL=binaries/tooling/ndn-tools/src/ctl.rs

# (a) Renderer references the new fields.
for field in flags feature_set n_lp_resent_packets n_congestion_marks_sent rto_micros; do
    check_grep "${field}" "$CTL" "print_face_list reads FaceStatus.${field}"
done

# (b) Kebab-case flag strings on the wire / display.
for label in 'local-fields' 'lp-reliability' 'congestion-marking'; do
    check_grep "${label}" "$CTL" "flag label '${label}'"
done

# (c) RUST-UNIT.
if ! cargo test -p ndn-tools --bin ndn-ctl ndnctl_renders_extended_ >/dev/null 2>&1; then
    echo "FAIL: RUST-UNIT ndnctl_renders_extended_ tests in ndn-tools/bin/ndn-ctl" >&2
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "PASS: face-system Tier 4 §C — ndn-ctl face list renders ndn-rs extension fields."
fi
exit "$fail"
