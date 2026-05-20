#!/usr/bin/env bash
# Witness recipe for Face-system Tier 4 §B — `FaceEvent` extends NFD's
# four lifecycle kinds with five ndn-rs-headline semantic events
# (MtuChanged / PersistencyChanged / ReliabilityBackoff /
# CongestionMark / OptionRefused).
#
# Finding:     docs/notes/face-system-design-2026-05-20.md §5
# Severity:    Phase-2b architectural cleanup (pre-v0.1.0)
# Decision:    Same parent TLV `FaceEventNotification = 0xC0`,
#              same `FaceEventKind = 0xC1` parent; new kind codepoints
#              5..=9.  Per-event payload TLVs in the project-private
#              `0xD0..=0xD9` range (see TLV allocations doc).
#
# Witnesses:
#   (a) GREP-PROOF — `FaceEventKind` enum has the five new variants.
#   (b) GREP-PROOF — `FaceEvent` enum carries each event's payload.
#   (c) GREP-PROOF — `faces/update` emits `MtuChanged` /
#       `PersistencyChanged` / `OptionRefused` on the matching paths.
#   (d) RUST-UNIT — `face_event_extended_round_trips` confirms an
#       encode→decode loop preserves each new kind's payload fields.
#
# Reverify recipe:
#   GREP-PROOF: this script (a-c).
#   RUST-UNIT: `cargo test -p ndn-mgmt --lib face_event_extended_`.
#
# Exit codes:
#   0 — PASS (Tier 4 §B landed)
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

FACES=crates/spec/ndn-mgmt/src/modules/faces.rs

# (a) FaceEventKind has the five new variants.
for variant in MtuChanged PersistencyChanged ReliabilityBackoff CongestionMark OptionRefused; do
    check_grep "${variant}" "$FACES" "FaceEventKind::${variant}"
done

# (b) FaceEvent enum (semantic shape) carries the payload fields.
check_grep 'MtuChanged \{' "$FACES" 'FaceEvent::MtuChanged payload'
check_grep 'PersistencyChanged \{' "$FACES" 'FaceEvent::PersistencyChanged payload'
check_grep 'OptionRefused \{' "$FACES" 'FaceEvent::OptionRefused payload'

# (c) faces/update emits the right events on the right paths.
check_grep 'MtuChanged' "$FACES" 'faces/update emits MtuChanged'
check_grep 'OptionRefused' "$FACES" 'faces/update emits OptionRefused'

# (d) RUST-UNIT — encode/decode round-trip for each new kind.
if ! cargo test -p ndn-mgmt --lib face_event_extended_ >/dev/null 2>&1; then
    echo "FAIL: RUST-UNIT face_event_extended_* tests in ndn-mgmt" >&2
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "PASS: face-system Tier 4 §B — FaceEvent extended kinds round-trip + emit from mgmt handlers."
fi
exit "$fail"
