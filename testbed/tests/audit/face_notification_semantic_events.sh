#!/usr/bin/env bash
# Witness recipe for Face-system Tier 5 §F — semantic events the
# Tier-4 §B handlers emit on `faces/update` reach subscribers on
# `/localhost/nfd/faces/notifications` end-to-end through the mgmt
# dispatcher.
#
# Finding:     docs/notes/face-system-design-2026-05-20.md §5 + Tier 4 §B
# Severity:    Phase-2b architectural cleanup (pre-v0.1.0)
# Decision:    Refused-option paths in `faces/update` publish a
#              `FaceEvent::OptionRefused { face_id, option, reason }`
#              alongside the named-field error body.  Subscribers see
#              the event by issuing an Interest at
#              `<prefix>/seg=N` and decoding the returned Data's
#              content as the `FaceEvent` wire shape.
#
# Witnesses:
#   (a) GREP-PROOF — the integration test exists.
#   (b) RUST-INTEG — `faces_update_refused_publishes_option_refused_event`
#       in `ndn-mgmt` exercises the full mgmt-handler →
#       NotificationStream → subscriber-Interest path and asserts the
#       payload matches the response body.
#
# Reverify recipe:
#   GREP-PROOF: this script (a).
#   RUST-INTEG: `cargo test -p ndn-mgmt --test face_notification_semantic_events`.
#
# Exit codes:
#   0 — PASS
#   1 — FAIL
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

fail=0

TEST=crates/ndn-mgmt/tests/face_notification_semantic_events.rs
if [ ! -f "$TEST" ]; then
    echo "FAIL: integration test $TEST missing" >&2
    fail=1
fi

if ! cargo test -p ndn-mgmt --test face_notification_semantic_events >/dev/null 2>&1; then
    echo "FAIL: RUST-INTEG face_notification_semantic_events" >&2
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "PASS: face-system Tier 5 §F — faces/update refused paths publish semantic events end-to-end."
fi
exit "$fail"
