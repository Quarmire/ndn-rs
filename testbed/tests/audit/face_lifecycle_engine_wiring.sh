#!/usr/bin/env bash
# Witness recipe for Face-system Tier 6 §I + §J + §K — engine-side
# wiring lands behind the Tier 3 / Tier 4 trait seams.
#
# Finding:     docs/notes/face-system-design-2026-05-20.md
#              §post-impl addendum "deferred items"
# Severity:    Phase-2b architectural cleanup (pre-v0.1.0)
# Decision:    The engine drives the per-feature state at face-add
#              time:
#                 §I — `wire_queue_depth_fn` injects a closure
#                      reading the egress send_tx into the
#                      CongestionMarkingFeature.
#                 §J — the face_sender retx tick pumps
#                      `take_retransmissions` onto the egress queue.
#                 §K — the engine holds an optional
#                      `FaceLifecycleSink`; `mount_management`
#                      installs one that publishes `Up` / `Down`
#                      events to the face notifications stream.
#
# Witnesses:
#   (a) GREP-PROOF — `LinkService` trait declares
#       `wire_queue_depth_fn` and `reliability_feature_handle`.
#   (b) GREP-PROOF — `add_face_with_persistency` calls
#       `wire_queue_depth_fn` with a closure reading the send_tx.
#   (c) GREP-PROOF — `run_face_sender` pumps
#       `take_retransmissions` on every retx tick.
#   (d) GREP-PROOF — `FaceLifecycleSink` trait + `set_face_lifecycle_sink`
#       accessor.
#   (e) GREP-PROOF — `mount_management` constructs
#       `NotificationFaceLifecycleSink` and calls
#       `engine.set_face_lifecycle_sink`.
#   (f) RUST-INTEG — `engine_up_and_mgmt_created_both_publish_on_face_create`
#       exercises the end-to-end Up + Created flow.
#
# Reverify recipe:
#   GREP-PROOF: this script.
#   RUST-INTEG: `cargo test -p ndn-mgmt --test face_lifecycle_sink_publishes`.
#
# Exit codes:
#   0 — PASS
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

LS=crates/spec/ndn-transport/src/link_service/mod.rs
EVENT=crates/spec/ndn-transport/src/face_event.rs
ENGINE=crates/spec/ndn-engine/src/engine.rs
MGMT=crates/spec/ndn-mgmt/src/lib.rs

# (a) LinkService trait seams.
check_grep 'fn wire_queue_depth_fn'         "$LS"    'LinkService::wire_queue_depth_fn'
check_grep 'fn reliability_feature_handle'  "$LS"    'LinkService::reliability_feature_handle'

# (b) Engine wires the queue-depth closure at face-add time.
check_grep 'wire_queue_depth_fn\(queue_depth_fn\)' "$ENGINE" \
    'engine calls wire_queue_depth_fn at add_face time'

# (c) Engine pumps take_retransmissions on the retx tick.
check_grep 'feature\.take_retransmissions' "$ENGINE" \
    'engine pumps ReliabilityFeature::take_retransmissions onto send_tx'

# (d) FaceLifecycleSink trait + setter.
check_grep 'pub trait FaceLifecycleSink' "$EVENT"  'FaceLifecycleSink trait'
check_grep 'fn set_face_lifecycle_sink' "$ENGINE" 'ForwarderEngine::set_face_lifecycle_sink'

# (e) mount_management installs the sink.
check_grep 'NotificationFaceLifecycleSink' "$MGMT" 'NotificationFaceLifecycleSink bridge impl'
check_grep 'set_face_lifecycle_sink'       "$MGMT" 'mount_management installs the sink'

# (f) End-to-end integration test.
if ! cargo test -p ndn-mgmt --test face_lifecycle_sink_publishes >/dev/null 2>&1; then
    echo "FAIL: RUST-INTEG face_lifecycle_sink_publishes" >&2
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "PASS: face-system Tier 6 §I+§J+§K — engine wires CongestionMarking queue depth, Reliability retx pump, and FaceLifecycleSink."
fi
exit "$fail"
