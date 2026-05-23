#!/usr/bin/env bash
# Witness recipe for ARCH-15 / S17 — `NotificationStream<T>`.
#
# Finding:     docs/notes/architecture-gap-inventory-2026-05-20.md § ARCH-15
# Severity:    Phase 2 architectural cleanup (pre-v0.1.0)
# Witnesses:
#   (a) GREP-PROOF — `NotificationStream<T>` + `NotificationEvent`
#       trait exist in ndn-mgmt; `FaceEvent` / `RouteEvent` /
#       `StrategyEvent` types are defined and publicly re-exported.
#   (b) GREP-PROOF — `mount_management` constructs and installs one
#       stream per NFD module (faces / rib / strategy-choice); the
#       per-module dispatch hooks publish on successful state changes.
#   (c) RUST-INTEG — `tests/notifications.rs` exercises the
#       persistent-Interest pattern end-to-end: a subscriber sends
#       Interest for `seg=<N>` (the next event), `publish` runs, and
#       the Data with the encoded event arrives at the subscriber.
#
# Reverify recipe: GREP-PROOF + RUST-INTEG. Runs in any checkout of
# ndn-rs; no Docker required.
#
# Exit codes:
#   0 — PASS (NotificationStream exists, three streams mounted, witness
#       integration test green)
#   1 — FAIL
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

fail=0

check_grep() {
    local pattern="$1" path="$2" label="$3"
    if ! grep -rqnE "$pattern" "$path"; then
        echo "FAIL: $label — \"$pattern\" not found under $path" >&2
        fail=1
    fi
}

MGMT=crates/ndn-mgmt

# (1) Trait + struct + per-module event types exist.
check_grep 'pub struct NotificationStream'    "$MGMT/src/notification.rs" 'NotificationStream struct'
check_grep 'pub trait NotificationEvent'      "$MGMT/src/notification.rs" 'NotificationEvent trait'
check_grep 'pub struct FaceEvent'             "$MGMT/src/modules/faces.rs"    'FaceEvent type'
check_grep 'pub struct RouteEvent'            "$MGMT/src/modules/rib.rs"      'RouteEvent type'
check_grep 'pub struct StrategyEvent'         "$MGMT/src/modules/strategy.rs" 'StrategyEvent type'

# (2) Public re-exports for host integration.
check_grep 'pub use notification::\{NotificationEvent, NotificationStream\}' \
    "$MGMT/src/lib.rs" 'lib re-exports NotificationStream + NotificationEvent'
check_grep 'pub use modules::faces::\{FaceEvent, FaceEventKind\}' \
    "$MGMT/src/lib.rs" 'lib re-exports FaceEvent'
check_grep 'pub use modules::rib::\{RouteEvent, RouteEventKind\}' \
    "$MGMT/src/lib.rs" 'lib re-exports RouteEvent'
check_grep 'pub use modules::strategy::\{StrategyEvent, StrategyEventKind\}' \
    "$MGMT/src/lib.rs" 'lib re-exports StrategyEvent'

# (3) mount_management mounts all three streams.
check_grep 'NotificationStream::<FaceEvent>::new\(notifications_prefix' \
    "$MGMT/src/lib.rs" 'mount_management creates FaceEvent stream'
check_grep 'NotificationStream::<RouteEvent>::new\(notifications_prefix' \
    "$MGMT/src/lib.rs" 'mount_management creates RouteEvent stream'
check_grep 'NotificationStream::<StrategyEvent>::new\(notifications_prefix' \
    "$MGMT/src/lib.rs" 'mount_management creates StrategyEvent stream'
check_grep 'Arc::clone\(&face_events\)\.install\(engine' \
    "$MGMT/src/lib.rs" 'face_events.install mounted on engine'

# (4) Per-module dispatch hooks publish on success.
check_grep 'stream\.publish\(FaceEvent'     "$MGMT/src/modules/faces.rs"    'FacesModule publishes'
check_grep 'stream\.publish\(RouteEvent'    "$MGMT/src/modules/rib.rs"      'RibModule publishes'
check_grep 'stream\.publish\(StrategyEvent' "$MGMT/src/modules/strategy.rs" 'StrategyModule publishes'

# (5) RUST-INTEG — long-poll subscriber receives the published event.
echo "→ cargo test -p ndn-mgmt --test notifications"
if ! cargo test --quiet -p ndn-mgmt --test notifications >/dev/null 2>&1; then
    echo "FAIL: cargo test -p ndn-mgmt --test notifications did not pass" >&2
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "PASS: ARCH-15 — NotificationStream<T> mounted at faces / rib / strategy-choice; long-poll witness green."
fi
exit "$fail"
