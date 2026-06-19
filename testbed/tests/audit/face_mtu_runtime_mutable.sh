#!/usr/bin/env bash
# Witness recipe for Face-system Tier 2 §B — `Transport` exposes
# typed runtime mutability for MTU and persistency, and the override
# matrix matches the design doc.
#
# Finding:     docs/notes/face-system-design-2026-05-20.md §2
# Severity:    Phase-2b architectural cleanup (pre-v0.1.0)
# Decision:    Mutable per-face knobs live on `Transport` (not on an
#              opaque options blob).  Default-impl on the trait errors
#              with `MtuError::NotSupported` / `PersistencyError::NotSupported`
#              so transports that have no story remain compile-safe.
#              UDP/TCP override `set_send_mtu` (clamping where the
#              medium requires); Shm / InProc / Internal override to
#              `Immutable` because the value is baked at create time;
#              Ether overrides MTU but persistency stays Immutable
#              (multi-access).  WebSocket / WebTransport / WebRtc keep
#              the default NotSupported (deferred).
#
# Witnesses:
#   (a) GREP-PROOF — `Transport` trait declares `fn set_send_mtu` and
#       `fn set_persistency`; both with default-impl that errors.
#   (b) GREP-PROOF — `MtuError` and `PersistencyError` enums exist with
#       at least `NotSupported`, `Immutable`, `OutOfRange` variants.
#   (c) GREP-PROOF — `ErasedTransport` mirrors both methods so the
#       object-safe surface stays usable by the face table.
#   (d) GREP-PROOF — UdpFace overrides `set_send_mtu` (the canonical
#       runtime-mutable transport).
#   (e) GREP-PROOF — ShmFace's transport impl returns `Immutable` for
#       both setters (witnesses the "baked at create time" decision
#       on disk, not just in the doc).
#   (f) RUST-UNIT — `mtu_default_errors_not_supported` confirms a
#       transport that does not override either method receives the
#       NotSupported variant.
#
# Reverify recipe:
#   GREP-PROOF: this script (a-e).
#   RUST-UNIT: `cargo test -p ndn-transport mtu_default_errors_not_supported`.
#
# Exit codes:
#   0 — PASS (Tier 2 §B landed)
#   1 — FAIL (Transport seam missing, override matrix incomplete, or
#       unit test fails)
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

TRANSPORT=crates/ndn-transport/src/transport.rs

# (a) Transport seam.
check_grep 'fn set_send_mtu'    "$TRANSPORT" 'Transport::set_send_mtu'
check_grep 'fn set_persistency' "$TRANSPORT" 'Transport::set_persistency'

# (b) Error enums.
check_grep 'enum MtuError'         "$TRANSPORT" 'MtuError enum'
check_grep 'enum PersistencyError' "$TRANSPORT" 'PersistencyError enum'
for variant in NotSupported Immutable OutOfRange; do
    check_grep "$variant" "$TRANSPORT" "Error variant ${variant}"
done

# (c) Object-safe ErasedTransport mirror.
check_grep 'fn set_send_mtu' "$TRANSPORT" 'ErasedTransport::set_send_mtu'
check_grep 'fn set_persistency' "$TRANSPORT" 'ErasedTransport::set_persistency'

# (d) UdpFace overrides set_send_mtu (canonical runtime-mutable transport).
check_grep 'fn set_send_mtu' crates/faces/ndn-face/src/net 'UdpFace::set_send_mtu override'

# (e) ShmFace declares Immutable for both setters.
check_grep 'Immutable' crates/faces/ndn-face/src/local 'ShmFace Immutable setter response'

# (f) RUST-UNIT exercising default-impl behaviour.
if ! cargo test -p ndn-transport --lib mtu_default_errors_not_supported \
        >/dev/null 2>&1; then
    echo "FAIL: RUST-UNIT mtu_default_errors_not_supported in ndn-transport" >&2
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "PASS: face-system Tier 2 §B — Transport runtime mutability seam + override matrix."
fi
exit "$fail"
