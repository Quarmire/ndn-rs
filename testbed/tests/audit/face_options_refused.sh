#!/usr/bin/env bash
# Witness recipe for Face-system Tier 2 §C — `faces/update` uses the
# typed FaceOption seam, the management-face protection guard returns
# `423 LOCKED`, and refused option requests surface a named field +
# reason in the response body.
#
# Finding:     docs/notes/face-system-design-2026-05-20.md §6
# Severity:    Phase-2b architectural cleanup (pre-v0.1.0)
# Decision:    Replace today's hardcoded
#                  if params.face_persistency.is_some() || params.mtu.is_some() {
#                      return ControlResponse::error(CONFLICT, "not yet supported");
#                  }
#              guard with per-option typed apply.  Error mapping:
#              503 NotSupportedByTransport, 409 Immutable,
#              400 OutOfRange, 423 LOCKED for management-face
#              protection.  Response body carries
#              `field=<option> reason=<machine-readable>` so operators
#              know which knob refused.
#
# Witnesses:
#   (a) GREP-PROOF — the dead "not yet supported" guard is gone from
#       `faces/update`.
#   (b) GREP-PROOF — handler calls `link_service().apply(` for typed
#       options.
#   (c) GREP-PROOF — the management-face guard returns status code
#       423 (LOCKED), not 401 (UNAUTHORIZED).
#   (d) GREP-PROOF — `ControlParameters` carries the new
#       `base_cong_interval` and `def_cong_threshold` fields.
#   (e) RUST-UNIT — `faces_update_returns_locked_on_management_face`
#       and `faces_update_refused_option_carries_named_field` in
#       `ndn-mgmt` exercise the response-body shape end-to-end.
#
# Reverify recipe:
#   GREP-PROOF: this script.
#   RUST-UNIT: `cargo test -p ndn-mgmt faces_update_`.
#
# Exit codes:
#   0 — PASS (Tier 2 §C landed)
#   1 — FAIL (handler still bit-twiddles, error taxonomy wrong, or
#       unit tests fail)
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

check_absent_in_paths() {
    local pattern="$1" label="$2"; shift 2
    local hits
    hits="$(grep -rnE "$pattern" "$@" 2>/dev/null || true)"
    if [ -n "$hits" ]; then
        echo "FAIL: $label" >&2
        echo "$hits" >&2
        fail=1
    fi
}

MGMT_FACES=crates/ndn-mgmt/src/modules/faces.rs
STATUS=crates/ndn-config/src/control_response.rs
CONTROL_PARAMS=crates/ndn-config/src/control_parameters.rs

# (a) The dead-end "not yet supported" guard is gone.
check_absent_in_paths 'not yet supported' \
    'faces/update still bails out with the dead "not yet supported" guard' \
    "$MGMT_FACES"

# (b) Handler dispatches typed options through LinkService::apply.
check_grep 'link_service\.apply\(' "$MGMT_FACES" 'faces/update calls LinkService::apply'

# (c) 423 LOCKED added to status codes and used by the management-face
#     guard.  Mirrors NFD's update-protection response code (their
#     "management face cannot be updated").
check_grep '\bLOCKED\b' "$STATUS" 'status::LOCKED (423) constant'
check_grep 'status::LOCKED' "$MGMT_FACES" 'faces/update returns 423 LOCKED on management-face guard'

# (d) ControlParameters has the new mgmt-wire fields.
check_grep 'base_cong_interval' "$CONTROL_PARAMS" 'ControlParameters::base_cong_interval'
check_grep 'def_cong_threshold' "$CONTROL_PARAMS" 'ControlParameters::def_cong_threshold'

# (e) RUST-UNIT — handler-level response-shape tests.
if ! cargo test -p ndn-mgmt --test faces_update_tier2 >/dev/null 2>&1; then
    echo "FAIL: RUST-INTEG faces_update_tier2 tests in ndn-mgmt" >&2
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "PASS: face-system Tier 2 §C — faces/update typed options + named-field error taxonomy."
fi
exit "$fail"
