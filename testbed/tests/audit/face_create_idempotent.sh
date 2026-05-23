#!/usr/bin/env bash
# Witness recipe for Face-system Tier 5 §H — idempotent
# `faces/create`: when the URI is already attached to a face,
# return `200 OK` with the existing face_id and best-effort apply
# mtu / flags / persistency.  Refused options collect into
# `body.partial_failures` so NFD-canonical clients ignore the
# extra field while ndn-rs clients learn which subset stuck.
#
# Finding:     docs/notes/face-system-design-2026-05-20.md §6 + §6.1
# Severity:    Phase-2b architectural cleanup (pre-v0.1.0)
# Decision:    `partial_failures` rides on `ControlParameters` as a
#              sequence of `(option, reason)` UTF-8 pairs wrapped in
#              TLV 0xE4 (PartialFailures) → 0xE5 (PartialFailure) →
#              0xD8 (OptionName) + 0xD9 (RefusalReason).
#
# Witnesses:
#   (a) GREP-PROOF — `existing_face_id_for_uri` + `faces_create_idempotent`
#       helpers live in `crates/ndn-mgmt/src/modules/faces.rs`.
#   (b) GREP-PROOF — `ControlParameters` carries `partial_failures`.
#   (c) GREP-PROOF — TLV constants for PARTIAL_FAILURES / PARTIAL_FAILURE
#       / OPTION_NAME / REFUSAL_REASON exist.
#   (d) RUST-UNIT — `encode_decode_partial_failures` round-trips the
#       body shape in ndn-config.
#   (e) RUST-INTEG — `faces_create_idempotent_*` in ndn-mgmt exercise
#       the re-attach + partial_failures paths against a UDP face.
#
# Reverify recipe:
#   GREP-PROOF: this script (a-c).
#   RUST-UNIT:  `cargo test -p ndn-config encode_decode_partial_failures`.
#   RUST-INTEG: `cargo test -p ndn-mgmt --test faces_create_idempotent`.
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

MGMT=crates/ndn-mgmt/src/modules/faces.rs
CP=crates/ndn-config/src/control_parameters.rs

# (a) Idempotent-path helpers.
check_grep 'fn existing_face_id_for_uri' "$MGMT" 'existing_face_id_for_uri helper'
check_grep 'fn faces_create_idempotent'  "$MGMT" 'faces_create_idempotent helper'

# (b) ControlParameters carries partial_failures.
check_grep 'partial_failures: Vec<\(String, String\)>' \
    "$CP" 'ControlParameters.partial_failures field'

# (c) New TLV constants live in ndn-config::control_parameters::tlv.
for c in PARTIAL_FAILURES PARTIAL_FAILURE OPTION_NAME REFUSAL_REASON; do
    check_grep "pub const ${c}: u64 = 0x" "$CP" "tlv::${c} constant"
done

# (d) Round-trip codec test.
if ! cargo test -p ndn-config encode_decode_partial_failures >/dev/null 2>&1; then
    echo "FAIL: RUST-UNIT encode_decode_partial_failures in ndn-config" >&2
    fail=1
fi

# (e) End-to-end integration tests.
if ! cargo test -p ndn-mgmt --test faces_create_idempotent >/dev/null 2>&1; then
    echo "FAIL: RUST-INTEG faces_create_idempotent in ndn-mgmt" >&2
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "PASS: face-system Tier 5 §H — idempotent faces/create + partial_failures body."
fi
exit "$fail"
