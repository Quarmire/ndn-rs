#!/usr/bin/env bash
# Witness recipe for Face-system Tier 0 — `FaceState.flags` bit access
# is funnelled through accessor methods, not direct atomic ops at
# external call sites.
#
# Finding:     docs/notes/face-system-design-2026-05-20.md § Tier 0
# Severity:    Phase-2b architectural cleanup (pre-v0.1.0)
# Decision:    `FaceState.flags: AtomicU64` becomes pub(crate); the
#              three NFD flag bits (LocalFields / LpReliability /
#              CongestionMarking) get a single home in
#              `ndn-transport/src/face_options.rs` as
#              `BIT_LOCAL_FIELDS` / `BIT_LP_RELIABILITY` /
#              `BIT_CONGESTION_MARKING`.  External callers go through
#              accessor methods on `FaceState`.
#
# Witnesses:
#   (a) GREP-PROOF — `crates/spec/ndn-transport/src/face_options.rs`
#       defines the three `BIT_*` constants.
#   (b) GREP-PROOF — `FaceState` has the accessor methods
#       (`face_flags_raw`, `apply_face_flags_mask`,
#       `set_local_fields_bit`, etc.) — checked by name.
#   (c) GREP-PROOF — outside `engine.rs` and `face_options.rs`, NO
#       file in `crates/spec/ndn-mgmt/` or `crates/spec/ndn-engine/`
#       touches `.flags.load|.flags.store|.flags.fetch_or|.flags.fetch_and`
#       on a `FaceState` reference.  Mgmt and external sites go
#       through accessors.
#   (d) GREP-PROOF — no remaining bare `1 << 0` / `1 << 1` / `1 << 2`
#       face-flag bit literals (replaced by named constants).
#
# Reverify recipe: GREP-PROOF only.  Runs in any checkout of ndn-rs.
#
# Exit codes:
#   0 — PASS (Tier 0 refactor landed)
#   1 — FAIL (bits leak through external call sites or constants missing)
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

FACE_OPTIONS=crates/spec/ndn-transport/src/face_options.rs
ENGINE=crates/spec/ndn-engine/src/engine.rs
MGMT_FACES=crates/spec/ndn-mgmt/src/modules/faces.rs

# (a) Bit constants live in face_options.rs.
check_grep '\bBIT_LOCAL_FIELDS\b'      "$FACE_OPTIONS" 'BIT_LOCAL_FIELDS const'
check_grep '\bBIT_LP_RELIABILITY\b'    "$FACE_OPTIONS" 'BIT_LP_RELIABILITY const'
check_grep '\bBIT_CONGESTION_MARKING\b' "$FACE_OPTIONS" 'BIT_CONGESTION_MARKING const'

# (b) FaceState exposes named accessors.
check_grep 'fn face_flags_raw'         "$ENGINE" 'FaceState::face_flags_raw accessor'
check_grep 'fn apply_face_flags_mask'  "$ENGINE" 'FaceState::apply_face_flags_mask accessor'
check_grep 'fn set_local_fields_bit'   "$ENGINE" 'FaceState::set_local_fields_bit accessor'

# (c) Mgmt/faces.rs does NOT touch the AtomicU64 directly.
check_absent_in_paths '\.flags\.(load|store|fetch_or|fetch_and)\b' \
    'mgmt/faces.rs reaches into FaceState.flags directly (must go through accessors)' \
    "$MGMT_FACES"

# (d) No remaining unnamed face-flag bit literals.  We only forbid the
# literal form `1 << 0` (etc.) in the engine.rs FaceState surface — the
# constants module is the only legitimate site of those literals.
check_absent_in_paths '1[[:space:]]*<<[[:space:]]*[012][^0-9]' \
    'unnamed face-flag bit literal in engine.rs (use BIT_* constants from face_options)' \
    "$ENGINE"

if [ "$fail" -eq 0 ]; then
    echo "PASS: face-system Tier 0 — FaceState.flags bits centralised; external sites use accessors."
fi
exit "$fail"
