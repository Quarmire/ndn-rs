#!/usr/bin/env bash
# Witness recipe for Face-system Tier 2 §A — typed `FaceOption` surface
# replaces ad-hoc `Flags + Mask` bit-twiddling at handler call sites.
#
# Finding:     docs/notes/face-system-design-2026-05-20.md §3
# Severity:    Phase-2b architectural cleanup (pre-v0.1.0)
# Decision:    Q1=(a) sub-module on ndn-transport.  A non-exhaustive
#              `FaceOption` enum names every per-face knob NFD's
#              faces/update accepts (Flags decomposed into the three
#              bool options; FacePersistency, EffectiveMtu,
#              BaseCongestionMarkingInterval, DefaultCongestionThreshold
#              first-class).  `FaceOptionError` distinguishes the three
#              outcomes operators care about:
#              NotSupportedByTransport (503), Immutable (409),
#              OutOfRange (400).  `LinkService` grows
#              `apply` + `snapshot` seams; default `apply` errors with
#              NotSupportedByTransport so existing impls compile
#              unchanged.
#
# Witnesses:
#   (a) GREP-PROOF — `enum FaceOption` exists with the seven variants
#       in `ndn-transport/src/face_options.rs`.
#   (b) GREP-PROOF — `enum FaceOptionError` with the three variants.
#   (c) GREP-PROOF — `LinkService` trait declares `fn apply` and
#       `fn snapshot` methods (object-safe seam).
#   (d) RUST-UNIT — `face_option_apply_default_errors` in
#       `ndn-transport` confirms a hand-rolled LinkService stub returns
#       NotSupportedByTransport from the default `apply()`.
#   (e) RUST-UNIT — `face_option_roundtrip` constructs each typed
#       variant and asserts the seven discriminants are reachable.
#
# Reverify recipe:
#   GREP-PROOF: this script (sections a-c).
#   RUST-UNIT: `cargo test -p ndn-transport face_option_roundtrip
#                                            face_option_apply_default_errors`.
#
# Exit codes:
#   0 — PASS (Tier 2 §A landed)
#   1 — FAIL (typed surface missing, LinkService seam absent, or unit
#       tests fail)
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

FACE_OPTIONS=crates/spec/ndn-transport/src/face_options.rs
LINK_SERVICE_DIR=crates/spec/ndn-transport/src/link_service

# (a) Typed enum with the seven variants.
check_grep 'pub enum FaceOption'                "$FACE_OPTIONS" 'FaceOption enum'
check_grep 'LocalFields\('                      "$FACE_OPTIONS" 'FaceOption::LocalFields'
check_grep 'LpReliability\('                    "$FACE_OPTIONS" 'FaceOption::LpReliability'
check_grep 'CongestionMarking\('                "$FACE_OPTIONS" 'FaceOption::CongestionMarking'
check_grep 'BaseCongestionMarkingInterval\('    "$FACE_OPTIONS" 'FaceOption::BaseCongestionMarkingInterval'
check_grep 'DefaultCongestionThreshold\('       "$FACE_OPTIONS" 'FaceOption::DefaultCongestionThreshold'
check_grep 'EffectiveMtu\('                     "$FACE_OPTIONS" 'FaceOption::EffectiveMtu'
check_grep 'Persistency\('                      "$FACE_OPTIONS" 'FaceOption::Persistency'

# (b) Error enum with the three operator-visible variants.
check_grep 'pub enum FaceOptionError'           "$FACE_OPTIONS" 'FaceOptionError enum'
check_grep 'NotSupportedByTransport'            "$FACE_OPTIONS" 'FaceOptionError::NotSupportedByTransport'
check_grep 'Immutable'                          "$FACE_OPTIONS" 'FaceOptionError::Immutable'
check_grep 'OutOfRange'                         "$FACE_OPTIONS" 'FaceOptionError::OutOfRange'

# (c) LinkService grows apply / snapshot.
check_grep 'fn apply\('                         "$LINK_SERVICE_DIR/mod.rs" 'LinkService::apply'
check_grep 'fn snapshot\('                      "$LINK_SERVICE_DIR/mod.rs" 'LinkService::snapshot'

# (d) RUST-UNIT — exercise the default-impl error path.
if ! cargo test -p ndn-transport --lib face_option_ >/dev/null 2>&1; then
    echo "FAIL: RUST-UNIT face_option_* tests in ndn-transport" >&2
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "PASS: face-system Tier 2 §A — typed FaceOption surface + LinkService apply/snapshot seam."
fi
exit "$fail"
