#!/usr/bin/env bash
# Witness recipe for Face-system Tier 5 §G — `ndn-ctl face list`
# accepts `--scheme` / `--remote` / `--local` filter flags and the
# post-decode filter respects AND semantics.
#
# Finding:     docs/notes/face-system-design-2026-05-20.md §8.3
# Severity:    Phase-2b architectural cleanup (pre-v0.1.0)
# Decision:    Filters run after the dataset decode — server-side
#              decode happens once, the CLI prunes by URI scheme or
#              by glob.  No protocol change.
#
# Witnesses:
#   (a) GREP-PROOF — the CLI declares `--scheme`, `--remote`,
#       `--local` flags on `FaceAction::List`.
#   (b) GREP-PROOF — `filter_face_list` and `glob_match` live in
#       `binaries/tooling/ndn-tools/src/ctl.rs`.
#   (c) RUST-UNIT — `ndnctl_filter_*` tests pin the matrix.
#
# Reverify recipe:
#   GREP-PROOF: this script (a-b).
#   RUST-UNIT: `cargo test -p ndn-tools --bin ndn-ctl ndnctl_filter_`.
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

CTL=binaries/tooling/ndn-tools/src/ctl.rs

# (a) Flag declarations.
for flag in scheme remote local; do
    check_grep "${flag}: Option<String>" "$CTL" "FaceAction::List ${flag} field"
done

# (b) Filter helpers live in the same file.
check_grep 'fn filter_face_list' "$CTL" 'filter_face_list helper'
check_grep 'fn glob_match'       "$CTL" 'glob_match helper'

# (c) Unit tests cover scheme / glob / combined / empty.
if ! cargo test -p ndn-tools --bin ndn-ctl ndnctl_filter_ >/dev/null 2>&1; then
    echo "FAIL: RUST-UNIT ndnctl_filter_* tests" >&2
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "PASS: face-system Tier 5 §G — ndn-ctl face list --scheme / --remote / --local filters land."
fi
exit "$fail"
