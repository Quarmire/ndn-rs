#!/usr/bin/env bash
# Witness — Phase 4 §4.6 writing standards: no marketing words and
# no comparative cross-impl framing in user-facing wiki pages.
#
# Finding:   Phase 4 wiki docs must not use marketing language and
#            must not name external NDN libraries as foils.
# Witness:   GREP-PROOF — grep -nEi against the marketing word list
#            and against the external-impl name list. Either match
#            fails the witness.
#
# Allowed elsewhere:
#   * docs/notes/ may name the external impls (audit/cross-ref).
#   * Code-cross-reference file paths under .claude/ archive are not
#     in docs/wiki/src/, so they don't reach this scan.
#
# Exit codes:
#   0 — PASS (no matches)
#   1 — FAIL (matches found)
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

WIKI=docs/wiki/src

marketing='comprehensive|robust|powerful|world-class|best-in-class|state-of-the-art|next-generation|cutting-edge'
impls='NDN_Service_Framework|ndn-cxx|ndnd|NFD|ndn-svs'

fail=0

m=$(grep -rEin "($marketing)" "$WIKI" || true)
if [ -n "$m" ]; then
    echo "FAIL: marketing words found in wiki:" >&2
    echo "$m" >&2
    fail=1
fi

i=$(grep -rEn "($impls)" "$WIKI" || true)
if [ -n "$i" ]; then
    echo "FAIL: external NDN impl names found in wiki:" >&2
    echo "$i" >&2
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "PASS"
fi
exit "$fail"
