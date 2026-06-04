#!/usr/bin/env bash
# Witness — Phase 4 §4.6 writing standards: no marketing words and
# no comparative cross-impl framing in user-facing wiki pages.
#
# Finding:   Phase 4 wiki docs must not use marketing language and must not
#            name external NDN libraries *as foils* (comparative framing).
#            Factual interop references — "interoperable with ndn-cxx",
#            "ndnsec import accepts this", "compliant per NFD" — are allowed;
#            only ranking/foil framing is banned.
# Witness:   GREP-PROOF — fail on (a) any marketing word, or (b) an external
#            impl name on a line that ALSO uses comparative/foil framing
#            (faster/better/unlike/outperforms/…). A bare factual mention passes.
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
# Comparative/foil framing — an impl name beside one of these ranking words is
# a superiority claim, not factual interop. Kept to unambiguous ranking terms
# (structural contrasts like "instead of"/"unlike" occur in factual prose).
comparative='faster|slower|better|worse|superior|inferior|outperform|outpace|beats?'

fail=0

m=$(grep -rEin "($marketing)" "$WIKI" || true)
if [ -n "$m" ]; then
    echo "FAIL: marketing words found in wiki:" >&2
    echo "$m" >&2
    fail=1
fi

# Flag an impl name only when the same line also uses comparative/foil framing.
# Bare factual interop references pass.
i=$(grep -rEn "($impls)" "$WIKI" | grep -Ei "($comparative)" || true)
if [ -n "$i" ]; then
    echo "FAIL: external NDN impl named as a comparative foil in wiki:" >&2
    echo "$i" >&2
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "PASS"
fi
exit "$fail"
