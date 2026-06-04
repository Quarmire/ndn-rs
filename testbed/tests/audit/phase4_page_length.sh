#!/usr/bin/env bash
# Witness — Phase 4 §4.6 page-length budgets.
#
# Caps (line count, including blank lines and code blocks):
#   start/       : 130   (kernel pages — narrative + one diagram)
#   path/        : 90    (thin persona ramps)
#   choosing/    : 120   (decision guides — table + how-to-decide)
#   quickstart/  : 100
#   concepts/    : 200
#   api/         : 250
#   guides/      : 200
#   operations/  : 150
#   reference/   : 200   (catalog pages — transport/profile/policy tables)
#   releases/    : 200
#   README.md    : 60
#   SUMMARY.md   : 80    (grew with the Start here + Your path sections)
#
# Exit codes:
#   0 — PASS
#   1 — FAIL
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

cap_for() {
    case "$1" in
        docs/wiki/src/README.md)     echo 60 ;;
        docs/wiki/src/SUMMARY.md)    echo 80 ;;
        docs/wiki/src/start/*)       echo 130 ;;
        docs/wiki/src/path/*)        echo 90 ;;
        docs/wiki/src/choosing/*)    echo 120 ;;
        docs/wiki/src/quickstart/*)  echo 100 ;;
        docs/wiki/src/concepts/*)    echo 200 ;;
        docs/wiki/src/api/*)         echo 250 ;;
        docs/wiki/src/guides/*)      echo 200 ;;
        docs/wiki/src/operations/*)  echo 150 ;;
        docs/wiki/src/reference/*)   echo 200 ;;
        docs/wiki/src/releases/*)    echo 200 ;;
        *)                           echo 9999 ;;
    esac
}

fail=0
while IFS= read -r f; do
    cap=$(cap_for "$f")
    n=$(wc -l <"$f" | tr -d ' ')
    if [ "$n" -gt "$cap" ]; then
        echo "FAIL: $f has $n lines (cap $cap)" >&2
        fail=1
    fi
done < <(find docs/wiki/src -type f -name '*.md' | sort)

if [ "$fail" -eq 0 ]; then
    echo "PASS"
fi
exit "$fail"
