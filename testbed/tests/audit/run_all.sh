#!/usr/bin/env bash
# Run every audit witness test in this directory and print a
# summary tagged with expected vs actual outcomes.
#
# Exit codes:
#   0 — all tests behaved as predicted by EXPECTED_FAILURES.md
#       (pass when expected PASS, fail when expected FAIL)
#   1 — one or more tests diverged from their expected outcome
#   2 — some tests could not run (SKIP); no divergences among those
#       that did run.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="${RESULTS_DIR:-/results}"
TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")
REPORT="${RESULTS_DIR}/audit-${TIMESTAMP}.txt"

mkdir -p "${RESULTS_DIR}"

# Per-test expected outcomes, read from the EXPECTED_FAILURES.md table.
# Keyed by finding id (lowercase, no dot — e.g. "a01").
declare -A EXPECTED=(
  ["a01"]="FAIL"   ["a02"]="FAIL"   ["a03"]="FAIL"   ["a09"]="FAIL"
  ["a10"]="FAIL"   ["a15"]="FAIL"   ["a17"]="FAIL"
  ["b01"]="FAIL"
  ["c01"]="FAIL"   ["c02"]="FAIL"   ["c03"]="FAIL"
  ["c07"]="FAIL"   ["c08"]="FAIL"   ["c11"]="FAIL"   ["c13"]="SKIP"
  ["d01"]="FAIL"   ["d02"]="FAIL"   ["d03"]="FAIL"   ["d04"]="FAIL"
  ["d07"]="FAIL"   ["d09"]="FAIL"   ["d13"]="FAIL"
  ["e01"]="FAIL"   ["e04"]="FAIL"   ["e05"]="SKIP"
  ["f01"]="FAIL"   ["f03"]="FAIL"
  ["g03"]="FAIL"
)

DIVERGED=0
PREDICTED_PASS=0
PREDICTED_FAIL=0
PREDICTED_SKIP=0

echo "# Audit Witness Run — ${TIMESTAMP}" | tee "${REPORT}"
echo "" | tee -a "${REPORT}"
echo "Finding | Expected | Actual | Verdict" | tee -a "${REPORT}"
echo "--------|----------|--------|--------" | tee -a "${REPORT}"

for script in "${SCRIPT_DIR}"/*.sh; do
    name="$(basename "${script}" .sh)"
    [[ "${name}" == "run_all" || "${name}" == "_template" ]] && continue

    # finding id is the leading a01 / b03 / cXX / etc. prefix.
    finding_id="${name%%_*}"
    expected="${EXPECTED[${finding_id}]:-UNKNOWN}"

    bash "${script}" >/tmp/audit-out 2>&1
    rc=$?

    case "${rc}" in
        0) actual="PASS" ;;
        1) actual="FAIL" ;;
        2) actual="SKIP" ;;
        *) actual="ERROR(${rc})" ;;
    esac

    verdict="— "
    case "${expected}-${actual}" in
        "PASS-PASS"|"FAIL-FAIL"|"SKIP-SKIP")
            verdict="as expected"
            ;;
        "FAIL-PASS")
            verdict="IMPROVED — finding may be resolved; update EXPECTED_FAILURES"
            DIVERGED=$((DIVERGED + 1))
            ;;
        "PASS-FAIL")
            verdict="REGRESSION — a previously-passing test now fails"
            DIVERGED=$((DIVERGED + 1))
            ;;
        "FAIL-SKIP"|"PASS-SKIP"|"SKIP-FAIL"|"SKIP-PASS")
            verdict="DIVERGED — investigate"
            DIVERGED=$((DIVERGED + 1))
            ;;
        *)
            verdict="UNKNOWN expectation"
            DIVERGED=$((DIVERGED + 1))
            ;;
    esac

    case "${expected}" in
        PASS) PREDICTED_PASS=$((PREDICTED_PASS + 1)) ;;
        FAIL) PREDICTED_FAIL=$((PREDICTED_FAIL + 1)) ;;
        SKIP) PREDICTED_SKIP=$((PREDICTED_SKIP + 1)) ;;
    esac

    printf "%s | %s | %s | %s\n" \
        "${finding_id}" "${expected}" "${actual}" "${verdict}" \
        | tee -a "${REPORT}"
done

echo "" | tee -a "${REPORT}"
echo "Predicted: ${PREDICTED_PASS} PASS / ${PREDICTED_FAIL} FAIL / ${PREDICTED_SKIP} SKIP" \
    | tee -a "${REPORT}"
echo "Divergences from expected: ${DIVERGED}" | tee -a "${REPORT}"
echo "Report: ${REPORT}"

if [ "${DIVERGED}" -eq 0 ]; then
    exit 0
elif [ "${DIVERGED}" -gt 0 ]; then
    exit 1
fi
