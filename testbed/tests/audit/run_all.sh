#!/usr/bin/env bash
# Run every audit witness named by testbed/EXPECTED_FAILURES.md and print a
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
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
TRACKER="${REPO_ROOT}/testbed/EXPECTED_FAILURES.md"
RESULTS_DIR="${RESULTS_DIR:-/results}"
TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")
REPORT="${RESULTS_DIR}/audit-${TIMESTAMP}.txt"
LOG_DIR="${RESULTS_DIR}/audit-${TIMESTAMP}-logs"

mkdir -p "${RESULTS_DIR}"
mkdir -p "${LOG_DIR}"

# Per-script expected outcomes, derived from EXPECTED_FAILURES.md:
# RESOLVED -> PASS, EXPECTED-FAIL -> FAIL, BLOCKED-BY-INTEROP -> SKIP.
declare -A EXPECTED=()
declare -A FINDING=()
scripts=()

while IFS='|' read -r _ finding witness status _rest; do
    finding="$(printf "%s" "${finding}" | xargs)"
    status="$(printf "%s" "${status}" | xargs)"
    [[ -z "${finding}" || "${finding}" == "Finding" ]] && continue
    [[ "${finding}" == --* ]] && continue

    case "${status}" in
        RESOLVED*) expected="PASS" ;;
        EXPECTED-FAIL*) expected="FAIL" ;;
        BLOCKED-BY-INTEROP*) expected="SKIP" ;;
        *) continue ;;
    esac

    remaining="${witness}"
    while [[ "${remaining}" == *'`'*'.sh`'* ]]; do
        script_name="${remaining#*\`}"
        script_name="${script_name%%\`*}"
        remaining="${remaining#*\`}"
        remaining="${remaining#*\`}"

        [[ "${script_name}" == *.sh ]] || continue
        if [[ -z "${EXPECTED[${script_name}]+x}" ]]; then
            scripts+=("${script_name}")
        fi
        EXPECTED["${script_name}"]="${expected}"
        FINDING["${script_name}"]="${finding}"
    done
done < "${TRACKER}"

DIVERGED=0
PREDICTED_PASS=0
PREDICTED_FAIL=0
PREDICTED_SKIP=0

echo "# Audit Witness Run — ${TIMESTAMP}" | tee "${REPORT}"
echo "" | tee -a "${REPORT}"
echo "Finding | Script | Expected | Actual | Verdict" | tee -a "${REPORT}"
echo "--------|--------|----------|--------|--------" | tee -a "${REPORT}"

for script_name in "${scripts[@]}"; do
    script="${SCRIPT_DIR}/${script_name}"
    finding_id="${FINDING[${script_name}]}"
    expected="${EXPECTED[${script_name}]:-UNKNOWN}"

    log_file="${LOG_DIR}/${script_name%.sh}.log"

    if [[ ! -f "${script}" ]]; then
        actual="MISSING"
    else
        set +e
        bash "${script}" >"${log_file}" 2>&1
        rc=$?
        set -e

        case "${rc}" in
            0) actual="PASS" ;;
            1) actual="FAIL" ;;
            2) actual="SKIP" ;;
            *) actual="ERROR(${rc})" ;;
        esac
    fi

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
        "PASS-MISSING"|"FAIL-MISSING"|"SKIP-MISSING")
            verdict="MISSING — tracker names a script that is absent or not executable"
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

    printf "%s | %s | %s | %s | %s\n" \
        "${finding_id}" "${script_name}" "${expected}" "${actual}" "${verdict}" \
        | tee -a "${REPORT}"
done

echo "" | tee -a "${REPORT}"
echo "Predicted: ${PREDICTED_PASS} PASS / ${PREDICTED_FAIL} FAIL / ${PREDICTED_SKIP} SKIP" \
    | tee -a "${REPORT}"
echo "Divergences from expected: ${DIVERGED}" | tee -a "${REPORT}"
echo "Report: ${REPORT}"
echo "Logs: ${LOG_DIR}"

if [ "${DIVERGED}" -eq 0 ]; then
    exit 0
elif [ "${DIVERGED}" -gt 0 ]; then
    exit 1
fi
