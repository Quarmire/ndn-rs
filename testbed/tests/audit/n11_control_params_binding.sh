#!/usr/bin/env bash
# Witness test for audit finding N.11 — `ControlParameters` location
# (Name vs AppParameters) was not bound to the signature; in particular
# the mgmt parser silently picked one location and ignored the other.
#
# Finding:     docs/notes/spec-compliance-cross-reference-2026-05-01.md § N.11
# Severity:    MAJOR (depends on E.01 + A.02)
# Spec ref:    NFD's command parsing accepts ControlParameters in either
#              the Name's 5th component or in `ApplicationParameters`,
#              but never both — peers must pick one location per
#              Interest. Combined with audit A.09's signed-region rule
#              (which covers Name + AppParameters) and A.02's
#              `ParametersSha256DigestComponent` enforcement, a signed
#              command's CP integrity is bound to the signature.
# Witnesses:   RUST-UNIT in `ndn-fwd::mgmt_ndn::tests`:
#                - n11_resolve_control_parameters_rejects_both_locations
#                - n11_resolve_control_parameters_accepts_name_only
#                - n11_resolve_control_parameters_accepts_app_params_only
#                - n11_resolve_control_parameters_no_cp_returns_none
#              The `resolve_control_parameters` helper is wired into the
#              mgmt dispatch loop; an Interest carrying CP in both
#              locations now returns `BAD_PARAMS` instead of silently
#              dispatching the Name-side value.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

fail=0
if cargo test -p ndn-fwd --bin ndn-fwd --quiet n11_ \
        >/tmp/n11_witness.log 2>&1; then
    echo "ok: ControlParameters resolver rejects ambiguous both-locations shape"
else
    echo "FAIL: mgmt accepts ambiguous CP-in-both-locations Interest"
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo
    echo "=== N.11 RESOLVED — ControlParameters location is unambiguous ==="
    exit 0
else
    echo
    echo "=== N.11 EXPECTED-FAIL — CP location ambiguous; mgmt picks silently ==="
    [ -f /tmp/n11_witness.log ] && cat /tmp/n11_witness.log
    exit 1
fi
