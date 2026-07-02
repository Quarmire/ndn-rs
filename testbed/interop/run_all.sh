#!/usr/bin/env bash
# Opt-in interop/e2e suite runner.
#
# These scripts exercise ndn-rs against real external peers (Dockerized NFD,
# ndnd, NDNCERT CA, C++ PSync/NLSR) or spawn forwarder/tool binaries that live
# in the sibling ndn-fwd repo. They are NOT part of the PR gate — run them
# manually or from a scheduled workflow on a host with Docker and a full
# ndn-workspace checkout (../../../ndn-fwd etc.).
#
# Per-script exit codes: 0 PASS / 1 FAIL / 2 SKIP (missing prerequisite).
#
# Usage:
#   ./run_all.sh              # run everything
#   ./run_all.sh quic mgmt    # run scripts whose name matches any filter

set -uo pipefail
cd "$(dirname "$0")"

filters=("$@")
pass=0 fail=0 skip=0 total=0
failed=()

for script in *.sh; do
    [[ "$script" == "run_all.sh" ]] && continue
    if ((${#filters[@]})); then
        keep=0
        for f in "${filters[@]}"; do [[ "$script" == *"$f"* ]] && keep=1; done
        ((keep)) || continue
    fi
    total=$((total + 1))
    printf '── %-50s ' "$script"
    if out=$(bash "$script" 2>&1); rc=$?; then rc=0; fi
    case $rc in
        0) echo "PASS"; pass=$((pass + 1)) ;;
        2) echo "SKIP"; skip=$((skip + 1)) ;;
        *) echo "FAIL (rc=$rc)"; fail=$((fail + 1)); failed+=("$script")
           printf '%s\n' "$out" | tail -20 | sed 's/^/    /' ;;
    esac
done

echo
echo "interop: $pass pass, $fail fail, $skip skip ($total run)"
((fail == 0))
