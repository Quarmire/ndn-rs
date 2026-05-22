#!/usr/bin/env bash
# Witness — reflexive forwarding §2b + §3: engine install-on-ingress, reverse
# routing, and scope/privilege confinement (W-RF-5, W-RF-7).
#
# Finding:   docs/notes/reflexive-forwarding-engine-2026-05-21.md §2b, §3
# Witnesses: RUST-UNIT in ndn-engine (builder::tests):
#              - reflexive_route_installed_on_ingress (§2b: install on ingress)
#              - reflexive_reverse_routing_forwards_to_install_face (§3: a reverse
#                Interest is forwarded only along the reverse route)
#              - reflexive_no_route_is_not_reverse_routed (W-RF-5: scope
#                confinement — unrouted reflexive name is not reverse-routed)
#              - reflexive_route_does_not_widen_reachability (W-RF-7: a route does
#                not make its face reachable for other names)
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

if cargo test -p ndn-engine --lib --quiet -- \
        reflexive_route_installed_on_ingress \
        reflexive_reverse_routing_forwards_to_install_face \
        reflexive_no_route_is_not_reverse_routed \
        reflexive_route_does_not_widen_reachability \
        >/tmp/rf_routing_witness.log 2>&1; then
    echo "=== RF §2b/§3 PASS — install, reverse routing, W-RF-5/W-RF-7 ==="
    exit 0
fi
echo "=== RF §2b/§3 FAIL ==="
cat /tmp/rf_routing_witness.log
exit 1
