#!/usr/bin/env bash
# Witness — reflexive forwarding §2a: reflexive-route table hardening invariants.
#
# Finding:   docs/notes/reflexive-forwarding-engine-2026-05-21.md §5 (W-RF-1..7)
# Witnesses: RUST-UNIT in ndn-engine (reflexive::tests):
#              - W-RF-1 backward-only: collision_from_different_face_refused,
#                install_then_lookup_lpm
#              - W-RF-3 bounded lifetime: expired_route_not_returned_and_swept,
#                lifetime_capped_by_config
#              - W-RF-4 per-face cap: per_face_cap_refuses_excess, remove_frees_cap_slot
#              - W-RF-6 monotonic id / teardown: remove_face_drops_all_its_routes
#              - hot-path guard: is_empty_tracks_live_routes
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

if cargo test -p ndn-engine --lib --quiet reflexive::tests \
        >/tmp/rf_table_witness.log 2>&1; then
    echo "=== RF §2a PASS — reflexive-route table invariants (W-RF-1/3/4/6) ==="
    exit 0
fi
echo "=== RF §2a FAIL ==="
cat /tmp/rf_table_witness.log
exit 1
