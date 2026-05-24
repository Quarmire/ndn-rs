#!/usr/bin/env bash
# Witness — NC.24: A-LAL wire layer + presence piggyback feature.
#
# CCLF's Ad-hoc Link Adaptation Layer carries three NON-CRITICAL experimental
# NDNLP TLVs (presence 0x0360, prev-hop-loc 0x0362, data-loc 0x0364): peers
# without A-LAL ignore them. Presence (the forwarding node's Name wire) is the
# network-layer neighbor identity for density — no MAC/host dependence. The
# AlalFeature splices presence onto egress and hands extracted presence to a
# sink on ingress; disabled by default (inert).
#
# Witnesses (RUST-UNIT):
#   ndn-packet (--features std):
#     - lp::al_lal::tests::presence_splice_extract_roundtrip
#     - lp::al_lal::tests::location_headers_coexist_in_order
#     - lp::al_lal::tests::geofix_value_roundtrip
#   ndn-transport:
#     - link_service::features::al_lal::tests::per_face_presence_splices_on_egress
#     - link_service::features::al_lal::tests::per_face_sink_gets_face_and_name_on_ingress
#     - link_service::features::al_lal::tests::inert_until_presence_set
#     - link_service::features::al_lal::tests::idle_beacon_due_after_interval_not_before
#     - link_service::features::al_lal::tests::egress_activity_resets_idle_beacon
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

if ! command -v cargo >/dev/null 2>&1; then
    echo "SKIP: cargo missing" >&2
    exit 2
fi

ok=1
if cargo test -p ndn-packet --features std --quiet -- \
        presence_splice_extract_roundtrip \
        location_headers_coexist_in_order \
        geofix_value_roundtrip \
        >/tmp/nc24_packet.log 2>&1 && grep -qE "result: ok\. [1-9]" /tmp/nc24_packet.log; then
    :
else
    ok=0
fi

if cargo test -p ndn-transport --quiet -- \
        per_face_presence_splices_on_egress \
        per_face_sink_gets_face_and_name_on_ingress \
        inert_until_presence_set \
        idle_beacon_due_after_interval_not_before \
        egress_activity_resets_idle_beacon \
        >/tmp/nc24_transport.log 2>&1 && grep -qE "result: ok\. [1-9]" /tmp/nc24_transport.log; then
    :
else
    ok=0
fi

if [ "$ok" -eq 1 ]; then
    echo "=== NC.24 PASS — A-LAL TLVs round-trip; presence piggyback works; non-critical ==="
    grep -E "test result" /tmp/nc24_packet.log /tmp/nc24_transport.log | tail -n 2
    exit 0
else
    echo "=== NC.24 FAIL — A-LAL wire/feature witness failed ==="
    cat /tmp/nc24_packet.log /tmp/nc24_transport.log
    exit 1
fi
