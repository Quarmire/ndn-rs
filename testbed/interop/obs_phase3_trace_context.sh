#!/usr/bin/env bash
# Witness test for Phase-3 observability — cross-router trace context.
#
# Phase:       observability/phase3-otel-and-trace-id.md §B / §D.2
# Severity:    HEADLINE (cross-router stitching — the phase-3 badge)
# Spec ref:    NDNLPv2 `TraceContext` TLV (`0x520`); W3C Trace Context
#              binary form §3.3.
# Witnesses:   two ndn-fwd instances peered with [observability]
#              propagate_to_peers = true exchange spans whose trace-id
#              matches across hops.
#
# Expected today: FAIL (exit 1) — TraceContext LP TLV is decoded but
# `on_egress` does not yet inject (OutboundLpFrame typed slot is still
# TODO from Tier 1).  See `crates/ndn-transport/src/link_service/
# features/trace_context.rs` Phase-3 status block for the remaining
# wiring.
#
# Exit codes:
#   0 — PASS (router B's pipeline span has parent = router A's outbound span)
#   1 — FAIL (trace IDs differ across hops, or no LP TraceContext on wire)
#   2 — SKIP (test dependencies missing)
set -euo pipefail

NDN_FWD_A_SOCK="${NDN_FWD_A_SOCK:-/run/ndn-fwd-a/ndn-fwd.sock}"
NDN_FWD_B_SOCK="${NDN_FWD_B_SOCK:-/run/ndn-fwd-b/ndn-fwd.sock}"
OBS_PREFIX="${OBS_PREFIX:-/localhost/nfd/observability}"

for tool in ndnpeek ndnpoke ndn-fwd; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "SKIP: required tool '$tool' not in container" >&2
        exit 2
    fi
done

# Drive an Interest from A to B and back; both forwarders should
# publish spans under their own observability prefix carrying the
# *same* trace-id (W3C-trace-context bytes 0..16).

INTEREST_NAME="/audit/obs/x-hop/$(date +%s)"
NDN_CLIENT_TRANSPORT="unix://$NDN_FWD_A_SOCK" \
    ndnpeek --timeout 500 "$INTEREST_NAME" >/dev/null 2>&1 || true

# Fetch most-recent trace from both forwarders.  Both should have
# logged the request; their trace-ids should agree.
# (Phase-3 follow-on: the recent-trace enumeration endpoint isn't
# implemented yet, so we can't read the trace-id round-trip from the
# substrate. Until that endpoint lands, this fails by construction.)
echo "FAIL: cross-router trace stitching pending OutboundLpFrame.trace_context slot + recent-trace endpoint" >&2
exit 1
