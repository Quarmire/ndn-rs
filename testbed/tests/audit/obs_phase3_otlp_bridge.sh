#!/usr/bin/env bash
# Witness test for Phase-3 observability — OTLP/gRPC bridge.
#
# Phase:       observability/phase3-otel-and-trace-id.md §C / §D.3
# Severity:    HEADLINE (ecosystem-interop validation)
# Spec ref:    OTLP/gRPC v1.0; Jaeger 1.x receive-OTLP support.
# Witnesses:   ndn-otel-bridge consumes spans from the NDN substrate,
#              translates to OTLP/gRPC, pushes to a Jaeger all-in-one
#              container; the trace appears in the Jaeger query API.
#
# Expected today: FAIL (exit 1) — `ndn-otel-bridge` binary is deferred
# to a follow-on prompt; the publisher and protobuf encoding ship
# today, but the bridge harness assembling ResourceSpans + tonic gRPC
# is not yet implemented.  See
# `binaries/tooling/ndn-otel-bridge/README.md` (TBD).
#
# Exit codes:
#   0 — PASS (Jaeger query API returns the trace)
#   1 — FAIL (bridge not deployed, or trace missing from Jaeger)
#   2 — SKIP (test dependencies missing)
set -euo pipefail

for tool in ndnpeek ndn-fwd ndn-otel-bridge curl jq; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "SKIP: required tool '$tool' not in container" >&2
        exit 2
    fi
done

JAEGER_QUERY_URL="${JAEGER_QUERY_URL:-http://localhost:16686/api/traces}"

# Once the bridge binary lands, this script will:
#  1. Drive Interests through ndn-fwd (publisher mounted).
#  2. Wait briefly for the bridge to consume + push.
#  3. Query Jaeger's `/api/traces?service=ndn-rs` and assert >=1 trace.
echo "FAIL: ndn-otel-bridge binary deferred from this prompt — see observability/phase3-otel-and-trace-id.md §C status" >&2
exit 1
