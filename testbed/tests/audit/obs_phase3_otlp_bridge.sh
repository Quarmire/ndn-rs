#!/usr/bin/env bash
# Witness test for Phase-3 observability — OTLP/HTTP-protobuf bridge.
#
# Phase:       observability/phase3-otel-and-trace-id.md §C / §D.3
# Severity:    HEADLINE (ecosystem-interop validation)
# Spec ref:    OTLP/HTTP v1.0
#              (https://opentelemetry.io/docs/specs/otlp/#otlphttp).
# Witnesses:   ndn-otel-bridge consumes spans from the NDN substrate,
#              decodes OTLP Span protobuf, batches into ResourceSpans,
#              POSTs to a configured OTLP/HTTP endpoint (Jaeger /
#              Tempo / Honeycomb / Datadog / collector).
#
# Expected today: FAIL (exit 1) UNTIL the test harness starts a Jaeger
# all-in-one container and drives Interests through ndn-fwd long enough
# for the bridge to flush.  The bridge binary itself ships and its
# unit tests pass; this script is the end-to-end black-box check.
#
# Exit codes:
#   0 — PASS (Jaeger query API returns a trace under service=ndn-rs)
#   1 — FAIL (bridge unreachable, or trace missing from Jaeger)
#   2 — SKIP (test dependencies missing)
set -euo pipefail

for tool in ndnpeek ndn-fwd ndn-otel-bridge curl jq; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "SKIP: required tool '$tool' not in container" >&2
        exit 2
    fi
done

JAEGER_QUERY_URL="${JAEGER_QUERY_URL:-http://localhost:16686/api/traces}"
NDN_PREFIX="${NDN_PREFIX:-/localhost/nfd/observability}"

# Drive ndn-fwd: emit a few spans.
for n in /audit/obs/bridge/0 /audit/obs/bridge/1 /audit/obs/bridge/2; do
    ndnpeek --timeout 200 "$n" >/dev/null 2>&1 || true
done

# Give the bridge a moment to poll /recent + flush.
sleep 6

# Query Jaeger for our service.  If the bridge flushed at least one
# batch and Jaeger received it, this returns >=1 trace.
RESP=$(curl -s "$JAEGER_QUERY_URL?service=ndn-rs&limit=1" 2>/dev/null || echo '{"data":[]}')
COUNT=$(echo "$RESP" | jq '.data | length' 2>/dev/null || echo 0)

if [ "$COUNT" -ge 1 ]; then
    echo "PASS: Jaeger received $COUNT trace(s) via ndn-otel-bridge"
    exit 0
fi

echo "FAIL: no traces visible in Jaeger; check bridge is running and pointing at $JAEGER_QUERY_URL" >&2
exit 1
