#!/usr/bin/env bash
# Witness test for Phase-3 observability — substrate publisher.
#
# Phase:       observability/phase3-otel-and-trace-id.md §A / §D.1
# Severity:    HEADLINE (Phase-3 substrate witness)
# Spec ref:    OTLP/proto v1 Span — `opentelemetry-proto` v1.3.2
# Witnesses:   spans published to /localhost/nfd/observability decode as
#              valid OTLP Span protobuf when fetched via Interest.
#
# Expected today: FAIL (exit 1) — the engine pipeline does not yet open
# spans against the NdnObservabilityLayer at runtime; spans only appear
# when something explicitly calls `tracing::info_span!()` inside the
# engine while the publisher is mounted.  Once the engine wires its
# `#[instrument]` stages to actually emit during forwarding under the
# publisher, this exits 0.
#
# Exit codes:
#   0 — PASS (spans served, OTLP-decodable)
#   1 — FAIL (no spans, or content fails OTLP decode)
#   2 — SKIP (test dependencies missing)
set -euo pipefail

NDN_FWD_SOCK="${NDN_FWD_SOCK:-/run/ndn-fwd/ndn-fwd.sock}"
OBS_PREFIX="${OBS_PREFIX:-/localhost/nfd/observability}"

for tool in ndnpeek ndn-fwd; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "SKIP: required tool '$tool' not in container" >&2
        exit 2
    fi
done

# Drive a few Interests through the engine to elicit spans.
for n in /audit/obs/probe/0 /audit/obs/probe/1 /audit/obs/probe/2; do
    ndnpeek --timeout 200 "$n" >/dev/null 2>&1 || true
done

# Fetch the most recent span name from a known canary trace.
# (Phase-3 follow-on: a status verb under
# `/localhost/nfd/observability/traces/recent` will enumerate recent
# trace-ids; for now, the engine pipeline isn't yet wired to publish
# during forwarding so this Interest times out and the script fails.)
SPAN_NAME="${OBS_PREFIX}/traces/00000000000000000000000000000000/spans/0000000000000000"
if ! ndnpeek --payload --timeout 500 "$SPAN_NAME" > /tmp/obs_span.bin 2>/dev/null; then
    echo "FAIL: no span served at $SPAN_NAME" >&2
    exit 1
fi

# Validate OTLP Span protobuf header — first byte should be 0x0a
# (field=1 wire=2 → trace_id), followed by length 16.
HDR=$(head -c 2 /tmp/obs_span.bin | xxd -p)
if [ "$HDR" != "0a10" ]; then
    echo "FAIL: span Content does not start with OTLP trace_id field (got $HDR)" >&2
    exit 1
fi

echo "PASS: span published and OTLP-decodable"
exit 0
