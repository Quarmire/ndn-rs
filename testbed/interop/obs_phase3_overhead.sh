#!/usr/bin/env bash
# Witness test for Phase-3 observability — substrate-publish overhead.
#
# Phase:       observability/phase3-otel-and-trace-id.md §D.4
# Severity:    MAJOR (gates the "publish to substrate is cheap" claim)
# Witnesses:   per-Interest p99 with [observability] publish_to_ndn =
#              true, sample = 0.01 is within 5% of publish_to_ndn = false.
#
# Expected today: FAIL (exit 1) — the bench harness comparing two
# configs back-to-back is shared with the face-system overhead bench
# scaffold (commit bc10ec5) but not yet specialised for observability;
# until the bench wrapper exists this script reports FAIL with a
# pointer.
#
# Exit codes:
#   0 — PASS (overhead < 5%)
#   1 — FAIL (overhead too high, or bench not run)
#   2 — SKIP (bench tool missing)
set -euo pipefail

for tool in ndn-bench; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "SKIP: ndn-bench not in container" >&2
        exit 2
    fi
done

echo "FAIL: overhead bench harness pending — extend binaries/tooling/ndn-bench with --observability flag" >&2
exit 1
