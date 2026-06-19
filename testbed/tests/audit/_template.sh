#!/usr/bin/env bash
# Witness test for audit finding <PHASE.NN> — <short title>.
#
# Finding:     see testbed/EXPECTED_FAILURES.md § <PHASE.NN>
# Severity:    BLOCKER | MAJOR | MINOR | DOCS
# Spec ref:    <URL and clause>
# Witnesses:   <one sentence: the specific wire event this script asserts>
#
# Expected today: FAIL (exit 1). After the finding is fixed, this script
# should exit 0 without any script body changes.
#
# Exit codes:
#   0 — PASS (ndn-rs behaviour matches spec)
#   1 — FAIL (ndn-rs behaviour violates spec — the expected state until fix)
#   2 — SKIP (test dependencies missing)
set -euo pipefail

# Environment knobs — set by the testbed scripts, with sensible defaults.
NDN_FWD_SOCK="${NDN_FWD_SOCK:-/run/ndn-fwd/ndn-fwd.sock}"
NFD_SOCK="${NFD_SOCK:-/run/nfd/nfd.sock}"
YANFD_SOCK="${YANFD_SOCK:-/run/yanfd/nfd.sock}"
PREFIX="${PREFIX:-/audit/<PHASE-NN>}"

# ── dependency checks — exit 2 with message if a tool is missing ──────────────
for tool in ndn-put ndnpeek; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "SKIP: required tool '$tool' not in container" >&2
        exit 2
    fi
done

# ── test body ─────────────────────────────────────────────────────────────────
# 1. Produce a packet that exhibits the spec-violating behaviour from ndn-rs.
# 2. Route it through the forwarder topology.
# 3. Observe the reference peer's reaction.
# 4. Assert spec-conformance.

echo "TODO: implement witness for <PHASE.NN>"
exit 1
