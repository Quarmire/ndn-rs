#!/usr/bin/env bash
# Witness test for audit finding E.04 — status datasets emitted as a
# single Data instead of a versioned segment series.
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § E.04
# Severity:    BLOCKER
# Spec ref:    ndn-cxx mgmt/dispatcher.cpp:282-297 +
#              mgmt/status-dataset-context.cpp — segmented response with
#              `<prefix>/<verb>/v=<version>/seg=<n>`, FinalBlockId on
#              the last segment.
# Witnesses:   Two RUST-UNIT tests in `ndn-fwd::mgmt_ndn::e04_tests`:
#                - e04_single_segment_response_carries_version_segment_and_final_block_id
#                - e04_multi_segment_response_marks_only_last_segment_as_final
#
# Live `nfdc status` interop is blocked by the lack of an ndn-cxx
# `nfdc` binary in the testclient image. The RUST-UNIT witness covers
# the wire shape; full end-to-end verification with `nfdc` remains
# BLOCKED-BY-INTEROP.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi
if cargo test -p ndn-fwd --bin ndn-fwd --quiet e04_ \
        >/tmp/e04_witness.log 2>&1; then
    echo "=== E.04 RESOLVED — status datasets are versioned + segmented + carry FinalBlockId ==="
    exit 0
else
    echo "=== E.04 EXPECTED-FAIL — status datasets emitted as single Data ==="
    cat /tmp/e04_witness.log
    exit 1
fi
