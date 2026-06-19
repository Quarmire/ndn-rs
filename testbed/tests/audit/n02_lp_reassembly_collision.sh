#!/usr/bin/env bash
# Witness test for audit finding N.02 — `ReassemblyBuffer` keys pending
# fragments by `Sequence` only, so two peers on a multi-access face
# (UDP multicast / Ethernet / BLE) using the same first-fragment
# Sequence value collide.
#
# Finding:     docs/notes/spec-compliance-cross-reference-2026-05-01.md § N.02
# Severity:    MAJOR (correctness on multi-access links)
# Spec ref:    NFD `daemon/face/lp-reassembler.hpp:134-137` keys by
#              `(EndpointId, Sequence)`.
# Witnesses:   RUST-UNIT in `ndn-packet`:
#                - n02_per_endpoint_keying_isolates_overlapping_sequences
#              Two simulated peers feed `seq=42` first fragments with
#              distinct endpoint identifiers; post-fix they produce two
#              pending entries and reassemble independently.
#              RUST-UNIT in `ndn-engine`:
#                - n02_face_addr_meta_yields_*_endpoint_ids
#                - n02_*decode*/reassembly tests
#              prove FaceAddr-derived UDP/MAC endpoint ids feed the decode
#              stage, so shared-medium senders do not alias at LP reassembly.
#              LIVE-UDP in `ndn-face`:
#                - n02_live_udp_shared_medium_source_addrs_drive_reassembly
#              sends colliding fragment sequences from two real UDP sockets
#              into one shared-medium face and reassembles both by source.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

fail=0
if cargo test -p ndn-packet --features std --lib --quiet n02_ \
        >/tmp/n02_witness.log 2>&1; then
    echo "ok: per-endpoint reassembly key isolates overlapping sequences"
else
    echo "FAIL: ReassemblyBuffer collides on shared Sequence value"
    fail=1
fi

if cargo test -p ndn-engine --lib --quiet n02_ \
        >>/tmp/n02_witness.log 2>&1; then
    echo "ok: FaceAddr-derived endpoint ids reach engine LP reassembly"
else
    echo "FAIL: engine does not preserve per-sender endpoint ids"
    fail=1
fi

if cargo test -p ndn-face --test shared_medium_live --quiet \
        n02_live_udp_shared_medium_source_addrs_drive_reassembly \
        >>/tmp/n02_witness.log 2>&1; then
    echo "ok: live UDP shared-medium senders reassemble independently"
else
    echo "FAIL: live UDP shared-medium reassembly fixture failed"
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo
    echo "=== N.02 RESOLVED 2026-05-28 — LP reassembly keyed by live FaceAddr-derived endpoint ids ==="
    exit 0
else
    echo
    echo "=== N.02 EXPECTED-FAIL — ReassemblyBuffer keyed by Sequence only ==="
    [ -f /tmp/n02_witness.log ] && cat /tmp/n02_witness.log
    exit 1
fi
