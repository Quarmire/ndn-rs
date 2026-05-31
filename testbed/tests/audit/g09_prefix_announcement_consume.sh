#!/usr/bin/env bash
# Witness test for audit finding G.09 — NDNLPv2 `PrefixAnnouncement`
# (TLV-TYPE 0x0350) header decoded by `LpPacket::decode` but never
# surfaced into the engine pipeline for downstream consumers.
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § G.09
# Severity:    MAJOR
# Spec ref:    NFD `daemon/fw/self-learning-strategy.cpp:122-245`
#              reads `data.getTag<lp::PrefixAnnouncementTag>()` and
#              inserts a route. NDNLPv2 spec defines the header for
#              the self-learning use case.
# Witnesses:   RUST-UNIT/RUST-INTEG in `ndn-engine`:
#                - g09_decode_stage_surfaces_prefix_announcement_tag
#              Builds an LP frame carrying PrefixAnnouncement(0x0350) +
#              Fragment(Interest), runs `TlvDecodeStage::process`, and
#              asserts `ctx.tags::<PrefixAnnouncement>()` is populated.
#                - learned_route_forwards_followup_interest
#              Drives a live in-process forwarding path: a neighbor returns
#              Data carrying a validated PrefixAnnouncement, self-learning
#              installs `/learned`, and a later `/learned/item` Interest
#              forwards to the announcing face.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

fail=0
if cargo test -p ndn-engine --lib --quiet g09_ \
        >/tmp/g09_witness.log 2>&1; then
    echo "ok: decode stage surfaces PrefixAnnouncement into ctx.tags"
else
    echo "FAIL: decode stage drops the PrefixAnnouncement tag"
    fail=1
fi

if cargo test -p ndn-engine --test self_learning --quiet \
        learned_route_forwards_followup_interest \
        >>/tmp/g09_witness.log 2>&1; then
    echo "ok: self-learning installs and uses PrefixAnnouncement route"
else
    echo "FAIL: self-learning PrefixAnnouncement route is not used"
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo
    echo "=== G.09 RESOLVED 2026-05-28 — PrefixAnnouncement decoded, validated, installed, and used ==="
    exit 0
else
    echo
    echo "=== G.09 EXPECTED-FAIL — PrefixAnnouncement tag not surfaced ==="
    [ -f /tmp/g09_witness.log ] && cat /tmp/g09_witness.log
    exit 1
fi
