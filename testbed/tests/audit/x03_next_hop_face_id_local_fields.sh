#!/usr/bin/env bash
# Witness test for X.03 — NDNLPv2 NextHopFaceId (TLV 0x0330) acceptance is
# gated, per-face, on the ingress face's LocalFields option.
#
# Finding:     .claude/notes/per-face-option-wiring-triage-2026-05-23.md (item 1)
# Severity:    MAJOR (privilege / forwarding-control drift)
# Spec ref:    NFD GenericLinkService DROPs a received NextHopFaceId unless
#              `m_options.allowLocalFields`
#              (NFD/daemon/face/generic-link-service.cpp:362-370). allowLocalFields
#              is settable only on local-scope faces via FaceUpdateCommand
#              (face-manager.cpp:292-299). NLSR/PSync enable it on their face,
#              then the forwarder honours their pinned Interests.
#
# Witness:     WIRE-CAPTURE (not GREP-PROOF). The integration test
#              `crates/ndn-engine/tests/next_hop_face_id_local_fields.rs` runs a
#              real ForwarderEngine: a pinned Interest (NextHopFaceId → face B)
#              with a FIB route → face C must follow the FIB by default and only
#              override to B once the ingress face has LocalFields enabled.
#
# Reverify:    cargo test -p ndn-engine --test next_hop_face_id_local_fields
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

if cargo test -p ndn-engine --test next_hop_face_id_local_fields --quiet \
        >/tmp/x03_witness.log 2>&1; then
    echo
    echo "=== X.03 RESOLVED — NextHopFaceId honoured only from LocalFields faces ==="
    exit 0
else
    echo "FAIL: NextHopFaceId honoured without the ingress LocalFields gate"
    echo
    echo "=== X.03 EXPECTED-FAIL — NextHopFaceId privilege gate missing ==="
    [ -f /tmp/x03_witness.log ] && tail -30 /tmp/x03_witness.log
    exit 1
fi
