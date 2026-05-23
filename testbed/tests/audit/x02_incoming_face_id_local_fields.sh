#!/usr/bin/env bash
# Witness test for X.02 — NDNLPv2 IncomingFaceId (TLV 0x032C) is gated,
# per-face, on the LocalFields option, and carries the true ingress FaceId.
#
# Finding:     .claude/notes/incoming-face-id-local-fields-audit-2026-05-23.md
# Severity:    MAJOR (NDNLPv2 local-field conformance / NFD interop)
# Spec ref:    NFD GenericLinkService::encodeLpFields gates IncomingFaceId on
#              `m_options.allowLocalFields`
#              (NFD/daemon/face/generic-link-service.cpp:152). The value is the
#              ingress face stamped by onIncomingInterest/onIncomingData
#              (NFD/daemon/fw/forwarder.cpp:92,301). allowLocalFields is off by
#              default (generic-link-service.hpp:99) and toggled by
#              FaceUpdateCommand BIT_LOCAL_FIELDS_ENABLED=0
#              (ndn-cxx/encoding/nfd-constants.hpp:71).
#
# Witness:     WIRE-CAPTURE (not GREP-PROOF). The integration test
#              `crates/ndn-engine/tests/incoming_face_id_local_fields.rs` runs a
#              real ForwarderEngine, drives Interest/Data through network-kind
#              (LP-framed) faces, and decodes the *actual NDNLPv2 egress bytes*:
#                - interest_incoming_face_id_gated_on_local_fields:
#                    default → IncomingFaceId absent; after set_local_fields →
#                    IncomingFaceId == the ingress (consumer) FaceId.
#                - data_incoming_face_id_is_producer_ingress_face:
#                    Data to a LocalFields consumer carries the producer
#                    ingress FaceId.
#
# Reverify:    cargo test -p ndn-engine --test incoming_face_id_local_fields
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

if cargo test -p ndn-engine --test incoming_face_id_local_fields --quiet \
        >/tmp/x02_witness.log 2>&1; then
    echo
    echo "=== X.02 RESOLVED — IncomingFaceId gated on LocalFields, carries ingress FaceId ==="
    exit 0
else
    echo "FAIL: IncomingFaceId not attached on LocalFields egress, or wrong value"
    echo
    echo "=== X.02 EXPECTED-FAIL — NDNLPv2 IncomingFaceId/LocalFields drift ==="
    [ -f /tmp/x02_witness.log ] && tail -30 /tmp/x02_witness.log
    exit 1
fi
