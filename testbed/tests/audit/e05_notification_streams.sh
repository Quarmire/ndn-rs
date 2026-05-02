#!/usr/bin/env bash
# Witness test for audit finding E.05 — NFD-style management notification
# streams (`/localhost/nfd/<module>/notifications/<seq>`) absent.
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § E.05
# Severity:    MAJOR (missing feature; subscriber-side parity with NFD)
# Spec ref:    NFD `daemon/mgmt/face-manager.cpp:71`
#              `m_postNotification = registerNotificationStream("events");`
#              ndn-cxx `mgmt/dispatcher.cpp:299-329`
#              `addNotificationStream` / `postNotification` —
#              the publisher appends a `SequenceNumberComponent`
#              (TLV-TYPE 0x3A) per emitted notification.
#
# Witnesses:   RUST-UNIT trio in `ndn-config::notifications::tests`:
#                - e05_stream_prefix_appends_notifications_segment
#                - e05_publish_increments_sequence_per_call
#                - e05_published_wire_decodes_with_payload
#
# Live `nfdc events` subscriber interop is BLOCKED-BY-INTEROP until the
# ndn-cxx `nfdc` binary lands in the testclient image. The architecture
# witness above proves the publisher primitive emits spec-shaped Data
# packets; wiring the publisher to actual face / route / strategy event
# sources is tracked as a follow-up.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

fail=0
if cargo test -p ndn-config --lib --quiet e05_ \
        >/tmp/e05_witness.log 2>&1; then
    echo "ok: NotificationStream publishes <prefix>/<seq> Data with payload"
else
    echo "FAIL: NotificationStream architecture"; fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo
    echo "=== E.05 RESOLVED 2026-05-02 (architecture); live nfdc events still BLOCKED-BY-INTEROP ==="
    exit 0
else
    echo
    echo "=== E.05 EXPECTED-FAIL — NotificationStream missing ==="
    [ -f /tmp/e05_witness.log ] && cat /tmp/e05_witness.log
    exit 1
fi
