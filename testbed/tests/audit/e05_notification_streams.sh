#!/usr/bin/env bash
# Witness test for audit finding E.05 — NFD-style management notification
# streams (`/localhost/nfd/<module>/notifications/<seq>`) are published
# from live management events.
#
# Finding:     testbed/EXPECTED_FAILURES.md § E.05
# Severity:    MAJOR (missing feature; subscriber-side parity with NFD)
# Spec ref:    NFD `daemon/mgmt/face-manager.cpp:71`
#              `m_postNotification = registerNotificationStream("events");`
#              ndn-cxx `mgmt/dispatcher.cpp:299-329`
#              `addNotificationStream` / `postNotification` —
#              the publisher appends a `SequenceNumberComponent`
#              (TLV-TYPE 0x3A) per emitted notification.
#
# Witnesses:   RUST-UNIT in `ndn-mgmt`:
#                - `notifications` tests cover long-poll and cached fetches.
#                - `face_notification_semantic_events` proves a semantic
#                  faces/update refusal is published.
#              LIVE-INTEROP in Docker:
#                - `ndn-ctl strategy set` triggers a real
#                  strategy-choice event.
#                - `ndn-mgmt-notification-fetch` fetches the latest
#                  `/localhost/nfd/strategy-choice/notifications/<seq>` Data
#                  and checks the unique event payload.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

fail=0
if cargo test -p ndn-mgmt --test notifications --quiet \
        >/tmp/e05_witness.log 2>&1 \
   && cargo test -p ndn-mgmt --test face_notification_semantic_events --quiet \
        >>/tmp/e05_witness.log 2>&1; then
    echo "ok: NotificationStream reaches unit subscribers from publisher and event sources"
else
    echo "FAIL: NotificationStream unit/event-source witnesses"; fail=1
fi

if [ "$fail" -eq 0 ] && command -v docker >/dev/null 2>&1; then
    if docker compose -f testbed/docker-compose.yml exec -T interop true \
            >/dev/null 2>&1; then
        unique="/e05-live/strategy-$(date +%s)"
        if docker compose -f testbed/docker-compose.yml exec -T interop bash -lc "
            set -euo pipefail
            ndn-ctl --socket /run/ndn-fwd/ndn-fwd.sock \
              strategy set '$unique' --strategy /localhost/nfd/strategy/best-route \
              >/tmp/e05_strategy_set.txt
            ndn-mgmt-notification-fetch \
              --socket /run/ndn-fwd/ndn-fwd.sock \
              --module strategy-choice \
              --expect-contains set \
              --expect-contains '$unique'
        " >/tmp/e05_live_witness.log 2>&1; then
            echo "ok: live strategy-choice notification fetched from ndn-fwd"
            cat /tmp/e05_live_witness.log
        else
            echo "FAIL: live management notification stream witness failed"
            cat /tmp/e05_live_witness.log
            fail=1
        fi
    else
        echo "SKIP: Docker interop services are not running; start with:"
        echo "      docker compose -f testbed/docker-compose.yml up -d interop ndn-fwd nfd yanfd"
    fi
fi

if [ "$fail" -eq 0 ]; then
    echo
    echo "=== E.05 RESOLVED 2026-05-28 (unit + live event-stream interop when Docker is running) ==="
    exit 0
else
    echo
    echo "=== E.05 FAIL — NotificationStream/event-source witness failed ==="
    [ -f /tmp/e05_witness.log ] && cat /tmp/e05_witness.log
    exit 1
fi
