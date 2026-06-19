#!/usr/bin/env bash
# Witness recipe for audit finding G.06 — NDN AutoConfig hub-discovery.
#
# Finding:   testbed/EXPECTED_FAILURES.md § G.06
# Severity:  MAJOR
# Type:      RUST-UNIT
#
# What this tests:
#   1. build_hub_data() encodes the hub FaceUri as TLV type 0x72 (nfd::Uri),
#      matching the wire format of ndn-autoconfig-server (program.cpp:56).
#   2. AutoConfigDiscovery.on_inbound() parses the hub Data and publishes
#      the URI to its watch channel.
#   3. build_hub_discovery_interest() emits an Interest with name
#      /localhop/ndn-autoconf/hub, CanBePrefix=true, MustBeFresh=true.
#
# These properties are verified by unit tests in ndn-discovery:
#   autoconfig::client::tests::build_hub_data_round_trips_uri
#   autoconfig::client::tests::hub_discovery_interest_has_correct_name
#   autoconfig::client::tests::parse_hub_uri_extracts_faceuri
#
# Reverify recipe:
#   cargo test -p ndn-discovery autoconfig::client::tests
#   Expected: all pass (exit 0)
#
# Exit codes: 0 PASS / 1 FAIL
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

TRANSCRIPT_DIR="testbed/tests/audit/transcripts"
TRANSCRIPT="$TRANSCRIPT_DIR/g06_autoconfig_hub_discovery_after.txt"

mkdir -p "$TRANSCRIPT_DIR"

echo "Running AutoConfig hub-discovery unit tests..." | tee "$TRANSCRIPT"
if cargo test -p ndn-discovery "autoconfig::client::tests" --no-fail-fast 2>&1 | tee -a "$TRANSCRIPT"; then
    echo "PASS: all hub-discovery unit tests passed" | tee -a "$TRANSCRIPT"
    exit 0
else
    echo "FAIL: one or more hub-discovery unit tests failed" | tee -a "$TRANSCRIPT"
    exit 1
fi
