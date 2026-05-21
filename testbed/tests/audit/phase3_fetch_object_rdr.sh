#!/usr/bin/env bash
# Witness recipe for Phase 3 §3.2 — `Consumer::fetch_object` /
# `Producer::publish_object` round-trip via the RDR metadata convention.
#
# Finding:     docs/notes/tiered-api-design-2026-05-20.md §2.5
# Severity:    Phase 3 deliverable (pre-v0.1.0)
# Witnesses:
#   (a) GREP-PROOF — `crates/spec/ndn-app/src/consumer.rs` exposes
#       `pub async fn fetch_object`.
#   (b) GREP-PROOF — `crates/spec/ndn-app/src/producer.rs` exposes
#       `pub async fn publish_object`.
#   (c) GREP-PROOF — the RDR helpers (`MetaData`, `metadata_name`,
#       `PreparedObject`) live in `crates/spec/ndn-app/src/rdr.rs` and
#       reference `<name>/32=metadata` via the `METADATA_KEYWORD`
#       constant.
#   (d) RUST-INTEG — the two-engine round-trip
#       `crates/spec/ndn-app/tests/rdr_round_trip.rs` passes (
#       producer publishes a 20 000-byte segmented object,
#       consumer reassembles via metadata + segment fetches,
#       byte equality asserted).
#
# Reverify recipe: GREP-PROOF + RUST-INTEG.  Runs in any checkout of
# ndn-rs; no Docker required.
#
# Cross-impl reference:  ndnd `Client.Consume` /  `Client.Produce`
#   (`~/Documents/Dev/ndnd/std/object/client_consume.go:22`,
#    `~/Documents/Dev/ndnd/std/object/client_produce.go:118`).
#
# Exit codes:
#   0 — PASS (fetch_object / publish_object ship and the round-trip is green)
#   1 — FAIL
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

fail=0

check_grep() {
    local pattern="$1" path="$2" label="$3"
    if ! grep -qE "$pattern" "$path"; then
        echo "FAIL: $label — \"$pattern\" not found in $path" >&2
        fail=1
    fi
}

CONS=crates/spec/ndn-app/src/consumer.rs
PROD=crates/spec/ndn-app/src/producer.rs
RDR=crates/spec/ndn-app/src/rdr.rs
TEST=crates/spec/ndn-app/tests/rdr_round_trip.rs

# (a)(b)(c) — surface presence.
check_grep 'pub async fn fetch_object'   "$CONS" 'Consumer::fetch_object exists'
check_grep 'pub async fn publish_object' "$PROD" 'Producer::publish_object exists'
check_grep 'pub const METADATA_KEYWORD'  "$RDR"  'METADATA_KEYWORD constant'
check_grep 'pub struct MetaData'         "$RDR"  'rdr::MetaData struct'
check_grep 'pub fn metadata_name'        "$RDR"  'rdr::metadata_name helper'
check_grep 'pub struct PreparedObject'   "$RDR"  'rdr::PreparedObject helper'

# (c) sanity — RDR test file references the round-trip we want to pin.
check_grep 'fn fetch_object_reassembles_publish_object' "$TEST" 'two-engine round-trip test exists'

# (d) RUST-INTEG.
echo "→ cargo test -p ndn-app --test rdr_round_trip"
if ! cargo test --quiet -p ndn-app --test rdr_round_trip >/dev/null 2>&1; then
    echo "FAIL: cargo test -p ndn-app --test rdr_round_trip did not pass" >&2
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "PASS: Phase 3 §3.2 — Consumer::fetch_object / Producer::publish_object RDR round-trip green."
fi
exit "$fail"
