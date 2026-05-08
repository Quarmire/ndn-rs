#!/usr/bin/env bash
# Witness test for audit finding D.19 — PIT/FIB check-then-act race under
# parallel pipeline (`pipeline_threads > 1`).
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § D.19
# Severity:    BLOCKER
# Pre-fix bug:
#   PitCheckStage::process did `with_entry_mut(...) → if None { insert(...) }`,
#   releasing the per-shard lock between the lookup and the insert. Two
#   concurrent same-name Interests on different pipeline threads could both
#   observe "no entry" and both fall through to insert; the second insert
#   silently overwrote the first, dropping in-records.
#
#   Fib::add_nexthop had the symmetric `get(...) → insert(...)` race on the
#   FIB's NameTrie.
#
# Fix:
#   Pit::with_entry_or_insert holds the per-shard write lock across the
#   existence check and the insert (DashMap entry API on native;
#   HashMap entry API under Mutex on wasm32).
#
#   NameTrie::update holds the leaf node's write lock across the
#   read-modify-write closure; Fib::add_nexthop now uses it.
#
# Reverify recipes:
#   RUST-UNIT (PIT):  cargo test -p ndn-engine --lib stages::pit::d19_tests
#                     Drives N={2, 10, 100*5} concurrent same-name Interests
#                     through PitCheckStage and asserts all in-records survive.
#   RUST-UNIT (FIB):  cargo test -p ndn-store --lib
#                     fib::tests::d19_concurrent_add_nexthop_preserves_all
#                     Drives N=50 concurrent add_nexthop calls and asserts
#                     all nexthops survive.
#
# Reproducer (pre-fix): N=100 concurrent consumer faces calling next_spark()
# for the same name on a fresh engine reliably lost 1–3 in-records per
# startup on M-series macOS.
#
# Exit codes:
#   0 — both unit tests pass
#   1 — at least one fails (race recurred)

set -euo pipefail

cd "$(dirname "$0")/../../.."

PIT_TEST="stages::pit::d19_tests"
FIB_TEST="fib::tests::d19_concurrent_add_nexthop_preserves_all"

echo "[D.19] PIT race regression test"
cargo test -p ndn-engine --lib "$PIT_TEST" -- --nocapture
echo

echo "[D.19] FIB race regression test"
cargo test -p ndn-store --lib "$FIB_TEST" -- --nocapture
echo

echo "[D.19] PASS — atomic check-and-insert prevents in-record / nexthop loss"
