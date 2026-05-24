#!/usr/bin/env bash
# Witness — NC.13: recode-as-named-computation (doctrine §8).
#
# A consumer can request a *specific* deterministic combination by naming the
# coding vector (`…/_gen/<id>/_nc/<vector>`): `recode_exact` produces the exact
# combination (deterministic + name-cacheable, distinct from the fresh-random
# `_req/<j>` mode), the name round-trips, and through a real engine a consumer
# naming the K unit vectors recovers the sources and decodes. This mode is
# additive — it coexists with `_req/<j>`, selected per-Interest by name.
#
# Witnesses (feature `f2-recode-face`):
#   - recode::tests::recode_exact_is_deterministic_and_named
#   - tests/recode_engine.rs::named_vector_combinations_served_through_engine
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

if ! command -v cargo >/dev/null 2>&1; then
    echo "SKIP: cargo missing" >&2
    exit 2
fi

if cargo test -p ndn-coding --features f2-recode-face --quiet -- \
        recode_exact_is_deterministic_and_named \
        named_vector_combinations_served_through_engine \
        >/tmp/nc13_witness.log 2>&1 && grep -qE "result: ok\. [1-9]" /tmp/nc13_witness.log; then
    echo "=== NC.13 PASS — named (deterministic) combinations served + decode ==="
    grep -E "test result|running" /tmp/nc13_witness.log | tail -n 3
    exit 0
else
    echo "=== NC.13 FAIL — named-computation witness failed ==="
    cat /tmp/nc13_witness.log
    exit 1
fi
