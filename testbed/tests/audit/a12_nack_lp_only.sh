#!/usr/bin/env bash
# Witness test for audit findings A.12 + B.08 — Nack::decode accepts an
# invented "legacy bare Nack TLV (0x0320)" form that has no spec basis;
# test helper build_nack emits this invented form.
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § A.12, B.08
# Severity:    MAJOR
# Spec ref:    NDNLPv2 §3.5 — Nack is a per-hop header on an LpPacket
#              carrying the Interest in its Fragment. 0x0320 is the Nack
#              header TLV-TYPE inside an LpPacket, not a standalone outer TLV.
#              ndn-cxx/ndn-cxx/lp/nack-header.hpp, nack.hpp — no bare Nack.
# Witnesses:   GREP-PROOF — non-test nack.rs must not reference tlv_type::NACK
#              as an outer packet type; fn build_nack must not exist anywhere.
#              RUST-UNIT — a12_nack_lp_only_decode asserts the bare form
#              fails and the LpPacket form succeeds.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

fail=0

# ── GREP-PROOF ────────────────────────────────────────────────────────────────

# 1. build_nack (invented-form emitter) must not exist anywhere in nack.rs
if grep -q "fn build_nack" \
        "$REPO_ROOT/crates/foundation/ndn-packet/src/nack.rs"; then
    echo "FAIL: fn build_nack still present in nack.rs"
    fail=1
else
    echo "ok: fn build_nack not found"
fi

# 2. Non-test production code in nack.rs must not reference tlv_type::NACK
#    as an outer packet type (LP decode/encode legitimately reference it for
#    the LP-field usage — only nack.rs decode() is in scope here).
nack_non_test=$(awk '/^#\[cfg\(test\)\]/{exit} {print}' \
    "$REPO_ROOT/crates/foundation/ndn-packet/src/nack.rs")
if echo "$nack_non_test" | grep -qE 'tlv_type::NACK\b'; then
    echo "FAIL: non-test nack.rs still references tlv_type::NACK as outer type"
    fail=1
else
    echo "ok: non-test nack.rs does not reference tlv_type::NACK"
fi

# ── RUST-UNIT ─────────────────────────────────────────────────────────────────

if cargo test -p ndn-packet --features std --lib --quiet \
        a12_nack_lp_only_decode \
        >/tmp/a12_witness.log 2>&1; then
    echo "ok: bare Nack form rejected; LpPacket form accepted"
else
    echo "FAIL: a12_nack_lp_only_decode did not pass"
    cat /tmp/a12_witness.log
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo
    echo "=== A.12/B.08 RESOLVED — only NDNLPv2 form accepted ==="
    exit 0
else
    echo
    echo "=== A.12/B.08 EXPECTED-FAIL — invented bare Nack TLV still present ==="
    exit 1
fi
