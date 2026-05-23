#!/usr/bin/env bash
# Witness test for X.04 — NDNLPv2 reliability consolidation gate (item 2 of
# .claude/notes/per-face-option-wiring-triage-2026-05-23.md).
#
# Finding:     The LinkService `ReliabilityFeature` (the consolidation target)
#              frames egress via `on_send_track`, which injects **no
#              TxSequence** (`crates/ndn-transport/src/reliability.rs:248-252`),
#              so a peer can never Ack a feature-sent frame — it is a
#              non-canonical stub. The spec-canonical path is store C's
#              `on_send`. Consolidating reliability onto the feature (Option A)
#              must first make the feature emit a TxSequence like the core.
# Severity:    MAJOR (reliability correctness / NDNLPv2 conformance)
# Spec ref:    NDNLPv2 §3.2 (Sequence/TxSequence); NFD daemon/face/lp-reliability.cpp.
#
# Witness:     RUST-UNIT (deterministic, in-process — no docker flake), the
#              stage-1 gate for the reliability refactor:
#                - canonical_core_recovers_loss        (GREEN — must stay green:
#                    canonical core emits TxSequence, Acks, recovers a drop)
#                - feature_egress_emits_tx_sequence    (RED today → GREEN once the
#                    feature is made canonical in stage 3)
#
# Reverify:    cargo test -p ndn-transport --test reliability_loss_recovery
#
# Exit codes:  0 PASS (both green — refactor landed) / 1 EXPECTED-FAIL (feature
#              still non-canonical) / 2 SKIP (no cargo)
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

if cargo test -p ndn-transport --test reliability_loss_recovery --quiet \
        >/tmp/x04_witness.log 2>&1; then
    echo
    echo "=== X.04 RESOLVED — reliability feature is canonical (TxSequence on egress) ==="
    exit 0
else
    echo "EXPECTED-FAIL: ReliabilityFeature egress emits no TxSequence (non-canonical stub)"
    echo
    echo "=== X.04 EXPECTED-FAIL — feature reliability not yet canonical (item 2 open) ==="
    [ -f /tmp/x04_witness.log ] && tail -25 /tmp/x04_witness.log
    exit 1
fi
