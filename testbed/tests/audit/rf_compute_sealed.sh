#!/usr/bin/env bash
# Witness — reflexive forwarding: the confidentiality leg (RICE §8). The params
# pulled over the reverse path are encrypted (X25519 ECDH + AES-256-GCM sealed
# box), unreadable by on-path forwarders.
#
# Finding:   docs/notes/reflexive-forwarding-engine-2026-05-21.md §6;
#            docs/notes/compute-wire-spec-2026-05-21.md §8
# Witness:   RUST-UNIT in ndn-compute (requires --features sealed-params):
#              - sealed::tests::{seal_open_round_trip, tampered_ciphertext_is_rejected,
#                wrong_node_key_cannot_open, truncated_blob_is_malformed}
#              - reflexive_sealed_end_to_end: consumer seals params to the node's
#                ephemeral key; node decrypts and computes; blob is ciphertext.
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

fail=0
if ! cargo test -p ndn-compute --features sealed-params --lib --quiet sealed:: \
        >/tmp/rf_sealed_witness.log 2>&1; then
    fail=1
fi
if ! cargo test -p ndn-compute --features sealed-params --test end_to_end --quiet \
        reflexive_sealed_end_to_end >>/tmp/rf_sealed_witness.log 2>&1; then
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "=== RF confidentiality PASS — sealed reflexive params (ECDH+AES-GCM) ==="
    exit 0
fi
echo "=== RF confidentiality FAIL ==="
cat /tmp/rf_sealed_witness.log
exit 1
