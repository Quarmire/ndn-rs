#!/usr/bin/env bash
# Witness — F16(ii) (NDF): ReplayGuard AND-semantics with the monotonic=false
# shared-key mode (one key shared across devices — NDF chain replication).
#
# Finding:   ndf-vault/45-libraries/ndn-rs-feature-requests.md § F16
# Severity:  MAJOR (deliberate divergence: NDF shares a signing key across
#            devices, so strict monotonic seq/time would reject legitimate
#            interleaved Interests).
# Spec ref:  ndn-rs extension over NDN signed-Interest replay protection.
# Witnesses: RUST-UNIT (ndn-security replay_guard):
#     AND-semantics (a replay iff every shared anti-replay field agrees):
#       - distinct_nonces_with_same_time_are_not_replays
#       - same_nonce_same_time_is_replay
#     monotonic=false shared-key (KeyLocator None → shared DigestSha256 bucket):
#       - monotonic_false_shared_key_allows_out_of_order_seq
#           a lower seq from another device is admitted; an exact in-window
#           repeat is still a replay.
#       - monotonic_true_shared_key_blocks_lower_seq
#           contrast proving the mode is a real, selectable behavior.
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

if cargo test -p ndn-security --lib --quiet -- \
        distinct_nonces_with_same_time_are_not_replays \
        same_nonce_same_time_is_replay \
        monotonic_false_shared_key_allows_out_of_order_seq \
        monotonic_true_shared_key_blocks_lower_seq \
        >/tmp/f16ii_witness.log 2>&1; then
    echo "=== F16(ii) PASS — ReplayGuard AND-semantics + monotonic=false shared key hold ==="
    exit 0
fi
echo "=== F16(ii) FAIL ==="
cat /tmp/f16ii_witness.log
exit 1
