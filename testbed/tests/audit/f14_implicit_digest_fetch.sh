#!/usr/bin/env bash
# Witness — F14 (NDF, D-40 track B): implicit-digest fetch + CanBePrefix
# content-hash-suffix resolution in the Content Store.
#
# Finding:   ndf-vault/45-libraries/ndn-rs-feature-requests.md § F14
# Severity:  MAJOR (NDF "any node serves it by content hash" model)
# Spec ref:  NDN ImplicitSha256DigestComponent (TLV 0x01); CanBePrefix selector.
# Witnesses: RUST-UNIT (ndn-store lru_cs + fjall_cs):
#              - implicit_digest_lookup_matches
#                  a digest-suffixed Interest hits cached Data when the SHA-256
#                  of the stored Data equals the suffix
#              - implicit_digest_wrong_hash_misses
#                  a mismatched digest does NOT alias another object
#              - can_be_prefix_finds_longer_name / _miss_for_unrelated_name
#              - d04_can_be_prefix_must_be_fresh_rejects_stale_descendant
#                  CanBePrefix resolution (the A.2 content-hash-suffix mechanism)
#                  respects MustBeFresh.
#
# These behaviors back D-40 track B routing of `<auth>/blocks/<hash>`; this
# witness pins them in the audited set so they cannot silently regress.
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

if cargo test -p ndn-store --lib --quiet -- \
        implicit_digest_lookup_matches \
        implicit_digest_wrong_hash_misses \
        can_be_prefix_finds_longer_name \
        can_be_prefix_miss_for_unrelated_name \
        d04_can_be_prefix_must_be_fresh_rejects_stale_descendant \
        >/tmp/f14_witness.log 2>&1; then
    echo "=== F14 PASS — implicit-digest CS lookup + CanBePrefix resolution hold ==="
    exit 0
fi
echo "=== F14 FAIL ==="
cat /tmp/f14_witness.log
exit 1
