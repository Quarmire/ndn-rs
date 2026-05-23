#!/usr/bin/env bash
# Witness recipe for ARCH-20 / S14 — unified `TrustPolicy` handle.
#
# Finding:     docs/notes/architecture-gap-inventory-2026-05-20.md § ARCH-20
# Severity:    Phase 2 architectural cleanup (pre-v0.1.0)
# Witnesses:
#   (a) GREP-PROOF — `ndn_security::TrustPolicy` exists; DV / NLSR /
#       ndn-cert each reference it; NLSR no longer carries a
#       `permissive_validation` flag on its protocol config.
#   (b) RUST-UNIT — `InsecureTrust`, `StaticTrust`, `LvsTrust`
#       round-trip through `TrustPolicy::signer` /
#       `TrustPolicy::validator` and yield the expected
#       signer-or-DigestSha256 + validator schema.
#
# Reverify recipe: GREP-PROOF + RUST-UNIT. Runs in any checkout of
# ndn-rs; no Docker required.
#
# Exit codes:
#   0 — PASS (TrustPolicy lifted to ndn-security; consumers reference it)
#   1 — FAIL (residual `permissive_validation` or missing TrustPolicy refs)
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

fail=0

check_grep() {
    local pattern="$1" path="$2" label="$3"
    if ! grep -rqnE "$pattern" "$path"; then
        echo "FAIL: $label — \"$pattern\" not found under $path" >&2
        fail=1
    fi
}

check_absent() {
    local pattern="$1" path="$2" label="$3"
    if grep -rqnE "$pattern" "$path"; then
        echo "FAIL: $label still present:" >&2
        grep -rnE "$pattern" "$path" >&2
        fail=1
    fi
}

# (1) TrustPolicy + the three built-ins live in ndn-security.
check_grep 'pub trait TrustPolicy'   crates/ndn-security/src/trust.rs   'TrustPolicy trait'
check_grep 'pub struct InsecureTrust' crates/ndn-security/src/trust.rs  'InsecureTrust'
check_grep 'pub struct StaticTrust'   crates/ndn-security/src/trust.rs  'StaticTrust'
check_grep 'pub struct LvsTrust'      crates/ndn-security/src/trust.rs  'LvsTrust'

# (2) DV / NLSR / ndn-cert reference the canonical TrustPolicy.
check_grep 'ndn_security::TrustPolicy' crates/ndn-routing/src/protocols/dv/signing.rs 'DV references TrustPolicy'
check_grep 'ndn_security::TrustPolicy' crates/ndn-routing/src/protocols/nlsr/protocol.rs 'NLSR references TrustPolicy'
check_grep 'ndn_security::TrustPolicy' crates/ndn-cert/src/policy.rs 'ndn-cert references TrustPolicy'

# (3) NLSR no longer carries a `permissive_validation` config field.
#     (Comments + TOML back-compat parsing may still mention the
#     phrase; the protocol-side struct must not.)
NLSR_PROTOCOL=crates/ndn-routing/src/protocols/nlsr/protocol.rs
if grep -nE '^\s*pub\s+permissive_validation\s*:\s*bool' "$NLSR_PROTOCOL" >/dev/null 2>&1; then
    echo "FAIL: NlsrConfig still declares permissive_validation: bool" >&2
    grep -nE '^\s*pub\s+permissive_validation\s*:\s*bool' "$NLSR_PROTOCOL" >&2
    fail=1
fi

# (4) RUST-UNIT — the three built-ins behave as designed.
TESTS=(
    "s14_insecure_trust_yields_no_signer"
    "s14_static_trust_from_keychain_yields_signer"
    "s14_static_trust_validator_rejects_cross_namespace"
    "s14_lvs_trust_holds_model"
)
for t in "${TESTS[@]}"; do
    echo "→ cargo test -p ndn-security --lib trust::tests::${t}"
    if ! cargo test --quiet -p ndn-security --lib "trust::tests::${t}" \
            -- --exact >/dev/null 2>&1; then
        echo "FAIL: trust::tests::${t}" >&2
        fail=1
    fi
done

if [ "$fail" -eq 0 ]; then
    echo "PASS: ARCH-20 — TrustPolicy lifted to ndn-security; DV / NLSR / ndn-cert speak one shape."
fi
exit "$fail"
