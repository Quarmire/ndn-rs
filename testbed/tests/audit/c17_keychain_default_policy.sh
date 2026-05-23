#!/usr/bin/env bash
# Witness test for audit finding C.17 — KeyChain::validator() uses
# TrustSchema::hierarchical() as default, not accept_all().
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § C.17
# Severity:    MINOR (default API should be the safe choice)
# Spec ref:    NFD Developer Guide §7 (trust anchors / validation policy);
#              ndn-cxx/ndn-cxx/security/validation-policy-command-interest.hpp
#              uses HierarchicalValidator as the inner policy.
# Witnesses:   GREP-PROOF — KeyChain::validator() calls
#              TrustSchema::hierarchical(), not TrustSchema::accept_all().
#              RUST-UNIT — c17_keychain_validator_uses_hierarchical
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

fail=0

# KeyChain::validator() must call hierarchical(), not accept_all()
if grep -A 5 "pub fn validator" \
    "$REPO_ROOT/crates/ndn-security/src/keychain.rs" \
    | grep -q "TrustSchema::hierarchical()"; then
    echo "ok: KeyChain::validator uses TrustSchema::hierarchical()"
else
    echo "FAIL: KeyChain::validator does not use TrustSchema::hierarchical()"
    fail=1
fi

# It must NOT use accept_all as the default
if grep -A 5 "pub fn validator" \
    "$REPO_ROOT/crates/ndn-security/src/keychain.rs" \
    | grep -q "accept_all"; then
    echo "FAIL: KeyChain::validator still uses accept_all as default"
    fail=1
else
    echo "ok: KeyChain::validator does not default to accept_all"
fi

# RUST-UNIT
if cargo test -p ndn-security --lib --quiet \
        "c17_keychain_validator_uses_hierarchical" \
        >>/tmp/c17_witness.log 2>&1; then
    echo "ok: c17_keychain_validator_uses_hierarchical"
else
    echo "FAIL: c17_keychain_validator_uses_hierarchical"
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo
    echo "=== C.17 RESOLVED — KeyChain::validator() defaults to hierarchical schema ==="
    exit 0
else
    echo
    echo "=== C.17 EXPECTED-FAIL — default validator policy is accept_all ==="
    cat /tmp/c17_witness.log
    exit 1
fi
