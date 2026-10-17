#!/usr/bin/env bash
# Witness for NDN Certificate Format v2 interop with ndn-cxx (C.07 naming).
#
# ndn-rs issues, through its public SecurityManager API
# (crates/security/ndn-security/examples/certv2_interop_chain.rs), one
# namespace chain per algorithm, every KeyLocator naming the signer's key:
#   root    /<ns>/KEY/<kid>/self/v=…               self-signed
#   CA      /<ns>/CA/KEY/<kid>/NA/v=…              certified by the root
#   device  /<ns>/member/dev/KEY/<kid>/NDNCERT/v=… certified by the CA
#   Data    /<ns>/member/dev/data/v=…              signed by the device key
# ndn-cxx 0.9 (ndncxx/check.sh) must then show:
#   1. ECDSA-P256: `ndnsec cert-dump` parses every certificate; ndn-cxx decodes
#      each as a v2 Certificate (version component, ContentType KEY, validity
#      covering now, KeyLocator = the issuer's key name); every hop verifies;
#      the ndn-cxx Validator accepts the device certificate and the Data.
#   2. ECDSA-P256 Data with one content byte flipped: the Validator refuses it.
#   3. Ed25519: the same decoding checks; every hop verifies with OpenSSL over
#      ndn-cxx's extracted signed ranges. ndn-cxx 0.9 has no Ed25519 verifier,
#      so its Validator lines must be UNSUPPORTED, never PASS or FAIL.
#   4. Ed25519 Data with one content byte flipped: the hop check refuses it.
# The Validator policy admits KEY- or certificate-name KeyLocators under the
# anchor. NFD's stock `hierarchical` rule refuses /<ns>/CA certifying
# /<ns>/member/... by design of the namespace layout (the namespace's trust
# schema governs that, not name hierarchy); expectation 1 records that refusal.
#
# Prerequisites: cargo, and either ndn-cxx in the environment (`ndnsec` on
# PATH, `libndn-cxx` known to pkg-config) or nix-shell (ndncxx/shell.nix pulls
# nixpkgs ndn-cxx). A C++17 compiler builds ndncxx/ndncxx-interop.cpp on demand.
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
CHECK="$HERE/ndncxx/check.sh"
cd "$REPO_ROOT" || exit 1

if ! command -v cargo >/dev/null 2>&1; then
    echo "SKIP: cargo missing"
    exit 2
fi
if ! { command -v ndnsec >/dev/null 2>&1 && pkg-config --exists libndn-cxx 2>/dev/null; } &&
        ! command -v nix-shell >/dev/null 2>&1; then
    echo "SKIP: ndn-cxx (ndnsec, libndn-cxx) not in the environment and nix-shell missing"
    exit 2
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "########## ndn-rs: cargo run -p ndn-security --example certv2_interop_chain"
if ! cargo run -q -p ndn-security --example certv2_interop_chain -- "$WORK"; then
    echo "FAIL: ndn-rs chain generator"
    exit 1
fi

# tamper SRC DST: DST = SRC with the first byte of the Data content flipped.
tamper() {
    local off
    cp "$1" "$2"
    off=$(LC_ALL=C grep -obUa -m1 "ndn-rs certv2 interop payload" "$2" | cut -d: -f1)
    [ -n "$off" ] && printf 'N' | dd of="$2" bs=1 seek="$off" conv=notrunc status=none
}
for alg in ecdsa ed25519; do
    if ! tamper "$WORK/$alg/data.data" "$WORK/$alg/tampered.data"; then
        echo "FAIL: payload not found in $WORK/$alg/data.data"
        exit 1
    fi
done

declare -A RC
# check RUN ALG DATA: ndn-cxx checks of ALG's chain and DATA, logged to $WORK/RUN.log.
check() {
    local d="$WORK/$2"
    echo "########## $1: check.sh -K -d $3 dev.cert ca.cert root.cert"
    "$CHECK" -K -d "$d/$3" "$d/dev.cert" "$d/ca.cert" "$d/root.cert" 2>&1 | tee "$WORK/$1.log"
    RC[$1]=${PIPESTATUS[0]}
    if [ "${RC[$1]}" -eq 2 ]; then
        echo "SKIP: ndn-cxx unavailable (see check.sh output above)"
        exit 2
    fi
}
check ecdsa ecdsa data.data
check ecdsa-tampered ecdsa tampered.data
check ed25519 ed25519 data.data
check ed25519-tampered ed25519 tampered.data

ok=0 bad=0
expect() {  # expect DESCRIPTION COMMAND...
    local what="$1"
    shift
    if "$@"; then
        echo "PASS: $what"
        ok=$((ok + 1))
    else
        echo "FAIL: $what"
        bad=$((bad + 1))
    fi
}
n() { grep -cE "$2" "$WORK/$1.log"; }          # n RUN REGEX: matching lines
is() { [ "$(n "$1" "$2")" -eq "$3" ]; }         # is RUN REGEX COUNT
rc() { [ "${RC[$1]}" -eq "$2" ]; }               # rc RUN CODE

echo "########## expectations"
for alg in ecdsa ed25519; do
    expect "$alg: check.sh exits 0 (no FAIL line)" rc "$alg" 0
    expect "$alg: ndnsec cert-dump parses root, CA and device certificates" \
        is "$alg" '^PASS: ndnsec cert-dump -p parses' 3
    expect "$alg: ndn-cxx decodes all three as v2 Certificates (version, ContentType KEY, validity)" \
        is "$alg" '^PASS: (ndn-cxx decodes as v2 Certificate|last name component is a VersionNameComponent|ContentType is KEY|validity period .* covers now)' 12
    expect "$alg: every KeyLocator (2 certificate-chain + 3 Data-chain hops) is the issuer key name" \
        is "$alg" '^PASS: KeyLocator of .* is the issuer key name /interop/' 5
    expect "$alg: root self-signature and all 5 chain hops verify" \
        is "$alg" '^PASS: (self-signature verifies|chain hop )' 6
done
expect "ecdsa: ndn-cxx Validator accepts the device certificate and the Data" \
    is ecdsa '^PASS: ndn-cxx Validator \(keylocator-v2-name policy, offline fetcher\): /interop/ecdsa/member/dev/' 2
expect "ecdsa: NFD hierarchical rule refuses /interop/ecdsa/CA certifying /interop/ecdsa/member/dev (namespace trust schema governs)" \
    is ecdsa '^NOTE: ndn-cxx Validator \(hierarchical policy, offline fetcher\): Policy violation \(Packet /interop/ecdsa/member/dev/KEY/' 2
expect "ecdsa-tampered: check.sh exits 1" rc ecdsa-tampered 1
expect "ecdsa-tampered: ndn-cxx Validator refuses the tampered Data" \
    is ecdsa-tampered '^FAIL: ndn-cxx Validator \(keylocator-v2-name policy, offline fetcher\): Signature verification failed' 1
expect "ecdsa-tampered: the Data hop is the only failed hop" \
    is ecdsa-tampered '^FAIL: chain hop /interop/ecdsa/member/dev/data/' 1
expect "ed25519: ndn-cxx Validator UNSUPPORTED for the device certificate and the Data (no Ed25519 in ndn-cxx 0.9)" \
    is ed25519 '^UNSUPPORTED: ndn-cxx Validator \(keylocator-v2-name policy' 2
expect "ed25519: hops verified with OpenSSL Ed25519 over ndn-cxx signed ranges" \
    is ed25519 '^PASS: chain hop .*SignatureEd25519, OpenSSL Ed25519 over ndn-cxx extractSignedRanges' 5
expect "ed25519-tampered: check.sh exits 1" rc ed25519-tampered 1
expect "ed25519-tampered: the Data hop is refused" \
    is ed25519-tampered '^FAIL: chain hop /interop/ed25519/member/dev/data/' 1

summary() { grep -h '^SUMMARY' "$WORK/$1.log" | sed "s/^SUMMARY:/$1:/"; }
echo
for r in ecdsa ecdsa-tampered ed25519 ed25519-tampered; do summary "$r"; done
if [ "$bad" -eq 0 ]; then
    echo "=== C.07 cert-v2 ndn-cxx interop PASS — $ok/$ok expectations hold ==="
    exit 0
fi
echo "=== C.07 cert-v2 ndn-cxx interop FAIL — $bad of $((ok + bad)) expectations broken ==="
exit 1
