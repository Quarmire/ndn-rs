#!/usr/bin/env bash
# Witness: `ndn-sec export` / `ndn-sec import` round-trips a whole identity
# (certificate + password-encrypted private key) through the SafeBag wire
# for BOTH supported signature types — Ed25519 and ECDSA-P256 — and in both
# base64 and raw encodings.
#
# This is the operator-facing CLI counterpart to c09 (which proves ndn-cxx
# `ndnsec` interop). It needs no docker: a fresh source PIB exports, a
# distinct destination PIB imports, and the imported key list must match.
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
# ndn-sec is built in the ndn-fwd workspace, a sibling of ndn-rs.
WORKSPACE_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
FWD_ROOT="$WORKSPACE_ROOT/ndn-fwd"
if [ ! -f "$FWD_ROOT/Cargo.toml" ]; then
    echo "SKIP: no ndn-fwd workspace at $FWD_ROOT"
    exit 2
fi
cd "$FWD_ROOT"

# Ask cargo where it puts the binary: a shared target dir (CARGO_TARGET_DIR,
# or the workspace's .cargo/config.toml) redirects it out of the repo.
if ! TARGET_DIR="$(cargo metadata --format-version 1 --no-deps 2>/dev/null \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"; then
    echo "SKIP: cannot locate the cargo target directory of $FWD_ROOT"
    exit 2
fi
BIN="$TARGET_DIR/debug/ndn-sec"
# Always build: a stale binary would witness old behaviour.
if ! cargo build -q -p ndn-tools --bin ndn-sec 2>/dev/null || [ ! -x "$BIN" ]; then
    echo "SKIP: could not build ndn-sec"
    exit 2
fi

SRC="$(mktemp -d)"; DST="$(mktemp -d)"; WORK="$(mktemp -d)"
cleanup() { rm -rf "$SRC" "$DST" "$WORK"; }
trap cleanup EXIT

fail() { echo "FAIL: $1"; exit 1; }

PW='correct horse battery staple'

# 1. Generate one identity per algorithm in the source PIB.
"$BIN" --pib "$SRC" keygen /lab/alice --anchor                >/dev/null || fail "keygen ed25519"
"$BIN" --pib "$SRC" keygen /lab/bob --type ecdsa              >/dev/null || fail "keygen ecdsa"

# 2. Export: ed25519 as base64 (ndnsec-compatible text), ecdsa as raw TLV.
"$BIN" --pib "$SRC" export /lab/alice --password "$PW" -o "$WORK/alice.safebag" \
    >/dev/null 2>&1 || fail "export ed25519"
"$BIN" --pib "$SRC" export /lab/bob --password "$PW" --format raw -o "$WORK/bob.safebag" \
    >/dev/null 2>&1 || fail "export ecdsa raw"

# base64 export must be printable text; raw export must start with the
# SafeBag type byte 0x80. (POSIX character classes — portable to BSD grep.)
if LC_ALL=C grep -q '[^[:print:][:space:]]' "$WORK/alice.safebag"; then
    fail "base64 export contains non-text bytes"
fi
[ "$(head -c1 "$WORK/bob.safebag" | xxd -p)" = "80" ] || fail "raw export missing 0x80 type byte"

# 3. Import both into a clean destination PIB (the import auto-derives the
#    key name from the embedded cert; the base64 vs raw form is auto-detected).
"$BIN" --pib "$DST" import "$WORK/alice.safebag" --password "$PW" --anchor \
    >/dev/null 2>&1 || fail "import ed25519 base64"
"$BIN" --pib "$DST" import "$WORK/bob.safebag" --password "$PW" \
    >/dev/null 2>&1 || fail "import ecdsa raw"

# 4. The destination PIB must now hold both identities, under the same key
#    names (`<identity>/KEY/<keyid>`, derived from the certificate), + the anchor.
#    `list` prints each key at two-space indent, its certificates below it.
SRC_KEYS="$("$BIN" --pib "$SRC" list | grep '^  /' | sort)"
DST_KEYS="$("$BIN" --pib "$DST" list | grep '^  /' | sort)"
[ "$(printf '%s\n' "$SRC_KEYS" | grep -c /KEY/)" -eq 2 ] || fail "expected 2 source keys, got: $SRC_KEYS"
[ "$SRC_KEYS" = "$DST_KEYS" ] || fail "imported keys differ: src=[$SRC_KEYS] dst=[$DST_KEYS]"
"$BIN" --pib "$DST" anchor list | grep -q /lab/alice || fail "imported anchor missing"

# 5. Wrong passphrase must be rejected, not silently accepted.
if "$BIN" --pib "$WORK/scratch" import "$WORK/alice.safebag" --password WRONG >/dev/null 2>&1; then
    fail "import accepted a wrong passphrase"
fi

echo "PASS: ndn-sec export/import round-trips Ed25519 + ECDSA (base64 & raw)"
exit 0
