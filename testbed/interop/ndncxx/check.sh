#!/usr/bin/env bash
# ndn-cxx interop check of NDN certificates / Data (ndn-rs output, or packets
# captured from a live network).
#
#   check.sh [-K] [-d DATA] [-a ANCHOR] CERT [ISSUER_CERT...]
#
#   CERT          certificate Data file (raw TLV as in an ndn-rs PIB / ca/*.data,
#                 or base64 as written by ndnsec)
#   ISSUER_CERT   issuer chain, in order: CERT's issuer, its issuer, ..., root
#   -a ANCHOR     trust anchor (default: last ISSUER_CERT, or CERT when no issuers)
#   -d DATA       Data packet signed by CERT's key (validated through the chain)
#   -K            every KeyLocator must name the signer's key (ndn-rs signers do)
#
# Prints PASS/FAIL/UNSUPPORTED/NOTE/INFO lines and a SUMMARY line.
# UNSUPPORTED = ndn-cxx 0.9 cannot verify Ed25519; the "chain hop" lines then
# carry the signature verdict (ndn-cxx decoding + OpenSSL Ed25519).
# Exit codes: 0 no FAIL / 1 FAIL / 2 SKIP (no ndn-cxx and no nix-shell) or usage.
#
# ndn-cxx comes from the environment (`ndnsec` on PATH, `libndn-cxx` known to
# pkg-config) or, failing that, from `nix-shell shell.nix` (nixpkgs ndn-cxx).
# The helper ndncxx-interop.cpp is compiled on demand into
# $NDNCXX_INTEROP_BUILD_DIR (default: <ndn-rs>/target/ndncxx-interop).
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"

usage() { sed -n '5,12p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }

if ! { command -v ndnsec >/dev/null 2>&1 && pkg-config --exists libndn-cxx 2>/dev/null; }; then
    if [ -n "${NDNCXX_INTEROP_IN_NIX:-}" ]; then
        echo "SKIP: nix-shell $HERE/shell.nix did not provide ndnsec and libndn-cxx"
        exit 2
    fi
    if ! command -v nix-shell >/dev/null 2>&1; then
        echo "SKIP: ndn-cxx (ndnsec, libndn-cxx) not in the environment and nix-shell missing"
        exit 2
    fi
    export NDNCXX_INTEROP_IN_NIX=1
    exec nix-shell "$HERE/shell.nix" --run "$(printf '%q ' "$HERE/check.sh" "$@")"
fi

KEYNAME="" DATA="" ANCHOR=""
while getopts "Kd:a:h" o; do
    case "$o" in
        K) KEYNAME="--key-name-locators" ;;
        d) DATA="$OPTARG" ;;
        a) ANCHOR="$OPTARG" ;;
        *) usage ;;
    esac
done
shift $((OPTIND - 1))
[ $# -ge 1 ] || usage
CERT="$1"; shift
ISSUERS=("$@")
for f in "$CERT" "${ISSUERS[@]}" ${DATA:+"$DATA"} ${ANCHOR:+"$ANCHOR"}; do
    [ -r "$f" ] || { echo "FAIL: cannot read $f"; exit 1; }
done
if [ -z "$ANCHOR" ]; then
    if [ ${#ISSUERS[@]} -gt 0 ]; then ANCHOR="${ISSUERS[-1]}"; else ANCHOR="$CERT"; fi
fi

# Build the helper when missing, older than its source, or linked against
# another ndn-cxx (a nixpkgs update moves libndn-cxx to a new store path).
BUILD_DIR="${NDNCXX_INTEROP_BUILD_DIR:-$REPO_ROOT/target/ndncxx-interop}"
TOOL="$BUILD_DIR/ndncxx-interop"
SRC="$HERE/ndncxx-interop.cpp"
LIBDIR="$(pkg-config --variable=libdir libndn-cxx)"
if [ ! -x "$TOOL" ] || [ "$SRC" -nt "$TOOL" ] || [ "$(cat "$TOOL.libdir" 2>/dev/null)" != "$LIBDIR" ]; then
    mkdir -p "$BUILD_DIR"
    # shellcheck disable=SC2046 # pkg-config output is a flag list
    if ! "${CXX:-c++}" -std=c++17 -O1 -Wall -o "$TOOL" "$SRC" \
            $(pkg-config --cflags --libs libndn-cxx) -lcrypto -Wl,-rpath,"$LIBDIR"; then
        echo "FAIL: cannot build $TOOL from $SRC"
        exit 1
    fi
    echo "$LIBDIR" >"$TOOL.libdir"
fi

# Isolated PIB/TPM so ndnsec never touches ~/.ndn.
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
export HOME="$WORK" NDN_CLIENT_PIB="pib-sqlite3:$WORK/pib" NDN_CLIENT_TPM="tpm-file:$WORK/tpm"

OUT="$WORK/out.txt"
: >"$OUT"
say() { echo "$@" | tee -a "$OUT"; }

to_b64() {  # raw TLV (starts with 0x06) -> base64; base64 input passes through
    if [ "$(od -An -tx1 -N1 "$1" | tr -d ' \n')" = "06" ]; then base64 -w0 "$1"; else tr -d '\n\r ' <"$1"; fi
}

echo "INFO: ndn-cxx $(pkg-config --modversion libndn-cxx) ($LIBDIR)"
say "### ndnsec cert-dump ($(ndnsec version 2>/dev/null))"
seen=()
for f in "$CERT" "${ISSUERS[@]}" "$ANCHOR"; do
    case " ${seen[*]-} " in *" $f "*) continue ;; esac
    seen+=("$f")
    echo "--- $f"
    if to_b64 "$f" | ndnsec cert-dump -p -f - >"$WORK/dump.txt" 2>&1; then
        cat "$WORK/dump.txt"
        say "PASS: ndnsec cert-dump -p parses $f"
    else
        cat "$WORK/dump.txt"
        say "FAIL: ndnsec cert-dump -p rejects $f"
    fi
done

say "### ndn-cxx certificate inspection"
"$TOOL" $KEYNAME inspect "${seen[@]}" | tee -a "$OUT"

CHAIN_ARGS=()
for f in "${ISSUERS[@]}"; do [ "$f" = "$ANCHOR" ] || CHAIN_ARGS+=(--cert "$f"); done

say "### certificate chain: $CERT -> anchor $ANCHOR"
"$TOOL" $KEYNAME validate --anchor "$ANCHOR" "${CHAIN_ARGS[@]}" "$CERT" | tee -a "$OUT"

if [ -n "$DATA" ]; then
    DATA_ARGS=("${CHAIN_ARGS[@]}")
    [ "$CERT" = "$ANCHOR" ] || DATA_ARGS+=(--cert "$CERT")
    say "### Data $DATA -> anchor $ANCHOR"
    "$TOOL" $KEYNAME validate --anchor "$ANCHOR" "${DATA_ARGS[@]}" "$DATA" | tee -a "$OUT"
fi

pass=$(grep -c '^PASS' "$OUT"); fail=$(grep -c '^FAIL' "$OUT"); uns=$(grep -c '^UNSUPPORTED' "$OUT")
echo "SUMMARY: $pass PASS, $fail FAIL, $uns UNSUPPORTED"
[ "$fail" -eq 0 ]
