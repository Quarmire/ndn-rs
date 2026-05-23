#!/usr/bin/env bash
# Witness for EMB-13 — status/general is the spec NFD ForwarderStatus dataset.
#
# Design:      .claude/notes/embedded-ndn-modular-build-2026-05-22.md § 4
# Spec ref:    ndn-cxx encoding/tlv-nfd.hpp (NfdVersion=128 … NUnsatisfiedInterests=154);
#              mgmt/nfd/forwarder-status.cpp (field order).
# Severity:    spec-compliance + cross-impl (pre-v0.2.0)
# Witnesses:
#   (a) GREP-PROOF — shared no_std codec `ndn-mgmt-wire` defines GeneralStatus
#       and the NFD TLV codes (NfdVersion = 128).
#   (b) GREP-PROOF — native `ndn-mgmt` status/general returns a GeneralStatus
#       Dataset, not the old human-readable "faces=N …" ControlResponse text.
#   (c) GREP-PROOF — ndn-ipc client status() returns GeneralStatus; the embedded
#       forwarder encodes via the same shared codec.
#   (d) RUST-UNIT  — the codec round-trips and the embedded response decodes as
#       a spec GeneralStatus (byte-identical to native by shared construction).
#
# Reverify recipe: GREP-PROOF + RUST-UNIT. Runs in any checkout; no Docker.
#
# Exit codes: 0 PASS · 1 FAIL · 2 SKIP (cargo missing)
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

command -v cargo >/dev/null 2>&1 || { echo "SKIP: cargo not in PATH" >&2; exit 2; }

fail=0
WIRE=crates/ndn-mgmt-wire/src/lib.rs
NATIVE=crates/ndn-mgmt/src/modules/status.rs
IPC=crates/ndn-ipc/src/mgmt_client.rs
EMB=crates/ndn-embedded/src/mgmt.rs

# (a) shared codec + spec code.
grep -qE 'struct GeneralStatus' "$WIRE" || { echo "FAIL: no GeneralStatus in ndn-mgmt-wire" >&2; fail=1; }
grep -qE 'NFD_VERSION: u64 = 128' "$WIRE" || { echo "FAIL: NfdVersion code (128) missing/wrong" >&2; fail=1; }

# (b) native emits the dataset, not the text ControlResponse.
grep -qE 'MgmtResponse::Dataset\(general_status_dataset' "$NATIVE" \
    || { echo "FAIL: native status/general does not emit a GeneralStatus Dataset" >&2; fail=1; }
if grep -qE 'faces=\{n_faces\}|format!\("faces=' "$NATIVE"; then
    echo "FAIL: native status/general still emits the non-spec text format" >&2
    fail=1
fi

# (c) ipc + embedded use the shared codec.
grep -qE 'GeneralStatus' "$IPC" || { echo "FAIL: ndn-ipc status() does not use GeneralStatus" >&2; fail=1; }
grep -qE 'ndn_mgmt_wire::GeneralStatus' "$EMB" || { echo "FAIL: embedded mgmt does not use the shared codec" >&2; fail=1; }

# (d) tests.
if [ "$fail" -eq 0 ]; then
    echo "→ cargo test -p ndn-mgmt-wire && cargo test -p ndn-embedded --features mgmt --test mgmt_conformance"
    if ! cargo test --quiet -p ndn-mgmt-wire >/dev/null 2>&1 \
        || ! cargo test --quiet -p ndn-embedded --features mgmt --test mgmt_conformance >/dev/null 2>&1; then
        echo "FAIL: codec / embedded mgmt conformance tests did not pass" >&2
        fail=1
    fi
fi

[ "$fail" -eq 0 ] && echo "PASS: EMB-13 — status/general is the spec NFD GeneralStatus dataset, shared native↔embedded."
exit "$fail"
