#!/usr/bin/env bash
# Witness recipe for ARCH-1 / S2 — NLSR migration off private faces.
#
# Finding:     docs/notes/architecture-gap-inventory-2026-05-20.md § ARCH-1
# Severity:    Phase 2 architectural cleanup (pre-v0.1.0)
# Witnesses:   the NLSR protocol body + ndn-fwd wiring contain no
#              `ErasedFace`, `CallbackFace`, or `hello_face`/`sync_face`
#              references — all inbound/outbound traffic flows through
#              the ndn-app `Consumer`/`Producer` surface.
#
# Reverify recipe: GREP-PROOF. Runs in any checkout of ndn-rs; no
# Docker, no toolchain required.
#
# Exit codes:
#   0 — PASS (audit clean)
#   1 — FAIL (one or more forbidden patterns present)
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

NLSR_PROTOCOL=crates/spec/ndn-routing/src/protocols/nlsr/protocol.rs
NLSR_HELLO=crates/spec/ndn-routing/src/protocols/nlsr/hello.rs
NLSR_SYNC=crates/spec/ndn-routing/src/protocols/nlsr/sync.rs
FWD_MAIN=binaries/spec/ndn-fwd/src/main.rs

fail=0

check_absent() {
    local pattern="$1" file="$2" label="$3"
    if grep -nE "$pattern" "$file" >/dev/null 2>&1; then
        echo "FAIL: $label still present in $file:" >&2
        grep -nE "$pattern" "$file" >&2
        fail=1
    fi
}

# (1) NLSR protocol body must not name `ErasedFace`, `hello_face`,
#     `sync_face`, or `CallbackFace`.
for f in "$NLSR_PROTOCOL" "$NLSR_HELLO" "$NLSR_SYNC"; do
    check_absent '\bErasedFace\b'   "$f" "ErasedFace reference"
    check_absent '\bhello_face\b'   "$f" "hello_face field/use"
    check_absent '\bsync_face\b'    "$f" "sync_face field/use"
    check_absent 'CallbackFace'     "$f" "CallbackFace usage"
done

# (2) ndn-fwd NLSR wiring must not construct CallbackFaces.
#     `CallbackFace::new(` is the canonical constructor; the DV wiring
#     does not use it, so the only place this would appear is the old
#     NLSR responder block this prompt deletes.
check_absent 'CallbackFace::new'    "$FWD_MAIN" "CallbackFace::new in ndn-fwd"

# (3) The NLSR wiring must use `NlsrProtocol::with_io` (the engine-IO
#     constructor) — `::new` alone signals the protocol is in stub mode
#     and won't exchange traffic.
if ! grep -nE 'NlsrProtocol::with_io' "$FWD_MAIN" >/dev/null 2>&1; then
    echo "FAIL: ndn-fwd does not call NlsrProtocol::with_io — NLSR cannot send traffic without IO" >&2
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "PASS: ARCH-1 — NLSR uses ndn-app Consumer/Producer; no private faces."
fi
exit "$fail"
