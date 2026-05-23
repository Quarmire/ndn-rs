#!/usr/bin/env bash
# Witness recipe for ARCH-4 / S3 — Face = Transport + LinkService split.
#
# Finding:     docs/notes/architecture-gap-inventory-2026-05-20.md § ARCH-4
# Severity:    Phase 2 architectural cleanup (pre-v0.1.0)
# Witnesses:   `PassthroughLinkService` does not LP-encode and
#              `LpLinkService` does, keyed on `FaceKind::uses_lp_framing()`.
#              The default LinkService selector picks Passthrough for IPC
#              kinds (bare TLV) and Lp for wire kinds (incl. WS/WT/WebRTC).
#              Framing is the transport-type axis, kept separate from
#              `FaceScope` (locality), which is now per-face via
#              `resolve_scope` (a loopback remote ⇒ Local).
#
# Reverify recipe: RUST-UNIT. Runs the targeted ndn-transport
# link-service test module; no Docker, no toolchain beyond cargo.
#
# Exit codes:
#   0 — PASS (LinkService behaviours match the FaceKind::uses_lp_framing() split)
#   1 — FAIL (Passthrough/Lp behaviour or default selection regressed)
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

# Behavioural witnesses live in `crates/ndn-transport/src/link_service.rs`
# under the `tests` module — they construct a CaptureTransport mock and
# verify wire bytes:
#   - `passthrough_does_not_lp_encode`
#   - `lp_link_service_lp_encodes`
#   - `passthrough_writes_raw_lp_writes_wrapped`
#   - `lp_link_service_fragments_at_mtu`
#   - `lp_link_service_passes_through_already_lp`
#   - `default_link_service_matches_framing`
TESTS=(
    "passthrough_does_not_lp_encode"
    "lp_link_service_lp_encodes"
    "passthrough_writes_raw_lp_writes_wrapped"
    "lp_link_service_fragments_at_mtu"
    "lp_link_service_passes_through_already_lp"
    "default_link_service_matches_framing"
)

fail=0
for t in "${TESTS[@]}"; do
    echo "→ cargo test -p ndn-transport --lib link_service::tests::${t}"
    if ! cargo test --quiet -p ndn-transport --lib "link_service::tests::${t}" \
            -- --exact >/dev/null 2>&1; then
        echo "FAIL: link_service::tests::${t}" >&2
        fail=1
    fi
done

if [ "$fail" -eq 0 ]; then
    echo "PASS: ARCH-4 — LinkService split is observable; Passthrough/Lp split matches FaceKind::uses_lp_framing()."
fi
exit "$fail"
