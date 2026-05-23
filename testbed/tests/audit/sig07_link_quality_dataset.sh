#!/usr/bin/env bash
# Witness for SIG-07 — read-only faces/link-quality observability dataset.
#
# Severity:    cross-layer observability + spec/docs (pre-v0.2.0)
# Design:      .claude/notes/signals/cross-layer-signals-design-2026-05-23.md (step 8)
# Witnesses:
#   (a) GREP-PROOF — the `link-quality` verb is defined (ndn-config) and is a
#       PUBLIC read dataset (auth allowlist), and faces dispatch serves it.
#   (b) GREP-PROOF — it is documented as ndn-rs-local (NOT an NFD dataset), and
#       the signals spec + strategy guide exist.
#   (c) RUST-UNIT  — the dataset TLV encoder round-trips (encode -> decode), and
#       ndn-mgmt builds.
#
# Reverify recipe: GREP-PROOF + RUST-UNIT. Runs in any checkout; no Docker.
#
# Exit codes: 0 PASS · 1 FAIL · 2 SKIP (cargo missing)
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

command -v cargo >/dev/null 2>&1 || { echo "SKIP: cargo not in PATH" >&2; exit 2; }

fail=0

# (a) verb + public-read gate + dispatch.
grep -qE 'LINK_QUALITY: &\[u8\] = b"link-quality"' crates/ndn-config/src/nfd_command.rs \
    || { echo "FAIL: link-quality verb not defined" >&2; fail=1; }
grep -qE 'verb == v::LINK_QUALITY' crates/ndn-mgmt/src/auth.rs \
    || { echo "FAIL: link-quality is not a public read dataset" >&2; fail=1; }
grep -qE 'verb::LINK_QUALITY' crates/ndn-mgmt/src/modules/faces.rs \
    || { echo "FAIL: faces dispatch does not serve link-quality" >&2; fail=1; }

# (b) documented as ndn-rs-local; spec + guide present.
grep -qiE 'ndn-rs-local|NOT an NFD' crates/ndn-mgmt/src/modules/faces.rs \
    || { echo "FAIL: link-quality dataset not documented as ndn-rs-local" >&2; fail=1; }
[ -f docs/signals.md ] || { echo "FAIL: docs/signals.md (spec) missing" >&2; fail=1; }
grep -qiE 'Cross-layer signals' docs/wiki/src/guides/writing-a-strategy.md \
    || { echo "FAIL: strategy guide lacks a cross-layer signals section" >&2; fail=1; }

# (c) encoder round-trip + build.
if [ "$fail" -eq 0 ]; then
    echo "→ cargo test -p ndn-mgmt link_quality && cargo build -p ndn-mgmt"
    if ! cargo test --quiet -p ndn-mgmt link_quality >/dev/null 2>&1 \
        || ! cargo build --quiet -p ndn-mgmt >/dev/null 2>&1; then
        echo "FAIL: link-quality dataset test / mgmt build did not pass" >&2
        fail=1
    fi
fi

[ "$fail" -eq 0 ] && echo "PASS: SIG-07 — public read-only faces/link-quality dataset (ndn-rs-local); spec + guide present."
exit "$fail"
