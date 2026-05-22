#!/usr/bin/env bash
# Witness for EMB-02 — native and embedded forwarders share ndn-fwd-core.
#
# Design:      .claude/notes/embedded-ndn-modular-build-2026-05-22.md § 2
# Severity:    embedded anti-divergence (pre-v0.2.0)
# Witnesses:
#   (a) GREP-PROOF — the native forwarding-table crate (ndn-store, which the
#       async engine composes) depends on ndn-fwd-core.
#   (b) GREP-PROOF — crates/extension/ndn-embedded/Cargo.toml depends on it too.
#   This is the fact that turns "two forwarders" into "two table layers over one
#   rule set." (ndn-engine inherits the rules transitively via ndn-store; a
#   direct engine-side adoption — hop-limit/PIT on the hot path — is a later,
#   benchmark-guarded step.)
#
# Reverify recipe: GREP-PROOF. Runs in any checkout; no Docker.
#
# Exit codes: 0 PASS · 1 FAIL
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

fail=0
STORE_TOML=crates/spec/ndn-store/Cargo.toml
EMBEDDED_TOML=crates/extension/ndn-embedded/Cargo.toml

for toml in "$STORE_TOML" "$EMBEDDED_TOML"; do
    if [ ! -f "$toml" ]; then
        echo "FAIL: $toml not found" >&2
        fail=1
        continue
    fi
    if ! grep -qE '^\s*ndn-fwd-core\s*=' "$toml"; then
        echo "FAIL: $toml does not depend on ndn-fwd-core" >&2
        fail=1
    fi
done

[ "$fail" -eq 0 ] && echo "PASS: EMB-02 — both ndn-engine and ndn-embedded depend on ndn-fwd-core."
exit "$fail"
