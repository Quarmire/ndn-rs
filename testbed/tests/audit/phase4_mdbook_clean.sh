#!/usr/bin/env bash
# Witness — Phase 4 §4.4 mdbook integrity.
#
# Witness:   RUST-BUILD — `mdbook build` succeeds (zero broken
#            links, zero unrecognised chapter refs in SUMMARY.md).
#            `mdbook test` succeeds (every Rust code fence
#            compiles against the workspace).
#
# Dependencies: mdbook + mdbook-mermaid in $PATH. The build picks
#            up docs/wiki/book.toml.
#
# Exit codes:
#   0 — PASS
#   1 — FAIL (mdbook build or test failed)
#   2 — SKIP (mdbook not installed)
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT/docs/wiki"

for tool in mdbook; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "SKIP: $tool not in PATH" >&2
        exit 2
    fi
done

echo "→ mdbook build"
mdbook build >&2
echo "→ mdbook test"
mdbook test >&2

echo "PASS"
exit 0
