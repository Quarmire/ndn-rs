#!/usr/bin/env bash
# Witness — reflexive forwarding TOML config ([reflexive] block seeds the
# engine's boot defaults).
#
# Finding:   docs/notes/reflexive-forwarding-engine-2026-05-21.md (mgmt surface,
#            TOML config gap)
# Witness:   RUST-UNIT in ndn-config:
#              - reflexive_config_parses_and_defaults (explicit values parse;
#                absent block falls back to enabled/256/8000)
#              - example_file_parses (the annotated example with [reflexive])
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

if cargo test -p ndn-config --lib --quiet -- \
        reflexive_config_parses_and_defaults \
        example_file_parses \
        >/tmp/rf_config_witness.log 2>&1; then
    echo "=== RF config PASS — [reflexive] TOML seeds engine defaults ==="
    exit 0
fi
echo "=== RF config FAIL ==="
cat /tmp/rf_config_witness.log
exit 1
