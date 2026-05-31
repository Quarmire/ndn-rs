#!/usr/bin/env bash
# Witness for configuration-style validator behavior.
#
# The release claim is behavioral: ordered rules, no-match rejection, and
# hierarchical checking. This is not a grep proof and does not claim that
# ndn-rs parses every ndn-cxx validator.conf stanza.
#
# Exit codes: 0 PASS / 1 FAIL
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

if cargo test -p ndn-security --lib --quiet validator_config_ \
        >/tmp/validator_config_behavior.log 2>&1; then
    cat /tmp/validator_config_behavior.log
    echo
    echo "=== validator-config behavior PASS — ordered first match, no-match deny, hierarchical checker ==="
    exit 0
else
    echo "FAIL: validator-config behavior tests"
    cat /tmp/validator_config_behavior.log
    exit 1
fi
