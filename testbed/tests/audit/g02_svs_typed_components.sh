#!/usr/bin/env bash
# Witness test for audit finding G.02 — `SvsNode` keys its state vector
# by `Name::to_string()` rather than canonical `Name`, so two peers
# emitting the same NodeID with different `Display` renderings (typed
# components, percent-escaping, …) end up as two separate state-vector
# entries.
#
# Finding:     testbed/EXPECTED_FAILURES.md § G.02
# Severity:    MAJOR (interop on typed-component NodeIDs)
# Spec ref:    ndn-svs `common.hpp:41` `using NodeID = ndn::Name`;
#              `version-vector.hpp:83` `std::map<NodeID, SeqNo>` —
#              keyed by component-wise canonical `Name`, not URI.
# Witnesses:   RUST-UNIT in `ndn-sync`:
#                - g02_typed_components_canonicalize_to_single_entry
#                - g02_merge_names_aggregates_equal_name_keys
#              The first asserts the legacy `String`-based `merge` /
#              `seq_for` API canonicalizes via `Name::from_str`. The
#              second exercises the new `merge_names` Name-keyed entry
#              point.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

fail=0
if cargo test -p ndn-sync --lib --quiet g02_ \
        >/tmp/g02_witness.log 2>&1; then
    echo "ok: SVS state vector keys on canonical Name"
else
    echo "FAIL: SVS state vector keys on URI string"
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo
    echo "=== G.02 RESOLVED — SVS state vector canonicalizes Name keys ==="
    exit 0
else
    echo
    echo "=== G.02 EXPECTED-FAIL — SVS keyed by stringified Name ==="
    [ -f /tmp/g02_witness.log ] && cat /tmp/g02_witness.log
    exit 1
fi
