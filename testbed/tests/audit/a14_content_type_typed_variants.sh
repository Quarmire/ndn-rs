#!/usr/bin/env bash
# Audit witness — A.14.
#
# Finding:     ContentType enum lacked `Manifest` (4) and `PrefixAnn` (5);
#              they decoded as `Other(n)` forcing every consumer to handle
#              the generic fallback for spec-defined types.
# Witness:     RUST-UNIT — `cargo test -p ndn-packet --features std --lib
#              a14_content_type_typed_manifest_and_prefix_ann`.
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

if ! cargo test -p ndn-packet --features std --lib \
        meta_info::tests::a14_content_type_typed_manifest_and_prefix_ann \
        --quiet 2>&1 | tail -5; then
    echo "FAIL: A.14 unit test"
    exit 1
fi

echo "=== A.14 RESOLVED — Manifest (4) and PrefixAnn (5) decode as typed variants ==="
