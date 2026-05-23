#!/usr/bin/env bash
# Audit witness — E.07.
#
# Finding:     `verb::UPDATE = b"update"` was declared in
#              `nfd_command.rs:44` but the management handler's
#              `faces_*` dispatch table only routed `create`,
#              `destroy`, `list`, `counters`.  `nfdc face update`
#              against ndn-rs got a 404 "unknown faces verb".
# Witness:     GREP-PROOF — the dispatch table now routes
#              `verb::UPDATE` to a `faces_update` handler, and
#              `faces_update` is defined.  The handler returns
#              a 200 ControlResponse on a no-op (FaceId-only)
#              request and a 409 when the caller asks for a
#              runtime parameter ndn-rs does not yet honour
#              (Flags / Mask / FacePersistency / MTU), so the
#              client sees a deterministic outcome instead of
#              "unknown verb".
# Spec ref:    NFD faces/update — change Flags, BaseCongestion
#              MarkingInterval, etc. of a persistent face without
#              re-creating it.
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

LIB="crates/ndn-mgmt/src/lib.rs"

if ! grep -q 'v if v == verb::UPDATE => faces_update' "$LIB"; then
    echo "FAIL: faces dispatch does not route verb::UPDATE"
    exit 1
fi
if ! grep -q '^fn faces_update' "$LIB"; then
    echo "FAIL: faces_update handler missing"
    exit 1
fi
if ! grep -q 'status::CONFLICT' "$LIB"; then
    echo "FAIL: faces_update does not signal CONFLICT for unsupported changes"
    exit 1
fi
# Mask semantics: new = (current & !mask) | (flags & mask)
if ! grep -q '(current & !mask) | (flags & mask)' "$LIB"; then
    echo "FAIL: faces_update does not implement NFD Flags+Mask semantics"
    exit 1
fi

if ! cargo build -p ndn-mgmt --quiet 2>&1 | tail -3; then
    echo "FAIL: ndn-mgmt does not build with faces/update handler"
    exit 1
fi

echo "=== E.07 RESOLVED — faces/update dispatched (no-op 200 / 409 on changes) ==="
