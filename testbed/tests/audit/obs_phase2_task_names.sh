#!/usr/bin/env bash
# GREP-PROOF witness: obs_phase2_task_names
#
# Verifies that every long-lived tokio task in ndn-rs is wrapped in a named
# tracing span so tokio-console can identify it.  Each check greps for the
# span name literal in the relevant source file.
#
# Exit 0 = all checks pass; exit 1 = one or more tasks unnamed.
#
# Strategy: GREP-PROOF over source files.
# Pass criteria: the literal span name appears in the expected source file.

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
PASS=0
FAIL=0

check() {
    local label="$1"
    local file="$REPO_ROOT/$2"
    local pattern="$3"
    if grep -qE "$pattern" "$file" 2>/dev/null; then
        echo "PASS  $label"
        PASS=$((PASS + 1))
    else
        echo "FAIL  $label  (no match for /$pattern/ in $2)"
        FAIL=$((FAIL + 1))
    fi
}

echo "=== obs_phase2_task_names — long-lived task instrumentation ==="

# engine_task — discovery tick in builder.rs
check "engine_task" \
    "crates/spec/ndn-engine/src/builder.rs" \
    '"engine_task"'

# pipeline_dispatch — main packet processing loop (spawned in dispatcher/mod.rs)
check "pipeline_dispatch" \
    "crates/spec/ndn-engine/src/dispatcher/mod.rs" \
    '"pipeline_dispatch"'

# validation_drain — async validation queue drain (spawned in dispatcher/mod.rs)
check "validation_drain" \
    "crates/spec/ndn-engine/src/dispatcher/mod.rs" \
    '"validation_drain"'

# face_write — per-face outbound send task
check "face_write (engine.rs)" \
    "crates/spec/ndn-engine/src/engine.rs" \
    '"face_write"'

# face_read — per-face inbound read task
check "face_read (engine.rs)" \
    "crates/spec/ndn-engine/src/engine.rs" \
    '"face_read"'

# face_write in dispatcher/mod.rs
check "face_write (dispatcher)" \
    "crates/spec/ndn-engine/src/dispatcher/mod.rs" \
    '"face_write"'

# face_read in dispatcher/mod.rs
check "face_read (dispatcher)" \
    "crates/spec/ndn-engine/src/dispatcher/mod.rs" \
    '"face_read"'

# expiry tasks — pit, rib, idle_face in expiry.rs
check "expiry pit" \
    "crates/spec/ndn-engine/src/expiry.rs" \
    '"pit"'

check "expiry rib" \
    "crates/spec/ndn-engine/src/expiry.rs" \
    '"rib"'

check "expiry idle_face" \
    "crates/spec/ndn-engine/src/expiry.rs" \
    '"idle_face"'

# dvr_adv — DVR stub wait task
check "dvr_adv" \
    "crates/spec/ndn-routing/src/protocols/dvr.rs" \
    '"dvr_adv"'

# nlsr_hello — Hello coordinator task
check "nlsr_hello" \
    "crates/spec/ndn-routing/src/protocols/nlsr/hello.rs" \
    '"nlsr_hello"'

# nlsr_recompute — routing recompute task
check "nlsr_recompute" \
    "crates/spec/ndn-routing/src/protocols/nlsr/protocol.rs" \
    '"nlsr_recompute"'

# nlsr_sync — NlsrSync task
check "nlsr_sync" \
    "crates/spec/ndn-routing/src/protocols/nlsr/protocol.rs" \
    '"nlsr_sync"'

# mgmt_request — per-request enrollment task
check "mgmt_request" \
    "binaries/spec/ndn-fwd/src/mgmt_ndn.rs" \
    '"mgmt_request"'

echo ""
echo "Results: $PASS passed, $FAIL failed"
if [[ $FAIL -gt 0 ]]; then
    exit 1
fi
exit 0
