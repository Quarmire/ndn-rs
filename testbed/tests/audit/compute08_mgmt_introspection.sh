#!/usr/bin/env bash
# Witness — C-COMPUTE-08: the read-only `/localhost/nfd/compute/list`
# introspection module reports the registered compute function table.
#
# Feature:    compute management introspection — `crates/ndn-mgmt`
#             module `compute`, backed by `ComputeService::mgmt_backend()`.
# Witnesses:
#   GREP-PROOF — the module is registered in register_builtins, the
#     `compute` module name exists, and ComputeService exposes mgmt_backend().
#   RUST-UNIT — ndn-mgmt's compute_tests (dataset encoding, 404 paths).
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

fail=0

if ! grep -q 'compute::ComputeModule' crates/ndn-mgmt/src/modules/mod.rs; then
    echo "FAIL: ComputeModule not registered in register_builtins" >&2
    fail=1
fi
if ! grep -q 'COMPUTE: &\[u8\] = b"compute"' crates/ndn-config/src/nfd_command.rs; then
    echo "FAIL: compute module name const missing in ndn-config" >&2
    fail=1
fi
if ! grep -q 'fn mgmt_backend' crates/ndn-compute/src/service.rs; then
    echo "FAIL: ComputeService::mgmt_backend() missing" >&2
    fail=1
fi

if [ "$fail" -ne 0 ]; then
    echo "=== C-COMPUTE-08 FAIL (grep-proof) ===" >&2
    exit 1
fi

if ! command -v cargo >/dev/null 2>&1; then
    echo "SKIP: cargo missing (grep-proof passed)" >&2
    exit 2
fi

if cargo test -p ndn-mgmt --lib --quiet compute_tests >/tmp/compute08_witness.log 2>&1; then
    echo "=== C-COMPUTE-08 PASS — compute/list module wired + dataset round-trips ==="
    tail -n 6 /tmp/compute08_witness.log
    exit 0
else
    echo "=== C-COMPUTE-08 FAIL — compute_tests failed ===" >&2
    cat /tmp/compute08_witness.log
    exit 1
fi
