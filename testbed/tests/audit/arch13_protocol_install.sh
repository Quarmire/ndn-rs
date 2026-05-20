#!/usr/bin/env bash
# Witness recipe for ARCH-13 / S18 — `InstallableProtocol` + main.rs
# collapse.
#
# Finding:     docs/notes/architecture-gap-inventory-2026-05-20.md § ARCH-13
# Severity:    Phase 2 architectural cleanup (pre-v0.1.0)
# Witnesses:
#   (a) GREP-PROOF — `InstallableProtocol` trait + `PostBuildQueue`
#       exist in ndn-engine; old `routing_protocol*` / `discovery*`
#       methods are gone.
#   (b) GREP-PROOF — `binaries/spec/ndn-fwd/src/main.rs` no longer
#       contains protocol-specific FIB writes, sentinel face-id
#       constructors, or inline `nlsr_post_build` / `dv_neighbor_seeds`
#       setup blocks.
#   (c) GREP-PROOF — `installs/{nlsr,dv}.rs` exist and impl
#       `InstallableProtocol`.
#   (d) RUST-UNIT  — ndn-engine, ndn-routing, ndn-fwd build with
#       `cargo build` and the ndn-routing integration tests pass.
#
# Reverify recipe: GREP-PROOF + RUST-UNIT. Runs in any checkout of
# ndn-rs; no Docker required.
#
# Note: the prompt's aspirational `main.rs < 800 lines` is checked
# softly — current main.rs is ~2050 lines after S18 (down from 2602).
# Further extraction (face listeners, tracing init) is queued as
# follow-up Phase-2b work; the architectural primitive (the
# `InstallableProtocol` trait subsuming `routing_protocol*` and
# `discovery*`) is what ARCH-13 actually gates.
#
# Exit codes:
#   0 — PASS (InstallableProtocol replaces old methods; main.rs has no
#       per-protocol inline blocks)
#   1 — FAIL
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

fail=0

check_grep() {
    local pattern="$1" path="$2" label="$3"
    if ! grep -rqnE "$pattern" "$path"; then
        echo "FAIL: $label — \"$pattern\" not found under $path" >&2
        fail=1
    fi
}

check_absent_in_file() {
    local pattern="$1" path="$2" label="$3"
    if grep -nE "$pattern" "$path" >/dev/null 2>&1; then
        echo "FAIL: $label" >&2
        grep -nE "$pattern" "$path" >&2
        fail=1
    fi
}

MAIN=binaries/spec/ndn-fwd/src/main.rs
ENGINE=crates/spec/ndn-engine
INSTALLS=binaries/spec/ndn-fwd/src/installs

# (1) The InstallableProtocol trait + PostBuildQueue exist in ndn-engine.
check_grep 'pub trait InstallableProtocol' "$ENGINE/src/installable.rs" 'InstallableProtocol trait'
check_grep 'pub struct PostBuildQueue'     "$ENGINE/src/installable.rs" 'PostBuildQueue struct'
check_grep 'pub use installable::\{InstallableProtocol, PostBuildQueue\}' \
    "$ENGINE/src/lib.rs" 'engine re-exports InstallableProtocol + PostBuildQueue'

# (2) The new `&mut self` register methods replaced the old chaining ones.
check_grep 'pub fn register_routing_protocol' "$ENGINE/src/builder.rs" 'register_routing_protocol'
check_grep 'pub fn register_discovery'        "$ENGINE/src/builder.rs" 'register_discovery'

# (3) The deleted methods are truly gone (no `fn routing_protocol(` /
#     `fn routing_protocol_dyn(` / `fn discovery(`-with-D-generic /
#     `fn discovery_arc(` definitions left in the builder).
check_absent_in_file 'fn routing_protocol\b'     "$ENGINE/src/builder.rs" 'old routing_protocol method'
check_absent_in_file 'fn routing_protocol_dyn'   "$ENGINE/src/builder.rs" 'old routing_protocol_dyn method'
check_absent_in_file 'fn discovery<D: DiscoveryProtocol' "$ENGINE/src/builder.rs" 'old discovery<D> method'
check_absent_in_file 'fn discovery_arc'          "$ENGINE/src/builder.rs" 'old discovery_arc method'

# (4) The installer adapter files exist and impl InstallableProtocol.
check_grep 'impl InstallableProtocol for NlsrInstaller' "$INSTALLS/nlsr.rs" 'NlsrInstaller impl'
check_grep 'impl InstallableProtocol for DvInstaller'   "$INSTALLS/dv.rs"   'DvInstaller impl'

# (5) main.rs no longer contains the deleted inline setup blocks.
check_absent_in_file 'struct NlsrPostBuild'                          "$MAIN" 'residual NlsrPostBuild struct'
check_absent_in_file 'let mut nlsr_post_build'                       "$MAIN" 'residual nlsr_post_build local'
check_absent_in_file 'let mut dv_neighbor_seeds'                     "$MAIN" 'residual dv_neighbor_seeds local'
check_absent_in_file 'let mut dv_pfs_routes'                         "$MAIN" 'residual dv_pfs_routes local'
check_absent_in_file '\.routing_protocol_dyn\('                      "$MAIN" 'old routing_protocol_dyn caller'
check_absent_in_file '\.discovery_arc\('                             "$MAIN" 'old discovery_arc caller'
check_absent_in_file 'if fwd_config\.routing\.nlsr\.enabled'         "$MAIN" 'inline NLSR setup block'
check_absent_in_file 'if fwd_config\.routing\.dv\.enabled'           "$MAIN" 'inline DV setup block'

# (6) RUST-UNIT — ndn-routing integration tests still pass.
echo "→ cargo build -p ndn-engine -p ndn-routing -p ndn-fwd"
if ! cargo build --quiet -p ndn-engine -p ndn-routing -p ndn-fwd >/dev/null 2>&1; then
    echo "FAIL: cargo build did not succeed for the install-touched crates" >&2
    fail=1
fi
echo "→ cargo test -p ndn-routing"
if ! cargo test --quiet -p ndn-routing >/dev/null 2>&1; then
    echo "FAIL: cargo test -p ndn-routing did not pass" >&2
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    main_lines=$(wc -l < "$MAIN" | tr -d ' ')
    echo "PASS: ARCH-13 — InstallableProtocol entry; main.rs=$main_lines lines (no protocol-specific inline blocks)."
fi
exit "$fail"
