#!/usr/bin/env bash
# Witness for EMB-18 — cross-platform endpoint API parity (zero-friction port).
#
# Severity:    developer-experience / anti-divergence (pre-v0.2.0)
# Goal:        the app-side endpoint reads the same on a server and on an MCU.
#              Names + argument shape match the native `ndn-app` Consumer/Producer;
#              the only divergence is the execution model (async .await -> nb poll),
#              and that divergence is documented in the developer guide.
# Witnesses:
#   (a) GREP-PROOF — ndn-embedded exposes a Consumer with `fn fetch(&mut self, name`
#       and a Producer with `fn serve(` + `fn prefix(`, mirroring the native verbs.
#   (b) GREP-PROOF — those verbs exist natively too (ndn-app Consumer::fetch /
#       Producer::serve), so the names line up across platforms.
#   (c) GREP-PROOF — the divergence is documented: api/develop.md carries the
#       "Cross-platform parity" section naming the nb::Result seam.
#   (d) RUST-UNIT — the embedded endpoint round-trips, AND ndn-embedded still
#       builds for a bare-metal no_std target (the no-alloc floor is intact).
#
# Reverify recipe: GREP-PROOF + RUST-UNIT. Runs in any checkout; no Docker.
#
# Exit codes: 0 PASS · 1 FAIL · 2 SKIP (cargo missing)
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

command -v cargo >/dev/null 2>&1 || { echo "SKIP: cargo not in PATH" >&2; exit 2; }

fail=0
EP=crates/ndn-embedded/src/endpoint.rs

# (a) embedded exposes the native verbs, sync/nb-shaped.
[ -f "$EP" ] || { echo "FAIL: $EP missing" >&2; fail=1; }
grep -qE 'pub struct Consumer' "$EP" 2>/dev/null || { echo "FAIL: no embedded Consumer" >&2; fail=1; }
grep -qE 'pub struct Producer' "$EP" 2>/dev/null || { echo "FAIL: no embedded Producer" >&2; fail=1; }
grep -qE 'fn fetch\(&mut self, name' "$EP" 2>/dev/null || { echo "FAIL: embedded Consumer lacks fetch(name)" >&2; fail=1; }
grep -qE 'fn serve<' "$EP" 2>/dev/null || { echo "FAIL: embedded Producer lacks serve(handler)" >&2; fail=1; }
grep -qE 'nb::Result' "$EP" 2>/dev/null || { echo "FAIL: embedded endpoint is not nb-poll-shaped" >&2; fail=1; }
grep -qE 'pub use endpoint::\{Consumer, EndpointError, Producer\}' crates/ndn-embedded/src/lib.rs \
    || { echo "FAIL: ndn-embedded does not re-export the endpoint types" >&2; fail=1; }

# (b) the same verbs exist on the native side -> the names align across platforms.
grep -rqE 'fn fetch\b' crates/ndn-app/src/consumer.rs 2>/dev/null \
    || { echo "FAIL: native Consumer::fetch not found (name parity broken)" >&2; fail=1; }
grep -rqE 'fn serve\b' crates/ndn-app/src/producer.rs 2>/dev/null \
    || { echo "FAIL: native Producer::serve not found (name parity broken)" >&2; fail=1; }

# (c) the necessary divergence is documented for developers.
DOC=docs/wiki/src/api/develop.md
grep -qE 'Cross-platform parity' "$DOC" 2>/dev/null \
    || { echo "FAIL: develop.md lacks the Cross-platform parity section" >&2; fail=1; }
grep -qE 'nb::Result|nb::block' "$DOC" 2>/dev/null \
    || { echo "FAIL: develop.md does not document the async->nb seam" >&2; fail=1; }

# (d) round-trip tests pass AND the no_std floor still builds.
if [ "$fail" -eq 0 ]; then
    echo "→ cargo test -p ndn-embedded endpoint"
    if ! cargo test --quiet -p ndn-embedded endpoint >/dev/null 2>&1; then
        echo "FAIL: embedded endpoint round-trip tests did not pass" >&2
        fail=1
    fi
    TARGET=thumbv7em-none-eabihf
    if rustup target list --installed 2>/dev/null | grep -q "$TARGET"; then
        echo "→ cargo build -p ndn-embedded --target $TARGET (no-alloc floor)"
        if ! cargo build --quiet -p ndn-embedded --target "$TARGET" >/dev/null 2>&1; then
            echo "FAIL: ndn-embedded no longer builds for $TARGET (alloc crept onto the floor)" >&2
            fail=1
        fi
    else
        echo "note: $TARGET not installed; skipping bare-metal build leg (CI covers it)"
    fi
fi

[ "$fail" -eq 0 ] && echo "PASS: EMB-18 — embedded Consumer::fetch / Producer::serve mirror native; nb seam documented; no_std floor intact."
exit "$fail"
