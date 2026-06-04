#!/usr/bin/env bash
# Witness — wiki API truth (guards against doc-rot back to fictional API).
#
# Two complementary guards:
#   (1) FICTION DENYLIST — fail if any API symbol that does NOT exist in the
#       public API reappears in a wiki code block. Seeded from the 2026-06-03
#       accuracy pass (see .claude/notes/wiki/api-accuracy-audit-2026-06-03.md).
#       Whenever you delete a fiction from the wiki, add it here so it cannot
#       silently return.
#   (2) COMPILED ANCHORS — the example crates + the prelude doctest that
#       exercise the REAL APIs the wiki mirrors must build. If a documented
#       trait/signature changes, these break in CI, flagging the drift.
#
# Note: the wiki's own code fences are ```rust,ignore (they `use` extension
# crates outside the `ndn` prelude, so `mdbook test` can't compile them).
# Compile-coverage therefore comes from the anchor crates below, which DO
# compile against the real API — keep each documented surface anchored by one.
#
# Reverify:   bash testbed/tests/audit/phase4_wiki_api_truth.sh
# Exit codes: 0 PASS · 1 FAIL · 2 SKIP (cargo missing)
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
WIKI="docs/wiki/src"

# (1) Symbols verified NOT to exist in the public API. One alternation per line.
FICTIONS='KeyChain::open_default'
FICTIONS+='|KeyChain::create_identity|KeyChain::open_memory|KeyChain::open_at'
FICTIONS+='|\.self_signed_cert\(|\.default_key\(|keychain\.import_cert|keychain\.issue_cert'
FICTIONS+='|SigningInfo::by_identity|SigningInfo::by_key|SigningInfo::by_cert|SigningInfo::sha256_digest'
FICTIONS+='|\bIdbPib\b|\bMemPib\b'
FICTIONS+='|Responder::connect|SubscriberConfig::new'
FICTIONS+='|Producer::connect\([^)]*keychain'
FICTIONS+='|\.fib_lookup\(|\.random_nexthop\(|ctx\.send_interest\('
FICTIONS+='|pub trait FaceListener|: FaceListener'
FICTIONS+='|TrustVerdict|\.with_validation\('
FICTIONS+='|HierarchicalPolicy::anchor|\.allow_for_prefix\(|LvsTrust::from_schema|ChainedPolicy::new\(\)\.then'
FICTIONS+='|ndn_security::TrustContext\b'
FICTIONS+='|\.pit\(\)\.iter\(|\.fib\(\)\.iter\(|InProcFace::pair_with'

# Exclude truthful prose that names a fiction to say it does NOT exist.
hits=$(grep -rnE "$FICTIONS" "$WIKI" 2>/dev/null | grep -vEi 'not exist|no general|removed|fiction|deprecated' || true)
if [ -n "$hits" ]; then
  echo "FAIL: fictional API symbol(s) reappeared in the wiki:" >&2
  echo "$hits" >&2
  echo "These do not exist in the public API. See" >&2
  echo ".claude/notes/wiki/api-accuracy-audit-2026-06-03.md for the real equivalents." >&2
  exit 1
fi
echo "→ fiction denylist: clean"

# (2) Compiled anchors for the real APIs the wiki mirrors.
if ! command -v cargo >/dev/null 2>&1; then
  echo "SKIP: cargo not in PATH (denylist passed)" >&2
  exit 2
fi
echo "→ building wiki anchor examples (app + producer/consumer + strategy)"
cargo build -q \
  -p example-secure-fetch \
  -p example-strategy-custom \
  -p example-strategy-composed \
  -p example-context-enricher >&2
echo "→ prelude doctest + secure-fetch witnesses (app-author golden path)"
cargo test -q -p ndn-rs-prelude --doc >&2
cargo test -q -p ndn-app --test secure_fetch >&2

echo "PASS"
exit 0
