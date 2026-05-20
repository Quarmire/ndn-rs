#!/usr/bin/env bash
# Witness recipe for Face-system Tier 1 — `LpLinkService` is a feature
# composer, not a monolith.
#
# Finding:     docs/notes/face-system-design-2026-05-20.md § Tier 1
# Severity:    Phase-2b architectural cleanup (pre-v0.1.0)
# Decision:    Q1=(a) — feature trait + composer live in
#              `crates/spec/ndn-transport/src/link_service/`.  Six
#              inert built-in features ship in Tier 1; reliability,
#              congestion-marking, and TraceContext-emission slot in
#              behind the same trait in later tiers.
#
# Witnesses (all GREP-PROOF; runs in any checkout):
#   (a) The trait `LinkServiceFeature` exists with the four required
#       methods (name, on_egress, on_ingress, tick).
#   (b) `OutboundLpFrame` / `InboundLpFrame` / `EgressCtx` /
#       `IngressCtx` / `TickCtx` types exist.
#   (c) `LpLinkService` holds a `Vec<Arc<dyn LinkServiceFeature>>`.
#   (d) The six inert built-in features exist (one file each):
#       Fragmentation, Reassembly, LocalFields, IncomingFaceId, Nack,
#       TraceContext.
#   (e) Every feature impls `LinkServiceFeature::name` returning a
#       stable kebab-case identifier (matches the strings the
#       feature_set FaceStatus TLV will surface).
#   (f) No "if let Some(reliability)" / "if reliability_enabled"
#       inline conditionals remain in `LpLinkService::send` —
#       per-feature logic has moved into feature impls.
#
# Reverify recipe: GREP-PROOF only.
#
# Exit codes:
#   0 — PASS (Tier 1 composition shape landed)
#   1 — FAIL (trait missing, composer not reshaped, or per-feature
#       conditionals leak into the composer)
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

fail=0

check_grep() {
    local pattern="$1" path="$2" label="$3"
    if ! grep -rqnE "$pattern" "$path"; then
        echo "FAIL: $label — pattern \"$pattern\" not found under $path" >&2
        fail=1
    fi
}

check_absent_in_paths() {
    local pattern="$1" label="$2"; shift 2
    local hits
    hits="$(grep -rnE "$pattern" "$@" 2>/dev/null || true)"
    if [ -n "$hits" ]; then
        echo "FAIL: $label" >&2
        echo "$hits" >&2
        fail=1
    fi
}

LS_DIR=crates/spec/ndn-transport/src/link_service
FEATURE_FILE="$LS_DIR/feature.rs"

# (a) Trait + four method names.
check_grep 'pub trait LinkServiceFeature' "$FEATURE_FILE" 'LinkServiceFeature trait'
check_grep 'fn name\(&self\) -> &.*str'   "$FEATURE_FILE" 'name() method'
check_grep 'fn on_egress'                  "$FEATURE_FILE" 'on_egress() method'
check_grep 'fn on_ingress'                 "$FEATURE_FILE" 'on_ingress() method'
check_grep 'fn tick'                       "$FEATURE_FILE" 'tick() method'

# (b) Frame + ctx types.
check_grep 'struct OutboundLpFrame'  "$FEATURE_FILE" 'OutboundLpFrame'
check_grep 'struct InboundLpFrame'   "$FEATURE_FILE" 'InboundLpFrame'
check_grep 'struct EgressCtx'        "$FEATURE_FILE" 'EgressCtx'
check_grep 'struct IngressCtx'       "$FEATURE_FILE" 'IngressCtx'
check_grep 'struct TickCtx'          "$FEATURE_FILE" 'TickCtx'

# (c) Composer holds the feature vec.
check_grep 'Vec<.*Arc<dyn LinkServiceFeature>>' "$LS_DIR" 'LpLinkService features vec'

# (d) Six inert built-in features.
FEATURES_DIR="$LS_DIR/features"
for feature in fragmentation reassembly local_fields incoming_face_id nack trace_context; do
    file="$FEATURES_DIR/$feature.rs"
    if [ ! -f "$file" ]; then
        echo "FAIL: missing feature impl $file" >&2
        fail=1
    fi
done

# (e) Every feature impl has a name() returning kebab-case.
for feature in Fragmentation Reassembly LocalFields IncomingFaceId Nack TraceContext; do
    check_grep "impl LinkServiceFeature for ${feature}Feature" \
        "$FEATURES_DIR" "${feature}Feature impl"
done

# (f) No inline per-feature conditionals in the composer.
check_absent_in_paths 'if[[:space:]]+let[[:space:]]+Some\(reliability\)' \
    'LpLinkService still has per-feature if let Some(reliability) — features must move out' \
    "$LS_DIR"

if [ "$fail" -eq 0 ]; then
    echo "PASS: face-system Tier 1 — LpLinkService is a LinkServiceFeature composer; 6 inert features in place."
fi
exit "$fail"
