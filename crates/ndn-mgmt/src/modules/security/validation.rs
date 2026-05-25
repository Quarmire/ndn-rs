//! `security/{validation-stats, validate}` — validator counters and the
//! trust-path inspector backed by `Validator::trace`.

use std::sync::Arc;

use ndn_config::{ControlParameters, ControlResponse, control_response::status};
use ndn_engine::ForwarderEngine;

pub(super) fn security_validation_stats(engine: &ForwarderEngine) -> ControlResponse {
    // Monotonic totals + probe timestamp; the dashboard computes
    // per-second deltas across two consecutive polls.
    // `validator_present` reflects whether SecurityManager (and an
    // anchor set + trust schema) is installed.
    let validator_present = engine.security().is_some();
    let (verified_total, rejected_total) =
        engine.validator().map(|v| v.counters()).unwrap_or((0, 0));
    let probe_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    // Legacy `*_per_sec=0` lines kept for older dashboards.
    let text = format!(
        "validator_present={validator_present}\n\
         verified_per_sec=0\n\
         rejected_per_sec=0\n\
         verified_total={verified_total}\n\
         rejected_total={rejected_total}\n\
         probe_unix_ns={probe_ns}\n"
    );
    ControlResponse::ok_empty(text)
}

pub(super) async fn security_validate(
    params: ControlParameters,
    engine: &ForwarderEngine,
) -> ControlResponse {
    // `TrustValidationResult` portable shape (JSON), backed by
    // `Validator::trace`.
    use ndn_security::validator::TraceFailure;
    let target_name = match params.name {
        Some(n) => n,
        None => {
            return ControlResponse::error(
                status::BAD_PARAMS,
                "Name is required (cert Name to trace)",
            );
        }
    };
    let target_str = target_name.to_string();

    // `validate` returns 404 when no trust anchors are wired.
    if engine.security().is_none() {
        return ControlResponse::error(
            status::NOT_FOUND,
            "no SecurityManager wired (engine started without trust anchors)",
        );
    }
    let validator = match engine.validator() {
        Some(v) => v,
        None => {
            return ControlResponse::error(
                status::NOT_FOUND,
                "no Validator wired (engine started without trust anchors)",
            );
        }
    };
    let trace = validator.trace(&target_name).await;

    let (verdict_json, failure_diagnosis) = match &trace.failure {
        None => (serde_json::json!("Valid"), serde_json::Value::Null),
        Some(failure) => {
            let (kind, hint, failed_at) = match failure {
                TraceFailure::CertNotFound { name } => (
                    "CertNotFound",
                    "intermediate cert isn't cached; install it or wait for the cert fetcher to resolve",
                    name.to_string(),
                ),
                TraceFailure::NoKeyLocator { name } => (
                    "NoKeyLocator",
                    "cert in the chain has no KeyLocator-name; can't continue the walk",
                    name.to_string(),
                ),
                TraceFailure::AnchorNotTrusted { name } => (
                    "AnchorNotTrusted",
                    "chain terminates at a self-signed cert that isn't in the trust-anchor set; either add the anchor or remove the cert",
                    name.to_string(),
                ),
                TraceFailure::ChainTooDeep { limit } => (
                    "ChainTooDeep",
                    "chain exceeds the validator's hop limit; likely a cycle or a deliberately deep chain",
                    format!("limit={limit}"),
                ),
            };
            (
                serde_json::json!({
                    "Invalid": { "failed_at": failed_at, "reason": hint }
                }),
                serde_json::json!({ "kind": kind, "hint": hint }),
            )
        }
    };

    let chain_json: Vec<serde_json::Value> = trace
        .steps
        .iter()
        .map(|s| {
            serde_json::json!({
                "name": s.name.to_string(),
                "signed_by": s.signed_by.to_string(),
            })
        })
        .collect();
    let rules_json: Vec<serde_json::Value> = trace
        .rules_applied
        .iter()
        .map(|r| {
            serde_json::json!({
                "data_pattern": r.data_pattern,
                "key_pattern": r.key_pattern,
                "matches": r.matches,
            })
        })
        .collect();

    // Challenge attestations embedded in the target cert (NDNCERT
    // AdditionalDescription), if it's cached and carries any. Empty for
    // certs issued without `emit_attestations`.
    let challenge_attestations = match engine.security() {
        Some(mgr) => mgr
            .cert_cache()
            .get(&Arc::new(target_name.clone()))
            .and_then(|cert| ndn_cert::AttestationSet::from_cert(&cert))
            .map(|set| project_attestations(&set))
            .unwrap_or_default(),
        None => Vec::new(),
    };

    let result = serde_json::json!({
        "verdict": verdict_json,
        "chain": chain_json,
        "schema_rules_applied": rules_json,
        "failure_diagnosis": failure_diagnosis,
        "challenge_attestations": challenge_attestations,
        "target": target_str,
    });
    match serde_json::to_string(&result) {
        Ok(s) => ControlResponse::ok_empty(s),
        Err(e) => ControlResponse::error(status::SERVER_ERROR, format!("encode: {e}")),
    }
}

/// Project an [`AttestationSet`](ndn_cert::AttestationSet) into the
/// `challenge_attestations` JSON the dashboard's `TrustValidationResult`
/// expects: one object per leaf with `kind` + a rendered `detail`, plus the
/// structured fields for richer renderers.
fn project_attestations(set: &ndn_cert::AttestationSet) -> Vec<serde_json::Value> {
    let combinator = format!("{:?}", set.combinator);
    set.leaves
        .iter()
        .map(|leaf| {
            let mut detail_parts: Vec<String> = Vec::new();
            if leaf.performed_at != 0 {
                detail_parts.push(format!("at {}", leaf.performed_at));
            }
            for (k, v) in &leaf.evidence {
                detail_parts.push(format!("{k}={}", json_scalar(v)));
            }
            serde_json::json!({
                "kind": leaf.kind,
                "detail": detail_parts.join(" · "),
                "performed_at": leaf.performed_at,
                "combinator": combinator,
                "evidence": leaf.evidence,
            })
        })
        .collect()
}

/// Render a JSON value compactly for the `detail` summary string,
/// unquoting bare strings.
fn json_scalar(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}
