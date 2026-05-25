//! `security/schema-*` — trust-schema rule management against the
//! engine's validator.

use ndn_config::{ControlParameters, ControlResponse, control_response::status};
use ndn_engine::ForwarderEngine;
use ndn_security::SchemaRule;

/// Get the validator from the engine or return a 404 error.
macro_rules! require_validator {
    ($engine:expr) => {
        match $engine.validator() {
            Some(v) => v,
            None => {
                return ControlResponse::error(
                    status::NOT_FOUND,
                    "validation is disabled; set [security] profile = \"default\" or \
                     \"accept-signed\" to enable trust schema management",
                );
            }
        }
    };
}

/// `security/schema-rule-add` — append a rule to the active trust schema.
///
/// ControlParameters.uri must contain a rule in the form:
/// `"<data_pattern> => <key_pattern>"`
///
/// Example: `/sensor/<node>/<type> => /sensor/<node>/KEY/<id>`
pub(super) fn security_schema_rule_add(
    params: ControlParameters,
    engine: &ForwarderEngine,
) -> ControlResponse {
    let rule_text = match params.uri.as_deref() {
        Some(s) if !s.is_empty() => s.to_owned(),
        _ => {
            return ControlResponse::error(
                status::BAD_PARAMS,
                "Uri is required: \"<data_pattern> => <key_pattern>\"",
            );
        }
    };

    let rule = match SchemaRule::parse(&rule_text) {
        Ok(r) => r,
        Err(e) => {
            return ControlResponse::error(status::BAD_PARAMS, format!("invalid rule: {e}"));
        }
    };

    let validator = require_validator!(engine);
    let rule_str = rule.to_string();
    validator.add_schema_rule(rule);
    tracing::info!(target: "mgmt.security", rule = %rule_str, "security/schema-rule-add");
    ControlResponse::ok_empty(format!("added rule: {rule_str}"))
}

/// `security/schema-rule-remove` — remove a rule by index.
///
/// ControlParameters.count must contain the 0-based rule index from `schema-list`.
pub(super) fn security_schema_rule_remove(
    params: ControlParameters,
    engine: &ForwarderEngine,
) -> ControlResponse {
    let idx = match params.count {
        Some(i) => i as usize,
        None => {
            return ControlResponse::error(
                status::BAD_PARAMS,
                "Count is required: 0-based rule index from schema-list",
            );
        }
    };

    let validator = require_validator!(engine);
    match validator.remove_schema_rule(idx) {
        Some(rule) => {
            let rule_str = rule.to_string();
            tracing::info!(target: "mgmt.security", index = idx, rule = %rule_str, "security/schema-rule-remove");
            ControlResponse::ok_empty(format!("removed rule[{idx}]: {rule_str}"))
        }
        None => ControlResponse::error(status::NOT_FOUND, format!("rule index {idx} out of range")),
    }
}

/// `security/schema-list` — list all active trust schema rules.
pub(super) fn security_schema_list(engine: &ForwarderEngine) -> ControlResponse {
    let validator = require_validator!(engine);
    let rules = validator.schema_rules_text();
    let mut text = format!("{} rule(s)\n", rules.len());
    for (i, (data_pat, key_pat)) in rules.iter().enumerate() {
        text.push_str(&format!("  [{i}] {data_pat} => {key_pat}\n"));
    }
    ControlResponse::ok_empty(text)
}

/// `security/schema-set` — replace the entire trust schema.
///
/// ControlParameters.uri must contain newline-separated rules, each in the form:
/// `"<data_pattern> => <key_pattern>"`
///
/// An empty uri clears all rules (schema rejects everything).
pub(super) fn security_schema_set(
    params: ControlParameters,
    engine: &ForwarderEngine,
) -> ControlResponse {
    let text = params.uri.as_deref().unwrap_or("").trim().to_owned();

    let mut new_schema = ndn_security::TrustSchema::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match SchemaRule::parse(line) {
            Ok(rule) => new_schema.add_rule(rule),
            Err(e) => {
                return ControlResponse::error(
                    status::BAD_PARAMS,
                    format!("invalid rule {line:?}: {e}"),
                );
            }
        }
    }

    let validator = require_validator!(engine);
    let rule_count = new_schema.rules().len();
    validator.set_schema(new_schema);
    tracing::info!(target: "mgmt.security", rules = rule_count, "security/schema-set");
    ControlResponse::ok_empty(format!("schema replaced with {rule_count} rule(s)"))
}
