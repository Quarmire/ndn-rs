//! `impl MgmtConfig for ForwarderConfig`.
//!
//! Gated behind the `mgmt` feature. `ndn-mgmt` (spec, the NFD management
//! protocol) defines the [`MgmtConfig`] read surface its command handlers need;
//! this crate (extension, the forwarder TOML) implements it for
//! [`ForwarderConfig`]. The dependency edge therefore runs extension → spec,
//! and consumers that only parse config (without mounting management) never
//! pull the management stack.

use crate::config::ForwarderConfig;
use ndn_mgmt::{CaInfo, MgmtConfig};

/// Key names (case-insensitive, exact match) whose values are secrets and must
/// be redacted from `config/get` (audit CFG-1). Covers CA invite tokens +
/// enrolment PINs, SMTP/TURN credentials, and the ACME DNS-provider API token
/// carried in the opaque `params` blob.
const SECRET_KEYS: &[&str] = &[
    "password",
    "token",
    "tokens",
    "pin",
    "credential",
    "username",
    "secret",
    "params",
];

/// Recursively replace any secret-keyed value with a placeholder.
fn redact_secrets(value: &mut toml::Value) {
    match value {
        toml::Value::Table(table) => {
            for (k, v) in table.iter_mut() {
                if SECRET_KEYS.contains(&k.to_ascii_lowercase().as_str()) {
                    *v = toml::Value::String("<redacted>".to_string());
                } else {
                    redact_secrets(v);
                }
            }
        }
        toml::Value::Array(arr) => {
            for v in arr.iter_mut() {
                redact_secrets(v);
            }
        }
        _ => {}
    }
}

impl MgmtConfig for ForwarderConfig {
    fn redacted_toml(&self) -> Result<String, String> {
        // Serialize to a tree, redact secret-bearing keys, then re-render — so a
        // read of the running config can never disclose issuance-authorising
        // secrets (audit CFG-1). The on-disk `to_toml_string` stays unredacted.
        let mut value = toml::Value::try_from(self).map_err(|e| e.to_string())?;
        redact_secrets(&mut value);
        toml::to_string_pretty(&value).map_err(|e| e.to_string())
    }

    fn security_identity(&self) -> Option<&str> {
        self.security.identity.as_deref()
    }

    fn pib_path(&self) -> Option<&str> {
        self.security.pib_path.as_deref()
    }

    fn require_signed_commands(&self) -> bool {
        self.security.mgmt.require_signed_commands
    }

    fn mgmt_trust_anchor_pib(&self) -> Option<&str> {
        self.security.mgmt.trust_anchor_pib.as_deref()
    }

    fn localhop_trust_anchor_pib(&self) -> Option<&str> {
        self.security.mgmt.localhop_trust_anchor_pib.as_deref()
    }

    fn ca_info(&self) -> Option<CaInfo<'_>> {
        let sec = &self.security;
        sec.ca_prefix.as_deref().map(|prefix| CaInfo {
            prefix,
            info: &sec.ca_info,
            max_validity_days: sec.ca_max_validity_days,
            challenges: &sec.ca_challenges,
        })
    }
}

#[cfg(test)]
mod cfg1_tests {
    use super::redact_secrets;

    #[test]
    fn redacts_secret_keys_recursively() {
        let mut v: toml::Value = toml::from_str(
            r#"
listen = "/run/x.sock"
[demo_ca]
tokens = ["invite-secret"]
[demo_ca.challenge]
pin = "1234"
[smtp]
username = "u@example.com"
password = "hunter2"
[[turn]]
username = "turnuser"
credential = "turnsecret"
"#,
        )
        .unwrap();
        redact_secrets(&mut v);
        let out = toml::to_string_pretty(&v).unwrap();
        for leaked in ["invite-secret", "hunter2", "1234", "turnsecret", "turnuser"] {
            assert!(!out.contains(leaked), "secret leaked: {leaked}\n{out}");
        }
        assert!(out.contains("<redacted>"), "expected redaction placeholder");
        assert!(out.contains("/run/x.sock"), "non-secret field must survive");
    }
}
