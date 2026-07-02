//! `/localhost/nfd/security/*` — identity, anchors, trust schema,
//! NDNCERT enrolment, YubiKey, posture (native only).

mod ca;
mod identity;
mod schema;
mod validation;
mod yubikey;

use std::sync::{Arc, RwLock};

use async_trait::async_trait;
#[cfg(test)]
use bytes::Bytes;
use ndn_engine::ForwarderEngine;
use ndn_mgmt_wire::{
    ControlParameters, ControlResponse,
    control_response::status,
    nfd_command::{module, verb},
};
use ndn_security::FilePib;

#[cfg(test)]
use crate::MgmtHandles;
use crate::MgmtResponse;
use crate::module::{MgmtContext, MgmtModule};

use ca::{security_ca_enroll, security_ca_info, security_ca_requests, security_ca_token_add};
use identity::{
    security_anchor_add, security_anchor_list, security_anchor_remove, security_identity_did,
    security_identity_generate, security_identity_list, security_identity_status,
    security_key_delete, security_safebag_import,
};
use schema::{
    security_schema_list, security_schema_rule_add, security_schema_rule_remove,
    security_schema_set,
};
use validation::{security_validate, security_validation_stats};
use yubikey::{security_yubikey_detect, security_yubikey_generate};

async fn handle_security(
    verb_name: &[u8],
    params: ControlParameters,
    pib: Option<&FilePib>,
    engine: &ForwarderEngine,
    config: &dyn crate::MgmtConfig,
    is_ephemeral: bool,
    runtime_policy: Option<&Arc<RwLock<MgmtAccessPolicy>>>,
) -> ControlResponse {
    // Verbs that don't need the PIB.
    match verb_name {
        v if v == verb::CA_INFO => return security_ca_info(config),
        v if v == verb::CA_REQUESTS => return security_ca_requests(),
        v if v == verb::CA_TOKEN_ADD => return security_ca_token_add(params),
        v if v == verb::YUBIKEY_DETECT => return security_yubikey_detect(),
        v if v == verb::SCHEMA_RULE_ADD => return security_schema_rule_add(params, engine),
        v if v == verb::SCHEMA_RULE_REMOVE => return security_schema_rule_remove(params, engine),
        v if v == verb::SCHEMA_LIST => return security_schema_list(engine),
        v if v == verb::SCHEMA_SET => return security_schema_set(params, engine),
        v if v == verb::IDENTITY_STATUS => {
            return security_identity_status(engine, config, is_ephemeral);
        }
        v if v == verb::POLICY_GET => return security_policy_get(config, runtime_policy),
        v if v == verb::POLICY_SET => {
            return security_policy_set(params, config, runtime_policy);
        }
        v if v == verb::VALIDATION_STATS => return security_validation_stats(engine),
        v if v == verb::VALIDATE => return security_validate(params, engine).await,
        // Anchor listing draws from the mgmt/localhop trust PIBs (config), so
        // it works even when the forwarder has no [security] identity PIB.
        v if v == verb::ANCHOR_LIST => return security_anchor_list(pib, config),
        _ => {}
    }

    let pib = match pib {
        Some(p) => p,
        None => {
            return ControlResponse::error(
                status::NOT_FOUND,
                "security identity not configured (no [security] section in config)",
            );
        }
    };
    match verb_name {
        v if v == verb::IDENTITY_LIST => security_identity_list(pib),
        v if v == verb::IDENTITY_GENERATE => security_identity_generate(params, pib),
        v if v == verb::IDENTITY_DID => security_identity_did(params, pib),
        v if v == verb::ANCHOR_ADD => security_anchor_add(params, engine, pib),
        v if v == verb::ANCHOR_REMOVE => security_anchor_remove(params, engine),
        v if v == verb::SAFEBAG_IMPORT => security_safebag_import(params, pib),
        v if v == verb::KEY_DELETE => security_key_delete(params, pib),
        v if v == verb::CA_ENROLL => security_ca_enroll(params, pib, engine).await,
        v if v == verb::YUBIKEY_GENERATE => security_yubikey_generate(params, pib).await,
        _ => ControlResponse::error(status::NOT_FOUND, "unknown security verb"),
    }
}

// Dashboard security-first surface:
//   security/policy-get          read forwarder-internal mgmt-access policy
//   security/policy-set          edit it (signed mgmt)
//   security/validation-stats    live validator counters
//   security/validate            trust-path inspector
//
// `MgmtAccessPolicy` wire body is JSON in `ControlParameters.uri`.

/// Same shape `policy-get` returns and `policy-set` consumes.
/// Forwarder-internal config; not a substrate chain entry.
///
/// When `MgmtHandles::runtime_policy` is `Some`, the boolean fields
/// (`ephemeral_allowed`, `localhop_disabled`, `require_signed_commands`)
/// are runtime-mutable through `policy-set`. `validator_anchor` and
/// `replay_window_secs` are pinned by Validator construction /
/// compiled-in floor respectively.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct MgmtAccessPolicy {
    pub ephemeral_allowed: bool,
    pub localhop_disabled: bool,
    pub replay_window_secs: u64,
    pub require_signed_commands: bool,
    pub validator_anchor: Option<String>,
}

impl MgmtAccessPolicy {
    pub fn from_config(config: &dyn crate::MgmtConfig) -> Self {
        Self {
            ephemeral_allowed: config.security_identity().is_none(),
            localhop_disabled: config.localhop_trust_anchor_pib().is_none(),
            // Compiled-in floor for the `SignatureTime` replay window.
            replay_window_secs: 120,
            require_signed_commands: config.require_signed_commands(),
            validator_anchor: config.mgmt_trust_anchor_pib().map(str::to_owned),
        }
    }
}

fn security_policy_get(
    config: &dyn crate::MgmtConfig,
    runtime_policy: Option<&Arc<RwLock<MgmtAccessPolicy>>>,
) -> ControlResponse {
    // Live runtime policy when wired; static config snapshot otherwise.
    let posture = match runtime_policy.and_then(|lock| lock.read().ok().map(|g| g.clone())) {
        Some(p) => p,
        None => MgmtAccessPolicy::from_config(config),
    };
    match serde_json::to_string(&posture) {
        Ok(json) => ControlResponse::ok_empty(json),
        Err(e) => ControlResponse::error(status::SERVER_ERROR, format!("posture encode: {e}")),
    }
}

fn security_policy_set(
    params: ControlParameters,
    config: &dyn crate::MgmtConfig,
    runtime_policy: Option<&Arc<RwLock<MgmtAccessPolicy>>>,
) -> ControlResponse {
    let body = match params.uri.as_deref() {
        Some(s) if !s.is_empty() => s,
        _ => {
            return ControlResponse::error(
                status::BAD_PARAMS,
                "Uri must contain JSON-encoded MgmtAccessPolicy",
            );
        }
    };
    let parsed: MgmtAccessPolicy = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return ControlResponse::error(status::BAD_PARAMS, format!("invalid JSON: {e}")),
    };
    // `replay_window_secs` is a compiled-in floor.
    if parsed.replay_window_secs < 60 {
        return ControlResponse::error(
            status::BAD_PARAMS,
            "replay_window_secs is a compiled-in floor (>= 60s)",
        );
    }

    // Diff against the active reader (runtime policy if present, else
    // static config). Three booleans are runtime-flippable; flipping
    // `validator_anchor` requires a Validator rebuild and lands in
    // `pending_restart`.
    let current = match runtime_policy.and_then(|lock| lock.read().ok().map(|g| g.clone())) {
        Some(p) => p,
        None => MgmtAccessPolicy::from_config(config),
    };
    let runtime_writable = runtime_policy.is_some();

    // SEC-1: refuse to *lower* the security posture at runtime. Turning
    // `require_signed_commands` off would let subsequent commands run unsigned
    // until restart — a one-way posture-lowering ratchet recorded only by a log
    // line. Raising it (false → true) is allowed; disabling must be a deliberate
    // on-disk config change + restart.
    if current.require_signed_commands && !parsed.require_signed_commands {
        return ControlResponse::error(
            status::BAD_PARAMS,
            "require_signed_commands cannot be disabled at runtime; \
             change it in the config and restart",
        );
    }

    let mut applied = Vec::new();
    let mut pending = Vec::new();

    let mut record = |field: &'static str, changed: bool, writable: bool| {
        if !changed {
            return;
        }
        if writable {
            applied.push(field);
        } else {
            pending.push(field);
        }
    };
    record(
        "require_signed_commands",
        current.require_signed_commands != parsed.require_signed_commands,
        runtime_writable,
    );
    record(
        "localhop_disabled",
        current.localhop_disabled != parsed.localhop_disabled,
        runtime_writable,
    );
    record(
        "ephemeral_allowed",
        current.ephemeral_allowed != parsed.ephemeral_allowed,
        runtime_writable,
    );
    record(
        "validator_anchor",
        current.validator_anchor != parsed.validator_anchor,
        false,
    );

    if runtime_writable
        && !applied.is_empty()
        && let Some(lock) = runtime_policy
        && let Ok(mut guard) = lock.write()
    {
        // Only runtime-writable fields land here; `validator_anchor`
        // and `replay_window_secs` need a Validator rebuild.
        guard.require_signed_commands = parsed.require_signed_commands;
        guard.localhop_disabled = parsed.localhop_disabled;
        guard.ephemeral_allowed = parsed.ephemeral_allowed;
    }

    let join = |v: &Vec<&'static str>| -> String {
        if v.is_empty() {
            "(none)".into()
        } else {
            v.join(",")
        }
    };
    let applied_str = join(&applied);
    let pending_str = join(&pending);
    tracing::info!(
        target: "mgmt.security",
        runtime_applied = %applied_str,
        pending_restart = %pending_str,
        "security/policy-set: accepted"
    );
    let text = format!("runtime_applied={applied_str}\npending_restart={pending_str}\n");
    ControlResponse::ok_empty(text)
}

pub(crate) struct SecurityModule;

#[async_trait]
impl MgmtModule for SecurityModule {
    fn name(&self) -> &'static [u8] {
        module::SECURITY
    }

    async fn dispatch(
        &self,
        verb: &[u8],
        params: ControlParameters,
        ctx: &MgmtContext<'_>,
    ) -> MgmtResponse {
        handle_security(
            verb,
            params,
            ctx.pib,
            ctx.engine,
            ctx.config,
            ctx.security_is_ephemeral,
            ctx.runtime_policy,
        )
        .await
        .into()
    }
}
#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod security_v1_handler_tests {
    //! Direct-call tests for the security policy handlers that the
    //! wire-path witness can't reach unsigned (`policy-set` is
    //! auth-gated).
    use super::*;

    fn empty_config() -> crate::module::TestMgmtConfig {
        crate::module::TestMgmtConfig {
            require_signed_commands: true,
            ..Default::default()
        }
    }

    #[test]
    fn policy_get_returns_json_body() {
        let resp = security_policy_get(&empty_config(), None);
        assert_eq!(resp.status_code, status::OK);
        let parsed: MgmtAccessPolicy =
            serde_json::from_str(&resp.status_text).expect("policy-get body is JSON");
        assert!(parsed.require_signed_commands);
    }

    #[test]
    fn policy_set_accepts_valid_json() {
        let posture = r#"{"ephemeral_allowed":false,"localhop_disabled":true,"replay_window_secs":120,"require_signed_commands":true,"validator_anchor":"/lab/router-ca/KEY/k0"}"#;
        let resp = security_policy_set(
            ControlParameters {
                uri: Some(posture.to_string()),
                ..Default::default()
            },
            &empty_config(),
            None,
        );
        assert_eq!(resp.status_code, status::OK, "{:?}", resp.status_text);
        assert!(resp.status_text.contains("runtime_applied="));
        assert!(resp.status_text.contains("pending_restart="));
    }

    #[test]
    fn policy_set_reports_pending_restart_for_changed_booleans() {
        // No runtime mutator wired → flipping a default-true boolean
        // lands in `pending_restart`. (Uses `localhop_disabled`, not
        // `require_signed_commands`, which can no longer be down-flipped — SEC-1.)
        let posture = r#"{"ephemeral_allowed":true,"localhop_disabled":false,"replay_window_secs":120,"require_signed_commands":true,"validator_anchor":null}"#;
        let resp = security_policy_set(
            ControlParameters {
                uri: Some(posture.to_string()),
                ..Default::default()
            },
            &empty_config(),
            None,
        );
        assert_eq!(resp.status_code, status::OK);
        let pending_line = resp
            .status_text
            .lines()
            .find_map(|l| l.strip_prefix("pending_restart="))
            .expect("pending_restart line");
        assert!(
            pending_line.contains("localhop_disabled"),
            "expected localhop_disabled in pending_restart; got {pending_line:?}"
        );
    }

    #[test]
    fn policy_set_rejects_require_signed_down_flip() {
        // SEC-1: turning require_signed_commands off at runtime is a one-way
        // posture-lowering ratchet and must be rejected.
        let posture = r#"{"ephemeral_allowed":true,"localhop_disabled":true,"replay_window_secs":120,"require_signed_commands":false,"validator_anchor":null}"#;
        let resp = security_policy_set(
            ControlParameters {
                uri: Some(posture.to_string()),
                ..Default::default()
            },
            &empty_config(),
            None,
        );
        assert_eq!(resp.status_code, status::BAD_PARAMS);
        assert!(resp.status_text.contains("cannot be disabled at runtime"));
    }

    #[test]
    fn policy_set_rejects_below_floor() {
        let posture = r#"{"ephemeral_allowed":true,"localhop_disabled":true,"replay_window_secs":1,"require_signed_commands":false,"validator_anchor":null}"#;
        let resp = security_policy_set(
            ControlParameters {
                uri: Some(posture.to_string()),
                ..Default::default()
            },
            &empty_config(),
            None,
        );
        assert_eq!(resp.status_code, status::BAD_PARAMS);
        assert!(resp.status_text.contains("compiled-in floor"));
    }

    #[test]
    fn policy_set_rejects_malformed_json() {
        let resp = security_policy_set(
            ControlParameters {
                uri: Some("not json".into()),
                ..Default::default()
            },
            &empty_config(),
            None,
        );
        assert_eq!(resp.status_code, status::BAD_PARAMS);
    }

    #[test]
    fn policy_set_rejects_empty_body() {
        let resp = security_policy_set(
            ControlParameters {
                uri: Some(String::new()),
                ..Default::default()
            },
            &empty_config(),
            None,
        );
        assert_eq!(resp.status_code, status::BAD_PARAMS);
    }

    /// With `runtime_policy = Some(...)`, `policy-set` flips the
    /// writable booleans in place; the next `policy-get` reflects them.
    #[test]
    fn policy_set_with_runtime_policy_flips_booleans_in_place() {
        use std::sync::{Arc, RwLock};

        let cfg = empty_config();
        let start = MgmtAccessPolicy::from_config(&cfg);
        assert!(
            start.localhop_disabled,
            "empty config has localhop_disabled=true (no localhop anchor)"
        );
        let lock = Arc::new(RwLock::new(start));

        // Runtime-writable → lands in `applied`, not `pending_restart`. Flips
        // `localhop_disabled` (keeping require_signed_commands=true — SEC-1
        // forbids down-flipping that one).
        let new = r#"{"ephemeral_allowed":true,"localhop_disabled":false,"replay_window_secs":120,"require_signed_commands":true,"validator_anchor":null}"#;
        let set_resp = security_policy_set(
            ControlParameters {
                uri: Some(new.into()),
                ..Default::default()
            },
            &cfg,
            Some(&lock),
        );
        assert_eq!(set_resp.status_code, status::OK);
        let applied_line = set_resp
            .status_text
            .lines()
            .find_map(|l| l.strip_prefix("runtime_applied="))
            .expect("runtime_applied line");
        assert!(
            applied_line.contains("localhop_disabled"),
            "expected localhop_disabled in runtime_applied; got {applied_line:?}"
        );

        assert!(!lock.read().unwrap().localhop_disabled);

        let get_resp = security_policy_get(&cfg, Some(&lock));
        let parsed: MgmtAccessPolicy = serde_json::from_str(&get_resp.status_text).unwrap();
        assert!(!parsed.localhop_disabled);
    }

    /// `effective_require_signed_commands` reads from `runtime_policy`
    /// when present, else the static field.
    #[test]
    fn effective_require_signed_commands_prefers_runtime_policy() {
        use std::sync::{Arc, RwLock};

        let lock = Arc::new(RwLock::new(MgmtAccessPolicy {
            require_signed_commands: false,
            ..Default::default()
        }));

        let handles_runtime = MgmtHandles {
            extra_modules: Vec::new(),
            face_provisioners: Vec::new(),
            control_surfaces: Vec::new(),
            security_is_ephemeral: true,
            command_validator: None,
            localhop_command_validator: None,
            require_signed_commands: true,
            command_replay_cache: None,
            command_response_signer: None,
            log_inspector: None,
            coding_handler: None,
            rate_limit_handler: None,
            compute_handler: None,
            webtransport_status_handler: None,
            ble_handler: None,
            approval_handler: None,
            runtime_policy: Some(lock),
        };
        assert!(!handles_runtime.effective_require_signed_commands());

        let handles_static = MgmtHandles {
            extra_modules: Vec::new(),
            face_provisioners: Vec::new(),
            control_surfaces: Vec::new(),
            runtime_policy: None,
            ..handles_runtime
        };
        assert!(handles_static.effective_require_signed_commands());
    }

    /// Writing back the body `policy-get` returned must succeed
    /// (stable field set).
    #[test]
    fn policy_get_to_policy_set_round_trips() {
        let cfg = empty_config();
        let get_resp = security_policy_get(&cfg, None);
        assert_eq!(get_resp.status_code, status::OK);
        let set_resp = security_policy_set(
            ControlParameters {
                uri: Some(get_resp.status_text),
                ..Default::default()
            },
            &cfg,
            None,
        );
        assert_eq!(set_resp.status_code, status::OK);
    }
}

/// Wire-shape unit tests for `security_safebag_import`. Bypasses the
/// signed-command gate by calling the handler directly with a temp PIB.
#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod safebag_import_tests {
    use super::*;
    use ndn_packet::{Name, NameComponent};

    fn pib() -> (tempfile::TempDir, FilePib) {
        let dir = tempfile::tempdir().unwrap();
        let pib = FilePib::new(dir.path()).unwrap();
        (dir, pib)
    }

    fn key_name(s: &str) -> Name {
        Name::from_components([NameComponent::generic(Bytes::copy_from_slice(s.as_bytes()))])
    }

    #[test]
    fn anchor_list_merges_engine_and_mgmt_sources() {
        use ndn_security::Certificate;
        use std::sync::Arc;

        let mk = |n: &str| {
            let name: Name = n.parse().unwrap();
            Certificate {
                name: Arc::new(name),
                public_key: Bytes::from_static(&[1u8; 32]),
                valid_from: 0,
                valid_until: u64::MAX,
                issuer: None,
                signed_region: None,
                sig_value: None,
                sig_type: ndn_packet::SignatureType::SignatureEd25519,
            }
        };

        let (_engine_dir, engine_pib) = pib();
        let en: Name = "/lab/engine/KEY/k0/self/v=0".parse().unwrap();
        engine_pib
            .add_trust_anchor(&en, &mk("/lab/engine/KEY/k0/self/v=0"))
            .unwrap();

        let (mgmt_dir, mgmt_pib) = pib();
        let mn: Name = "/op/alice/KEY/k0/self/v=0".parse().unwrap();
        mgmt_pib
            .add_trust_anchor(&mn, &mk("/op/alice/KEY/k0/self/v=0"))
            .unwrap();

        let config = crate::module::TestMgmtConfig {
            mgmt_trust_anchor_pib: Some(mgmt_dir.path().to_str().unwrap().to_string()),
            ..Default::default()
        };

        let cr = security_anchor_list(Some(&engine_pib), &config);
        assert!(
            cr.status_text
                .contains("name=/lab/engine/KEY/k0/self/v=0 source=engine"),
            "{}",
            cr.status_text
        );
        assert!(
            cr.status_text
                .contains("name=/op/alice/KEY/k0/self/v=0 source=mgmt"),
            "{}",
            cr.status_text
        );

        // Works with no engine identity PIB (forwarder with only
        // [security.mgmt]) — the mgmt anchor still surfaces.
        let cr_no_pib = security_anchor_list(None, &config);
        assert!(
            cr_no_pib
                .status_text
                .contains("name=/op/alice/KEY/k0/self/v=0 source=mgmt"),
            "{}",
            cr_no_pib.status_text
        );
    }

    #[test]
    fn requires_name() {
        let (_dir, pib) = pib();
        let cp = ControlParameters {
            uri: Some("aa:bb".to_string()),
            ..Default::default()
        };
        let cr = security_safebag_import(cp, &pib);
        assert_eq!(cr.status_code, status::BAD_PARAMS);
        assert!(cr.status_text.to_lowercase().contains("name"));
    }

    #[test]
    fn requires_uri() {
        let (_dir, pib) = pib();
        let cp = ControlParameters {
            name: Some(key_name("alice")),
            ..Default::default()
        };
        let cr = security_safebag_import(cp, &pib);
        assert_eq!(cr.status_code, status::BAD_PARAMS);
    }

    #[test]
    fn requires_delimiter() {
        let (_dir, pib) = pib();
        let cp = ControlParameters {
            name: Some(key_name("alice")),
            uri: Some("just-hex-no-colon".to_string()),
            ..Default::default()
        };
        let cr = security_safebag_import(cp, &pib);
        assert_eq!(cr.status_code, status::BAD_PARAMS);
        assert!(cr.status_text.contains(':'));
    }

    #[test]
    fn rejects_invalid_safebag_hex() {
        let (_dir, pib) = pib();
        let cp = ControlParameters {
            name: Some(key_name("alice")),
            uri: Some("ZZ:aa".to_string()),
            ..Default::default()
        };
        let cr = security_safebag_import(cp, &pib);
        assert_eq!(cr.status_code, status::BAD_PARAMS);
        assert!(cr.status_text.to_lowercase().contains("safebag"));
    }

    #[test]
    fn rejects_invalid_passphrase_hex() {
        let (_dir, pib) = pib();
        let cp = ControlParameters {
            name: Some(key_name("alice")),
            uri: Some("aa:ZZ".to_string()),
            ..Default::default()
        };
        let cr = security_safebag_import(cp, &pib);
        assert_eq!(cr.status_code, status::BAD_PARAMS);
        assert!(cr.status_text.to_lowercase().contains("passphrase"));
    }

    #[test]
    fn rejects_garbage_safebag_bytes_and_leaves_no_partial_state() {
        let (_dir, pib) = pib();
        let name = key_name("alice");
        let cp = ControlParameters {
            name: Some(name.clone()),
            uri: Some("deadbeef:70617373".to_string()),
            ..Default::default()
        };
        let cr = security_safebag_import(cp, &pib);
        assert_eq!(cr.status_code, status::BAD_PARAMS);
        assert!(pib.get_signer(&name).is_err());
    }
}
