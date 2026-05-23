//! `/localhost/nfd/security/*` — identity, anchors, trust schema,
//! NDNCERT enrolment, YubiKey, posture (native only).

use std::sync::{Arc, RwLock};

#[cfg(feature = "yubikey-piv")]
use base64::Engine as _;

use async_trait::async_trait;
#[cfg(test)]
use bytes::Bytes;
use ndn_config::{
    ControlParameters, ControlResponse,
    control_response::status,
    nfd_command::{module, verb},
};
use ndn_engine::ForwarderEngine;
use ndn_packet::Name;
use ndn_security::{FilePib, SchemaRule};
use tokio_util::sync::CancellationToken;
use tracing::Instrument as _;

#[cfg(test)]
use crate::MgmtHandles;
use crate::MgmtResponse;
use crate::module::{MgmtContext, MgmtModule};

async fn handle_security(
    verb_name: &[u8],
    params: ControlParameters,
    pib: Option<&FilePib>,
    engine: &ForwarderEngine,
    config: &ndn_config::ForwarderConfig,
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
        v if v == verb::ANCHOR_LIST => security_anchor_list(pib),
        v if v == verb::ANCHOR_ADD => security_anchor_add(params, engine, pib),
        v if v == verb::ANCHOR_REMOVE => security_anchor_remove(params, engine),
        v if v == verb::SAFEBAG_IMPORT => security_safebag_import(params, pib),
        v if v == verb::KEY_DELETE => security_key_delete(params, pib),
        v if v == verb::CA_ENROLL => security_ca_enroll(params, pib, engine).await,
        v if v == verb::YUBIKEY_GENERATE => security_yubikey_generate(params, pib).await,
        _ => ControlResponse::error(status::NOT_FOUND, "unknown security verb"),
    }
}

fn security_identity_status(
    engine: &ForwarderEngine,
    config: &ndn_config::ForwarderConfig,
    is_ephemeral: bool,
) -> ControlResponse {
    // Prefer the configured identity name; otherwise derive from the
    // first trust-anchor in the SecurityManager.
    let identity_name: String = if let Some(id) = &config.security.identity {
        id.clone()
    } else if let Some(mgr) = engine.security() {
        mgr.trust_anchor_names()
            .first()
            .map(|n| {
                let s = n.to_string();
                if let Some(pos) = s.find("/KEY/") {
                    s[..pos].to_string()
                } else {
                    s
                }
            })
            .unwrap_or_else(|| "(none)".to_string())
    } else {
        "(none)".to_string()
    };

    let pib_path = config
        .security
        .pib_path
        .as_deref()
        .map(str::to_owned)
        .unwrap_or_else(|| dirs_or_tmp_pib().display().to_string());

    let text =
        format!("identity={identity_name} is_ephemeral={is_ephemeral} pib_path={pib_path}\n");
    ControlResponse::ok_empty(text)
}

/// Default PIB path (mirrors `default_pib_path()` in `main.rs`).
fn dirs_or_tmp_pib() -> std::path::PathBuf {
    let mut p = std::env::var("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("/tmp"));
    p.push(".ndn");
    p.push("pib");
    p
}

fn security_identity_list(pib: &FilePib) -> ControlResponse {
    let keys = match pib.list_keys() {
        Ok(k) => k,
        Err(e) => return ControlResponse::error(status::SERVER_ERROR, e.to_string()),
    };
    let mut text = format!("{} identities\n", keys.len());
    for key_name in &keys {
        let cert = pib.get_cert(key_name);
        let (has_cert, valid_until) = match cert {
            Ok(c) => {
                let exp = if c.valid_until == u64::MAX {
                    "never".to_string()
                } else {
                    format!("{}ns", c.valid_until)
                };
                (true, exp)
            }
            Err(_) => (false, "-".to_string()),
        };
        text.push_str(&format!(
            "  name={} has_cert={} valid_until={}\n",
            key_name, has_cert, valid_until,
        ));
    }
    ControlResponse::ok_empty(text)
}

fn security_identity_generate(params: ControlParameters, pib: &FilePib) -> ControlResponse {
    let name = match params.name {
        Some(n) => n,
        None => return ControlResponse::error(status::BAD_PARAMS, "Name is required"),
    };
    match pib.generate_ed25519(&name) {
        Ok(_signer) => {
            tracing::info!(target: "mgmt.security", name = %name, "security/identity-generate: generated Ed25519 key");
            let echo = ControlParameters {
                name: Some(name),
                ..Default::default()
            };
            ControlResponse::ok("OK", echo)
        }
        Err(e) => ControlResponse::error(status::SERVER_ERROR, e.to_string()),
    }
}

fn security_anchor_list(pib: &FilePib) -> ControlResponse {
    let anchors = match pib.list_anchors() {
        Ok(a) => a,
        Err(e) => return ControlResponse::error(status::SERVER_ERROR, e.to_string()),
    };
    let mut text = format!("{} anchors\n", anchors.len());
    for anchor_name in &anchors {
        text.push_str(&format!("  name={}\n", anchor_name));
    }
    ControlResponse::ok_empty(text)
}

/// Install a trust anchor at runtime.
///
/// `ControlParameters.name` — the anchor key name.
/// `ControlParameters.uri` — the cert wire bytes hex-encoded.
///
/// The handler decodes the cert, verifies its name matches the requested
/// key, and installs into both the SecurityManager's anchor set and the
/// PIB so it survives restart.
fn security_anchor_add(
    params: ControlParameters,
    engine: &ForwarderEngine,
    pib: &FilePib,
) -> ControlResponse {
    use ndn_packet::Data;
    use ndn_security::Certificate;

    let key_name = match params.name {
        Some(n) => n,
        None => {
            return ControlResponse::error(
                status::BAD_PARAMS,
                "Name is required (cert key name to install)",
            );
        }
    };
    let cert_hex = match params.uri.as_deref() {
        Some(s) if !s.is_empty() => s,
        _ => {
            return ControlResponse::error(
                status::BAD_PARAMS,
                "Uri must carry the cert wire bytes hex-encoded",
            );
        }
    };
    let cert_wire = match decode_hex(cert_hex) {
        Ok(b) => b,
        Err(e) => {
            return ControlResponse::error(status::BAD_PARAMS, format!("invalid hex: {e}"));
        }
    };
    let cert_data = match Data::decode(bytes::Bytes::from(cert_wire)) {
        Ok(d) => d,
        Err(e) => {
            return ControlResponse::error(
                status::BAD_PARAMS,
                format!("cert Data decode failed: {e:?}"),
            );
        }
    };
    let cert = match Certificate::decode(&cert_data) {
        Ok(c) => c,
        Err(e) => {
            return ControlResponse::error(
                status::BAD_PARAMS,
                format!("Certificate decode failed: {e}"),
            );
        }
    };
    // Sanity: the cert's own name must match the requested key.
    if *cert.name != key_name {
        return ControlResponse::error(
            status::BAD_PARAMS,
            format!(
                "cert name {} does not match requested key {}",
                cert.name, key_name
            ),
        );
    }

    let security = match engine.security() {
        Some(s) => s,
        None => {
            return ControlResponse::error(
                status::NOT_FOUND,
                "no SecurityManager wired (engine started without security)",
            );
        }
    };
    security.add_trust_anchor(cert.clone());
    // Persist via the PIB so the anchor survives restart. PIB write
    // failure is non-fatal; surface it as `in-memory-only` for the
    // operator.
    let pib_status = match pib.add_trust_anchor(&key_name, &cert) {
        Ok(()) => "persisted",
        Err(e) => {
            tracing::warn!(
                target: "mgmt.security",
                error = %e,
                "anchor-add: PIB write failed (anchor installed in-memory only)"
            );
            "in-memory-only"
        }
    };
    tracing::info!(
        target: "mgmt.security",
        name = %key_name,
        pib_status,
        "security/anchor-add"
    );
    let echo = ControlParameters {
        name: Some(key_name),
        uri: Some(pib_status.to_string()),
        ..Default::default()
    };
    ControlResponse::ok("OK", echo)
}

/// Remove a trust anchor at runtime. The cert stays in the cert cache
/// (still usable for chain-walk against existing certs); it is no
/// longer an implicit root of trust.
fn security_anchor_remove(params: ControlParameters, engine: &ForwarderEngine) -> ControlResponse {
    let key_name = match params.name {
        Some(n) => n,
        None => {
            return ControlResponse::error(
                status::BAD_PARAMS,
                "Name is required (anchor key name)",
            );
        }
    };
    let security = match engine.security() {
        Some(s) => s,
        None => {
            return ControlResponse::error(status::NOT_FOUND, "no SecurityManager wired");
        }
    };
    let removed = security.remove_trust_anchor(&key_name);
    tracing::info!(
        target: "mgmt.security",
        name = %key_name,
        removed,
        "security/anchor-remove"
    );
    if removed {
        let echo = ControlParameters {
            name: Some(key_name),
            ..Default::default()
        };
        ControlResponse::ok("OK", echo)
    } else {
        ControlResponse::error(status::NOT_FOUND, "anchor not in trust-anchor set")
    }
}

/// Decode a lowercase-hex string into raw bytes. Tolerates whitespace
/// and `:` / `-` separators.
fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = s
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != ':' && *c != '-')
        .collect();
    if !cleaned.len().is_multiple_of(2) {
        return Err("odd hex length".into());
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    for chunk in cleaned.as_bytes().chunks(2) {
        let hi = (chunk[0] as char)
            .to_digit(16)
            .ok_or_else(|| format!("non-hex char '{}'", chunk[0] as char))?;
        let lo = (chunk[1] as char)
            .to_digit(16)
            .ok_or_else(|| format!("non-hex char '{}'", chunk[1] as char))?;
        out.push(((hi << 4) | lo) as u8);
    }
    Ok(out)
}

/// Import an ndn-cxx-compatible SafeBag (TLV 0x80) into the PIB.
///
/// `name` — key name to install (must match the SafeBag's embedded
/// cert name; sanity-checked downstream).
/// `uri` — `<safebag_hex>:<passphrase_hex>`. Both halves are hex so the
/// `:` delimiter is unambiguous; the passphrase never appears in logs.
///
/// `FilePib::store_safebag` fails-fast on wire/decrypt/sanity errors
/// so partial PIB state is impossible.
fn security_safebag_import(params: ControlParameters, pib: &FilePib) -> ControlResponse {
    let key_name = match params.name {
        Some(n) => n,
        None => {
            return ControlResponse::error(
                status::BAD_PARAMS,
                "Name is required (key name the SafeBag carries)",
            );
        }
    };
    let uri = match params.uri.as_deref() {
        Some(s) if !s.is_empty() => s,
        _ => {
            return ControlResponse::error(
                status::BAD_PARAMS,
                "Uri must carry `<safebag_hex>:<passphrase_hex>`",
            );
        }
    };
    let (bag_hex, pw_hex) = match uri.split_once(':') {
        Some(parts) => parts,
        None => {
            return ControlResponse::error(
                status::BAD_PARAMS,
                "Uri must carry `<safebag_hex>:<passphrase_hex>`",
            );
        }
    };
    let bag_wire = match decode_hex(bag_hex) {
        Ok(b) => b,
        Err(e) => {
            return ControlResponse::error(status::BAD_PARAMS, format!("invalid SafeBag hex: {e}"));
        }
    };
    let passphrase = match decode_hex(pw_hex) {
        Ok(b) => b,
        Err(e) => {
            return ControlResponse::error(
                status::BAD_PARAMS,
                format!("invalid passphrase hex: {e}"),
            );
        }
    };
    match pib.store_safebag(&key_name, &bag_wire, &passphrase) {
        Ok(cert) => {
            tracing::info!(
                target: "mgmt.security",
                name = %key_name,
                cert_name = %cert.name,
                "security/safebag-import"
            );
            let echo = ControlParameters {
                name: Some(key_name),
                uri: Some(format!("imported cert={}", cert.name)),
                ..Default::default()
            };
            ControlResponse::ok("OK", echo)
        }
        Err(e) => {
            tracing::warn!(
                target: "mgmt.security",
                name = %key_name,
                error = %e,
                "security/safebag-import failed"
            );
            ControlResponse::error(status::BAD_PARAMS, format!("SafeBag import failed: {e}"))
        }
    }
}

fn security_key_delete(params: ControlParameters, pib: &FilePib) -> ControlResponse {
    let name = match params.name {
        Some(n) => n,
        None => return ControlResponse::error(status::BAD_PARAMS, "Name is required"),
    };
    match pib.delete_key(&name) {
        Ok(()) => {
            tracing::info!(target: "mgmt.security", name = %name, "security/key-delete");
            let echo = ControlParameters {
                name: Some(name),
                ..Default::default()
            };
            ControlResponse::ok("OK", echo)
        }
        Err(e) => ControlResponse::error(status::SERVER_ERROR, e.to_string()),
    }
}

fn security_identity_did(params: ControlParameters, pib: &FilePib) -> ControlResponse {
    let name = match params.name {
        Some(n) => n,
        None => return ControlResponse::error(status::BAD_PARAMS, "Name is required"),
    };
    match pib.list_keys() {
        Ok(keys) if keys.contains(&name) => {}
        Ok(_) => return ControlResponse::error(status::NOT_FOUND, "identity not found in PIB"),
        Err(e) => return ControlResponse::error(status::SERVER_ERROR, e.to_string()),
    }
    // did:ndn:<percent-encoded-name> per W3C DID spec.
    let encoded = name.to_string().replace('/', "%2F");
    let did = format!("did:ndn:{encoded}");
    ControlResponse::ok_empty(did)
}

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
fn security_schema_rule_add(
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
fn security_schema_rule_remove(
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
fn security_schema_list(engine: &ForwarderEngine) -> ControlResponse {
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
fn security_schema_set(params: ControlParameters, engine: &ForwarderEngine) -> ControlResponse {
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

fn security_ca_info(config: &ndn_config::ForwarderConfig) -> ControlResponse {
    let sec = &config.security;
    match &sec.ca_prefix {
        None => ControlResponse::error(
            status::NOT_FOUND,
            "no CA configured (set [security] ca_prefix in router TOML)",
        ),
        Some(prefix) => {
            let info = format!(
                "ca_prefix={}\nca_info={}\nmax_validity_days={}\nchallenges={}\n",
                prefix,
                sec.ca_info,
                sec.ca_max_validity_days,
                sec.ca_challenges.join(","),
            );
            ControlResponse::ok_empty(info)
        }
    }
}

fn security_ca_requests() -> ControlResponse {
    // CaState not yet embedded in the router process.
    ControlResponse::ok_empty("0 pending requests\n".to_string())
}

fn security_ca_token_add(params: ControlParameters) -> ControlResponse {
    let description = params.uri.unwrap_or_default();
    let mut token_bytes = [0u8; 16];
    let _ = getrandom::getrandom(&mut token_bytes);
    let token: String = token_bytes.iter().map(|b| format!("{b:02x}")).collect();
    tracing::info!(target: "mgmt.security", token = %token, description = %description, "security/ca-token-add");
    let echo = ControlParameters {
        // Token returned in `uri` (repurposed as a generic string slot).
        uri: Some(format!("token={token} description={description}")),
        ..Default::default()
    };
    ControlResponse::ok("OK", echo)
}

/// Start a background NDNCERT enrollment session.
///
/// Creates a temporary [`AppFace`] registered with the engine so that
/// NDN Interests can be expressed through the live forwarder, then runs
/// the PROBE → NEW → CHALLENGE exchange against the requested CA prefix.
/// When the CA issues a certificate it is stored in the PIB.
async fn security_ca_enroll(
    params: ControlParameters,
    pib: &FilePib,
    engine: &ForwarderEngine,
) -> ControlResponse {
    use ndn_face_local::InProcFace;

    let ca_name = match params.name {
        Some(n) => n,
        None => return ControlResponse::error(status::BAD_PARAMS, "ca_prefix (Name) is required"),
    };

    // `uri` encodes "challenge_type:challenge_param".
    let (challenge_type, challenge_param) = match params.uri.as_deref() {
        Some(s) => match s.split_once(':') {
            Some((t, p)) => (t.to_owned(), p.to_owned()),
            None => (s.to_owned(), String::new()),
        },
        None => return ControlResponse::error(status::BAD_PARAMS, "challenge type:param required"),
    };

    let identity_name = match pib.list_keys() {
        Ok(keys) => match keys.into_iter().next() {
            Some(n) => n,
            None => return ControlResponse::error(status::NOT_FOUND, "no identity keys in PIB"),
        },
        Err(e) => return ControlResponse::error(status::SERVER_ERROR, e.to_string()),
    };

    let signer: std::sync::Arc<dyn ndn_security::Signer> = match pib.get_signer(&identity_name) {
        Ok(s) => s,
        Err(e) => return ControlResponse::error(status::SERVER_ERROR, e.to_string()),
    };

    let face_id = engine.faces().alloc_id();
    // Enrollment is an `App` (the handler speaks NDNCERT to a CA).
    let (app_face, app_handle) = InProcFace::new(face_id, 32);
    let face_cancel = CancellationToken::new();
    engine.add_face(app_face, face_cancel.clone());

    let engine_clone = engine.clone();
    let pib_path = pib.root().to_owned();
    let identity_name_echo = identity_name.clone();

    tokio::spawn(
      async move {
        let result = run_enrollment(
            app_handle,
            face_id,
            &ca_name,
            &identity_name,
            signer,
            &challenge_type,
            &challenge_param,
        )
        .await;

        face_cancel.cancel();

        match result {
            Ok(cert) => {
                match ndn_security::FilePib::open(&pib_path) {
                    Ok(pib) => match pib.store_cert(&identity_name, &cert) {
                        Ok(()) => tracing::info!(
                            target: "mgmt.security",
                            name = %identity_name,
                            "ca-enroll: certificate installed"
                        ),
                        Err(e) => tracing::error!(target: "mgmt.security", error = %e, "ca-enroll: failed to store cert"),
                    },
                    Err(e) => tracing::error!(target: "mgmt.security", error = %e, "ca-enroll: failed to open PIB"),
                }
            }
            Err(e) => {
                tracing::error!(
                    target: "mgmt.security",
                    ca = %ca_name,
                    error = %e,
                    "ca-enroll: enrollment failed"
                );
            }
        }

        drop(engine_clone);
      }
      .instrument(tracing::info_span!(target: "mgmt.security", "mgmt_request", verb = "enroll")),
    );

    let echo = ControlParameters {
        name: Some(identity_name_echo),
        ..Default::default()
    };
    ControlResponse::ok("started", echo)
}

/// Run the three-step NDNCERT enrollment exchange (PROBE → NEW → CHALLENGE)
/// using a temporary AppFace that routes Interests through the live forwarder.
async fn run_enrollment(
    handle: ndn_face_local::InProcHandle,
    _face_id: ndn_transport::FaceId,
    ca_prefix: &Name,
    identity_name: &Name,
    signer: std::sync::Arc<dyn ndn_security::Signer>,
    challenge_type: &str,
    challenge_param: &str,
) -> Result<ndn_security::Certificate, String> {
    use ndn_cert::client::EnrollmentSession;
    use ndn_packet::encode::encode_interest;

    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

    // PROBE.
    let probe_name = ca_prefix.clone().append(b"CA").append(b"PROBE");
    let probe_interest = encode_interest(&probe_name, None);
    handle
        .send(probe_interest)
        .await
        .map_err(|e| format!("PROBE send: {e}"))?;

    let probe_resp = tokio::time::timeout(TIMEOUT, handle.recv())
        .await
        .map_err(|_| "PROBE timeout")?
        .ok_or("PROBE: face closed")?;

    tracing::debug!(
        target: "mgmt.security",
        bytes = probe_resp.len(),
        "ca-enroll: PROBE response received"
    );

    // NEW.
    let mut session = EnrollmentSession::new(
        identity_name.clone(),
        std::sync::Arc::clone(&signer),
        86400,
    );

    let new_body = session
        .new_request_body()
        .await
        .map_err(|e| e.to_string())?;
    let new_name = ca_prefix.clone().append(b"CA").append(b"NEW");
    let new_interest = encode_interest(&new_name, Some(&new_body));
    handle
        .send(new_interest)
        .await
        .map_err(|e| format!("NEW send: {e}"))?;

    let new_resp = tokio::time::timeout(TIMEOUT, handle.recv())
        .await
        .map_err(|_| "NEW timeout")?
        .ok_or("NEW: face closed")?;

    let new_body_content = extract_data_content(&new_resp).ok_or("NEW: malformed Data")?;
    session
        .handle_new_response(&new_body_content)
        .map_err(|e| e.to_string())?;

    // CHALLENGE.
    let mut challenge_params = serde_json::Map::new();
    challenge_params.insert(
        "code".to_owned(),
        serde_json::Value::String(challenge_param.to_owned()),
    );
    let chal_body = session
        .challenge_request_body(challenge_type, challenge_params)
        .map_err(|e| e.to_string())?;

    // CHALLENGE name includes the request-id as a binary component
    // (ndn-cert `requester-request.cpp:217`).
    let request_id_raw = session
        .request_id_bytes()
        .map(|b| b.to_vec())
        .unwrap_or_default();
    let chal_name = ca_prefix
        .clone()
        .append(b"CA")
        .append(b"CHALLENGE")
        .append(&request_id_raw);
    let chal_interest = encode_interest(&chal_name, Some(&chal_body));
    handle
        .send(chal_interest)
        .await
        .map_err(|e| format!("CHALLENGE send: {e}"))?;

    let chal_resp = tokio::time::timeout(TIMEOUT, handle.recv())
        .await
        .map_err(|_| "CHALLENGE timeout")?
        .ok_or("CHALLENGE: face closed")?;

    let chal_body_content = extract_data_content(&chal_resp).ok_or("CHALLENGE: malformed Data")?;
    session
        .handle_challenge_response(&chal_body_content)
        .map_err(|e| e.to_string())?;

    if !session.is_complete() {
        if session.needs_another_round() {
            let msg = session
                .challenge_status_message()
                .unwrap_or("another round required");
            return Err(format!("multi-round challenge not supported: {msg}"));
        }
        return Err("enrollment did not complete".to_owned());
    }

    // CERT FETCH — issued cert returned by name; fetch separately.
    let cert_name = session
        .issued_cert_name()
        .ok_or_else(|| "no issued cert name after completion".to_owned())?
        .clone();

    let cert_interest = encode_interest(&cert_name, None);
    handle
        .send(cert_interest)
        .await
        .map_err(|e| format!("cert fetch send: {e}"))?;

    let cert_resp = tokio::time::timeout(TIMEOUT, handle.recv())
        .await
        .map_err(|_| "cert fetch timeout")?
        .ok_or("cert fetch: face closed")?;

    let cert_content = extract_data_content(&cert_resp).ok_or("cert fetch: malformed Data")?;
    ndn_cert::ca::deserialize_cert(&cert_content)
        .ok_or_else(|| "could not decode issued certificate".to_owned())
}

/// Extract the Content TLV value from a Data packet (best-effort).
fn extract_data_content(data_bytes: &[u8]) -> Option<Vec<u8>> {
    use ndn_packet::Data;
    Data::decode(bytes::Bytes::copy_from_slice(data_bytes))
        .ok()
        .and_then(|d| d.content().map(|c| c.to_vec()))
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
/// When [`MgmtHandles::runtime_policy`] is `Some`, the boolean fields
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
    pub fn from_config(config: &ndn_config::ForwarderConfig) -> Self {
        Self {
            ephemeral_allowed: config.security.identity.is_none(),
            localhop_disabled: config.security.mgmt.localhop_trust_anchor_pib.is_none(),
            // Compiled-in floor for the `SignatureTime` replay window.
            replay_window_secs: 120,
            require_signed_commands: config.security.mgmt.require_signed_commands,
            validator_anchor: config.security.mgmt.trust_anchor_pib.clone(),
        }
    }
}

fn security_policy_get(
    config: &ndn_config::ForwarderConfig,
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
    config: &ndn_config::ForwarderConfig,
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

fn security_validation_stats(engine: &ForwarderEngine) -> ControlResponse {
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

async fn security_validate(params: ControlParameters, engine: &ForwarderEngine) -> ControlResponse {
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

/// Detect a PC/SC-accessible YubiKey. Returns `status_text="present"`,
/// or `NOT_FOUND` if absent or when the `yubikey-piv` feature is off.
fn security_yubikey_detect() -> ControlResponse {
    #[cfg(feature = "yubikey-piv")]
    {
        match ndn_security::yubikey::YubikeyKeyStore::open() {
            Ok(_) => ControlResponse::ok_empty("present"),
            Err(e) => ControlResponse::error(status::NOT_FOUND, format!("YubiKey not found: {e}")),
        }
    }
    #[cfg(not(feature = "yubikey-piv"))]
    {
        ControlResponse::error(
            status::NOT_FOUND,
            "yubikey-piv feature is not compiled in; rebuild ndn-fwd with --features yubikey-piv",
        )
    }
}

/// Generate a P-256 key in YubiKey PIV slot 9a, register it under
/// `params.name`, and persist a `{pib_root}/yubikey-slots.json` entry.
/// The uncompressed 65-byte public key is returned base64url-encoded
/// in the response `uri`. Requires the `yubikey-piv` cargo feature.
async fn security_yubikey_generate(params: ControlParameters, pib: &FilePib) -> ControlResponse {
    let key_name = match params.name {
        Some(n) => n,
        None => return ControlResponse::error(status::BAD_PARAMS, "missing name parameter"),
    };

    #[cfg(feature = "yubikey-piv")]
    {
        use ndn_security::yubikey::{YubikeyKeyStore, YubikeySlot};

        let store = match YubikeyKeyStore::open() {
            Ok(s) => s,
            Err(e) => {
                return ControlResponse::error(
                    status::NOT_FOUND,
                    format!("YubiKey not found: {e}"),
                );
            }
        };

        let pub_bytes = match store
            .generate_in_slot(key_name.clone(), YubikeySlot::Authentication)
            .await
        {
            Ok(b) => b,
            Err(e) => {
                return ControlResponse::error(
                    status::SERVER_ERROR,
                    format!("YubiKey generate failed: {e}"),
                );
            }
        };

        let slot_file = pib.root().join("yubikey-slots.json");
        let entry = serde_json::json!({
            "name": key_name.to_string(),
            "slot": "9a"
        });
        let mut entries: Vec<serde_json::Value> = if slot_file.exists() {
            std::fs::read_to_string(&slot_file)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        entries.retain(|e| e["name"].as_str() != Some(&key_name.to_string()));
        entries.push(entry);
        let _ = std::fs::write(
            &slot_file,
            serde_json::to_vec_pretty(&entries).unwrap_or_default(),
        );

        let pubkey_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&pub_bytes);
        tracing::info!(
            target: "mgmt.security",
            name = %key_name,
            pubkey_len = pub_bytes.len(),
            "security/yubikey-generate: P-256 key generated in PIV slot 9a"
        );
        ControlResponse::ok(
            "generated",
            ControlParameters {
                name: Some(key_name),
                uri: Some(pubkey_b64),
                ..Default::default()
            },
        )
    }
    #[cfg(not(feature = "yubikey-piv"))]
    {
        let _ = (key_name, pib);
        ControlResponse::error(
            status::NOT_FOUND,
            "yubikey-piv feature is not compiled in; rebuild ndn-fwd with --features yubikey-piv",
        )
    }
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

    fn empty_config() -> ndn_config::ForwarderConfig {
        ndn_config::ForwarderConfig::default()
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
        // lands in `pending_restart`.
        let posture = r#"{"ephemeral_allowed":true,"localhop_disabled":true,"replay_window_secs":120,"require_signed_commands":false,"validator_anchor":null}"#;
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
            pending_line.contains("require_signed_commands"),
            "expected require_signed_commands in pending_restart; got {pending_line:?}"
        );
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
            start.require_signed_commands,
            "default config has require_signed_commands=true"
        );
        let lock = Arc::new(RwLock::new(start));

        // Runtime-writable → lands in `applied`, not `pending_restart`.
        let new = r#"{"ephemeral_allowed":true,"localhop_disabled":true,"replay_window_secs":120,"require_signed_commands":false,"validator_anchor":null}"#;
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
            applied_line.contains("require_signed_commands"),
            "expected require_signed_commands in runtime_applied; got {applied_line:?}"
        );

        assert!(!lock.read().unwrap().require_signed_commands);

        let get_resp = security_policy_get(&cfg, Some(&lock));
        let parsed: MgmtAccessPolicy = serde_json::from_str(&get_resp.status_text).unwrap();
        assert!(!parsed.require_signed_commands);
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
            discovery_cfg: None,
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
