//! `security/{identity-*, anchor-*, safebag-import, key-delete}` —
//! PIB-backed identity, trust-anchor, and SafeBag operations.

use base64::Engine as _;

use ndn_config::{ControlParameters, ControlResponse, control_response::status};
use ndn_engine::ForwarderEngine;
use ndn_security::FilePib;

pub(super) fn security_identity_status(
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

pub(super) fn security_identity_list(pib: &FilePib) -> ControlResponse {
    let keys = match pib.list_keys() {
        Ok(k) => k,
        Err(e) => return ControlResponse::error(status::SERVER_ERROR, e.to_string()),
    };
    let mut text = format!("{} identities\n", keys.len());
    for key_name in &keys {
        let cert = pib.get_cert(key_name);
        let (has_cert, valid_until, public_key_b64) = match cert {
            Ok(c) => {
                let exp = if c.valid_until == u64::MAX {
                    "never".to_string()
                } else {
                    format!("{}ns", c.valid_until)
                };
                let pk = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&c.public_key);
                (true, exp, pk)
            }
            Err(_) => (false, "-".to_string(), "-".to_string()),
        };
        text.push_str(&format!(
            "  name={} has_cert={} valid_until={} public_key={}\n",
            key_name, has_cert, valid_until, public_key_b64,
        ));
    }
    ControlResponse::ok_empty(text)
}

pub(super) fn security_identity_generate(
    params: ControlParameters,
    pib: &FilePib,
) -> ControlResponse {
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

/// List trust anchors across every store the forwarder trusts, tagged by
/// `source`: the engine identity PIB (`engine`, used for Data validation),
/// the management command validator (`mgmt`, from
/// `[security.mgmt].trust_anchor_pib` — who may issue signed commands), and
/// the localhop registration validator (`localhop`). Surfacing the `mgmt`
/// set lets the dashboard show the operator anchor that authorizes its own
/// commands, which otherwise lived only inside the command validator.
pub(super) fn security_anchor_list(
    pib: Option<&FilePib>,
    config: &ndn_config::ForwarderConfig,
) -> ControlResponse {
    // (name, source); first source wins on duplicate names.
    let mut entries: Vec<(String, &'static str)> = Vec::new();
    let mut push = |names: Vec<ndn_packet::Name>, source: &'static str| {
        for n in names {
            let s = n.to_string();
            if !entries.iter().any(|(name, _)| name == &s) {
                entries.push((s, source));
            }
        }
    };

    // The engine identity PIB is optional — a forwarder may run with only
    // [security.mgmt] (no [security] identity), yet still trust an operator
    // anchor for commands.
    if let Some(pib) = pib {
        match pib.list_anchors() {
            Ok(a) => push(a, "engine"),
            Err(e) => return ControlResponse::error(status::SERVER_ERROR, e.to_string()),
        }
    }
    // Management + localhop anchors live in separate PIBs the validators were
    // built from; read them so the dashboard sees the full trust posture.
    for (path, source) in [
        (config.security.mgmt.trust_anchor_pib.as_deref(), "mgmt"),
        (
            config.security.mgmt.localhop_trust_anchor_pib.as_deref(),
            "localhop",
        ),
    ] {
        if let Some(p) = path
            && let Ok(other) = FilePib::open(p)
            && let Ok(names) = other.list_anchors()
        {
            push(names, source);
        }
    }

    let mut text = format!("{} anchors\n", entries.len());
    for (name, source) in &entries {
        text.push_str(&format!("  name={name} source={source}\n"));
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
pub(super) fn security_anchor_add(
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
pub(super) fn security_anchor_remove(
    params: ControlParameters,
    engine: &ForwarderEngine,
) -> ControlResponse {
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
pub(super) fn security_safebag_import(params: ControlParameters, pib: &FilePib) -> ControlResponse {
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

pub(super) fn security_key_delete(params: ControlParameters, pib: &FilePib) -> ControlResponse {
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

pub(super) fn security_identity_did(params: ControlParameters, pib: &FilePib) -> ControlResponse {
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
