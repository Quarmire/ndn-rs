//! `security/yubikey-*` — PC/SC YubiKey PIV detection and key generation.

#[cfg(feature = "yubikey-piv")]
use base64::Engine as _;

use ndn_mgmt_wire::{ControlParameters, ControlResponse, control_response::status};
use ndn_security::FilePib;

/// Detect a PC/SC-accessible YubiKey. Returns `status_text="present"`,
/// or `NOT_FOUND` if absent or when the `yubikey-piv` feature is off.
pub(super) fn security_yubikey_detect() -> ControlResponse {
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
pub(super) async fn security_yubikey_generate(
    params: ControlParameters,
    pib: &FilePib,
) -> ControlResponse {
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
