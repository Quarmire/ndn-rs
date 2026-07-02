//! `security/ca-*` — NDNCERT CA info / token issuance / enrollment.

use ndn_engine::ForwarderEngine;
use ndn_mgmt_wire::{ControlParameters, ControlResponse, control_response::status};
use ndn_packet::Name;
use ndn_security::FilePib;
use tokio_util::sync::CancellationToken;
use tracing::Instrument as _;

pub(super) fn security_ca_info(config: &dyn crate::MgmtConfig) -> ControlResponse {
    match config.ca_info() {
        None => ControlResponse::error(
            status::NOT_FOUND,
            "no CA configured (set [security] ca_prefix in router TOML)",
        ),
        Some(ca) => {
            let info = format!(
                "ca_prefix={}\nca_info={}\nmax_validity_days={}\nchallenges={}\n",
                ca.prefix,
                ca.info,
                ca.max_validity_days,
                ca.challenges.join(","),
            );
            ControlResponse::ok_empty(info)
        }
    }
}

pub(super) fn security_ca_requests() -> ControlResponse {
    // CaState not yet embedded in the router process.
    ControlResponse::ok_empty("0 pending requests\n".to_string())
}

pub(super) fn security_ca_token_add(params: ControlParameters) -> ControlResponse {
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
pub(super) async fn security_ca_enroll(
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
    let mut session =
        EnrollmentSession::new(identity_name.clone(), std::sync::Arc::clone(&signer), 86400);

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
