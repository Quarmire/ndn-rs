//! `security/ca-*` — NDNCERT CA info / enrollment.

use ndn_cert::CertError;
use ndn_engine::ForwarderEngine;
use ndn_mgmt_wire::{ControlParameters, ControlResponse, control_response::status};
use ndn_packet::Name;
use ndn_security::FilePib;
use tokio_util::sync::CancellationToken;
use tracing::Instrument as _;

pub(super) fn security_ca_info(config: &dyn crate::MgmtConfig) -> ControlResponse {
    match config.ca_info() {
        None => crate::refusal_response(&crate::not_at_runtime("ca-info", "this node runs no CA")),
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

/// Start a background NDNCERT enrollment session.
///
/// Creates a temporary [`InProcFace`] registered with the engine so that
/// NDN Interests can be expressed through the live forwarder, then runs
/// the shared NEW → CHALLENGE driver ([`ndn_cert::client::enroll`]) against
/// the requested CA prefix. When the CA issues a certificate it is stored in
/// the PIB.
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
        let mut exchange = InProcExchange(app_handle);
        let result = run_enrollment(
            &mut exchange,
            &ca_name,
            signer,
            &challenge_type,
            &challenge_param,
        )
        .await;

        face_cancel.cancel();

        match result {
            Ok(cert_data) => {
                match ndn_security::FilePib::open(&pib_path) {
                    // One more certificate of the key, stored as received;
                    // refused unless it certifies this key.
                    Ok(pib) => match pib.store_issued_cert(&identity_name, cert_data.raw()) {
                        Ok(cert) => tracing::info!(
                            target: "mgmt.security",
                            name = %identity_name,
                            certificate = %cert.name,
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

/// [`ndn_cert::CaExchange`] over the temporary in-process app face: send the
/// Interest, await the next Data on the face.
struct InProcExchange(ndn_face_local::InProcHandle);

impl ndn_cert::CaExchange for InProcExchange {
    async fn express(&mut self, interest: bytes::Bytes) -> Result<ndn_packet::Data, CertError> {
        const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
        self.0
            .send(interest)
            .await
            .map_err(|e| CertError::Transport(format!("send: {e}")))?;
        let reply = tokio::time::timeout(TIMEOUT, self.0.recv())
            .await
            .map_err(|_| CertError::Transport("timeout".into()))?
            .ok_or_else(|| CertError::Transport("face closed".into()))?;
        ndn_packet::Data::decode(reply)
            .map_err(|e| CertError::Transport(format!("malformed Data: {e:?}")))
    }
}

/// One CHALLENGE round carrying `{"code": challenge_param}`, then fetch the
/// issued certificate Data.
async fn run_enrollment(
    exchange: &mut InProcExchange,
    ca_prefix: &Name,
    signer: std::sync::Arc<dyn ndn_security::Signer>,
    challenge_type: &str,
    challenge_param: &str,
) -> Result<ndn_packet::Data, String> {
    let mut params = serde_json::Map::new();
    params.insert(
        "code".to_owned(),
        serde_json::Value::String(challenge_param.to_owned()),
    );
    let mut params = Some(params);
    let cert_name = ndn_cert::client::enroll(
        exchange,
        ca_prefix,
        signer,
        86400,
        challenge_type,
        |round| {
            let next = match params.take() {
                Some(p) => Ok(Some(p)),
                None => Err(CertError::ChallengePending(format!(
                    "multi-round challenge not supported: {}",
                    round
                        .status_message
                        .as_deref()
                        .unwrap_or("another round required")
                ))),
            };
            std::future::ready(next)
        },
    )
    .await
    .map_err(|e| e.to_string())?;

    ndn_cert::client::fetch_issued_cert(exchange, &cert_name)
        .await
        .map_err(|e| format!("cert fetch: {e}"))
}
