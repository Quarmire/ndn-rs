//! Invariant: a trust-changing verb (`security/context-adopt`,
//! `security/enroll`) arriving over `/localhop` never reaches the trust-admin
//! backend, even when it is signed by a key the localhop validator accepts.
//! Trust changes are accepted only on the node's local management socket.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ndn_config::{ControlParameters, ControlResponse};
use ndn_engine::{EngineBuilder, EngineConfig};
use ndn_face_local::{InProcFace, InProcHandle};
use ndn_mgmt::{
    AdoptedContextInfo, EnrollOutcome, EnrollRequest, MgmtHandles, TrustAdminMgmtBackend,
    TrustRefusal, mount_management,
};
use ndn_packet::encode::InterestBuilder;
use ndn_packet::{Data, Name};
use ndn_security::Validator;
use ndn_security::cert_cache::Certificate;
use ndn_security::signer::{Ed25519Signer, Signer as _};
use ndn_security::trust_schema::{NamePattern, PatternComponent, SchemaRule, TrustSchema};
use ndn_transport::FaceId;
use tokio_util::sync::CancellationToken;

const APP_FACE_ID: FaceId = FaceId(7300);

#[derive(Default)]
struct CountingBackend {
    calls: AtomicUsize,
}

#[async_trait::async_trait]
impl TrustAdminMgmtBackend for CountingBackend {
    async fn adopt(&self, _link_uri: String) -> Result<AdoptedContextInfo, TrustRefusal> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(TrustRefusal {
            status_code: 500,
            reason: "backend reached".into(),
        })
    }

    async fn enroll(&self, _request: EnrollRequest) -> Result<EnrollOutcome, TrustRefusal> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(TrustRefusal {
            status_code: 500,
            reason: "backend reached".into(),
        })
    }
}

/// A localhop validator that accepts any signer whose key it holds — the
/// most permissive setup (a CA host anchors it at the namespace root).
fn accepting_validator(key_name: &Name, pubkey: &[u8]) -> Arc<Validator> {
    let mut schema = TrustSchema::new();
    schema.add_rule(SchemaRule {
        data_pattern: NamePattern(vec![PatternComponent::MultiCapture("_".into())]),
        key_pattern: NamePattern(vec![PatternComponent::MultiCapture("_".into())]),
    });
    let validator = Validator::new(schema);
    validator.cert_cache().insert(Certificate {
        name: Arc::new(key_name.clone()),
        public_key: bytes::Bytes::copy_from_slice(pubkey),
        valid_from: 0,
        valid_until: u64::MAX,
        issuer: None,
        signed_region: None,
        sig_value: None,
        sig_type: ndn_packet::SignatureType::SignatureEd25519,
    });
    Arc::new(validator)
}

async fn send_localhop(
    handle: &InProcHandle,
    signer: &Ed25519Signer,
    key_name: &Name,
    verb: &[u8],
    params: &ControlParameters,
) -> ControlResponse {
    let name = Name::root()
        .append(b"localhop")
        .append(b"nfd")
        .append(b"security")
        .append(verb);
    let wire = InterestBuilder::new(name)
        .lifetime(Duration::from_millis(4000))
        .app_parameters(params.encode().to_vec())
        .sign_sync(
            ndn_packet::SignatureType::SignatureEd25519,
            Some(key_name),
            |region| signer.sign_sync(region).expect("ed25519 sign"),
        );
    handle.send(wire).await.expect("send Interest");
    let wire = tokio::time::timeout(Duration::from_secs(2), handle.recv())
        .await
        .expect("response within 2s")
        .expect("response not None");
    ControlResponse::decode(
        Data::decode(wire)
            .unwrap()
            .content()
            .cloned()
            .unwrap_or_default(),
    )
    .expect("ControlResponse decode")
}

#[tokio::test]
async fn localhop_trust_admin_verbs_never_run() {
    let key_name: Name = "/home/member/phone/KEY/k1".parse().unwrap();
    let signer = Ed25519Signer::from_seed(&[11u8; 32], key_name.clone());
    let backend = Arc::new(CountingBackend::default());

    let (app_face, app_handle) = InProcFace::new(APP_FACE_ID, 64);
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(app_face)
        .build()
        .await
        .expect("engine build");
    let cancel = CancellationToken::new();
    let handles = MgmtHandles {
        extra_modules: Vec::new(),
        face_provisioners: Vec::new(),
        control_surfaces: Vec::new(),
        security_is_ephemeral: true,
        command_validator: None,
        localhop_command_validator: Some(accepting_validator(
            &key_name,
            &signer.public_key_bytes(),
        )),
        require_signed_commands: false,
        command_replay_cache: None,
        command_response_signer: None,
        log_inspector: None,
        coding_handler: None,
        rate_limit_handler: None,
        compute_handler: None,
        webtransport_status_handler: None,
        ble_handler: None,
        approval_handler: None,
        trust_context_handler: Some(backend.clone() as Arc<dyn TrustAdminMgmtBackend>),
        runtime_policy: None,
    };
    tokio::spawn(mount_management(
        &engine,
        cancel.clone(),
        Arc::new(ndn_config::ForwarderConfig::default()),
        None,
        handles,
    ));
    tokio::time::sleep(Duration::from_millis(50)).await;

    let adopt = ControlParameters {
        uri: Some("ndn-trust://anchor?ns=/home&fp=00".into()),
        ..Default::default()
    };
    let cr = send_localhop(&app_handle, &signer, &key_name, b"context-adopt", &adopt).await;
    assert_eq!(cr.status_code, 403, "localhop context-adopt: {:?}", cr.status_text);

    let enroll = ControlParameters {
        uri: Some("ndn-trust://invite?ns=/home/member".into()),
        name: Some("/home/member/root".parse().unwrap()),
        ..Default::default()
    };
    let cr = send_localhop(&app_handle, &signer, &key_name, b"enroll", &enroll).await;
    assert_eq!(cr.status_code, 403, "localhop enroll: {:?}", cr.status_text);

    assert_eq!(
        backend.calls.load(Ordering::SeqCst),
        0,
        "a /localhop trust change must never reach the backend"
    );

    cancel.cancel();
    shutdown.shutdown().await;
}
