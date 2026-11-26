//! Invariant: `/localhop/nfd` is for a neighbour's route registration (`rib/register`,
//! `rib/unregister`), not a second management socket. A command for any other module arriving
//! over `/localhop` is refused with a sentence that says why and where to send it, even when
//! it is signed by a key the localhop validator accepts, and never reaches the module.

use std::sync::Arc;
use std::time::Duration;

use ndn_config::{ControlParameters, ControlResponse};
use ndn_engine::{EngineBuilder, EngineConfig};
use ndn_face_local::{InProcFace, InProcHandle};
use ndn_mgmt::{MgmtHandles, mount_management};
use ndn_packet::encode::InterestBuilder;
use ndn_packet::{Data, Name};
use ndn_security::Validator;
use ndn_security::cert_cache::Certificate;
use ndn_security::signer::{Ed25519Signer, Signer as _};
use ndn_security::trust_schema::{NamePattern, PatternComponent, SchemaRule, TrustSchema};
use ndn_transport::FaceId;
use tokio_util::sync::CancellationToken;

const APP_FACE_ID: FaceId = FaceId(7300);
const OTHER_FACE_ID: FaceId = FaceId(7301);

/// A localhop validator that accepts any signer whose key it holds: the most permissive setup
/// (a CA host anchors it at the namespace root).
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
    module: &[u8],
    verb: &[u8],
    params: &ControlParameters,
) -> ControlResponse {
    let name = Name::root()
        .append(b"localhop")
        .append(b"nfd")
        .append(module)
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
async fn localhop_runs_route_registration_and_refuses_every_other_module() {
    let key_name: Name = "/home/member/phone/KEY/k1".parse().unwrap();
    let signer = Ed25519Signer::from_seed(&[11u8; 32], key_name.clone());

    let (app_face, app_handle) = InProcFace::new(APP_FACE_ID, 64);
    let (other_face, _other_handle) = InProcFace::new(OTHER_FACE_ID, 64);
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(app_face)
        .face(other_face)
        .build()
        .await
        .expect("engine build");
    let cancel = CancellationToken::new();
    let handles = MgmtHandles {
        extra_modules: Vec::new(),
        face_provisioners: Vec::new(),
        control_surfaces: Vec::new(),
        events: Default::default(),
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
        invite_handler: None,
        trust_context_handler: None,
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

    // `side/quarantine` bars a link and `side/list` shows the routes: local operators only.
    let bar = ControlParameters {
        face_id: Some(OTHER_FACE_ID.0),
        ..Default::default()
    };
    let cr = send_localhop(
        &app_handle,
        &signer,
        &key_name,
        b"side",
        b"quarantine",
        &bar,
    )
    .await;
    assert_eq!(
        cr.status_code, 403,
        "a signed /localhop/nfd/side/quarantine was not refused: {} {:?}",
        cr.status_code, cr.status_text
    );
    assert!(
        cr.status_text.contains("/localhop") && cr.status_text.contains("rib"),
        "the refusal does not say why or what to do: {:?}",
        cr.status_text
    );
    assert!(
        engine.side().quarantined().is_empty(),
        "the face was barred by a /localhop command"
    );
    let cr = send_localhop(
        &app_handle,
        &signer,
        &key_name,
        b"side",
        b"list",
        &ControlParameters::default(),
    )
    .await;
    assert_eq!(
        cr.status_code, 403,
        "a signed /localhop/nfd/side/list was not refused: {} {:?}",
        cr.status_code, cr.status_text
    );

    // What the localhop path is for still runs.
    let register = ControlParameters {
        name: Some("/hop/test".parse().unwrap()),
        face_id: Some(OTHER_FACE_ID.0),
        ..Default::default()
    };
    let cr = send_localhop(
        &app_handle,
        &signer,
        &key_name,
        b"rib",
        b"register",
        &register,
    )
    .await;
    assert_eq!(
        cr.status_code, 200,
        "a signed /localhop/nfd/rib/register was refused: {:?}",
        cr.status_text
    );

    cancel.cancel();
    shutdown.shutdown().await;
}
