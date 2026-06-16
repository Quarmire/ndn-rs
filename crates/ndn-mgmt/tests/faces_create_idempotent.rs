//! Face-system Tier 5 §H — idempotent `faces/create` returns
//! `200 OK` with the existing face id when the URI is already
//! attached; failed option-applies collect into `partial_failures`.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_config::{ControlParameters, ControlResponse};
use ndn_engine::{EngineBuilder, EngineConfig};
use ndn_face_local::InProcFace;
use ndn_mgmt::{MgmtHandles, mount_management};
use ndn_packet::{Data, Name, encode::InterestBuilder};
use ndn_transport::{BIT_LP_RELIABILITY, FaceId};
use tokio_util::sync::CancellationToken;

const APP_FACE_ID: FaceId = FaceId(9000);

struct TestEnv {
    _engine: ndn_engine::ForwarderEngine,
    _shutdown: ndn_engine::ShutdownHandle,
    app_handle: ndn_face_local::InProcHandle,
    cancel: CancellationToken,
}

async fn setup() -> TestEnv {
    let (app_face, app_handle) = InProcFace::new(APP_FACE_ID, 64);
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(app_face)
        .build()
        .await
        .expect("engine build");

    let cancel = CancellationToken::new();
    let mgmt_handles = MgmtHandles {
        extra_modules: Vec::new(),
        face_provisioners: Vec::new(),
        discovery_cfg: None,
        security_is_ephemeral: true,
        command_validator: None,
        localhop_command_validator: None,
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
        runtime_policy: None,
    };
    let fut = mount_management(
        &engine,
        cancel.clone(),
        None,
        Vec::new(),
        Arc::new(ndn_config::ForwarderConfig::default()),
        None,
        mgmt_handles,
    );
    tokio::spawn(fut);
    tokio::time::sleep(Duration::from_millis(50)).await;
    TestEnv {
        _engine: engine,
        _shutdown: shutdown,
        app_handle,
        cancel,
    }
}

async fn dispatch(env: &TestEnv, verb: &[u8], params: &ControlParameters) -> ControlResponse {
    let name = Name::root()
        .append(b"localhost")
        .append(b"nfd")
        .append(b"faces")
        .append(verb);
    let interest = InterestBuilder::new(name)
        .can_be_prefix()
        .must_be_fresh()
        .lifetime(Duration::from_millis(4000))
        .app_parameters(params.encode().to_vec())
        .build();
    env.app_handle.send(interest).await.expect("send Interest");
    let wire: Bytes = tokio::time::timeout(Duration::from_secs(2), env.app_handle.recv())
        .await
        .expect("response within 2s")
        .expect("response not None");
    let data = Data::decode(wire).expect("Data decode");
    let content = data.content().cloned().unwrap_or_default();
    ControlResponse::decode(content).expect("ControlResponse decode")
}

/// Tier 5 §H — second `faces/create` for the same UDP URI returns
/// the existing face_id with `200 OK` and no partial failures.
#[tokio::test]
async fn faces_create_idempotent_returns_existing_face_id() {
    let env = setup().await;

    // First create — get a real UDP face (loopback, ephemeral port).
    let cp = ControlParameters {
        uri: Some("udp4://127.0.0.1:6363".to_owned()),
        ..Default::default()
    };
    let first = dispatch(&env, b"create", &cp).await;
    assert_eq!(first.status_code, 200, "{:?}", first.status_text);
    let first_id = first
        .body
        .as_ref()
        .and_then(|b| b.face_id)
        .expect("face_id on first create");
    let first_body = first.body.as_ref().expect("first body");
    assert_eq!(
        first_body.flags,
        Some(0),
        "faces/create must echo Flags for NFD FaceCreateCommand compatibility",
    );
    assert_eq!(
        first_body.face_persistency,
        Some(0),
        "faces/create must echo persistent FacePersistency for NFD clients",
    );

    // Second create — same URI, should reuse the existing id and
    // ship no partial failures (no extra options requested).
    let second = dispatch(&env, b"create", &cp).await;
    assert_eq!(second.status_code, 200);
    let second_body = second.body.as_ref().expect("second body");
    let second_id = second_body.face_id.unwrap();
    assert_eq!(
        second_id, first_id,
        "idempotent create must return the same face_id",
    );
    assert_eq!(
        second_body.flags,
        Some(0),
        "idempotent faces/create must echo current Flags for NFD clients",
    );
    assert_eq!(
        second_body.face_persistency,
        Some(0),
        "idempotent faces/create must echo current FacePersistency for NFD clients",
    );
    assert!(
        second
            .body
            .as_ref()
            .map(|b| b.partial_failures.is_empty())
            .unwrap_or(false),
        "no partial failures expected when no extra options are requested",
    );

    env.cancel.cancel();
}

/// Tier 5 §H — when the idempotent re-attach is asked to apply an
/// MTU that exceeds the transport's hard max, the response stays
/// `200 OK` and records the refused option in
/// `body.partial_failures`.
#[tokio::test]
async fn faces_create_idempotent_records_partial_failures() {
    let env = setup().await;

    // First create.
    let cp = ControlParameters {
        uri: Some("udp4://127.0.0.1:6364".to_owned()),
        ..Default::default()
    };
    let first = dispatch(&env, b"create", &cp).await;
    assert_eq!(first.status_code, 200);

    // Re-attach with an out-of-range MTU (UDP_HARD_MAX = 65507).
    let cp = ControlParameters {
        uri: Some("udp4://127.0.0.1:6364".to_owned()),
        mtu: Some(100_000),
        flags: Some(BIT_LP_RELIABILITY),
        mask: Some(BIT_LP_RELIABILITY),
        ..Default::default()
    };
    let second = dispatch(&env, b"create", &cp).await;
    assert_eq!(
        second.status_code, 200,
        "idempotent re-attach is best-effort; status stays 200",
    );
    let body = second.body.as_ref().expect("body");
    let failures = &body.partial_failures;
    assert!(
        failures.iter().any(|(opt, _)| opt == "mtu"),
        "mtu refusal must appear in partial_failures: {failures:?}",
    );

    env.cancel.cancel();
}
