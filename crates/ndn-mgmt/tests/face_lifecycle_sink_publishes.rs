//! Face-system Tier 6 §K — end-to-end witness for the engine ↔
//! mgmt face-lifecycle wiring.
//!
//! Mounts management on a fresh engine, adds a face via
//! `faces/create`, subscribes to
//! `/localhost/nfd/faces/notifications/seg=N` by Interest, and
//! asserts that both `Created` (from the mgmt handler) and `Up`
//! (from the engine's face-task) reach subscribers.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_config::{ControlParameters, ControlResponse};
use ndn_engine::{EngineBuilder, EngineConfig};
use ndn_face_local::InProcFace;
use ndn_mgmt::{FaceEvent, MgmtHandles, mount_management};
use ndn_packet::{Data, Name, encode::InterestBuilder};
use ndn_transport::FaceId;
use tokio_util::sync::CancellationToken;

const APP_FACE_ID: FaceId = FaceId(10_000);

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

async fn fetch_event(env: &TestEnv, seq: u64) -> FaceEvent {
    let name = Name::root()
        .append(b"localhost")
        .append(b"nfd")
        .append(b"faces")
        .append(b"notifications")
        .append_sequence_num(seq);
    let interest = InterestBuilder::new(name)
        .must_be_fresh()
        .lifetime(Duration::from_secs(3))
        .build();
    env.app_handle.send(interest).await.expect("send Interest");
    let wire = tokio::time::timeout(Duration::from_secs(2), env.app_handle.recv())
        .await
        .expect("notification within 2s")
        .expect("notification not None");
    let data = Data::decode(wire).expect("Data decode");
    let content = data.content().cloned().unwrap_or_default();
    FaceEvent::decode(&content).expect("FaceEvent decode")
}

/// Tier 6 §K — creating a face via mgmt fires two notifications in
/// order: the engine's `Up` from the face task (sink path) and the
/// mgmt handler's `Created` (response-success path).  Both must
/// reach a subscribing client.
#[tokio::test]
async fn engine_up_and_mgmt_created_both_publish_on_face_create() {
    let env = setup().await;

    let cp = ControlParameters {
        uri: Some("udp4://127.0.0.1:6390".to_owned()),
        ..Default::default()
    };
    let cr = dispatch(&env, b"create", &cp).await;
    assert_eq!(cr.status_code, 200, "faces/create failed: {cr:?}");

    // Both kinds must appear within the first two segments — exact
    // ordering depends on async scheduling between the face-task's
    // on_up call and the dispatch wrapper's Created publish; we
    // assert presence + face-id consistency rather than order.
    let e1 = fetch_event(&env, 1).await;
    let e2 = fetch_event(&env, 2).await;
    let saw_up = matches!(e1, FaceEvent::Up { .. }) || matches!(e2, FaceEvent::Up { .. });
    let saw_created =
        matches!(e1, FaceEvent::Created { .. }) || matches!(e2, FaceEvent::Created { .. });
    assert!(saw_up, "engine Up event must publish; got {e1:?}, {e2:?}");
    assert!(
        saw_created,
        "mgmt Created event must publish; got {e1:?}, {e2:?}",
    );
    // Both refer to the same face.
    let id1 = e1.face_id();
    let id2 = e2.face_id();
    assert_eq!(id1, id2, "events must share the same face_id");

    env.cancel.cancel();
}
