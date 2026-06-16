//! Face-system Tier 5 §F — end-to-end witness for the Tier-4 semantic
//! events.
//!
//! Spins up a forwarder with mgmt mounted, runs a `faces/update` call
//! that exercises the refused-option path, then subscribes to
//! `/localhost/nfd/faces/notifications/seg=N` by Interest and decodes
//! the returned `FaceEvent` Data.  Asserts the published event names
//! the same field + reason the response carries.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_config::{ControlParameters, ControlResponse};
use ndn_engine::{EngineBuilder, EngineConfig};
use ndn_face_local::InProcFace;
use ndn_mgmt::{FaceEvent, MgmtHandles, mount_management};
use ndn_packet::{Data, Name, encode::InterestBuilder};
use ndn_transport::{BIT_LP_RELIABILITY, FaceId};
use tokio_util::sync::CancellationToken;

const APP_FACE_ID: FaceId = FaceId(8000);
const SECOND_FACE_ID: FaceId = FaceId(8001);

struct TestEnv {
    _engine: ndn_engine::ForwarderEngine,
    _shutdown: ndn_engine::ShutdownHandle,
    app_handle: ndn_face_local::InProcHandle,
    cancel: CancellationToken,
}

async fn setup() -> TestEnv {
    let (app_face, app_handle) = InProcFace::new(APP_FACE_ID, 64);
    let (second_face, _second_handle) = InProcFace::new(SECOND_FACE_ID, 64);
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(app_face)
        .face(second_face)
        .build()
        .await
        .expect("engine build");

    let cancel = CancellationToken::new();
    let mgmt_handles = MgmtHandles {
        extra_modules: Vec::new(),
        face_provisioners: Vec::new(),
        control_surfaces: Vec::new(),
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

fn build_mgmt_interest(verb: &[u8], params: &ControlParameters) -> Bytes {
    let name = Name::root()
        .append(b"localhost")
        .append(b"nfd")
        .append(b"faces")
        .append(verb);
    InterestBuilder::new(name)
        .can_be_prefix()
        .must_be_fresh()
        .lifetime(Duration::from_millis(4000))
        .app_parameters(params.encode().to_vec())
        .build()
}

async fn dispatch_faces_update(env: &TestEnv, params: &ControlParameters) -> ControlResponse {
    let interest = build_mgmt_interest(b"update", params);
    env.app_handle.send(interest).await.expect("send Interest");
    let data_wire = tokio::time::timeout(Duration::from_secs(2), env.app_handle.recv())
        .await
        .expect("response within 2s")
        .expect("response not None");
    let data = Data::decode(data_wire).expect("Data decode");
    let content = data.content().cloned().unwrap_or_default();
    ControlResponse::decode(content).expect("ControlResponse decode")
}

/// Subscribe to `/localhost/nfd/faces/notifications/seg=N` and return
/// the decoded `FaceEvent`.  Long-poll: the producer holds the
/// Interest open until the seq becomes available.
async fn fetch_face_event(env: &TestEnv, seq: u64) -> FaceEvent {
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

/// Tier 5 §F — refused `faces/update` publishes an `OptionRefused`
/// notification carrying the same field + reason the response
/// status_text carries.
#[tokio::test]
async fn faces_update_refused_publishes_option_refused_event() {
    let env = setup().await;

    let cp = ControlParameters {
        face_id: Some(SECOND_FACE_ID.0),
        flags: Some(BIT_LP_RELIABILITY),
        mask: Some(BIT_LP_RELIABILITY),
        ..Default::default()
    };
    let cr = dispatch_faces_update(&env, &cp).await;
    assert_eq!(cr.status_code, 503, "expected 503 SERVICE_UNAVAILABLE");
    assert!(
        cr.status_text.contains("field=flags:lp-reliability"),
        "named field absent: {:?}",
        cr.status_text,
    );

    // Tier 4 §B emits one OptionRefused event on the refused-flag
    // path.  Subscribe at seg=1 — the first event the stream
    // published.  Long-poll resolves as soon as the publish lands.
    let event = fetch_face_event(&env, 1).await;
    match event {
        FaceEvent::OptionRefused {
            face_id,
            option,
            reason,
        } => {
            assert_eq!(face_id, SECOND_FACE_ID);
            assert_eq!(option, "flags:lp-reliability");
            assert_eq!(reason, "transport-not-eligible");
        }
        other => panic!("expected OptionRefused, got {other:?}"),
    }

    env.cancel.cancel();
}
