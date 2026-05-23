//! Face-system Tier 2 §C — integration witnesses for the
//! `faces/update` typed-option seam.
//!
//! Two cases pin the named-field error taxonomy end-to-end:
//!
//! - `faces_update_returns_locked_on_management_face` — the
//!   management-face protection guard returns `423 LOCKED` with
//!   `field=management-face reason=management-face-protected`
//!   when called from a non-management face.
//! - `faces_update_refused_option_carries_named_field` — a
//!   `flags+mask` request that names an LP-only bit against a
//!   local-scope face (`PassthroughLinkService`) returns
//!   `503 SERVICE_UNAVAILABLE` with `field=flags:lp-reliability
//!   reason=transport-not-eligible`.  Asserts the first-refused
//!   option appears in the body (no silent partial application).
//!
//! These run through the in-process mgmt dispatcher exactly as the
//! `nfd/faces/update` Interest does on the wire — the round-trip is
//! `app_face → mgmt module → ControlResponse → app_face`.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_config::{ControlParameters, ControlResponse};
use ndn_engine::{EngineBuilder, EngineConfig};
use ndn_face_local::InProcFace;
use ndn_mgmt::{MgmtHandles, mount_management};
use ndn_packet::{Data, Name, encode::InterestBuilder};
use ndn_transport::{BIT_CONGESTION_MARKING, BIT_LP_RELIABILITY, FaceId, FaceKind};
use tokio_util::sync::CancellationToken;

const APP_FACE_ID: FaceId = FaceId(7000);
const SECOND_FACE_ID: FaceId = FaceId(7001);
const MGMT_FACE_ID: FaceId = FaceId(7002);

struct TestEnv {
    _engine: ndn_engine::ForwarderEngine,
    _shutdown: ndn_engine::ShutdownHandle,
    app_handle: ndn_face_local::InProcHandle,
    cancel: CancellationToken,
}

async fn setup_with_extra<F>(register_extra: F) -> TestEnv
where
    F: FnOnce(&mut EngineBuilder),
{
    let (app_face, app_handle) = InProcFace::new(APP_FACE_ID, 64);
    let mut builder = EngineBuilder::new(EngineConfig::default()).face(app_face);
    register_extra(&mut builder);
    let (engine, shutdown) = builder.build().await.expect("engine build");

    let cancel = CancellationToken::new();
    let mgmt_handles = MgmtHandles {
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

fn build_mgmt_interest(module: &[u8], verb: &[u8], params: &ControlParameters) -> Bytes {
    let name = Name::root()
        .append(b"localhost")
        .append(b"nfd")
        .append(module)
        .append(verb);
    InterestBuilder::new(name)
        .can_be_prefix()
        .must_be_fresh()
        .lifetime(Duration::from_millis(4000))
        .app_parameters(params.encode().to_vec())
        .build()
}

async fn dispatch(env: &TestEnv, params: &ControlParameters) -> ControlResponse {
    let interest = build_mgmt_interest(b"faces", b"update", params);
    env.app_handle.send(interest).await.expect("send Interest");
    let data_wire = tokio::time::timeout(Duration::from_secs(2), env.app_handle.recv())
        .await
        .expect("response within 2s")
        .expect("response not None");
    let data = Data::decode(data_wire).expect("Data decode");
    let content = data.content().cloned().unwrap_or_default();
    ControlResponse::decode(content).expect("ControlResponse decode")
}

/// faces/update against the router's management face from a
/// non-management face returns `423 LOCKED` with the named-field
/// body the operator can grep.
#[tokio::test]
async fn faces_update_returns_locked_on_management_face() {
    let env = setup_with_extra(|builder| {
        let (mgmt_face, _mgmt_handle) =
            InProcFace::new_kind(MGMT_FACE_ID, 64, FaceKind::Management);
        builder.add_face(mgmt_face);
    })
    .await;

    let cp = ControlParameters {
        face_id: Some(MGMT_FACE_ID.0),
        flags: Some(BIT_LP_RELIABILITY),
        mask: Some(BIT_LP_RELIABILITY),
        ..Default::default()
    };
    let cr = dispatch(&env, &cp).await;

    assert_eq!(
        cr.status_code, 423,
        "management face guard must return 423 LOCKED; got {} {:?}",
        cr.status_code, cr.status_text,
    );
    assert!(
        cr.status_text.contains("field=management-face"),
        "named field absent from body: {:?}",
        cr.status_text,
    );
    assert!(
        cr.status_text.contains("reason=management-face-protected"),
        "named reason absent from body: {:?}",
        cr.status_text,
    );

    env.cancel.cancel();
}

/// A flags+mask request that names an LP-only bit against a
/// local-scope face (PassthroughLinkService) comes back as
/// `503 SERVICE_UNAVAILABLE` with `field=flags:lp-reliability` —
/// the first-refused option appears in the body, no silent partial
/// application.
#[tokio::test]
async fn faces_update_refused_option_carries_named_field() {
    let env = setup_with_extra(|builder| {
        let (second_face, _h) = InProcFace::new(SECOND_FACE_ID, 64);
        builder.add_face(second_face);
    })
    .await;

    let mask = BIT_LP_RELIABILITY | BIT_CONGESTION_MARKING;
    let cp = ControlParameters {
        face_id: Some(SECOND_FACE_ID.0),
        flags: Some(mask),
        mask: Some(mask),
        ..Default::default()
    };
    let cr = dispatch(&env, &cp).await;

    assert_eq!(
        cr.status_code, 503,
        "refused LP-only option on local face must be 503; got {} {:?}",
        cr.status_code, cr.status_text,
    );
    assert!(
        cr.status_text.contains("field=flags:lp-reliability"),
        "first-refused option must appear in body: {:?}",
        cr.status_text,
    );
    assert!(
        cr.status_text.contains("reason=transport-not-eligible"),
        "named reason absent from body: {:?}",
        cr.status_text,
    );

    env.cancel.cancel();
}
