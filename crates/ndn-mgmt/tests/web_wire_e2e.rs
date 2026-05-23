//! End-to-end witness — `mount_management` accepts the wire format the
//! dashboard's web `WsMgmtClient` produces.
//!
//! Pre-2026-05-13 the web build hand-rolled an Interest encoder that
//! shoved raw bytes into `ApplicationParameters` and skipped the
//! `ParametersSha256DigestComponent`, so no spec-compliant dispatcher
//! could parse it. The fix routes the web client through
//! `InterestBuilder::new(name).app_parameters(ControlParameters::encode())`,
//! which is the NDNts Signed-Interest-v0.3 shape: CP in AppParameters
//! plus an auto-appended PSDC.
//!
//! This test exercises that exact byte sequence against an in-process
//! `ForwarderEngine` + `mount_management`. The dispatcher's path that
//! handles this shape is `dispatch_command`'s `params_in_app` fallback
//! (search the crate source for "NDNts Signed Interest v0.3").
//!
//! Wire path proven:
//!   client → `InterestBuilder::app_parameters(CP)` → `Interest::decode` →
//!   `parse_command_name` → `app_parameters()` fallback → handler →
//!   `ControlResponse` Data → client decode → assert 200.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_config::{ControlParameters, ControlResponse};
use ndn_engine::{EngineBuilder, EngineConfig};
use ndn_face_local::InProcFace;
use ndn_mgmt::{MgmtHandles, mount_management};
use ndn_packet::{Data, Name, encode::InterestBuilder};
use ndn_transport::FaceId;
use tokio_util::sync::CancellationToken;

const TEST_FACE_ID: FaceId = FaceId(99);

async fn setup() -> (
    ndn_engine::ForwarderEngine,
    ndn_engine::ShutdownHandle,
    ndn_face_local::InProcHandle,
    CancellationToken,
) {
    let (test_face, test_handle) = InProcFace::new(TEST_FACE_ID, 64);

    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(test_face)
        .build()
        .await
        .expect("engine build");

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

    // Give mount_management a tick to install the /localhost/nfd FIB
    // entry before the test sends its first Interest.
    tokio::time::sleep(Duration::from_millis(50)).await;

    (engine, shutdown, test_handle, cancel)
}

fn build_mgmt_interest(module: &[u8], verb: &[u8], params: Option<&ControlParameters>) -> Bytes {
    let name = Name::root()
        .append(b"localhost")
        .append(b"nfd")
        .append(module)
        .append(verb);

    let mut builder = InterestBuilder::new(name)
        .can_be_prefix()
        .must_be_fresh()
        .lifetime(Duration::from_millis(4000));
    if let Some(cp) = params {
        builder = builder.app_parameters(cp.encode().to_vec());
    }
    builder.build()
}

/// Recv the Data response within a generous timeout. Panics on
/// timeout so a hang surfaces as a test failure, not a CI stall.
async fn recv_response(handle: &ndn_face_local::InProcHandle) -> Bytes {
    tokio::time::timeout(Duration::from_secs(2), handle.recv())
        .await
        .expect("response within 2s")
        .expect("response not None")
}

/// `cs/config` with `capacity` — exercises the CP-in-AppParameters
/// mutation path. Returns 200 with the current capacity echoed back.
#[tokio::test]
async fn web_wire_cs_config_returns_200() {
    let (_engine, _shutdown, handle, cancel) = setup().await;

    let cp = ControlParameters {
        capacity: Some(8192),
        ..Default::default()
    };
    let interest = build_mgmt_interest(b"cs", b"config", Some(&cp));

    handle.send(interest).await.expect("send Interest");
    let data_wire = recv_response(&handle).await;

    let data = Data::decode(data_wire).expect("Data decode");
    let content = data.content().cloned().unwrap_or_default();
    let cr = ControlResponse::decode(content).expect("ControlResponse decode");
    assert!(
        cr.is_ok(),
        "cs/config must return 2xx; got {} {:?}",
        cr.status_code,
        cr.status_text
    );

    cancel.cancel();
}

/// `status/general` — dataset-shaped reply (no CP) but still exercises
/// the bare-Interest path. CanBePrefix is required because the
/// response carries a versioned/segmented name.
#[tokio::test]
async fn web_wire_status_general_returns_dataset() {
    let (_engine, _shutdown, handle, cancel) = setup().await;

    let interest = build_mgmt_interest(b"status", b"general", None);
    handle.send(interest).await.expect("send Interest");
    let data_wire = recv_response(&handle).await;

    let data = Data::decode(data_wire).expect("Data decode");
    let content = data.content().cloned().unwrap_or_default();
    // status/general is the spec NFD ForwarderStatus (GeneralStatus) dataset.
    let gs = ndn_mgmt_wire::GeneralStatus::decode(content).expect("GeneralStatus decode");
    assert!(
        gs.nfd_version.starts_with("ndn-rs"),
        "unexpected NfdVersion: {:?}",
        gs.nfd_version,
    );

    cancel.cancel();
}

/// `faces/list` — pure dataset verb. Reply name is
/// `/localhost/nfd/faces/list/v=N/seg=0` so CanBePrefix is mandatory;
/// without it the PIT never matches. This pins the CanBePrefix bit on
/// the web client's bare-Interest path.
#[tokio::test]
async fn web_wire_faces_list_returns_dataset() {
    let (_engine, _shutdown, handle, cancel) = setup().await;

    let interest = build_mgmt_interest(b"faces", b"list", None);
    handle.send(interest).await.expect("send Interest");
    let data_wire = recv_response(&handle).await;

    let data = Data::decode(data_wire).expect("Data decode");
    let content = data.content().cloned().unwrap_or_default();
    // Dataset replies are concatenated FaceStatus TLVs — at least the
    // test face itself should appear, so the content is non-empty.
    assert!(!content.is_empty(), "faces/list dataset must be non-empty");

    cancel.cancel();
}
