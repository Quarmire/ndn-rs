//! Gate-pin witness for `/localhost/nfd/security/safebag-import`.
//!
//! SECURITY-module writes are gated by the signed-command requirement
//! regardless of the operator's global `require_signed_commands`
//! flag (see `is_extended_module` in `ndn-mgmt::lib.rs`). This test
//! pins that the new §5.1 `safebag-import` verb participates in that
//! gate — an unsigned Interest comes back as 403 UNAUTHORIZED.
//!
//! Wire-shape (BAD_PARAMS / round-trip / partial-state) coverage
//! lives as unit tests next to the handler in `crates/ndn-mgmt/src/lib.rs`
//! so they bypass the gate and exercise the handler function directly.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_config::{ControlParameters, ControlResponse};
use ndn_engine::{EngineBuilder, EngineConfig};
use ndn_face_local::InProcFace;
use ndn_mgmt::{MgmtHandles, mount_management};
use ndn_packet::{Data, Name, NameComponent, encode::InterestBuilder};
use ndn_transport::FaceId;
use tokio_util::sync::CancellationToken;

const TEST_FACE_ID: FaceId = FaceId(7777);

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
    let handles = MgmtHandles {
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
        handles,
    );
    tokio::spawn(fut);
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

async fn send_verb(
    handle: &ndn_face_local::InProcHandle,
    module: &[u8],
    verb: &[u8],
    params: Option<&ControlParameters>,
) -> ControlResponse {
    let interest = build_mgmt_interest(module, verb, params);
    handle.send(interest).await.expect("send Interest");
    let raw = tokio::time::timeout(Duration::from_secs(2), handle.recv())
        .await
        .expect("response within 2s")
        .expect("response not None");
    let data = Data::decode(raw).expect("data decode");
    let body = data.content().cloned().unwrap_or_default();
    ControlResponse::decode(body).expect("ControlResponse decode")
}

fn key_name(s: &str) -> Name {
    Name::from_components([NameComponent::generic(Bytes::copy_from_slice(s.as_bytes()))])
}

/// Pin the SECURITY-module signed-command gate for the new
/// `safebag-import` verb. Mirrors the `policy_set_unsigned_is_rejected`
/// pattern in `security_v1_verbs.rs` — extended-module writes always
/// require a signed command, even when the operator's global flag is
/// off.
#[tokio::test]
async fn safebag_import_unsigned_is_rejected() {
    let (_engine, _shutdown, handle, cancel) = setup().await;
    let cp = ControlParameters {
        name: Some(key_name("alice")),
        uri: Some("aa:bb".to_string()),
        ..Default::default()
    };
    let cr = send_verb(&handle, b"security", b"safebag-import", Some(&cp)).await;
    assert_eq!(
        cr.status_code, 403,
        "unsigned safebag-import must be 403; got {} {:?}",
        cr.status_code, cr.status_text
    );
    cancel.cancel();
}
