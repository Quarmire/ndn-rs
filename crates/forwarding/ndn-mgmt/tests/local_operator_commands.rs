//! Invariant: with signed commands required and no command trust anchor (the
//! default configuration), the kernel's peer credentials on the local
//! management socket authenticate the caller. A command from the daemon's own
//! user is accepted unsigned; the same unsigned command on a face that
//! carries no caller identity is refused.
#![cfg(unix)]

use std::sync::Arc;
use std::time::Duration;

use ndn_config::{ControlParameters, ControlResponse};
use ndn_engine::{EngineBuilder, EngineConfig};
use ndn_face_local::InProcFace;
use ndn_ipc::MgmtClient;
use ndn_mgmt::{MgmtHandles, mount_management, run_face_listener};
use ndn_packet::encode::encode_interest;
use ndn_packet::{Data, Name};
use ndn_transport::FaceId;
use tokio_util::sync::CancellationToken;

const APP_FACE_ID: FaceId = FaceId(7400);

#[tokio::test]
async fn local_operator_needs_no_signature_unidentified_face_does() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sock = dir.path().join("mgmt.sock");

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
        localhop_command_validator: None,
        require_signed_commands: true,
        command_replay_cache: None,
        command_response_signer: None,
        log_inspector: None,
        coding_handler: None,
        rate_limit_handler: None,
        compute_handler: None,
        webtransport_status_handler: None,
        ble_handler: None,
        approval_handler: None,
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
    let sock_path = sock.to_str().expect("utf-8 path").to_owned();
    {
        let (path, engine, cancel) = (sock_path.clone(), engine.clone(), cancel.clone());
        tokio::spawn(async move { run_face_listener(&path, engine, cancel).await });
    }
    for _ in 0..100 {
        if sock.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // This process is the daemon: the socket's peer is the daemon's user.
    let client = MgmtClient::connect(&sock_path)
        .await
        .expect("connect to the management socket");
    let prefix: Name = "/local/operator".parse().unwrap();
    client
        .route_add(&prefix, None, 10)
        .await
        .expect("the daemon's user's unsigned command is accepted on the local socket");

    // The same unsigned command on a face without peer credentials.
    let params = ControlParameters {
        name: Some(prefix),
        ..Default::default()
    };
    let name = Name::root()
        .append(b"localhost")
        .append(b"nfd")
        .append(b"rib")
        .append(b"register")
        .append(params.encode().as_ref());
    app_handle
        .send(encode_interest(&name, None))
        .await
        .expect("send Interest");
    let wire = tokio::time::timeout(Duration::from_secs(2), app_handle.recv())
        .await
        .expect("response within 2s")
        .expect("response not None");
    let cr = ControlResponse::decode(
        Data::decode(wire)
            .unwrap()
            .content()
            .cloned()
            .unwrap_or_default(),
    )
    .expect("ControlResponse decode");
    assert_eq!(
        cr.status_code, 403,
        "an unsigned command from a face with no caller identity must be refused: {:?}",
        cr.status_text
    );

    cancel.cancel();
    shutdown.shutdown().await;
}
