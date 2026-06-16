//! `/localhost/nfd/cs/erase` mgmt round-trip witness: insert Content Store
//! entries, erase a prefix over the wire, assert they're gone and the response
//! echoes the erased count. The store-level eviction is unit-tested in
//! ndn-store; this pins the mgmt parse → `evict_prefix_erased` → echo path.

use std::sync::Arc;
use std::time::Duration;

use ndn_config::{ControlParameters, ControlResponse};
use ndn_engine::{EngineBuilder, EngineConfig};
use ndn_face_local::{InProcFace, InProcHandle};
use ndn_mgmt::{MgmtHandles, mount_management};
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_packet::{Data, Name};
use ndn_store::CsMeta;
use ndn_transport::FaceId;
use tokio_util::sync::CancellationToken;

const APP_FACE_ID: FaceId = FaceId(7100);

fn empty_handles() -> MgmtHandles {
    MgmtHandles {
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
    }
}

async fn dispatch(
    handle: &InProcHandle,
    verb: &[u8],
    params: &ControlParameters,
) -> ControlResponse {
    let name = Name::root()
        .append(b"localhost")
        .append(b"nfd")
        .append(b"cs")
        .append(verb);
    let interest = InterestBuilder::new(name)
        .can_be_prefix()
        .must_be_fresh()
        .lifetime(Duration::from_millis(4000))
        .app_parameters(params.encode().to_vec())
        .build();
    handle.send(interest).await.expect("send Interest");
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
async fn cs_erase_removes_prefix_over_the_wire() {
    let (app_face, app_handle) = InProcFace::new(APP_FACE_ID, 64);
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(app_face)
        .build()
        .await
        .expect("engine build");
    let cancel = CancellationToken::new();
    tokio::spawn(mount_management(
        &engine,
        cancel.clone(),
        Arc::new(ndn_config::ForwarderConfig::default()),
        None,
        empty_handles(),
    ));
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Seed two CS entries under /app.
    for leaf in ["a", "b"] {
        let n: Name = format!("/app/{leaf}").parse().unwrap();
        let data = DataBuilder::new(n.clone(), b"x").sign_digest_sha256();
        engine
            .cs()
            .insert_erased(data, Arc::new(n), CsMeta { stale_at: u64::MAX })
            .await;
    }
    assert_eq!(engine.cs().len(), 2, "two entries seeded");

    // Erase /app over the wire.
    let cp = ControlParameters {
        name: Some("/app".parse().unwrap()),
        ..Default::default()
    };
    let cr = dispatch(&app_handle, b"erase", &cp).await;

    assert_eq!(
        cr.status_code, 200,
        "cs/erase must succeed: {:?}",
        cr.status_text
    );
    assert_eq!(
        cr.body.and_then(|p| p.count),
        Some(2),
        "response must echo the erased count"
    );
    assert_eq!(engine.cs().len(), 0, "both /app entries must be erased");

    cancel.cancel();
    shutdown.shutdown().await;
}
