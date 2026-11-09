//! Invariant: `security/transit` — carrying a person's namespace in transit,
//! so its Data reaches local apps unvalidated — is a trust change. A local
//! operator on the management socket reaches the backend; the same command
//! on a face that carries no caller identity is refused
//! (`trust-change-unidentified`) and never reaches it, even where unsigned
//! commands are otherwise accepted.
#![cfg(unix)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use ndn_config::{ControlParameters, ControlResponse};
use ndn_engine::{EngineBuilder, EngineConfig};
use ndn_face_local::InProcFace;
use ndn_ipc::MgmtClient;
use ndn_mgmt::{
    AdoptedContextInfo, MgmtHandles, TransitInfo, TrustAdminMgmtBackend, TrustRefusal,
    mount_management, run_face_listener,
};
use ndn_packet::encode::encode_interest;
use ndn_packet::{Data, Name};
use ndn_transport::FaceId;
use tokio_util::sync::CancellationToken;

const APP_FACE_ID: FaceId = FaceId(7500);

/// Records each `transit` it is asked (by which face), and answers with the
/// count so far.
#[derive(Default)]
struct Marking {
    asked: Mutex<Vec<(Name, bool)>>,
    faces: Mutex<Vec<Option<FaceId>>>,
}

#[async_trait::async_trait]
impl TrustAdminMgmtBackend for Marking {
    async fn adopt(&self, _link_uri: String) -> Result<AdoptedContextInfo, TrustRefusal> {
        Err(ndn_mgmt::not_at_runtime(
            "context-adopt",
            "not in this test",
        ))
    }

    fn transit(
        &self,
        face: Option<FaceId>,
        namespace: Name,
        carry: bool,
    ) -> Result<TransitInfo, TrustRefusal> {
        self.faces.lock().unwrap().push(face);
        let mut asked = self.asked.lock().unwrap();
        asked.push((namespace.clone(), carry));
        Ok(TransitInfo {
            namespace: namespace.to_string(),
            marks: asked.len() as u64,
            held: false,
        })
    }
}

#[tokio::test]
async fn transit_needs_a_local_operator() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sock = dir.path().join("mgmt.sock");
    let backend = Arc::new(Marking::default());

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
        events: Default::default(),
        security_is_ephemeral: true,
        command_validator: None,
        localhop_command_validator: None,
        // Unsigned commands pass the command gate: only the trust-admin
        // gate stands between an unidentified face and the backend.
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
    let ns: Name = "/user/carol".parse().unwrap();
    let client = MgmtClient::connect(&sock_path)
        .await
        .expect("connect to the management socket");
    let carried = client
        .security_transit(&ns, true)
        .await
        .expect("a local operator marks a namespace in transit");
    assert_eq!(carried.marks, 1, "{carried:?}");
    client
        .security_transit(&ns, false)
        .await
        .expect("a local operator takes a mark back");
    assert_eq!(
        *backend.asked.lock().unwrap(),
        vec![(ns.clone(), true), (ns.clone(), false)],
        "the flag carries mark or release to the backend"
    );
    let faces = backend.faces.lock().unwrap().clone();
    assert!(
        faces[0].is_some() && faces[0] == faces[1] && faces[0] != Some(APP_FACE_ID),
        "each mark names the management face that asked, which owns it: {faces:?}"
    );

    // The same command on a face without peer credentials.
    let params = ControlParameters {
        name: Some(ns),
        ..Default::default()
    };
    let name = Name::root()
        .append(b"localhost")
        .append(b"nfd")
        .append(b"security")
        .append(b"transit")
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
    let refusal = ndn_ipc::trust_refusal_of(cr.status_code, &cr.status_text);
    assert!(
        refusal
            .as_ref()
            .is_some_and(|r| r.is(ndn_cert::report::code::TRUST_CHANGE_UNIDENTIFIED)),
        "transit from a face with no caller identity must be refused by the trust-admin gate: \
         {} {:?}",
        cr.status_code,
        cr.status_text
    );
    assert_eq!(
        backend.asked.lock().unwrap().len(),
        2,
        "a refused transit must never reach the backend"
    );

    cancel.cancel();
    shutdown.shutdown().await;
}
