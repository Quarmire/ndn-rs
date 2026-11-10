//! A local client that connects to an app-face listener and goes away leaves
//! nothing behind: its face leaves the face table and its socket is closed.
//! A client that reconnects again and again cannot exhaust the forwarder's
//! file descriptors.
//!
//! Its own test binary: it counts the process's open file descriptors, which
//! tests running alongside it in one process would change.

#![cfg(target_os = "linux")]

use std::time::Duration;

use ndn_engine::{APP_FACE_DRAIN, EngineBuilder, EngineConfig, ForwarderEngine};
use ndn_face::local::ProgramPeers;
use ndn_mgmt::listeners::run_face_listener_as;
use ndn_transport::FaceKind;
use tokio_util::sync::CancellationToken;

/// Open file descriptors of this process.
fn open_fds() -> usize {
    std::fs::read_dir("/proc/self/fd")
        .expect("read /proc/self/fd")
        .count()
}

/// Connect a client to `path`, wait until the listener has added its face,
/// then disconnect it.
async fn connect_and_leave(engine: &ForwarderEngine, path: &std::path::Path) {
    let before = engine.faces().face_ids();
    let client = std::os::unix::net::UnixStream::connect(path).expect("connect");
    for _ in 0..500 {
        if engine
            .faces()
            .face_ids()
            .iter()
            .any(|id| !before.contains(id))
        {
            drop(client);
            return;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    panic!("the listener never added a face for the client");
}

/// Wait (for the drain and two seconds more) until the face table is back to
/// `faces` entries; returns how many it has.
async fn settle(engine: &ForwarderEngine, faces: usize) -> usize {
    let deadline = tokio::time::Instant::now() + APP_FACE_DRAIN + Duration::from_secs(2);
    while engine.faces().len() != faces && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    engine.faces().len()
}

#[tokio::test]
async fn reconnecting_local_clients_leak_no_face_and_no_socket() {
    let (engine, _shutdown) = EngineBuilder::new(EngineConfig::default())
        .build()
        .await
        .expect("engine build");
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("app.sock");
    let cancel = CancellationToken::new();
    tokio::spawn({
        let (engine, cancel) = (engine.clone(), cancel.clone());
        let path = path.to_str().expect("utf-8 path").to_owned();
        async move {
            run_face_listener_as(
                &path,
                FaceKind::App,
                ProgramPeers::this_user(),
                engine,
                cancel,
            )
            .await
        }
    });
    for _ in 0..500 {
        if path.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }

    let faces = engine.faces().len();
    // One client first, so whatever the runtime opens once is open before
    // the descriptors are counted.
    connect_and_leave(&engine, &path).await;
    settle(&engine, faces).await;
    let fds = open_fds();

    for _ in 0..32 {
        connect_and_leave(&engine, &path).await;
    }
    let faces_after = settle(&engine, faces).await;
    let fds_after = open_fds();
    assert!(
        fds_after <= fds,
        "clients that left hold no socket: {fds} descriptors open before 32 reconnects, {fds_after} after"
    );
    assert_eq!(
        faces_after, faces,
        "clients that left hold no face in the face table"
    );
    cancel.cancel();
}
