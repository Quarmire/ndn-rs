//! IPC-seam witness (Phase 2): two "processes" talk NDN over a `socketpair()`,
//! and the engine drives it.
//!
//! Models the mobile UI↔tunnel split — the tunnel process owns the engine, the
//! UI process is a bare NDN client, and the seam between them is one NDN face
//! over a duplex fd (Android hands that fd across Binder). Here both ends live
//! in one test process over a `socketpair()`:
//!
//! - engine side: a `ForwarderEngine` with an in-process producer serving
//!   `/seam/test`, plus the socketpair end mounted as a `FaceKind::App` face via
//!   [`ndn_mgmt::mount_app_face_from_fd`];
//! - client side: a bare `ndn-app` `Consumer` riding the other end through
//!   `ForwarderClient::from_raw_fd` — no engine, no PIT/FIB/CS.
//!
//! The consumer's Interest crosses the seam, the engine forwards it to the
//! producer, and the Data comes back across the seam.

#![cfg(unix)]

use std::os::fd::RawFd;
use std::sync::Arc;

use ndn_app::{Consumer, EngineAppExt, EngineBuilder, IpcConnection};
use ndn_ipc::ForwarderClient;
use ndn_mgmt::mount_app_face_from_fd;
use tokio_util::sync::CancellationToken;

/// A connected `AF_UNIX`/`SOCK_STREAM` pair — the in-test stand-in for the two
/// fds Android's `VpnService` produces with `socketpair()` and splits across
/// Binder.
// Scoped exception to the workspace `deny(unsafe_code)`: one socketpair(2)
// FFI call, return code checked below.
#[allow(unsafe_code)]
fn stream_socketpair() -> (RawFd, RawFd) {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: standard socketpair(2); we check the return code.
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
    assert_eq!(
        rc,
        0,
        "socketpair() failed: {}",
        std::io::Error::last_os_error()
    );
    (fds[0], fds[1])
}

#[tokio::test]
async fn client_over_socketpair_fetches_from_engine() {
    let (engine_fd, client_fd) = stream_socketpair();

    // ── engine side (the "tunnel process") ──────────────────────────────
    let (engine, _shutdown) = EngineBuilder::new(Default::default())
        .build()
        .await
        .expect("build engine");
    let cancel = CancellationToken::new();

    // A producer serving /seam/test, embedded in the engine process.
    let producer = engine.register_producer("/seam/test", cancel.child_token());
    tokio::spawn(async move {
        let _ = producer
            .serve(|interest, responder| async move {
                let _ = responder
                    .respond(interest.name.as_ref().clone(), b"over-the-seam".to_vec())
                    .await;
            })
            .await;
    });

    // Mount the engine's end of the socketpair as a (non-operator) app face.
    let face_id = mount_app_face_from_fd(engine_fd, &engine, cancel.child_token())
        .expect("mount app face from fd");
    assert!(face_id.0 > 0, "a real face id was allocated");

    // ── client side (the "UI process") ──────────────────────────────────
    // A bare client over the other end of the socketpair — no engine.
    let client = ForwarderClient::from_raw_fd(client_fd).expect("client from fd");
    let conn = Arc::new(IpcConnection::new(client));
    let mut consumer = Consumer::new(conn);

    // The Interest crosses the seam → engine → producer → Data back across it.
    let data = consumer
        .fetch("/seam/test/hello")
        .await
        .expect("fetch across the IPC seam");

    assert_eq!(
        data.content().map(|c| c.as_ref()),
        Some(&b"over-the-seam"[..]),
        "the producer's content came back across the socketpair seam"
    );
    assert_eq!(data.name.to_string(), "/seam/test/hello");

    cancel.cancel();
}
