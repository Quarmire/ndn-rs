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
    let producer = engine.register_producer(ndn_packet::name!("/seam/test"), cancel.child_token());
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
        .fetch(ndn_packet::name!("/seam/test/hello"))
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

/// A channel frame crosses the seam in both directions: two bare clients ride two socketpairs
/// into one engine (each end an IPC face, mounted by `mount_app_face_from_fd` and
/// `ForwarderClient::from_raw_fd`). The sender answers the receiver's Interest with a Data that
/// carries a `SideRoute`, the engine installs the route from the sender's face to the
/// receiver's, the sender's frame reaches the receiver's `recv_side` byte for byte with the
/// sender's face as its ingress, and the receiver's `UP` record goes back the other way. NDN
/// traffic between the frames is untouched.
#[tokio::test]
async fn channel_frames_cross_the_ipc_seam_in_both_directions() {
    use bytes::Bytes;
    use ndn_app::Connection;
    use ndn_packet::encode::{DataBuilder, InterestBuilder};
    use ndn_packet::lp::{LpHeaders, SideRoute};
    use ndn_transport::SideClass;
    use ndn_transport::side_header::{STREAM_FRAME_GRANT, UpOp, UpRecord};
    use std::time::Duration;

    const ID: u64 = 0x1BC5_1DE0_0000_0001;

    let (engine, _shutdown) = EngineBuilder::new(Default::default())
        .build()
        .await
        .expect("build engine");
    let cancel = CancellationToken::new();

    let (engine_s, client_s) = stream_socketpair();
    let (engine_r, client_r) = stream_socketpair();
    let face_s = mount_app_face_from_fd(engine_s, &engine, cancel.child_token()).unwrap();
    let face_r = mount_app_face_from_fd(engine_r, &engine, cancel.child_token()).unwrap();
    engine
        .fib()
        .add_nexthop(&ndn_packet::name!("/chan"), face_s, 0);

    let sender = IpcConnection::new(ForwarderClient::from_raw_fd(client_s).unwrap());
    let receiver = IpcConnection::new(ForwarderClient::from_raw_fd(client_r).unwrap());
    assert_eq!(sender.side_frame_max(), STREAM_FRAME_GRANT);
    assert!(receiver.side_carries_here(SideClass::Stream));
    // Capable is not carrying: nothing goes either way until a client says it reads side records.
    let probe = Bytes::from_static(&[ndn_transport::SIDE_MARKER, 0x20, 0, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(
        sender.try_send_side(probe.clone(), SideClass::Datagram),
        Err(ndn_transport::SideRefused::NotCarried)
    );
    let refused = sender
        .send_side(probe, SideClass::Datagram)
        .await
        .unwrap_err()
        .to_string();
    assert!(refused.contains("open_side"), "{refused}");
    sender.open_side();
    receiver.open_side();

    // The receiver asks, the sender answers with the route header.
    let name = ndn_packet::name!("/chan/sess/1");
    receiver
        .send(
            InterestBuilder::new(name.clone())
                .lifetime(Duration::from_secs(4))
                .build(),
        )
        .await
        .unwrap();
    let asked = tokio::time::timeout(Duration::from_secs(5), sender.recv())
        .await
        .expect("the Interest reaches the sender")
        .expect("the sender's connection is open");
    assert!(!asked.is_empty());
    sender
        .send_with(
            DataBuilder::new(name, b"session").sign_digest_sha256(),
            LpHeaders {
                side_route: Some(SideRoute {
                    id: ID,
                    ttl_secs: 30,
                }),
                ..LpHeaders::default()
            },
        )
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), receiver.recv())
        .await
        .expect("the Data reaches the receiver")
        .expect("the receiver's connection is open");

    // A frame from the sender reaches the receiver byte for byte, over the sender's face.
    let mut frame = vec![0x5A; 200];
    frame[0] = ndn_transport::SIDE_MARKER;
    frame[1] = 0x20; // version 1, datagram, DATA
    frame[2..10].copy_from_slice(&ID.to_be_bytes());
    let frame = Bytes::from(frame);
    sender
        .send_side(frame.clone(), SideClass::Datagram)
        .await
        .unwrap();
    let (got, ingress) = tokio::time::timeout(Duration::from_secs(5), receiver.recv_side())
        .await
        .expect("the frame reaches the receiver")
        .expect("the receiver's connection is open");
    assert_eq!(got, frame);
    assert_eq!(
        ingress, face_s,
        "the receiver is told the face it came over"
    );

    // The receiver's keep-alive goes back to the sender, over the receiver's face, by the
    // non-waiting path.
    let keep = Bytes::copy_from_slice(
        &UpRecord {
            id: ID,
            op: UpOp::Keep,
        }
        .encode(),
    );
    receiver
        .try_send_side(keep.clone(), SideClass::Datagram)
        .unwrap();
    let (got, ingress) = tokio::time::timeout(Duration::from_secs(5), sender.recv_side())
        .await
        .expect("the Keep reaches the sender")
        .expect("the sender's connection is open");
    assert_eq!(got, keep);
    assert_eq!(ingress, face_r);

    // What is not a channel frame is refused at the app, and nothing is written.
    assert!(
        sender
            .send_side(Bytes::from_static(&[0x05, 0x01, 0xAB]), SideClass::Datagram)
            .await
            .is_err()
    );
    assert_eq!(
        sender.try_send_side(Bytes::new(), SideClass::Datagram),
        Err(ndn_transport::SideRefused::Malformed)
    );
    assert_eq!(engine.side().stats().frames_out, 1);

    cancel.cancel();
}

/// The next whole TLV element of `buf` (removed from it), `None` when it is incomplete, and an
/// error when the stream is not TLV elements: what a client built before the side record reads
/// its socket with.
fn next_element(buf: &mut Vec<u8>) -> Result<Option<Vec<u8>>, String> {
    fn varnum(b: &[u8]) -> Option<(u64, usize)> {
        let first = *b.first()?;
        let width = match first {
            0..=252 => return Some((u64::from(first), 1)),
            253 => 2,
            254 => 4,
            255 => 8,
        };
        let rest = b.get(1..=width)?;
        Some((
            rest.iter().fold(0, |v, &x| (v << 8) | u64::from(x)),
            1 + width,
        ))
    }
    if buf.first() == Some(&0) {
        return Err(format!(
            "the stream carries a record, not a TLV element: it starts {:02x?}",
            &buf[..buf.len().min(16)]
        ));
    }
    let Some((_, type_len)) = varnum(buf) else {
        return Ok(None);
    };
    let Some((len, len_len)) = varnum(&buf[type_len..]) else {
        return Ok(None);
    };
    let total = type_len + len_len + len as usize;
    if buf.len() < total {
        return Ok(None);
    }
    Ok(Some(buf.drain(..total).collect()))
}

/// Read from `stream` until `buf` holds a whole element, and return it.
async fn read_element(
    stream: &mut tokio::net::UnixStream,
    buf: &mut Vec<u8>,
) -> Result<Vec<u8>, String> {
    use tokio::io::AsyncReadExt;
    loop {
        if let Some(element) = next_element(buf)? {
            return Ok(element);
        }
        let mut chunk = [0u8; 4096];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut chunk))
            .await
            .map_err(|_| "nothing within 5 s".to_string())?
            .map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("the daemon closed the stream".into());
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// A daemon sends a side record only to a client that said it reads them. An app built before
/// the record reads its socket as TLV elements and a record would put it out of step for good,
/// so the forwarder installs no route to it: the session Data that asks for one reaches it
/// bare, the route is refused `NotCarried`, and what the app reads stays TLV elements.
#[tokio::test]
async fn a_client_that_has_not_said_it_reads_side_records_is_sent_none() {
    use bytes::Bytes;
    use ndn_app::Connection;
    use ndn_packet::Data;
    use ndn_packet::encode::{DataBuilder, InterestBuilder};
    use ndn_packet::lp::{LpHeaders, SideRoute};
    use ndn_transport::SideClass;
    use std::os::fd::IntoRawFd;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;

    const ID: u64 = 0x1BC5_1DE0_0000_0002;

    let (engine, _shutdown) = EngineBuilder::new(Default::default())
        .build()
        .await
        .expect("build engine");
    let cancel = CancellationToken::new();

    let (engine_s, client_s) = stream_socketpair();
    let face_s = mount_app_face_from_fd(engine_s, &engine, cancel.child_token()).unwrap();
    let (engine_o, old_end) = std::os::unix::net::UnixStream::pair().expect("socket pair");
    old_end.set_nonblocking(true).unwrap();
    mount_app_face_from_fd(engine_o.into_raw_fd(), &engine, cancel.child_token()).unwrap();
    engine
        .fib()
        .add_nexthop(&ndn_packet::name!("/chan"), face_s, 0);
    let sender = IpcConnection::new(ForwarderClient::from_raw_fd(client_s).unwrap());
    sender.open_side();
    let mut old = tokio::net::UnixStream::from_std(old_end).unwrap();
    let mut seen = Vec::new();

    // The old app asks; the sender answers with the route label.
    let name = ndn_packet::name!("/chan/sess/1");
    let ask = InterestBuilder::new(name.clone())
        .lifetime(Duration::from_secs(4))
        .build();
    old.write_all(&ask).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), sender.recv())
        .await
        .expect("the Interest reaches the sender")
        .expect("the sender's connection is open");
    sender
        .send_with(
            DataBuilder::new(name.clone(), b"session").sign_digest_sha256(),
            LpHeaders {
                side_route: Some(SideRoute {
                    id: ID,
                    ttl_secs: 30,
                }),
                ..LpHeaders::default()
            },
        )
        .await
        .unwrap();
    let first = read_element(&mut old, &mut seen)
        .await
        .expect("the old app reads the Data");
    assert_eq!(
        Data::decode(Bytes::from(first)).expect("a bare Data").name,
        name.clone().into(),
        "the old app is sent the session Data as a bare Data, with no route label"
    );
    assert_eq!(
        engine.side().stats().refused_not_carried,
        1,
        "the route to a client that has not said it reads side records is refused"
    );

    // The sender's frame goes nowhere; the old app's stream stays TLV elements.
    let mut frame = vec![0x5A; 100];
    frame[0] = ndn_transport::SIDE_MARKER;
    frame[1] = 0x20;
    frame[2..10].copy_from_slice(&ID.to_be_bytes());
    sender
        .send_side(Bytes::from(frame), SideClass::Datagram)
        .await
        .expect("the sender opted in, so its frame goes to the daemon, which routes it nowhere");
    let name2 = ndn_packet::name!("/chan/sess/2");
    old.write_all(
        &InterestBuilder::new(name2.clone())
            .lifetime(Duration::from_secs(4))
            .build(),
    )
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(5), sender.recv())
        .await
        .expect("the second Interest reaches the sender")
        .expect("the sender's connection is open");
    sender
        .send(DataBuilder::new(name2.clone(), b"again").sign_digest_sha256())
        .await
        .unwrap();
    let second = read_element(&mut old, &mut seen)
        .await
        .expect("the old app's stream is TLV elements, and the Data comes");
    assert_eq!(
        Data::decode(Bytes::from(second)).expect("a bare Data").name,
        name2.into()
    );
    cancel.cancel();
}
