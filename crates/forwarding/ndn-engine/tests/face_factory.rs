//! End-to-end witness for the data-driven face-construction seam
//! ([`FaceFactory`] → [`EngineBuilder::face_factory`] →
//! [`ForwarderEngine::add_face_of_kind`]).
//!
//! A connectivity resolver holds a *data* record — `(FaceKind::Udp,
//! FaceParams { remote })` — and asks the engine to realise it as a live face
//! with no per-kind code. This test registers the reference
//! [`UdpFaceFactory`](ndn_face::UdpFaceFactory), builds a face from that record,
//! and proves the resulting face is (a) live in the engine's face table and
//! (b) actually carries a datagram to the peer the record named. It also proves
//! the no-factory-registered path returns a typed error.

use std::time::Duration;

use bytes::Bytes;
use ndn_engine::{EngineBuilder, EngineConfig};
use ndn_face::UdpFaceFactory;
use ndn_transport::{FaceError, FaceKind, FaceParams};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

/// Register the reference UDP factory, build a face from a `(kind, params)`
/// record, and prove it is live in the table AND transmits to the named peer.
#[tokio::test]
async fn add_face_of_kind_builds_a_live_udp_face_that_carries_a_packet() {
    // A real UDP peer the factory-built face will reach — this stands in for
    // the neighbor the resolver's record pointed at.
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = peer.local_addr().unwrap();

    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face_factory(Arc::new(UdpFaceFactory))
        .build()
        .await
        .expect("engine build");

    // The data record: nothing but a kind + a remote string.
    let params = FaceParams::remote(peer_addr.to_string());
    let cancel = CancellationToken::new();

    let face_id = engine
        .add_face_of_kind(FaceKind::Udp, &params, cancel.clone())
        .await
        .expect("factory should build the UDP face from the record");

    // (a) The face is live in the engine's face table.
    let face = engine
        .faces()
        .get(face_id)
        .expect("factory-built face must be resident in the table");
    assert_eq!(face.kind(), FaceKind::Udp);

    // (b) It carries a packet: send through the face; the peer receives the
    // datagram on the address the record named. (UDP is an LP-framing kind, so
    // the bytes on the wire are the NDNLPv2 frame — we only assert delivery.)
    let payload = Bytes::from_static(b"\x05\x03ndn");
    face.send_bytes(payload.clone())
        .await
        .expect("send through the factory-built face");

    let mut buf = [0u8; 128];
    let (n, from) = tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut buf))
        .await
        .expect("peer never received the datagram")
        .expect("peer recv_from failed");
    assert!(n > 0, "peer received an empty datagram");
    // The reply came from the face's own bound local address (not the peer).
    assert!(from.ip().is_loopback());

    cancel.cancel();
    shutdown.shutdown().await;
}

/// No factory registered for the requested kind → the typed
/// `FaceError::NoFactory(kind)`, not a panic or a silent no-op.
#[tokio::test]
async fn add_face_of_kind_errors_when_no_factory_registered() {
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face_factory(Arc::new(UdpFaceFactory)) // a Udp factory, but we ask for Tcp
        .build()
        .await
        .expect("engine build");

    let params = FaceParams::remote("127.0.0.1:6363");
    let cancel = CancellationToken::new();

    match engine
        .add_face_of_kind(FaceKind::Tcp, &params, cancel)
        .await
    {
        Err(FaceError::NoFactory(kind)) => assert_eq!(kind, FaceKind::Tcp),
        Err(other) => panic!("expected NoFactory(Tcp), got {other:?}"),
        Ok(_) => panic!("expected an error when no Tcp factory is registered"),
    }

    shutdown.shutdown().await;
}
