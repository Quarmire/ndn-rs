//! Live shared-medium fixtures using real UDP sockets.
//!
//! These are not pure table tests: packets cross kernel UDP sockets, the
//! receiver observes real source addresses via `FaceAddr::Udp`, and the engine
//! decode / forwarding paths consume those addresses.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use dashmap::DashMap;
use ndn_discovery_core::InboundMeta;
use ndn_engine::stages::TlvDecodeStage;
use ndn_engine::{DecodedPacket, DropReason, EngineBuilder, EngineConfig};
use ndn_face_local::InProcFace;
use ndn_face::MulticastUdpFace;
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_packet::fragment::fragment_packet;
use ndn_transport::{FaceAddr, FaceId, FaceTable, Transport};
use tokio::net::UdpSocket;

const CONSUMER: FaceId = FaceId(41);
const SHARED: FaceId = FaceId(42);

async fn recv_timeout(handle: &ndn_face_local::InProcHandle) -> Option<Bytes> {
    tokio::time::timeout(Duration::from_millis(300), handle.recv())
        .await
        .ok()
        .flatten()
}

fn is_nack(wire: &Bytes) -> bool {
    ndn_packet::lp::LpPacket::decode(wire.clone())
        .ok()
        .and_then(|lp| lp.nack)
        .is_some()
}

async fn recv_shared(face: &MulticastUdpFace) -> (Bytes, std::net::SocketAddr) {
    let (wire, addr) = tokio::time::timeout(Duration::from_secs(2), face.recv_bytes_with_addr())
        .await
        .expect("shared-medium receive timed out")
        .expect("shared-medium receive failed");
    let Some(FaceAddr::Udp(src)) = addr else {
        panic!("shared-medium UDP face must surface FaceAddr::Udp");
    };
    (wire, src)
}

fn decode_stage() -> TlvDecodeStage {
    TlvDecodeStage::new(Arc::new(FaceTable::new()), Arc::new(DashMap::new()))
}

/// N.02 live fixture: two real UDP senders share one multi-access receive face.
/// They deliberately use the same LP fragment sequence numbers. Reassembly must
/// key on the FaceAddr-derived endpoint id, not sequence alone or unicast `0`.
#[tokio::test]
async fn n02_live_udp_shared_medium_source_addrs_drive_reassembly() {
    let recv_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let recv_addr = recv_socket.local_addr().unwrap();
    let receiver = MulticastUdpFace::with_socket(SHARED, recv_socket, recv_addr);
    let sender_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sender_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sender_a_addr = sender_a.local_addr().unwrap();
    let sender_b_addr = sender_b.local_addr().unwrap();

    let data_a = DataBuilder::new("/shared/a", &vec![0xA1; 500]).sign_digest_sha256();
    let data_b = DataBuilder::new("/shared/b", &vec![0xB2; 500]).sign_digest_sha256();
    let frags_a = fragment_packet(&data_a, 120, 0);
    let frags_b = fragment_packet(&data_b, 120, 0);
    assert!(
        frags_a.len() > 1 && frags_b.len() > 1,
        "fixtures must fragment"
    );

    let decode = decode_stage();
    let mut got_a = None;
    let mut got_b = None;

    for i in 0..frags_a.len().max(frags_b.len()) {
        if let Some(frag) = frags_a.get(i) {
            sender_a.send_to(frag, recv_addr).await.unwrap();
            let (wire, src) = recv_shared(&receiver).await;
            assert_eq!(src, sender_a_addr);
            let endpoint_id = InboundMeta::udp(src).endpoint_id();
            match decode.decode_inbound(wire, SHARED, 0, endpoint_id) {
                ndn_engine::Action::Continue(ctx) => got_a = Some(ctx),
                ndn_engine::Action::Drop(DropReason::FragmentCollect) => {}
                _ => panic!("unexpected decode action for sender A"),
            }
        }

        if let Some(frag) = frags_b.get(i) {
            sender_b.send_to(frag, recv_addr).await.unwrap();
            let (wire, src) = recv_shared(&receiver).await;
            assert_eq!(src, sender_b_addr);
            let endpoint_id = InboundMeta::udp(src).endpoint_id();
            match decode.decode_inbound(wire, SHARED, 0, endpoint_id) {
                ndn_engine::Action::Continue(ctx) => got_b = Some(ctx),
                ndn_engine::Action::Drop(DropReason::FragmentCollect) => {}
                _ => panic!("unexpected decode action for sender B"),
            }
        }
    }

    match got_a.expect("sender A reassembles").packet {
        DecodedPacket::Data(data) => assert_eq!(data.name.to_string(), "/shared/a"),
        _ => panic!("sender A should reassemble Data"),
    }
    match got_b.expect("sender B reassembles").packet {
        DecodedPacket::Data(data) => assert_eq!(data.name.to_string(), "/shared/b"),
        _ => panic!("sender B should reassemble Data"),
    }
}

/// N.09 live fixture: a Nack arriving from a real UDP source address on a
/// multi-access face is point-to-point feedback and must not propagate to a
/// downstream consumer.
#[tokio::test]
async fn n09_live_udp_shared_medium_nack_is_ignored() {
    let recv_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let recv_addr = recv_socket.local_addr().unwrap();
    let drain_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let shared_dest = drain_socket.local_addr().unwrap();
    let shared_face = MulticastUdpFace::with_socket(SHARED, recv_socket, shared_dest);
    let nack_sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let (consumer_face, consumer) = InProcFace::new(CONSUMER, 128);
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(consumer_face)
        .face(shared_face)
        .build()
        .await
        .expect("engine build");

    let prefix: ndn_packet::Name = "/shared-n09".parse().unwrap();
    engine.fib().add_nexthop(&prefix, SHARED, 0);

    let interest = InterestBuilder::new("/shared-n09/item")
        .lifetime(Duration::from_secs(2))
        .build();
    consumer.send(interest.clone()).await.unwrap();

    let mut buf = vec![0u8; 4096];
    let _forwarded = tokio::time::timeout(Duration::from_secs(2), drain_socket.recv_from(&mut buf))
        .await
        .expect("forwarded Interest did not leave the shared-medium face")
        .expect("drain socket receive failed");

    let nack = ndn_packet::lp::encode_lp_nack(ndn_packet::NackReason::NoRoute, &interest);
    nack_sender.send_to(&nack, recv_addr).await.unwrap();

    let got = recv_timeout(&consumer).await;
    assert!(
        got.as_ref().is_none_or(|wire| !is_nack(wire)),
        "incoming Nack from shared-medium UDP face must not propagate"
    );

    shutdown.shutdown().await;
}
