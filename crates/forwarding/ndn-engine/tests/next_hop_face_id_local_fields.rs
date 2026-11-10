//! NDNLPv2 `NextHopFaceId` (TLV 0x0330) is a *privileged* ingress local field:
//! the forwarder honours it only from a face that opted into `LocalFields`,
//! mirroring NFD's `GenericLinkService` which DROPs a received NextHopFaceId
//! unless `m_options.allowLocalFields` (`NFD/daemon/face/generic-link-service.cpp:362-370`).
//! Without the gate, any unprivileged peer could steer forwarding by injecting
//! the header.
//!
//! Witness shape (wire-level, like `incoming_face_id_local_fields`): a consumer
//! face pins an Interest to face B via `InterestBuilder::pin_face` (the same LP
//! header `Consumer::fetch_on` / NLSR emit). A FIB route for the prefix points
//! at a *different* face C. The pin must override the FIB **only** once the
//! ingress face has LocalFields enabled.

use std::time::Duration;

use ndn_engine::{EngineBuilder, EngineConfig};
use ndn_face_local::{InProcFace, InProcHandle};
use ndn_packet::Name;
use ndn_packet::encode::InterestBuilder;
use ndn_transport::FaceId;

const FACE_A: u64 = 1; // consumer: pinned Interest ingresses here
const FACE_B: u64 = 2; // NextHopFaceId pin target
const FACE_C: u64 = 3; // FIB nexthop (decoy: where the Interest goes if pin ignored)

async fn recv_timeout(handle: &InProcHandle) -> Option<bytes::Bytes> {
    tokio::time::timeout(Duration::from_millis(300), handle.recv())
        .await
        .ok()
        .flatten()
}

fn is_interest(wire: &bytes::Bytes) -> bool {
    use ndn_packet::lp::LpPacket;
    const T_INTEREST: u8 = 0x05;
    if wire.first() == Some(&T_INTEREST) {
        return true;
    }
    match LpPacket::decode(wire.clone()) {
        Ok(lp) if lp.nack.is_none() => lp
            .fragment
            .as_ref()
            .is_some_and(|f| f.first() == Some(&T_INTEREST)),
        _ => false,
    }
}

/// NextHopFaceId is ignored by default (no LocalFields) and honoured once the
/// ingress face opts in — the value overriding the FIB nexthop.
#[tokio::test]
async fn next_hop_face_id_gated_on_local_fields() {
    let (face_a, handle_a) = InProcFace::new(FaceId(FACE_A), 128);
    let (face_b, handle_b) = InProcFace::new(FaceId(FACE_B), 128);
    let (face_c, handle_c) = InProcFace::new(FaceId(FACE_C), 128);

    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(face_a)
        .face(face_b)
        .face(face_c)
        .build()
        .await
        .expect("engine build");

    // FIB points the prefix at face C; the NextHopFaceId pin targets face B.
    let prefix: Name = "/nh".parse().unwrap();
    engine.fib().add_nexthop(&prefix, FaceId(FACE_C), 0);

    // (1) Default: LocalFields off on the ingress face → NextHopFaceId ignored,
    //     Interest follows the FIB to C, not the pinned face B.
    let i1 = InterestBuilder::new(ndn_packet::name!("/nh/off"))
        .lifetime(Duration::from_secs(2))
        .pin_face(FACE_B)
        .build();
    handle_a.send(i1).await.expect("inject pinned interest 1");
    assert!(
        recv_timeout(&handle_c)
            .await
            .as_ref()
            .is_some_and(is_interest),
        "without LocalFields, the Interest must follow the FIB to face C"
    );
    assert!(
        recv_timeout(&handle_b).await.is_none(),
        "without LocalFields, the NextHopFaceId pin to face B must be ignored"
    );

    // (2) Enable LocalFields on the ingress face → NextHopFaceId honoured,
    //     overriding the FIB: the Interest goes to the pinned face B.
    engine.set_local_fields(FaceId(FACE_A), true);
    let i2 = InterestBuilder::new(ndn_packet::name!("/nh/on"))
        .lifetime(Duration::from_secs(2))
        .pin_face(FACE_B)
        .build();
    handle_a.send(i2).await.expect("inject pinned interest 2");
    assert!(
        recv_timeout(&handle_b)
            .await
            .as_ref()
            .is_some_and(is_interest),
        "with LocalFields, NextHopFaceId must override the FIB and reach face B"
    );

    shutdown.shutdown().await;
}

/// LocalFields lets a face choose the next hop, so only a program face may
/// have it. A validated face (a loopback TCP client: any user of the host can
/// open it) whose LocalFields bit is on anyway — set through any path other
/// than the management gate, which refuses it — still does not pin the next
/// hop: the Interest follows the FIB.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn next_hop_face_id_is_ignored_from_a_validated_face_with_local_fields_on() {
    let (face_b, handle_b) = InProcFace::new(FaceId(FACE_B), 128);
    let (face_c, handle_c) = InProcFace::new(FaceId(FACE_C), 128);
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(face_b)
        .face(face_c)
        .build()
        .await
        .expect("engine build");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (client, accepted) = tokio::join!(
        ndn_face::tcp_face_connect(FaceId(0), addr),
        listener.accept()
    );
    let (stream, _) = accepted.unwrap();
    engine.add_face(
        ndn_face::tcp_face_from_stream(FaceId(FACE_A), stream),
        tokio_util::sync::CancellationToken::new(),
    );
    let client = ndn_transport::Face::from_transport(client.unwrap());
    engine.set_local_fields(FaceId(FACE_A), true);

    let prefix: Name = "/nh".parse().unwrap();
    engine.fib().add_nexthop(&prefix, FaceId(FACE_C), 0);

    let pinned = InterestBuilder::new(ndn_packet::name!("/nh/validated"))
        .lifetime(Duration::from_secs(2))
        .pin_face(FACE_B)
        .build();
    client
        .transport
        .send_bytes(pinned)
        .await
        .expect("send the pinned Interest");
    assert!(
        recv_timeout(&handle_c)
            .await
            .as_ref()
            .is_some_and(is_interest),
        "the Interest from a validated face must follow the FIB to face C"
    );
    assert!(
        recv_timeout(&handle_b).await.is_none(),
        "a validated face pinned the next hop with NextHopFaceId"
    );

    shutdown.shutdown().await;
}
