//! NDNLPv2 `IncomingFaceId` (TLV 0x032C) is gated, per-face, on the
//! `LocalFields` option — matching NFD's `GenericLinkService::encodeLpFields`
//! gate on `m_options.allowLocalFields`
//! (`NFD/daemon/face/generic-link-service.cpp:152`). The value is the
//! *ingress* face the packet arrived on, mirroring NFD's `onIncomingInterest`
//! / `onIncomingData` `IncomingFaceIdTag` (`NFD/daemon/fw/forwarder.cpp:92,301`).
//!
//! This is a **wire-capture** witness, not a grep: each egress face is an
//! `InProcFace` stamped with a network [`FaceKind`] (so the dispatcher
//! LP-frames its egress, `FaceKind::uses_lp_framing() == true`), and the test
//! decodes the *actual NDNLPv2 bytes* the forwarder emits and inspects the
//! decoded `LpPacket::incoming_face_id`.
//!
//! Cross-reference / audit: `docs/notes/incoming-face-id-local-fields-audit-2026-05-23.md`.

use std::time::Duration;

use ndn_engine::{EngineBuilder, EngineConfig};
use ndn_face_local::{InProcFace, InProcHandle};
use ndn_packet::Name;
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_packet::lp::LpPacket;
use ndn_transport::{FaceId, FaceKind};

const FACE_A: u64 = 1; // consumer side: Interest arrives here
const FACE_B: u64 = 2; // producer side: route nexthop

async fn recv_timeout(handle: &InProcHandle) -> Option<bytes::Bytes> {
    tokio::time::timeout(Duration::from_millis(300), handle.recv())
        .await
        .ok()
        .flatten()
}

/// Decode the captured egress wire and return its `IncomingFaceId`, if any.
/// Accepts both a bare Interest/Data (no LP frame at all → `None`) and an
/// LP-framed packet (header present or absent).
fn captured_incoming_face_id(wire: &bytes::Bytes) -> Option<u64> {
    LpPacket::decode(wire.clone())
        .ok()
        .and_then(|lp| lp.incoming_face_id)
}

/// Interest path: a forwarded Interest delivered to the producer face carries
/// `IncomingFaceId` **only** once that face has `LocalFields` enabled, and the
/// value is the *consumer* face the Interest arrived on.
#[tokio::test]
async fn interest_incoming_face_id_gated_on_local_fields() {
    // Network-kind faces so the dispatcher LP-frames egress to them.
    let (face_a, handle_a) = InProcFace::new_kind(FaceId(FACE_A), 128, FaceKind::Tcp);
    let (face_b, handle_b) = InProcFace::new_kind(FaceId(FACE_B), 128, FaceKind::Tcp);

    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(face_a)
        .face(face_b)
        .build()
        .await
        .expect("engine build");

    let prefix: Name = "/lf".parse().unwrap();
    engine.fib().add_nexthop(&prefix, FaceId(FACE_B), 0);

    // (1) Default: LocalFields off on the producer face → no IncomingFaceId.
    let i1 = InterestBuilder::new("/lf/off")
        .lifetime(Duration::from_secs(2))
        .build();
    handle_a.send(i1).await.expect("inject interest 1");
    let egress = recv_timeout(&handle_b)
        .await
        .expect("forwarded interest reaches producer face");
    assert_eq!(
        captured_incoming_face_id(&egress),
        None,
        "IncomingFaceId must be absent by default (LocalFields off)"
    );

    // (2) Enable LocalFields on the producer face (the runtime toggle
    //     faces/update drives) → IncomingFaceId == the ingress (consumer) face.
    engine.set_local_fields(FaceId(FACE_B), true);
    let i2 = InterestBuilder::new("/lf/on")
        .lifetime(Duration::from_secs(2))
        .build();
    handle_a.send(i2).await.expect("inject interest 2");
    let egress = recv_timeout(&handle_b)
        .await
        .expect("forwarded interest reaches producer face");
    assert_eq!(
        captured_incoming_face_id(&egress),
        Some(FACE_A),
        "IncomingFaceId must equal the true ingress FaceId once LocalFields is on"
    );

    shutdown.shutdown().await;
}

/// Data path: Data returned to a consumer face carries `IncomingFaceId` only
/// when that face has `LocalFields` enabled, and the value is the *producer*
/// face the Data arrived on (NFD `onIncomingData` semantics).
#[tokio::test]
async fn data_incoming_face_id_is_producer_ingress_face() {
    let (face_a, handle_a) = InProcFace::new_kind(FaceId(FACE_A), 128, FaceKind::Tcp);
    let (face_b, handle_b) = InProcFace::new_kind(FaceId(FACE_B), 128, FaceKind::Tcp);

    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(face_a)
        .face(face_b)
        .build()
        .await
        .expect("engine build");

    let prefix: Name = "/lf".parse().unwrap();
    engine.fib().add_nexthop(&prefix, FaceId(FACE_B), 0);

    // Consumer face wants local fields on the Data it receives.
    engine.set_local_fields(FaceId(FACE_A), true);

    // Consumer Interest → forwarded to producer, PIT entry recorded.
    let interest = InterestBuilder::new("/lf/data")
        .lifetime(Duration::from_secs(2))
        .build();
    handle_a.send(interest).await.expect("inject interest");
    let _ = recv_timeout(&handle_b)
        .await
        .expect("interest reaches producer face");

    // Producer Data → satisfies PIT, delivered to consumer with IncomingFaceId
    // = the producer face the Data arrived on.
    let data = DataBuilder::new("/lf/data", b"payload").sign_digest_sha256();
    handle_b.send(data).await.expect("inject data");
    let egress = recv_timeout(&handle_a)
        .await
        .expect("data delivered to consumer face");
    assert_eq!(
        captured_incoming_face_id(&egress),
        Some(FACE_B),
        "Data delivered to a LocalFields consumer must carry the producer ingress FaceId"
    );

    shutdown.shutdown().await;
}
