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
//!
//! Audit: `.claude/notes/per-face-option-wiring-triage-2026-05-23.md` (item 1).

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
    let i1 = InterestBuilder::new("/nh/off")
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
    let i2 = InterestBuilder::new("/nh/on")
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
