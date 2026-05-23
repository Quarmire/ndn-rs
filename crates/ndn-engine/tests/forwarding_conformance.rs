//! Cross-impl forwarding conformance — native engine side.
//!
//! Drives the shared decision vectors in `ndn_fwd_core::conformance` through a
//! real `ForwarderEngine` with two in-process faces, and asserts the engine's
//! observable forward/drop outcome matches the sans-io `decide_interest`
//! prediction. The sans-io side of the same vectors is pinned in
//! `ndn-fwd-core`'s `decide_interest_matches_conformance_vectors` test.
//!
//! The native engine and the embedded forwarder have deliberately different
//! execution architectures (multi-stage async + lock-free `Arc` tables vs
//! single-threaded `&mut` sans-IO), so they cannot share the storage-trait
//! orchestration. This behavioural pin is what guarantees they do not diverge
//! on forwarding *semantics* regardless.

use std::time::Duration;

use ndn_engine::{EngineBuilder, EngineConfig};
use ndn_face_local::{InProcFace, InProcHandle};
use ndn_fwd_core::conformance::INTEREST_DECISION_CASES;
use ndn_packet::Name;
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_transport::FaceId;

const FACE_A: u64 = 1; // the Interest arrives here
const FACE_B: u64 = 2; // a non-split-horizon route points here

async fn recv_timeout(handle: &InProcHandle) -> Option<bytes::Bytes> {
    tokio::time::timeout(Duration::from_millis(300), handle.recv())
        .await
        .ok()
        .flatten()
}

/// Whether `wire` is a forwarded Interest (a bare Interest TLV, or an NDNLP
/// packet carrying an Interest fragment) — as opposed to a Nack sent back to
/// the incoming face, which is a *drop* signal, not a forward.
fn is_forwarded_interest(wire: &bytes::Bytes) -> bool {
    use ndn_packet::lp::LpPacket;
    const T_INTEREST: u8 = 0x05;
    if wire.first() == Some(&T_INTEREST) {
        return true;
    }
    if let Ok(lp) = LpPacket::decode(wire.clone()) {
        if lp.nack.is_some() {
            return false; // a Nack is a drop, not a forward
        }
        if let Some(frag) = lp.fragment {
            return frag.first() == Some(&T_INTEREST);
        }
    }
    false
}

/// Whether `wire` is a forwarded Data (bare Data TLV, or an NDNLP packet
/// carrying a Data fragment).
fn is_forwarded_data(wire: &bytes::Bytes) -> bool {
    use ndn_packet::lp::LpPacket;
    const T_DATA: u8 = 0x06;
    if wire.first() == Some(&T_DATA) {
        return true;
    }
    if let Ok(lp) = LpPacket::decode(wire.clone()) {
        if lp.nack.is_some() {
            return false;
        }
        if let Some(frag) = lp.fragment {
            return frag.first() == Some(&T_DATA);
        }
    }
    false
}

#[tokio::test]
async fn native_interest_decision_conformance() {
    for case in INTEREST_DECISION_CASES {
        let (face_a, handle_a) = InProcFace::new(FaceId(FACE_A), 128);
        let (face_b, handle_b) = InProcFace::new(FaceId(FACE_B), 128);

        let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
            .face(face_a)
            .face(face_b)
            .build()
            .await
            .expect("engine build");

        let prefix: Name = "/conf".parse().unwrap();
        if case.has_route {
            let nexthop = if case.route_to_incoming {
                FaceId(FACE_A)
            } else {
                FaceId(FACE_B)
            };
            engine.fib().add_nexthop(&prefix, nexthop, 0);
        }

        let mut ib = InterestBuilder::new("/conf/data");
        if let Some(h) = case.hop_limit {
            ib = ib.hop_limit(h);
        }
        let wire = ib.lifetime(Duration::from_secs(2)).build();
        handle_a.send(wire).await.expect("inject interest");

        // The Interest forwards out its nexthop face: face B normally, or back
        // out face A only if the (split-horizon) route points at the incoming
        // face — which best-route must suppress.
        let target = if case.route_to_incoming {
            &handle_a
        } else {
            &handle_b
        };
        let forwarded = recv_timeout(target)
            .await
            .as_ref()
            .is_some_and(is_forwarded_interest);

        assert_eq!(
            forwarded, case.expect_forward,
            "native engine disagreed with decide_interest on: {}",
            case.desc
        );

        shutdown.shutdown().await;
    }
}

/// Data path: a Data matching a pending Interest is satisfied back to the
/// recorded consumer face — the native mirror of `decide_data` → `Satisfied`.
#[tokio::test]
async fn native_data_satisfies_pit_to_consumer() {
    let (face_a, handle_a) = InProcFace::new(FaceId(FACE_A), 128);
    let (face_b, handle_b) = InProcFace::new(FaceId(FACE_B), 128);
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(face_a)
        .face(face_b)
        .build()
        .await
        .expect("engine build");

    let prefix: Name = "/conf".parse().unwrap();
    engine.fib().add_nexthop(&prefix, FaceId(FACE_B), 0);

    // Consumer (face A) Interest → forwarded to producer (face B), PIT entry in.
    let interest = InterestBuilder::new("/conf/data")
        .lifetime(Duration::from_secs(2))
        .build();
    handle_a.send(interest).await.expect("inject interest");
    assert!(
        recv_timeout(&handle_b)
            .await
            .as_ref()
            .is_some_and(is_forwarded_interest),
        "interest must reach the producer face"
    );

    // Producer (face B) Data → satisfies the PIT, delivered to consumer (face A).
    let data = DataBuilder::new("/conf/data", b"payload").sign_digest_sha256();
    handle_b.send(data).await.expect("inject data");
    assert!(
        recv_timeout(&handle_a)
            .await
            .as_ref()
            .is_some_and(is_forwarded_data),
        "Data must be delivered to the consumer (decide_data: Satisfied)"
    );

    shutdown.shutdown().await;
}

/// Data path: a Data with no pending Interest is unsolicited — dropped, not
/// delivered. The native mirror of `decide_data` → `Unsolicited`.
#[tokio::test]
async fn native_unsolicited_data_dropped() {
    let (face_a, handle_a) = InProcFace::new(FaceId(FACE_A), 128);
    let (face_b, handle_b) = InProcFace::new(FaceId(FACE_B), 128);
    let (_engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(face_a)
        .face(face_b)
        .build()
        .await
        .expect("engine build");

    // No prior Interest → no PIT entry.
    let data = DataBuilder::new("/conf/unsolicited", b"payload").sign_digest_sha256();
    handle_b.send(data).await.expect("inject data");
    assert!(
        recv_timeout(&handle_a).await.is_none(),
        "unsolicited Data must be dropped, not delivered"
    );

    shutdown.shutdown().await;
}
