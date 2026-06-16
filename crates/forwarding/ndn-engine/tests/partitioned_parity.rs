//! Phase 1 witness for the partitioned forwarding data-plane runtime.
//!
//! Runs the same Interest→forward and Data→satisfy exchange as
//! `forwarding_conformance::native_data_satisfies_pit_to_consumer`, but with
//! `EngineConfig::data_plane = Partitioned { workers: 1 }`. The single-worker
//! partitioned runtime must reach the identical observable outcome as the
//! shared runtime — proving the decode-in-RX → worker → `forward_decoded` seam
//! introduces no semantic change. See
//! `.claude/notes/partitioned-fwd-design-2026-05-24.md`.
#![cfg(feature = "partitioned-fwd")]

use std::time::Duration;

use ndn_engine::{DataPlane, EngineBuilder, EngineConfig};
use ndn_face_local::{InProcFace, InProcHandle};
use ndn_packet::Name;
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_transport::FaceId;

const FACE_A: u64 = 1; // consumer side
const FACE_B: u64 = 2; // producer side (the route points here)
const FACE_C: u64 = 3; // second consumer (aggregation test)

const T_INTEREST: u8 = 0x05;
const T_DATA: u8 = 0x06;

async fn recv_timeout(handle: &InProcHandle) -> Option<bytes::Bytes> {
    tokio::time::timeout(Duration::from_millis(300), handle.recv())
        .await
        .ok()
        .flatten()
}

fn is_forwarded(wire: &bytes::Bytes, tlv_type: u8) -> bool {
    use ndn_packet::lp::LpPacket;
    if wire.first() == Some(&tlv_type) {
        return true;
    }
    if let Ok(lp) = LpPacket::decode(wire.clone()) {
        if lp.nack.is_some() {
            return false; // a Nack is a drop, not a forward
        }
        if let Some(frag) = lp.fragment {
            return frag.first() == Some(&tlv_type);
        }
    }
    false
}

#[tokio::test]
async fn partitioned_n1_forwards_interest_and_satisfies_data() {
    let (face_a, handle_a) = InProcFace::new(FaceId(FACE_A), 128);
    let (face_b, handle_b) = InProcFace::new(FaceId(FACE_B), 128);

    let config = EngineConfig {
        data_plane: DataPlane::Partitioned { workers: 1 },
        ..Default::default()
    };
    let (engine, shutdown) = EngineBuilder::new(config)
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
            .is_some_and(|w| is_forwarded(w, T_INTEREST)),
        "partitioned (N=1): Interest must reach the producer face"
    );

    // Producer (face B) Data → satisfies the PIT, delivered to consumer (face A).
    let data = DataBuilder::new("/conf/data", b"payload").sign_digest_sha256();
    handle_b.send(data).await.expect("inject data");
    assert!(
        recv_timeout(&handle_a)
            .await
            .as_ref()
            .is_some_and(|w| is_forwarded(w, T_DATA)),
        "partitioned (N=1): Data must return to the consumer"
    );

    shutdown.shutdown().await;
}

#[tokio::test]
async fn partitioned_n4_forwards_interest_and_satisfies_data() {
    let (face_a, handle_a) = InProcFace::new(FaceId(FACE_A), 128);
    let (face_b, handle_b) = InProcFace::new(FaceId(FACE_B), 128);

    let config = EngineConfig {
        data_plane: DataPlane::Partitioned { workers: 4 },
        ..Default::default()
    };
    let (engine, shutdown) = EngineBuilder::new(config)
        .face(face_a)
        .face(face_b)
        .build()
        .await
        .expect("engine build");

    engine
        .fib()
        .add_nexthop(&"/conf".parse::<Name>().unwrap(), FaceId(FACE_B), 0);

    let interest = InterestBuilder::new("/conf/data")
        .lifetime(Duration::from_secs(2))
        .build();
    handle_a.send(interest).await.expect("inject interest");
    assert!(
        recv_timeout(&handle_b)
            .await
            .as_ref()
            .is_some_and(|w| is_forwarded(w, T_INTEREST)),
        "partitioned (N=4): Interest must reach the producer face"
    );

    let data = DataBuilder::new("/conf/data", b"payload").sign_digest_sha256();
    handle_b.send(data).await.expect("inject data");
    assert!(
        recv_timeout(&handle_a)
            .await
            .as_ref()
            .is_some_and(|w| is_forwarded(w, T_DATA)),
        "partitioned (N=4): Data must return to the consumer"
    );

    shutdown.shutdown().await;
}

/// Two consumers Interesting the same name must aggregate to a single upstream
/// Interest and both be satisfied by one Data — even with N>1 workers. The NDT
/// routes identical names to the same worker, so PIT aggregation holds.
#[tokio::test]
async fn partitioned_aggregates_same_name_across_workers() {
    let (face_a, handle_a) = InProcFace::new(FaceId(FACE_A), 128);
    let (face_b, handle_b) = InProcFace::new(FaceId(FACE_B), 128);
    let (face_c, handle_c) = InProcFace::new(FaceId(FACE_C), 128);

    let config = EngineConfig {
        data_plane: DataPlane::Partitioned { workers: 4 },
        ..Default::default()
    };
    let (engine, shutdown) = EngineBuilder::new(config)
        .face(face_a)
        .face(face_b)
        .face(face_c)
        .build()
        .await
        .expect("engine build");

    engine
        .fib()
        .add_nexthop(&"/conf".parse::<Name>().unwrap(), FaceId(FACE_B), 0);

    let mk = || {
        InterestBuilder::new("/conf/data")
            .lifetime(Duration::from_secs(2))
            .build()
    };

    // Consumer A → forwarded upstream (one Interest to producer B).
    handle_a.send(mk()).await.expect("inject A");
    assert!(
        recv_timeout(&handle_b)
            .await
            .as_ref()
            .is_some_and(|w| is_forwarded(w, T_INTEREST)),
        "first Interest must reach producer"
    );

    // Consumer C → same name while A's PIT entry is live → aggregated, NOT a
    // second upstream Interest.
    handle_c.send(mk()).await.expect("inject C");
    assert!(
        recv_timeout(&handle_b).await.is_none(),
        "second same-name Interest must be aggregated, not forwarded again"
    );

    // One Data satisfies both downstream faces.
    let data = DataBuilder::new("/conf/data", b"payload").sign_digest_sha256();
    handle_b.send(data).await.expect("inject data");
    assert!(
        recv_timeout(&handle_a)
            .await
            .as_ref()
            .is_some_and(|w| is_forwarded(w, T_DATA)),
        "Data must reach consumer A"
    );
    assert!(
        recv_timeout(&handle_c)
            .await
            .as_ref()
            .is_some_and(|w| is_forwarded(w, T_DATA)),
        "Data must reach consumer C (aggregated in-record)"
    );

    shutdown.shutdown().await;
}
