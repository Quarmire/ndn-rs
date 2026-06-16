//! NFD `NInNacks` / `NOutNacks` face counters (`faces/list`). NFD increments
//! these in `LinkService::receiveNack`/`sendNack` (link-service.cpp:103,73);
//! ndn-rs previously reported them hardcoded `0`.
//!
//! - `in_nacks`: a Nack received on a face is counted at decode.
//! - `out_nacks`: a Nack the forwarder sends (e.g. NoRoute) is counted on egress.

use std::sync::atomic::Ordering;
use std::time::Duration;

use ndn_engine::{EngineBuilder, EngineConfig};
use ndn_face_local::InProcFace;
use ndn_packet::NackReason;
use ndn_packet::encode::InterestBuilder;
use ndn_packet::lp::encode_lp_nack;
use ndn_transport::FaceId;

const FACE_A: u64 = 1;

#[tokio::test]
async fn in_and_out_nacks_are_counted() {
    let (face_a, handle_a) = InProcFace::new(FaceId(FACE_A), 128);
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(face_a)
        .build()
        .await
        .expect("engine build");

    // (1) out_nacks: an Interest with no FIB route → forwarder Nacks back on the
    //     ingress face.
    let interest = InterestBuilder::new("/unrouted/data")
        .lifetime(Duration::from_secs(2))
        .build();
    handle_a.send(interest).await.expect("inject interest");
    let _ = tokio::time::timeout(Duration::from_millis(300), handle_a.recv()).await;

    // (2) in_nacks: inject a Nack wire on face A.
    let interest_wire = InterestBuilder::new("/some/interest")
        .lifetime(Duration::from_secs(2))
        .build();
    let nack_wire = encode_lp_nack(NackReason::NoRoute, &interest_wire);
    handle_a.send(nack_wire).await.expect("inject nack");
    tokio::time::sleep(Duration::from_millis(100)).await;

    let states = engine.face_states();
    let s = states.get(&FaceId(FACE_A)).expect("face A state");
    assert_eq!(
        s.counters.in_nacks.load(Ordering::Relaxed),
        1,
        "a received Nack must increment NInNacks"
    );
    assert_eq!(
        s.counters.out_nacks.load(Ordering::Relaxed),
        1,
        "a NoRoute Nack sent back must increment NOutNacks"
    );

    shutdown.shutdown().await;
}
