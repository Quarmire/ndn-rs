//! NDNLPv2 ForwardingHint forwarding (NFD onIncomingInterest + NetworkRegionTable).
//! An Interest whose name has no route is forwarded toward its forwarding-hint
//! delegation instead — unless the hint has reached a configured producer
//! region, in which case the hint is stripped and the Interest name is used.

use std::time::Duration;

use ndn_engine::{EngineBuilder, EngineConfig};
use ndn_face_local::{InProcFace, InProcHandle};
use ndn_packet::Name;
use ndn_packet::encode::InterestBuilder;
use ndn_transport::FaceId;

const CONSUMER: u64 = 1;
const TARGET: u64 = 2;

async fn recv_timeout(h: &InProcHandle) -> Option<bytes::Bytes> {
    tokio::time::timeout(Duration::from_millis(300), h.recv())
        .await
        .ok()
        .flatten()
}

fn is_interest(wire: &bytes::Bytes) -> bool {
    use ndn_packet::lp::LpPacket;
    wire.first() == Some(&0x05)
        || LpPacket::decode(wire.clone())
            .ok()
            .and_then(|lp| lp.fragment)
            .is_some_and(|f| f.first() == Some(&0x05))
}

/// No route for the Interest name, but a route for the hint delegation → the
/// Interest is forwarded toward the delegation.
#[tokio::test]
async fn forwarding_hint_routes_by_delegation() {
    let (fc, hc) = InProcFace::new(FaceId(CONSUMER), 128);
    let (ft, ht) = InProcFace::new(FaceId(TARGET), 128);
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(fc)
        .face(ft)
        .build()
        .await
        .expect("engine build");
    // Route only for the hint delegation; the Interest name is unrouted.
    let hint: Name = "/hint".parse().unwrap();
    engine.fib().add_nexthop(&hint, FaceId(TARGET), 0);

    let i = InterestBuilder::new("/app/data")
        .lifetime(Duration::from_secs(2))
        .forwarding_hint(vec![hint])
        .build();
    hc.send(i).await.unwrap();

    assert!(
        recv_timeout(&ht).await.as_ref().is_some_and(is_interest),
        "Interest must be forwarded toward the forwarding-hint delegation"
    );
    shutdown.shutdown().await;
}

/// With the delegation inside a configured producer region, the hint is
/// stripped → the (unrouted) Interest name is used → no route → not forwarded.
#[tokio::test]
async fn forwarding_hint_stripped_in_producer_region() {
    let cfg = EngineConfig {
        network_region: vec!["/hint".parse().unwrap()],
        ..Default::default()
    };
    let (fc, hc) = InProcFace::new(FaceId(CONSUMER), 128);
    let (ft, ht) = InProcFace::new(FaceId(TARGET), 128);
    let (engine, shutdown) = EngineBuilder::new(cfg)
        .face(fc)
        .face(ft)
        .build()
        .await
        .expect("engine build");
    let hint: Name = "/hint".parse().unwrap();
    engine.fib().add_nexthop(&hint, FaceId(TARGET), 0);

    let i = InterestBuilder::new("/app/data")
        .lifetime(Duration::from_secs(2))
        .forwarding_hint(vec![hint])
        .build();
    hc.send(i).await.unwrap();

    assert!(
        recv_timeout(&ht).await.is_none(),
        "in producer region the hint is stripped; unrouted Interest name is not forwarded"
    );
    shutdown.shutdown().await;
}
