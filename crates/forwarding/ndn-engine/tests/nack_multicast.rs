//! Under the multicast strategy a Nack from an upstream reaches the consumer once no upstream
//! is left that may still answer (NFD `ProcessNackTraditional`: a strategy that does not retry
//! tells the downstream when every upstream it forwarded to has Nacked, with the least severe
//! reason among them). Multicast sent the Interest to every upstream, so it has no one to fail
//! over to: before this a Nack under it was suppressed and the consumer's Interest timed out
//! (`Congestion`, `NotYet` and `Duplicate` are what an application says it is over rate or
//! cannot answer yet; a timeout told it nothing).
//!
//! Faces: `CONSUMER` asks `/t/x`; `UP_A` and `UP_B` are the FIB's nexthops for `/t`.

use std::time::Duration;

use bytes::Bytes;
use ndn_engine::{EngineBuilder, EngineConfig, ShutdownHandle};
use ndn_face_local::{InProcFace, InProcHandle};
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_packet::lp::{LpPacket, encode_lp_nack};
use ndn_packet::{Data, Interest, NackReason, Name};
use ndn_transport::FaceId;

const CONSUMER: u64 = 1;
const UP_A: u64 = 2;
const UP_B: u64 = 3;

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

async fn recv_timeout(h: &InProcHandle, ms: u64) -> Option<Bytes> {
    tokio::time::timeout(Duration::from_millis(ms), h.recv())
        .await
        .ok()
        .flatten()
}

/// The bare packet a face was handed: the payload of an LP frame without a Nack, or the wire
/// itself.
fn payload(wire: &Bytes) -> Option<Bytes> {
    match LpPacket::decode(wire.clone()) {
        Ok(lp) if lp.nack.is_none() => lp.fragment,
        Ok(_) => None,
        Err(_) => Some(wire.clone()),
    }
}

fn interest_of(wire: &Bytes) -> Interest {
    Interest::decode(payload(wire).expect("an Interest")).expect("a decodable Interest")
}

fn is_data(wire: &Bytes) -> bool {
    payload(wire).is_some_and(|p| Data::decode(p).is_ok())
}

fn nack_reason(wire: &Bytes) -> Option<NackReason> {
    LpPacket::decode(wire.clone()).ok()?.nack?.reason
}

struct Rig {
    consumer: InProcHandle,
    up_a: InProcHandle,
    up_b: InProcHandle,
    /// The Interest as each upstream received it (the forwarder's own).
    at_a: Interest,
    at_b: Option<Interest>,
    shutdown: ShutdownHandle,
}

/// `CONSUMER` asks `/t/x` (4 s) under the multicast strategy; the FIB routes `/t` to `UP_A`,
/// and to `UP_B` when `two`. Each upstream receives the forwarded Interest.
async fn rig(two: bool) -> Rig {
    let (consumer_face, consumer) = InProcFace::new(FaceId(CONSUMER), 64);
    let (a_face, up_a) = InProcFace::new(FaceId(UP_A), 64);
    let (b_face, up_b) = InProcFace::new(FaceId(UP_B), 64);
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(consumer_face)
        .face(a_face)
        .face(b_face)
        .build()
        .await
        .expect("engine build");
    let multicast = ndn_strategy::registry::create_by_name(b"multicast")
        .expect("multicast strategy registered");
    engine.strategy_table().insert(&n("/"), multicast);
    engine.fib().add_nexthop(&n("/t"), FaceId(UP_A), 0);
    if two {
        engine.fib().add_nexthop(&n("/t"), FaceId(UP_B), 0);
    }
    let interest = InterestBuilder::new(n("/t/x"))
        .lifetime(Duration::from_secs(4))
        .build();
    consumer.send(interest).await.expect("send Interest");
    let at_a = recv_timeout(&up_a, 1000)
        .await
        .expect("the Interest reaches the first upstream");
    let at_b = if two {
        let wire = recv_timeout(&up_b, 1000)
            .await
            .expect("the Interest reaches the second upstream");
        Some(interest_of(&wire))
    } else {
        None
    };
    Rig {
        consumer,
        up_a,
        up_b,
        at_a: interest_of(&at_a),
        at_b,
        shutdown,
    }
}

/// With one upstream the Nack it sends is the consumer's answer, whatever its reason: a
/// `Congestion` says "slower", which the consumer's application tells its user.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lone_upstreams_nack_reaches_the_consumer() {
    let rig = rig(false).await;
    rig.up_a
        .send(encode_lp_nack(NackReason::Congestion, rig.at_a.raw()))
        .await
        .expect("send Nack");
    let got = recv_timeout(&rig.consumer, 1000)
        .await
        .expect("the consumer hears back (not a timeout)");
    assert_eq!(nack_reason(&got), Some(NackReason::Congestion));
    rig.shutdown.shutdown().await;
}

/// One upstream refusing is not the end while another may still answer: the consumer hears
/// nothing yet, and the other's Data satisfies it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_of_two_upstreams_nacking_leaves_the_fetch_to_the_other() {
    let rig = rig(true).await;
    rig.up_a
        .send(encode_lp_nack(NackReason::NoRoute, rig.at_a.raw()))
        .await
        .expect("send Nack");
    assert!(
        recv_timeout(&rig.consumer, 400).await.is_none(),
        "the consumer was told while the second upstream could still answer"
    );
    let data = DataBuilder::new(n("/t/x"), b"payload").sign_digest_sha256();
    rig.up_b.send(data).await.expect("send Data");
    let got = recv_timeout(&rig.consumer, 1000)
        .await
        .expect("the consumer hears back");
    assert!(is_data(&got), "the other upstream's Data reaches it");
    rig.shutdown.shutdown().await;
}

/// Every upstream refusing is told, with the least severe reason: the one that says "ask again"
/// beats the one that says "no route".
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_upstream_nacking_tells_the_consumer_the_least_severe_reason() {
    let rig = rig(true).await;
    let at_b = rig.at_b.as_ref().expect("two upstreams");
    rig.up_a
        .send(encode_lp_nack(NackReason::NoRoute, rig.at_a.raw()))
        .await
        .expect("send Nack");
    rig.up_b
        .send(encode_lp_nack(NackReason::Congestion, at_b.raw()))
        .await
        .expect("send Nack");
    let got = recv_timeout(&rig.consumer, 1000)
        .await
        .expect("the consumer hears back (not a timeout)");
    assert_eq!(nack_reason(&got), Some(NackReason::Congestion));
    rig.shutdown.shutdown().await;
}
