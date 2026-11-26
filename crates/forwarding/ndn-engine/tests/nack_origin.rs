//! A Nack is accepted only from a face that holds an out-record for the PIT
//! entry it names, and only with the nonce that out-record last sent (NFD
//! `Forwarder::onIncomingNack`: no out-record → drop; nonce differs → drop).
//! Without the check, any face could end a pending fetch ("no route",
//! "duplicate") or steer the forwarder's failover by naming a pending
//! Interest, and the forwarder would forward the Interest the stranger's Nack
//! embedded rather than its own.
//!
//! Faces: `CONSUMER` asks `/t/x`; `UPSTREAM` is the FIB's first nexthop,
//! `SPARE` the second (failover); `STRANGER` is a network face with no route
//! and no out-record.

use std::time::Duration;

use bytes::Bytes;
use ndn_engine::{EngineBuilder, EngineConfig, ShutdownHandle};
use ndn_face_local::{InProcFace, InProcHandle};
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_packet::lp::{LpPacket, encode_lp_nack};
use ndn_packet::{Data, Interest, NackReason, Name};
use ndn_transport::{FaceId, FaceKind};

const CONSUMER: u64 = 1;
const UPSTREAM: u64 = 2;
const SPARE: u64 = 3;
const STRANGER: u64 = 4;

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

async fn recv_timeout(h: &InProcHandle, ms: u64) -> Option<Bytes> {
    tokio::time::timeout(Duration::from_millis(ms), h.recv())
        .await
        .ok()
        .flatten()
}

/// The bare packet a face was handed: the payload of an LP frame without a
/// Nack, or the wire itself.
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
    upstream: InProcHandle,
    spare: InProcHandle,
    stranger: InProcHandle,
    engine: ndn_engine::ForwarderEngine,
    /// The Interest as `UPSTREAM` received it (the forwarder's own).
    forwarded: Interest,
    shutdown: ShutdownHandle,
}

/// `CONSUMER` asks `/t/x` (4 s); the FIB routes `/t` to `UPSTREAM`, and also
/// to `SPARE` when `failover`. `UPSTREAM` receives the forwarded Interest.
async fn rig(failover: bool) -> Rig {
    let (consumer_face, consumer) = InProcFace::new(FaceId(CONSUMER), 64);
    let (up_face, upstream) = InProcFace::new(FaceId(UPSTREAM), 64);
    let (spare_face, spare) = InProcFace::new(FaceId(SPARE), 64);
    let (stranger_face, stranger) = InProcFace::new_kind(FaceId(STRANGER), 64, FaceKind::Tcp);
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(consumer_face)
        .face(up_face)
        .face(spare_face)
        .face(stranger_face)
        .build()
        .await
        .expect("engine build");
    engine.fib().add_nexthop(&n("/t"), FaceId(UPSTREAM), 0);
    if failover {
        engine.fib().add_nexthop(&n("/t"), FaceId(SPARE), 10);
    }
    let interest = InterestBuilder::new(n("/t/x"))
        .lifetime(Duration::from_secs(4))
        .build();
    consumer.send(interest).await.expect("send Interest");
    let at_upstream = recv_timeout(&upstream, 1000)
        .await
        .expect("the Interest reaches the upstream");
    Rig {
        consumer,
        upstream,
        spare,
        stranger,
        engine,
        forwarded: interest_of(&at_upstream),
        shutdown,
    }
}

impl Rig {
    /// Let the engine finish with a Nack sent on `face` before anything else
    /// is sent (counted at decode, then a moment for the pipeline).
    async fn settle_after_nack(&self, face: u64) {
        for _ in 0..200 {
            let seen = self
                .engine
                .face_states()
                .get(&FaceId(face))
                .map(|s| {
                    s.counters
                        .in_nacks
                        .load(std::sync::atomic::Ordering::Relaxed)
                })
                .unwrap_or(0);
            if seen > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    /// The real Data for `/t/x` arrives from `UPSTREAM`.
    async fn upstream_answers(&self) {
        let data = DataBuilder::new(n("/t/x"), b"payload").sign_digest_sha256();
        self.upstream.send(data).await.expect("send Data");
    }
}

/// A stranger's NoRoute Nack for the name another face is fetching — even one
/// that copies the forwarded Interest down to its nonce — is dropped, naming
/// the missing out-record: the fetch lives and the real Data arrives.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stranger_cannot_nack_a_pending_interest() {
    let rig = rig(false).await;
    let nack = encode_lp_nack(NackReason::NoRoute, rig.forwarded.raw());
    rig.stranger.send(nack).await.expect("send Nack");
    rig.settle_after_nack(STRANGER).await;
    rig.upstream_answers().await;
    let got = recv_timeout(&rig.consumer, 1000)
        .await
        .expect("the consumer hears back");
    assert!(
        is_data(&got),
        "the consumer's first answer must be the Data, not {:?}: a face with no \
         out-record ended the fetch with its own Nack",
        nack_reason(&got)
    );
    rig.shutdown.shutdown().await;
}

/// A stranger's Nack does not make the forwarder fail over either: nothing is
/// sent to the spare route.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stranger_cannot_steer_failover() {
    let rig = rig(true).await;
    let nack = encode_lp_nack(NackReason::NoRoute, rig.forwarded.raw());
    rig.stranger.send(nack).await.expect("send Nack");
    rig.settle_after_nack(STRANGER).await;
    assert!(
        recv_timeout(&rig.spare, 300).await.is_none(),
        "a Nack from a face with no out-record made the forwarder fail over"
    );
    rig.upstream_answers().await;
    assert!(is_data(
        &recv_timeout(&rig.consumer, 1000)
            .await
            .expect("the consumer hears back")
    ));
    rig.shutdown.shutdown().await;
}

/// The upstream holding the out-record is believed only with the nonce it was
/// sent: a Nack naming the Interest under another nonce is dropped.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_nack_with_another_nonce_is_dropped() {
    let rig = rig(true).await;
    let other = loop {
        let candidate = InterestBuilder::new(n("/t/x"))
            .lifetime(Duration::from_secs(4))
            .build();
        if Interest::decode(candidate.clone()).unwrap().nonce() != rig.forwarded.nonce() {
            break candidate;
        }
    };
    rig.upstream
        .send(encode_lp_nack(NackReason::NoRoute, &other))
        .await
        .expect("send Nack");
    rig.settle_after_nack(UPSTREAM).await;
    assert!(
        recv_timeout(&rig.spare, 300).await.is_none(),
        "a Nack with a nonce the upstream was not sent made the forwarder fail over"
    );
    rig.upstream_answers().await;
    assert!(is_data(
        &recv_timeout(&rig.consumer, 1000)
            .await
            .expect("the consumer hears back")
    ));
    rig.shutdown.shutdown().await;
}

/// The legitimate upstream's Nack (its out-record's nonce) still reaches the
/// strategy: with no other route the consumer hears the Nack's reason.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_upstreams_own_nack_reaches_the_consumer() {
    let rig = rig(false).await;
    rig.upstream
        .send(encode_lp_nack(NackReason::NoRoute, rig.forwarded.raw()))
        .await
        .expect("send Nack");
    let got = recv_timeout(&rig.consumer, 1000)
        .await
        .expect("the consumer hears back");
    assert_eq!(nack_reason(&got), Some(NackReason::NoRoute));
    rig.shutdown.shutdown().await;
}

/// A route back through the face the Interest came in over is no one to fail over to: the
/// Nack of the only real upstream is the consumer's answer, with its reason, not the Interest
/// sent back to the consumer (which a router upstream of the consumer then drops as a loop,
/// leaving the consumer to time out).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_nack_does_not_fail_over_to_the_face_the_interest_came_in_on() {
    let rig = rig(false).await;
    rig.engine.fib().add_nexthop(&n("/t"), FaceId(CONSUMER), 10);
    rig.upstream
        .send(encode_lp_nack(NackReason::Congestion, rig.forwarded.raw()))
        .await
        .expect("send Nack");
    let got = recv_timeout(&rig.consumer, 1000)
        .await
        .expect("the consumer hears back");
    assert_eq!(
        nack_reason(&got),
        Some(NackReason::Congestion),
        "the consumer was sent its own Interest back, not the Nack"
    );
    rig.shutdown.shutdown().await;
}

/// On failover the forwarder sends its own PIT Interest — its name, nonce and
/// selectors as the downstream asked — never the bytes the Nack enclosed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failover_sends_the_pits_interest_not_the_nacks() {
    let rig = rig(true).await;
    // What the upstream's Nack encloses: the same name and nonce, but with
    // selectors and a lifetime the downstream never asked for.
    let nonce = rig
        .forwarded
        .nonce()
        .expect("a forwarded Interest has a nonce");
    let enclosed = {
        let mut w = ndn_tlv::TlvWriter::new();
        w.write_nested(0x05, |w| {
            w.write_raw(&n("/t/x").encode_to_tlv());
            w.write_tlv(0x12, &[]); // MustBeFresh
            w.write_tlv(0x0a, &nonce.to_be_bytes());
            w.write_tlv(0x0c, &[0x04, 0xD2]); // InterestLifetime 1234 ms
        });
        w.finish()
    };
    rig.upstream
        .send(encode_lp_nack(NackReason::NoRoute, &enclosed))
        .await
        .expect("send Nack");
    let at_spare = recv_timeout(&rig.spare, 1000)
        .await
        .expect("the forwarder fails over to the spare route");
    let sent = interest_of(&at_spare);
    assert_eq!(sent.nonce(), Some(nonce), "the PIT entry's nonce");
    assert!(
        !sent.selectors().must_be_fresh,
        "the downstream asked without MustBeFresh; the enclosed bytes were forwarded"
    );
    assert_ne!(
        sent.lifetime(),
        Some(Duration::from_millis(1234)),
        "the enclosed bytes' lifetime was forwarded"
    );
    assert!(
        sent.lifetime().is_some_and(|l| l <= Duration::from_secs(4)),
        "the failover Interest lives no longer than the entry: {:?}",
        sent.lifetime()
    );
    rig.shutdown.shutdown().await;
}

/// An Interest pinned to a face (`NextHopFaceId`) bypasses the strategy, but
/// that face holds an out-record too: its Nack is accepted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pinned_upstream_may_nack() {
    let (consumer_face, consumer) = InProcFace::new(FaceId(CONSUMER), 64);
    let (up_face, upstream) = InProcFace::new(FaceId(UPSTREAM), 64);
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(consumer_face)
        .face(up_face)
        .build()
        .await
        .expect("engine build");
    engine.set_local_fields(FaceId(CONSUMER), true);
    let interest = InterestBuilder::new(n("/t/pinned"))
        .lifetime(Duration::from_secs(4))
        .pin_face(UPSTREAM)
        .build();
    consumer.send(interest).await.expect("send Interest");
    let at_upstream = recv_timeout(&upstream, 1000)
        .await
        .expect("the pinned Interest reaches the upstream");
    let forwarded = interest_of(&at_upstream);
    upstream
        .send(encode_lp_nack(NackReason::NoRoute, forwarded.raw()))
        .await
        .expect("send Nack");
    let got = recv_timeout(&consumer, 1000)
        .await
        .expect("the consumer hears back");
    assert_eq!(nack_reason(&got), Some(NackReason::NoRoute));
    shutdown.shutdown().await;
}
