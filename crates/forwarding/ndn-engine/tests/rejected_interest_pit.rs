//! An Interest the strategy does not forward — its only nexthop is the face it
//! came in on — is Nacked back, and must not leave its PIT entry behind: a
//! later Interest for the same name from another face would aggregate onto an
//! entry nothing will ever satisfy and stall until that entry expires. NFD
//! erases the entry (`Strategy::rejectPendingInterest` after the NoRoute
//! Nack).
//!
//! Seen live in the end-to-end harness (ndn-fwd/testbed/e2e, `negatives`): a
//! probe for a name a producer was just registering went from the member's
//! forwarder to its neighbour, whose route for the name led straight back; for
//! the probe's lifetime the neighbour aggregated its own consumer's Interest
//! onto that entry, and the consumer timed out.

use std::time::Duration;

use ndn_engine::{EngineBuilder, EngineConfig};
use ndn_face_local::{InProcFace, InProcHandle};
use ndn_packet::Name;
use ndn_packet::encode::InterestBuilder;
use ndn_packet::lp::LpPacket;
use ndn_transport::FaceId;

const FACE_A: u64 = 1; // a consumer
const FACE_B: u64 = 2; // the only nexthop for the name

async fn recv_timeout(handle: &InProcHandle) -> Option<bytes::Bytes> {
    tokio::time::timeout(Duration::from_millis(300), handle.recv())
        .await
        .ok()
        .flatten()
}

fn is_nack(wire: &bytes::Bytes) -> bool {
    LpPacket::decode(wire.clone()).is_ok_and(|lp| lp.nack.is_some())
}

fn is_interest(wire: &bytes::Bytes) -> bool {
    const T_INTEREST: u8 = 0x05;
    if wire.first() == Some(&T_INTEREST) {
        return true;
    }
    LpPacket::decode(wire.clone()).is_ok_and(|lp| {
        lp.nack.is_none() && lp.fragment.is_some_and(|f| f.first() == Some(&T_INTEREST))
    })
}

#[tokio::test]
async fn an_interest_nacked_for_no_route_leaves_no_pit_entry_behind() {
    let (face_a, handle_a) = InProcFace::new(FaceId(FACE_A), 128);
    let (face_b, handle_b) = InProcFace::new(FaceId(FACE_B), 128);
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(face_a)
        .face(face_b)
        .build()
        .await
        .expect("engine build");
    let prefix: Name = "/reject/pit".parse().unwrap();
    engine.fib().add_nexthop(&prefix, FaceId(FACE_B), 0);
    let name: Name = "/reject/pit/x".parse().unwrap();

    // From B, whose only route leads back to B: nowhere to forward it.
    let from_b = InterestBuilder::new(name.clone())
        .lifetime(Duration::from_secs(4))
        .build();
    handle_b.send(from_b).await.expect("inject on B");
    let back = recv_timeout(&handle_b).await.expect("an answer on B");
    assert!(is_nack(&back), "an Interest with no eligible nexthop is Nacked back");

    // Within that Interest's lifetime, the same name from A must reach B.
    let from_a = InterestBuilder::new(name.clone())
        .lifetime(Duration::from_secs(4))
        .build();
    handle_a.send(from_a).await.expect("inject on A");
    let forwarded = recv_timeout(&handle_b).await;
    assert!(
        forwarded.as_ref().is_some_and(is_interest),
        "the consumer's Interest must be forwarded to B, not aggregated onto the \
         rejected entry (got {forwarded:?})"
    );

    shutdown.shutdown().await;
}

/// The same, when the consumer's Interest arrives while the rejected one is
/// still in its strategy pass (nothing sent upstream yet): it must not be
/// aggregated onto the entry the Nack then releases, but forwarded to B.
/// Seen live in the end-to-end harness (`lifecycle-push`): a relay's fetch of
/// a sync group's Data reached a device a fraction of a millisecond before
/// the device's own fetch of it, whose only route was that relay; the
/// device's fetch was dropped with the released entry and timed out.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_interest_arriving_while_another_is_rejected_is_still_forwarded() {
    let (face_a, handle_a) = InProcFace::new(FaceId(FACE_A), 128);
    let (face_b, handle_b) = InProcFace::new(FaceId(FACE_B), 128);
    // The daemon's parallel pipeline, where the two passes overlap.
    let (engine, shutdown) = EngineBuilder::new(EngineConfig {
        pipeline_threads: 4,
        ..EngineConfig::default()
    })
    .face(face_a)
    .face(face_b)
    .build()
    .await
    .expect("engine build");
    let prefix: Name = "/reject/pit".parse().unwrap();
    engine.fib().add_nexthop(&prefix, FaceId(FACE_B), 0);

    for i in 0..20 {
        let name = prefix.clone().append_segment(i);
        let interest = || {
            InterestBuilder::new(name.clone())
                .lifetime(Duration::from_secs(4))
                .build()
        };
        // Back to back: A's arrives before B's is Nacked.
        handle_b.send(interest()).await.expect("inject on B");
        handle_a.send(interest()).await.expect("inject on A");
        let mut forwarded = false;
        while let Some(wire) = recv_timeout(&handle_b).await {
            if is_interest(&wire) {
                forwarded = true;
                break;
            }
        }
        assert!(
            forwarded,
            "Interest {i}: the consumer's Interest must be forwarded to B, not dropped with \
             the rejected one's entry"
        );
    }

    shutdown.shutdown().await;
}
