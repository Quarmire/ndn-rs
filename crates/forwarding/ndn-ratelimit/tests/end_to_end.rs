//! End-to-end witness for inbound rate limiting through an embedded
//! `ForwarderEngine`. Wires `EngineRateLimitHook` to the engine, sends
//! a burst of Interests from one face, asserts that the rate-limit
//! policy denies the excess.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_app::{Consumer, EngineBuilder, Producer};
use ndn_engine::EngineConfig;
use ndn_face::local::InProcFace;
use ndn_packet::Name;
use ndn_packet::encode::DataBuilder;
use ndn_transport::FaceId;

use ndn_ratelimit::{
    BucketSpec, Cell, Direction, EngineRateLimitHook, FaceRef, Overflow, RateLimitPolicy,
    RateLimitPolicyTable,
};

/// A flood of K Interests through a face that's pinned to a 5-PPS /
/// burst-5 inbound rate-limit on the producer prefix yields:
///   - the first ≤5 Interests succeed (burst credit)
///   - subsequent fetches fail (NACK or timeout)
///
/// The witness asserts that **not all** K fetches succeed, and at
/// least one succeeds — i.e. the rate limit is functional and
/// non-trivial. (Strict-permit and strict-deny counts would couple
/// the test to NACK timing.)
#[tokio::test]
async fn inbound_pps_burst_caps_floods() {
    let (consumer_face, consumer_handle) = InProcFace::new(FaceId(1), 256);
    let (producer_face, producer_handle) = InProcFace::new(FaceId(2), 256);

    // Build the rate-limit table + hook *before* the engine so the
    // builder can install it.
    let table: Arc<RateLimitPolicyTable> = Arc::new(RateLimitPolicyTable::new());
    let prefix: Name = "/test/rl".parse().unwrap();
    table
        .set(RateLimitPolicy {
            cell: Cell {
                face: Some(FaceRef(1)), // limit the consumer's face
                prefix: Some(prefix.clone()),
                direction: Direction::Inbound,
            },
            bucket: BucketSpec::pps(5, 5),
            overflow: Overflow::Nack,
            queue_max: None,
        })
        .unwrap();
    let hook: Arc<dyn ndn_engine::RateLimitHook> =
        Arc::new(EngineRateLimitHook::new(Arc::clone(&table)));

    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(consumer_face)
        .face(producer_face)
        .with_rate_limit_hook(Some(hook))
        .build()
        .await
        .expect("engine build");

    engine.fib().add_nexthop(&prefix, FaceId(2), 0);

    let mut consumer = Consumer::from_handle(consumer_handle);
    let producer = Producer::from_handle(producer_handle, prefix.clone());

    let producer_task = tokio::spawn(async move {
        producer
            .serve(|interest, responder| {
                let name = (*interest.name).clone();
                async move {
                    let wire = DataBuilder::new(name, b"ok").build();
                    responder.respond_bytes(wire).await.ok();
                }
            })
            .await
    });

    const K: usize = 25;
    let mut permits = 0usize;
    let mut denials = 0usize;
    for i in 0..K {
        let name = prefix.clone().append(i.to_string());
        let fetch = tokio::time::timeout(Duration::from_millis(150), consumer.fetch(name)).await;
        match fetch {
            Ok(Ok(_data)) => permits += 1,
            // Any other outcome (timeout, NACK, error) counts as denial.
            _ => denials += 1,
        }
    }

    drop(consumer);
    drop(engine);
    shutdown.shutdown().await;
    let _ = producer_task.await;

    // Burst of 5 means we expect 4-6 permits within the test window;
    // the GCRA leaks at 5 PPS over ~3.75 seconds total wall time
    // (25 × 150ms), so a few more may pass. Tolerate that.
    assert!(
        permits >= 1,
        "rate limit denied everything (permits={permits})"
    );
    assert!(
        permits < K,
        "rate limit did not engage: all {K} permits succeeded"
    );
    assert!(denials > 0, "expected some denials, got 0");
    eprintln!("permits={permits} denials={denials} (K={K})");
}

/// Confirm that with **no** hook installed, all K fetches succeed —
/// the regression guard against the hook misfiring in the no-limit
/// case.
#[tokio::test]
async fn no_hook_permits_everything() {
    let (consumer_face, consumer_handle) = InProcFace::new(FaceId(1), 256);
    let (producer_face, producer_handle) = InProcFace::new(FaceId(2), 256);

    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(consumer_face)
        .face(producer_face)
        .build()
        .await
        .expect("engine build");
    let prefix: Name = "/test/no-rl".parse().unwrap();
    engine.fib().add_nexthop(&prefix, FaceId(2), 0);

    let mut consumer = Consumer::from_handle(consumer_handle);
    let producer = Producer::from_handle(producer_handle, prefix.clone());

    let producer_task = tokio::spawn(async move {
        producer
            .serve(|interest, responder| {
                let name = (*interest.name).clone();
                async move {
                    let _ = name;
                    let wire = DataBuilder::new((*interest.name).clone(), b"ok").build();
                    responder.respond_bytes(wire).await.ok();
                }
            })
            .await
    });

    const K: usize = 10;
    let mut permits = 0usize;
    for i in 0..K {
        let name = prefix.clone().append(i.to_string());
        if let Ok(Ok(_)) =
            tokio::time::timeout(Duration::from_millis(200), consumer.fetch(name)).await
        {
            permits += 1;
        }
    }

    drop(consumer);
    drop(engine);
    shutdown.shutdown().await;
    let _ = producer_task.await;

    assert_eq!(
        permits, K,
        "every fetch must succeed without rate-limit hook"
    );
}

#[allow(dead_code)]
fn _unused_bytes() -> Bytes {
    Bytes::new()
}
