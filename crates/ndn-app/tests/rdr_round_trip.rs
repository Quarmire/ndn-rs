//! Phase 3 §3.2 — `Consumer::fetch_object` / `Producer::publish_object`
//! two-engine RDR round-trip witness.
//!
//! Tests the full RDR flow:
//!   1. Producer publishes a multi-segment object under `/obj`.
//!   2. Consumer issues `<obj>/32=metadata`, receives MetaData, then
//!      fetches every segment.
//!   3. The reassembled bytes match the original payload.

use bytes::Bytes;

use ndn_app::{Consumer, EngineBuilder, Producer};
use ndn_engine::EngineConfig;
use ndn_face::local::InProcFace;
use ndn_packet::Name;
use ndn_transport::FaceId;

#[tokio::test]
async fn fetch_object_reassembles_publish_object() {
    let (consumer_face, consumer_handle) = InProcFace::new(FaceId(1), 256);
    let (producer_face, producer_handle) = InProcFace::new(FaceId(2), 256);

    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(consumer_face)
        .face(producer_face)
        .build()
        .await
        .expect("engine build");

    let prefix: Name = "/obj".parse().unwrap();
    engine.fib().add_nexthop(&prefix, FaceId(2), 0);

    let payload_bytes: Vec<u8> = (0..20_000u32).map(|i| (i & 0xff) as u8).collect();
    let payload = Bytes::from(payload_bytes.clone());

    let producer = Producer::from_handle(producer_handle, prefix.clone());
    let publish_payload = payload.clone();
    let publish_prefix = prefix.clone();
    let producer_task = tokio::spawn(async move {
        // ~8 KiB chunks → 3 segments for 20 000 bytes.
        producer
            .publish_object(publish_prefix, publish_payload, 8192)
            .await
    });

    let mut consumer = Consumer::from_handle(consumer_handle);
    let reassembled = consumer
        .fetch_object(prefix.clone())
        .await
        .expect("fetch_object");
    assert_eq!(reassembled.as_ref(), payload_bytes.as_slice());

    drop(consumer);
    drop(engine);
    shutdown.shutdown().await;
    let _ = producer_task.await;
}

#[tokio::test]
async fn fetch_object_single_segment_object() {
    // Object that fits in one segment — last_seg == 0.
    let (consumer_face, consumer_handle) = InProcFace::new(FaceId(1), 64);
    let (producer_face, producer_handle) = InProcFace::new(FaceId(2), 64);

    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(consumer_face)
        .face(producer_face)
        .build()
        .await
        .expect("engine build");

    let prefix: Name = "/small".parse().unwrap();
    engine.fib().add_nexthop(&prefix, FaceId(2), 0);

    let payload = Bytes::from_static(b"hello world");

    let producer = Producer::from_handle(producer_handle, prefix.clone());
    let pub_prefix = prefix.clone();
    let pub_payload = payload.clone();
    let producer_task =
        tokio::spawn(async move { producer.publish_object(pub_prefix, pub_payload, 8192).await });

    let mut consumer = Consumer::from_handle(consumer_handle);
    let got = consumer.fetch_object(prefix).await.expect("fetch_object");
    assert_eq!(got.as_ref(), b"hello world");

    drop(consumer);
    drop(engine);
    shutdown.shutdown().await;
    let _ = producer_task.await;
}
