//! Integration test: embedded forwarding engine with Consumer and Producer.
//!
//! Demonstrates the pattern for running NDN on Android or any environment
//! where the app IS the forwarder — no external router, no Unix sockets,
//! no SHM.  Everything runs in-process via `AppFace` channel pairs.

use std::sync::Arc;

use bytes::Bytes;

use ndn_face_local::AppFace;
use ndn_packet::encode::DataBuilder;
use ndn_packet::Name;
use ndn_transport::FaceId;

use ndn_app::{Consumer, EngineBuilder, Producer};
use ndn_engine::EngineConfig;

/// Full end-to-end test: Consumer sends Interest, Producer replies with Data.
#[tokio::test]
async fn embedded_consumer_producer() {
    // 1. Create two AppFace pairs: one for the consumer, one for the producer.
    let (consumer_face, consumer_handle) = AppFace::new(FaceId(1), 64);
    let (producer_face, producer_handle) = AppFace::new(FaceId(2), 64);

    // 2. Build the forwarding engine with both faces.
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(consumer_face)
        .face(producer_face)
        .build()
        .await
        .expect("engine build");

    // 3. Add a FIB route: Interests for /test → producer face.
    let prefix: Name = "/test".parse().unwrap();
    engine.fib().add_nexthop(&prefix, FaceId(2), 0);

    // 4. Create Consumer and Producer from their handles.
    let mut consumer = Consumer::from_handle(consumer_handle);
    let mut producer = Producer::from_handle(producer_handle, prefix.clone());

    // 5. Run producer in a background task.
    let producer_task = tokio::spawn(async move {
        producer
            .serve(|interest| {
                let name = (*interest.name).clone();
                async move {
                    let wire = DataBuilder::new(name, b"hello from producer").build();
                    Some(wire)
                }
            })
            .await
    });

    // 6. Consumer fetches data.
    let data = consumer.fetch(prefix.clone()).await.expect("fetch");
    assert_eq!(*data.name, prefix);
    assert_eq!(
        data.content().map(|c| c.to_vec()),
        Some(b"hello from producer".to_vec()),
    );

    // 7. Clean up: drop the engine so AppFace senders close, then producer
    //    loop sees `None` from recv and exits.
    drop(consumer);
    drop(engine);
    shutdown.shutdown().await;
    let _ = producer_task.await;
}

/// Test fetching multiple packets sequentially.
#[tokio::test]
async fn embedded_multiple_fetches() {
    let (consumer_face, consumer_handle) = AppFace::new(FaceId(1), 64);
    let (producer_face, producer_handle) = AppFace::new(FaceId(2), 64);

    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(consumer_face)
        .face(producer_face)
        .build()
        .await
        .expect("engine build");

    let prefix: Name = "/counter".parse().unwrap();
    engine.fib().add_nexthop(&prefix, FaceId(2), 0);

    let mut consumer = Consumer::from_handle(consumer_handle);
    let mut producer = Producer::from_handle(producer_handle, prefix.clone());

    let counter = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let counter_clone = counter.clone();

    let producer_task = tokio::spawn(async move {
        producer
            .serve(move |interest| {
                let name = (*interest.name).clone();
                let n = counter_clone.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                async move {
                    let payload = n.to_be_bytes();
                    let wire = DataBuilder::new(name, &payload).build();
                    Some(wire)
                }
            })
            .await
    });

    // Fetch 5 times.
    for i in 0u32..5 {
        let name: Name = format!("/counter/{i}").parse().unwrap();
        let data = consumer.fetch(name).await.expect("fetch");
        let content = data.content().unwrap();
        let val = u32::from_be_bytes(content[..4].try_into().unwrap());
        assert_eq!(val, i);
    }

    drop(consumer);
    drop(engine);
    shutdown.shutdown().await;
    let _ = producer_task.await;
}

/// Test the raw `get()` convenience method.
#[tokio::test]
async fn embedded_consumer_get() {
    let (consumer_face, consumer_handle) = AppFace::new(FaceId(1), 64);
    let (producer_face, producer_handle) = AppFace::new(FaceId(2), 64);

    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(consumer_face)
        .face(producer_face)
        .build()
        .await
        .expect("engine build");

    let prefix: Name = "/data".parse().unwrap();
    engine.fib().add_nexthop(&prefix, FaceId(2), 0);

    let mut consumer = Consumer::from_handle(consumer_handle);
    let mut producer = Producer::from_handle(producer_handle, prefix.clone());

    tokio::spawn(async move {
        producer
            .serve(|interest| {
                let name = (*interest.name).clone();
                async move {
                    Some(DataBuilder::new(name, b"raw bytes").build())
                }
            })
            .await
    });

    let content: Bytes = consumer.get("/data/item").await.expect("get");
    assert_eq!(&content[..], b"raw bytes");

    shutdown.shutdown().await;
}
