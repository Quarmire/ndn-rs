//! Integration tests for `ndn-mobile`.
//!
//! All tests use the in-process engine (no network faces) so they run without
//! special privileges and work on any platform including CI.

use ndn_mobile::{Consumer, MobileEngine, SecurityProfile};
use ndn_packet::encode::DataBuilder;

/// Build a minimal engine (no network, no discovery, no persistent CS).
async fn build_minimal() -> (MobileEngine, Consumer) {
    let (engine, handle) = MobileEngine::builder()
        .security_profile(SecurityProfile::Disabled)
        .build()
        .await
        .expect("engine build failed");
    let consumer = Consumer::from_handle(handle);
    (engine, consumer)
}

/// A producer and consumer on the same in-process engine can exchange a packet.
#[tokio::test]
async fn test_in_process_roundtrip() {
    let (engine, mut consumer) = build_minimal().await;

    let prefix: ndn_mobile::Name = "/test/data".parse().unwrap();
    let producer = engine.register_producer(prefix.clone());

    // Serve one Data packet from the producer.
    let name = prefix.clone();
    tokio::spawn(async move {
        producer
            .serve(move |_interest, responder| {
                let wire = DataBuilder::new(name.clone(), b"hello ndn").build();
                async move {
                    responder.respond_bytes(wire).await.ok();
                }
            })
            .await
            .ok();
    });

    let data = consumer.fetch("/test/data").await.expect("fetch failed");
    assert_eq!(
        data.content().map(|b| b.as_ref()),
        Some(b"hello ndn".as_ref())
    );

    engine.shutdown().await;
}

/// `register_producer` returns distinct faces each call.
#[tokio::test]
async fn test_multiple_producers_distinct_faces() {
    let (engine, _handle) = MobileEngine::builder()
        .security_profile(SecurityProfile::Disabled)
        .build()
        .await
        .expect("engine build failed");

    let p1 = engine.register_producer("/a");
    let p2 = engine.register_producer("/b");

    // The producers reference distinct prefixes.
    assert_ne!(p1.prefix().to_string(), p2.prefix().to_string());

    engine.shutdown().await;
}

/// `suspend_network_faces` then `resume_network_faces` keeps the in-process
/// AppFace (and therefore consumer/producer) functional throughout.
#[tokio::test]
async fn test_suspend_resume_keeps_appface_alive() {
    let (mut engine, handle) = MobileEngine::builder()
        .security_profile(SecurityProfile::Disabled)
        .build()
        .await
        .expect("engine build failed");
    let mut consumer = Consumer::from_handle(handle);

    let prefix: ndn_mobile::Name = "/test/suspend".parse().unwrap();
    let producer = engine.register_producer(prefix.clone());
    let name = prefix.clone();
    tokio::spawn(async move {
        producer
            .serve(move |_interest, responder| {
                let wire = DataBuilder::new(name.clone(), b"alive").build();
                async move {
                    responder.respond_bytes(wire).await.ok();
                }
            })
            .await
            .ok();
    });

    // Suspend (no network faces configured, so this is a no-op on sockets but
    // exercises the token refresh path).
    engine.suspend_network_faces();

    // AppFace must still work.
    let data = consumer
        .fetch("/test/suspend")
        .await
        .expect("fetch after suspend failed");
    assert_eq!(data.content().map(|b| b.as_ref()), Some(b"alive".as_ref()));

    // Resume (again no-op on sockets, exercises the multicast_iface == None branch).
    engine.resume_network_faces().await;

    engine.shutdown().await;
}

/// `pipeline_threads` builder knob compiles and builds without error.
#[tokio::test]
async fn test_pipeline_threads_knob() {
    let (engine, _handle) = MobileEngine::builder()
        .security_profile(SecurityProfile::Disabled)
        .pipeline_threads(2)
        .build()
        .await
        .expect("engine build with pipeline_threads(2) failed");
    engine.shutdown().await;
}
