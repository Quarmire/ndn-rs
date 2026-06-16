//! Integration test: `CallbackFace` wired into a live `ForwarderEngine`.
//!
//! Mirrors the pattern from `ndn-app/tests/embedded.rs` but replaces the
//! producer `InProcFace` with a `CallbackFace` registered as a FIB next-hop.

use ndn_app::{Consumer, EngineBuilder};
use ndn_engine::EngineConfig;
use ndn_face::CallbackFace;
use ndn_face::local::InProcFace;
use ndn_packet::Data;
use ndn_packet::encode::DataBuilder;
use ndn_transport::FaceId;

/// Send Interest through the forwarder; `CallbackFace` returns Data; consumer
/// receives it through the standard CS→PIT→FIB pipeline.
#[tokio::test]
async fn callback_face_in_forwarder() {
    let (consumer_face, consumer_handle) = InProcFace::new(FaceId(1), 64);

    let virtual_face = CallbackFace::from_fn(FaceId(2), |interest| {
        let name = (*interest.name).clone();
        let wire = DataBuilder::new(name, b"from-virtual-face").build();
        Some(Data::decode(wire).unwrap())
    });

    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(consumer_face)
        .face(virtual_face)
        .build()
        .await
        .expect("engine build");

    let prefix: ndn_packet::Name = "/virtual".parse().unwrap();
    engine.fib().add_nexthop(&prefix, FaceId(2), 0);

    let mut consumer = Consumer::from_handle(consumer_handle);

    let item_name: ndn_packet::Name = "/virtual/item".parse().unwrap();
    let data = consumer
        .fetch(item_name)
        .await
        .expect("fetch via CallbackFace");

    assert_eq!(
        data.content().map(|c| c.to_vec()),
        Some(b"from-virtual-face".to_vec())
    );

    drop(consumer);
    drop(engine);
    shutdown.shutdown().await;
}
