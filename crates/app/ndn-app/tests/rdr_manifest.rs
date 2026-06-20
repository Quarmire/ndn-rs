//! FLIC aggregated-signing object path: `Producer::publish_object_with(
//! Aggregation::Manifest)` + `VerifiedConsumer::fetch_object`. One signature
//! over the metadata/manifest root authenticates the whole object; segments are
//! served plain (DigestSha256) and verified by hash-match against the manifest.
//! This is the witness that aggregated signing is end-to-end authenticated, not
//! merely integrity-checked, and transparent to the consumer (same `fetch_object`).

use bytes::Bytes;

use ndn_app::{Aggregation, Consumer, EngineBuilder, Producer, PublishOptions};
use ndn_engine::EngineConfig;
use ndn_face::local::InProcFace;
use ndn_packet::Name;
use ndn_security::KeyChain;
use ndn_transport::FaceId;

async fn rig() -> (
    ndn_face::local::InProcHandle,
    ndn_face::local::InProcHandle,
    impl Sized,
) {
    let (consumer_face, consumer_handle) = InProcFace::new(FaceId(1), 256);
    let (producer_face, producer_handle) = InProcFace::new(FaceId(2), 256);
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(consumer_face)
        .face(producer_face)
        .build()
        .await
        .expect("engine build");
    engine
        .fib()
        .add_nexthop(&"/obj".parse::<Name>().unwrap(), FaceId(2), 0);
    (consumer_handle, producer_handle, (engine, shutdown))
}

/// One signature over the manifest authenticates an object whose segments are
/// served unsigned — and the verified consumer reassembles it correctly.
#[tokio::test]
async fn manifest_object_round_trips_verified() {
    let kc = KeyChain::ephemeral("/obj").expect("keychain");
    let signer = kc.signer().expect("signer");

    let (consumer_handle, producer_handle, _engine) = rig().await;
    let prefix: Name = "/obj".parse().unwrap();

    // 20 000 bytes at 4 KiB → 5 segments, all under one manifest signature.
    let payload: Vec<u8> = (0..20_000u32).map(|i| (i & 0xff) as u8).collect();
    let producer = Producer::from_handle(producer_handle, prefix.clone()).with_signer(signer);
    let pub_payload = Bytes::from(payload.clone());
    let pub_prefix = prefix.clone();
    let task = tokio::spawn(async move {
        producer
            .publish_object_with(
                pub_prefix,
                pub_payload,
                PublishOptions {
                    chunk_size: 4096,
                    aggregation: Aggregation::Manifest,
                },
            )
            .await
    });

    let mut consumer = Consumer::from_handle(consumer_handle).verifying(kc.validator());
    let reassembled = consumer
        .fetch_object(prefix)
        .await
        .expect("verified fetch_object of a manifest-signed object");
    assert_eq!(reassembled.as_ref(), payload.as_slice());
    task.abort();
}

/// A manifest whose root is unsigned still reassembles for an *unverified*
/// fetch (integrity via hash-match) — proving the segment-by-hash path itself
/// works independently of the root signature.
#[tokio::test]
async fn manifest_object_round_trips_unverified() {
    let (consumer_handle, producer_handle, _engine) = rig().await;
    let prefix: Name = "/obj".parse().unwrap();

    let payload: Vec<u8> = (0..30_000u32).map(|i| (i & 0xff) as u8).collect();
    let producer = Producer::from_handle(producer_handle, prefix.clone());
    let pub_payload = Bytes::from(payload.clone());
    let pub_prefix = prefix.clone();
    let task = tokio::spawn(async move {
        producer
            .publish_object_with(
                pub_prefix,
                pub_payload,
                PublishOptions {
                    chunk_size: 4096,
                    aggregation: Aggregation::Manifest,
                },
            )
            .await
    });

    let mut consumer = Consumer::from_handle(consumer_handle);
    let reassembled = consumer
        .fetch_object(prefix)
        .await
        .expect("unverified fetch_object of a manifest object");
    assert_eq!(reassembled.as_ref(), payload.as_slice());
    task.abort();
}
