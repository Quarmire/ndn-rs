//! Secure RDR object path: `Producer::with_signer(...).publish_object` +
//! `VerifiedConsumer::fetch_object`. NDN security travels with the data — a
//! whole-object fetch is authenticated, not merely integrity-checked, and an
//! unsigned (DigestSha256) object is *refused*. This is the witness that the
//! object plane is secure by default, not as a later layer.

use bytes::Bytes;

use ndn_app::{Consumer, EngineBuilder, Producer};
use ndn_engine::EngineConfig;
use ndn_face::local::InProcFace;
use ndn_packet::Name;
use ndn_security::KeyChain;
use ndn_transport::FaceId;

/// Spin a two-face in-proc engine routing `<prefix>` Interests to the producer.
async fn rig() -> (ndn_face::local::InProcHandle, ndn_face::local::InProcHandle, impl Sized) {
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
    // Keep the engine alive for the test by leaking it into the returned tuple.
    (consumer_handle, producer_handle, (engine, shutdown))
}

#[tokio::test]
async fn verified_fetch_object_accepts_signed_and_reassembles() {
    // Identity named for the object so the hierarchical schema accepts segments
    // under it; the self-cert is the anchor the consumer pins.
    let kc = KeyChain::ephemeral("/obj").expect("keychain");
    let signer = kc.signer().expect("signer");

    let (consumer_handle, producer_handle, _engine) = rig().await;
    let prefix: Name = "/obj".parse().unwrap();

    let payload: Vec<u8> = (0..20_000u32).map(|i| (i & 0xff) as u8).collect();
    let producer = Producer::from_handle(producer_handle, prefix.clone()).with_signer(signer);
    let pub_payload = Bytes::from(payload.clone());
    let pub_prefix = prefix.clone();
    let task = tokio::spawn(async move { producer.publish_object(pub_prefix, pub_payload, 8192).await });

    let mut consumer = Consumer::from_handle(consumer_handle).verifying(kc.validator());
    let reassembled = consumer
        .fetch_object(prefix)
        .await
        .expect("verified fetch_object of a signed object");
    assert_eq!(reassembled.as_ref(), payload.as_slice());
    task.abort();
}

#[tokio::test]
async fn verified_fetch_object_rejects_unsigned() {
    let kc = KeyChain::ephemeral("/obj").expect("keychain");

    let (consumer_handle, producer_handle, _engine) = rig().await;
    let prefix: Name = "/obj".parse().unwrap();

    // Producer WITHOUT a signer → DigestSha256 (integrity only, not authored).
    let producer = Producer::from_handle(producer_handle, prefix.clone());
    let pub_prefix = prefix.clone();
    let task = tokio::spawn(async move {
        producer
            .publish_object(pub_prefix, Bytes::from_static(b"unsigned payload"), 8192)
            .await
    });

    let mut consumer = Consumer::from_handle(consumer_handle).verifying(kc.validator());
    let result = consumer.fetch_object(prefix).await;
    assert!(
        result.is_err(),
        "a verified object fetch MUST refuse an unsigned (DigestSha256) object, got {result:?}"
    );
    task.abort();
}
