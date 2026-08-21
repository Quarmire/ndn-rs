//! In-process fetch throughput — no radio, no socketpair seam, just engine +
//! Consumer. A slow result here indicts the fetch path itself, not the link.
//!   cargo test -p ndn-app --test suite -- --ignored local_throughput --nocapture

use std::time::Instant;

use bytes::Bytes;
use ndn_app::{Consumer, EngineBuilder, Producer};
use ndn_engine::EngineConfig;
use ndn_face::local::InProcFace;
use ndn_packet::Name;
use ndn_security::KeyChain;
use ndn_transport::FaceId;

const OBJ_SIZE: usize = 32 * 1024 * 1024;

async fn rig() -> (
    ndn_face::local::InProcHandle,
    ndn_face::local::InProcHandle,
    impl Sized,
) {
    let (consumer_face, consumer_handle) = InProcFace::new(FaceId(1), 8192);
    let (producer_face, producer_handle) = InProcFace::new(FaceId(2), 8192);
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

fn report(label: &str, elapsed: std::time::Duration) {
    let mbps = (OBJ_SIZE as f64 * 8.0) / elapsed.as_secs_f64() / 1e6;
    eprintln!(
        "{label}: {} MB in {:.3}s = {:.0} Mbps",
        OBJ_SIZE >> 20,
        elapsed.as_secs_f64(),
        mbps
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "throughput measurement, run explicitly"]
async fn unverified() {
    let (consumer_handle, producer_handle, _engine) = rig().await;
    let prefix: Name = "/obj".parse().unwrap();
    let payload = Bytes::from(vec![0u8; OBJ_SIZE]);

    let producer = Producer::from_handle(producer_handle, prefix.clone());
    let (pp, pre) = (payload.clone(), prefix.clone());
    tokio::spawn(async move { producer.publish_object(pre, pp, 8192).await });

    let mut consumer = Consumer::from_handle(consumer_handle);
    let started = Instant::now();
    let got = consumer.fetch_object(prefix).await.expect("fetch_object");
    report("unverified", started.elapsed());
    assert_eq!(got.len(), OBJ_SIZE);
}

async fn verified_with(kc: KeyChain, label: &str) {
    let signer = kc.signer().expect("signer");

    let (consumer_handle, producer_handle, _engine) = rig().await;
    let prefix: Name = "/obj".parse().unwrap();
    let payload = Bytes::from(vec![0u8; OBJ_SIZE]);

    let producer = Producer::from_handle(producer_handle, prefix.clone()).with_signer(signer);
    let (pp, pre) = (payload.clone(), prefix.clone());
    tokio::spawn(async move { producer.publish_object(pre, pp, 8192).await });

    let mut consumer = Consumer::from_handle(consumer_handle).verifying(kc.validator());
    let started = Instant::now();
    let got = consumer
        .fetch_object(prefix)
        .await
        .expect("verified fetch_object");
    report(label, started.elapsed());
    assert_eq!(got.len(), OBJ_SIZE);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "throughput measurement, run explicitly"]
async fn verified_ed25519() {
    verified_with(
        KeyChain::ephemeral("/obj").expect("keychain"),
        "verified Ed25519",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "throughput measurement, run explicitly"]
async fn verified_ecdsa() {
    verified_with(
        KeyChain::ephemeral_ecdsa("/obj").expect("keychain"),
        "verified ECDSA-P256 (mobile)",
    )
    .await;
}
