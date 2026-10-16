//! Engine-backed certificate fetching on the Data path.
//!
//! Pairing scenario: the node trusts only the home root (`/home/KEY/root`). A
//! newly enrolled device (`/home/phone`) signs Data with its own key, whose cert
//! (issued by the root) the node has never seen — the producer serves it. Under
//! the `Default` security profile the engine must fetch that intermediate cert
//! through itself and then validate the Data. Before the fix the engine's
//! fetcher was a no-op placeholder: the Data was parked, never resolved, and
//! dropped.
//!
//! The producer sits on an in-proc face with `require_data_validation`, so its
//! Data is validated exactly like Data from a remote face.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use ndn_app::{Consumer, EngineBuilder, ForwarderEngine, Producer, ShutdownHandle};
use ndn_engine::EngineConfig;
use ndn_face::local::InProcFace;
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_packet::{NackReason, Name, SignatureType};
use ndn_security::{Certificate, Ed25519Signer, SecurityManager, Signer, encode_cert_data};
use ndn_transport::FaceId;
use tokio_util::sync::CancellationToken;

const CONSUMER: FaceId = FaceId(1);
const PRODUCER: FaceId = FaceId(2);

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

fn root() -> Ed25519Signer {
    Ed25519Signer::from_seed(&[7; 32], n("/home/KEY/root"))
}

fn phone() -> Ed25519Signer {
    Ed25519Signer::from_seed(&[8; 32], n("/home/phone/KEY/k1/root/v1"))
}

/// Default-profile engine whose SecurityManager trusts only the home root,
/// with a consumer face and a validated producer face routed for `/home`.
async fn engine_trusting_root() -> (ForwarderEngine, ShutdownHandle, Consumer, Producer) {
    let root = root();
    let mgr = SecurityManager::new();
    assert!(mgr.add_trust_anchor(Certificate {
        name: Arc::new(root.key_name().clone()),
        public_key: Bytes::copy_from_slice(&root.public_key_bytes()),
        valid_from: 0,
        valid_until: u64::MAX,
        issuer: None,
        signed_region: None,
        sig_value: None,
        sig_type: SignatureType::SignatureEd25519,
    }));

    let (consumer_face, consumer_handle) = InProcFace::new(CONSUMER, 64);
    let (producer_face, producer_handle) = InProcFace::new(PRODUCER, 64);
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .security(Arc::new(mgr))
        .face(consumer_face)
        .face(producer_face)
        .build()
        .await
        .expect("engine build");
    // Validate the producer's Data as if it came from a remote peer.
    engine.set_require_data_validation(PRODUCER, true);
    engine.fib().add_nexthop(&n("/home"), PRODUCER, 0);

    (
        engine,
        shutdown,
        Consumer::from_handle(consumer_handle),
        Producer::from_handle(producer_handle, n("/home")),
    )
}

fn sign_data(name: Name, signer: &Ed25519Signer) -> Bytes {
    DataBuilder::new(name, b"photo").sign_sync(
        SignatureType::SignatureEd25519,
        Some(signer.key_name()),
        |region| signer.sign_sync(region).unwrap(),
    )
}

/// Serve `/home/phone/...` Data signed by the phone key. The phone's cert is
/// served when `serve_cert`, else its Interests are Nacked. Returns the number
/// of cert Interests that reached the producer.
async fn spawn_producer(producer: Producer, serve_cert: bool) -> Arc<AtomicUsize> {
    let phone = Arc::new(phone());
    let cert_wire = encode_cert_data(
        phone.key_name(),
        &phone.public_key_bytes(),
        &root(),
        0,
        u64::MAX,
    )
    .await
    .unwrap();
    let cert_interests = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&cert_interests);
    tokio::spawn(async move {
        producer
            .serve(move |interest, responder| {
                let phone = Arc::clone(&phone);
                let cert_wire = cert_wire.clone();
                let counter = Arc::clone(&counter);
                async move {
                    let name = (*interest.name).clone();
                    if &name == phone.key_name() {
                        counter.fetch_add(1, Ordering::SeqCst);
                        if serve_cert {
                            responder.respond_bytes(cert_wire).await.ok();
                        } else {
                            responder.nack(NackReason::NoRoute).await.ok();
                        }
                    } else {
                        responder.respond_bytes(sign_data(name, &phone)).await.ok();
                    }
                }
            })
            .await
            .ok();
    });
    cert_interests
}

async fn fetch(consumer: &mut Consumer, name: &str, lifetime: Duration) -> Option<Bytes> {
    consumer
        .fetch_with(InterestBuilder::new(n(name)).lifetime(lifetime))
        .await
        .ok()
        .and_then(|d| d.content().map(|c| Bytes::copy_from_slice(c)))
}

/// The acceptance path: Data signed by an intermediate cert that only the
/// producer serves validates once the engine fetches that cert.
#[tokio::test]
async fn data_signed_by_uncached_intermediate_validates_after_cert_fetch() {
    let (engine, shutdown, mut consumer, producer) = engine_trusting_root().await;
    let cancel = CancellationToken::new();
    assert!(
        ndn_app::install_engine_cert_fetcher(&engine, cancel.child_token()),
        "Default profile engine must accept the engine-backed fetcher"
    );
    assert!(
        !ndn_app::install_engine_cert_fetcher(&engine, cancel.child_token()),
        "set-once: a second install is a no-op"
    );
    let cert_interests = spawn_producer(producer, true).await;

    let got = fetch(&mut consumer, "/home/phone/photo/1", Duration::from_secs(3)).await;
    assert_eq!(got.as_deref(), Some(&b"photo"[..]), "Data must validate after cert fetch");
    assert_eq!(cert_interests.load(Ordering::SeqCst), 1, "one fetch for the cert");

    // The cert is now cached: the next Data validates inline, no new fetch.
    let got = fetch(&mut consumer, "/home/phone/photo/2", Duration::from_secs(1)).await;
    assert_eq!(got.as_deref(), Some(&b"photo"[..]));
    assert_eq!(cert_interests.load(Ordering::SeqCst), 1);

    cancel.cancel();
    shutdown.shutdown().await;
}

/// Control for the bug: the same engine without a fetcher (the old no-op
/// placeholder's behaviour) drops the Data — the cert is never requested.
#[tokio::test]
async fn without_engine_fetcher_uncached_intermediate_is_dropped() {
    let (_engine, shutdown, mut consumer, producer) = engine_trusting_root().await;
    let cert_interests = spawn_producer(producer, true).await;

    let got = fetch(&mut consumer, "/home/phone/photo/1", Duration::from_millis(500)).await;
    assert!(got.is_none(), "unverifiable Data must not be delivered");
    assert_eq!(cert_interests.load(Ordering::SeqCst), 0);

    shutdown.shutdown().await;
}

/// A cert nobody serves: every Data naming it is dropped, and the fetcher
/// sends ONE cert Interest for the whole burst (dedup + failure back-off) —
/// no per-packet retry storm.
#[tokio::test]
async fn missing_cert_drops_data_without_retry_storm() {
    let (engine, shutdown, mut consumer, producer) = engine_trusting_root().await;
    let cancel = CancellationToken::new();
    assert!(ndn_app::install_engine_cert_fetcher(&engine, cancel.child_token()));
    let cert_interests = spawn_producer(producer, false).await;

    for i in 0..4 {
        let got = fetch(
            &mut consumer,
            &format!("/home/phone/photo/{i}"),
            Duration::from_millis(200),
        )
        .await;
        assert!(got.is_none(), "Data {i} must be dropped: its cert is unavailable");
    }
    assert_eq!(
        cert_interests.load(Ordering::SeqCst),
        1,
        "4 Data naming one missing cert must cost one cert Interest"
    );

    cancel.cancel();
    shutdown.shutdown().await;
}
