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
use ndn_security::{
    Certificate, Ed25519Signer, SecurityManager, SecurityProfile, Signer, encode_cert_data,
};
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

/// The routes for the cert lead to a node that never answers (after a
/// namespace's root device was replaced, nobody there holds the earlier CA's
/// certificate any more), but the producer that delivered the Data serves
/// its own issuer chain: the engine asks the face the Data arrived on, and
/// the Data validates. Before, it was dropped at its deadline.
#[tokio::test]
async fn the_face_that_delivered_the_data_serves_its_issuer_chain() {
    let (engine, shutdown, mut consumer, producer) = engine_trusting_root().await;
    let cancel = CancellationToken::new();
    assert!(ndn_app::install_engine_cert_fetcher(&engine, cancel.child_token()));
    let silent_id = engine.faces().alloc_id();
    let (silent, silent_handle) = InProcFace::new(silent_id, 64);
    engine.add_face(silent, cancel.child_token());
    engine.fib().add_nexthop(&n("/home/phone/KEY"), silent_id, 0);
    let cert_interests = spawn_producer(producer, true).await;

    let got = fetch(&mut consumer, "/home/phone/photo/1", Duration::from_secs(3)).await;
    assert_eq!(got.as_deref(), Some(&b"photo"[..]), "Data must validate through its own face");
    assert_eq!(cert_interests.load(Ordering::SeqCst), 1, "the producer was asked once");
    drop(silent_handle);

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

/// A key outside the home trust context, certified only by itself:
/// `/home/stranger/KEY/s1`, certificate `/home/stranger/KEY/s1/self/v=1`.
fn stranger() -> Ed25519Signer {
    Ed25519Signer::from_seed(&[9; 32], n("/home/stranger/KEY/s1"))
}

/// An engine under `profile` (SecurityManager trusting only the home root)
/// with the engine-backed fetcher attached, and a producer serving
/// `/home/stranger/...` Data signed by the stranger key plus the stranger's
/// self-signed certificate under its key name. Returns the number of
/// certificate Interests that reached the producer.
async fn engine_with_self_signed_producer(
    profile: SecurityProfile,
) -> (
    ForwarderEngine,
    ShutdownHandle,
    Consumer,
    CancellationToken,
    Arc<AtomicUsize>,
) {
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
        .security_profile(profile)
        .face(consumer_face)
        .face(producer_face)
        .build()
        .await
        .expect("engine build");
    engine.set_require_data_validation(PRODUCER, true);
    engine.fib().add_nexthop(&n("/home"), PRODUCER, 0);
    let cancel = CancellationToken::new();
    assert!(ndn_app::install_engine_cert_fetcher(&engine, cancel.child_token()));

    let stranger = Arc::new(stranger());
    let cert_wire = encode_cert_data(
        &n("/home/stranger/KEY/s1/self/v=1"),
        &stranger.public_key_bytes(),
        stranger.as_ref(),
        0,
        u64::MAX,
    )
    .await
    .unwrap();
    let cert_interests = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&cert_interests);
    let producer = Producer::from_handle(producer_handle, n("/home"));
    tokio::spawn(async move {
        producer
            .serve(move |interest, responder| {
                let stranger = Arc::clone(&stranger);
                let cert_wire = cert_wire.clone();
                let counter = Arc::clone(&counter);
                async move {
                    let name = (*interest.name).clone();
                    if &name == stranger.key_name() {
                        counter.fetch_add(1, Ordering::SeqCst);
                        responder.respond_bytes(cert_wire).await.ok();
                    } else {
                        responder.respond_bytes(sign_data(name, &stranger)).await.ok();
                    }
                }
            })
            .await
            .ok();
    });
    (
        engine,
        shutdown,
        Consumer::from_handle(consumer_handle),
        cancel,
        cert_interests,
    )
}

/// `AcceptSigned` verifies each packet's signature against its signer's
/// certificate, with no trust anchor: Data signed by a key whose only
/// certificate is self-signed validates once that certificate is fetched.
/// Before the fix the fetched certificate's own Data waited in the pending
/// queue for a fetch of itself, and both timed out.
#[tokio::test]
async fn accept_signed_accepts_data_from_a_fetchable_self_signed_key() {
    let (_engine, shutdown, mut consumer, cancel, cert_interests) =
        engine_with_self_signed_producer(SecurityProfile::AcceptSigned).await;

    let got = fetch(&mut consumer, "/home/stranger/photo/1", Duration::from_secs(3)).await;
    assert_eq!(got.as_deref(), Some(&b"photo"[..]), "validly signed Data must arrive");
    assert_eq!(cert_interests.load(Ordering::SeqCst), 1);

    // The certificate is cached: the next Data validates inline.
    let got = fetch(&mut consumer, "/home/stranger/photo/2", Duration::from_secs(1)).await;
    assert_eq!(got.as_deref(), Some(&b"photo"[..]));
    assert_eq!(cert_interests.load(Ordering::SeqCst), 1);

    cancel.cancel();
    shutdown.shutdown().await;
}

/// The anchored `Default` profile refuses Data whose chain ends at a
/// self-signed certificate that is no anchor — with a verdict as soon as the
/// certificate arrives, not by letting the Data time out in the pending
/// queue; later Data of that key is refused at once, without a new fetch.
#[tokio::test]
async fn anchored_profile_refuses_unknown_self_signed_chain_promptly() {
    let (engine, shutdown, mut consumer, cancel, cert_interests) =
        engine_with_self_signed_producer(SecurityProfile::Default).await;
    let validator = engine.validator().expect("Default profile has a validator");
    let rejected = || validator.counters().1;

    // Each fetch is refused while it is still outstanding: well before the
    // 4 s certificate fetch / pending-queue timeout.
    for (i, refusals) in [(1, 2), (2, 3)] {
        let started = std::time::Instant::now();
        let consumer_task = tokio::spawn(async move {
            let name = format!("/home/stranger/photo/{i}");
            let got = fetch(&mut consumer, &name, Duration::from_secs(1)).await;
            (consumer, got)
        });
        // First the certificate and the Data waiting for it, then the next
        // Data alone, at once.
        while rejected() < refusals {
            assert!(
                started.elapsed() < Duration::from_millis(1500),
                "Data {i}: refusal must not wait for a timeout (rejected {})",
                rejected()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let got;
        (consumer, got) = consumer_task.await.unwrap();
        assert!(got.is_none(), "Data under an untrusted self-signed root must not be delivered");
        assert_eq!(cert_interests.load(Ordering::SeqCst), 1, "one certificate fetch");
    }

    cancel.cancel();
    shutdown.shutdown().await;
}
