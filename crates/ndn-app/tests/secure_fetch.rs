//! Reference: **the safe consumer path**, end to end and compiling.
//!
//! A producer signs Data with a real identity key (whose self-signed cert is
//! its own trust anchor); the consumer fetches and **verifies**, getting
//! [`SafeData`](ndn_security::SafeData) only when the signature *and* the trust
//! schema check out. Contrast `embedded.rs`, which fetches **unsigned** Data and
//! never validates — the footgun this example exists to replace.
//!
//! The two safe surfaces are both shown:
//! - `fetch_verified(name, &validator)` — the one-line safe fetch;
//! - `fetch_unverified(name)` → `Unverified<Data>` — forces an explicit
//!   `.verify(&validator)` (or a loud `.trust_unchecked()`); no silent `Data`.

use ndn_face_native::local::InProcFace;
use ndn_packet::Name;
use ndn_packet::encode::DataBuilder;
use ndn_security::{KeyChain, SignWith};
use ndn_transport::FaceId;

use ndn_app::{Consumer, EngineBuilder, Producer};
use ndn_engine::EngineConfig;

#[tokio::test]
async fn consumer_fetch_verified_yields_safedata() {
    // Producer identity: an ephemeral keychain whose self-signed cert is its own
    // trust anchor — the anchor the consumer pins.
    let producer_kc = KeyChain::ephemeral("/demo/alice").expect("keychain");
    let signer = producer_kc.signer().expect("signer");

    // Embedded engine with a consumer face and a producer face.
    let (consumer_face, consumer_handle) = InProcFace::new(FaceId(1), 64);
    let (producer_face, producer_handle) = InProcFace::new(FaceId(2), 64);
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(consumer_face)
        .face(producer_face)
        .build()
        .await
        .expect("engine build");

    let prefix: Name = "/demo/alice".parse().unwrap();
    engine.fib().add_nexthop(&prefix, FaceId(2), 0);

    let mut consumer = Consumer::from_handle(consumer_handle);
    let producer = Producer::from_handle(producer_handle, prefix.clone());

    let producer_task = tokio::spawn(async move {
        producer
            .serve(move |interest, responder| {
                let name = (*interest.name).clone();
                let signer = signer.clone();
                async move {
                    // Signed with the producer's identity key — *not* an unsigned
                    // `DataBuilder::build()`.
                    let wire = DataBuilder::new(name, b"authenticated payload")
                        .sign_with_sync(&*signer)
                        .expect("sign");
                    responder.respond_bytes(wire).await.ok();
                }
            })
            .await
    });

    let validator = producer_kc.validator();

    // The safe path: fetch + verify against the pinned anchor → SafeData.
    let safe = consumer
        .fetch_verified("/demo/alice/thing", &validator)
        .await
        .expect("verified fetch yields SafeData");
    assert_eq!(
        safe.data().content().map(|c| c.to_vec()),
        Some(b"authenticated payload".to_vec()),
    );

    // The explicit-unverified surface forces a choice — you can't get a usable
    // value without `.verify()` (here) or a loud `.trust_unchecked()`.
    let unverified = consumer
        .fetch_unverified("/demo/alice/thing")
        .await
        .expect("fetch");
    assert!(
        unverified.verify(&validator).await.is_ok(),
        "the same Data verifies on the explicit path too"
    );

    drop(consumer);
    drop(engine);
    shutdown.shutdown().await;
    let _ = producer_task.await;
}
