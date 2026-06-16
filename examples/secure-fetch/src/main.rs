//! The smallest complete, **signed-and-verified** NDN exchange — runnable.
//!
//! ```sh
//! cargo run -p example-secure-fetch
//! ```
//!
//! In NDN, security travels with the data: a producer signs each `Data` with its
//! identity key, and a consumer accepts it only after checking that signature
//! against a trust anchor it has pinned. That check is the whole point of NDN
//! over IP — so this first example *does* it, rather than leaving it for later.
//!
//! The payoff type is [`SafeData`](ndn_security::SafeData): you can only obtain
//! one by verifying, so "did I check this?" is answered by the compiler, not by
//! convention. The unverified surface ([`Consumer::fetch_unverified`]) hands back
//! an [`Unverified<Data>`](ndn_security::Unverified) that forces an explicit
//! `.verify(...)` or a loud, greppable `.trust_unchecked()` — there is no silent
//! path to a usable packet.
//!
//! This runs the engine in-process (no external forwarder) so the whole exchange
//! is one file; talking to a standalone `ndn-fwd` is covered by the
//! "Ten-minute producer" quickstart in the wiki.

use ndn_app::{Consumer, EngineBuilder, Producer};
use ndn_engine::EngineConfig;
use ndn_face::local::InProcFace;
use ndn_packet::Name;
use ndn_packet::encode::DataBuilder;
use ndn_security::{KeyChain, SignWith};
use ndn_transport::FaceId;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. The producer's identity. Its self-signed certificate is the trust
    //    anchor the consumer will pin — "I trust data signed by /demo/alice".
    let producer_kc = KeyChain::ephemeral("/demo/alice")?;
    let signer = producer_kc.signer()?;

    // 2. An in-process engine with a face for the producer and one for the
    //    consumer, and a route sending /demo/alice Interests to the producer.
    let (consumer_face, consumer_handle) = InProcFace::new(FaceId(1), 64);
    let (producer_face, producer_handle) = InProcFace::new(FaceId(2), 64);
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(consumer_face)
        .face(producer_face)
        .build()
        .await
        .map_err(|e| anyhow::anyhow!("engine build: {e}"))?;
    let prefix: Name = "/demo/alice".parse()?;
    engine.fib().add_nexthop(&prefix, FaceId(2), 0);

    let consumer = Consumer::from_handle(consumer_handle);
    let producer = Producer::from_handle(producer_handle, prefix.clone());

    // 3. The producer serves Data signed with its identity key — not an
    //    unsigned `DataBuilder::build()`, which only carries a digest (integrity,
    //    not authorship).
    let producer_task = tokio::spawn(async move {
        producer
            .serve(move |interest, responder| {
                let name = (*interest.name).clone();
                let signer = signer.clone();
                async move {
                    let wire = DataBuilder::new(name, b"authenticated payload")
                        .sign_with_sync(&*signer)
                        .expect("sign");
                    responder.respond_bytes(wire).await.ok();
                }
            })
            .await
    });

    // 4. Decide trust once, then fetch. `verifying(validator)` pins the anchor;
    //    after that the short verb `fetch` returns `SafeData` — the obvious call
    //    is the safe one, and there is no way to get a `SafeData` you didn't
    //    verify.
    let mut consumer = consumer.verifying(producer_kc.validator());
    let safe = consumer
        .fetch("/demo/alice/thing")
        .await
        .map_err(|e| anyhow::anyhow!("verified fetch: {e}"))?;
    println!(
        "verified: {} bytes under {} — signature checked against /demo/alice",
        safe.data().content().map(|c| c.len()).unwrap_or(0),
        safe.data().name,
    );

    // 5. The explicit-unverified surface, for contrast: drop to the raw consumer
    //    and you still cannot use the bytes without a decision — `.verify()`
    //    here, or the loud `.trust_unchecked()` you can grep for in review.
    let unverified = consumer
        .unverified()
        .fetch_unverified("/demo/alice/thing")
        .await
        .map_err(|e| anyhow::anyhow!("fetch: {e}"))?;
    match unverified.verify(consumer.validator()).await {
        Ok(_) => println!("explicit path: same Data verifies too"),
        Err(e) => println!("explicit path: refused ({e})"),
    }

    drop(consumer);
    drop(engine);
    shutdown.shutdown().await;
    let _ = producer_task.await;
    Ok(())
}
