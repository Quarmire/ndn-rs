//! The front door: the smallest real [`Node`] app — runnable.
//!
//! ```sh
//! cargo run -p example-hello-node
//! ```
//!
//! One in-process forwarding engine, two [`Node`]s on it: one serves a Data
//! under `/hello`, the other fetches it back and prints it. No external
//! forwarder, no sockets, no configuration.
//!
//! `node.fetch` here is the unverified surface (the reply is a
//! `DigestSha256` Data — integrity, not authorship). The verified path is
//! one call away — `node.verifying(validator).fetch(...)` returns
//! [`SafeData`](ndn::SafeData) — and `example-secure-fetch` shows it end
//! to end, trust anchor included.

use ndn::{EngineAppExt, EngineBuilder, EngineConfig, Node};
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default()).build().await?;
    let cancel = CancellationToken::new();
    let alice: Node = engine.app_node(cancel.child_token());
    let bob: Node = engine.app_node(cancel.child_token());

    let _guard = alice
        .serve("/hello", |interest, reply| async move {
            let _ = reply.respond((*interest.name).clone(), "hello from ndn-rs").await;
        })
        .await?;

    let data = bob.fetch("/hello/world").await?;
    let payload = data.content().map(|c| c.as_ref()).unwrap_or_default();
    println!("{} => {}", data.name, String::from_utf8_lossy(payload));

    cancel.cancel();
    shutdown.shutdown().await;
    Ok(())
}
