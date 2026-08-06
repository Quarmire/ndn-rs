//! Gate for [`Node::serve_latest`]: a latest-wins producer serves the freshest
//! value, and a `MustBeFresh` consumer is never satisfied by a superseded cached
//! copy. Two `app_node`s on one embedded engine (with a real Content Store in the
//! pipeline) exercise the whole Node → engine → CS → peer path.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_app::{Connection, Consumer, EngineAppExt, EngineBuilder, Node};
use ndn_engine::EngineConfig;
use ndn_packet::Data;
use ndn_packet::encode::InterestBuilder;
use tokio_util::sync::CancellationToken;

/// A `MustBeFresh` fetch over `node`'s connection — the consumer posture that a
/// stale, superseded cached value must never satisfy.
async fn fetch_fresh(node: &Node, name: &str) -> Data {
    let mut consumer = Consumer::new(node.connection() as Arc<dyn Connection>);
    consumer
        .fetch_with(
            InterestBuilder::new(name.parse::<ndn_packet::Name>().unwrap())
                .must_be_fresh()
                .lifetime(Duration::from_secs(2)),
        )
        .await
        .expect("fresh fetch")
}

#[tokio::test]
async fn must_be_fresh_always_gets_the_latest_value() {
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .build()
        .await
        .expect("engine build");
    let cancel = CancellationToken::new();
    let producer = engine.app_node(cancel.child_token());
    let consumer = engine.app_node(cancel.child_token());

    // A latest-wins telemetry stream, initial value "v0".
    let (tx, rx) = tokio::sync::watch::channel(Bytes::from_static(b"v0"));
    let _guard = producer
        .serve_latest("/muas/telemetry", rx)
        .await
        .expect("serve_latest");

    // The first MustBeFresh fetch sees the initial value and caches it in the CS
    // (with freshness 0, so it is stale on arrival).
    let got = fetch_fresh(&consumer, "/muas/telemetry").await;
    assert_eq!(got.content().map(|c| c.to_vec()), Some(b"v0".to_vec()));

    // After each update, a fresh fetch must observe the *new* value — never the
    // superseded copy sitting in the Content Store under the same name.
    for i in 1..=6u32 {
        let value = format!("alt={}", 1000 + i);
        tx.send(Bytes::from(value.clone().into_bytes()))
            .expect("update");
        let got = fetch_fresh(&consumer, "/muas/telemetry").await;
        assert_eq!(
            got.content().map(|c| c.to_vec()),
            Some(value.clone().into_bytes()),
            "MustBeFresh fetch #{i} must return the latest value, not a cached one",
        );
    }

    drop(cancel);
    drop(engine);
    shutdown.shutdown().await;
}
