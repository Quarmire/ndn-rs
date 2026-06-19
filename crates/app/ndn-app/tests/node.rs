//! Integration tests for the unified [`Node`] over the in-process harness.
//!
//! Two `app_node`s on one embedded engine talk to each other with no sockets:
//! one `serve`s a prefix, the other `fetch`es / `object`s it — exercising the
//! whole Node → DemuxConnection → engine → FIB → peer face path.

use ndn_app::{EngineAppExt, EngineBuilder};
use ndn_engine::EngineConfig;
use tokio_util::sync::CancellationToken;

/// alice serves a dynamic prefix; bob fetches a single Data over it.
#[tokio::test]
async fn node_serve_and_fetch() {
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .build()
        .await
        .expect("engine build");
    let cancel = CancellationToken::new();
    let alice = engine.app_node(cancel.child_token());
    let bob = engine.app_node(cancel.child_token());

    let _guard = alice
        .serve("/alice", |interest, reply| async move {
            let _ = reply.respond((*interest.name).clone(), "hi from alice").await;
        })
        .await
        .expect("serve");

    let data = bob.fetch("/alice/greeting").await.expect("fetch");
    assert_eq!(
        data.content().map(|c| c.to_vec()),
        Some(b"hi from alice".to_vec()),
    );

    drop(cancel);
    drop(engine);
    shutdown.shutdown().await;
}

/// A larger Content payload round-trips intact through the demux + engine.
#[tokio::test]
async fn node_fetch_large_data() {
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .build()
        .await
        .expect("engine build");
    let cancel = CancellationToken::new();
    let alice = engine.app_node(cancel.child_token());
    let bob = engine.app_node(cancel.child_token());

    let payload = vec![0xABu8; 40_000];
    let expected = payload.clone();
    let _guard = alice
        .serve("/alice/blob", move |interest, reply| {
            let payload = payload.clone();
            async move {
                let _ = reply.respond((*interest.name).clone(), payload).await;
            }
        })
        .await
        .expect("serve");

    let data = bob.fetch("/alice/blob").await.expect("fetch");
    assert_eq!(data.content().map(|c| c.to_vec()), Some(expected));

    drop(cancel);
    drop(engine);
    shutdown.shutdown().await;
}

/// A `Node` built from a single connection rejects the patterns that need a
/// dedicated stream, pointing the caller at `connection()`.
#[tokio::test]
async fn pinned_node_rejects_sync_patterns() {
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .build()
        .await
        .expect("engine build");
    let cancel = CancellationToken::new();
    let node = engine.app_node(cancel.child_token());

    // app_node is a from_connection (Pinned) handle: no re-dial. These patterns
    // need a dedicated stream, so they must report Unsupported (not panic/hang).
    assert!(matches!(
        node.publish("/g", "/me").await,
        Err(ndn_app::AppError::Unsupported(_))
    ));
    assert!(matches!(
        node.query("/svc").await,
        Err(ndn_app::AppError::Unsupported(_))
    ));
    assert!(matches!(
        node.serve_object("/o", "x").await,
        Err(ndn_app::AppError::Unsupported(_))
    ));

    drop(cancel);
    drop(engine);
    shutdown.shutdown().await;
}
