//! Integration tests for the unified [`Node`] over the in-process harness.
//!
//! Two `app_node`s on one embedded engine talk to each other with no sockets:
//! one `serve`s a prefix, the other `fetch`es / `object`s it — exercising the
//! whole Node → DemuxConnection → engine → FIB → peer face path.

use std::sync::Arc;
use std::time::Duration;

use ndn_app::{EngineAppExt, EngineBuilder, InProcConnection, Node};
use ndn_engine::EngineConfig;
use ndn_face::local::InProcFace;
use ndn_strategy::MulticastStrategy;
use ndn_transport::FaceId;
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
            let _ = reply
                .respond((*interest.name).clone(), "hi from alice")
                .await;
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

/// An engine-backed `Node` (app_node) is a full node: it serves a segmented RDR
/// object on a dedicated face and the peer reassembles it — proving the
/// engine-backed ConnectionProvider mints working faces in-process.
#[tokio::test]
async fn engine_node_serve_object_roundtrip() {
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .build()
        .await
        .expect("engine build");
    let cancel = CancellationToken::new();
    let alice = engine.app_node(cancel.child_token());
    let bob = engine.app_node(cancel.child_token());

    // Larger than one segment, so this exercises RDR metadata + windowed fetch.
    let payload = vec![0x5Au8; 20_000];
    let _guard = alice
        .serve_object("/alice/blob", payload.clone())
        .await
        .expect("serve_object");

    let got = bob
        .object("/alice/blob")
        .fetch()
        .await
        .expect("fetch_object");
    assert_eq!(got.len(), payload.len());
    assert_eq!(&got[..], &payload[..]);

    drop(cancel);
    drop(engine);
    shutdown.shutdown().await;
}

/// Two engine-backed nodes converge over SVS: alice `publish`es into a group,
/// bob `subscribe`s and receives the sample — proving the sync patterns work
/// fully in-process over the engine-backed connector (each on its own face).
#[tokio::test]
async fn engine_node_publish_subscribe() {
    // MulticastStrategy so sync Interests fan out to every in-process face.
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .strategy(MulticastStrategy::new())
        .build()
        .await
        .expect("engine build");
    let cancel = CancellationToken::new();
    let alice = engine.app_node(cancel.child_token());
    let bob = engine.app_node(cancel.child_token());

    let publisher = alice.publish("/svs/room", "/alice").await.expect("publish");
    let mut subscriber = bob.subscribe("/svs/room", "/bob").await.expect("subscribe");

    // Let both sides register their group prefix and exchange initial state.
    tokio::time::sleep(Duration::from_millis(100)).await;
    publisher.put(b"hello room").await.expect("put");

    let sample = tokio::time::timeout(Duration::from_secs(5), subscriber.recv())
        .await
        .expect("sample within timeout")
        .expect("sample");
    assert_eq!(sample.payload.as_deref(), Some(&b"hello room"[..]));

    drop(cancel);
    drop(engine);
    shutdown.shutdown().await;
}

/// A `Node` built from a single pre-made connection (`from_connection`) cannot
/// open a second stream, so the dedicated patterns report Unsupported rather
/// than panicking or hanging — the caller is pointed at `connection()`.
#[tokio::test]
async fn pinned_node_rejects_sync_patterns() {
    let (face, handle) = InProcFace::new(FaceId(900), 64);
    drop(face); // not wired to any engine; we only test that Pinned rejects
    let node = Node::from_connection(Arc::new(InProcConnection::new(handle)));

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
}
