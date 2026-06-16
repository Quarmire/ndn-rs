//! `DemuxConnection` lets one connection serve a producer and run a consumer at
//! the same time — the thing a bare `Connection` (single shared `recv`) can't do.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_face::local::InProcFace;
use ndn_transport::FaceId;

use ndn_app::{Connection, Consumer, DemuxConnection, EngineBuilder, InProcConnection};
use ndn_engine::EngineConfig;

/// Two endpoints over one engine, each a `DemuxConnection`: endpoint A serves
/// `/a` while it fetches `/b`; endpoint B serves `/b` while it fetches `/a`.
/// Both fetches resolve — the serve handler and the fetch coexist on the same
/// connection without racing the `recv` stream.
#[tokio::test]
async fn demux_serves_and_fetches_on_one_connection() {
    let (face_a, handle_a) = InProcFace::new(FaceId(1), 64);
    let (face_b, handle_b) = InProcFace::new(FaceId(2), 64);

    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(face_a)
        .face(face_b)
        .build()
        .await
        .expect("engine build");
    engine.fib().add_nexthop(&"/a".parse().unwrap(), FaceId(1), 0);
    engine.fib().add_nexthop(&"/b".parse().unwrap(), FaceId(2), 0);

    let a = DemuxConnection::new(Arc::new(InProcConnection::new(handle_a)));
    let b = DemuxConnection::new(Arc::new(InProcConnection::new(handle_b)));

    // A serves /a, B serves /b — both long-lived, concurrently with their fetches.
    let a_serve = a.clone();
    let serve_a = tokio::spawn(async move {
        a_serve
            .serve("/a".parse().unwrap(), |interest, responder| async move {
                let _ = responder.respond((*interest.name).clone(), Bytes::from_static(b"from-a")).await;
            })
            .await
    });
    let b_serve = b.clone();
    let serve_b = tokio::spawn(async move {
        b_serve
            .serve("/b".parse().unwrap(), |interest, responder| async move {
                let _ = responder.respond((*interest.name).clone(), Bytes::from_static(b"from-b")).await;
            })
            .await
    });

    // Give the serves a moment to register their prefixes.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // A fetches /b (served by B) while A is itself serving /a; B fetches /a.
    let mut a_consumer = Consumer::new(a.clone() as Arc<dyn Connection>);
    let mut b_consumer = Consumer::new(b.clone() as Arc<dyn Connection>);
    let from_b = a_consumer.fetch("/b").await.expect("A fetches /b");
    let from_a = b_consumer.fetch("/a").await.expect("B fetches /a");

    assert_eq!(from_b.content().map(|c| c.to_vec()), Some(b"from-b".to_vec()));
    assert_eq!(
        from_a.content().map(|c| c.to_vec()),
        Some(b"from-a".to_vec()),
        "A served /a while concurrently fetching /b — no recv race",
    );

    drop(a_consumer);
    drop(b_consumer);
    drop(a);
    drop(b);
    drop(engine);
    shutdown.shutdown().await;
    serve_a.abort();
    serve_b.abort();
}
