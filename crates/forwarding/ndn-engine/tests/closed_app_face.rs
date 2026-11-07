//! An in-process app face that closes — its app stopped, or dropped its end —
//! takes its routes with it: Interests under the prefixes it registered go to
//! the app that registers them next (an app started again), never to the
//! closed face, where they would be lost. The face itself is removed after
//! its drain, releasing everything it held.

use std::time::Duration;

use ndn_engine::{APP_FACE_DRAIN, EngineBuilder, EngineConfig, ForwarderEngine};
use ndn_face_local::InProcFace;
use ndn_packet::Name;
use ndn_transport::FaceId;
use tokio_util::sync::CancellationToken;

/// Whether `engine` routes `prefix` to `face` (within a second).
async fn routes_to(engine: &ForwarderEngine, prefix: &Name, face: FaceId) -> bool {
    for _ in 0..100 {
        let routed = engine
            .fib()
            .lpm(prefix)
            .is_some_and(|e| e.nexthops.iter().any(|n| n.face_id == face));
        if !routed {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    true
}

/// Whether `face` is still in `engine`'s face table once its drain is over
/// (polled for the drain and two seconds more).
async fn still_present_after_drain(engine: &ForwarderEngine, face: FaceId) -> bool {
    let deadline = tokio::time::Instant::now() + APP_FACE_DRAIN + Duration::from_secs(2);
    while tokio::time::Instant::now() < deadline {
        if engine.faces().get(face).is_none() {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    true
}

#[tokio::test]
async fn a_closed_app_face_takes_its_routes_with_it() {
    let (engine, _shutdown) = EngineBuilder::new(EngineConfig::default())
        .build()
        .await
        .expect("engine build");
    let prefix: Name = "/app".parse().unwrap();
    // Stopped by its cancel token (an app stopped in process), and closed by
    // dropping its end (an app gone).
    for stop_by_cancel in [true, false] {
        let id = engine.faces().alloc_id();
        let (face, handle) = InProcFace::new(id, 16);
        let cancel = CancellationToken::new();
        engine.add_face(face, cancel.clone());
        engine.fib().add_nexthop(&prefix, id, 0);
        match stop_by_cancel {
            true => cancel.cancel(),
            false => drop(handle),
        }
        assert!(
            !routes_to(&engine, &prefix, id).await,
            "a closed app face keeps no route (stopped by cancel: {stop_by_cancel})"
        );
    }
}

/// A stopped app face does not stay in the face table: after its drain it is
/// gone, and the engine holds nothing of it — the app's end sees the face's
/// sending side closed.
#[tokio::test]
async fn a_closed_app_face_is_gone_after_its_drain() {
    let (engine, _shutdown) = EngineBuilder::new(EngineConfig::default())
        .build()
        .await
        .expect("engine build");
    for stop_by_cancel in [true, false] {
        let id = engine.faces().alloc_id();
        let (face, handle) = InProcFace::new(id, 16);
        let cancel = CancellationToken::new();
        engine.add_face(face, cancel.clone());
        let kept = match stop_by_cancel {
            true => {
                cancel.cancel();
                Some(handle)
            }
            false => {
                drop(handle);
                None
            }
        };
        assert!(
            !still_present_after_drain(&engine, id).await,
            "a closed app face leaves the face table after its drain (stopped by cancel: {stop_by_cancel})"
        );
        if let Some(handle) = kept {
            let closed = tokio::time::timeout(Duration::from_secs(2), handle.recv()).await;
            assert_eq!(
                closed,
                Ok(None),
                "the engine released the stopped app face, closing what it sent the app on"
            );
        }
    }
}

/// Removing a closed app face stops that face only: an app that runs several
/// faces under one cancel token (a pool of consumers, one of them dropped)
/// keeps the others, and they still carry its Interests.
#[tokio::test]
async fn a_closed_app_face_leaves_faces_sharing_its_token_alone() {
    let (engine, _shutdown) = EngineBuilder::new(EngineConfig::default())
        .build()
        .await
        .expect("engine build");
    let app = CancellationToken::new();
    let gone = engine.faces().alloc_id();
    let (face, handle) = InProcFace::new(gone, 16);
    engine.add_face(face, app.clone());
    let kept = engine.faces().alloc_id();
    let (face, kept_handle) = InProcFace::new(kept, 16);
    engine.add_face(face, app.clone());

    drop(handle);
    assert!(
        !still_present_after_drain(&engine, gone).await,
        "the dropped face is removed"
    );
    assert!(
        !app.is_cancelled(),
        "removing one face does not stop the app that owns it"
    );
    assert!(
        engine.faces().get(kept).is_some(),
        "the app's other face stays"
    );

    // The kept face still carries the app's Interests to a producer.
    let prefix: Name = "/still/here".parse().unwrap();
    let producer_id = engine.faces().alloc_id();
    let (face, producer) = InProcFace::new(producer_id, 16);
    engine.add_face(face, CancellationToken::new());
    engine.fib().add_nexthop(&prefix, producer_id, 0);
    let interest =
        ndn_packet::encode::InterestBuilder::new("/still/here/1".parse::<Name>().unwrap()).build();
    kept_handle
        .send(interest)
        .await
        .expect("the kept face takes the app's Interest");
    let forwarded = tokio::time::timeout(Duration::from_secs(2), producer.recv()).await;
    assert!(
        matches!(forwarded, Ok(Some(_))),
        "the kept face's Interest is forwarded"
    );
}
