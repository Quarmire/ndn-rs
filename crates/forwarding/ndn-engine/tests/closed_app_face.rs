//! An in-process app face that closes — its app stopped, or dropped its end —
//! takes its routes with it: Interests under the prefixes it registered go to
//! the app that registers them next (an app started again), never to the
//! closed face, where they would be lost.

use std::time::Duration;

use ndn_engine::{EngineBuilder, EngineConfig, ForwarderEngine};
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
