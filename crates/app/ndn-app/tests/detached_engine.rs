//! GATE for `ShutdownHandle::detach()` (skyfall FIELD-REPORT-2 §2): consuming the handle must
//! leave the engine fully alive — `detach()` is the named replacement for the
//! `std::mem::forget(shutdown)` idiom, expressing "run for the process lifetime" as intent
//! instead of a leak workaround. Verified against the mechanism: after `detach()` the engine
//! still allocates app faces, installs FIB routes, and forwards a real Interest/Data
//! round-trip between two app nodes.

use ndn_app::{EngineAppExt, EngineBuilder};
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn detached_engine_keeps_forwarding() {
    let (engine, shutdown) = EngineBuilder::new(Default::default())
        .build()
        .await
        .expect("engine");

    // The engine runs for the rest of the process — the handle is consumed, not leaked-by-hand.
    shutdown.detach();

    let cancel = CancellationToken::new();
    let alice = engine.app_node(cancel.child_token());
    let bob = engine.app_node(cancel.child_token());

    let _guard = alice
        .serve("/alice", |i, r| async move {
            let _ = r.respond((*i.name).clone(), "hi").await;
        })
        .await
        .expect("serve");

    let data = bob.fetch("/alice/greeting").await.expect(
        "a detached engine must keep forwarding — detach() may not tear anything down",
    );
    assert_eq!(
        data.content().map(|c| c.as_ref()),
        Some(&b"hi"[..]),
        "the round-trip crossed the detached engine intact"
    );
}
