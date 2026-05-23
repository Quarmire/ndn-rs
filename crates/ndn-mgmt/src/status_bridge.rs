//! `/localhost/<proto>/status` status-surface bridge.
//!
//! Mounts a long-lived Producer at a protocol's status prefix whose
//! Content is the binary TLV from `status_provider`. Matches the wire
//! consumed by ndnd's `dvc status` at `/localhost/nlsr/status`
//! (`~/Documents/Dev/ndnd/tools/dvc/dvc_status.go`).

use std::sync::Arc;

use bytes::Bytes;
use ndn_engine::{EngineBuilder, PostBuildQueue};
use ndn_packet::Name;

/// Mount a Producer at `prefix` whose Content is the bytes returned
/// by `status_provider` (called once per Interest, so keep it cheap).
pub fn mount_routing_status<F>(
    builder: &mut EngineBuilder,
    post_build: &mut PostBuildQueue,
    prefix: Name,
    status_provider: F,
) where
    F: Fn() -> Bytes + Send + Sync + 'static,
{
    let face_id = builder.alloc_face_id();
    let (face, handle) =
        ndn_face_local::InProcFace::new_kind(face_id, 16, ndn_transport::face::FaceKind::Internal);
    builder.add_face(face);
    post_build.add_fib_entry(prefix.clone(), face_id, 0);

    let provider: Arc<dyn Fn() -> Bytes + Send + Sync + 'static> = Arc::new(status_provider);
    post_build.defer(move |_engine, cancel| {
        let producer_cancel = cancel.clone();
        tokio::spawn(async move {
            use ndn_app::{Connection, InProcConnection, Producer};
            let conn = Arc::new(InProcConnection::new(handle)) as Arc<dyn Connection>;
            let producer = Producer::new(conn, Name::root());
            let provider = Arc::clone(&provider);
            let serve_fut = producer.serve(move |interest, responder| {
                let provider = Arc::clone(&provider);
                async move {
                    let bytes = provider();
                    let name: Name = (*interest.name).clone();
                    let _ = responder.respond(name, bytes).await;
                }
            });
            tokio::select! {
                biased;
                _ = producer_cancel.cancelled() => {}
                _ = serve_fut => {}
            }
        });
    });
    tracing::info!(
        target: "routing.status_bridge",
        prefix = %prefix,
        face = face_id.0,
        "status-bridge Producer mounted",
    );
}
