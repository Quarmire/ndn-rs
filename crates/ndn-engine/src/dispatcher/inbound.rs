use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc;
use tracing::{debug, trace, warn};

use ndn_transport::{FaceAddr, FaceError, FaceKind, FacePersistency};

use super::{FaceRunnerCtx, InboundPacket};

/// Reader loop for a single face.
///
/// Exposed as `pub(crate)` so `ForwarderEngine::add_face` can spawn readers for
/// faces registered after the initial `build()`.
///
/// Cleanup behaviour depends on the face's persistence level:
///
/// - **Permanent**: recv errors are logged but the loop retries indefinitely
///   (only cancellation or pipeline closure breaks the loop).
/// - **Persistent**: the recv loop exits on error/close, but the face is NOT
///   removed from the table or FIB — it can be re-used later.
/// - **OnDemand** (and any face without a FaceState): the face is fully removed
///   from the table and all FIB routes are cleaned up.
///
/// Internal faces (`FaceKind::App` / `FaceKind::Internal`) are long-lived
/// engine objects and are never removed on reader exit regardless of
/// persistency.
pub(crate) async fn run_face_reader(
    face: Arc<dyn ndn_transport::ErasedFace>,
    tx: mpsc::Sender<InboundPacket>,
    pit: Arc<ndn_store::Pit>,
    ctx: FaceRunnerCtx,
) {
    let FaceRunnerCtx {
        face_id,
        cancel,
        face_table,
        fib,
        face_states,
        discovery,
        discovery_ctx,
    } = ctx;
    let kind = face.kind();
    let persistency = face_states
        .get(&face_id)
        .map(|s| s.persistency)
        .unwrap_or(FacePersistency::OnDemand);

    // Cache whether this face needs idle-timeout tracking.  Local faces
    // (App, Shm, Internal) don't idle-timeout, so skip the per-packet
    // DashMap lookup + clock read for them.
    let track_activity = matches!(persistency, FacePersistency::OnDemand)
        && !matches!(kind, FaceKind::App | FaceKind::Shm | FaceKind::Internal);

    // Cache whether this face has reliability enabled.
    let has_reliability = face_states
        .get(&face_id)
        .map(|s| s.reliability.is_some())
        .unwrap_or(false);

    loop {
        let result = tokio::select! {
            _ = cancel.cancelled() => break,
            r = face.recv_bytes_with_addr()  => r,
        };
        match result {
            Ok((raw, src_addr)) => {
                trace!(face=%face_id, len=raw.len(), "face-reader: recv");

                // Feed inbound packet to reliability layer (extracts TxSeq for
                // Ack, processes piggybacked Acks from remote).
                if has_reliability
                    && let Some(state) = face_states.get(&face_id)
                    && let Some(rel) = state.reliability.as_ref()
                {
                    rel.lock().unwrap().on_receive(&raw);
                }

                let arrival = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as u64;
                // Reuse the arrival timestamp for idle tracking (avoids
                // a second clock read and DashMap lookup per packet).
                if track_activity && let Some(state) = face_states.get(&face_id) {
                    state.last_activity.store(arrival, Ordering::Relaxed);
                }
                // Build InboundMeta from the link-layer source address when
                // the face exposed it (e.g. MulticastUdpFace, NamedEtherFace).
                // Flows through InboundPacket into process_packet where
                // discovery.on_inbound is called after LP-unwrap and decode.
                let meta = match src_addr {
                    Some(FaceAddr::Udp(addr)) => ndn_discovery::InboundMeta::udp(addr),
                    Some(FaceAddr::Ether(mac)) => {
                        ndn_discovery::InboundMeta::ether(ndn_discovery::MacAddr::new(mac))
                    }
                    None => ndn_discovery::InboundMeta::none(),
                };

                // Use try_send to avoid blocking the face reader when the
                // pipeline channel is full.  Blocking here cascades back
                // through the SHM ring — the face can't recv, its peer's
                // send() spins and eventually times out, killing the peer
                // application.  Dropping the packet is the correct NDN
                // behaviour: consumers re-express, and the pipeline is
                // protected from overload.
                match tx.try_send(InboundPacket {
                    raw,
                    face_id,
                    arrival,
                    meta,
                }) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        debug!(face=%face_id, "pipeline full, dropping inbound packet");
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        break; // Runner dropped.
                    }
                }
            }
            Err(FaceError::Closed) => {
                debug!(face=%face_id, "face closed");
                break;
            }
            Err(e) => {
                match persistency {
                    FacePersistency::Permanent => {
                        // Permanent faces retry on transient errors.
                        warn!(face=%face_id, error=%e, "recv error on permanent face, retrying");
                        continue;
                    }
                    _ => {
                        warn!(face=%face_id, error=%e, "recv error, stopping");
                        break;
                    }
                }
            }
        }
    }

    // Drain PIT entries whose sole consumer was this face.
    let pit_removed = pit.remove_face(face_id.0);
    if pit_removed > 0 {
        debug!(face=%face_id, count=pit_removed, "PIT entries drained for closed face");
    }

    // Cleanup depends on face kind and persistency.
    match kind {
        FaceKind::App | FaceKind::Internal => {}
        _ => match persistency {
            FacePersistency::Persistent | FacePersistency::Permanent => {
                // Keep the face in the table and FIB — it may reconnect or be
                // re-used.  Only cancel child tokens.
                debug!(face=%face_id, ?persistency, "face reader stopped (face retained)");
            }
            FacePersistency::OnDemand => {
                // Notify discovery before removing from tables.
                discovery.on_face_down(face_id, &*discovery_ctx);
                // Fully remove the face.
                if let Some((_, state)) = face_states.remove(&face_id) {
                    state.cancel.cancel();
                }
                fib.remove_face(face_id);
                face_table.remove(face_id);
                debug!(face=%face_id, "on-demand face removed from table (FIB routes cleaned)");
            }
        },
    }
}
