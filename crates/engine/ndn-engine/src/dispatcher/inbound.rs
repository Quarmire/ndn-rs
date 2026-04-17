use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc;
use tracing::{debug, trace, warn};

use ndn_packet::lp::is_lp_packet;
use ndn_transport::{FaceAddr, FaceError, FaceKind, FacePersistency};

use super::{FaceRunnerCtx, InboundPacket};

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
        rib,
        face_states,
        discovery,
        discovery_ctx,
    } = ctx;
    let kind = face.kind();
    let persistency = face_states
        .get(&face_id)
        .map(|s| s.persistency)
        .unwrap_or(FacePersistency::OnDemand);

    // Only connectionless OnDemand faces need idle-timeout tracking.
    let track_activity = matches!(persistency, FacePersistency::OnDemand)
        && !matches!(
            kind,
            FaceKind::App
                | FaceKind::Shm
                | FaceKind::Internal
                | FaceKind::Unix
                | FaceKind::Tcp
                | FaceKind::WebSocket
                | FaceKind::Management,
        );

    #[cfg(feature = "face-net")]
    let has_reliability = face_states
        .get(&face_id)
        .map(|s| s.reliability.is_some())
        .unwrap_or(false);
    #[cfg(not(feature = "face-net"))]
    let has_reliability = false;

    loop {
        let result = tokio::select! {
            _ = cancel.cancelled() => break,
            r = face.recv_bytes_with_addr()  => r,
        };
        match result {
            Ok((raw, src_addr)) => {
                trace!(face=%face_id, len=raw.len(), "face-reader: recv");

                #[cfg(feature = "face-net")]
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
                if track_activity && let Some(state) = face_states.get(&face_id) {
                    state.last_activity.store(arrival, Ordering::Relaxed);
                }
                if is_lp_packet(&raw)
                    && let Some(state) = face_states.get(&face_id)
                    && !state.uses_lp.load(Ordering::Relaxed)
                {
                    state.uses_lp.store(true, Ordering::Relaxed);
                    trace!(face=%face_id, "face-reader: LP-mode detected, enabling LP encode for outgoing");
                }

                let meta = match src_addr {
                    Some(FaceAddr::Udp(addr)) => ndn_discovery::InboundMeta::udp(addr),
                    Some(FaceAddr::Ether(mac)) => {
                        ndn_discovery::InboundMeta::ether(ndn_discovery::MacAddr::new(mac))
                    }
                    None => ndn_discovery::InboundMeta::none(),
                };

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
                    Err(mpsc::error::TrySendError::Closed(_)) => break,
                }
            }
            Err(FaceError::Closed) => {
                debug!(face=%face_id, "face closed");
                break;
            }
            Err(e) => {
                match persistency {
                    FacePersistency::Permanent => {
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

    let pit_removed = pit.remove_face(face_id.0);
    if pit_removed > 0 {
        debug!(face=%face_id, count=pit_removed, "PIT entries drained for closed face");
    }

    match kind {
        FaceKind::App | FaceKind::Internal => {}
        _ => match persistency {
            FacePersistency::Persistent | FacePersistency::Permanent => {
                debug!(face=%face_id, ?persistency, "face reader stopped (face retained)");
            }
            FacePersistency::OnDemand => {
                discovery.on_face_down(face_id, &*discovery_ctx);
                if let Some((_, state)) = face_states.remove(&face_id) {
                    state.cancel.cancel();
                }
                rib.handle_face_down(face_id, &fib);
                fib.remove_face(face_id);
                face_table.remove(face_id);
                debug!(face=%face_id, "on-demand face removed from table (FIB routes cleaned)");
            }
        },
    }
}
