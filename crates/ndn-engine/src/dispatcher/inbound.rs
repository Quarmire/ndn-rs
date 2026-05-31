use std::sync::Arc;
use std::sync::atomic::Ordering;
use web_time::SystemTime;
use web_time::UNIX_EPOCH;

use tokio::sync::mpsc;
use tracing::{debug, trace, warn};

use ndn_packet::lp::is_lp_packet;
use ndn_transport::{FaceAddr, FaceError, FaceKind, FacePersistency};

use crate::observability::targets as t;

use super::{FaceRunnerCtx, InboundPacket};

pub(crate) fn inbound_meta_from_face_addr(
    src_addr: Option<FaceAddr>,
) -> ndn_discovery_core::InboundMeta {
    match src_addr {
        Some(FaceAddr::Udp(addr)) => ndn_discovery_core::InboundMeta::udp(addr),
        Some(FaceAddr::Ether(mac)) => {
            ndn_discovery_core::InboundMeta::ether(ndn_discovery_core::MacAddr::new(mac))
        }
        None => ndn_discovery_core::InboundMeta::none(),
    }
}

pub(crate) async fn run_face_reader(
    face: Arc<ndn_transport::Face>,
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
        runtime: _,
        face_lifecycle_sink,
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

    loop {
        let result = tokio::select! {
            biased;            _ = cancel.cancelled() => break,
            r = face.recv_bytes_with_addr()  => r,
        };
        match result {
            Ok((raw, src_addr)) => {
                trace!(target: t::FACE_SYSTEM, face=%face_id, len=raw.len(), "face-reader: recv");
                // Reliability Ack-consumption for socket faces runs inside
                // `link_service.recv` (the feature's `on_ingress`).

                let arrival = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as u64;
                if track_activity && let Some(state) = face_states.get(&face_id) {
                    state.last_activity.store(arrival, Ordering::Relaxed);
                }
                // Restrict `uses_lp` auto-detect to LP-framed (wire) faces.
                // IPC kinds (InProc/Unix/Shm/Internal/Compute/Management) carry
                // bare TLV; flipping `uses_lp` on one breaks NLSR's PSync, whose
                // Sync Interest carries a `NextHopFaceId` LP header and whose
                // Sync Data response is bare TLV that PSync's `first_byte ==
                // 0x06` check requires. (Framing is the right axis here, not
                // scope: a loopback UDP face is `Local` but still LP-framed.)
                if kind.uses_lp_framing()
                    && is_lp_packet(&raw)
                    && let Some(state) = face_states.get(&face_id)
                    && !state.uses_lp.load(Ordering::Relaxed)
                {
                    state.uses_lp.store(true, Ordering::Relaxed);
                    trace!(target: t::FACE_LP, face=%face_id, "face-reader: LP-mode detected, enabling LP encode for outgoing");
                }

                let meta = inbound_meta_from_face_addr(src_addr);

                match tx.try_send(InboundPacket {
                    raw,
                    face_id,
                    arrival,
                    meta,
                }) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        debug!(target: t::FWD_PIPELINE, face=%face_id, "pipeline full, dropping inbound packet");
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => break,
                }
            }
            Err(FaceError::Closed) => {
                debug!(target: t::FACE_SYSTEM, face=%face_id, "face closed");
                break;
            }
            Err(e) => match persistency {
                FacePersistency::Permanent => {
                    warn!(target: t::FACE_SYSTEM, face=%face_id, error=%e, "recv error on permanent face, retrying");
                    continue;
                }
                _ => {
                    warn!(target: t::FACE_SYSTEM, face=%face_id, error=%e, "recv error, stopping");
                    break;
                }
            },
        }
    }

    let pit_removed = pit.remove_face(face_id.0);
    if pit_removed > 0 {
        debug!(target: t::FWD_PIT, face=%face_id, count=pit_removed, "PIT entries drained for closed face");
    }

    match kind {
        FaceKind::App | FaceKind::Internal => {}
        _ => match persistency {
            FacePersistency::Persistent | FacePersistency::Permanent => {
                debug!(target: t::FACE_SYSTEM, face=%face_id, ?persistency, "face reader stopped (face retained)");
            }
            FacePersistency::OnDemand => {
                discovery.on_face_down(face_id, &*discovery_ctx);
                // Publish Down before clearing state so subscribers see
                // the transition end-to-end.
                if let Some(sink) = face_lifecycle_sink.as_ref() {
                    sink.on_down(face_id);
                }
                if let Some((_, state)) = face_states.remove(&face_id) {
                    state.cancel.cancel();
                }
                rib.handle_face_down(face_id, &fib);
                fib.remove_face(face_id);
                face_table.remove(face_id);
                debug!(target: t::FACE_SYSTEM, face=%face_id, "on-demand face removed from table (FIB routes cleaned)");
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[test]
    fn n02_face_addr_meta_yields_stable_nonzero_udp_endpoint_ids() {
        let a: SocketAddr = "192.0.2.1:6363".parse().unwrap();
        let b: SocketAddr = "192.0.2.2:6363".parse().unwrap();

        let endpoint_a = inbound_meta_from_face_addr(Some(FaceAddr::Udp(a))).endpoint_id();
        let endpoint_b = inbound_meta_from_face_addr(Some(FaceAddr::Udp(b))).endpoint_id();

        assert_ne!(endpoint_a, 0, "UDP source must not alias unicast stream");
        assert_ne!(endpoint_b, 0, "UDP source must not alias unicast stream");
        assert_ne!(
            endpoint_a, endpoint_b,
            "distinct UDP senders on one shared face need distinct reassembly keys"
        );
        assert_eq!(
            endpoint_a,
            inbound_meta_from_face_addr(Some(FaceAddr::Udp(a))).endpoint_id(),
            "same UDP sender must map to a stable endpoint id"
        );
    }

    #[test]
    fn n02_face_addr_meta_yields_stable_nonzero_ether_endpoint_ids() {
        let a = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let b = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];

        let endpoint_a = inbound_meta_from_face_addr(Some(FaceAddr::Ether(a))).endpoint_id();
        let endpoint_b = inbound_meta_from_face_addr(Some(FaceAddr::Ether(b))).endpoint_id();

        assert_ne!(endpoint_a, 0, "Ether source must not alias unicast stream");
        assert_ne!(endpoint_b, 0, "Ether source must not alias unicast stream");
        assert_ne!(
            endpoint_a, endpoint_b,
            "distinct MAC senders on one shared face need distinct reassembly keys"
        );
        assert_eq!(
            endpoint_a,
            inbound_meta_from_face_addr(Some(FaceAddr::Ether(a))).endpoint_id(),
            "same MAC sender must map to a stable endpoint id"
        );
    }

    #[test]
    fn n02_absent_face_addr_uses_unicast_endpoint_zero() {
        assert_eq!(inbound_meta_from_face_addr(None).endpoint_id(), 0);
    }
}
