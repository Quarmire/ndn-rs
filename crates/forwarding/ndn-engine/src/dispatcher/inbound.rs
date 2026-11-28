use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio::sync::mpsc;
use tracing::{debug, trace, warn};

use ndn_packet::lp::is_lp_packet;
use ndn_transport::{FaceAddr, FaceError, FaceKind, FacePersistency, SIDE_MARKER};

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

/// How long an app face that stopped sending stays in the face table before
/// it is removed.
///
/// An app face stops sending when its app is gone (its end dropped, its
/// socket closed) or stopped (its cancel token fired). Its routes go at once;
/// the face itself stays this long so the Data of Interests the app sent just
/// before it stopped — still queued in the pipeline — can go back to an app
/// that only half-closed. Nothing relies on the drain for correctness: an app
/// that still waits for Data keeps its sending end open while it waits.
pub const APP_FACE_DRAIN: Duration = Duration::from_secs(1);

/// Yields a stream lane makes, looking for room each time, before it sleeps between looks
/// (the first hop's wait does the same: `ndn-app`'s `EngineConnection::send_side`).
const LANE_YIELDS: u32 = 256;
/// The first sleep between looks; it doubles after each [`LANE_BACKOFF_EVERY`] looks, to 16 times
/// this.
const LANE_RECHECK: Duration = Duration::from_millis(1);
const LANE_BACKOFF_EVERY: u32 = 32;

/// What a face's stream lane needs of the engine.
struct SideLane {
    face_id: ndn_transport::FaceId,
    cancel: tokio_util::sync::CancellationToken,
    face_table: Arc<ndn_transport::FaceTable>,
    face_states: Arc<dashmap::DashMap<ndn_transport::FaceId, crate::FaceState>>,
    runtime: Arc<dyn ndn_runtime::Runtime>,
    side: Arc<crate::side::SideTable>,
}

/// Read the frames of a face's channel stream (`Face::recv_side_stream`) and route each as the
/// face reader routes a side frame, **after waiting until every live sink of its route has room
/// for it** ([`SideTable::stream_room`](crate::side::SideTable::stream_room)), for at most
/// [`STREAM_HOLD_MAX`](crate::side::STREAM_HOLD_MAX). While it waits it takes nothing more from
/// the stream: the transport stops reading the peer's octets and the peer's flow control, and
/// the first-hop hold-back behind it, slow the sender. A stream cannot drop a frame without
/// breaking its channel's order, so the loss of a stream frame at the forwarder is the
/// exception (a sink that stayed full for the bound, counted), not the congestion response.
/// Ends when the face's stream ends or the face's token fires; the face reader, which reads
/// everything else, is not told.
async fn run_side_stream_lane(face: Arc<ndn_transport::Face>, lane: SideLane) {
    let SideLane {
        face_id,
        cancel,
        face_table,
        face_states,
        runtime,
        side,
    } = lane;
    loop {
        let frame = tokio::select! {
            biased;
            _ = cancel.cancelled() => return,
            r = face.recv_side_stream() => match r {
                Ok(frame) => frame,
                Err(_) => return,
            },
        };
        if let Some(state) = face_states.get(&face_id) {
            state
                .counters
                .in_side_frames
                .fetch_add(1, Ordering::Relaxed);
            state
                .counters
                .in_side_bytes
                .fetch_add(frame.len() as u64, Ordering::Relaxed);
        }
        if !side.stream_room(face_id, &frame, &face_table) {
            side.count_stream_held();
            let (mut yields, mut sleeps, mut waited) = (0u32, 0u32, Duration::ZERO);
            loop {
                if yields < LANE_YIELDS {
                    yields += 1;
                    tokio::task::yield_now().await;
                } else {
                    let step = LANE_RECHECK * (1 << (sleeps / LANE_BACKOFF_EVERY).min(4));
                    sleeps += 1;
                    waited += step;
                    tokio::select! {
                        biased;
                        _ = cancel.cancelled() => return,
                        () = runtime.sleep(step) => {}
                    }
                }
                if side.stream_room(face_id, &frame, &face_table) {
                    break;
                }
                if waited >= crate::side::STREAM_HOLD_MAX {
                    side.count_stream_stalled();
                    break;
                }
            }
        }
        let outcome = side.on_frame(face_id, frame, &face_table);
        trace!(target: t::FACE_SYSTEM, face=%face_id, ?outcome, "stream lane: side frame");
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
        runtime,
        face_lifecycle_sink,
        side,
    } = ctx;

    // A face that reads its channel stream apart (a QUIC link) has that stream's frames read by
    // a task of their own, which can wait for room at a sink without this reader ever waiting:
    // the NDN packets and datagram frames of the face keep flowing (channel.md §14.4).
    if face.side_stream_lane() {
        runtime.spawn(Box::pin(run_side_stream_lane(
            Arc::clone(&face),
            SideLane {
                face_id,
                cancel: cancel.clone(),
                face_table: Arc::clone(&face_table),
                face_states: Arc::clone(&face_states),
                runtime: Arc::clone(&runtime),
                side: Arc::clone(&side),
            },
        )));
    }
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

    // True when the reader stopped because the underlying connection failed
    // (closed / recv error), as opposed to a deliberate `cancel` (suspend /
    // shutdown). A dropped Persistent face is dead and gets cleaned up so a
    // supervisor can re-dial it; a suspended one is retained for resume.
    let mut errored = false;
    loop {
        let result = tokio::select! {
            biased;            _ = cancel.cancelled() => break,
            r = face.recv_bytes_with_addr()  => r,
        };
        match result {
            Ok((raw, src_addr)) => {
                // A side frame (`ndn_transport::side`) is not an NDN packet: peel it
                // here, with one comparison, before LP detection and before the
                // bounded pipeline channel, so it never costs a PIT entry, a spawned
                // task, an `in_drops` count or a malformed-packet verdict. The side
                // table routes it (or drops it, counted, when no route matches); the
                // call never blocks, so this reader keeps reading the face's NDN
                // packets whatever a sink does with the frame.
                if raw.first() == Some(&SIDE_MARKER) {
                    if let Some(state) = face_states.get(&face_id) {
                        state
                            .counters
                            .in_side_frames
                            .fetch_add(1, Ordering::Relaxed);
                        state
                            .counters
                            .in_side_bytes
                            .fetch_add(raw.len() as u64, Ordering::Relaxed);
                        // A side frame is traffic on the face as an NDN packet is:
                        // it keeps a connectionless on-demand face from idling out.
                        if track_activity {
                            state
                                .last_activity
                                .store(runtime.unix_nanos(), Ordering::Relaxed);
                        }
                    }
                    let outcome = side.on_frame(face_id, raw, &face_table);
                    trace!(target: t::FACE_SYSTEM, face=%face_id, ?outcome, "face-reader: side frame");
                    // A sink that refused the frame (a link whose send buffer this reader has
                    // filled without letting the link's own task run) gets its turn before the
                    // next frame is read, so a burst already queued at this face does not all
                    // find the link full for lack of a poll. It is a yield, not a wait: the
                    // fan-out still never blocks on a sink, and a sink that stays full costs
                    // only the frames it refuses.
                    if matches!(outcome, crate::side::SideOutcome::Routed { dropped, .. } if dropped > 0)
                    {
                        tokio::task::yield_now().await;
                    }
                    continue;
                }
                trace!(target: t::FACE_SYSTEM, face=%face_id, len=raw.len(), "face-reader: recv");
                // Reliability Ack-consumption for socket faces runs inside
                // `link_service.recv` (the feature's `on_ingress`).

                // Arrival is stamped via the runtime clock seam, so a virtual runtime makes
                // socket-received packets deterministic too (the inject_packet path supplies
                // arrival explicitly). (ndn-lab slice 0b.)
                let arrival = runtime.unix_nanos();
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
                        if let Some(state) = face_states.get(&face_id) {
                            state.counters.in_drops.fetch_add(1, Ordering::Relaxed);
                        }
                        debug!(target: t::FWD_PIPELINE, face=%face_id, "pipeline full, dropping inbound packet");
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => break,
                }
            }
            Err(FaceError::Closed) => {
                debug!(target: t::FACE_SYSTEM, face=%face_id, "face closed");
                errored = true;
                break;
            }
            Err(e) => match persistency {
                FacePersistency::Permanent => {
                    warn!(target: t::FACE_SYSTEM, face=%face_id, error=%e, "recv error on permanent face, retrying");
                    continue;
                }
                _ => {
                    warn!(target: t::FACE_SYSTEM, face=%face_id, error=%e, "recv error, stopping");
                    errored = true;
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
        // The engine's own internal faces live as long as the engine.
        FaceKind::Internal => {}
        // An app face that stopped sending can no longer answer an Interest:
        // its routes go at once, so Interests under its prefixes reach the app
        // that registers them next (one started again) instead of a dead face.
        // Then the face goes, with whatever routes or PIT entries the pipeline
        // still made for it, so a gone app holds no face, socket or task. An
        // app that closed its sending end may still read: its face stays for
        // `APP_FACE_DRAIN` first. A stopped one (its cancel token fired) has
        // no sender left to drain.
        FaceKind::App => {
            rib.handle_face_down(face_id, &fib);
            fib.remove_face(face_id);
            side.remove_face(face_id);
            debug!(target: t::FACE_SYSTEM, face=%face_id, "app face stopped sending: its routes removed");
            if errored {
                drop(tx);
                drop(face);
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => {}
                    _ = runtime.sleep(APP_FACE_DRAIN) => {}
                }
            }
            discovery.on_face_down(face_id, &*discovery_ctx);
            if let Some(sink) = face_lifecycle_sink.as_ref() {
                sink.on_down(face_id);
            }
            if let Some((_, state)) = face_states.remove(&face_id) {
                state.cancel.cancel();
            }
            rib.handle_face_down(face_id, &fib);
            fib.remove_face(face_id);
            face_table.remove(face_id);
            side.remove_face(face_id);
            pit.remove_face(face_id.0);
            debug!(target: t::FACE_SYSTEM, face=%face_id, "app face removed");
        }
        _ => match persistency {
            FacePersistency::Permanent => {
                debug!(target: t::FACE_SYSTEM, face=%face_id, "face reader stopped (permanent face retained)");
            }
            // Suspend/shutdown (cancel): retain the face + state + routes so
            // `resume_network_faces` brings it back unchanged.
            FacePersistency::Persistent if !errored => {
                debug!(target: t::FACE_SYSTEM, face=%face_id, "persistent face reader stopped (retained for resume)");
            }
            // Connection dropped: the face is dead. Publish Down and drop it from
            // the table so a supervisor (e.g. `ndn-mobile`'s peer dialer) can
            // re-dial at the SAME id — but KEEP its FIB routes (Persistent means
            // routes survive a drop), so the instant the re-dial succeeds the
            // upstream is live again with no route churn.
            FacePersistency::Persistent => {
                if let Some(sink) = face_lifecycle_sink.as_ref() {
                    sink.on_down(face_id);
                }
                if let Some((_, state)) = face_states.remove(&face_id) {
                    state.cancel.cancel();
                }
                face_table.remove(face_id);
                side.remove_face(face_id);
                debug!(target: t::FACE_SYSTEM, face=%face_id, "persistent face dropped on connection loss (routes kept for re-dial)");
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
                side.remove_face(face_id);
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
