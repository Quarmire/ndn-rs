//! `SvsServiceDiscovery` — SVS-backed push service-record notifications.
//!
//! Joins the SVS sync group at `/ndn/local/sd/updates/` so that service record
//! *changes* are pushed to all group members rather than requiring periodic
//! pulls.  Nodes that only need occasional browsability continue to use
//! `ServiceDiscoveryProtocol` via `/ndn/local/sd/services/`.
//!
//! ## Architecture
//!
//! The SVS background task is fully async (`join_svs_group`), but
//! `DiscoveryProtocol` hooks are synchronous. The bridge uses two
//! `tokio::sync::mpsc` channels:
//!
//! ```text
//!  on_inbound ──►  incoming_tx ──► SVS task (merge, detect gaps)
//!  SVS task ──► outgoing_tx ──► on_tick drain ──► ctx.send_on (all neighbor faces)
//!  SVS updates ──► update_rx ──► on_tick drain ──► express fetch Interests
//! ```
//!
//! `on_tick` performs non-blocking draining of both channels using
//! `try_recv()`.  This keeps the synchronous discovery hooks from blocking
//! while still processing all pending work in bounded time.
//!
//! ## Packet routing
//!
//! All SVS Sync Interests arrive under `/ndn/local/sd/updates/svs/…`.
//! This protocol claims `/ndn/local/sd/updates/`, so `CompositeDiscovery`
//! routes these packets here before the forwarding pipeline sees them.
//! Service record Data packets arrive under `/ndn/local/sd/services/` and
//! are handled by `ServiceDiscoveryProtocol`; this protocol only handles the
//! sync control plane.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use bytes::Bytes;
use ndn_packet::Name;
use ndn_packet::encode::InterestBuilder;
use ndn_transport::FaceId;
use tokio::sync::mpsc;
use tracing::{debug, trace, warn};

use crate::context::DiscoveryContext;
use crate::protocol::{DiscoveryProtocol, InboundMeta, ProtocolId};
use crate::scope::sd_updates;
use crate::wire::parse_raw_interest;

use ndn_sync::{SvsConfig, SyncHandle, SyncUpdate, join_svs_group};

const PROTOCOL: ProtocolId = ProtocolId("svs-service-discovery");

/// Capacity of the incoming-packet bridge channel.
const CHANNEL_CAP: usize = 256;

/// How often a pending `SyncUpdate` (fetch request) is retried if no Data
/// has been seen.  In practice the SVS task emits each update only once.
const FETCH_LIFETIME: Duration = Duration::from_secs(4);

struct Inner {
    /// Channel to feed raw incoming SVS packets into the background task.
    incoming_tx: mpsc::Sender<Bytes>,
    /// Channel that the background task uses to request outgoing SVS packets.
    outgoing_rx: mpsc::Receiver<Bytes>,
    /// Updates from the SVS task (new data to fetch from peers).
    sync_handle: SyncHandle,
    /// Timestamp of last housekeeping sweep.
    last_tick: Option<Instant>,
}

/// SVS-backed push service-record discovery.
///
/// Add alongside [`ServiceDiscoveryProtocol`] in a [`CompositeDiscovery`] to
/// receive push notifications whenever a peer publishes or updates a service
/// record.
///
/// [`ServiceDiscoveryProtocol`]: crate::service_discovery::ServiceDiscoveryProtocol
/// [`CompositeDiscovery`]: crate::CompositeDiscovery
pub struct SvsServiceDiscovery {
    /// Static claimed prefixes — set at construction, never mutated.
    claimed: Vec<Name>,
    inner: Mutex<Inner>,
}

impl SvsServiceDiscovery {
    /// Create a new `SvsServiceDiscovery` for `node_name`.
    ///
    /// Immediately spawns the SVS background task (requires a Tokio runtime).
    pub fn new(node_name: Name) -> Self {
        let group = sd_updates().clone();

        // Channels: we feed raw incoming bytes to SVS, SVS sends raw outgoing bytes back.
        let (incoming_tx, incoming_rx) = mpsc::channel::<Bytes>(CHANNEL_CAP);
        let (outgoing_tx, outgoing_rx) = mpsc::channel::<Bytes>(CHANNEL_CAP);

        // Wrap the outgoing_tx so the SVS task can use it as its `send` channel.
        // SVS `join_svs_group` takes `send: mpsc::Sender<Bytes>` for outgoing packets
        // and `recv: mpsc::Receiver<Bytes>` for incoming packets.
        let sync_handle = join_svs_group(
            group,
            node_name,
            outgoing_tx,
            incoming_rx,
            SvsConfig::default(),
        );

        Self {
            claimed: vec![sd_updates().clone()],
            inner: Mutex::new(Inner {
                incoming_tx,
                outgoing_rx,
                sync_handle,
                last_tick: None,
            }),
        }
    }

    /// Send pending outgoing SVS packets to all reachable neighbors.
    fn drain_outgoing(inner: &mut Inner, ctx: &dyn DiscoveryContext) {
        // Drain all pending outgoing packets (Sync Interests).
        let reachable_faces: Vec<FaceId> = ctx
            .neighbors()
            .all()
            .into_iter()
            .filter(|e| e.is_reachable())
            .flat_map(|e| e.faces.iter().map(|(fid, _, _)| *fid).collect::<Vec<_>>())
            .collect();

        loop {
            match inner.outgoing_rx.try_recv() {
                Ok(pkt) => {
                    trace!(len=%pkt.len(), "svs-sd: sending SVS Sync Interest to {} faces", reachable_faces.len());
                    for &face_id in &reachable_faces {
                        ctx.send_on(face_id, pkt.clone());
                    }
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    warn!("svs-sd: outgoing channel disconnected");
                    break;
                }
            }
        }
    }

    /// Drain sync updates and express fetch Interests for missing service records.
    fn drain_updates(inner: &mut Inner, ctx: &dyn DiscoveryContext) {
        loop {
            match inner.sync_handle.rx.try_recv() {
                Ok(update) => Self::handle_update(&update, ctx),
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    warn!("svs-sd: update channel disconnected");
                    break;
                }
            }
        }
    }

    /// Express fetch Interests for all records in a `SyncUpdate` gap.
    fn handle_update(update: &SyncUpdate, ctx: &dyn DiscoveryContext) {
        debug!(
            publisher=%update.publisher,
            low=%update.low_seq,
            high=%update.high_seq,
            "svs-sd: new service record update from peer"
        );
        // Express an Interest for each missing sequence number.
        // The records live under the SD services prefix, keyed by
        // `<publisher-name>/<seq>`.  The publisher's node name is embedded
        // in `update.name` as the last component of the group prefix.
        for seq in update.low_seq..=update.high_seq {
            let fetch_name = update.name.clone().append(seq.to_string());
            let interest = InterestBuilder::new(fetch_name)
                .must_be_fresh()
                .lifetime(FETCH_LIFETIME)
                .build();
            // Send on all reachable faces — the PIT will aggregate duplicates.
            let faces: Vec<FaceId> = ctx
                .neighbors()
                .all()
                .into_iter()
                .filter(|e| e.is_reachable())
                .flat_map(|e| e.faces.iter().map(|(fid, _, _)| *fid).collect::<Vec<_>>())
                .collect();
            for face_id in faces {
                ctx.send_on(face_id, interest.clone());
            }
        }
    }
}

impl DiscoveryProtocol for SvsServiceDiscovery {
    fn protocol_id(&self) -> ProtocolId {
        PROTOCOL
    }

    fn claimed_prefixes(&self) -> &[Name] {
        &self.claimed
    }

    fn on_face_up(&self, _face_id: FaceId, _ctx: &dyn DiscoveryContext) {}

    fn on_face_down(&self, _face_id: FaceId, _ctx: &dyn DiscoveryContext) {}

    fn on_inbound(
        &self,
        raw: &Bytes,
        _incoming_face: FaceId,
        _meta: &InboundMeta,
        _ctx: &dyn DiscoveryContext,
    ) -> bool {
        if raw.is_empty() {
            return false;
        }
        // Only forward SVS Sync Interests (under sd_updates/).
        let is_svs = parse_raw_interest(raw)
            .map(|i| i.name.has_prefix(sd_updates()))
            .unwrap_or(false);

        if !is_svs {
            return false;
        }

        // Non-blocking send; if the channel is full, drop the packet.
        let inner = self.inner.lock().unwrap();
        match inner.incoming_tx.try_send(raw.clone()) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(_)) => {
                warn!("svs-sd: incoming channel full, dropping SVS packet");
                true // still consumed — don't forward to pipeline
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                warn!("svs-sd: incoming channel closed");
                false
            }
        }
    }

    fn on_tick(&self, now: Instant, ctx: &dyn DiscoveryContext) {
        let mut inner = self.inner.lock().unwrap();
        inner.last_tick = Some(now);
        // Drain outgoing SVS packets (send Sync Interests to all neighbors).
        Self::drain_outgoing(&mut inner, ctx);
        // Drain sync updates (express fetch Interests for new service records).
        Self::drain_updates(&mut inner, ctx);
    }

    fn tick_interval(&self) -> Duration {
        // Tick frequently enough to keep SVS Sync Interests flowing.
        Duration::from_millis(200)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[tokio::test]
    async fn svs_sd_creates_without_panic() {
        let node = Name::from_str("/ndn/local/test-node").unwrap();
        let _sd = SvsServiceDiscovery::new(node);
        // Minimal smoke test: ensure construction and drop are clean.
    }
}
