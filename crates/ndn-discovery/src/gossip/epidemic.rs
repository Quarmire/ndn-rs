//! `EpidemicGossip` — pull-gossip for neighbor state dissemination.
//!
//! Each node publishes a neighbor state snapshot under
//! `/ndn/local/nd/gossip/<node-name>/<seq>` and subscribes to its peers'
//! snapshots by expressing prefix Interests (`CanBePrefix=true`) for
//! `/ndn/local/nd/gossip/`.
//!
//! ## Wire format — gossip record payload
//!
//! The Data Content is a sequence of concatenated Name TLVs, one per
//! established-or-stale neighbor:
//!
//! ```text
//! GossipRecord ::= (Name TLV)*
//! ```
//!
//! This is intentionally minimal — gossip records carry name hints for
//! nodes that should be probed; the receiver creates `Probing` state entries
//! and the normal hello state machine confirms them.  No RTT or face-ID
//! metadata is included (link-local face IDs have no meaning to remote peers).
//!
//! ## Operation
//!
//! * `on_tick`: every `gossip_interval` ticks, express a fresh prefix Interest
//!   for each established peer's gossip prefix and publish a local snapshot
//!   when the local sequence number has advanced.
//! * `on_inbound` for Interest: respond with the latest local gossip Data.
//! * `on_inbound` for Data: decode the neighbor name list and add any
//!   unknown names as `Probing` entries to the neighbor table.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use bytes::Bytes;
use ndn_packet::Name;
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_tlv::{TlvReader, TlvWriter};
use ndn_transport::FaceId;
use tracing::{debug, trace};

use crate::config::DiscoveryConfig;
use crate::context::DiscoveryContext;
use crate::neighbor::{NeighborEntry, NeighborState, NeighborUpdate};
use crate::protocol::{DiscoveryProtocol, InboundMeta, ProtocolId};
use crate::scope::gossip_prefix;
use crate::wire::{parse_raw_data, parse_raw_interest, write_name_tlv};

const PROTOCOL: ProtocolId = ProtocolId("epidemic-gossip");

/// Gossip subscription interval: how often we express prefix Interests for
/// each peer's gossip prefix to pull fresh snapshots.
const GOSSIP_SUBSCRIBE_INTERVAL: Duration = Duration::from_secs(5);

/// Internal state protected by a mutex.
struct State {
    /// This node's own NDN name.
    node_name: Name,
    /// Monotonically increasing sequence number for local gossip records.
    local_seq: u64,
    /// Cached wire bytes for the most recent local gossip Data.
    local_gossip_data: Option<Bytes>,
    /// The name of the last-published gossip Data (used as Interest name prefix
    /// when peers subscribe to this node's gossip).
    local_gossip_name: Option<Name>,
    /// Timestamp of last gossip subscription sweep.
    last_subscribe: Option<Instant>,
    /// Timestamp of last local snapshot publication.
    last_publish: Option<Instant>,
}

/// Pull-gossip protocol for neighbor state dissemination.
///
/// Publishes and subscribes to neighbor snapshots at
/// `/ndn/local/nd/gossip/<node-name>/<seq>`.  Remote node names discovered
/// via gossip are inserted into the neighbor table as `Probing` entries so the
/// normal hello state machine takes over.
pub struct EpidemicGossip {
    config: DiscoveryConfig,
    /// The claimed prefix as an owned `Vec` for `claimed_prefixes()`.
    claimed: Vec<Name>,
    state: Mutex<State>,
}

impl EpidemicGossip {
    /// Create a new `EpidemicGossip` for `node_name`.
    pub fn new(node_name: Name, config: DiscoveryConfig) -> Self {
        let claimed = vec![gossip_prefix().clone()];
        let state = State {
            node_name,
            local_seq: 0,
            local_gossip_data: None,
            local_gossip_name: None,
            last_subscribe: None,
            last_publish: None,
        };
        Self {
            config,
            claimed,
            state: Mutex::new(state),
        }
    }

    // ─── helpers ──────────────────────────────────────────────────────────────

    /// Build a gossip Interest for a specific peer: subscribes to all of that
    /// peer's gossip publications under `/ndn/local/nd/gossip/<peer-name>/`.
    fn build_subscribe_interest(peer_name: &Name) -> Bytes {
        // Append all components of peer_name onto gossip_prefix().
        let mut interest_name = gossip_prefix().clone();
        for comp in peer_name.components() {
            interest_name = interest_name.append_component(comp.clone());
        }
        InterestBuilder::new(interest_name)
            .can_be_prefix()
            .must_be_fresh()
            .lifetime(Duration::from_secs(10))
            .build()
    }

    /// Encode the local neighbor snapshot as a gossip record payload.
    ///
    /// Returns the encoded TLV bytes (sequence of Name TLVs) and the list
    /// of neighbor names included.
    fn encode_snapshot(ctx: &dyn DiscoveryContext) -> Vec<u8> {
        let mut w = TlvWriter::new();
        for entry in ctx.neighbors().all() {
            match &entry.state {
                NeighborState::Established { .. } | NeighborState::Stale { .. } => {
                    write_name_tlv(&mut w, &entry.node_name);
                }
                _ => {}
            }
        }
        w.finish().to_vec()
    }

    /// Decode a gossip record payload into a list of neighbor names.
    fn decode_snapshot(content: &Bytes) -> Vec<Name> {
        let mut names = Vec::new();
        let mut r = TlvReader::new(content.clone());
        while !r.is_empty() {
            if let Ok((typ, val)) = r.read_tlv() {
                if typ == ndn_packet::tlv_type::NAME
                    && let Ok(name) = Name::decode(val)
                {
                    names.push(name);
                }
            } else {
                break;
            }
        }
        names
    }

    /// Publish a fresh local gossip Data packet.  Returns the wire bytes.
    fn publish_local_snapshot(&self, ctx: &dyn DiscoveryContext) -> Bytes {
        let mut st = self.state.lock().unwrap();
        st.local_seq += 1;
        let seq = st.local_seq;
        let node_name = st.node_name.clone();
        drop(st);

        let payload = Self::encode_snapshot(ctx);
        // Build data name: gossip_prefix / node_name components / seq
        let mut data_name = gossip_prefix().clone();
        for comp in node_name.components() {
            data_name = data_name.append_component(comp.clone());
        }
        let data_name = data_name.append(seq.to_string());

        let wire = DataBuilder::new(data_name.clone(), &payload)
            .freshness(GOSSIP_SUBSCRIBE_INTERVAL * 2)
            .build();

        let mut st = self.state.lock().unwrap();
        st.local_gossip_data = Some(wire.clone());
        st.local_gossip_name = Some(data_name);
        st.last_publish = Some(Instant::now());
        wire
    }

    /// Handle an incoming gossip Interest and respond with local snapshot.
    fn handle_gossip_interest(&self, incoming_face: FaceId, ctx: &dyn DiscoveryContext) {
        let wire = {
            let st = self.state.lock().unwrap();
            st.local_gossip_data.clone()
        };
        // Publish fresh snapshot if we don't have one yet.
        let wire = wire.unwrap_or_else(|| self.publish_local_snapshot(ctx));
        ctx.send_on(incoming_face, wire);
    }

    /// Handle an incoming gossip Data: merge remote neighbor names into table.
    fn handle_gossip_data(&self, raw: &Bytes, ctx: &dyn DiscoveryContext) {
        let parsed = match parse_raw_data(raw) {
            Some(d) => d,
            None => return,
        };
        let content = match parsed.content {
            Some(c) => c,
            None => return,
        };
        let names = Self::decode_snapshot(&content);
        debug!(
            source_name=%parsed.name,
            count=%names.len(),
            "epidemic-gossip: received gossip record"
        );
        let local_name = self.state.lock().unwrap().node_name.clone();
        for name in names {
            // Skip self.
            if name == local_name {
                continue;
            }
            // Only insert if not already known.
            if ctx.neighbors().get(&name).is_none() {
                trace!(peer=%name, "epidemic-gossip: inserting Probing entry from gossip");
                ctx.update_neighbor(NeighborUpdate::Upsert(NeighborEntry {
                    node_name: name,
                    state: NeighborState::Probing {
                        attempts: 0,
                        last_probe: Instant::now(),
                    },
                    faces: Vec::new(),
                    rtt_us: None,
                    pending_nonce: None,
                }));
            }
        }
    }
}

impl DiscoveryProtocol for EpidemicGossip {
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
        incoming_face: FaceId,
        _meta: &InboundMeta,
        ctx: &dyn DiscoveryContext,
    ) -> bool {
        // Quick peek to classify Interest vs Data without full decode.
        if raw.is_empty() {
            return false;
        }
        let first = raw[0];

        // Interest TLV type 0x05.
        if first == ndn_packet::tlv_type::INTEREST as u8
            && let Some(interest) = parse_raw_interest(raw)
            && interest.name.has_prefix(gossip_prefix())
        {
            self.handle_gossip_interest(incoming_face, ctx);
            return true;
        }

        // Data TLV type 0x06.
        if first == ndn_packet::tlv_type::DATA as u8
            && let Some(parsed) = parse_raw_data(raw)
            && parsed.name.has_prefix(gossip_prefix())
        {
            self.handle_gossip_data(raw, ctx);
            return true;
        }

        false
    }

    fn on_tick(&self, now: Instant, ctx: &dyn DiscoveryContext) {
        let (should_subscribe, should_publish) = {
            let st = self.state.lock().unwrap();
            let subscribe = st
                .last_subscribe
                .map(|t| now.duration_since(t) >= GOSSIP_SUBSCRIBE_INTERVAL)
                .unwrap_or(true);
            let publish = st
                .last_publish
                .map(|t| now.duration_since(t) >= GOSSIP_SUBSCRIBE_INTERVAL)
                .unwrap_or(true);
            (subscribe, publish)
        };

        // Publish a fresh local snapshot if due.
        if should_publish {
            self.publish_local_snapshot(ctx);
        }

        if !should_subscribe {
            return;
        }
        self.state.lock().unwrap().last_subscribe = Some(now);

        // Express gossip subscription Interests to established/stale peers.
        // Limit to `gossip_fanout` peers when set, otherwise subscribe to all.
        let fanout = self.config.gossip_fanout as usize;
        let peers: Vec<_> = ctx
            .neighbors()
            .all()
            .into_iter()
            .filter(|e| e.is_reachable())
            .collect();

        let selected: Vec<_> = if fanout > 0 && fanout < peers.len() {
            // Pseudo-random selection: pick every Nth entry using tick count.
            let step = peers.len() / fanout;
            peers.iter().step_by(step.max(1)).take(fanout).collect()
        } else {
            peers.iter().collect()
        };

        for entry in selected {
            let face_ids: Vec<FaceId> = entry.faces.iter().map(|(fid, _, _)| *fid).collect();
            let interest = Self::build_subscribe_interest(&entry.node_name);
            for face_id in face_ids {
                trace!(peer=%entry.node_name, face=%face_id, "epidemic-gossip: sending gossip subscription Interest");
                ctx.send_on(face_id, interest.clone());
            }
        }
    }

    fn tick_interval(&self) -> Duration {
        self.config.tick_interval
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn snapshot_roundtrip_empty() {
        let encoded: Vec<u8> = {
            let w = TlvWriter::new();
            w.finish().to_vec()
        };
        let decoded = EpidemicGossip::decode_snapshot(&Bytes::from(encoded));
        assert!(decoded.is_empty());
    }

    #[test]
    fn snapshot_roundtrip_with_names() {
        let names = vec![
            Name::from_str("/ndn/site/alice").unwrap(),
            Name::from_str("/ndn/site/bob").unwrap(),
        ];
        // Encode.
        let mut w = TlvWriter::new();
        for n in &names {
            write_name_tlv(&mut w, n);
        }
        let encoded = Bytes::from(w.finish().to_vec());
        // Decode.
        let decoded = EpidemicGossip::decode_snapshot(&encoded);
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0], names[0]);
        assert_eq!(decoded[1], names[1]);
    }
}
