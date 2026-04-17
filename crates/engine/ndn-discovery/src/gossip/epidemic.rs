//! `EpidemicGossip` — pull-gossip for neighbor state dissemination.
//!
//! ## Wire format
//!
//! ```text
//! GossipRecord ::= (Name TLV)*   -- one per established/stale neighbor
//! ```
//!
//! Gossip records carry only name hints; the receiver creates `Probing`
//! entries and the hello state machine confirms reachability.

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

const GOSSIP_SUBSCRIBE_INTERVAL: Duration = Duration::from_secs(5);

struct State {
    node_name: Name,
    local_seq: u64,
    local_gossip_data: Option<Bytes>,
    local_gossip_name: Option<Name>,
    last_subscribe: Option<Instant>,
    last_publish: Option<Instant>,
}

pub struct EpidemicGossip {
    config: DiscoveryConfig,
    claimed: Vec<Name>,
    state: Mutex<State>,
}

impl EpidemicGossip {
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


    fn build_subscribe_interest(peer_name: &Name) -> Bytes {
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

    fn handle_gossip_interest(&self, incoming_face: FaceId, ctx: &dyn DiscoveryContext) {
        let wire = {
            let st = self.state.lock().unwrap();
            st.local_gossip_data.clone()
        };
        let wire = wire.unwrap_or_else(|| self.publish_local_snapshot(ctx));
        ctx.send_on(incoming_face, wire);
    }

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
            if name == local_name {
                continue;
            }
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

        if should_publish {
            self.publish_local_snapshot(ctx);
        }

        if !should_subscribe {
            return;
        }
        self.state.lock().unwrap().last_subscribe = Some(now);

        let fanout = self.config.gossip_fanout as usize;
        let peers: Vec<_> = ctx
            .neighbors()
            .all()
            .into_iter()
            .filter(|e| e.is_reachable())
            .collect();

        let selected: Vec<_> = if fanout > 0 && fanout < peers.len() {
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
