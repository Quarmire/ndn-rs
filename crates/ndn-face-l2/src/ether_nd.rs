//! `EtherNeighborDiscovery` — NDN neighbor discovery over raw Ethernet.
//!
//! Implements [`DiscoveryProtocol`] using periodic hello Interest broadcasts on
//! a [`MulticastEtherFace`] and unicast [`NamedEtherFace`] creation per peer.
//!
//! # Protocol (doc format)
//!
//! **Hello Interest** (broadcast on multicast face):
//! ```text
//! Name: /ndn/local/nd/hello/<nonce-u32>
//! (no AppParams)
//! ```
//!
//! **Hello Data** (reply sent back on multicast face):
//! ```text
//! Name:    /ndn/local/nd/hello/<nonce-u32>
//! Content: HelloPayload TLV
//!   NODE-NAME     = /ndn/site/mynode
//!   SERVED-PREFIX = ...        (optional, InHello mode)
//!   CAPABILITIES  = [flags]    (optional)
//!   NEIGHBOR-DIFF = [...]      (SWIM gossip piggyback, optional)
//! ```
//!
//! The sender's MAC is extracted from `meta.source` (populated by the engine
//! via `MulticastEtherFace::recv_with_source`), not from the packet payload.
//!
//! On receiving a Hello Interest a node:
//! 1. Reads the sender MAC from `meta.source` (`LinkAddr::Ether`).
//! 2. Triggers `PassiveDetection` on the strategy when the MAC is new.
//! 3. Replies with a Hello Data carrying its own `HelloPayload`.
//!
//! On receiving a Hello Data the sender:
//! 1. Decodes `HelloPayload` from Content.
//! 2. Reads responder MAC from `meta.source`.
//! 3. Creates a [`NamedEtherFace`] to the responder if needed.
//! 4. Updates the neighbor to `Established` and records RTT.
//! 5. Installs FIB routes for `served_prefixes` (if `InHello` mode).
//! 6. Applies any piggybacked `NEIGHBOR-DIFF` entries.

use std::time::Duration;

use bytes::Bytes;
use ndn_discovery::link_medium::{HELLO_PREFIX_DEPTH, HelloCore, HelloState, LinkMedium};
use ndn_discovery::wire::{parse_raw_data, parse_raw_interest, write_name_tlv, write_nni};
use ndn_discovery::{
    DiscoveryConfig, DiscoveryContext, DiscoveryProfile, HelloPayload, HelloProtocol, InboundMeta,
    LinkAddr, NeighborEntry, NeighborUpdate, ProtocolId,
};
use ndn_packet::{Name, tlv_type};
use ndn_tlv::TlvWriter;
use ndn_transport::FaceId;
use tracing::{debug, warn};

use crate::af_packet::MacAddr;
use crate::ether::NamedEtherFace;
use crate::radio::RadioFaceMetadata;

const PROTOCOL: ProtocolId = ProtocolId("ether-nd");

/// Ethernet-specific link medium for [`HelloProtocol`].
///
/// Handles unsigned hello Data, MAC address extraction from inbound
/// metadata, passive detection of new MACs, and unicast face creation
/// via [`NamedEtherFace`].
pub struct EtherMedium {
    /// Multicast face used for hello broadcasts.
    multicast_face_id: FaceId,
    /// Network interface name (e.g. "wlan0").
    iface: String,
    /// Our Ethernet MAC address (needed when creating unicast faces).
    local_mac: MacAddr,
}

/// Ethernet neighbor discovery — type alias for `HelloProtocol<EtherMedium>`.
pub type EtherNeighborDiscovery = HelloProtocol<EtherMedium>;

impl EtherNeighborDiscovery {
    /// Create a new instance with the default LAN profile.
    pub fn new(
        multicast_face_id: FaceId,
        iface: impl Into<String>,
        node_name: Name,
        local_mac: MacAddr,
    ) -> Self {
        Self::new_with_config(
            multicast_face_id,
            iface,
            node_name,
            local_mac,
            DiscoveryConfig::for_profile(&DiscoveryProfile::Lan),
        )
    }

    /// Create with an explicit [`DiscoveryConfig`].
    pub fn new_with_config(
        multicast_face_id: FaceId,
        iface: impl Into<String>,
        node_name: Name,
        local_mac: MacAddr,
        config: DiscoveryConfig,
    ) -> Self {
        let medium = EtherMedium {
            multicast_face_id,
            iface: iface.into(),
            local_mac,
        };
        HelloProtocol::create(medium, node_name, config)
    }

    /// Create with a named deployment profile.
    pub fn from_profile(
        multicast_face_id: FaceId,
        iface: impl Into<String>,
        node_name: Name,
        local_mac: MacAddr,
        profile: &DiscoveryProfile,
    ) -> Self {
        Self::new_with_config(
            multicast_face_id,
            iface,
            node_name,
            local_mac,
            DiscoveryConfig::for_profile(profile),
        )
    }
}

impl EtherMedium {
    fn ensure_peer(
        &self,
        ctx: &dyn DiscoveryContext,
        peer_name: &Name,
        peer_mac: MacAddr,
    ) -> Option<FaceId> {
        let existing = ctx.neighbors().face_for_peer(&peer_mac, &self.iface);

        let face_id = if let Some(fid) = existing {
            fid
        } else {
            let fid = ctx.alloc_face_id();
            match NamedEtherFace::new(
                fid,
                peer_name.clone(),
                peer_mac,
                self.iface.clone(),
                RadioFaceMetadata::default(),
            ) {
                Ok(face) => {
                    let registered = ctx.add_face(std::sync::Arc::new(face));
                    debug!("EtherND: created unicast face {registered:?} -> {peer_name}");
                    registered
                }
                Err(e) => {
                    warn!("EtherND: failed to create unicast face to {peer_name}: {e}");
                    return None;
                }
            }
        };

        if ctx.neighbors().get(peer_name).is_none() {
            ctx.update_neighbor(NeighborUpdate::Upsert(NeighborEntry::new(
                peer_name.clone(),
            )));
        }

        ctx.update_neighbor(NeighborUpdate::AddFace {
            name: peer_name.clone(),
            face_id,
            mac: peer_mac,
            iface: self.iface.clone(),
        });

        ctx.add_fib_entry(peer_name, face_id, 0, PROTOCOL);
        Some(face_id)
    }
}

impl LinkMedium for EtherMedium {
    fn protocol_id(&self) -> ProtocolId {
        PROTOCOL
    }

    fn build_hello_data(&self, core: &HelloCore, interest_name: &Name) -> Bytes {
        let mut payload = ndn_discovery::HelloPayload::new(core.node_name.clone());

        if core.config.prefix_announcement == ndn_discovery::PrefixAnnouncementMode::InHello {
            let sp = core.served_prefixes.lock().unwrap();
            payload.served_prefixes = sp.clone();
        }

        {
            let st = core.state.lock().unwrap();
            if !st.recent_diffs.is_empty() {
                payload.neighbor_diffs.push(ndn_discovery::NeighborDiff {
                    entries: st.recent_diffs.iter().cloned().collect(),
                });
            }
        }

        let content = payload.encode();
        let freshness_ms = core
            .config
            .hello_interval_base
            .as_millis()
            .min(u32::MAX as u128) as u64
            * 2;

        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::DATA, |w: &mut TlvWriter| {
            write_name_tlv(w, interest_name);
            w.write_nested(tlv_type::META_INFO, |w: &mut TlvWriter| {
                write_nni(w, tlv_type::FRESHNESS_PERIOD, freshness_ms);
            });
            w.write_tlv(tlv_type::CONTENT, &content);
            w.write_nested(tlv_type::SIGNATURE_INFO, |w: &mut TlvWriter| {
                w.write_tlv(tlv_type::SIGNATURE_TYPE, &[0u8]);
            });
            w.write_tlv(tlv_type::SIGNATURE_VALUE, &[0u8; 32]);
        });
        w.finish()
    }

    fn handle_hello_interest(
        &self,
        raw: &Bytes,
        _incoming_face: FaceId,
        meta: &InboundMeta,
        core: &HelloCore,
        ctx: &dyn DiscoveryContext,
    ) -> bool {
        let parsed = match parse_raw_interest(raw) {
            Some(p) => p,
            None => return false,
        };

        let name = &parsed.name;
        if !name.has_prefix(&core.hello_prefix) {
            return false;
        }
        if name.components().len() != HELLO_PREFIX_DEPTH + 1 {
            return false;
        }

        // Extract sender MAC from link-layer metadata.
        let sender_mac = match &meta.source {
            Some(LinkAddr::Ether(mac)) => *mac,
            _ => {
                debug!("EtherND: hello Interest has no source MAC in meta — ignoring");
                return true;
            }
        };

        // Trigger PassiveDetection when a previously-unknown MAC sends a hello.
        let is_new = ctx
            .neighbors()
            .face_for_peer(&sender_mac, &self.iface)
            .is_none();
        if is_new {
            core.strategy
                .lock()
                .unwrap()
                .trigger(ndn_discovery::TriggerEvent::PassiveDetection);
        }

        let reply = self.build_hello_data(core, name);
        ctx.send_on(self.multicast_face_id, reply);

        debug!(
            "EtherND: received hello Interest from {:?}, sent Data reply",
            sender_mac
        );
        true
    }

    fn verify_and_ensure_peer(
        &self,
        _raw: &Bytes,
        payload: &HelloPayload,
        meta: &InboundMeta,
        _core: &HelloCore,
        ctx: &dyn DiscoveryContext,
    ) -> Option<(Name, Option<FaceId>)> {
        let responder_name = payload.node_name.clone();

        let responder_mac = match &meta.source {
            Some(LinkAddr::Ether(mac)) => *mac,
            _ => {
                debug!("EtherND: hello Data has no source MAC in meta — ignoring");
                return None;
            }
        };

        let peer_face_id = self.ensure_peer(ctx, &responder_name, responder_mac);
        Some((responder_name, peer_face_id))
    }

    fn send_multicast(&self, ctx: &dyn DiscoveryContext, pkt: Bytes) {
        ctx.send_on(self.multicast_face_id, pkt);
    }

    fn is_multicast_face(&self, face_id: FaceId) -> bool {
        face_id == self.multicast_face_id
    }

    fn on_face_down(&self, _face_id: FaceId, _state: &mut HelloState, _ctx: &dyn DiscoveryContext) {
        // Ethernet has no link-specific state to clean up on face down.
    }

    fn on_peer_removed(&self, _entry: &NeighborEntry, _state: &mut HelloState) {
        // Ethernet has no link-specific state to clean up on peer removal.
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_discovery::wire::parse_raw_data;
    use std::str::FromStr;

    fn make_nd() -> EtherNeighborDiscovery {
        EtherNeighborDiscovery::new(
            FaceId(1),
            "eth0",
            Name::from_str("/ndn/test/node").unwrap(),
            MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
        )
    }

    #[test]
    fn hello_interest_format() {
        let nd = make_nd();
        let nonce: u32 = 0xDEAD_BEEF;
        let pkt = nd.build_hello_interest(nonce);

        let parsed = parse_raw_interest(&pkt).unwrap();
        let comps = parsed.name.components();

        assert_eq!(
            comps.len(),
            HELLO_PREFIX_DEPTH + 1,
            "unexpected component count: {}",
            comps.len()
        );

        let last = &comps[HELLO_PREFIX_DEPTH];
        let decoded_nonce = u32::from_be_bytes(last.value[..4].try_into().unwrap());
        assert_eq!(decoded_nonce, nonce);

        assert!(
            parsed.app_params.is_none(),
            "Interest must have no AppParams"
        );
    }

    #[test]
    fn hello_data_carries_hello_payload() {
        let nd = make_nd();
        let interest_name = Name::from_str("/ndn/local/nd/hello/DEADBEEF").unwrap();
        let pkt = nd.medium.build_hello_data(&nd.core, &interest_name);

        let parsed = parse_raw_data(&pkt).unwrap();
        assert_eq!(parsed.name, interest_name);

        let content = parsed.content.unwrap();
        let payload = HelloPayload::decode(&content).unwrap();
        assert_eq!(payload.node_name, nd.core.node_name);
    }

    #[test]
    fn in_hello_served_prefixes_encoded() {
        let nd = make_nd();
        nd.set_served_prefixes(vec![
            Name::from_str("/ndn/edu/test").unwrap(),
            Name::from_str("/ndn/edu/test2").unwrap(),
        ]);

        let interest_name = Name::from_str("/ndn/local/nd/hello/DEADBEEF").unwrap();
        let pkt = nd.medium.build_hello_data(&nd.core, &interest_name);

        let parsed = parse_raw_data(&pkt).unwrap();
        let payload = HelloPayload::decode(&parsed.content.unwrap()).unwrap();
        assert_eq!(payload.served_prefixes.len(), 2);
        assert_eq!(
            payload.served_prefixes[0],
            Name::from_str("/ndn/edu/test").unwrap()
        );
    }

    #[test]
    fn neighbor_diffs_piggybacked() {
        let nd = make_nd();
        {
            let mut st = nd.core.state.lock().unwrap();
            st.recent_diffs.push_back(ndn_discovery::DiffEntry::Add(
                Name::from_str("/ndn/peer/alpha").unwrap(),
            ));
        }
        let interest_name = Name::from_str("/ndn/local/nd/hello/1").unwrap();
        let pkt = nd.medium.build_hello_data(&nd.core, &interest_name);
        let parsed = parse_raw_data(&pkt).unwrap();
        let payload = HelloPayload::decode(&parsed.content.unwrap()).unwrap();
        assert_eq!(payload.neighbor_diffs.len(), 1);
        assert_eq!(payload.neighbor_diffs[0].entries.len(), 1);
    }

    #[test]
    fn protocol_id_and_prefix() {
        let nd = make_nd();
        assert_eq!(nd.medium.protocol_id(), PROTOCOL);
        assert_eq!(nd.core.claimed.len(), 1);
        assert_eq!(
            nd.core.claimed[0],
            Name::from_str(ndn_discovery::link_medium::HELLO_PREFIX_STR).unwrap()
        );
    }

    #[test]
    fn from_profile_sets_config() {
        let nd = EtherNeighborDiscovery::from_profile(
            FaceId(1),
            "wlan0",
            Name::from_str("/ndn/test/node").unwrap(),
            MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            &DiscoveryProfile::HighMobility,
        );
        assert!(nd.core.config.hello_interval_base < Duration::from_millis(100));
    }
}
