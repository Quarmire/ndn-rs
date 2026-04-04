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
//!   SERVED-PREFIX = ...        (optional)
//!   CAPABILITIES  = [flags]    (optional)
//!   NEIGHBOR-DIFF = [...]      (SWIM piggyback, optional)
//! ```
//!
//! The sender's MAC is extracted from `meta.source` (populated by the engine
//! via `MulticastEtherFace::recv_with_source`), not from the packet payload.
//!
//! On receiving a Hello Interest a node:
//! 1. Reads the sender MAC from `meta.source` (`LinkAddr::Ether`).
//! 2. Creates a [`NamedEtherFace`] to the sender if one does not yet exist.
//! 3. Installs a FIB route for the sender's name (if already known from a
//!    prior hello Data).
//! 4. Replies with a Hello Data carrying its own `HelloPayload`.
//!
//! On receiving a Hello Data the sender:
//! 1. Decodes `HelloPayload` from Content.
//! 2. Reads responder MAC from `meta.source`.
//! 3. Creates a [`NamedEtherFace`] to the responder if needed.
//! 4. Updates the neighbor to `Reachable` and records RTT.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use bytes::Bytes;
use ndn_discovery::{
    BackoffConfig, BackoffState, DiscoveryContext, DiscoveryProtocol, HelloPayload, InboundMeta,
    LinkAddr, NeighborEntry, NeighborState, NeighborUpdate, ProtocolId,
};
use ndn_discovery::wire::{parse_raw_data, parse_raw_interest, unwrap_lp, write_name_tlv, write_nni};
use ndn_packet::{Name, tlv_type};
use ndn_tlv::TlvWriter;
use ndn_transport::FaceId;
use tracing::{debug, warn};

use crate::af_packet::MacAddr;
use crate::radio::RadioFaceMetadata;
use crate::ether::NamedEtherFace;

/// Hello prefix used by EtherND.
const HELLO_PREFIX_STR: &str = "/ndn/local/nd/hello";
/// Number of name components in the hello prefix.
const HELLO_PREFIX_DEPTH: usize = 4; // /ndn/local/nd/hello
/// Protocol identifier.
const PROTOCOL: ProtocolId = ProtocolId("ether-nd");

/// Mutable state, protected by a `Mutex` for interior mutability.
struct EtherNdState {
    /// When to next broadcast a hello.
    next_hello_at: Instant,
    /// Exponential backoff state for broadcast hello scheduling.
    hello_backoff: BackoffState,
    /// Static config for the hello backoff (passed to `next_failure`).
    hello_cfg: BackoffConfig,
    /// Outstanding hellos: nonce → send_time.
    pending_probes: HashMap<u32, Instant>,
}

/// NDN neighbor discovery protocol over raw Ethernet.
///
/// Attach one instance per interface + multicast face.  Multiple instances
/// (one per interface) can coexist inside a [`CompositeDiscovery`].
///
/// [`CompositeDiscovery`]: ndn_discovery::CompositeDiscovery
pub struct EtherNeighborDiscovery {
    /// Multicast face used for hello broadcasts.
    multicast_face_id: FaceId,
    /// Network interface name (e.g. "wlan0").
    iface: String,
    /// This node's NDN name.
    node_name: Name,
    /// Our Ethernet MAC address (needed when creating unicast faces).
    local_mac: MacAddr,
    /// Parsed `/ndn/local/nd/hello` prefix.
    hello_prefix: Name,
    /// Claimed prefixes (single element: `hello_prefix`).
    claimed: Vec<Name>,
    /// Monotonically increasing nonce counter.
    nonce_counter: AtomicU32,
    /// Protected mutable state.
    state: Mutex<EtherNdState>,
}

impl EtherNeighborDiscovery {
    /// Create a new `EtherNeighborDiscovery` instance.
    ///
    /// # Arguments
    /// - `multicast_face_id`: the `FaceId` of the [`MulticastEtherFace`] already
    ///   registered with the engine.
    /// - `iface`: network interface name (e.g. `"wlan0"`).
    /// - `node_name`: this node's NDN name.
    /// - `local_mac`: this node's Ethernet MAC address on `iface`.
    pub fn new(
        multicast_face_id: FaceId,
        iface: impl Into<String>,
        node_name: Name,
        local_mac: MacAddr,
    ) -> Self {
        let hello_prefix = Name::from_str(HELLO_PREFIX_STR).expect("static prefix is valid");
        let claimed = vec![hello_prefix.clone()];

        Self {
            multicast_face_id,
            iface: iface.into(),
            node_name,
            local_mac,
            hello_prefix,
            claimed,
            nonce_counter: AtomicU32::new(1),
            state: Mutex::new(EtherNdState {
                next_hello_at: Instant::now(),
                hello_backoff: BackoffState::new(0),
                hello_cfg: BackoffConfig::for_neighbor_hello(),
                pending_probes: HashMap::new(),
            }),
        }
    }

    // ─── Packet builders ──────────────────────────────────────────────────────

    /// Build a Hello Interest TLV.
    ///
    /// Name: `/ndn/local/nd/hello/<nonce-u32>` — no AppParams.
    fn build_hello_interest(&self, nonce: u32) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::INTEREST, |w: &mut TlvWriter| {
            w.write_nested(tlv_type::NAME, |w: &mut TlvWriter| {
                for comp in self.hello_prefix.components() {
                    w.write_tlv(comp.typ, &comp.value);
                }
                w.write_tlv(tlv_type::NAME_COMPONENT, &nonce.to_be_bytes());
            });
            w.write_tlv(tlv_type::NONCE, &nonce.to_be_bytes());
            write_nni(w, tlv_type::INTEREST_LIFETIME, 4000);
        });
        w.finish()
    }

    /// Build a Hello Data reply TLV.
    ///
    /// Name: same as the received Interest.
    /// Content: `HelloPayload` TLV encoding this node's name and capabilities.
    fn build_hello_data(&self, interest_name: &Name) -> Bytes {
        let payload = HelloPayload::new(self.node_name.clone());
        let content = payload.encode();

        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::DATA, |w: &mut TlvWriter| {
            write_name_tlv(w, interest_name);
            w.write_nested(tlv_type::META_INFO, |w: &mut TlvWriter| {
                write_nni(w, tlv_type::FRESHNESS_PERIOD, 0);
            });
            w.write_tlv(tlv_type::CONTENT, &content);
            w.write_nested(tlv_type::SIGNATURE_INFO, |w: &mut TlvWriter| {
                w.write_tlv(tlv_type::SIGNATURE_TYPE, &[0u8]);
            });
            w.write_tlv(tlv_type::SIGNATURE_VALUE, &[0u8; 32]);
        });
        w.finish()
    }

    // ─── Inbound handlers ─────────────────────────────────────────────────────

    fn handle_hello_interest(
        &self,
        raw: &Bytes,
        _incoming_face: FaceId,
        meta: &InboundMeta,
        ctx: &dyn DiscoveryContext,
    ) -> bool {
        let parsed = match parse_raw_interest(raw) {
            Some(p) => p,
            None => return false,
        };

        let name = &parsed.name;
        if !name.has_prefix(&self.hello_prefix) {
            return false;
        }

        // Validate: prefix (4) + nonce (1) = 5 components minimum.
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

        // Create unicast face for the sender (we'll learn their name from the
        // Data they send in reply; for now just ensure a face exists).
        // We don't know their NDN name yet, so we create a placeholder entry
        // only if they reply.

        let reply = self.build_hello_data(name);
        ctx.send_on(self.multicast_face_id, reply);

        debug!("EtherND: received hello Interest from {:?}, sent Data reply", sender_mac);
        true
    }

    fn handle_hello_data(
        &self,
        raw: &Bytes,
        _incoming_face: FaceId,
        meta: &InboundMeta,
        ctx: &dyn DiscoveryContext,
    ) -> bool {
        let parsed = match parse_raw_data(raw) {
            Some(d) => d,
            None => return false,
        };

        let name = &parsed.name;
        if !name.has_prefix(&self.hello_prefix) {
            return false;
        }

        if name.components().len() != HELLO_PREFIX_DEPTH + 1 {
            return false;
        }

        // Extract nonce and look up send time for RTT measurement.
        let nonce_comp = &name.components()[HELLO_PREFIX_DEPTH];
        if nonce_comp.value.len() != 4 {
            return false;
        }
        let nonce = u32::from_be_bytes(nonce_comp.value[..4].try_into().unwrap());
        let send_time = {
            let mut st = self.state.lock().unwrap();
            st.pending_probes.remove(&nonce)
        };

        // Decode HelloPayload from Content.
        let content = match parsed.content {
            Some(c) => c,
            None => {
                debug!("EtherND: hello Data has no content");
                return true;
            }
        };
        let payload = match HelloPayload::decode(&content) {
            Some(p) => p,
            None => {
                debug!("EtherND: could not decode HelloPayload");
                return true;
            }
        };
        let responder_name = payload.node_name;

        // Extract responder MAC from link-layer metadata.
        let responder_mac = match &meta.source {
            Some(LinkAddr::Ether(mac)) => *mac,
            _ => {
                debug!("EtherND: hello Data has no source MAC in meta — ignoring");
                return true;
            }
        };

        self.ensure_peer(ctx, &responder_name, responder_mac);

        ctx.update_neighbor(NeighborUpdate::SetState {
            name: responder_name.clone(),
            state: NeighborState::Reachable { last_seen: Instant::now() },
        });

        if let Some(sent) = send_time {
            let rtt_us = sent.elapsed().as_micros().min(u32::MAX as u128) as u32;
            ctx.update_neighbor(NeighborUpdate::UpdateRtt { name: responder_name, rtt_us });
        }

        true
    }

    // ─── Peer management ─────────────────────────────────────────────────────

    fn ensure_peer(&self, ctx: &dyn DiscoveryContext, peer_name: &Name, peer_mac: MacAddr) {
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
                    debug!("EtherND: created unicast face {registered:?} → {peer_name}");
                    registered
                }
                Err(e) => {
                    warn!("EtherND: failed to create unicast face to {peer_name}: {e}");
                    return;
                }
            }
        };

        if ctx.neighbors().get(peer_name).is_none() {
            ctx.update_neighbor(NeighborUpdate::Upsert(NeighborEntry::new(peer_name.clone())));
        }

        ctx.update_neighbor(NeighborUpdate::AddFace {
            name: peer_name.clone(),
            face_id,
            mac: peer_mac,
            iface: self.iface.clone(),
        });

        ctx.add_fib_entry(peer_name, face_id, 0, PROTOCOL);
    }
}

// ─── DiscoveryProtocol impl ───────────────────────────────────────────────────

impl DiscoveryProtocol for EtherNeighborDiscovery {
    fn protocol_id(&self) -> ProtocolId {
        PROTOCOL
    }

    fn claimed_prefixes(&self) -> &[Name] {
        &self.claimed
    }

    fn on_face_up(&self, face_id: FaceId, ctx: &dyn DiscoveryContext) {
        if face_id == self.multicast_face_id {
            let nonce = self.nonce_counter.fetch_add(1, Ordering::Relaxed);
            {
                let mut st = self.state.lock().unwrap();
                st.pending_probes.insert(nonce, Instant::now());
            }
            let pkt = self.build_hello_interest(nonce);
            ctx.send_on(self.multicast_face_id, pkt);
            debug!("EtherND: sent initial hello on face {face_id:?}");
        }
    }

    fn on_face_down(&self, _face_id: FaceId, _ctx: &dyn DiscoveryContext) {}

    fn on_inbound(
        &self,
        raw: &Bytes,
        incoming_face: FaceId,
        meta: &InboundMeta,
        ctx: &dyn DiscoveryContext,
    ) -> bool {
        if raw.is_empty() {
            return false;
        }
        // EtherFaces don't LP-wrap, but handle it defensively.
        let inner = match ndn_discovery::wire::unwrap_lp(raw) {
            Some(b) => b,
            None => return false,
        };
        match inner.first() {
            Some(&0x05) => self.handle_hello_interest(&inner, incoming_face, meta, ctx),
            Some(&0x06) => self.handle_hello_data(&inner, incoming_face, meta, ctx),
            _ => false,
        }
    }

    fn on_tick(&self, now: Instant, ctx: &dyn DiscoveryContext) {
        // ── Broadcast hello ────────────────────────────────────────────────────
        let should_send = {
            let st = self.state.lock().unwrap();
            now >= st.next_hello_at
        };

        if should_send {
            let nonce = self.nonce_counter.fetch_add(1, Ordering::Relaxed);
            let pkt = self.build_hello_interest(nonce);
            ctx.send_on(self.multicast_face_id, pkt);

            let mut st = self.state.lock().unwrap();
            st.pending_probes.insert(nonce, now);
            let cfg = st.hello_cfg.clone();
            let delay = st.hello_backoff.next_failure(&cfg);
            st.next_hello_at = now + delay;
            debug!("EtherND: broadcast hello (nonce={nonce:#010x}), next in {delay:.1?}");
        }

        // ── Neighbor state machine ─────────────────────────────────────────────
        let all = ctx.neighbors().all();
        for entry in all {
            match &entry.state {
                NeighborState::Reachable { last_seen } => {
                    if now.duration_since(*last_seen) > Duration::from_secs(30) {
                        ctx.update_neighbor(NeighborUpdate::SetState {
                            name: entry.node_name.clone(),
                            state: NeighborState::Failing {
                                miss_count: 1,
                                last_seen: *last_seen,
                            },
                        });
                    }
                }
                NeighborState::Failing { miss_count, last_seen } => {
                    if *miss_count >= 3 {
                        debug!("EtherND: peer {} is Dead", entry.node_name);
                        for (face_id, _, _) in &entry.faces {
                            ctx.remove_fib_entry(&entry.node_name, *face_id, PROTOCOL);
                            ctx.remove_face(*face_id);
                        }
                        ctx.update_neighbor(NeighborUpdate::Remove(entry.node_name.clone()));
                    } else if now.duration_since(*last_seen) > Duration::from_secs(30) {
                        ctx.update_neighbor(NeighborUpdate::SetState {
                            name: entry.node_name.clone(),
                            state: NeighborState::Failing {
                                miss_count: miss_count + 1,
                                last_seen: *last_seen,
                            },
                        });
                    }
                }
                _ => {}
            }
        }

        // Expire pending probes older than 5 s.
        let mut st = self.state.lock().unwrap();
        st.pending_probes
            .retain(|_, sent| now.duration_since(*sent) < Duration::from_secs(5));
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use ndn_discovery::wire::parse_raw_data;

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

        // /ndn/local/nd/hello/<nonce> = 5 components
        assert_eq!(comps.len(), HELLO_PREFIX_DEPTH + 1,
            "unexpected component count: {}", comps.len());

        let last = &comps[HELLO_PREFIX_DEPTH];
        let decoded_nonce = u32::from_be_bytes(last.value[..4].try_into().unwrap());
        assert_eq!(decoded_nonce, nonce);

        // No AppParams in the doc format.
        assert!(parsed.app_params.is_none(), "Interest must have no AppParams");
    }

    #[test]
    fn hello_data_carries_hello_payload() {
        let nd = make_nd();
        let interest_name = Name::from_str("/ndn/local/nd/hello/DEADBEEF").unwrap();
        let pkt = nd.build_hello_data(&interest_name);

        let parsed = parse_raw_data(&pkt).unwrap();
        assert_eq!(parsed.name, interest_name);

        let content = parsed.content.unwrap();
        let payload = HelloPayload::decode(&content).unwrap();
        assert_eq!(payload.node_name, nd.node_name);
    }

    #[test]
    fn protocol_id_and_prefix() {
        let nd = make_nd();
        assert_eq!(nd.protocol_id(), PROTOCOL);
        assert_eq!(nd.claimed_prefixes().len(), 1);
        assert_eq!(
            nd.claimed_prefixes()[0],
            Name::from_str(HELLO_PREFIX_STR).unwrap()
        );
    }
}
