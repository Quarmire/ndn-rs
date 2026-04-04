//! `UdpNeighborDiscovery` — cross-platform NDN neighbor discovery over UDP.
//!
//! Works on Linux, macOS, Windows, Android, and iOS without any platform-
//! specific code.  Uses the IANA-assigned NDN multicast group
//! (`224.0.23.170:6363`) for hello broadcasts and creates a unicast
//! [`UdpFace`] per discovered peer.
//!
//! # Protocol (doc format)
//!
//! **Hello Interest** (broadcast on the multicast face):
//! ```text
//! Name: /ndn/local/nd/hello/<nonce-u32>
//! (no AppParams)
//! ```
//!
//! **Hello Data** (reply via the multicast socket):
//! ```text
//! Name:    /ndn/local/nd/hello/<nonce-u32>
//! Content: HelloPayload TLV
//!   NODE-NAME     = /ndn/site/mynode
//!   SERVED-PREFIX = ...        (optional)
//!   CAPABILITIES  = [flags]    (optional)
//! ```
//!
//! The sender's IP:port is obtained from `meta.source` (`LinkAddr::Udp`),
//! populated by the engine via `MulticastUdpFace::recv_with_source`.  The
//! address is never embedded in the NDN Interest payload.
//!
//! Inbound packets arrive LP-framed from UDP faces; `on_inbound` strips the
//! LP wrapper before inspection.
//!
//! # Usage
//!
//! ```rust,no_run
//! use ndn_discovery::UdpNeighborDiscovery;
//! use ndn_packet::Name;
//! use ndn_transport::FaceId;
//! use std::str::FromStr;
//!
//! let node_name = Name::from_str("/ndn/site/mynode").unwrap();
//! let multicast_face_id = FaceId(1); // registered with engine beforehand
//!
//! let nd = UdpNeighborDiscovery::new(multicast_face_id, node_name);
//! // Pass to EngineBuilder::discovery(nd)
//! ```

use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use ndn_face_net::UdpFace;
use ndn_packet::{Name, tlv_type};
use ndn_tlv::TlvWriter;
use ndn_transport::FaceId;
use tracing::{debug, warn};

use crate::{
    BackoffConfig, BackoffState, DiscoveryContext, DiscoveryProtocol, HelloPayload, InboundMeta,
    LinkAddr, NeighborEntry, NeighborState, NeighborUpdate, ProtocolId,
};
use crate::wire::{parse_raw_data, parse_raw_interest, unwrap_lp, write_name_tlv, write_nni};

/// Hello name prefix used by UDP ND.
const HELLO_PREFIX_STR: &str = "/ndn/local/nd/hello";
/// Number of components in the hello prefix.
const HELLO_PREFIX_DEPTH: usize = 4; // /ndn/local/nd/hello
/// Protocol identifier.
const PROTOCOL: ProtocolId = ProtocolId("udp-nd");

// ─── Internal state ───────────────────────────────────────────────────────────

struct UdpNdState {
    next_hello_at: Instant,
    hello_backoff: BackoffState,
    hello_cfg: BackoffConfig,
    /// Nonce → send_time (for RTT measurement).
    pending_probes: HashMap<u32, Instant>,
    /// Peer address → engine FaceId (deduplication).
    peer_faces: HashMap<SocketAddr, FaceId>,
}

// ─── Public API ───────────────────────────────────────────────────────────────

/// NDN neighbor discovery over UDP multicast.
///
/// Cross-platform: works wherever `tokio::net::UdpSocket` works.
pub struct UdpNeighborDiscovery {
    multicast_face_id: FaceId,
    node_name: Name,
    hello_prefix: Name,
    claimed: Vec<Name>,
    nonce_counter: AtomicU32,
    state: Mutex<UdpNdState>,
}

impl UdpNeighborDiscovery {
    /// Create a new `UdpNeighborDiscovery` instance.
    ///
    /// - `multicast_face_id`: `FaceId` of the [`MulticastUdpFace`] already
    ///   registered with the engine.
    /// - `node_name`: this node's NDN name, advertised in Hello Data.
    ///
    /// [`MulticastUdpFace`]: ndn_face_net::MulticastUdpFace
    pub fn new(multicast_face_id: FaceId, node_name: Name) -> Self {
        let hello_prefix = Name::from_str(HELLO_PREFIX_STR).expect("static prefix is valid");
        let claimed = vec![hello_prefix.clone()];
        Self {
            multicast_face_id,
            node_name,
            hello_prefix,
            claimed,
            nonce_counter: AtomicU32::new(1),
            state: Mutex::new(UdpNdState {
                next_hello_at: Instant::now(),
                hello_backoff: BackoffState::new(0),
                hello_cfg: BackoffConfig::for_neighbor_hello(),
                pending_probes: HashMap::new(),
                peer_faces: HashMap::new(),
            }),
        }
    }

    // ─── Packet builders ──────────────────────────────────────────────────────

    /// Build a Hello Interest: `/ndn/local/nd/hello/<nonce>`, no AppParams.
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

    /// Build a Hello Data: same name, Content = `HelloPayload` TLV.
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
        inner: &Bytes,
        _incoming_face: FaceId,
        meta: &InboundMeta,
        ctx: &dyn DiscoveryContext,
    ) -> bool {
        let parsed = match parse_raw_interest(inner) {
            Some(p) => p,
            None => return false,
        };

        let name = &parsed.name;
        if !name.has_prefix(&self.hello_prefix) {
            return false;
        }

        // Flat format: prefix (4) + nonce (1) = exactly 5 components.
        if name.components().len() != HELLO_PREFIX_DEPTH + 1 {
            return false;
        }

        // Source address comes from the socket, not the packet.
        let sender_addr = match &meta.source {
            Some(LinkAddr::Udp(addr)) => *addr,
            _ => {
                debug!("UdpND: hello Interest has no source addr in meta — ignoring");
                return true;
            }
        };

        let reply = self.build_hello_data(name);
        ctx.send_on(self.multicast_face_id, reply);
        debug!("UdpND: received hello Interest from {sender_addr}, sent Data reply");
        true
    }

    fn handle_hello_data(
        &self,
        inner: &Bytes,
        _incoming_face: FaceId,
        meta: &InboundMeta,
        ctx: &dyn DiscoveryContext,
    ) -> bool {
        let parsed = match parse_raw_data(inner) {
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

        let nonce_comp = &name.components()[HELLO_PREFIX_DEPTH];
        if nonce_comp.value.len() != 4 {
            return false;
        }
        let nonce = u32::from_be_bytes(nonce_comp.value[..4].try_into().unwrap());

        let send_time = {
            let mut st = self.state.lock().unwrap();
            st.pending_probes.remove(&nonce)
        };

        let content = match parsed.content {
            Some(c) => c,
            None => {
                debug!("UdpND: hello Data has no content");
                return true;
            }
        };

        let payload = match HelloPayload::decode(&content) {
            Some(p) => p,
            None => {
                debug!("UdpND: could not decode HelloPayload");
                return true;
            }
        };
        let responder_name = payload.node_name;

        // Source address from socket metadata.
        let responder_addr = match &meta.source {
            Some(LinkAddr::Udp(addr)) => *addr,
            _ => {
                debug!("UdpND: hello Data has no source addr in meta — ignoring");
                return true;
            }
        };

        self.ensure_peer(ctx, &responder_name, responder_addr);

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

    fn ensure_peer(&self, ctx: &dyn DiscoveryContext, peer_name: &Name, peer_addr: SocketAddr) {
        let existing = {
            let st = self.state.lock().unwrap();
            st.peer_faces.get(&peer_addr).copied()
        };

        let face_id = if let Some(fid) = existing {
            fid
        } else {
            match self.create_udp_face(ctx, peer_addr) {
                Some(fid) => fid,
                None => return,
            }
        };

        if ctx.neighbors().get(peer_name).is_none() {
            ctx.update_neighbor(NeighborUpdate::Upsert(NeighborEntry::new(peer_name.clone())));
        }

        ctx.add_fib_entry(peer_name, face_id, 0, PROTOCOL);
    }

    fn create_udp_face(&self, ctx: &dyn DiscoveryContext, peer_addr: SocketAddr) -> Option<FaceId> {
        let bind_addr: SocketAddr = if peer_addr.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };

        let std_sock = match std::net::UdpSocket::bind(bind_addr) {
            Ok(s) => s,
            Err(e) => {
                warn!("UdpND: failed to bind socket for peer {peer_addr}: {e}");
                return None;
            }
        };
        if let Err(e) = std_sock.set_nonblocking(true) {
            warn!("UdpND: set_nonblocking failed: {e}");
            return None;
        }
        let async_sock = match tokio::net::UdpSocket::from_std(std_sock) {
            Ok(s) => s,
            Err(e) => {
                warn!("UdpND: tokio::net::UdpSocket::from_std failed: {e}");
                return None;
            }
        };

        let face_id = ctx.alloc_face_id();
        let face = UdpFace::from_socket(face_id, async_sock, peer_addr);
        let registered = ctx.add_face(std::sync::Arc::new(face));

        {
            let mut st = self.state.lock().unwrap();
            st.peer_faces.insert(peer_addr, registered);
        }

        debug!("UdpND: created unicast face {registered:?} → {peer_addr}");
        Some(registered)
    }
}

// ─── DiscoveryProtocol impl ───────────────────────────────────────────────────

impl DiscoveryProtocol for UdpNeighborDiscovery {
    fn protocol_id(&self) -> ProtocolId { PROTOCOL }

    fn claimed_prefixes(&self) -> &[Name] { &self.claimed }

    fn on_face_up(&self, face_id: FaceId, ctx: &dyn DiscoveryContext) {
        if face_id == self.multicast_face_id {
            let nonce = self.nonce_counter.fetch_add(1, Ordering::Relaxed);
            {
                let mut st = self.state.lock().unwrap();
                st.pending_probes.insert(nonce, Instant::now());
            }
            let pkt = self.build_hello_interest(nonce);
            ctx.send_on(self.multicast_face_id, pkt);
            debug!("UdpND: sent initial hello on face {face_id:?}");
        }
    }

    fn on_face_down(&self, face_id: FaceId, _ctx: &dyn DiscoveryContext) {
        let mut st = self.state.lock().unwrap();
        st.peer_faces.retain(|_, fid| *fid != face_id);
    }

    fn on_inbound(
        &self,
        raw: &Bytes,
        incoming_face: FaceId,
        meta: &InboundMeta,
        ctx: &dyn DiscoveryContext,
    ) -> bool {
        let inner = match unwrap_lp(raw) {
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
            debug!("UdpND: broadcast hello (nonce={nonce:#010x}), next in {delay:.1?}");
        }

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
                        debug!("UdpND: peer {} is Dead", entry.node_name);
                        let dead_faces: Vec<FaceId> = {
                            let st = self.state.lock().unwrap();
                            st.peer_faces.values().copied().collect()
                        };
                        for fid in dead_faces {
                            ctx.remove_fib_entry(&entry.node_name, fid, PROTOCOL);
                            ctx.remove_face(fid);
                        }
                        {
                            let mut st = self.state.lock().unwrap();
                            st.peer_faces.retain(|_, fid| {
                                !entry.faces.iter().any(|(f, _, _)| f == fid)
                            });
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

    fn make_nd() -> UdpNeighborDiscovery {
        UdpNeighborDiscovery::new(
            FaceId(1),
            Name::from_str("/ndn/test/node").unwrap(),
        )
    }

    #[test]
    fn hello_interest_format() {
        let nd = make_nd();
        let nonce: u32 = 0xCAFE_BABE;
        let pkt = nd.build_hello_interest(nonce);

        let parsed = parse_raw_interest(&pkt).unwrap();
        let comps = parsed.name.components();

        // /ndn/local/nd/hello/<nonce> = 5 components (flat, no sender name)
        assert_eq!(comps.len(), HELLO_PREFIX_DEPTH + 1,
            "unexpected component count: {}", comps.len());

        let decoded_nonce = u32::from_be_bytes(
            comps[HELLO_PREFIX_DEPTH].value[..4].try_into().unwrap(),
        );
        assert_eq!(decoded_nonce, nonce);

        // No AppParams in the doc format.
        assert!(parsed.app_params.is_none(), "Interest must have no AppParams");
    }

    #[test]
    fn hello_data_carries_hello_payload() {
        let nd = make_nd();
        let interest_name = Name::from_str("/ndn/local/nd/hello/CAFEBABE").unwrap();
        let pkt = nd.build_hello_data(&interest_name);

        let parsed = parse_raw_data(&pkt).unwrap();
        assert_eq!(parsed.name, interest_name);

        let content = parsed.content.unwrap();
        let payload = HelloPayload::decode(&content).unwrap();
        assert_eq!(payload.node_name, nd.node_name);
    }

    #[test]
    fn lp_unwrap_strips_framing() {
        let raw = Bytes::from_static(b"\x05\x03ndn");
        let wrapped = ndn_packet::lp::encode_lp_packet(&raw);
        let unwrapped = crate::wire::unwrap_lp(&wrapped).unwrap();
        assert_eq!(unwrapped, raw);
    }

    #[test]
    fn lp_unwrap_passthrough_for_bare_packet() {
        let raw = Bytes::from_static(b"\x05\x03ndn");
        let unwrapped = crate::wire::unwrap_lp(&raw).unwrap();
        assert_eq!(unwrapped, raw);
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

    #[test]
    fn on_face_down_removes_peer_entry() {
        let nd = make_nd();
        {
            let mut st = nd.state.lock().unwrap();
            st.peer_faces.insert("10.0.0.1:6363".parse().unwrap(), FaceId(5));
        }
        struct NullCtx;
        impl crate::DiscoveryContext for NullCtx {
            fn alloc_face_id(&self) -> FaceId { FaceId(0) }
            fn add_face(&self, _: std::sync::Arc<dyn ndn_transport::ErasedFace>) -> FaceId { FaceId(0) }
            fn remove_face(&self, _: FaceId) {}
            fn add_fib_entry(&self, _: &Name, _: FaceId, _: u32, _: ProtocolId) {}
            fn remove_fib_entry(&self, _: &Name, _: FaceId, _: ProtocolId) {}
            fn remove_fib_entries_by_owner(&self, _: ProtocolId) {}
            fn neighbors(&self) -> &dyn crate::NeighborTableView { unimplemented!() }
            fn update_neighbor(&self, _: crate::NeighborUpdate) {}
            fn send_on(&self, _: FaceId, _: Bytes) {}
            fn now(&self) -> Instant { Instant::now() }
        }
        nd.on_face_down(FaceId(5), &NullCtx);
        let st = nd.state.lock().unwrap();
        assert!(st.peer_faces.is_empty());
    }
}
