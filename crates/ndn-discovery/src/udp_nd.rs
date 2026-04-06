//! `UdpNeighborDiscovery` — cross-platform NDN neighbor discovery over UDP.
//!
//! Works on Linux, macOS, Windows, Android, and iOS without any platform-
//! specific code.  Uses the IANA-assigned NDN multicast group
//! (`224.0.23.170:6363`) for hello broadcasts and creates a unicast
//! [`UdpFace`] per discovered peer.
//!
//! # Protocol
//!
//! **Hello Interest** (broadcast on the multicast face):
//! ```text
//! Name: /ndn/local/nd/hello/<nonce-u32>
//! ```
//!
//! **Hello Data** (reply via the multicast socket):
//! ```text
//! Name:    /ndn/local/nd/hello/<nonce-u32>
//! Content: HelloPayload TLV (NODE-NAME, SERVED-PREFIX*, CAPABILITIES?, NEIGHBOR-DIFF*)
//! ```
//!
//! When `swim_indirect_fanout > 0`, the protocol also handles:
//! - `/ndn/local/nd/probe/direct/<target>/<nonce>` — respond with ACK if we are the target
//! - `/ndn/local/nd/probe/via/<us>/<target>/<nonce>` — relay liveness check to target
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

use std::collections::{HashMap, VecDeque};
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
    DiffEntry, DiscoveryContext, DiscoveryProtocol, HelloPayload, InboundMeta,
    LinkAddr, NeighborDiff, NeighborEntry, NeighborState, NeighborUpdate, ProtocolId,
};
use crate::config::{DiscoveryConfig, DiscoveryProfile, PrefixAnnouncementMode};
use crate::probe::{
    build_direct_probe, build_indirect_probe, build_probe_ack,
    parse_direct_probe, parse_indirect_probe, is_probe_ack,
};
use crate::scope::{probe_direct, probe_via};
use crate::strategy::{NeighborProbeStrategy, ProbeRequest, TriggerEvent, build_strategy};
use crate::wire::{parse_raw_data, parse_raw_interest, unwrap_lp, write_name_tlv, write_nni};

const HELLO_PREFIX_STR: &str = "/ndn/local/nd/hello";
const HELLO_PREFIX_DEPTH: usize = 4;
const PROTOCOL: ProtocolId = ProtocolId("udp-nd");
const MAX_DIFF_ENTRIES: usize = 16;

struct UdpNdState {
    /// Nonce -> send_time (hello probes).
    pending_probes: HashMap<u32, Instant>,
    /// Peer address -> engine FaceId.
    peer_faces: HashMap<SocketAddr, FaceId>,
    /// Recent neighbor additions/removals for SWIM gossip piggyback.
    recent_diffs: VecDeque<DiffEntry>,
    /// SWIM direct probes: nonce -> (sent_at, target_name).
    swim_probes: HashMap<u32, (Instant, Name)>,
    /// Relay state: direct_probe_nonce -> (origin_face, relay_interest_name).
    relay_probes: HashMap<u32, (FaceId, Name)>,
}

pub struct UdpNeighborDiscovery {
    multicast_face_id: FaceId,
    node_name: Name,
    hello_prefix: Name,
    /// All prefixes claimed (hello + probe when SWIM enabled).
    claimed: Vec<Name>,
    nonce_counter: AtomicU32,
    config: DiscoveryConfig,
    strategy: Mutex<Box<dyn NeighborProbeStrategy>>,
    served_prefixes: Mutex<Vec<Name>>,
    state: Mutex<UdpNdState>,
}

impl UdpNeighborDiscovery {
    /// Create a new `UdpNeighborDiscovery` with the default LAN profile.
    pub fn new(multicast_face_id: FaceId, node_name: Name) -> Self {
        Self::new_with_config(
            multicast_face_id,
            node_name,
            DiscoveryConfig::for_profile(&DiscoveryProfile::Lan),
        )
    }

    pub fn new_with_config(multicast_face_id: FaceId, node_name: Name, config: DiscoveryConfig) -> Self {
        let hello_prefix = Name::from_str(HELLO_PREFIX_STR).expect("static prefix is valid");
        let mut claimed = vec![hello_prefix.clone()];
        if config.swim_indirect_fanout > 0 {
            claimed.push(probe_direct().clone());
            claimed.push(probe_via().clone());
        }
        let strategy = build_strategy(&config);
        Self {
            multicast_face_id,
            node_name,
            hello_prefix,
            claimed,
            nonce_counter: AtomicU32::new(1),
            strategy: Mutex::new(strategy),
            served_prefixes: Mutex::new(Vec::new()),
            config,
            state: Mutex::new(UdpNdState {
                pending_probes: HashMap::new(),
                peer_faces: HashMap::new(),
                recent_diffs: VecDeque::new(),
                swim_probes: HashMap::new(),
                relay_probes: HashMap::new(),
            }),
        }
    }

    pub fn from_profile(multicast_face_id: FaceId, node_name: Name, profile: &DiscoveryProfile) -> Self {
        Self::new_with_config(multicast_face_id, node_name, DiscoveryConfig::for_profile(profile))
    }

    /// Set the prefixes this node serves (announced in Hello Data when InHello mode).
    pub fn set_served_prefixes(&self, prefixes: Vec<Name>) {
        *self.served_prefixes.lock().unwrap() = prefixes;
    }

    // ── Packet builders ───────────────────────────────────────────────────────

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
            // Lifetime = hello_interval_base * 2 (doc §Hello Packet Format)
            let lifetime_ms = self.config.hello_interval_base.as_millis().min(u32::MAX as u128) as u64 * 2;
            write_nni(w, tlv_type::INTEREST_LIFETIME, lifetime_ms);
        });
        w.finish()
    }

    fn build_hello_data(&self, interest_name: &Name) -> Bytes {
        let mut payload = HelloPayload::new(self.node_name.clone());
        if self.config.prefix_announcement == PrefixAnnouncementMode::InHello {
            payload.served_prefixes = self.served_prefixes.lock().unwrap().clone();
        }
        {
            let st = self.state.lock().unwrap();
            if !st.recent_diffs.is_empty() {
                payload.neighbor_diffs.push(NeighborDiff {
                    entries: st.recent_diffs.iter().cloned().collect(),
                });
            }
        }
        let content = payload.encode();
        // FreshnessPeriod = hello_interval_base * 2 (doc §Hello Packet Format)
        let freshness_ms = self.config.hello_interval_base.as_millis().min(u32::MAX as u128) as u64 * 2;

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

    // ── Inbound handlers ──────────────────────────────────────────────────────

    fn handle_hello_interest(&self, inner: &Bytes, _incoming_face: FaceId, meta: &InboundMeta, ctx: &dyn DiscoveryContext) -> bool {
        let parsed = match parse_raw_interest(inner) { Some(p) => p, None => return false };
        let name = &parsed.name;
        if !name.has_prefix(&self.hello_prefix) { return false; }
        if name.components().len() != HELLO_PREFIX_DEPTH + 1 { return false; }
        let sender_addr = match &meta.source {
            Some(LinkAddr::Udp(addr)) => *addr,
            _ => { debug!("UdpND: hello Interest has no source addr"); return true; }
        };
        let reply = self.build_hello_data(name);
        ctx.send_on(self.multicast_face_id, reply);
        debug!("UdpND: hello Interest from {sender_addr}, sent reply");
        true
    }

    fn handle_hello_data(&self, inner: &Bytes, _incoming_face: FaceId, meta: &InboundMeta, ctx: &dyn DiscoveryContext) -> bool {
        let parsed = match parse_raw_data(inner) { Some(d) => d, None => return false };
        let name = &parsed.name;
        if !name.has_prefix(&self.hello_prefix) { return false; }
        if name.components().len() != HELLO_PREFIX_DEPTH + 1 { return false; }
        let nonce_comp = &name.components()[HELLO_PREFIX_DEPTH];
        if nonce_comp.value.len() != 4 { return false; }
        let nonce = u32::from_be_bytes(nonce_comp.value[..4].try_into().unwrap());
        let send_time = { let mut st = self.state.lock().unwrap(); st.pending_probes.remove(&nonce) };
        let content = match parsed.content { Some(c) => c, None => { debug!("UdpND: hello Data no content"); return true; } };
        let payload = match HelloPayload::decode(&content) { Some(p) => p, None => { debug!("UdpND: HelloPayload decode failed"); return true; } };
        let responder_name = payload.node_name.clone();
        let responder_addr = match &meta.source {
            Some(LinkAddr::Udp(addr)) => *addr,
            _ => { debug!("UdpND: hello Data no source addr"); return true; }
        };
        let peer_face_id = self.ensure_peer(ctx, &responder_name, responder_addr);
        ctx.update_neighbor(NeighborUpdate::SetState {
            name: responder_name.clone(),
            state: NeighborState::Established { last_seen: Instant::now() },
        });
        if let Some(sent) = send_time {
            let rtt = sent.elapsed();
            ctx.update_neighbor(NeighborUpdate::UpdateRtt { name: responder_name.clone(), rtt_us: rtt.as_micros().min(u32::MAX as u128) as u32 });
            self.strategy.lock().unwrap().on_probe_success(rtt);
        }
        if self.config.prefix_announcement == PrefixAnnouncementMode::InHello {
            if let Some(face_id) = peer_face_id {
                for prefix in &payload.served_prefixes {
                    ctx.add_fib_entry(prefix, face_id, 10, PROTOCOL);
                    debug!("UdpND: auto-FIB {prefix:?} via {face_id:?}");
                }
            }
        }
        self.apply_neighbor_diffs(&payload, ctx);
        {
            let mut st = self.state.lock().unwrap();
            st.recent_diffs.push_back(DiffEntry::Add(responder_name));
            while st.recent_diffs.len() > MAX_DIFF_ENTRIES { st.recent_diffs.pop_front(); }
        }
        true
    }

    fn handle_direct_probe_interest(&self, raw: &Bytes, incoming_face: FaceId, ctx: &dyn DiscoveryContext) -> bool {
        let probe = match parse_direct_probe(raw) { Some(p) => p, None => return false };
        if probe.target == self.node_name {
            // We are the target — send ACK.
            if let Some(parsed) = parse_raw_interest(raw) {
                let ack = build_probe_ack(&parsed.name);
                ctx.send_on(incoming_face, ack);
                debug!("UdpND: probe ACK sent (direct, nonce={:#010x})", probe.nonce);
            }
        }
        true
    }

    fn handle_via_probe_interest(&self, raw: &Bytes, incoming_face: FaceId, ctx: &dyn DiscoveryContext) -> bool {
        let probe = match parse_indirect_probe(raw) { Some(p) => p, None => return false };
        if probe.intermediary != self.node_name { return false; }
        // We are the intermediary. Check if we know the target.
        if let Some(entry) = ctx.neighbors().get(&probe.target) {
            if let Some((face_id, _, _)) = entry.faces.first() {
                // Send a fresh direct probe to the target; track the relay.
                let relay_nonce = self.nonce_counter.fetch_add(1, Ordering::Relaxed);
                let direct_pkt = build_direct_probe(&probe.target, relay_nonce);
                ctx.send_on(*face_id, direct_pkt);
                if let Some(parsed) = parse_raw_interest(raw) {
                    let mut st = self.state.lock().unwrap();
                    st.relay_probes.insert(relay_nonce, (incoming_face, parsed.name.clone()));
                }
                debug!("UdpND: relaying via-probe to {:?}", probe.target);
                return true;
            }
        }
        // Target unknown — send NACK by not replying (let the Interest time out).
        debug!("UdpND: via-probe target {:?} unknown, dropping", probe.target);
        true
    }

    fn handle_probe_ack(&self, raw: &Bytes, incoming_face: FaceId, ctx: &dyn DiscoveryContext) -> Option<bool> {
        let parsed = parse_raw_data(raw)?;
        let name = &parsed.name;
        // Extract nonce from last component.
        let comps = name.components();
        let last = comps.last()?;
        if last.value.len() != 4 { return Some(false); }
        let nonce = u32::from_be_bytes(last.value[..4].try_into().ok()?);

        // Was this a relay probe?
        let relay = { let mut st = self.state.lock().unwrap(); st.relay_probes.remove(&nonce) };
        if let Some((origin_face, original_name)) = relay {
            // Forward ACK back to the original requester.
            let ack = build_probe_ack(&original_name);
            ctx.send_on(origin_face, ack);
            debug!("UdpND: relayed probe ACK for nonce={nonce:#010x}");
        }

        // Was this an ACK for one of our own SWIM direct probes?
        let swim = { let mut st = self.state.lock().unwrap(); st.swim_probes.remove(&nonce) };
        if let Some((sent, _target)) = swim {
            let rtt = sent.elapsed();
            self.strategy.lock().unwrap().on_probe_success(rtt);
            debug!("UdpND: SWIM direct probe ACK nonce={nonce:#010x} rtt={rtt:?}");
        }
        Some(true)
    }

    fn apply_neighbor_diffs(&self, payload: &HelloPayload, ctx: &dyn DiscoveryContext) {
        let mut should_broadcast = false;
        for diff in &payload.neighbor_diffs {
            for entry in &diff.entries {
                match entry {
                    DiffEntry::Add(name) => {
                        if ctx.neighbors().get(name).is_none() {
                            // Spec: newly-heard-of neighbor starts in Probing state
                            // (not yet verified via direct hello exchange).
                            ctx.update_neighbor(NeighborUpdate::Upsert(NeighborEntry {
                                node_name: name.clone(),
                                state: NeighborState::Probing { attempts: 0, last_probe: Instant::now() },
                                faces: Vec::new(),
                                rtt_us: None,
                                pending_nonce: None,
                            }));
                            should_broadcast = true;
                            debug!("UdpND: SWIM diff — new peer {:?} in Probing", name);
                        }
                    }
                    DiffEntry::Remove(name) => {
                        if ctx.neighbors().get(name).is_some() {
                            ctx.update_neighbor(NeighborUpdate::SetState {
                                name: name.clone(),
                                state: NeighborState::Stale { miss_count: 1, last_seen: Instant::now() },
                            });
                        }
                    }
                }
            }
        }
        if should_broadcast { self.strategy.lock().unwrap().trigger(TriggerEvent::ForwardingFailure); }
    }

    // ── Peer management ───────────────────────────────────────────────────────

    fn ensure_peer(&self, ctx: &dyn DiscoveryContext, peer_name: &Name, peer_addr: SocketAddr) -> Option<FaceId> {
        let existing = { let st = self.state.lock().unwrap(); st.peer_faces.get(&peer_addr).copied() };
        let face_id = if let Some(fid) = existing { fid } else {
            match self.create_udp_face(ctx, peer_addr) { Some(fid) => fid, None => return None }
        };
        if ctx.neighbors().get(peer_name).is_none() {
            ctx.update_neighbor(NeighborUpdate::Upsert(NeighborEntry::new(peer_name.clone())));
        }
        ctx.add_fib_entry(peer_name, face_id, 0, PROTOCOL);
        Some(face_id)
    }

    fn create_udp_face(&self, ctx: &dyn DiscoveryContext, peer_addr: SocketAddr) -> Option<FaceId> {
        let bind_addr: SocketAddr = if peer_addr.is_ipv4() { "0.0.0.0:0".parse().unwrap() } else { "[::]:0".parse().unwrap() };
        let std_sock = match std::net::UdpSocket::bind(bind_addr) {
            Ok(s) => s, Err(e) => { warn!("UdpND: bind failed for {peer_addr}: {e}"); return None; }
        };
        if let Err(e) = std_sock.set_nonblocking(true) { warn!("UdpND: set_nonblocking: {e}"); return None; }
        let async_sock = match tokio::net::UdpSocket::from_std(std_sock) {
            Ok(s) => s, Err(e) => { warn!("UdpND: from_std: {e}"); return None; }
        };
        let face_id = ctx.alloc_face_id();
        let face = UdpFace::from_socket(face_id, async_sock, peer_addr);
        let registered = ctx.add_face(std::sync::Arc::new(face));
        { let mut st = self.state.lock().unwrap(); st.peer_faces.insert(peer_addr, registered); }
        debug!("UdpND: created unicast face {registered:?} -> {peer_addr}");
        Some(registered)
    }
}

// ── DiscoveryProtocol impl ────────────────────────────────────────────────────

impl DiscoveryProtocol for UdpNeighborDiscovery {
    fn protocol_id(&self) -> ProtocolId { PROTOCOL }
    fn claimed_prefixes(&self) -> &[Name] { &self.claimed }
    fn tick_interval(&self) -> Duration { self.config.tick_interval }

    fn on_face_up(&self, face_id: FaceId, ctx: &dyn DiscoveryContext) {
        if face_id == self.multicast_face_id {
            let nonce = self.nonce_counter.fetch_add(1, Ordering::Relaxed);
            { let mut st = self.state.lock().unwrap(); st.pending_probes.insert(nonce, Instant::now()); }
            ctx.send_on(self.multicast_face_id, self.build_hello_interest(nonce));
            self.strategy.lock().unwrap().trigger(TriggerEvent::FaceUp);
            debug!("UdpND: sent initial hello on face {face_id:?}");
        }
    }

    fn on_face_down(&self, face_id: FaceId, _ctx: &dyn DiscoveryContext) {
        let mut st = self.state.lock().unwrap();
        st.peer_faces.retain(|_, fid| *fid != face_id);
    }

    fn on_inbound(&self, raw: &Bytes, incoming_face: FaceId, meta: &InboundMeta, ctx: &dyn DiscoveryContext) -> bool {
        let inner = match unwrap_lp(raw) { Some(b) => b, None => return false };
        match inner.first() {
            Some(&0x05) => {
                // Interest: check probe prefixes first (fast path when SWIM disabled: prefixes not claimed)
                if self.config.swim_indirect_fanout > 0 {
                    if let Some(parsed) = parse_raw_interest(&inner) {
                        if parsed.name.has_prefix(probe_via()) {
                            return self.handle_via_probe_interest(&inner, incoming_face, ctx);
                        }
                        if parsed.name.has_prefix(probe_direct()) {
                            return self.handle_direct_probe_interest(&inner, incoming_face, ctx);
                        }
                    }
                }
                self.handle_hello_interest(&inner, incoming_face, meta, ctx)
            }
            Some(&0x06) => {
                if self.config.swim_indirect_fanout > 0 && is_probe_ack(&inner) {
                    return self.handle_probe_ack(&inner, incoming_face, ctx).unwrap_or(false);
                }
                self.handle_hello_data(&inner, incoming_face, meta, ctx)
            }
            _ => false,
        }
    }

    fn on_tick(&self, now: Instant, ctx: &dyn DiscoveryContext) {
        // ── Hello probe scheduling ────────────────────────────────────────────
        let probes = { self.strategy.lock().unwrap().on_tick(now) };
        for probe in probes {
            match probe {
                ProbeRequest::Broadcast => {
                    let nonce = self.nonce_counter.fetch_add(1, Ordering::Relaxed);
                    ctx.send_on(self.multicast_face_id, self.build_hello_interest(nonce));
                    self.state.lock().unwrap().pending_probes.insert(nonce, now);
                    debug!("UdpND: broadcast hello (nonce={nonce:#010x})");
                }
                ProbeRequest::Unicast(face_id) => {
                    let nonce = self.nonce_counter.fetch_add(1, Ordering::Relaxed);
                    ctx.send_on(face_id, self.build_hello_interest(nonce));
                    self.state.lock().unwrap().pending_probes.insert(nonce, now);
                    debug!("UdpND: unicast hello on {face_id:?} (nonce={nonce:#010x})");
                }
            }
        }

        // ── Neighbor state machine ────────────────────────────────────────────
        let liveness_timeout = self.config.liveness_timeout;
        let miss_limit = self.config.liveness_miss_count;
        let gossip_k = self.config.gossip_fanout as usize;
        let all = ctx.neighbors().all();
        for entry in &all {
            match &entry.state {
                NeighborState::Established { last_seen } => {
                    if now.duration_since(*last_seen) > liveness_timeout {
                        ctx.update_neighbor(NeighborUpdate::SetState {
                            name: entry.node_name.clone(),
                            state: NeighborState::Stale { miss_count: 1, last_seen: *last_seen },
                        });
                        self.strategy.lock().unwrap().trigger(TriggerEvent::NeighborStale);
                        // Send unicast hello to the stale neighbor's face directly.
                        if let Some((face_id, _, _)) = entry.faces.first() {
                            let nonce = self.nonce_counter.fetch_add(1, Ordering::Relaxed);
                            ctx.send_on(*face_id, self.build_hello_interest(nonce));
                            self.state.lock().unwrap().pending_probes.insert(nonce, now);
                        }
                        // Emergency gossip: send K unicast hellos to other established peers.
                        if gossip_k > 0 {
                            let stale_name = &entry.node_name;
                            let peers: Vec<FaceId> = all.iter()
                                .filter(|e| e.is_reachable() && &e.node_name != stale_name)
                                .flat_map(|e| e.faces.iter().map(|(fid, _, _)| *fid))
                                .take(gossip_k)
                                .collect();
                            for face_id in peers {
                                let nonce = self.nonce_counter.fetch_add(1, Ordering::Relaxed);
                                ctx.send_on(face_id, self.build_hello_interest(nonce));
                                self.state.lock().unwrap().pending_probes.insert(nonce, now);
                            }
                        }
                    }
                }
                NeighborState::Stale { miss_count, last_seen } => {
                    if u32::from(*miss_count) >= miss_limit {
                        debug!("UdpND: peer {} is Absent", entry.node_name);
                        {
                            let mut st = self.state.lock().unwrap();
                            st.peer_faces.retain(|_, fid| !entry.faces.iter().any(|(f, _, _)| f == fid));
                            st.recent_diffs.push_back(DiffEntry::Remove(entry.node_name.clone()));
                            while st.recent_diffs.len() > MAX_DIFF_ENTRIES { st.recent_diffs.pop_front(); }
                        }
                        for (face_id, _, _) in &entry.faces {
                            ctx.remove_fib_entry(&entry.node_name, *face_id, PROTOCOL);
                            ctx.remove_face(*face_id);
                        }
                        ctx.update_neighbor(NeighborUpdate::Remove(entry.node_name.clone()));
                    } else if now.duration_since(*last_seen) > liveness_timeout {
                        ctx.update_neighbor(NeighborUpdate::SetState {
                            name: entry.node_name.clone(),
                            state: NeighborState::Stale { miss_count: miss_count + 1, last_seen: *last_seen },
                        });
                    }
                }
                _ => {}
            }
        }

        // ── SWIM direct probes to established neighbors ───────────────────────
        if self.config.swim_indirect_fanout > 0 {
            for entry in all.iter().filter(|e| e.is_reachable()) {
                if let Some((face_id, _, _)) = entry.faces.first() {
                    let nonce = self.nonce_counter.fetch_add(1, Ordering::Relaxed);
                    ctx.send_on(*face_id, build_direct_probe(&entry.node_name, nonce));
                    self.state.lock().unwrap().swim_probes.insert(nonce, (now, entry.node_name.clone()));
                }
            }
        }

        // ── Expire hello pending probes ───────────────────────────────────────
        let probe_timeout = self.config.probe_timeout;
        let mut timed_out = 0u32;
        {
            let mut st = self.state.lock().unwrap();
            st.pending_probes.retain(|_, sent| {
                if now.duration_since(*sent) >= probe_timeout { timed_out += 1; false } else { true }
            });
        }
        if timed_out > 0 {
            for _ in 0..timed_out { self.strategy.lock().unwrap().on_probe_timeout(); }
        }

        // ── Expire SWIM direct probes; dispatch indirect probes on failure ─────
        if self.config.swim_indirect_fanout > 0 {
            let k = self.config.swim_indirect_fanout as usize;
            let mut timed_out_swim: Vec<Name> = Vec::new();
            {
                let mut st = self.state.lock().unwrap();
                st.swim_probes.retain(|_, (sent, target)| {
                    if now.duration_since(*sent) >= probe_timeout {
                        timed_out_swim.push(target.clone()); false
                    } else { true }
                });
            }
            for target in timed_out_swim {
                let intermediaries: Vec<_> = ctx.neighbors().all().into_iter()
                    .filter(|e| e.is_reachable() && e.node_name != target)
                    .take(k)
                    .collect();
                for via in intermediaries {
                    let nonce = self.nonce_counter.fetch_add(1, Ordering::Relaxed);
                    if let Some((face_id, _, _)) = via.faces.first() {
                        ctx.send_on(*face_id, build_indirect_probe(&via.node_name, &target, nonce));
                        debug!("UdpND: SWIM indirect probe -> {:?} via {:?}", target, via.node_name);
                    }
                }
                self.strategy.lock().unwrap().on_probe_timeout();
            }
        }
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::time::Duration;
    use super::*;
    use std::str::FromStr;

    fn make_nd() -> UdpNeighborDiscovery {
        UdpNeighborDiscovery::new(FaceId(1), Name::from_str("/ndn/test/node").unwrap())
    }

    #[test]
    fn hello_interest_format() {
        let nd = make_nd();
        let nonce: u32 = 0xCAFE_BABE;
        let pkt = nd.build_hello_interest(nonce);
        let parsed = parse_raw_interest(&pkt).unwrap();
        let comps = parsed.name.components();
        assert_eq!(comps.len(), HELLO_PREFIX_DEPTH + 1);
        let decoded_nonce = u32::from_be_bytes(comps[HELLO_PREFIX_DEPTH].value[..4].try_into().unwrap());
        assert_eq!(decoded_nonce, nonce);
        assert!(parsed.app_params.is_none());
    }

    #[test]
    fn hello_data_freshness_period_is_nonzero() {
        use ndn_tlv::TlvReader;
        let nd = make_nd();
        let interest_name = Name::from_str("/ndn/local/nd/hello/CAFEBABE").unwrap();
        let pkt = nd.build_hello_data(&interest_name);
        // Walk the TLV tree manually to find FRESHNESS_PERIOD.
        let mut r = TlvReader::new(pkt.clone());
        let (_, data_val) = r.read_tlv().unwrap(); // DATA
        let mut inner = TlvReader::new(data_val);
        let mut found_fp = false;
        while !inner.is_empty() {
            let (t, v) = inner.read_tlv().unwrap();
            if t == tlv_type::META_INFO {
                let mut meta_r = TlvReader::new(v);
                while !meta_r.is_empty() {
                    let (mt, mv) = meta_r.read_tlv().unwrap();
                    if mt == tlv_type::FRESHNESS_PERIOD {
                        let mut val: u64 = 0;
                        for b in mv.iter() { val = (val << 8) | (*b as u64); }
                        assert!(val > 0, "FreshnessPeriod should be > 0, got {val}");
                        found_fp = true;
                    }
                }
            }
        }
        assert!(found_fp, "FreshnessPeriod TLV not found in MetaInfo");
    }

    #[test]
    fn hello_data_carries_hello_payload() {
        let nd = make_nd();
        let interest_name = Name::from_str("/ndn/local/nd/hello/CAFEBABE").unwrap();
        let pkt = nd.build_hello_data(&interest_name);
        let parsed = parse_raw_data(&pkt).unwrap();
        assert_eq!(parsed.name, interest_name);
        let payload = HelloPayload::decode(&parsed.content.unwrap()).unwrap();
        assert_eq!(payload.node_name, nd.node_name);
    }

    #[test]
    fn in_hello_served_prefixes_encoded() {
        let nd = make_nd();
        nd.set_served_prefixes(vec![Name::from_str("/ndn/edu/test").unwrap()]);
        let interest_name = Name::from_str("/ndn/local/nd/hello/1").unwrap();
        let pkt = nd.build_hello_data(&interest_name);
        let parsed = parse_raw_data(&pkt).unwrap();
        let payload = HelloPayload::decode(&parsed.content.unwrap()).unwrap();
        assert_eq!(payload.served_prefixes.len(), 1);
    }

    #[test]
    fn neighbor_diffs_piggybacked() {
        let nd = make_nd();
        { let mut st = nd.state.lock().unwrap(); st.recent_diffs.push_back(DiffEntry::Add(Name::from_str("/ndn/peer/alpha").unwrap())); }
        let interest_name = Name::from_str("/ndn/local/nd/hello/1").unwrap();
        let pkt = nd.build_hello_data(&interest_name);
        let parsed = parse_raw_data(&pkt).unwrap();
        let payload = HelloPayload::decode(&parsed.content.unwrap()).unwrap();
        assert_eq!(payload.neighbor_diffs.len(), 1);
    }

    #[test]
    fn swim_probes_added_to_claimed_when_enabled() {
        let mut cfg = DiscoveryConfig::for_profile(&DiscoveryProfile::Campus);
        cfg.swim_indirect_fanout = 3;
        let nd = UdpNeighborDiscovery::new_with_config(FaceId(1), Name::from_str("/ndn/test/node").unwrap(), cfg);
        let has_probe_direct = nd.claimed_prefixes().iter().any(|p| p == probe_direct());
        let has_probe_via = nd.claimed_prefixes().iter().any(|p| p == probe_via());
        assert!(has_probe_direct, "probe/direct should be claimed when SWIM enabled");
        assert!(has_probe_via, "probe/via should be claimed when SWIM enabled");
    }

    #[test]
    fn lp_unwrap_strips_framing() {
        let raw = Bytes::from_static(b"\x05\x03ndn");
        let wrapped = ndn_packet::lp::encode_lp_packet(&raw);
        let unwrapped = crate::wire::unwrap_lp(&wrapped).unwrap();
        assert_eq!(unwrapped, raw);
    }

    #[test]
    fn protocol_id_and_prefix() {
        let nd = make_nd();
        assert_eq!(nd.protocol_id(), PROTOCOL);
        assert!(nd.claimed_prefixes().iter().any(|p| p == &Name::from_str(HELLO_PREFIX_STR).unwrap()));
    }

    #[test]
    fn tick_interval_from_config() {
        let nd = make_nd(); // LAN profile
        assert_eq!(nd.tick_interval(), Duration::from_millis(500));
    }

    #[test]
    fn on_face_down_removes_peer_entry() {
        let nd = make_nd();
        { let mut st = nd.state.lock().unwrap(); st.peer_faces.insert("10.0.0.1:6363".parse().unwrap(), FaceId(5)); }
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
        assert!(nd.state.lock().unwrap().peer_faces.is_empty());
    }

    #[test]
    fn from_profile_sets_config() {
        let nd = UdpNeighborDiscovery::from_profile(FaceId(1), Name::from_str("/ndn/test/node").unwrap(), &DiscoveryProfile::Mobile);
        assert!(nd.config.hello_interval_base < Duration::from_secs(1));
    }

    #[test]
    fn swim_diff_add_creates_probing_neighbor() {
        use crate::{NeighborTable, NeighborState, NeighborTableView, NeighborUpdate};
        use std::sync::Arc;

        struct TrackCtx {
            neighbors: Arc<NeighborTable>,
        }
        impl crate::DiscoveryContext for TrackCtx {
            fn alloc_face_id(&self) -> FaceId { FaceId(0) }
            fn add_face(&self, _: Arc<dyn ndn_transport::ErasedFace>) -> FaceId { FaceId(0) }
            fn remove_face(&self, _: FaceId) {}
            fn add_fib_entry(&self, _: &Name, _: FaceId, _: u32, _: ProtocolId) {}
            fn remove_fib_entry(&self, _: &Name, _: FaceId, _: ProtocolId) {}
            fn remove_fib_entries_by_owner(&self, _: ProtocolId) {}
            fn neighbors(&self) -> &dyn NeighborTableView { &*self.neighbors }
            fn update_neighbor(&self, u: NeighborUpdate) { self.neighbors.apply(u); }
            fn send_on(&self, _: FaceId, _: Bytes) {}
            fn now(&self) -> Instant { Instant::now() }
        }

        let nd = make_nd();
        let ctx = TrackCtx { neighbors: NeighborTable::new() };

        // Construct a HelloPayload containing a NEIGHBOR-DIFF Add entry for an unknown peer.
        let peer_name = Name::from_str("/ndn/peer/unknown").unwrap();
        let mut payload = crate::HelloPayload::new(Name::from_str("/ndn/test/sender").unwrap());
        payload.neighbor_diffs.push(crate::NeighborDiff {
            entries: vec![DiffEntry::Add(peer_name.clone())],
        });
        nd.apply_neighbor_diffs(&payload, &ctx);

        // The unknown peer must now exist in Probing state.
        let entry = ctx.neighbors.get(&peer_name).expect("neighbor should be created");
        assert!(matches!(entry.state, NeighborState::Probing { .. }),
            "expected Probing state, got {:?}", entry.state);
    }
}
