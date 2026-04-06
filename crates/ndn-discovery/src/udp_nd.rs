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
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use ndn_face_net::UdpFace;
use ndn_packet::{Name, SignatureType, tlv_type};
use ndn_packet::encode::DataBuilder;
use ndn_security::{Ed25519Signer, Ed25519Verifier, Signer, VerifyOutcome};
use ndn_tlv::TlvWriter;
use ndn_transport::FaceId;
use tracing::{debug, error, info, trace, warn};

use crate::{
    DiffEntry, DiscoveryContext, DiscoveryProtocol, HelloPayload, InboundMeta,
    LinkAddr, MacAddr, NeighborDiff, NeighborEntry, NeighborState, NeighborUpdate, ProtocolId,
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
    /// All multicast face IDs (one per interface) to broadcast hellos on.
    multicast_face_ids: Vec<FaceId>,
    node_name: Name,
    hello_prefix: Name,
    /// All prefixes claimed (hello + probe when SWIM enabled).
    claimed: Vec<Name>,
    nonce_counter: AtomicU32,
    config: DiscoveryConfig,
    strategy: Mutex<Box<dyn NeighborProbeStrategy>>,
    served_prefixes: Mutex<Vec<Name>>,
    state: Mutex<UdpNdState>,
    /// Ed25519 signer for hello Data packets.  Also provides the public key
    /// embedded in `HelloPayload::public_key` for self-attesting verification.
    signer: Arc<dyn Signer>,
    /// This node's UDP unicast listen port, advertised in hello payloads so
    /// peers create their unicast face on the right port instead of the
    /// multicast source port (which would misroute data traffic).
    unicast_port: Option<u16>,
}

impl UdpNeighborDiscovery {
    /// Create a new `UdpNeighborDiscovery` with the default LAN profile.
    pub fn new(multicast_face_id: FaceId, node_name: Name) -> Self {
        Self::new_multi(
            vec![multicast_face_id],
            node_name,
            DiscoveryConfig::for_profile(&DiscoveryProfile::Lan),
        )
    }

    pub fn new_with_config(multicast_face_id: FaceId, node_name: Name, config: DiscoveryConfig) -> Self {
        Self::new_multi(vec![multicast_face_id], node_name, config)
    }

    /// Create a `UdpNeighborDiscovery` listening on multiple multicast faces
    /// (one per network interface).  Hello broadcasts are sent on all faces.
    ///
    /// A transient Ed25519 key is derived deterministically from the node name
    /// via SHA-256.  Callers that need a persistent key should use
    /// [`new_multi_with_signer`].
    pub fn new_multi(face_ids: Vec<FaceId>, node_name: Name, config: DiscoveryConfig) -> Self {
        let signer = Self::make_transient_signer(&node_name);
        Self::new_multi_with_signer(face_ids, node_name, config, signer)
    }

    /// Create with an explicit signer (e.g. from the router's PIB).
    pub fn new_multi_with_signer(
        face_ids: Vec<FaceId>,
        node_name: Name,
        config: DiscoveryConfig,
        signer: Arc<dyn Signer>,
    ) -> Self {
        let hello_prefix = Name::from_str(HELLO_PREFIX_STR).expect("static prefix is valid");
        let mut claimed = vec![hello_prefix.clone()];
        if config.swim_indirect_fanout > 0 {
            claimed.push(probe_direct().clone());
            claimed.push(probe_via().clone());
        }
        let strategy = build_strategy(&config);
        Self {
            multicast_face_ids: face_ids,
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
            signer,
            unicast_port: None,
        }
    }

    /// Set the UDP unicast port this node listens on for forwarding traffic.
    ///
    /// When set, this port is advertised in every hello Data so that peers
    /// create their unicast face to `<peer-ip>:<unicast_port>` rather than
    /// to the multicast source port.  Call this after construction, before
    /// passing to `EngineBuilder::discovery()`.
    pub fn with_unicast_port(mut self, port: u16) -> Self {
        self.unicast_port = Some(port);
        self
    }

    /// Derive a deterministic transient Ed25519 key from the node name.
    ///
    /// Uses SHA-256 of the node name's canonical URI as a 32-byte seed.
    /// This is sufficient for link-local bootstrapping; production deployments
    /// should supply a persistent signer via `new_multi_with_signer`.
    fn make_transient_signer(node_name: &Name) -> Arc<dyn Signer> {
        let name_str = node_name.to_string();
        let digest = ring::digest::digest(&ring::digest::SHA256, name_str.as_bytes());
        let seed: &[u8; 32] = digest.as_ref().try_into().expect("SHA-256 is 32 bytes");
        // Key name: <node_name>/KEY/discovery-transient
        let key_name = format!("{node_name}/KEY/discovery-transient")
            .parse::<Name>()
            .unwrap_or_else(|_| node_name.clone());
        Arc::new(Ed25519Signer::from_seed(seed, key_name))
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
        // Include the public key for self-attesting signature verification.
        payload.public_key = self.signer.public_key();
        // Advertise our unicast port so peers don't use the multicast port.
        payload.unicast_port = self.unicast_port;
        let content = payload.encode();
        // FreshnessPeriod = hello_interval_base * 2 (doc §Hello Packet Format)
        let freshness_ms = self.config.hello_interval_base.as_millis().min(u32::MAX as u128) as u64 * 2;

        let signer = &self.signer;
        DataBuilder::new(interest_name.clone(), &content)
            .freshness(Duration::from_millis(freshness_ms))
            .sign_sync(
                signer.sig_type(),
                signer.cert_name(),
                |region| signer.sign_sync(region).unwrap_or_default(),
            )
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
        for &fid in &self.multicast_face_ids {
            ctx.send_on(fid, reply.clone());
        }
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

        // ── Signature verification ────────────────────────────────────────────
        if let Some(ref peer_pk) = payload.public_key {
            // Decode the full Data packet to access the signed region + sig value.
            if let Ok(data_pkt) = ndn_packet::Data::decode(inner.clone()) {
                let region = data_pkt.signed_region();
                let sig_val = data_pkt.sig_value();
                let verifier = Ed25519Verifier;
                let outcome = verifier.verify_sync(region, sig_val, peer_pk);
                if outcome != VerifyOutcome::Valid {
                    warn!(name=%payload.node_name, "UdpND: hello Data signature invalid, discarding");
                    return true;
                }
            } else {
                warn!("UdpND: hello Data has public_key but failed full decode; discarding");
                return true;
            }
        }

        // ── Node name uniqueness check ────────────────────────────────────────
        let responder_name = payload.node_name.clone();
        if responder_name == self.node_name {
            // This could be our own echo or a genuine name conflict.
            let our_pk = self.signer.public_key();
            match (our_pk, payload.public_key.as_ref()) {
                (Some(ref ours), Some(ref theirs)) if ours == theirs => {
                    // Own echo — silently discard.
                    debug!(name=%responder_name, "UdpND: hello echo (own packet), discarding");
                }
                _ => {
                    // Different key or unsigned — real conflict.
                    error!(
                        name = %responder_name,
                        "UdpND: DUPLICATE NODE NAME detected — another node is using our name!"
                    );
                }
            }
            return true;
        }

        let responder_addr = match &meta.source {
            Some(LinkAddr::Udp(addr)) => *addr,
            _ => { debug!("UdpND: hello Data no source addr"); return true; }
        };
        // If the hello payload advertises a unicast port, use that instead of
        // the source port (which is the multicast port when hellos are sent via
        // the multicast socket).  This ensures data traffic uses a true unicast
        // path rather than going through the multicast group.
        let unicast_addr = match payload.unicast_port {
            Some(port) => std::net::SocketAddr::new(responder_addr.ip(), port),
            None => responder_addr,
        };
        let peer_face_id = self.ensure_peer(ctx, &responder_name, unicast_addr);
        ctx.update_neighbor(NeighborUpdate::SetState {
            name: responder_name.clone(),
            state: NeighborState::Established { last_seen: Instant::now() },
        });
        if let Some(sent) = send_time {
            let rtt = sent.elapsed();
            let rtt_us = rtt.as_micros().min(u32::MAX as u128) as u32;
            debug!(peer = %responder_name, addr = %responder_addr, rtt_us, "UdpND: hello response accepted");
            ctx.update_neighbor(NeighborUpdate::UpdateRtt { name: responder_name.clone(), rtt_us });
            self.strategy.lock().unwrap().on_probe_success(rtt);
        } else {
            debug!(peer = %responder_name, addr = %responder_addr, "UdpND: hello response accepted (no RTT — unsolicited)");
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
        // Register the unicast face with the neighbor entry so that protocols
        // iterating entry.faces (e.g. service discovery browse) can reach the
        // peer.  For UDP there is no MAC; use the peer address as the iface
        // string for stable deduplication.
        ctx.update_neighbor(NeighborUpdate::AddFace {
            name: peer_name.clone(),
            face_id,
            mac: MacAddr::new([0; 6]),
            iface: peer_addr.to_string(),
        });
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
        if self.multicast_face_ids.contains(&face_id) {
            let nonce = self.nonce_counter.fetch_add(1, Ordering::Relaxed);
            { let mut st = self.state.lock().unwrap(); st.pending_probes.insert(nonce, Instant::now()); }
            let hello = self.build_hello_interest(nonce);
            for &fid in &self.multicast_face_ids {
                ctx.send_on(fid, hello.clone());
            }
            self.strategy.lock().unwrap().trigger(TriggerEvent::FaceUp);
            debug!("UdpND: sent initial hello on face {face_id:?}");
        }
    }

    fn on_face_down(&self, face_id: FaceId, _ctx: &dyn DiscoveryContext) {
        let mut st = self.state.lock().unwrap();
        let removed = st.peer_faces.iter().filter(|(_, fid)| **fid == face_id).count();
        st.peer_faces.retain(|_, fid| *fid != face_id);
        if removed > 0 {
            debug!(face = ?face_id, peers_removed = removed, "UdpND: face down, removed peer bindings");
        } else {
            debug!(face = ?face_id, "UdpND: face down");
        }
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
                    let hello = self.build_hello_interest(nonce);
                    for &fid in &self.multicast_face_ids {
                        ctx.send_on(fid, hello.clone());
                    }
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
                        let idle_ms = now.duration_since(*last_seen).as_millis();
                        debug!(peer = %entry.node_name, idle_ms, "UdpND: liveness timeout, sending probe");
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
                        info!(peer = %entry.node_name, miss_count, "UdpND: peer unreachable, removing");
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
                        let new_miss = miss_count + 1;
                        debug!(peer = %entry.node_name, miss_count = new_miss, limit = miss_limit, "UdpND: missed hello, incrementing miss count");
                        ctx.update_neighbor(NeighborUpdate::SetState {
                            name: entry.node_name.clone(),
                            state: NeighborState::Stale { miss_count: new_miss, last_seen: *last_seen },
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
                    trace!(peer = %entry.node_name, face = ?face_id, nonce, "UdpND: SWIM direct probe →");
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
                debug!(peer = %target, via_count = intermediaries.len(), "UdpND: SWIM direct probe timed out, dispatching indirect probes");
                for via in intermediaries {
                    let nonce = self.nonce_counter.fetch_add(1, Ordering::Relaxed);
                    if let Some((face_id, _, _)) = via.faces.first() {
                        ctx.send_on(*face_id, build_indirect_probe(&via.node_name, &target, nonce));
                        trace!(peer = %target, via = %via.node_name, nonce, "UdpND: SWIM indirect probe →");
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
            fn neighbors(&self) -> std::sync::Arc<dyn crate::NeighborTableView> {
                crate::NeighborTable::new()
            }
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
            fn neighbors(&self) -> Arc<dyn NeighborTableView> { Arc::clone(&self.neighbors) as Arc<dyn NeighborTableView> }
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
