//! `HelloProtocol<T>` — generic SWIM/hello/probe discovery state machine.
//!
//! Link-specific operations are delegated to a [`LinkMedium`] implementation.

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use bytes::Bytes;
use ndn_packet::{Name, tlv_type};
use ndn_tlv::TlvWriter;
use ndn_transport::FaceId;
use tracing::{debug, info, trace};

use super::medium::{HELLO_PREFIX_DEPTH, HelloCore, LinkMedium, MAX_DIFF_ENTRIES};
use super::probe::{
    build_direct_probe, build_indirect_probe, build_probe_ack, is_probe_ack, parse_direct_probe,
    parse_indirect_probe,
};
use crate::config::PrefixAnnouncementMode;
use crate::scope::{probe_direct, probe_via};
use crate::strategy::{ProbeRequest, TriggerEvent};
use crate::wire::{parse_raw_data, parse_raw_interest, write_nni};
use crate::{
    DiffEntry, DiscoveryContext, DiscoveryProtocol, HelloPayload, InboundMeta, NeighborDiff,
    NeighborEntry, NeighborState, NeighborUpdate, ProtocolId,
};

/// Generic neighbor discovery protocol over any [`LinkMedium`].
pub struct HelloProtocol<T: LinkMedium> {
    pub core: HelloCore,
    pub medium: T,
}

impl<T: LinkMedium> HelloProtocol<T> {
    pub fn create(medium: T, node_name: Name, config: crate::config::DiscoveryConfig) -> Self {
        let core = HelloCore::new(node_name, config);
        Self { core, medium }
    }

    pub fn core(&self) -> &HelloCore {
        &self.core
    }

    pub fn medium(&self) -> &T {
        &self.medium
    }

    pub fn set_served_prefixes(&self, prefixes: Vec<Name>) {
        *self.core.served_prefixes.lock().unwrap() = prefixes;
    }


    pub fn build_hello_interest(&self, nonce: u32) -> Bytes {
        let hello_interval_base = self.core.config.read().unwrap().hello_interval_base;
        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::INTEREST, |w: &mut TlvWriter| {
            w.write_nested(tlv_type::NAME, |w: &mut TlvWriter| {
                for comp in self.core.hello_prefix.components() {
                    w.write_tlv(comp.typ, &comp.value);
                }
                w.write_tlv(tlv_type::NAME_COMPONENT, &nonce.to_be_bytes());
            });
            w.write_tlv(tlv_type::NONCE, &nonce.to_be_bytes());
            let lifetime_ms = hello_interval_base.as_millis().min(u32::MAX as u128) as u64 * 2;
            write_nni(w, tlv_type::INTEREST_LIFETIME, lifetime_ms);
        });
        w.finish()
    }

    pub fn build_hello_payload(&self) -> HelloPayload {
        let mut payload = HelloPayload::new(self.core.node_name.clone());
        if self.core.config.read().unwrap().prefix_announcement == PrefixAnnouncementMode::InHello {
            payload.served_prefixes = self.core.served_prefixes.lock().unwrap().clone();
        }
        {
            let st = self.core.state.lock().unwrap();
            if !st.recent_diffs.is_empty() {
                payload.neighbor_diffs.push(NeighborDiff {
                    entries: st.recent_diffs.iter().cloned().collect(),
                });
            }
        }
        payload
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
        if !name.has_prefix(&self.core.hello_prefix) {
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
            let mut st = self.core.state.lock().unwrap();
            st.pending_probes.remove(&nonce)
        };

        let content = match parsed.content {
            Some(c) => c,
            None => {
                debug!("{}: hello Data no content", self.medium.protocol_id());
                return true;
            }
        };
        let payload = match HelloPayload::decode(&content) {
            Some(p) => p,
            None => {
                debug!("{}: HelloPayload decode failed", self.medium.protocol_id());
                return true;
            }
        };

        let (responder_name, peer_face_id) = match self
            .medium
            .verify_and_ensure_peer(raw, &payload, meta, &self.core, ctx)
        {
            Some(result) => result,
            None => return true,
        };

        ctx.update_neighbor(NeighborUpdate::SetState {
            name: responder_name.clone(),
            state: NeighborState::Established {
                last_seen: Instant::now(),
            },
        });

        if let Some(sent) = send_time {
            let rtt = sent.elapsed();
            let rtt_us = rtt.as_micros().min(u32::MAX as u128) as u32;
            ctx.update_neighbor(NeighborUpdate::UpdateRtt {
                name: responder_name.clone(),
                rtt_us,
            });
            self.core.strategy.lock().unwrap().on_probe_success(rtt);
        }

        if self.core.config.read().unwrap().prefix_announcement == PrefixAnnouncementMode::InHello
            && let Some(face_id) = peer_face_id
        {
            for prefix in &payload.served_prefixes {
                ctx.add_fib_entry(prefix, face_id, 10, self.medium.protocol_id());
                debug!(
                    "{}: auto-FIB {prefix:?} via {face_id:?}",
                    self.medium.protocol_id()
                );
            }
        }

        self.apply_neighbor_diffs(&payload, ctx);

        {
            let mut st = self.core.state.lock().unwrap();
            st.recent_diffs.push_back(DiffEntry::Add(responder_name));
            while st.recent_diffs.len() > MAX_DIFF_ENTRIES {
                st.recent_diffs.pop_front();
            }
        }

        true
    }

    fn handle_direct_probe_interest(
        &self,
        raw: &Bytes,
        incoming_face: FaceId,
        ctx: &dyn DiscoveryContext,
    ) -> bool {
        let probe = match parse_direct_probe(raw) {
            Some(p) => p,
            None => return false,
        };
        if probe.target == self.core.node_name
            && let Some(parsed) = parse_raw_interest(raw)
        {
            let ack = build_probe_ack(&parsed.name);
            ctx.send_on(incoming_face, ack);
            debug!(
                "{}: probe ACK sent (direct, nonce={:#010x})",
                self.medium.protocol_id(),
                probe.nonce
            );
        }
        true
    }

    fn handle_via_probe_interest(
        &self,
        raw: &Bytes,
        incoming_face: FaceId,
        ctx: &dyn DiscoveryContext,
    ) -> bool {
        let probe = match parse_indirect_probe(raw) {
            Some(p) => p,
            None => return false,
        };
        if probe.intermediary != self.core.node_name {
            return false;
        }
        if let Some(entry) = ctx.neighbors().get(&probe.target)
            && let Some((face_id, _, _)) = entry.faces.first()
        {
            let relay_nonce = self.core.nonce_counter.fetch_add(1, Ordering::Relaxed);
            let direct_pkt = build_direct_probe(&probe.target, relay_nonce);
            ctx.send_on(*face_id, direct_pkt);
            if let Some(parsed) = parse_raw_interest(raw) {
                let mut st = self.core.state.lock().unwrap();
                st.relay_probes
                    .insert(relay_nonce, (incoming_face, parsed.name.clone()));
            }
            debug!(
                "{}: relaying via-probe to {:?}",
                self.medium.protocol_id(),
                probe.target
            );
            return true;
        }
        debug!(
            "{}: via-probe target {:?} unknown, dropping",
            self.medium.protocol_id(),
            probe.target
        );
        true
    }

    fn handle_probe_ack(
        &self,
        raw: &Bytes,
        _incoming_face: FaceId,
        ctx: &dyn DiscoveryContext,
    ) -> Option<bool> {
        let parsed = parse_raw_data(raw)?;
        let name = &parsed.name;
        let comps = name.components();
        let last = comps.last()?;
        if last.value.len() != 4 {
            return Some(false);
        }
        let nonce = u32::from_be_bytes(last.value[..4].try_into().ok()?);

        let relay = {
            let mut st = self.core.state.lock().unwrap();
            st.relay_probes.remove(&nonce)
        };
        if let Some((origin_face, original_name)) = relay {
            let ack = build_probe_ack(&original_name);
            ctx.send_on(origin_face, ack);
            debug!(
                "{}: relayed probe ACK for nonce={nonce:#010x}",
                self.medium.protocol_id()
            );
        }

        let swim = {
            let mut st = self.core.state.lock().unwrap();
            st.swim_probes.remove(&nonce)
        };
        if let Some((sent, _target)) = swim {
            let rtt = sent.elapsed();
            self.core.strategy.lock().unwrap().on_probe_success(rtt);
            debug!(
                "{}: SWIM direct probe ACK nonce={nonce:#010x} rtt={rtt:?}",
                self.medium.protocol_id()
            );
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
                            ctx.update_neighbor(NeighborUpdate::Upsert(NeighborEntry {
                                node_name: name.clone(),
                                state: NeighborState::Probing {
                                    attempts: 0,
                                    last_probe: Instant::now(),
                                },
                                faces: Vec::new(),
                                rtt_us: None,
                                pending_nonce: None,
                            }));
                            should_broadcast = true;
                            debug!(
                                "{}: SWIM diff — new peer {name:?} in Probing",
                                self.medium.protocol_id()
                            );
                        }
                    }
                    DiffEntry::Remove(name) => {
                        if ctx.neighbors().get(name).is_some() {
                            ctx.update_neighbor(NeighborUpdate::SetState {
                                name: name.clone(),
                                state: NeighborState::Stale {
                                    miss_count: 1,
                                    last_seen: Instant::now(),
                                },
                            });
                        }
                    }
                }
            }
        }

        if should_broadcast {
            self.core
                .strategy
                .lock()
                .unwrap()
                .trigger(TriggerEvent::ForwardingFailure);
        }
    }
}


impl<T: LinkMedium> DiscoveryProtocol for HelloProtocol<T> {
    fn protocol_id(&self) -> ProtocolId {
        self.medium.protocol_id()
    }

    fn claimed_prefixes(&self) -> &[Name] {
        &self.core.claimed
    }

    fn tick_interval(&self) -> Duration {
        self.core.config.read().unwrap().tick_interval
    }

    fn on_face_up(&self, face_id: FaceId, ctx: &dyn DiscoveryContext) {
        if self.medium.is_multicast_face(face_id) {
            let nonce = self.core.nonce_counter.fetch_add(1, Ordering::Relaxed);
            {
                let mut st = self.core.state.lock().unwrap();
                st.pending_probes.insert(nonce, Instant::now());
            }
            let hello = self.build_hello_interest(nonce);
            self.medium.send_multicast(ctx, hello);
            self.core
                .strategy
                .lock()
                .unwrap()
                .trigger(TriggerEvent::FaceUp);
            debug!(
                "{}: sent initial hello on face {face_id:?}",
                self.medium.protocol_id()
            );
        }
    }

    fn on_face_down(&self, face_id: FaceId, ctx: &dyn DiscoveryContext) {
        let mut st = self.core.state.lock().unwrap();
        self.medium.on_face_down(face_id, &mut st, ctx);
    }

    fn on_inbound(
        &self,
        raw: &Bytes,
        incoming_face: FaceId,
        meta: &InboundMeta,
        ctx: &dyn DiscoveryContext,
    ) -> bool {
        let swim_fanout = self.core.config.read().unwrap().swim_indirect_fanout;
        match raw.first() {
            Some(&0x05) => {
                if swim_fanout > 0
                    && let Some(parsed) = parse_raw_interest(raw)
                {
                    if parsed.name.has_prefix(probe_via()) {
                        return self.handle_via_probe_interest(raw, incoming_face, ctx);
                    }
                    if parsed.name.has_prefix(probe_direct()) {
                        return self.handle_direct_probe_interest(raw, incoming_face, ctx);
                    }
                }
                self.medium
                    .handle_hello_interest(raw, incoming_face, meta, &self.core, ctx)
            }
            Some(&0x06) => {
                if swim_fanout > 0 && is_probe_ack(raw) {
                    return self
                        .handle_probe_ack(raw, incoming_face, ctx)
                        .unwrap_or(false);
                }
                self.handle_hello_data(raw, incoming_face, meta, ctx)
            }
            _ => false,
        }
    }

    fn on_tick(&self, now: Instant, ctx: &dyn DiscoveryContext) {
        let protocol = self.medium.protocol_id();

        let (liveness_timeout, miss_limit, gossip_k, swim_k, probe_timeout) = {
            let cfg = self.core.config.read().unwrap();
            (
                cfg.liveness_timeout,
                cfg.liveness_miss_count,
                cfg.gossip_fanout as usize,
                cfg.swim_indirect_fanout as usize,
                cfg.probe_timeout,
            )
        };

        let probes = { self.core.strategy.lock().unwrap().on_tick(now) };
        for probe in probes {
            match probe {
                ProbeRequest::Broadcast => {
                    let nonce = self.core.nonce_counter.fetch_add(1, Ordering::Relaxed);
                    let hello = self.build_hello_interest(nonce);
                    self.medium.send_multicast(ctx, hello);
                    self.core
                        .state
                        .lock()
                        .unwrap()
                        .pending_probes
                        .insert(nonce, now);
                    debug!("{protocol}: broadcast hello (nonce={nonce:#010x})");
                }
                ProbeRequest::Unicast(face_id) => {
                    let nonce = self.core.nonce_counter.fetch_add(1, Ordering::Relaxed);
                    ctx.send_on(face_id, self.build_hello_interest(nonce));
                    self.core
                        .state
                        .lock()
                        .unwrap()
                        .pending_probes
                        .insert(nonce, now);
                    debug!("{protocol}: unicast hello on {face_id:?} (nonce={nonce:#010x})");
                }
            }
        }

        let all = ctx.neighbors().all();
        for entry in &all {
            match &entry.state {
                NeighborState::Established { last_seen } => {
                    if now.duration_since(*last_seen) > liveness_timeout {
                        ctx.update_neighbor(NeighborUpdate::SetState {
                            name: entry.node_name.clone(),
                            state: NeighborState::Stale {
                                miss_count: 1,
                                last_seen: *last_seen,
                            },
                        });
                        self.core
                            .strategy
                            .lock()
                            .unwrap()
                            .trigger(TriggerEvent::NeighborStale);
                        if let Some((face_id, _, _)) = entry.faces.first() {
                            let nonce = self.core.nonce_counter.fetch_add(1, Ordering::Relaxed);
                            ctx.send_on(*face_id, self.build_hello_interest(nonce));
                            self.core
                                .state
                                .lock()
                                .unwrap()
                                .pending_probes
                                .insert(nonce, now);
                        }
                        if gossip_k > 0 {
                            let stale_name = &entry.node_name;
                            let peers: Vec<FaceId> = all
                                .iter()
                                .filter(|e| e.is_reachable() && &e.node_name != stale_name)
                                .flat_map(|e| e.faces.iter().map(|(fid, _, _)| *fid))
                                .take(gossip_k)
                                .collect();
                            for face_id in peers {
                                let nonce = self.core.nonce_counter.fetch_add(1, Ordering::Relaxed);
                                ctx.send_on(face_id, self.build_hello_interest(nonce));
                                self.core
                                    .state
                                    .lock()
                                    .unwrap()
                                    .pending_probes
                                    .insert(nonce, now);
                            }
                        }
                    }
                }
                NeighborState::Stale {
                    miss_count,
                    last_seen,
                } => {
                    if u32::from(*miss_count) >= miss_limit {
                        info!(
                            peer = %entry.node_name, miss_count,
                            "{protocol}: peer unreachable, removing"
                        );
                        {
                            let mut st = self.core.state.lock().unwrap();
                            self.medium.on_peer_removed(entry, &mut st);
                            st.recent_diffs
                                .push_back(DiffEntry::Remove(entry.node_name.clone()));
                            while st.recent_diffs.len() > MAX_DIFF_ENTRIES {
                                st.recent_diffs.pop_front();
                            }
                        }
                        for (face_id, _, _) in &entry.faces {
                            ctx.remove_fib_entry(&entry.node_name, *face_id, protocol);
                            ctx.remove_face(*face_id);
                        }
                        ctx.update_neighbor(NeighborUpdate::Remove(entry.node_name.clone()));
                    } else if now.duration_since(*last_seen) > liveness_timeout {
                        ctx.update_neighbor(NeighborUpdate::SetState {
                            name: entry.node_name.clone(),
                            state: NeighborState::Stale {
                                miss_count: miss_count + 1,
                                last_seen: now,
                            },
                        });
                    }
                }
                _ => {}
            }
        }

        if swim_k > 0 {
            for entry in all.iter().filter(|e| e.is_reachable()) {
                if let Some((face_id, _, _)) = entry.faces.first() {
                    let nonce = self.core.nonce_counter.fetch_add(1, Ordering::Relaxed);
                    trace!(
                        peer = %entry.node_name, face = ?face_id, nonce,
                        "{protocol}: SWIM direct probe →"
                    );
                    ctx.send_on(*face_id, build_direct_probe(&entry.node_name, nonce));
                    self.core
                        .state
                        .lock()
                        .unwrap()
                        .swim_probes
                        .insert(nonce, (now, entry.node_name.clone()));
                }
            }
        }

        let mut timed_out = 0u32;
        {
            let mut st = self.core.state.lock().unwrap();
            st.pending_probes.retain(|_, sent| {
                if now.duration_since(*sent) >= probe_timeout {
                    timed_out += 1;
                    false
                } else {
                    true
                }
            });
        }
        if timed_out > 0 {
            let mut strategy = self.core.strategy.lock().unwrap();
            for _ in 0..timed_out {
                strategy.on_probe_timeout();
            }
        }

        if swim_k > 0 {
            let k = swim_k;
            let mut timed_out_swim: Vec<Name> = Vec::new();
            {
                let mut st = self.core.state.lock().unwrap();
                st.swim_probes.retain(|_, (sent, target)| {
                    if now.duration_since(*sent) >= probe_timeout {
                        timed_out_swim.push(target.clone());
                        false
                    } else {
                        true
                    }
                });
            }
            for target in timed_out_swim {
                let intermediaries: Vec<_> = ctx
                    .neighbors()
                    .all()
                    .into_iter()
                    .filter(|e| e.is_reachable() && e.node_name != target)
                    .take(k)
                    .collect();
                debug!(
                    peer = %target, via_count = intermediaries.len(),
                    "{protocol}: SWIM direct probe timed out, dispatching indirect probes"
                );
                for via in intermediaries {
                    let nonce = self.core.nonce_counter.fetch_add(1, Ordering::Relaxed);
                    if let Some((face_id, _, _)) = via.faces.first() {
                        ctx.send_on(
                            *face_id,
                            build_indirect_probe(&via.node_name, &target, nonce),
                        );
                    }
                }
                self.core.strategy.lock().unwrap().on_probe_timeout();
            }
        }
    }
}
