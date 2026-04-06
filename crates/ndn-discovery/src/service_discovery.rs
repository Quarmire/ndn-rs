//! `ServiceDiscoveryProtocol` — `/ndn/local/sd/services/` and `/ndn/local/nd/peers`.
//!
//! This protocol implementation handles two closely related discovery functions:
//!
//! ## 1. Service record publication and browsing
//!
//! Producers call [`ServiceDiscoveryProtocol::publish`] to register a
//! [`ServiceRecord`].  The protocol responds to incoming browse Interests
//! (`/ndn/local/sd/services/` with `CanBePrefix`) with Data packets for each
//! locally registered record.
//!
//! When an incoming service record Data arrives from a peer, the protocol
//! optionally auto-populates the FIB using the announced prefix (governed by
//! [`ServiceDiscoveryConfig::auto_populate_fib`] and related fields).
//!
//! ## 2. Demand-driven peer list (`/ndn/local/nd/peers`)
//!
//! Any node can express an Interest for `/ndn/local/nd/peers` to get a
//! snapshot of the current neighbor table.  The protocol responds with a Data
//! whose Content is a compact TLV list of neighbor names.
//!
//! ## Wire format — Peers response
//!
//! ```text
//! PeerList ::= (PEER-ENTRY TLV)*
//! PEER-ENTRY  ::= 0xE0 length Name
//! ```

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use bytes::Bytes;
use ndn_packet::{Name, encode::encode_interest, tlv_type};
use ndn_tlv::TlvWriter;
use ndn_transport::FaceId;
use tracing::{debug, info, trace, warn};

use crate::config::{DiscoveryScope, ServiceDiscoveryConfig, ServiceValidationPolicy};
use crate::context::DiscoveryContext;
use crate::prefix_announce::ServiceRecord;
use crate::protocol::{DiscoveryProtocol, InboundMeta, ProtocolId};
use crate::scope::{peers_prefix, sd_services};
use crate::wire::{parse_raw_data, parse_raw_interest, write_name_tlv, write_nni};

const PROTOCOL: ProtocolId = ProtocolId("service-discovery");

/// TLV type for a peer entry in the `/ndn/local/nd/peers` response.
const T_PEER_ENTRY: u64 = 0xE0;

/// Entry in the local service record table.
struct RecordEntry {
    record: ServiceRecord,
    /// Timestamp used for the Data version component.
    published_at_ms: u64,
}

/// An auto-populated FIB entry that must be expired after its TTL.
struct AutoFibEntry {
    prefix: Name,
    face_id: FaceId,
    expires_at: Instant,
}

/// Rate-limit tracker per producer name.
struct ProducerRateLimit {
    /// Count of registrations in the current window.
    count: u32,
    /// Start of the current window.
    window_start: Instant,
}

/// Service discovery and peer-list protocol.
///
/// Attach alongside [`UdpNeighborDiscovery`] or [`EtherNeighborDiscovery`] in
/// a [`CompositeDiscovery`] to enable service record publication/browsing and
/// demand-driven neighbor queries.
///
/// [`UdpNeighborDiscovery`]: crate::UdpNeighborDiscovery
/// [`CompositeDiscovery`]: crate::CompositeDiscovery
pub struct ServiceDiscoveryProtocol {
    /// This node's NDN name (used when building responses).
    node_name: Name,
    /// Service discovery configuration.
    config: ServiceDiscoveryConfig,
    /// Claimed name prefixes.
    claimed: Vec<Name>,
    /// Locally published service records.
    local_records: Mutex<Vec<RecordEntry>>,
    /// Service records received from remote peers.
    ///
    /// Populated by [`handle_sd_data`].  Deduplicated on
    /// `(announced_prefix, node_name)`: re-receiving a record updates it in-place.
    peer_records: Mutex<Vec<ServiceRecord>>,
    /// Per-producer rate-limit state.
    rate_limits: Mutex<HashMap<String, ProducerRateLimit>>,
    /// Auto-populated FIB entries pending TTL expiry.
    auto_fib: Mutex<Vec<AutoFibEntry>>,
    /// Timestamp of the last proactive browse broadcast to established neighbors.
    ///
    /// Used by `on_tick()` to throttle periodic re-browse so that runtime
    /// service announcements (e.g. ndn-iperf starting after neighbor
    /// establishment) propagate to peers within one browse interval.
    last_browse: Mutex<Option<Instant>>,
}

impl ServiceDiscoveryProtocol {
    /// Create a new `ServiceDiscoveryProtocol`.
    ///
    /// - `node_name`: this node's NDN name.
    /// - `config`: service discovery parameters.
    pub fn new(node_name: Name, config: ServiceDiscoveryConfig) -> Self {
        // Claimed prefixes: sd/services for service records, nd/peers for the
        // demand-driven neighbor list.  The nd/peers prefix is under nd_root,
        // not hello_prefix, so it doesn't conflict with hello traffic.
        let claimed = vec![
            sd_services().clone(),
            peers_prefix().clone(),
        ];
        Self {
            node_name,
            config,
            claimed,
            local_records: Mutex::new(Vec::new()),
            peer_records: Mutex::new(Vec::new()),
            rate_limits: Mutex::new(HashMap::new()),
            auto_fib: Mutex::new(Vec::new()),
            last_browse: Mutex::new(None),
        }
    }

    /// Create with the default [`ServiceDiscoveryConfig`].
    pub fn with_defaults(node_name: Name) -> Self {
        Self::new(node_name, ServiceDiscoveryConfig::default())
    }

    /// Publish a service record.
    ///
    /// Records are stored locally and served in response to browse Interests.
    /// Call this whenever the set of served prefixes changes.
    pub fn publish(&self, record: ServiceRecord) {
        let ts = current_timestamp_ms();
        let mut records = self.local_records.lock().unwrap();
        // Replace existing record for the same (prefix, node) pair.
        let existing = records.iter().position(|e| {
            e.record.announced_prefix == record.announced_prefix
                && e.record.node_name == record.node_name
        });
        info!(
            prefix = %record.announced_prefix,
            node   = %record.node_name,
            freshness_ms = record.freshness_ms,
            "service record published",
        );
        let entry = RecordEntry { record, published_at_ms: ts };
        if let Some(idx) = existing {
            records[idx] = entry;
        } else {
            records.push(entry);
        }
    }

    /// Withdraw a service record.
    pub fn withdraw(&self, announced_prefix: &Name) {
        let mut records = self.local_records.lock().unwrap();
        let before = records.len();
        records.retain(|e| &e.record.announced_prefix != announced_prefix);
        if records.len() < before {
            info!(prefix = %announced_prefix, "service record withdrawn");
        } else {
            debug!(prefix = %announced_prefix, "service record withdraw: prefix not found (no-op)");
        }
    }

    /// Return a snapshot of locally published service records.
    pub fn local_records(&self) -> Vec<ServiceRecord> {
        self.local_records
            .lock()
            .unwrap()
            .iter()
            .map(|e| e.record.clone())
            .collect()
    }

    /// Return a snapshot of all known service records — both local and
    /// records received from remote peers.
    ///
    /// Deduplicated: if the same `(announced_prefix, node_name)` pair appears
    /// in both tables, the local version takes precedence.
    pub fn all_records(&self) -> Vec<ServiceRecord> {
        let local = self.local_records.lock().unwrap();
        let peers = self.peer_records.lock().unwrap();

        let mut out: Vec<ServiceRecord> = local.iter().map(|e| e.record.clone()).collect();
        for pr in peers.iter() {
            let already = out.iter().any(|r| {
                r.announced_prefix == pr.announced_prefix && r.node_name == pr.node_name
            });
            if !already {
                out.push(pr.clone());
            }
        }
        out
    }

    // ── Inbound handlers ──────────────────────────────────────────────────────

    fn handle_sd_interest(
        &self,
        raw: &Bytes,
        incoming_face: FaceId,
        ctx: &dyn DiscoveryContext,
    ) -> bool {
        let parsed = match parse_raw_interest(raw) {
            Some(p) => p,
            None => return false,
        };

        let name = &parsed.name;
        if !name.has_prefix(sd_services()) {
            return false;
        }

        // Browse Interest: respond with all locally published records.
        let records = self.local_records.lock().unwrap();
        let mut responded = false;
        for entry in records.iter() {
            let pkt = entry.record.build_data(entry.published_at_ms);
            ctx.send_on(incoming_face, pkt);
            responded = true;
        }
        if responded {
            debug!("ServiceDiscovery: answered browse Interest with {} records", records.len());
        }
        true
    }

    fn handle_sd_data(
        &self,
        raw: &Bytes,
        incoming_face: FaceId,
        ctx: &dyn DiscoveryContext,
    ) -> bool {
        let parsed = match parse_raw_data(raw) {
            Some(d) => d,
            None => return false,
        };

        if !parsed.name.has_prefix(sd_services()) {
            return false;
        }

        let content = match parsed.content {
            Some(c) => c,
            None => return true, // no content, consume but ignore
        };

        let record = match ServiceRecord::decode(&content) {
            Some(r) => r,
            None => {
                debug!("ServiceDiscovery: could not decode ServiceRecord");
                return true;
            }
        };

        // Validation policy check.
        match self.config.validation {
            ServiceValidationPolicy::Skip => {}
            ServiceValidationPolicy::WarnOnly => {
                // In a real implementation, check the signature.  For now, log.
                debug!("ServiceDiscovery: received unvalidated record for {:?}", record.announced_prefix);
            }
            ServiceValidationPolicy::Required => {
                // Drop unsigned records (signature check not yet wired).
                warn!("ServiceDiscovery: dropping unvalidated record (Required policy)");
                return true;
            }
        }

        // Scope filter.
        if !self.is_in_scope(&record.announced_prefix) {
            debug!("ServiceDiscovery: record {:?} outside configured scope", record.announced_prefix);
            return true;
        }

        // Prefix filter.
        if !self.config.auto_populate_prefix_filter.is_empty() {
            let allowed = self.config.auto_populate_prefix_filter.iter()
                .any(|f| record.announced_prefix.has_prefix(f));
            if !allowed {
                return true;
            }
        }

        // Rate limit check.
        if !self.check_rate_limit(&record.node_name, ctx.now()) {
            debug!("ServiceDiscovery: rate-limiting producer {:?}", record.node_name);
            return true;
        }

        // Cache the peer record for browse queries.
        {
            let mut peer_recs = self.peer_records.lock().unwrap();
            if let Some(idx) = peer_recs.iter().position(|r| {
                r.announced_prefix == record.announced_prefix && r.node_name == record.node_name
            }) {
                peer_recs[idx] = record.clone();
            } else {
                peer_recs.push(record.clone());
            }
        }

        // Auto-populate FIB with TTL tracking.
        if self.config.auto_populate_fib {
            ctx.add_fib_entry(
                &record.announced_prefix,
                incoming_face,
                self.config.auto_fib_cost,
                PROTOCOL,
            );
            let ttl_ms = (record.freshness_ms as f64 * self.config.auto_fib_ttl_multiplier as f64) as u64;
            let expires_at = ctx.now() + Duration::from_millis(ttl_ms);
            {
                let mut auto_fib = self.auto_fib.lock().unwrap();
                // Replace any existing entry for the same prefix+face.
                auto_fib.retain(|e| !(e.prefix == record.announced_prefix && e.face_id == incoming_face));
                auto_fib.push(AutoFibEntry {
                    prefix: record.announced_prefix.clone(),
                    face_id: incoming_face,
                    expires_at,
                });
            }
            debug!(
                "ServiceDiscovery: auto-FIB {:?} via face {incoming_face:?} (cost {}, ttl {}ms)",
                record.announced_prefix, self.config.auto_fib_cost, ttl_ms
            );
        }

        // Relay service record to established neighbors when enabled.
        // Exclude the face the record arrived on to prevent loops.
        if self.config.relay_records {
            let relay_faces: Vec<FaceId> = ctx.neighbors().all().into_iter()
                .filter(|e| e.is_reachable())
                .flat_map(|e| e.faces.iter().map(|(fid, _, _)| *fid).collect::<Vec<_>>())
                .filter(|fid| *fid != incoming_face)
                .collect();
            let relay_count = relay_faces.len();
            for face_id in relay_faces {
                ctx.send_on(face_id, raw.clone());
            }
            if relay_count > 0 {
                debug!("ServiceDiscovery: relayed record {:?} to {relay_count} peers", record.announced_prefix);
            }
        }

        true
    }

    fn handle_peers_interest(
        &self,
        raw: &Bytes,
        incoming_face: FaceId,
        ctx: &dyn DiscoveryContext,
    ) -> bool {
        let parsed = match parse_raw_interest(raw) {
            Some(p) => p,
            None => return false,
        };

        if !parsed.name.has_prefix(peers_prefix()) {
            return false;
        }

        let peers_depth = peers_prefix().components().len();
        let extra_comps = parsed.name.components().len().saturating_sub(peers_depth);

        let peer_list = if extra_comps > 0 {
            // `/ndn/local/nd/peers/<node-name>` — single-peer query.
            // The node name follows the peers prefix; reconstruct it from the
            // extra components (everything after the prefix depth).
            let comps = parsed.name.components();
            let node_name_comps = &comps[peers_depth..];
            let mut uri = String::new();
            for comp in node_name_comps {
                uri.push('/');
                for byte in comp.value.iter() {
                    if byte.is_ascii_alphanumeric() || b"-.~_".contains(byte) {
                        uri.push(*byte as char);
                    } else {
                        uri.push_str(&format!("%{byte:02X}"));
                    }
                }
            }
            if uri.is_empty() { uri.push('/'); }
            let target = match std::str::FromStr::from_str(&uri) {
                Ok(n) => n,
                Err(_) => return true,
            };
            let entry = ctx.neighbors().get(&target);
            let mut w = TlvWriter::new();
            if let Some(e) = entry {
                if e.is_reachable() {
                    w.write_nested(T_PEER_ENTRY, |w: &mut TlvWriter| {
                        write_name_tlv(w, &e.node_name);
                    });
                }
            }
            let content = w.finish();
            debug!("ServiceDiscovery: answered single-peer query for {:?}", target);
            content
        } else {
            // `/ndn/local/nd/peers` — full peer list.
            let neighbors = ctx.neighbors().all();
            let mut w = TlvWriter::new();
            for entry in &neighbors {
                if entry.is_reachable() {
                    w.write_nested(T_PEER_ENTRY, |w: &mut TlvWriter| {
                        write_name_tlv(w, &entry.node_name);
                    });
                }
            }
            debug!("ServiceDiscovery: answered peers query with {} neighbors", neighbors.len());
            w.finish()
        };

        // Build a Data response at the exact Interest name.
        let data_name = &parsed.name;
        let mut dw = TlvWriter::new();
        dw.write_nested(tlv_type::DATA, |w: &mut TlvWriter| {
            write_name_tlv(w, data_name);
            w.write_nested(tlv_type::META_INFO, |w: &mut TlvWriter| {
                // FreshnessPeriod = 1 s (peer list changes frequently)
                write_nni(w, tlv_type::FRESHNESS_PERIOD, 1000);
            });
            w.write_tlv(tlv_type::CONTENT, &peer_list);
            w.write_nested(tlv_type::SIGNATURE_INFO, |w: &mut TlvWriter| {
                w.write_tlv(tlv_type::SIGNATURE_TYPE, &[0u8]);
            });
            w.write_tlv(tlv_type::SIGNATURE_VALUE, &[0u8; 32]);
        });

        ctx.send_on(incoming_face, dw.finish());
        true
    }

    // ── Browse helpers ────────────────────────────────────────────────────────

    /// Send a browse Interest on `face_id` to solicit service records from
    /// the peer on that face.  When the peer's SD protocol receives this
    /// Interest it will respond with its local records as Data packets;
    /// those are handled by [`handle_sd_data`] which auto-populates the FIB.
    fn send_browse_interest(&self, face_id: FaceId, ctx: &dyn DiscoveryContext) {
        let interest = encode_interest(sd_services(), None);
        ctx.send_on(face_id, interest);
        trace!(face = ?face_id, "ServiceDiscovery: sent browse Interest");
    }

    /// Send browse Interests to every face of every established neighbor.
    /// Records `now` as the last-browse timestamp to throttle calls from
    /// `on_tick()`.
    fn browse_all_neighbors(&self, now: Instant, ctx: &dyn DiscoveryContext) {
        let neighbors = ctx.neighbors().all();
        let mut count = 0usize;
        for entry in &neighbors {
            if entry.is_reachable() {
                for (face_id, _, _) in &entry.faces {
                    self.send_browse_interest(*face_id, ctx);
                    count += 1;
                }
            }
        }
        *self.last_browse.lock().unwrap() = Some(now);
        if count > 0 {
            debug!(peers = count, "ServiceDiscovery: browse refresh sent to established neighbors");
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn is_in_scope(&self, _prefix: &Name) -> bool {
        match self.config.auto_populate_scope {
            DiscoveryScope::LinkLocal => {
                // Accept anything under /ndn/local/ or /ndn/site/ for backwards compat
                true
            }
            DiscoveryScope::Site => true,
            DiscoveryScope::Global => true,
        }
    }

    fn check_rate_limit(&self, producer: &Name, now: Instant) -> bool {
        let key = producer.to_string();
        let window = self.config.max_registrations_window;
        let limit = self.config.max_registrations_per_producer;

        let mut limits = self.rate_limits.lock().unwrap();
        let entry = limits.entry(key).or_insert_with(|| ProducerRateLimit {
            count: 0,
            window_start: now,
        });

        if now.duration_since(entry.window_start) >= window {
            // New window.
            entry.count = 1;
            entry.window_start = now;
            true
        } else if entry.count < limit {
            entry.count += 1;
            true
        } else {
            false
        }
    }
}

/// Decode a `PeerList` Data Content into a `Vec<Name>`.
///
/// Used by consumers of the `/ndn/local/nd/peers` response.
pub fn decode_peer_list(content: &[u8]) -> Vec<Name> {
    let mut peers = Vec::new();
    let mut pos = 0;
    while pos < content.len() {
        let Some((typ, len, hl)) = read_tlv_header(content, pos) else { break };
        let val = &content[pos + hl..pos + hl + len];
        if typ == T_PEER_ENTRY as u32 {
            if let Some(name) = decode_name_tlv(val) {
                peers.push(name);
            }
        }
        pos += hl + len;
    }
    peers
}

// ── DiscoveryProtocol impl ────────────────────────────────────────────────────

impl DiscoveryProtocol for ServiceDiscoveryProtocol {
    fn protocol_id(&self) -> ProtocolId { PROTOCOL }

    fn claimed_prefixes(&self) -> &[Name] { &self.claimed }

    fn on_face_up(&self, face_id: FaceId, ctx: &dyn DiscoveryContext) {
        // Immediately probe the peer for its service records.  The peer's SD
        // protocol will respond with its local records as Data packets, which
        // handle_sd_data() will pick up to auto-populate our FIB.
        self.send_browse_interest(face_id, ctx);
    }

    fn on_face_down(&self, _face_id: FaceId, _ctx: &dyn DiscoveryContext) {
        // Remove all auto-populated FIB entries for the face that went down.
        // We can't easily know which entries belong to the downed face without
        // iterating, so we rely on the engine's face-removal housekeeping.
        // The `remove_fib_entries_by_owner` is too broad here (removes all SD
        // routes, not just the downed face).
    }

    fn on_inbound(
        &self,
        raw: &Bytes,
        incoming_face: FaceId,
        _meta: &InboundMeta,
        ctx: &dyn DiscoveryContext,
    ) -> bool {
        if raw.is_empty() {
            return false;
        }
        match raw.first() {
            Some(&0x05) => {
                // Interest
                if self.handle_sd_interest(raw, incoming_face, ctx) {
                    return true;
                }
                self.handle_peers_interest(raw, incoming_face, ctx)
            }
            Some(&0x06) => {
                // Data
                self.handle_sd_data(raw, incoming_face, ctx)
            }
            _ => false,
        }
    }

    fn on_tick(&self, now: Instant, ctx: &dyn DiscoveryContext) {
        // Expire auto-populated FIB entries past their TTL.
        let mut expired: Vec<(Name, FaceId)> = Vec::new();
        {
            let mut auto_fib = self.auto_fib.lock().unwrap();
            auto_fib.retain(|e| {
                if now >= e.expires_at {
                    expired.push((e.prefix.clone(), e.face_id));
                    false
                } else {
                    true
                }
            });
        }
        for (prefix, face_id) in expired {
            ctx.remove_fib_entry(&prefix, face_id, PROTOCOL);
            debug!("ServiceDiscovery: expired auto-FIB {:?} via {face_id:?}", prefix);
        }

        // Periodically re-browse all established neighbors so that runtime
        // service announcements (e.g. ndn-iperf starting after neighbor
        // establishment) are discovered without waiting for a face event.
        // The interval is derived from the auto-FIB TTL: half the minimum
        // freshness period guarantees records are refreshed before they expire.
        // Floor: 10 s (avoid hammering on fast-tick profiles).
        const BROWSE_FLOOR: Duration = Duration::from_secs(10);
        let browse_interval = {
            let auto_fib = self.auto_fib.lock().unwrap();
            auto_fib.iter()
                .map(|e| e.expires_at.saturating_duration_since(now) / 2)
                .min()
                .unwrap_or(Duration::from_secs(30))
                .max(BROWSE_FLOOR)
        };

        let due = self.last_browse.lock().unwrap()
            .map_or(true, |t| now.duration_since(t) >= browse_interval);

        if due {
            self.browse_all_neighbors(now, ctx);
        }
    }
}

// ── Wire helpers ──────────────────────────────────────────────────────────────

fn read_tlv_header(b: &[u8], pos: usize) -> Option<(u32, usize, usize)> {
    if pos >= b.len() {
        return None;
    }
    let (typ, t_len) = read_varnumber(b, pos)?;
    let (len, l_len) = read_varnumber(b, pos + t_len)?;
    Some((typ as u32, len as usize, t_len + l_len))
}

fn read_varnumber(b: &[u8], pos: usize) -> Option<(u64, usize)> {
    let first = *b.get(pos)?;
    match first {
        0xFD => {
            let hi = *b.get(pos + 1)? as u64;
            let lo = *b.get(pos + 2)? as u64;
            Some(((hi << 8) | lo, 3))
        }
        0xFE => {
            let v = u32::from_be_bytes(b[pos + 1..pos + 5].try_into().ok()?);
            Some((v as u64, 5))
        }
        0xFF => {
            let v = u64::from_be_bytes(b[pos + 1..pos + 9].try_into().ok()?);
            Some((v, 9))
        }
        _ => Some((first as u64, 1)),
    }
}

fn decode_name_tlv(b: &[u8]) -> Option<Name> {
    // b is the value of a T_PEER_ENTRY, which is a Name TLV (type 0x07).
    if b.is_empty() || b[0] != 0x07 {
        return None;
    }
    use ndn_packet::NameComponent;
    let (_, len, hl) = read_tlv_header(b, 0)?;
    let comps_bytes = &b[hl..hl + len];
    let mut comps = Vec::new();
    let mut pos = 0;
    while pos < comps_bytes.len() {
        let (typ, clen, chl) = read_tlv_header(comps_bytes, pos)?;
        let val = comps_bytes[pos + chl..pos + chl + clen].to_vec();
        comps.push(NameComponent { typ: typ as u64, value: val.into() });
        pos += chl + clen;
    }
    if comps.is_empty() {
        return Some(Name::root());
    }
    // Build canonical URI to re-parse.
    let mut uri = String::new();
    for comp in &comps {
        uri.push('/');
        for byte in comp.value.iter() {
            if byte.is_ascii_alphanumeric() || b"-.~_".contains(byte) {
                uri.push(*byte as char);
            } else {
                uri.push_str(&format!("%{byte:02X}"));
            }
        }
    }
    if uri.is_empty() { uri.push('/'); }
    use std::str::FromStr;
    Name::from_str(&uri).ok()
}

fn current_timestamp_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::sync::Arc;

    use super::*;
    use crate::{NeighborEntry, NeighborState, NeighborTable, NeighborUpdate, NeighborTableView, MacAddr};
    use crate::neighbor::NeighborTable as NT;

    fn name(s: &str) -> Name { Name::from_str(s).unwrap() }

    fn make_sd() -> ServiceDiscoveryProtocol {
        ServiceDiscoveryProtocol::with_defaults(name("/ndn/test/node"))
    }

    #[test]
    fn publish_and_withdraw() {
        let sd = make_sd();
        let rec = ServiceRecord::new(name("/ndn/sensor/temp"), name("/ndn/test/node"));
        sd.publish(rec);
        {
            let records = sd.local_records.lock().unwrap();
            assert_eq!(records.len(), 1);
        }
        sd.withdraw(&name("/ndn/sensor/temp"));
        {
            let records = sd.local_records.lock().unwrap();
            assert!(records.is_empty());
        }
    }

    #[test]
    fn publish_replaces_existing() {
        let sd = make_sd();
        let rec1 = ServiceRecord {
            announced_prefix: name("/ndn/sensor/temp"),
            node_name: name("/ndn/test/node"),
            freshness_ms: 30_000,
            capabilities: 0,
        };
        let mut rec2 = rec1.clone();
        rec2.freshness_ms = 60_000;
        sd.publish(rec1);
        sd.publish(rec2);
        let records = sd.local_records.lock().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].record.freshness_ms, 60_000);
    }

    #[test]
    fn claimed_prefixes_includes_sd_and_peers() {
        let sd = make_sd();
        let claimed = sd.claimed_prefixes();
        assert!(claimed.iter().any(|p| p.has_prefix(sd_services())));
        assert!(claimed.iter().any(|p| p == peers_prefix()));
    }

    #[test]
    fn decode_peer_list_roundtrip() {
        let mut w = TlvWriter::new();
        let n1 = name("/ndn/test/peer1");
        let n2 = name("/ndn/test/peer2");
        w.write_nested(T_PEER_ENTRY, |w: &mut TlvWriter| { write_name_tlv(w, &n1); });
        w.write_nested(T_PEER_ENTRY, |w: &mut TlvWriter| { write_name_tlv(w, &n2); });
        let content = w.finish();
        let decoded = decode_peer_list(&content);
        assert_eq!(decoded.len(), 2);
    }

    #[test]
    fn auto_fib_ttl_expiry_on_tick() {
        use crate::context::DiscoveryContext;
        use crate::{NeighborTableView, NeighborUpdate};
        use std::sync::{Arc, Mutex as StdMutex};

        struct TrackCtx {
            now: Instant,
            removed: StdMutex<Vec<Name>>,
        }
        impl DiscoveryContext for TrackCtx {
            fn alloc_face_id(&self) -> FaceId { FaceId(0) }
            fn add_face(&self, _: Arc<dyn ndn_transport::ErasedFace>) -> FaceId { FaceId(0) }
            fn remove_face(&self, _: FaceId) {}
            fn add_fib_entry(&self, _: &Name, _: FaceId, _: u32, _: ProtocolId) {}
            fn remove_fib_entry(&self, prefix: &Name, _: FaceId, _: ProtocolId) {
                self.removed.lock().unwrap().push(prefix.clone());
            }
            fn remove_fib_entries_by_owner(&self, _: ProtocolId) {}
            fn neighbors(&self) -> Arc<dyn NeighborTableView> { NeighborTable::new() }
            fn update_neighbor(&self, _: NeighborUpdate) {}
            fn send_on(&self, _: FaceId, _: Bytes) {}
            fn now(&self) -> Instant { self.now }
        }

        let sd = make_sd();
        let now = Instant::now();
        let ctx = TrackCtx {
            now,
            removed: StdMutex::new(Vec::new()),
        };

        // Manually insert an already-expired auto-FIB entry.
        {
            let mut af = sd.auto_fib.lock().unwrap();
            af.push(AutoFibEntry {
                prefix: name("/ndn/sensor/temp"),
                face_id: FaceId(7),
                expires_at: now - Duration::from_millis(1),
            });
        }

        sd.on_tick(now, &ctx);
        let removed = ctx.removed.lock().unwrap();
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0], name("/ndn/sensor/temp"));
        assert!(sd.auto_fib.lock().unwrap().is_empty());
    }

    #[test]
    fn relay_records_sends_to_other_peers() {
        use crate::context::DiscoveryContext;
        use crate::{NeighborTableView, NeighborUpdate, NeighborEntry, NeighborState, NeighborTable};
        use std::sync::{Arc, Mutex as StdMutex};

        struct RelayCtx {
            neighbors: Arc<NeighborTable>,
            sent: StdMutex<Vec<(FaceId, Bytes)>>,
        }
        impl DiscoveryContext for RelayCtx {
            fn alloc_face_id(&self) -> FaceId { FaceId(99) }
            fn add_face(&self, _: Arc<dyn ndn_transport::ErasedFace>) -> FaceId { FaceId(99) }
            fn remove_face(&self, _: FaceId) {}
            fn add_fib_entry(&self, _: &Name, _: FaceId, _: u32, _: ProtocolId) {}
            fn remove_fib_entry(&self, _: &Name, _: FaceId, _: ProtocolId) {}
            fn remove_fib_entries_by_owner(&self, _: ProtocolId) {}
            fn neighbors(&self) -> Arc<dyn NeighborTableView> { Arc::clone(&self.neighbors) as Arc<dyn NeighborTableView> }
            fn update_neighbor(&self, u: NeighborUpdate) { self.neighbors.apply(u); }
            fn send_on(&self, face_id: FaceId, pkt: Bytes) {
                self.sent.lock().unwrap().push((face_id, pkt));
            }
            fn now(&self) -> Instant { Instant::now() }
        }

        let mut cfg = ServiceDiscoveryConfig::default();
        cfg.relay_records = true;
        cfg.auto_populate_fib = false; // keep test focused on relay only
        let sd = ServiceDiscoveryProtocol::new(name("/ndn/test/node"), cfg);

        let neighbors = NeighborTable::new();
        // Add two reachable neighbors with different faces.
        let mut e1 = NeighborEntry::new(name("/ndn/peer/a"));
        e1.state = NeighborState::Established { last_seen: Instant::now() };
        e1.faces = vec![(FaceId(10), MacAddr([0u8;6]), "eth0".into())];
        let mut e2 = NeighborEntry::new(name("/ndn/peer/b"));
        e2.state = NeighborState::Established { last_seen: Instant::now() };
        e2.faces = vec![(FaceId(20), MacAddr([0u8;6]), "eth0".into())];
        neighbors.apply(NeighborUpdate::Upsert(e1));
        neighbors.apply(NeighborUpdate::Upsert(e2));

        let ctx = RelayCtx { neighbors, sent: StdMutex::new(Vec::new()) };

        // Build a valid service record Data packet arriving on face 10.
        let rec = ServiceRecord { announced_prefix: name("/ndn/sensor/temp"), node_name: name("/ndn/peer/a"), freshness_ms: 10_000, capabilities: 0 };
        let pkt = rec.build_data(1000);

        sd.on_inbound(&pkt, FaceId(10), &crate::InboundMeta::none(), &ctx);

        let sent = ctx.sent.lock().unwrap();
        // Should relay to face 20 (peer/b), not back to face 10 (source).
        assert!(sent.iter().any(|(fid, _)| *fid == FaceId(20)), "should relay to peer/b");
        assert!(!sent.iter().any(|(fid, _)| *fid == FaceId(10)), "must not relay back to source face");
    }
}
