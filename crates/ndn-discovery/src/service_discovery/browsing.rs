//! Interest handling for service browsing, response encoding, and peer list.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use bytes::Bytes;
use ndn_packet::{Name, encode::encode_interest, tlv_type};
use ndn_tlv::TlvWriter;
use ndn_transport::FaceId;
use tracing::{debug, trace, warn};

use crate::config::ServiceValidationPolicy;
use crate::context::DiscoveryContext;
use crate::prefix_announce::ServiceRecord;
use crate::scope::{peers_prefix, sd_services};
use crate::wire::{parse_raw_data, parse_raw_interest, write_name_tlv, write_nni};

use super::ServiceDiscoveryProtocol;

/// TLV type for a peer entry in the `/ndn/local/nd/peers` response.
const T_PEER_ENTRY: u64 = 0xE0;

impl ServiceDiscoveryProtocol {
    // ── Inbound handlers ──────────────────────────────────────────────────────

    pub(super) fn handle_sd_interest(
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
            debug!(
                "ServiceDiscovery: answered browse Interest with {} records",
                records.len()
            );
        }
        true
    }

    pub(super) fn handle_sd_data(
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
                debug!(
                    "ServiceDiscovery: received unvalidated record for {:?}",
                    record.announced_prefix
                );
            }
            ServiceValidationPolicy::Required => {
                // Drop unsigned records (signature check not yet wired).
                warn!("ServiceDiscovery: dropping unvalidated record (Required policy)");
                return true;
            }
        }

        // Scope filter.
        if !self.is_in_scope(&record.announced_prefix) {
            debug!(
                "ServiceDiscovery: record {:?} outside configured scope",
                record.announced_prefix
            );
            return true;
        }

        // Prefix filter.
        if !self.config.auto_populate_prefix_filter.is_empty() {
            let allowed = self
                .config
                .auto_populate_prefix_filter
                .iter()
                .any(|f| record.announced_prefix.has_prefix(f));
            if !allowed {
                return true;
            }
        }

        // Rate limit check.
        if !self.check_rate_limit(&record.node_name, ctx.now()) {
            debug!(
                "ServiceDiscovery: rate-limiting producer {:?}",
                record.node_name
            );
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
        //
        // Use the producer's unicast face rather than incoming_face.  Browse
        // responses arrive on the multicast face (because the remote sends
        // them back via its own multicast face), and routing data traffic over
        // the multicast face broadcasts every Interest to all peers.  The
        // correct nexthop is the unicast face we have for the producer.
        if self.config.auto_populate_fib {
            self.auto_populate_fib(&record, incoming_face, ctx);
        }

        // Relay service record to established neighbors when enabled.
        // Exclude the face the record arrived on to prevent loops.
        if self.config.relay_records {
            let relay_faces: Vec<FaceId> = ctx
                .neighbors()
                .all()
                .into_iter()
                .filter(|e| e.is_reachable())
                .flat_map(|e| e.faces.iter().map(|(fid, _, _)| *fid).collect::<Vec<_>>())
                .filter(|fid| *fid != incoming_face)
                .collect();
            let relay_count = relay_faces.len();
            for face_id in relay_faces {
                ctx.send_on(face_id, raw.clone());
            }
            if relay_count > 0 {
                debug!(
                    "ServiceDiscovery: relayed record {:?} to {relay_count} peers",
                    record.announced_prefix
                );
            }
        }

        true
    }

    pub(super) fn handle_peers_interest(
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
            if uri.is_empty() {
                uri.push('/');
            }
            let target = match std::str::FromStr::from_str(&uri) {
                Ok(n) => n,
                Err(_) => return true,
            };
            let entry = ctx.neighbors().get(&target);
            let mut w = TlvWriter::new();
            if let Some(e) = entry
                && e.is_reachable()
            {
                w.write_nested(T_PEER_ENTRY, |w: &mut TlvWriter| {
                    write_name_tlv(w, &e.node_name);
                });
            }
            let content = w.finish();
            debug!(
                "ServiceDiscovery: answered single-peer query for {:?}",
                target
            );
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
            debug!(
                "ServiceDiscovery: answered peers query with {} neighbors",
                neighbors.len()
            );
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
    pub(super) fn send_browse_interest(&self, face_id: FaceId, ctx: &dyn DiscoveryContext) {
        let interest = encode_interest(sd_services(), None);
        ctx.send_on(face_id, interest);
        trace!(face = ?face_id, "ServiceDiscovery: sent browse Interest");
    }

    /// Browse established neighbors, distinguishing two cases:
    ///
    /// - **Newly established** (not yet in `browsed_neighbors`): browse
    ///   immediately regardless of the periodic interval.
    /// - **Already browsed**: re-browse only if `browse_interval` has elapsed
    ///   since `last_browse`.
    ///
    /// Using the neighbor table (not raw face IDs) ensures that management
    /// and app faces are never sent unsolicited browse Interests.
    pub(super) fn browse_neighbors(
        &self,
        now: Instant,
        browse_interval: Duration,
        ctx: &dyn DiscoveryContext,
    ) {
        let neighbors = ctx.neighbors().all();
        let mut seen = self.browsed_neighbors.lock().unwrap();
        let periodic_due = self
            .last_browse
            .lock()
            .unwrap()
            .is_none_or(|t| now.duration_since(t) >= browse_interval);

        let mut new_count = 0usize;
        let mut refresh_count = 0usize;

        for entry in &neighbors {
            if !entry.is_reachable() {
                continue;
            }
            let is_new = seen.insert(entry.node_name.clone());
            if is_new {
                // First time we see this neighbor as Established — browse now.
                for (face_id, _, _) in &entry.faces {
                    self.send_browse_interest(*face_id, ctx);
                }
                new_count += 1;
            } else if periodic_due {
                // Periodic refresh for already-known neighbors.
                for (face_id, _, _) in &entry.faces {
                    self.send_browse_interest(*face_id, ctx);
                }
                refresh_count += 1;
            }
        }

        if periodic_due {
            *self.last_browse.lock().unwrap() = Some(now);
        }
        if new_count > 0 {
            debug!(
                peers = new_count,
                "ServiceDiscovery: initial browse sent to new neighbors"
            );
        }
        if refresh_count > 0 {
            debug!(
                peers = refresh_count,
                "ServiceDiscovery: periodic browse refresh sent"
            );
        }

        // Prune departed neighbors from the seen set so they get a fresh
        // initial browse if they reconnect later.
        let active: HashSet<Name> = neighbors
            .iter()
            .filter(|e| e.is_reachable())
            .map(|e| e.node_name.clone())
            .collect();
        seen.retain(|n| active.contains(n));
    }
}

// ── Wire helpers ──────────────────────────────────────────────────────────────

/// Decode a `PeerList` Data Content into a `Vec<Name>`.
///
/// Used by consumers of the `/ndn/local/nd/peers` response.
pub fn decode_peer_list(content: &[u8]) -> Vec<Name> {
    let mut peers = Vec::new();
    let mut pos = 0;
    while pos < content.len() {
        let Some((typ, len, hl)) = read_tlv_header(content, pos) else {
            break;
        };
        let val = &content[pos + hl..pos + hl + len];
        if typ == T_PEER_ENTRY as u32
            && let Some(name) = decode_name_tlv(val)
        {
            peers.push(name);
        }
        pos += hl + len;
    }
    peers
}

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
        comps.push(NameComponent {
            typ: typ as u64,
            value: val.into(),
        });
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
    if uri.is_empty() {
        uri.push('/');
    }
    use std::str::FromStr;
    Name::from_str(&uri).ok()
}
