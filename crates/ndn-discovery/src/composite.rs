//! `CompositeDiscovery` — runs multiple protocols simultaneously.
//!
//! Validates at construction time that no two protocols claim overlapping name
//! prefixes, then routes inbound packets to the correct protocol by prefix
//! match.  Face lifecycle hooks are delivered to all protocols in registration
//! order.

use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use ndn_packet::Name;
use ndn_transport::FaceId;

use crate::{DiscoveryContext, DiscoveryProtocol, InboundMeta, ProtocolId};

/// Wrapper that runs multiple [`DiscoveryProtocol`] implementations in parallel.
///
/// # Namespace safety
///
/// [`CompositeDiscovery::new`] returns an error if any two protocols claim
/// overlapping name prefixes (one is a prefix of the other).  Each protocol
/// must use a distinct sub-tree of `/ndn/local/`.
///
/// # Inbound routing
///
/// When a raw packet arrives, `CompositeDiscovery` tries to parse its top-level
/// NDN name and routes it to the first protocol whose `claimed_prefixes` contains
/// a matching prefix.  If the name cannot be parsed or no protocol matches, the
/// packet is not consumed (returns `false`).
///
/// # Tick delivery
///
/// All protocols receive every `on_tick` call.  Order is not guaranteed.
pub struct CompositeDiscovery {
    protocols: Vec<Arc<dyn DiscoveryProtocol>>,
}

impl CompositeDiscovery {
    /// Construct a composite from a list of protocols.
    ///
    /// Returns `Err` with a human-readable message if any two protocols claim
    /// overlapping prefixes.
    pub fn new(protocols: Vec<Arc<dyn DiscoveryProtocol>>) -> Result<Self, String> {
        // Collect all (prefix, protocol_id) pairs and check for overlaps.
        let mut all_prefixes: Vec<(Name, ProtocolId)> = Vec::new();
        for proto in &protocols {
            for prefix in proto.claimed_prefixes() {
                // Check against all previously registered prefixes.
                for (existing, existing_id) in &all_prefixes {
                    if prefixes_overlap(existing, prefix) {
                        return Err(format!(
                            "protocol '{}' prefix '{}' overlaps with protocol '{}' prefix '{}'",
                            proto.protocol_id(),
                            prefix,
                            existing_id,
                            existing,
                        ));
                    }
                }
                all_prefixes.push((prefix.clone(), proto.protocol_id()));
            }
        }
        Ok(Self { protocols })
    }

    /// Number of contained protocols.
    pub fn len(&self) -> usize {
        self.protocols.len()
    }

    pub fn is_empty(&self) -> bool {
        self.protocols.is_empty()
    }

    /// Collect all prefixes claimed by any child protocol.
    ///
    /// Unlike `claimed_prefixes()` (which returns the composite's own
    /// top-level claims), this method flattens the claims of all children.
    /// Use this to enumerate the full set of prefixes owned by the discovery
    /// stack (e.g. for management security enforcement).
    pub fn all_claimed_prefixes(&self) -> Vec<Name> {
        self.protocols
            .iter()
            .flat_map(|p| p.claimed_prefixes().iter().cloned())
            .collect()
    }
}

impl DiscoveryProtocol for CompositeDiscovery {
    fn protocol_id(&self) -> ProtocolId {
        ProtocolId("composite")
    }

    fn claimed_prefixes(&self) -> &[Name] {
        // CompositeDiscovery doesn't claim additional prefixes beyond
        // what its children claim — return empty here since children
        // are already registered and checked.
        &[]
    }

    fn on_face_up(&self, face_id: FaceId, ctx: &dyn DiscoveryContext) {
        for proto in &self.protocols {
            proto.on_face_up(face_id, ctx);
        }
    }

    fn on_face_down(&self, face_id: FaceId, ctx: &dyn DiscoveryContext) {
        for proto in &self.protocols {
            proto.on_face_down(face_id, ctx);
        }
    }

    fn on_inbound(
        &self,
        raw: &Bytes,
        incoming_face: FaceId,
        meta: &InboundMeta,
        ctx: &dyn DiscoveryContext,
    ) -> bool {
        // Try to parse the packet name for prefix-based routing.
        if let Some(name) = parse_first_name(raw) {
            for proto in &self.protocols {
                for prefix in proto.claimed_prefixes() {
                    if name.has_prefix(prefix) {
                        return proto.on_inbound(raw, incoming_face, meta, ctx);
                    }
                }
            }
            // Name parsed but no protocol claimed it — not consumed.
            return false;
        }

        // Name parse failed — try all protocols in order (fallback).
        for proto in &self.protocols {
            if proto.on_inbound(raw, incoming_face, meta, ctx) {
                return true;
            }
        }
        false
    }

    fn on_tick(&self, now: Instant, ctx: &dyn DiscoveryContext) {
        for proto in &self.protocols {
            proto.on_tick(now, ctx);
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Returns true if `a` is a prefix of `b` or vice-versa (i.e. they overlap
/// in the name tree).
fn prefixes_overlap(a: &Name, b: &Name) -> bool {
    b.has_prefix(a) || a.has_prefix(b)
}

/// Try to parse the first NDN name out of a raw TLV packet.
///
/// NDN packet TLV: Interest (0x05) or Data (0x06), then a Name TLV (0x07)
/// immediately as the first child.  This does a minimal parse — just enough
/// to route the packet; full decode happens in the pipeline.
fn parse_first_name(raw: &Bytes) -> Option<Name> {
    // Require at least a 2-byte TLV header.
    if raw.len() < 4 {
        return None;
    }
    let pkt_type = raw[0];
    if pkt_type != 0x05 && pkt_type != 0x06 {
        return None; // Not an Interest or Data
    }
    // Skip packet type + length (variable-length varint).
    let (_, inner) = skip_tlv_header(raw)?;
    // First child should be a Name TLV (type 0x07).
    if inner.is_empty() || inner[0] != 0x07 {
        return None;
    }
    // inner begins with the Name TLV; skip its type+length to get just the
    // component bytes that Name::decode expects.
    let (_, name_value) = skip_tlv_header(inner)?;
    let name_bytes = bytes::Bytes::copy_from_slice(name_value);
    Name::decode(name_bytes).ok()
}

/// Skip a TLV type+length prefix, returning a slice of the value bytes.
/// Returns `(type, value_bytes)` or `None` on truncation.
fn skip_tlv_header(buf: &[u8]) -> Option<(u8, &[u8])> {
    if buf.is_empty() {
        return None;
    }
    let t = buf[0];
    let (len, hdr_size) = read_varu(buf.get(1..)?)?;
    let end = 1 + hdr_size + len;
    Some((t, buf.get(1 + hdr_size..end)?))
}

/// Read a minimal NDN TLV varint.  Returns `(value, bytes_consumed)`.
fn read_varu(buf: &[u8]) -> Option<(usize, usize)> {
    match buf.first()? {
        b if *b < 253 => Some((*b as usize, 1)),
        253 => {
            let hi = *buf.get(1)? as usize;
            let lo = *buf.get(2)? as usize;
            Some(((hi << 8) | lo, 3))
        }
        254 => {
            let b1 = *buf.get(1)? as usize;
            let b2 = *buf.get(2)? as usize;
            let b3 = *buf.get(3)? as usize;
            let b4 = *buf.get(4)? as usize;
            Some(((b1 << 24) | (b2 << 16) | (b3 << 8) | b4, 5))
        }
        _ => None, // 8-byte form not needed for discovery packets
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use std::sync::atomic::{AtomicBool, Ordering};
    use crate::{DiscoveryContext, InboundMeta, NeighborTable, NeighborTableView, NeighborUpdate, NoDiscovery, ProtocolId};

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// Build a minimal, parseable Interest TLV for `name`.
    ///
    /// Wire: `0x05 <len> 0x07 <name_len> <components...>`
    fn minimal_interest(name: &Name) -> Bytes {
        use ndn_tlv::TlvWriter;
        let mut w = TlvWriter::new();
        w.write_nested(0x05u64, |w: &mut TlvWriter| {
            w.write_nested(0x07u64, |w: &mut TlvWriter| {
                for comp in name.components() {
                    w.write_tlv(comp.typ, &comp.value);
                }
            });
        });
        w.finish()
    }

    struct MockProto {
        id: ProtocolId,
        prefixes: Vec<Name>,
        called: AtomicBool,
    }

    impl MockProto {
        fn new(id: &'static str, prefix: &str) -> Arc<Self> {
            Arc::new(Self {
                id: ProtocolId(id),
                prefixes: vec![Name::from_str(prefix).unwrap()],
                called: AtomicBool::new(false),
            })
        }
    }

    impl DiscoveryProtocol for MockProto {
        fn protocol_id(&self) -> ProtocolId { self.id }
        fn claimed_prefixes(&self) -> &[Name] { &self.prefixes }
        fn on_face_up(&self, _: FaceId, _: &dyn DiscoveryContext) {}
        fn on_face_down(&self, _: FaceId, _: &dyn DiscoveryContext) {}
        fn on_inbound(&self, _: &Bytes, _: FaceId, _: &InboundMeta, _: &dyn DiscoveryContext) -> bool {
            self.called.store(true, Ordering::SeqCst);
            true
        }
        fn on_tick(&self, _: Instant, _: &dyn DiscoveryContext) {}
    }

    struct NullCtx;

    impl DiscoveryContext for NullCtx {
        fn alloc_face_id(&self) -> FaceId { FaceId(0) }
        fn add_face(&self, _: Arc<dyn ndn_transport::ErasedFace>) -> FaceId { FaceId(0) }
        fn remove_face(&self, _: FaceId) {}
        fn add_fib_entry(&self, _: &Name, _: FaceId, _: u32, _: ProtocolId) {}
        fn remove_fib_entry(&self, _: &Name, _: FaceId, _: ProtocolId) {}
        fn remove_fib_entries_by_owner(&self, _: ProtocolId) {}
        fn neighbors(&self) -> Arc<dyn NeighborTableView> { NeighborTable::new() }
        fn update_neighbor(&self, _: NeighborUpdate) {}
        fn send_on(&self, _: FaceId, _: Bytes) {}
        fn now(&self) -> Instant { Instant::now() }
    }

    // ── Construction tests ────────────────────────────────────────────────────

    #[test]
    fn no_overlap_is_ok() {
        let p1 = MockProto::new("nd", "/ndn/local/nd");
        let p2 = MockProto::new("sd", "/ndn/local/sd");
        assert!(CompositeDiscovery::new(vec![p1, p2]).is_ok());
    }

    #[test]
    fn overlap_is_rejected() {
        let p1 = MockProto::new("nd", "/ndn/local/nd");
        // /ndn/local/nd/hello is a sub-prefix of /ndn/local/nd → overlap
        let p2 = MockProto::new("nd2", "/ndn/local/nd/hello");
        assert!(CompositeDiscovery::new(vec![p1, p2]).is_err());
    }

    #[test]
    fn empty_composite_works() {
        let c = CompositeDiscovery::new(vec![]).unwrap();
        assert!(c.is_empty());
    }

    #[test]
    fn no_discovery_doesnt_conflict() {
        let nd = Arc::new(NoDiscovery) as Arc<dyn DiscoveryProtocol>;
        let nd2 = Arc::new(NoDiscovery) as Arc<dyn DiscoveryProtocol>;
        // Both claim no prefixes → no conflict.
        assert!(CompositeDiscovery::new(vec![nd, nd2]).is_ok());
    }

    // ── on_inbound routing tests ──────────────────────────────────────────────

    #[test]
    fn routes_to_matching_protocol() {
        let p1 = MockProto::new("nd", "/ndn/local/nd");
        let p2 = MockProto::new("sd", "/ndn/local/sd");
        let p1_ref = Arc::clone(&p1);
        let p2_ref = Arc::clone(&p2);
        let composite = CompositeDiscovery::new(vec![p1, p2]).unwrap();

        // Build an Interest with name /ndn/local/nd/hello — matches p1's prefix.
        let name = Name::from_str("/ndn/local/nd/hello").unwrap();
        let pkt = minimal_interest(&name);

        let consumed = composite.on_inbound(&pkt, FaceId(0), &InboundMeta::none(), &NullCtx);
        assert!(consumed, "composite should consume packet matching p1");
        assert!(p1_ref.called.load(Ordering::SeqCst), "p1 should have been called");
        assert!(!p2_ref.called.load(Ordering::SeqCst), "p2 should NOT have been called");
    }

    #[test]
    fn routes_to_second_protocol() {
        let p1 = MockProto::new("nd", "/ndn/local/nd");
        let p2 = MockProto::new("sd", "/ndn/local/sd");
        let p1_ref = Arc::clone(&p1);
        let p2_ref = Arc::clone(&p2);
        let composite = CompositeDiscovery::new(vec![p1, p2]).unwrap();

        // Build an Interest with name /ndn/local/sd/hello — matches p2's prefix.
        let name = Name::from_str("/ndn/local/sd/hello").unwrap();
        let pkt = minimal_interest(&name);

        let consumed = composite.on_inbound(&pkt, FaceId(0), &InboundMeta::none(), &NullCtx);
        assert!(consumed, "composite should consume packet matching p2");
        assert!(!p1_ref.called.load(Ordering::SeqCst), "p1 should NOT have been called");
        assert!(p2_ref.called.load(Ordering::SeqCst), "p2 should have been called");
    }

    #[test]
    fn no_match_returns_false() {
        let p1 = MockProto::new("nd", "/ndn/local/nd");
        let p2 = MockProto::new("sd", "/ndn/local/sd");
        let composite = CompositeDiscovery::new(vec![p1, p2]).unwrap();

        // Build an Interest with name /ndn/local/other — matches neither.
        let name = Name::from_str("/ndn/local/other/hello").unwrap();
        let pkt = minimal_interest(&name);

        let consumed = composite.on_inbound(&pkt, FaceId(0), &InboundMeta::none(), &NullCtx);
        assert!(!consumed, "composite should NOT consume unmatched packet");
    }

    #[test]
    fn garbage_bytes_not_consumed_when_no_protocol_claims_them() {
        // A protocol that never claims any packet (returns false from on_inbound).
        struct NullProto;
        impl DiscoveryProtocol for NullProto {
            fn protocol_id(&self) -> ProtocolId { ProtocolId("null") }
            fn claimed_prefixes(&self) -> &[Name] { &[] }
            fn on_face_up(&self, _: FaceId, _: &dyn DiscoveryContext) {}
            fn on_face_down(&self, _: FaceId, _: &dyn DiscoveryContext) {}
            fn on_inbound(&self, _: &Bytes, _: FaceId, _: &InboundMeta, _: &dyn DiscoveryContext) -> bool { false }
            fn on_tick(&self, _: Instant, _: &dyn DiscoveryContext) {}
        }
        let composite = CompositeDiscovery::new(vec![Arc::new(NullProto) as Arc<dyn DiscoveryProtocol>]).unwrap();

        let junk = Bytes::from_static(b"\xFF\xFF\xFF");
        let consumed = composite.on_inbound(&junk, FaceId(0), &InboundMeta::none(), &NullCtx);
        assert!(!consumed, "garbage packet should not be consumed when no protocol claims it");
    }

    #[test]
    fn face_lifecycle_delivered_to_all() {
        let p1 = MockProto::new("nd", "/ndn/local/nd");
        let p2 = MockProto::new("sd", "/ndn/local/sd");
        let p1_ref = Arc::clone(&p1);
        let p2_ref = Arc::clone(&p2);

        // Wrap in a tracking impl for on_face_up.
        struct TrackFaceUp {
            inner: Arc<MockProto>,
            up_called: AtomicBool,
        }
        impl DiscoveryProtocol for TrackFaceUp {
            fn protocol_id(&self) -> ProtocolId { self.inner.id }
            fn claimed_prefixes(&self) -> &[Name] { &self.inner.prefixes }
            fn on_face_up(&self, _: FaceId, _: &dyn DiscoveryContext) {
                self.up_called.store(true, Ordering::SeqCst);
            }
            fn on_face_down(&self, _: FaceId, _: &dyn DiscoveryContext) {}
            fn on_inbound(&self, _: &Bytes, _: FaceId, _: &InboundMeta, _: &dyn DiscoveryContext) -> bool { false }
            fn on_tick(&self, _: Instant, _: &dyn DiscoveryContext) {}
        }

        let t1 = Arc::new(TrackFaceUp { inner: Arc::clone(&p1_ref), up_called: AtomicBool::new(false) });
        let t2 = Arc::new(TrackFaceUp { inner: Arc::clone(&p2_ref), up_called: AtomicBool::new(false) });
        let t1_ref = Arc::clone(&t1);
        let t2_ref = Arc::clone(&t2);

        let composite = CompositeDiscovery::new(
            vec![t1 as Arc<dyn DiscoveryProtocol>, t2 as Arc<dyn DiscoveryProtocol>]
        ).unwrap();
        composite.on_face_up(FaceId(3), &NullCtx);

        assert!(t1_ref.up_called.load(Ordering::SeqCst), "p1 should have received on_face_up");
        assert!(t2_ref.up_called.load(Ordering::SeqCst), "p2 should have received on_face_up");
    }
}
