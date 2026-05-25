//! NDNLPv2 `TraceContext` LP TLV codec. Wire form follows the W3C trace-context
//! binary draft (16-byte trace id, 8-byte span id, 1 byte flags) plus an
//! 8-byte big-endian timestamp (micros since router epoch) so the receiver
//! can compute single-hop latency without a separate LP TLV. TLV-TYPE
//! `0x520` is in the NDNLPv2 experimental range.

#[cfg(all(not(feature = "std"), not(target_arch = "wasm32")))]
use alloc::vec::Vec;

use bytes::Bytes;

/// LP TLV-TYPE reserved for `TraceContext` in the NDNLPv2 experimental range.
pub const TLV_TRACE_CONTEXT: u64 = 0x520;

const VALUE_LEN: usize = 16 + 8 + 1 + 8;

/// 128-bit trace identifier; equal-byte semantics.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct TraceId(pub [u8; 16]);

/// 64-bit span identifier.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct SpanId(pub [u8; 8]);

/// 8-bit trace flags. Bit 0 = sampled; remaining bits reserved.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Default)]
pub struct TraceFlags(pub u8);

impl TraceFlags {
    pub const SAMPLED: Self = Self(0x01);

    pub fn is_sampled(self) -> bool {
        self.0 & 0x01 != 0
    }
}

/// Decoded `TraceContext` LP TLV value.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TraceContext {
    pub trace_id: TraceId,
    pub span_id: SpanId,
    pub flags: TraceFlags,
    /// Microseconds since the originating router's local epoch; meaningful
    /// only for per-hop latency relative to the receiver's clock.
    pub timestamp_us: u64,
}

/// Decode-side error; kept distinct from `crate::PacketError` so the codec
/// stays `no_std`-clean.
#[derive(Debug, PartialEq, Eq)]
pub enum TraceContextError {
    BadLength(usize),
}

impl core::fmt::Display for TraceContextError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadLength(n) => write!(f, "TraceContext value must be 33 bytes, got {n}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TraceContextError {}

impl TraceContext {
    /// Decode from the LP TLV value bytes (no outer TYPE/LENGTH).
    pub fn decode_value(value: &[u8]) -> Result<Self, TraceContextError> {
        if value.len() != VALUE_LEN {
            return Err(TraceContextError::BadLength(value.len()));
        }
        let mut trace_id = [0u8; 16];
        let mut span_id = [0u8; 8];
        trace_id.copy_from_slice(&value[0..16]);
        span_id.copy_from_slice(&value[16..24]);
        let flags = TraceFlags(value[24]);
        let mut ts = [0u8; 8];
        ts.copy_from_slice(&value[25..33]);
        Ok(Self {
            trace_id: TraceId(trace_id),
            span_id: SpanId(span_id),
            flags,
            timestamp_us: u64::from_be_bytes(ts),
        })
    }

    /// Encode the value bytes (no outer TYPE/LENGTH).
    pub fn encode_value(&self) -> [u8; VALUE_LEN] {
        let mut buf = [0u8; VALUE_LEN];
        buf[0..16].copy_from_slice(&self.trace_id.0);
        buf[16..24].copy_from_slice(&self.span_id.0);
        buf[24] = self.flags.0;
        buf[25..33].copy_from_slice(&self.timestamp_us.to_be_bytes());
        buf
    }

    /// Encode as a full LP TLV (TYPE 0x520, LENGTH 33, VALUE).
    pub fn encode_tlv(&self) -> Bytes {
        let value = self.encode_value();
        let mut out = Vec::with_capacity(4 + VALUE_LEN);
        // TLV-TYPE 0x520 needs the 3-byte `0xFD nn nn` varnumber form.
        out.push(0xFD);
        out.extend_from_slice(&(TLV_TRACE_CONTEXT as u16).to_be_bytes());
        out.push(VALUE_LEN as u8);
        out.extend_from_slice(&value);
        Bytes::from(out)
    }

    /// Nonce-derived fallback `TraceContext` synthesis for inbound frames
    /// that lack one: `trace_id = blake3(nonce || name || router_id)[..16]`,
    /// stable per `(nonce, name, router_id)`. Internal-only; the
    /// synthesised context is never echoed back unchanged.
    #[cfg(feature = "std")]
    pub fn from_nonce_and_name(
        nonce: u32,
        name_wire: &[u8],
        router_id: &[u8],
        span_id: SpanId,
        timestamp_us: u64,
    ) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&nonce.to_be_bytes());
        hasher.update(name_wire);
        hasher.update(router_id);
        let digest = hasher.finalize();
        let bytes = digest.as_bytes();
        let mut trace_id = [0u8; 16];
        trace_id.copy_from_slice(&bytes[..16]);
        Self {
            trace_id: TraceId(trace_id),
            span_id,
            flags: TraceFlags::default(),
            timestamp_us,
        }
    }
}

/// Splice a `TraceContext` TLV into an existing LP-wrapped packet wire,
/// landing in ascending TLV-TYPE order so the LP element-order rule holds.
/// Replaces an existing `TraceContext` if present. Cost: one full LP re-encode.
/// Non-LP wires are returned unchanged.
#[cfg(feature = "std")]
pub fn splice_into_lp_wire(lp_wire: Bytes, ctx: &TraceContext) -> Bytes {
    use ndn_tlv::{TlvReader, TlvWriter};

    if !super::is_lp_packet(&lp_wire) {
        return lp_wire;
    }
    let mut outer = TlvReader::new(lp_wire.clone());
    let (typ, value) = match outer.read_tlv() {
        Ok(t) => t,
        Err(_) => return lp_wire,
    };
    if typ != crate::tlv_type::LP_PACKET {
        return lp_wire;
    }

    let mut inner = TlvReader::new(value);
    let mut headers: Vec<(u64, Bytes)> = Vec::new();
    let mut fragment_tlv: Option<(u64, Bytes)> = None;
    while !inner.is_empty() {
        let Ok((t, v)) = inner.read_tlv() else {
            return lp_wire;
        };
        if t == crate::tlv_type::LP_FRAGMENT {
            fragment_tlv = Some((t, v));
            continue;
        }
        if t == TLV_TRACE_CONTEXT {
            continue;
        }
        headers.push((t, v));
    }

    let mut w = TlvWriter::new();
    w.write_nested(crate::tlv_type::LP_PACKET, |w| {
        let mut inserted = false;
        for (t, v) in &headers {
            if !inserted && *t > TLV_TRACE_CONTEXT {
                w.write_tlv(TLV_TRACE_CONTEXT, &ctx.encode_value());
                inserted = true;
            }
            w.write_tlv(*t, v);
        }
        if !inserted {
            w.write_tlv(TLV_TRACE_CONTEXT, &ctx.encode_value());
        }
        if let Some((t, v)) = fragment_tlv {
            w.write_tlv(t, &v);
        }
    });
    w.finish()
}

/// Extract a `TraceContext` TLV from an LP-wrapped packet wire. Returns
/// `None` if the wire is not LP-wrapped, malformed, or carries no
/// `TraceContext`. Forgiving — malformed inner bytes yield `None` so the
/// engine can fall through to Nonce-fallback synthesis.
#[cfg(feature = "std")]
pub fn extract_from_lp_wire(lp_wire: &Bytes) -> Option<TraceContext> {
    use ndn_tlv::TlvReader;

    if !super::is_lp_packet(lp_wire) {
        return None;
    }
    let mut outer = TlvReader::new(lp_wire.clone());
    let (typ, value) = outer.read_tlv().ok()?;
    if typ != crate::tlv_type::LP_PACKET {
        return None;
    }
    let mut inner = TlvReader::new(value);
    while !inner.is_empty() {
        let (t, v) = inner.read_tlv().ok()?;
        if t == TLV_TRACE_CONTEXT {
            return TraceContext::decode_value(&v).ok();
        }
        if t == crate::tlv_type::LP_FRAGMENT {
            return None;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_ctx() -> TraceContext {
        TraceContext {
            trace_id: TraceId([
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
                0x0F, 0x10,
            ]),
            span_id: SpanId([0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8]),
            flags: TraceFlags::SAMPLED,
            timestamp_us: 0x0123_4567_89AB_CDEF,
        }
    }

    #[test]
    fn trace_context_value_roundtrip() {
        let ctx = sample_ctx();
        let bytes = ctx.encode_value();
        assert_eq!(bytes.len(), VALUE_LEN);
        let back = TraceContext::decode_value(&bytes).expect("decode");
        assert_eq!(ctx, back);
    }

    #[test]
    fn trace_context_tlv_roundtrip_inner_value() {
        let ctx = sample_ctx();
        let wire = ctx.encode_tlv();
        // Wire shape: [0xFD, hi, lo, 33, …33 value bytes]
        assert_eq!(wire.len(), 4 + VALUE_LEN);
        assert_eq!(wire[0], 0xFD);
        let typ = u16::from_be_bytes([wire[1], wire[2]]);
        assert_eq!(typ as u64, TLV_TRACE_CONTEXT);
        assert_eq!(wire[3], VALUE_LEN as u8);
        let back = TraceContext::decode_value(&wire[4..]).expect("decode");
        assert_eq!(ctx, back);
    }

    #[test]
    fn trace_context_decode_rejects_wrong_length() {
        let err = TraceContext::decode_value(&[0u8; 32]).unwrap_err();
        assert_eq!(err, TraceContextError::BadLength(32));
        let err = TraceContext::decode_value(&[0u8; 34]).unwrap_err();
        assert_eq!(err, TraceContextError::BadLength(34));
    }

    #[test]
    fn trace_flags_sampled_bit() {
        assert!(TraceFlags::SAMPLED.is_sampled());
        assert!(!TraceFlags(0).is_sampled());
        assert!(TraceFlags(0xFF).is_sampled());
    }

    #[cfg(feature = "std")]
    #[test]
    fn trace_ids_aggregate_from_nonce_stable_per_input() {
        let span = SpanId([0u8; 8]);
        let a1 = TraceContext::from_nonce_and_name(42, b"/audit/n.03", b"router-A", span, 0);
        let a2 = TraceContext::from_nonce_and_name(42, b"/audit/n.03", b"router-A", span, 0);
        assert_eq!(
            a1.trace_id, a2.trace_id,
            "same (nonce, name, router) must produce the same TraceId"
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn trace_ids_aggregate_from_nonce_differs_on_nonce() {
        let span = SpanId([0u8; 8]);
        let a = TraceContext::from_nonce_and_name(42, b"/n", b"router-A", span, 0);
        let b = TraceContext::from_nonce_and_name(43, b"/n", b"router-A", span, 0);
        assert_ne!(
            a.trace_id, b.trace_id,
            "different nonces must produce different TraceIds"
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn trace_ids_aggregate_from_nonce_differs_on_name() {
        let span = SpanId([0u8; 8]);
        let a = TraceContext::from_nonce_and_name(42, b"/a", b"router", span, 0);
        let b = TraceContext::from_nonce_and_name(42, b"/b", b"router", span, 0);
        assert_ne!(a.trace_id, b.trace_id);
    }

    #[cfg(feature = "std")]
    #[test]
    fn trace_ids_aggregate_from_nonce_differs_on_router() {
        let span = SpanId([0u8; 8]);
        let a = TraceContext::from_nonce_and_name(42, b"/n", b"router-A", span, 0);
        let b = TraceContext::from_nonce_and_name(42, b"/n", b"router-B", span, 0);
        assert_ne!(a.trace_id, b.trace_id);
    }

    // splice / extract

    #[cfg(feature = "std")]
    fn lp_packet_around(inner_interest: &[u8]) -> Bytes {
        use ndn_tlv::TlvWriter;
        let mut w = TlvWriter::new();
        w.write_nested(crate::tlv_type::LP_PACKET, |w| {
            w.write_tlv(crate::tlv_type::LP_FRAGMENT, inner_interest);
        });
        w.finish()
    }

    #[cfg(feature = "std")]
    fn minimal_interest() -> Vec<u8> {
        let mut w = ndn_tlv::TlvWriter::new();
        w.write_nested(crate::tlv_type::INTEREST, |w| {
            w.write_nested(crate::tlv_type::NAME, |w| {
                w.write_tlv(crate::tlv_type::NAME_COMPONENT, b"test");
            });
            w.write_tlv(crate::tlv_type::NONCE, &[1, 2, 3, 4]);
        });
        w.finish().to_vec()
    }

    #[cfg(feature = "std")]
    #[test]
    fn splice_then_extract_roundtrip() {
        let interest = minimal_interest();
        let lp = lp_packet_around(&interest);
        let ctx = sample_ctx();
        let spliced = splice_into_lp_wire(lp.clone(), &ctx);
        let extracted = extract_from_lp_wire(&spliced).expect("must extract");
        assert_eq!(extracted, ctx);
    }

    #[cfg(feature = "std")]
    #[test]
    fn splice_preserves_fragment_payload() {
        let interest = minimal_interest();
        let lp = lp_packet_around(&interest);
        let ctx = sample_ctx();
        let spliced = splice_into_lp_wire(lp, &ctx);
        // Decode via LpPacket and check the fragment round-trips.
        let pkt = crate::lp::LpPacket::decode(spliced).expect("LpPacket decode");
        let frag = pkt.fragment.expect("fragment present");
        assert_eq!(frag.as_ref(), &interest[..]);
    }

    #[cfg(feature = "std")]
    #[test]
    fn splice_passthrough_for_non_lp_wire() {
        let bare = Bytes::from_static(&[0x05, 0x00]);
        let ctx = sample_ctx();
        let out = splice_into_lp_wire(bare.clone(), &ctx);
        assert_eq!(out, bare, "non-LP wire must pass through unchanged");
    }

    #[cfg(feature = "std")]
    #[test]
    fn extract_returns_none_when_absent() {
        let interest = minimal_interest();
        let lp = lp_packet_around(&interest);
        assert!(extract_from_lp_wire(&lp).is_none());
    }

    #[cfg(feature = "std")]
    #[test]
    fn splice_replaces_existing_trace_context() {
        let interest = minimal_interest();
        let lp = lp_packet_around(&interest);
        let ctx1 = TraceContext {
            trace_id: TraceId([0xAA; 16]),
            span_id: SpanId([0xBB; 8]),
            flags: TraceFlags::SAMPLED,
            timestamp_us: 1,
        };
        let ctx2 = TraceContext {
            trace_id: TraceId([0xCC; 16]),
            span_id: SpanId([0xDD; 8]),
            flags: TraceFlags::SAMPLED,
            timestamp_us: 2,
        };
        let once = splice_into_lp_wire(lp, &ctx1);
        let twice = splice_into_lp_wire(once, &ctx2);
        let extracted = extract_from_lp_wire(&twice).expect("must extract");
        assert_eq!(extracted, ctx2, "second splice must replace, not duplicate");
    }

    #[cfg(feature = "std")]
    #[test]
    fn splice_keeps_packet_decodable_by_lp_packet() {
        // Combined wire must still decode as a valid LpPacket so peers that
        // ignore the unknown non-critical TraceContext TLV remain interop-able.
        let interest = minimal_interest();
        let lp = lp_packet_around(&interest);
        let ctx = sample_ctx();
        let spliced = splice_into_lp_wire(lp, &ctx);
        crate::lp::LpPacket::decode(spliced).expect("LpPacket must accept TraceContext");
    }
}
