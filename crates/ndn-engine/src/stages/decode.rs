use std::sync::Arc;

use bytes::Bytes;
use dashmap::DashMap;
use tracing::trace;

use ndn_packet::{Data, Interest, Nack, Name, tlv_type};
use ndn_packet::encode::ensure_nonce;
use ndn_packet::fragment::ReassemblyBuffer;
use ndn_packet::lp::{LpPacket, is_lp_packet};
use ndn_pipeline::{Action, DropReason, PacketContext, DecodedPacket};
use ndn_transport::{FaceId, FaceScope, FaceTable};

/// Check if a name starts with `/localhost`.
fn is_localhost_name(name: &Name) -> bool {
    name.components()
        .first()
        .is_some_and(|c| c.value.as_ref() == b"localhost")
}

/// NDNLPv2 congestion mark, stored as a tag in `PacketContext::tags`.
#[derive(Clone, Copy, Debug)]
pub struct CongestionMark(pub u64);

/// Decodes the raw bytes in `ctx` into an `Interest`, `Data`, or `Nack`.
///
/// Handles both bare Interest/Data packets and NDNLPv2 LpPacket-wrapped
/// packets. LpPackets with a Nack header produce a `DecodedPacket::Nack`.
///
/// On success sets `ctx.packet` and `ctx.name`. On any parse failure returns
/// `Action::Drop(MalformedPacket)`.
///
/// Enforces `/localhost` scope: packets with names starting with `/localhost`
/// arriving on non-local faces are dropped.
pub struct TlvDecodeStage {
    pub face_table: Arc<FaceTable>,
    /// Per-face NDNLPv2 fragment reassembly buffers.
    ///
    /// Keyed by FaceId so fragments from different faces are reassembled
    /// independently.  Buffers are created on first fragmented packet and
    /// cleaned up lazily via `purge_expired()`.
    pub(crate) reassembly: DashMap<FaceId, ReassemblyBuffer>,
}

impl TlvDecodeStage {
    /// Fast-path fragment collection that bypasses `PacketContext` creation.
    ///
    /// If the raw bytes are a fragmented LpPacket, parses just the header fields
    /// and feeds the fragment to the per-face `ReassemblyBuffer`.
    ///
    /// Returns:
    /// - `Ok(Some(bytes))` — reassembly completed, `bytes` is the full packet
    /// - `Ok(None)` — fragment buffered, waiting for more
    /// - `Err(bytes)` — not a fragment (bare packet, unfragmented LpPacket, or
    ///   Nack); caller should process through the full pipeline. The original
    ///   bytes are returned back.
    pub fn try_collect_fragment(&self, face_id: FaceId, raw: Bytes) -> Result<Option<Bytes>, Bytes> {
        if !is_lp_packet(&raw) {
            return Err(raw);
        }
        // Parse just enough to check fragmentation.
        let lp = match LpPacket::decode(raw.clone()) {
            Ok(lp) => lp,
            Err(_) => return Err(raw),
        };
        if !lp.is_fragmented() {
            return Err(raw);
        }
        // Feed to reassembly buffer.
        let mut rb = self.reassembly
            .entry(face_id)
            .or_insert_with(ReassemblyBuffer::default);
        Ok(rb.process(
            lp.sequence.unwrap_or(0),
            lp.frag_index.unwrap_or(0),
            lp.frag_count.unwrap_or(1),
            lp.fragment,
        ))
    }

    pub fn process(&self, mut ctx: PacketContext) -> Action {
        let first_byte = match ctx.raw_bytes.first() {
            Some(&b) => b as u64,
            None => {
                trace!(face=%ctx.face_id, "decode: empty packet");
                return Action::Drop(DropReason::MalformedPacket);
            }
        };

        // NDNLPv2: unwrap LpPacket if present.
        if is_lp_packet(&ctx.raw_bytes) {
            trace!(face=%ctx.face_id, len=ctx.raw_bytes.len(), "decode: LpPacket");
            return self.process_lp(ctx);
        }

        match first_byte {
            t if t == tlv_type::INTEREST => self.decode_interest(ctx),
            t if t == tlv_type::DATA => {
                match Data::decode(ctx.raw_bytes.clone()) {
                    Ok(data) => {
                        trace!(face=%ctx.face_id, name=%data.name, "decode: Data");
                        ctx.name   = Some(data.name.clone());
                        ctx.packet = DecodedPacket::Data(Box::new(data));
                        if let Some(drop) = self.check_scope(&ctx) { return drop; }
                        Action::Continue(ctx)
                    }
                    Err(e) => {
                        trace!(face=%ctx.face_id, error=%e, "decode: malformed Data");
                        Action::Drop(DropReason::MalformedPacket)
                    }
                }
            }
            _ => {
                trace!(face=%ctx.face_id, tlv_type=first_byte, "decode: unknown TLV type");
                Action::Drop(DropReason::MalformedPacket)
            }
        }
    }

    /// Decode a bare Interest, enforcing HopLimit and inserting Nonce.
    fn decode_interest(&self, mut ctx: PacketContext) -> Action {
        match Interest::decode(ctx.raw_bytes.clone()) {
            Ok(interest) => {
                if interest.hop_limit() == Some(0) {
                    trace!(face=%ctx.face_id, name=%interest.name, "decode: HopLimit=0, dropping");
                    return Action::Drop(DropReason::HopLimitExceeded);
                }
                trace!(face=%ctx.face_id, name=%interest.name, nonce=?interest.nonce(), "decode: Interest");
                ctx.raw_bytes = ensure_nonce(&ctx.raw_bytes);
                ctx.name   = Some(interest.name.clone());
                ctx.packet = DecodedPacket::Interest(Box::new(interest));
                if let Some(drop) = self.check_scope(&ctx) { return drop; }
                Action::Continue(ctx)
            }
            Err(e) => {
                trace!(face=%ctx.face_id, error=%e, "decode: malformed Interest");
                Action::Drop(DropReason::MalformedPacket)
            }
        }
    }

    /// Drop packets with `/localhost` names arriving on non-local faces.
    fn check_scope(&self, ctx: &PacketContext) -> Option<Action> {
        if let Some(ref name) = ctx.name {
            if is_localhost_name(name) {
                let is_non_local = self.face_table.get(ctx.face_id)
                    .is_some_and(|f| f.kind().scope() == FaceScope::NonLocal);
                if is_non_local {
                    trace!(face=%ctx.face_id, name=%name, "decode: /localhost on non-local face, dropping");
                    return Some(Action::Drop(DropReason::ScopeViolation));
                }
            }
        }
        None
    }

    /// Process an NDNLPv2 LpPacket.
    ///
    /// Handles fragment reassembly: if the LpPacket is a fragment, it is
    /// buffered per-face until all fragments arrive.  Returns `Action::Drop`
    /// for incomplete reassemblies (waiting for more fragments) and
    /// re-enters `process()` when the complete packet is available.
    fn process_lp(&self, mut ctx: PacketContext) -> Action {
        let lp = match LpPacket::decode(ctx.raw_bytes.clone()) {
            Ok(lp) => lp,
            Err(e) => {
                trace!(face=%ctx.face_id, error=%e, "decode: malformed LpPacket");
                return Action::Drop(DropReason::MalformedPacket);
            }
        };

        // Propagate CongestionMark through the pipeline via tags.
        if let Some(mark) = lp.congestion_mark {
            ctx.tags.insert(CongestionMark(mark));
        }

        // Fragment reassembly: buffer until all fragments arrive.
        if lp.is_fragmented() {
            let face_id = ctx.face_id;
            let complete = {
                let mut rb = self.reassembly
                    .entry(face_id)
                    .or_insert_with(ReassemblyBuffer::default);
                rb.process(
                    lp.sequence.unwrap_or(0),
                    lp.frag_index.unwrap_or(0),
                    lp.frag_count.unwrap_or(1),
                    lp.fragment,
                )
            };
            match complete {
                Some(packet) => {
                    trace!(face=%ctx.face_id, len=packet.len(), "decode: reassembled");
                    ctx.raw_bytes = packet;
                    return self.process(ctx);
                }
                None => {
                    // Still waiting for more fragments — not an error.
                    return Action::Drop(DropReason::FragmentCollect);
                }
            }
        }

        if let Some(reason) = lp.nack {
            // LpPacket with Nack header: fragment is the nacked Interest.
            match Interest::decode(lp.fragment) {
                Ok(interest) => {
                    trace!(face=%ctx.face_id, name=%interest.name, reason=?reason, "decode: Nack");
                    let nack = Nack::new(interest, reason);
                    ctx.name   = Some(nack.interest.name.clone());
                    ctx.packet = DecodedPacket::Nack(Box::new(nack));
                    if let Some(drop) = self.check_scope(&ctx) { return drop; }
                    Action::Continue(ctx)
                }
                Err(e) => {
                    trace!(face=%ctx.face_id, error=%e, "decode: malformed nacked Interest");
                    Action::Drop(DropReason::MalformedPacket)
                }
            }
        } else {
            // Plain LpPacket wrapping Interest or Data.
            ctx.raw_bytes = lp.fragment;
            self.process(ctx)
        }
    }
}
