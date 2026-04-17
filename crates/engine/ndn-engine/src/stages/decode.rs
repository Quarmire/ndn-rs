use std::sync::Arc;

use bytes::Bytes;
use dashmap::DashMap;
use tracing::trace;

use crate::pipeline::{Action, DecodedPacket, DropReason, PacketContext};
use ndn_packet::encode::ensure_nonce;
use ndn_packet::fragment::ReassemblyBuffer;
use ndn_packet::lp::{LpPacket, extract_fragment, is_lp_packet};
use ndn_packet::{Data, Interest, Nack, Name, tlv_type};
use ndn_store::NameHashes;
use ndn_transport::{FaceId, FaceScope, FaceTable};

fn is_localhost_name(name: &Name) -> bool {
    name.components()
        .first()
        .is_some_and(|c| c.value.as_ref() == b"localhost")
}

#[derive(Clone, Copy, Debug)]
pub struct CongestionMark(pub u64);

#[derive(Clone, Copy, Debug)]
pub struct NextHopFaceId(pub u64);

#[derive(Clone, Copy, Debug)]
pub struct LpCachePolicy(pub ndn_packet::CachePolicyType);

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
    pub(crate) reassembly: DashMap<FaceId, ReassemblyBuffer>,
}

impl TlvDecodeStage {
    pub fn new(face_table: Arc<FaceTable>) -> Self {
        Self {
            face_table,
            reassembly: DashMap::new(),
        }
    }

    /// Fast-path fragment collection bypassing `PacketContext` creation.
    ///
    /// - `Ok(Some(bytes))` -- reassembly complete
    /// - `Ok(None)` -- fragment buffered, waiting for more
    /// - `Err(bytes)` -- not a fragment; process through full pipeline
    pub fn try_collect_fragment(
        &self,
        face_id: FaceId,
        raw: Bytes,
    ) -> Result<Option<Bytes>, Bytes> {
        let hdr = match extract_fragment(&raw) {
            Some(h) => h,
            None => return Err(raw),
        };
        let fragment = raw.slice(hdr.frag_start..hdr.frag_end);
        let base_seq = hdr.sequence - hdr.frag_index;
        let mut rb = self.reassembly.entry(face_id).or_default();
        Ok(rb.process(base_seq, hdr.frag_index, hdr.frag_count, fragment))
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
            t if t == tlv_type::DATA => match Data::decode(ctx.raw_bytes.clone()) {
                Ok(data) => {
                    trace!(face=%ctx.face_id, name=%data.name, "decode: Data");
                    if data.name.len() > 3 {
                        ctx.name_hashes = Some(NameHashes::compute(&data.name));
                    }
                    ctx.name = Some(data.name.clone());
                    ctx.packet = DecodedPacket::Data(Box::new(data));
                    if let Some(drop) = self.check_scope(&ctx) {
                        return drop;
                    }
                    Action::Continue(ctx)
                }
                Err(e) => {
                    trace!(face=%ctx.face_id, error=%e, "decode: malformed Data");
                    Action::Drop(DropReason::MalformedPacket)
                }
            },
            _ => {
                trace!(face=%ctx.face_id, tlv_type=first_byte, "decode: unknown TLV type");
                Action::Drop(DropReason::MalformedPacket)
            }
        }
    }

    fn decode_interest(&self, mut ctx: PacketContext) -> Action {
        match Interest::decode(ctx.raw_bytes.clone()) {
            Ok(interest) => {
                if interest.hop_limit() == Some(0) {
                    trace!(face=%ctx.face_id, name=%interest.name, "decode: HopLimit=0, dropping");
                    return Action::Drop(DropReason::HopLimitExceeded);
                }
                trace!(face=%ctx.face_id, name=%interest.name, nonce=?interest.nonce(), "decode: Interest");
                ctx.raw_bytes = ensure_nonce(&ctx.raw_bytes);
                if interest.name.len() > 3 {
                    ctx.name_hashes = Some(NameHashes::compute(&interest.name));
                }
                ctx.name = Some(interest.name.clone());
                ctx.packet = DecodedPacket::Interest(Box::new(interest));
                if let Some(drop) = self.check_scope(&ctx) {
                    return drop;
                }
                Action::Continue(ctx)
            }
            Err(e) => {
                trace!(face=%ctx.face_id, error=%e, "decode: malformed Interest");
                Action::Drop(DropReason::MalformedPacket)
            }
        }
    }

    fn check_scope(&self, ctx: &PacketContext) -> Option<Action> {
        if let Some(ref name) = ctx.name
            && is_localhost_name(name)
        {
            let is_non_local = self
                .face_table
                .get(ctx.face_id)
                .is_some_and(|f| f.kind().scope() == FaceScope::NonLocal);
            if is_non_local {
                trace!(face=%ctx.face_id, name=%name, "decode: /localhost on non-local face, dropping");
                return Some(Action::Drop(DropReason::ScopeViolation));
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

        if let Some(mark) = lp.congestion_mark {
            ctx.tags.insert(CongestionMark(mark));
        }
        if let Some(token) = lp.pit_token.clone() {
            ctx.lp_pit_token = Some(token);
        }
        if let Some(face_id) = lp.next_hop_face_id {
            ctx.tags.insert(NextHopFaceId(face_id));
        }
        if let Some(ref policy) = lp.cache_policy {
            ctx.tags.insert(LpCachePolicy(*policy));
        }

        if lp.is_ack_only() {
            return Action::Drop(DropReason::FragmentCollect);
        }

        let is_fragmented = lp.is_fragmented();
        let sequence = lp.sequence;
        let frag_index = lp.frag_index;
        let frag_count = lp.frag_count;
        let nack = lp.nack;

        let fragment = match lp.fragment {
            Some(f) => f,
            None => return Action::Drop(DropReason::MalformedPacket),
        };

        if is_fragmented {
            let face_id = ctx.face_id;
            let complete = {
                let mut rb = self.reassembly.entry(face_id).or_default();
                let seq = sequence.unwrap_or(0);
                let idx = frag_index.unwrap_or(0);
                let base_seq = seq - idx;
                rb.process(base_seq, idx, frag_count.unwrap_or(1), fragment)
            };
            match complete {
                Some(packet) => {
                    trace!(face=%ctx.face_id, len=packet.len(), "decode: reassembled");
                    ctx.raw_bytes = packet;
                    return self.process(ctx);
                }
                None => {
                    return Action::Drop(DropReason::FragmentCollect);
                }
            }
        }

        if let Some(reason) = nack {
            match Interest::decode(fragment) {
                Ok(interest) => {
                    trace!(face=%ctx.face_id, name=%interest.name, reason=?reason, "decode: Nack");
                    let nack = Nack::new(interest, reason);
                    if nack.interest.name.len() > 3 {
                        ctx.name_hashes = Some(NameHashes::compute(&nack.interest.name));
                    }
                    ctx.name = Some(nack.interest.name.clone());
                    ctx.packet = DecodedPacket::Nack(Box::new(nack));
                    if let Some(drop) = self.check_scope(&ctx) {
                        return drop;
                    }
                    Action::Continue(ctx)
                }
                Err(e) => {
                    trace!(face=%ctx.face_id, error=%e, "decode: malformed nacked Interest");
                    Action::Drop(DropReason::MalformedPacket)
                }
            }
        } else {
            ctx.raw_bytes = fragment;
            self.process(ctx)
        }
    }
}
