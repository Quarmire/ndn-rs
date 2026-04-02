use std::sync::Arc;

use tracing::trace;

use ndn_packet::{Data, Interest, Nack, Name, tlv_type};
use ndn_packet::encode::ensure_nonce;
use ndn_packet::lp::{LpPacket, is_lp_packet};
use ndn_pipeline::{Action, DropReason, PacketContext, DecodedPacket};
use ndn_transport::{FaceScope, FaceTable};

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
}

impl TlvDecodeStage {
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
