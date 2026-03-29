use ndn_packet::{Data, Interest, Nack, tlv_type};
use ndn_packet::encode::ensure_nonce;
use ndn_packet::lp::{LpPacket, is_lp_packet};
use ndn_pipeline::{Action, DropReason, PacketContext, DecodedPacket};

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
pub struct TlvDecodeStage;

impl TlvDecodeStage {
    pub fn process(&self, mut ctx: PacketContext) -> Action {
        let first_byte = match ctx.raw_bytes.first() {
            Some(&b) => b as u64,
            None => return Action::Drop(DropReason::MalformedPacket),
        };

        // NDNLPv2: unwrap LpPacket if present.
        if is_lp_packet(&ctx.raw_bytes) {
            return self.process_lp(ctx);
        }

        match first_byte {
            t if t == tlv_type::INTEREST => self.decode_interest(ctx),
            t if t == tlv_type::DATA => {
                match Data::decode(ctx.raw_bytes.clone()) {
                    Ok(data) => {
                        ctx.name   = Some(data.name.clone());
                        ctx.packet = DecodedPacket::Data(Box::new(data));
                        Action::Continue(ctx)
                    }
                    Err(_) => Action::Drop(DropReason::MalformedPacket),
                }
            }
            _ => Action::Drop(DropReason::MalformedPacket),
        }
    }

    /// Decode a bare Interest, enforcing HopLimit and inserting Nonce.
    fn decode_interest(&self, mut ctx: PacketContext) -> Action {
        match Interest::decode(ctx.raw_bytes.clone()) {
            Ok(interest) => {
                if interest.hop_limit() == Some(0) {
                    return Action::Drop(DropReason::HopLimitExceeded);
                }
                ctx.raw_bytes = ensure_nonce(&ctx.raw_bytes);
                ctx.name   = Some(interest.name.clone());
                ctx.packet = DecodedPacket::Interest(Box::new(interest));
                Action::Continue(ctx)
            }
            Err(_) => Action::Drop(DropReason::MalformedPacket),
        }
    }

    /// Process an NDNLPv2 LpPacket.
    fn process_lp(&self, mut ctx: PacketContext) -> Action {
        let lp = match LpPacket::decode(ctx.raw_bytes.clone()) {
            Ok(lp) => lp,
            Err(_) => return Action::Drop(DropReason::MalformedPacket),
        };

        // Propagate CongestionMark through the pipeline via tags.
        if let Some(mark) = lp.congestion_mark {
            ctx.tags.insert(CongestionMark(mark));
        }

        if let Some(reason) = lp.nack {
            // LpPacket with Nack header: fragment is the nacked Interest.
            match Interest::decode(lp.fragment) {
                Ok(interest) => {
                    let nack = Nack::new(interest, reason);
                    ctx.name   = Some(nack.interest.name.clone());
                    ctx.packet = DecodedPacket::Nack(Box::new(nack));
                    Action::Continue(ctx)
                }
                Err(_) => Action::Drop(DropReason::MalformedPacket),
            }
        } else {
            // Plain LpPacket wrapping Interest or Data.
            ctx.raw_bytes = lp.fragment;
            self.process(ctx)
        }
    }
}
