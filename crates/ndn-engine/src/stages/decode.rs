use ndn_packet::{Data, Interest, Nack, tlv_type};
use ndn_pipeline::{Action, DropReason, PacketContext, DecodedPacket};

/// Decodes the raw bytes in `ctx` into an `Interest`, `Data`, or `Nack`.
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

        match first_byte {
            t if t == tlv_type::INTEREST => {
                match Interest::decode(ctx.raw_bytes.clone()) {
                    Ok(interest) => {
                        ctx.name   = Some(interest.name.clone());
                        ctx.packet = DecodedPacket::Interest(Box::new(interest));
                        Action::Continue(ctx)
                    }
                    Err(_) => Action::Drop(DropReason::MalformedPacket),
                }
            }
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
            _ => {
                // Try Nack (NDNv3: outer type 0x0320, two-byte varint).
                match Nack::decode(ctx.raw_bytes.clone()) {
                    Ok(nack) => {
                        ctx.name   = Some(nack.interest.name.clone());
                        ctx.packet = DecodedPacket::Nack(Box::new(nack));
                        Action::Continue(ctx)
                    }
                    Err(_) => Action::Drop(DropReason::MalformedPacket),
                }
            }
        }
    }
}
