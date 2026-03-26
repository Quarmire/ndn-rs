use bytes::Bytes;

use crate::{Interest, PacketError};
use ndn_tlv::TlvReader;
use crate::tlv_type;

/// Reason codes carried in a Nack packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NackReason {
    /// The forwarder has no route for this Interest.
    NoRoute,
    /// The Interest is a duplicate (loop detected).
    Duplicate,
    /// The forwarder is congested.
    Congestion,
    /// The data does not yet exist; consumer may retry after a hint.
    NotYet,
    /// Unknown/vendor-specific reason code.
    Other(u64),
}

impl NackReason {
    pub fn code(&self) -> u64 {
        match self {
            NackReason::Congestion => 50,
            NackReason::Duplicate  => 100,
            NackReason::NoRoute    => 150,
            NackReason::NotYet     => 160,
            NackReason::Other(c)   => *c,
        }
    }

    pub fn from_code(code: u64) -> Self {
        match code {
            50  => NackReason::Congestion,
            100 => NackReason::Duplicate,
            150 => NackReason::NoRoute,
            160 => NackReason::NotYet,
            c   => NackReason::Other(c),
        }
    }
}

/// An NDN Nack — a negative acknowledgement wrapping the rejected Interest.
pub struct Nack {
    pub reason:   NackReason,
    pub interest: Interest,
}

impl Nack {
    pub fn new(interest: Interest, reason: NackReason) -> Self {
        Self { reason, interest }
    }

    pub fn decode(raw: Bytes) -> Result<Self, PacketError> {
        let mut reader = TlvReader::new(raw.clone());
        let (typ, value) = reader.read_tlv()?;
        if typ != tlv_type::NACK {
            return Err(PacketError::UnknownPacketType(typ));
        }
        let mut inner = TlvReader::new(value);

        let mut reason = NackReason::Other(0);
        let mut interest_raw: Option<Bytes> = None;

        while !inner.is_empty() {
            let (t, v) = inner.read_tlv()?;
            match t {
                t if t == tlv_type::NACK_REASON => {
                    let mut code = 0u64;
                    for &b in v.iter() {
                        code = (code << 8) | b as u64;
                    }
                    reason = NackReason::from_code(code);
                }
                t if t == tlv_type::INTEREST => {
                    interest_raw = Some(v);
                }
                _ => {}
            }
        }

        let interest_bytes = interest_raw.ok_or_else(|| {
            PacketError::Tlv(ndn_tlv::TlvError::MissingField("Interest inside Nack"))
        })?;
        let interest = Interest::decode(interest_bytes)?;
        Ok(Self { reason, interest })
    }
}
