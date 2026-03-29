use ndn_tlv::TlvError;

#[derive(Debug)]
pub enum PacketError {
    Tlv(TlvError),
    UnknownPacketType(u64),
    MalformedPacket(String),
}

impl From<TlvError> for PacketError {
    fn from(e: TlvError) -> Self {
        PacketError::Tlv(e)
    }
}

impl core::fmt::Display for PacketError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PacketError::Tlv(e) => write!(f, "TLV error: {e}"),
            PacketError::UnknownPacketType(t) => write!(f, "unknown packet type {t:#x}"),
            PacketError::MalformedPacket(msg) => write!(f, "malformed packet: {msg}"),
        }
    }
}

impl core::error::Error for PacketError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            PacketError::Tlv(e) => Some(e),
            _ => None,
        }
    }
}
