#[cfg(all(not(feature = "std"), not(target_arch = "wasm32")))]
use alloc::string::String;

use ndn_tlv::TlvError;

#[derive(Debug)]
pub enum PacketError {
    Tlv(TlvError),
    UnknownPacketType(u64),
    MalformedPacket(String),
    /// KeyLocator presence violates the rule for this SignatureType.
    /// NDN Packet Format v0.3 signature.html — KeyLocator table.
    KeyLocatorRule {
        sig_type_code: u64,
    },
}

impl From<TlvError> for PacketError {
    fn from(e: TlvError) -> Self {
        PacketError::Tlv(e)
    }
}

impl From<ndn_foundation_types::name::NameError> for PacketError {
    fn from(e: ndn_foundation_types::name::NameError) -> Self {
        PacketError::MalformedPacket(e.0.into())
    }
}

impl core::fmt::Display for PacketError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PacketError::Tlv(e) => write!(f, "TLV error: {e}"),
            PacketError::UnknownPacketType(t) => write!(f, "unknown packet type {t:#x}"),
            PacketError::MalformedPacket(msg) => write!(f, "malformed packet: {msg}"),
            PacketError::KeyLocatorRule { sig_type_code } => {
                write!(
                    f,
                    "KeyLocator rule violated for SignatureType {sig_type_code}"
                )
            }
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
