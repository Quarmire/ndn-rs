//! Stateless NDN packet codec — encode Interests, decode Data, LP framing.
//!
//! These functions are used by the BLE test apps (Android / iOS) to prepare
//! NDN wire-format packets for transmission over BLE GATT characteristics.

use boltffi::export;
use bytes::Bytes;

use crate::types::{NdnData, NdnError};

/// Stateless NDN packet codec for BLE test apps.
///
/// All methods are static — no engine or runtime needed.
pub struct NdnCodec;

#[export]
impl NdnCodec {
    /// Encode an NDN Interest packet.
    ///
    /// Returns the raw TLV wire bytes ready for transmission.
    ///
    /// # Parameters
    ///
    /// - `name`: NDN name URI, e.g. `"/ndn/ble/test"`.
    /// - `nonce`: 32-bit nonce for loop detection (use a random value).
    pub fn encode_interest(name: String, nonce: u32) -> Result<Vec<u8>, NdnError> {
        use ndn_packet::encode::InterestBuilder;

        let parsed: ndn_packet::Name = name.parse().map_err(|_| NdnError::invalid_name(&name))?;
        let wire = InterestBuilder::new(parsed).build();
        // Patch in the caller's nonce (the builder generates a random one).
        let mut buf = wire.to_vec();
        patch_nonce(&mut buf, nonce);
        Ok(buf)
    }

    /// Decode an NDN Data packet from raw TLV wire bytes.
    ///
    /// Returns the name and content payload, or an error if the bytes are
    /// not a valid Data packet.
    pub fn decode_data(wire: Vec<u8>) -> Result<NdnData, NdnError> {
        let data =
            ndn_packet::Data::decode(Bytes::from(wire)).map_err(NdnError::engine)?;
        Ok(NdnData::from_packet(data))
    }

    /// Wrap a raw NDN packet (Interest or Data) in an NDNLPv2 LpPacket
    /// envelope.
    ///
    /// Use this when talking to a desktop `BleFace` (macOS / Linux) which
    /// expects NDNLPv2 framing on the BLE GATT transport.
    pub fn wrap_lp_packet(payload: Vec<u8>) -> Vec<u8> {
        ndn_packet::lp::encode_lp_packet(&payload).to_vec()
    }

    /// Unwrap an NDNLPv2 LpPacket envelope and return the inner fragment
    /// (Interest or Data wire bytes).
    ///
    /// Returns an error if the input is not a valid LpPacket or has no
    /// fragment payload.
    pub fn unwrap_lp_packet(wire: Vec<u8>) -> Result<Vec<u8>, NdnError> {
        let lp = ndn_packet::lp::LpPacket::decode(Bytes::from(wire))
            .map_err(NdnError::engine)?;
        lp.fragment
            .map(|f| f.to_vec())
            .ok_or_else(|| NdnError::Engine {
                msg: "LpPacket contains no fragment".into(),
            })
    }
}

/// Patch the Nonce TLV (type 0x0A, length 4) inside an encoded Interest.
fn patch_nonce(buf: &mut [u8], nonce: u32) {
    // Scan for the Nonce TLV: type=0x0A, length=0x04, followed by 4 bytes.
    for i in 0..buf.len().saturating_sub(5) {
        if buf[i] == 0x0A && buf[i + 1] == 0x04 {
            buf[i + 2..i + 6].copy_from_slice(&nonce.to_be_bytes());
            return;
        }
    }
}
