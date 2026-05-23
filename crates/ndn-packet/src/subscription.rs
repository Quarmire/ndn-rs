use bytes::Bytes;
use ndn_tlv::{TlvReader, TlvWriter};

/// Provisional TLV type for `SubscriptionRequest` inside `ApplicationParameters`.
/// Even, so non-critical: forwarders without this extension ignore it and
/// treat the Interest as a normal long-lifetime one.
pub const TLV_SUBSCRIPTION_REQUEST: u64 = 0x230;

/// Maximum lifetime (seconds) the forwarder will honour for a persistent PIT entry.
pub const MAX_PERSISTENT_LIFETIME_SECS: u32 = 3600;

/// Wire payload for a persistent-Interest request: a 9-byte flat value
/// (`version: u8`, `max_data_count: u32 BE`, `max_lifetime: u32 BE`) inside
/// the `TLV_SUBSCRIPTION_REQUEST` TLV under `ApplicationParameters`. All
/// three fields are mandatory; on parse failure the whole sub-TLV is
/// ignored and the Interest is treated as a normal one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionRequest {
    /// Wire-format version. Must be 1.
    pub version: u8,
    pub max_data_count: u32,
    pub max_lifetime_secs: u32,
}

impl SubscriptionRequest {
    const WIRE_LEN: usize = 9;

    /// Scan an `ApplicationParameters` value for a `SubscriptionRequest`
    /// sub-TLV. `None` means "no persistent request" — fall through to the
    /// classical non-persistent path.
    pub fn find_in(app_params: &Bytes) -> Option<Self> {
        let mut reader = TlvReader::new(app_params.clone());
        while !reader.is_empty() {
            let (typ, val) = reader.read_tlv().ok()?;
            if typ == TLV_SUBSCRIPTION_REQUEST {
                return Self::decode_value(&val);
            }
        }
        None
    }

    /// Encode as a self-contained TLV (type + length + value).
    pub fn encode(&self) -> Bytes {
        let mut val = [0u8; Self::WIRE_LEN];
        val[0] = self.version;
        val[1..5].copy_from_slice(&self.max_data_count.to_be_bytes());
        val[5..9].copy_from_slice(&self.max_lifetime_secs.to_be_bytes());
        let mut w = TlvWriter::new();
        w.write_tlv(TLV_SUBSCRIPTION_REQUEST, &val);
        w.finish()
    }

    fn decode_value(bytes: &Bytes) -> Option<Self> {
        if bytes.len() != Self::WIRE_LEN {
            return None;
        }
        Some(Self {
            version: bytes[0],
            max_data_count: u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]),
            max_lifetime_secs: u32::from_be_bytes([bytes[5], bytes[6], bytes[7], bytes[8]]),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(sr: &SubscriptionRequest) -> Option<SubscriptionRequest> {
        let encoded = sr.encode();
        // encoded = TLV(0x230, 9 bytes of value)
        // To use find_in we need the value, not the full TLV.
        // Simulate an ApplicationParameters payload containing this sub-TLV.
        SubscriptionRequest::find_in(&encoded)
    }

    #[test]
    fn encode_decode_round_trip() {
        let sr = SubscriptionRequest {
            version: 1,
            max_data_count: 100,
            max_lifetime_secs: 60,
        };
        let recovered = round_trip(&sr).expect("should decode");
        assert_eq!(recovered, sr);
    }

    #[test]
    fn find_in_returns_none_when_absent() {
        let other_bytes = Bytes::from_static(b"\x70\x02\xab\xcd"); // TLV type 0x70
        assert!(SubscriptionRequest::find_in(&other_bytes).is_none());
    }

    #[test]
    fn find_in_returns_none_on_wrong_length() {
        // Write a sub-TLV with our type but wrong value length
        let mut w = TlvWriter::new();
        w.write_tlv(TLV_SUBSCRIPTION_REQUEST, &[1u8, 2, 3]); // 3 bytes instead of 9
        let bytes = w.finish();
        assert!(SubscriptionRequest::find_in(&bytes).is_none());
    }

    #[test]
    fn find_in_skips_preceding_sub_tlvs() {
        let sr = SubscriptionRequest {
            version: 1,
            max_data_count: 50,
            max_lifetime_secs: 120,
        };
        let sr_encoded = sr.encode();
        // Prepend an unrelated non-critical sub-TLV
        let mut combined = Vec::new();
        let other_tlv = {
            let mut w = TlvWriter::new();
            w.write_tlv(0x70, b"ignored");
            w.finish()
        };
        combined.extend_from_slice(&other_tlv);
        combined.extend_from_slice(&sr_encoded);
        let bytes = Bytes::from(combined);
        let recovered = SubscriptionRequest::find_in(&bytes).expect("should find after prefix");
        assert_eq!(recovered, sr);
    }

    #[test]
    fn encode_known_wire_layout() {
        let sr = SubscriptionRequest {
            version: 1,
            max_data_count: 0x0000_0064,    // 100
            max_lifetime_secs: 0x0000_003c, // 60
        };
        let wire = sr.encode();
        // Expected: TLV-TYPE=0x230 (varint 0xfd 0x02 0x30), TLV-LEN=9,
        // then version=1, count=0x00000064, lifetime=0x0000003c
        // 0x230 in NDN varint: 0xfd 0x02 0x30
        assert_eq!(&wire[0..3], &[0xfd, 0x02, 0x30]);
        assert_eq!(wire[3], 9); // length
        assert_eq!(wire[4], 1); // version
        assert_eq!(&wire[5..9], &[0, 0, 0, 100]); // max_data_count
        assert_eq!(&wire[9..13], &[0, 0, 0, 60]); // max_lifetime_secs
    }
}
