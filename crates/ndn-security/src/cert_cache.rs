use crate::TrustError;
use bytes::Bytes;
use dashmap::DashMap;
use ndn_packet::{Data, Name};
use ndn_packet::tlv_type;
use ndn_tlv::TlvReader;
use std::sync::Arc;

/// A decoded NDN certificate (a signed Data packet with a public key payload).
#[derive(Clone, Debug)]
pub struct Certificate {
    pub name: Arc<Name>,
    pub public_key: Bytes,
    pub valid_from: u64,
    pub valid_until: u64,
}

impl Certificate {
    /// Decode a certificate from a Data packet.
    ///
    /// The Content field is expected to contain:
    /// - TLV type 0x00: raw public key bytes
    /// - TLV type 0xFD (ValidityPeriod): nested tlv_type::NOT_BEFORE (0xFE) + tlv_type::NOT_AFTER (0xFF)
    ///   as big-endian nanosecond timestamps
    pub fn decode(data: &Data) -> Result<Self, TrustError> {
        let content = data.content().ok_or(TrustError::InvalidKey)?;

        let mut public_key: Option<Bytes> = None;
        let mut valid_from: u64 = 0;
        let mut valid_until: u64 = u64::MAX;

        let mut reader = TlvReader::new(content.clone());
        while !reader.is_empty() {
            let (typ, value) = reader.read_tlv().map_err(|_| TrustError::InvalidKey)?;
            match typ {
                0x00 => {
                    public_key = Some(value);
                }
                tlv_type::VALIDITY_PERIOD => {
                    let mut vr = TlvReader::new(value);
                    while !vr.is_empty() {
                        let (vtyp, vval) =
                            vr.read_tlv().map_err(|_| TrustError::InvalidKey)?;
                        match vtyp {
                            tlv_type::NOT_BEFORE => {
                                valid_from = decode_be_u64(&vval);
                            }
                            tlv_type::NOT_AFTER => {
                                valid_until = decode_be_u64(&vval);
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }

        let public_key = public_key.ok_or(TrustError::InvalidKey)?;
        if public_key.is_empty() {
            return Err(TrustError::InvalidKey);
        }

        Ok(Certificate {
            name: Arc::clone(&data.name),
            public_key,
            valid_from,
            valid_until,
        })
    }

    /// Returns `true` if the certificate is valid at the given time (nanoseconds
    /// since Unix epoch).
    pub fn is_valid_at(&self, now_ns: u64) -> bool {
        now_ns >= self.valid_from && now_ns <= self.valid_until
    }
}

/// Decode a big-endian variable-length integer (up to 8 bytes).
fn decode_be_u64(bytes: &[u8]) -> u64 {
    let mut val: u64 = 0;
    for &b in bytes.iter().take(8) {
        val = (val << 8) | b as u64;
    }
    val
}

/// In-memory certificate cache.
///
/// Certificates are just named Data packets — fetching one is a normal NDN
/// Interest. The cache avoids re-fetching recently validated certificates.
pub struct CertCache {
    local: DashMap<Arc<Name>, Certificate>,
}

impl CertCache {
    pub fn new() -> Self {
        Self {
            local: DashMap::new(),
        }
    }

    pub fn get(&self, key_name: &Arc<Name>) -> Option<Certificate> {
        self.local.get(key_name).map(|r| r.clone())
    }

    pub fn insert(&self, cert: Certificate) {
        self.local.insert(Arc::clone(&cert.name), cert);
    }
}

impl Default for CertCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_packet::NameComponent;
    use ndn_tlv::TlvWriter;

    /// Build a minimal Data packet with a certificate Content field.
    fn make_cert_data(pk: &[u8], valid_from: u64, valid_until: u64) -> Bytes {
        let mut signed = TlvWriter::new();

        // Name: /test/KEY/k1
        signed.write_nested(0x07, |w| {
            w.write_tlv(0x08, b"test");
            w.write_tlv(0x08, b"KEY");
            w.write_tlv(0x08, b"k1");
        });

        // Content: public key + validity period
        signed.write_nested(0x15, |w| {
            w.write_tlv(0x00, pk);
            w.write_nested(tlv_type::VALIDITY_PERIOD, |w| {
                w.write_tlv(tlv_type::NOT_BEFORE, &valid_from.to_be_bytes());
                w.write_tlv(tlv_type::NOT_AFTER, &valid_until.to_be_bytes());
            });
        });

        // SignatureInfo (minimal)
        signed.write_nested(0x16, |w| {
            w.write_tlv(0x1b, &[5u8]); // Ed25519
        });

        let signed_region = signed.finish();

        // SignatureValue (dummy)
        let mut outer = TlvWriter::new();
        let sig_val = vec![0u8; 64];
        let mut inner = signed_region.to_vec();
        {
            let mut sw = TlvWriter::new();
            sw.write_tlv(0x17, &sig_val);
            inner.extend_from_slice(&sw.finish());
        }
        outer.write_tlv(0x06, &inner);
        outer.finish()
    }

    #[test]
    fn decode_certificate_from_data() {
        let pk = vec![1u8; 32];
        let wire = make_cert_data(&pk, 1000, 2000);
        let data = Data::decode(wire).unwrap();
        let cert = Certificate::decode(&data).unwrap();

        assert_eq!(cert.public_key.as_ref(), &pk[..]);
        assert_eq!(cert.valid_from, 1000);
        assert_eq!(cert.valid_until, 2000);
        assert_eq!(cert.name.components().len(), 3);
    }

    #[test]
    fn decode_certificate_no_content_fails() {
        // Data with no Content TLV
        let mut signed = TlvWriter::new();
        signed.write_nested(0x07, |w| {
            w.write_tlv(0x08, b"test");
        });
        signed.write_nested(0x16, |w| {
            w.write_tlv(0x1b, &[5u8]);
        });
        let signed_region = signed.finish();
        let mut inner = signed_region.to_vec();
        {
            let mut sw = TlvWriter::new();
            sw.write_tlv(0x17, &[0u8; 64]);
            inner.extend_from_slice(&sw.finish());
        }
        let mut outer = TlvWriter::new();
        outer.write_tlv(0x06, &inner);
        let wire = outer.finish();

        let data = Data::decode(wire).unwrap();
        assert!(Certificate::decode(&data).is_err());
    }

    #[test]
    fn decode_certificate_empty_key_fails() {
        let wire = make_cert_data(&[], 0, u64::MAX);
        let data = Data::decode(wire).unwrap();
        assert!(Certificate::decode(&data).is_err());
    }

    #[test]
    fn is_valid_at_checks_time_range() {
        let cert = Certificate {
            name: Arc::new(Name::from_components([NameComponent::generic(
                Bytes::from_static(b"k"),
            )])),
            public_key: Bytes::from_static(&[1; 32]),
            valid_from: 1000,
            valid_until: 2000,
        };
        assert!(!cert.is_valid_at(999));
        assert!(cert.is_valid_at(1000));
        assert!(cert.is_valid_at(1500));
        assert!(cert.is_valid_at(2000));
        assert!(!cert.is_valid_at(2001));
    }
}
