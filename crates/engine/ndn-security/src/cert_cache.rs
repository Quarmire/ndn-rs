use crate::TrustError;
use bytes::Bytes;
use dashmap::DashMap;
use ndn_packet::tlv_type;
use ndn_packet::{Data, Name};
use ndn_tlv::TlvReader;
use std::sync::Arc;

/// A decoded NDN certificate (a signed Data packet with a public key payload).
#[derive(Clone, Debug)]
pub struct Certificate {
    pub name: Arc<Name>,
    pub public_key: Bytes,
    pub valid_from: u64,
    pub valid_until: u64,
    /// The issuer's key name (from SignatureInfo.KeyLocator).
    /// Populated by `Certificate::decode()`; `None` for manually constructed certs.
    pub issuer: Option<Arc<Name>>,
    /// The signed region of the certificate Data (Name through end of SigInfo).
    /// Needed for chain-walking verification of this cert's own signature.
    pub signed_region: Option<Bytes>,
    /// The signature value of the certificate Data.
    pub sig_value: Option<Bytes>,
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
                        let (vtyp, vval) = vr.read_tlv().map_err(|_| TrustError::InvalidKey)?;
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

        // Extract issuer name from SignatureInfo.KeyLocator for chain walking.
        let issuer = data
            .sig_info()
            .and_then(|si| si.key_locator.as_ref())
            .map(Arc::clone);

        // Preserve signed region and signature value for chain verification.
        let signed_region = Some(Bytes::copy_from_slice(data.signed_region()));
        let sig_value = Some(Bytes::copy_from_slice(data.sig_value()));

        Ok(Certificate {
            name: Arc::clone(&data.name),
            public_key,
            valid_from,
            valid_until,
            issuer,
            signed_region,
            sig_value,
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
///
/// Two indices are maintained: by certificate name (the canonical lookup
/// used when a packet's `KeyLocator` carries a `Name`), and by SHA-256 of
/// the public key (used when the locator carries a `KeyDigest`). Both are
/// populated on `insert` so callers do not need to know which form a
/// future verification will use.
pub struct CertCache {
    local: DashMap<Arc<Name>, Certificate>,
    by_digest: DashMap<[u8; 32], Arc<Name>>,
}

impl CertCache {
    pub fn new() -> Self {
        Self {
            local: DashMap::new(),
            by_digest: DashMap::new(),
        }
    }

    pub fn get(&self, key_name: &Arc<Name>) -> Option<Certificate> {
        self.local.get(key_name).map(|r| r.clone())
    }

    /// Look up a certificate by the SHA-256 of its public key — used to
    /// resolve `KeyLocator` → `KeyDigest` references. Only matches
    /// certificates already in the cache: `KeyDigest` cannot be used to
    /// fetch a certificate over the network because the cert's name is
    /// not known to the caller.
    pub fn get_by_key_digest(&self, digest: &[u8]) -> Option<Certificate> {
        let key: &[u8; 32] = digest.try_into().ok()?;
        let name = self.by_digest.get(key)?.clone();
        self.local.get(&name).map(|r| r.clone())
    }

    pub fn insert(&self, cert: Certificate) {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(&cert.public_key);
        let digest_arr: [u8; 32] = digest.into();
        self.by_digest.insert(digest_arr, Arc::clone(&cert.name));
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
    fn get_by_key_digest_returns_inserted_cert() {
        let pk = vec![7u8; 32];
        let cache = CertCache::new();
        cache.insert(Certificate {
            name: Arc::new(Name::from_components([NameComponent::generic(
                Bytes::from_static(b"k1"),
            )])),
            public_key: Bytes::copy_from_slice(&pk),
            valid_from: 0,
            valid_until: u64::MAX,
            issuer: None,
            signed_region: None,
            sig_value: None,
        });

        // Digest is SHA-256 of the public key bytes.
        use sha2::{Digest, Sha256};
        let expected = Sha256::digest(&pk);
        let cert = cache
            .get_by_key_digest(expected.as_slice())
            .expect("digest lookup should hit");
        assert_eq!(cert.public_key.as_ref(), &pk[..]);
    }

    #[test]
    fn get_by_key_digest_misses_for_unknown_digest() {
        let cache = CertCache::new();
        cache.insert(Certificate {
            name: Arc::new(Name::from_components([NameComponent::generic(
                Bytes::from_static(b"k1"),
            )])),
            public_key: Bytes::copy_from_slice(&[1u8; 32]),
            valid_from: 0,
            valid_until: u64::MAX,
            issuer: None,
            signed_region: None,
            sig_value: None,
        });
        let bogus = [0xFFu8; 32];
        assert!(cache.get_by_key_digest(&bogus).is_none());
    }

    #[test]
    fn get_by_key_digest_rejects_wrong_length() {
        let cache = CertCache::new();
        // 31-byte digest cannot be valid SHA-256.
        assert!(cache.get_by_key_digest(&[0u8; 31]).is_none());
        // 33-byte digest cannot be valid SHA-256.
        assert!(cache.get_by_key_digest(&[0u8; 33]).is_none());
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
            issuer: None,
            signed_region: None,
            sig_value: None,
        };
        assert!(!cert.is_valid_at(999));
        assert!(cert.is_valid_at(1000));
        assert!(cert.is_valid_at(1500));
        assert!(cert.is_valid_at(2000));
        assert!(!cert.is_valid_at(2001));
    }
}
