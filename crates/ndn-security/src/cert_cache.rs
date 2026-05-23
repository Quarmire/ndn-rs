use crate::TrustError;
use bytes::Bytes;
use dashmap::DashMap;
use ndn_packet::tlv_type;
use ndn_packet::{Data, Name, SignatureType};
use ndn_tlv::TlvReader;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct Certificate {
    pub name: Arc<Name>,
    pub public_key: Bytes,
    pub valid_from: u64,
    pub valid_until: u64,
    pub issuer: Option<Arc<Name>>,
    pub signed_region: Option<Bytes>,
    pub sig_value: Option<Bytes>,
    /// Signature algorithm used by the issuer; the chain validator uses
    /// this to dispatch the right [`Verifier`](crate::Verifier) at the
    /// next chain level.
    pub sig_type: SignatureType,
}

impl Certificate {
    /// Decode a certificate from a Data packet per NDN Certificate Format v2.
    ///
    /// `Content` body is the DER SubjectPublicKeyInfo; for Ed25519 we unwrap
    /// the 32-byte key, other algorithms get SPKI bytes through unchanged.
    /// `ValidityPeriod` lives inside `SignatureInfo` and carries 15-byte
    /// ASCII `YYYYMMDDTHHMMSS` `NotBefore` / `NotAfter` strings.
    pub fn decode(data: &Data) -> Result<Self, TrustError> {
        let content = data.content().ok_or(TrustError::InvalidKey)?;

        let public_key: Bytes = match crate::spki::unwrap_ed25519(content) {
            Some(key) => Bytes::copy_from_slice(&key),
            None if !content.is_empty() => content.clone(),
            None => return Err(TrustError::InvalidKey),
        };

        let (valid_from, valid_until) = decode_validity_period(data.signed_region());

        let issuer = data.sig_info().and_then(|si| si.key_locator_name());
        let sig_type = data
            .sig_info()
            .map(|si| si.sig_type)
            .unwrap_or(SignatureType::SignatureEd25519);

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
            sig_type,
        })
    }

    pub fn is_valid_at(&self, now_ns: u64) -> bool {
        now_ns >= self.valid_from && now_ns <= self.valid_until
    }
}

/// Parse `(valid_from_ns, valid_until_ns)` from the cert's `ValidityPeriod`
/// sub-TLV. Falls back to `(0, u64::MAX)` when absent or malformed.
fn decode_validity_period(signed_region: &[u8]) -> (u64, u64) {
    let mut reader = TlvReader::new(Bytes::copy_from_slice(signed_region));
    while !reader.is_empty() {
        let Ok((typ, val)) = reader.read_tlv() else {
            break;
        };
        if typ != tlv_type::SIGNATURE_INFO {
            continue;
        }
        let mut si = TlvReader::new(val);
        while !si.is_empty() {
            let Ok((stype, sval)) = si.read_tlv() else {
                break;
            };
            if stype != tlv_type::VALIDITY_PERIOD {
                continue;
            }
            let mut vp = TlvReader::new(sval);
            let mut not_before = 0u64;
            let mut not_after = u64::MAX;
            while !vp.is_empty() {
                let Ok((vtype, vval)) = vp.read_tlv() else {
                    break;
                };
                match vtype {
                    t if t == tlv_type::NOT_BEFORE => {
                        if let Some(ns) = crate::iso8601::parse_iso_basic(&vval) {
                            not_before = ns;
                        }
                    }
                    t if t == tlv_type::NOT_AFTER => {
                        if let Some(ns) = crate::iso8601::parse_iso_basic(&vval) {
                            not_after = ns;
                        }
                    }
                    _ => {}
                }
            }
            return (not_before, not_after);
        }
    }
    (0, u64::MAX)
}

/// In-memory certificate cache, indexed by both certificate name and
/// SHA-256 of the public key. Both indices are populated on `insert` so
/// callers resolving a `KeyLocator::Name` or `KeyLocator::KeyDigest` hit
/// the same entries.
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

    /// Look up a certificate by the SHA-256 of its public key. Only matches
    /// certs already in the cache — `KeyDigest` cannot drive a network
    /// fetch because the cert's name is not known to the caller.
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

    fn make_cert_data(pk: &[u8], valid_from: u64, valid_until: u64) -> Bytes {
        let mut signed = TlvWriter::new();

        signed.write_nested(0x07, |w| {
            w.write_tlv(0x08, b"test");
            w.write_tlv(0x08, b"KEY");
            w.write_tlv(0x08, b"k1");
        });

        signed.write_tlv(0x15, pk);

        let nb = crate::iso8601::format_iso_basic(valid_from);
        let na = crate::iso8601::format_iso_basic(valid_until);
        signed.write_nested(0x16, |w| {
            w.write_tlv(0x1b, &[5u8]); // SignatureType = Ed25519
            // Ed25519 requires a KeyLocator per NDN Packet Format v0.3;
            // self-locator is the simplest satisfying fixture.
            w.write_nested(tlv_type::KEY_LOCATOR, |w| {
                w.write_nested(0x07, |w| {
                    w.write_tlv(0x08, b"test");
                    w.write_tlv(0x08, b"KEY");
                    w.write_tlv(0x08, b"k1");
                });
            });
            w.write_nested(tlv_type::VALIDITY_PERIOD, |w| {
                w.write_tlv(tlv_type::NOT_BEFORE, &nb);
                w.write_tlv(tlv_type::NOT_AFTER, &na);
            });
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
        // Second-aligned timestamps so ISO-8601 second resolution
        // round-trips losslessly.
        let pk = vec![1u8; 32];
        let valid_from_ns = 1_700_000_000u64 * 1_000_000_000;
        let valid_until_ns = 1_800_000_000u64 * 1_000_000_000;
        let wire = make_cert_data(&pk, valid_from_ns, valid_until_ns);
        let data = Data::decode(wire).unwrap();
        let cert = Certificate::decode(&data).unwrap();

        assert_eq!(cert.public_key.as_ref(), &pk[..]);
        assert_eq!(cert.valid_from, valid_from_ns);
        assert_eq!(cert.valid_until, valid_until_ns);
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
            w.write_nested(tlv_type::KEY_LOCATOR, |w| {
                w.write_nested(0x07, |w| {
                    w.write_tlv(0x08, b"test");
                });
            });
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
            sig_type: ndn_packet::SignatureType::SignatureEd25519,
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
            sig_type: ndn_packet::SignatureType::SignatureEd25519,
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
            sig_type: ndn_packet::SignatureType::SignatureEd25519,
        };
        assert!(!cert.is_valid_at(999));
        assert!(cert.is_valid_at(1000));
        assert!(cert.is_valid_at(1500));
        assert!(cert.is_valid_at(2000));
        assert!(!cert.is_valid_at(2001));
    }
}
