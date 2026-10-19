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

    pub fn is_valid_now(&self) -> bool {
        self.is_valid_at(now_ns())
    }

    /// The key this certificate certifies: its name without the
    /// `<issuer-id>/<version>` tail ([`crate::cert_name::key_name_of`]); a
    /// legacy key-named certificate is its own key name.
    pub fn key_name(&self) -> Name {
        crate::cert_name::key_name_of(&self.name)
    }

    /// The certificate as its signed Data wire, rebuilt from the retained
    /// signed region and signature value. `None` for a certificate that
    /// carries neither (an unsigned test fixture).
    pub fn data_wire(&self) -> Option<Bytes> {
        let (signed_region, sig_value) = (self.signed_region.as_ref()?, self.sig_value.as_ref()?);
        let mut w = ndn_tlv::TlvWriter::new();
        w.write_nested(tlv_type::DATA, |w| {
            w.write_raw(signed_region);
            w.write_tlv(tlv_type::SIGNATURE_VALUE, sig_value);
        });
        Some(w.finish())
    }

    /// Whether `self` should be preferred over `other` among certificates of
    /// one key: issued later (`valid_from`), then the greater name (the
    /// later version).
    fn is_newer_than(&self, other: &Certificate) -> bool {
        (self.valid_from, self.name.as_ref()) > (other.valid_from, other.name.as_ref())
    }
}

fn now_ns() -> u64 {
    web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// The newest of `certs` valid at `now`, else the newest of all.
fn pick_newest(certs: impl IntoIterator<Item = Certificate>, now: u64) -> Option<Certificate> {
    let mut valid: Option<Certificate> = None;
    let mut any: Option<Certificate> = None;
    for c in certs {
        if c.is_valid_at(now) && valid.as_ref().is_none_or(|v| c.is_newer_than(v)) {
            valid = Some(c.clone());
        }
        if any.as_ref().is_none_or(|a| c.is_newer_than(a)) {
            any = Some(c);
        }
    }
    valid.or(any)
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

/// In-memory certificate cache, indexed by certificate name, by key name and
/// by SHA-256 of the public key.
///
/// A key may hold several certificates at once (NDN Certificate Format v2:
/// `<key>/<issuer-id>/<version>`, e.g. the certificate a renewal replaced and
/// its successor), so lookups take a *prefix*: [`get`](Self::get) with a key
/// name resolves to that key's newest currently valid certificate, with a
/// full certificate name to that certificate. Legacy key-named certificates
/// (named exactly after their key) are found the same way. A lookup only ever
/// returns certificates of the key `name` names, never another key's
/// certificate that merely lies under `name`.
pub struct CertCache {
    local: DashMap<Arc<Name>, Certificate>,
    /// Key name → names of its cached certificates.
    by_key: DashMap<Name, Vec<Arc<Name>>>,
    /// SHA-256 of a public key → the key name it is certified under.
    by_digest: DashMap<[u8; 32], Name>,
}

impl CertCache {
    pub fn new() -> Self {
        Self {
            local: DashMap::new(),
            by_key: DashMap::new(),
            by_digest: DashMap::new(),
        }
    }

    /// The certificate `name` resolves to: among cached certificates of the
    /// key `name` names (a key name, a full certificate name, or a
    /// certificate name without its version) that start with `name`, the
    /// newest one valid now; when
    /// none is valid, the newest one regardless, so a caller can tell an
    /// expired certificate from a missing one. See
    /// [`get_valid`](Self::get_valid) for valid certificates only.
    pub fn get(&self, name: &Arc<Name>) -> Option<Certificate> {
        pick_newest(self.matching(name), now_ns())
    }

    /// As [`get`](Self::get), but only a certificate valid now: `None` when
    /// every cached certificate under `name` has expired (or is not yet
    /// valid), so the caller fetches a current one — e.g. the certificate a
    /// renewal issued in place of an expired one it still caches.
    pub fn get_valid(&self, name: &Name) -> Option<Certificate> {
        let now = now_ns();
        pick_newest(self.matching(name).filter(|c| c.is_valid_at(now)), now)
    }

    /// Every cached certificate under `name` (see [`get`](Self::get)), in no
    /// particular order.
    pub fn all(&self, name: &Name) -> Vec<Certificate> {
        self.matching(name).collect()
    }

    fn matching(&self, name: &Name) -> impl Iterator<Item = Certificate> + '_ {
        let names: Vec<Arc<Name>> = key_candidates(name)
            .into_iter()
            .find_map(|key| self.by_key.get(&key).map(|r| r.value().clone()))
            .unwrap_or_default();
        let name = name.clone();
        names
            .into_iter()
            .filter(move |cn| resolves_to(&name, cn))
            .filter_map(|cn| self.local.get(&cn).map(|r| r.value().clone()))
    }

    /// Look up a certificate by the SHA-256 of its public key: the newest
    /// valid certificate of the key holding that public key. Only matches
    /// certs already in the cache — `KeyDigest` cannot drive a network fetch
    /// because the cert's name is not known to the caller.
    pub fn get_by_key_digest(&self, digest: &[u8]) -> Option<Certificate> {
        use sha2::{Digest, Sha256};
        let digest: &[u8; 32] = digest.try_into().ok()?;
        let key_name = self.by_digest.get(digest)?.value().clone();
        // A key name may (rarely) be certified for other public keys too;
        // only certificates of the digested public key answer.
        let of_key = |c: &Certificate| <[u8; 32]>::from(Sha256::digest(&c.public_key)) == *digest;
        pick_newest(self.matching(&key_name).filter(of_key), now_ns())
    }

    pub fn insert(&self, cert: Certificate) {
        use sha2::{Digest, Sha256};
        let digest: [u8; 32] = Sha256::digest(&cert.public_key).into();
        let key_name = cert.key_name();
        self.by_digest.insert(digest, key_name.clone());
        {
            let mut names = self.by_key.entry(key_name).or_default();
            if !names.contains(&cert.name) {
                names.push(Arc::clone(&cert.name));
            }
        }
        self.local.insert(Arc::clone(&cert.name), cert);
    }

    /// Evict every certificate under `name` (e.g. once its key is revoked):
    /// with a key name, all certificates of that key; with a certificate
    /// name, that certificate. Returns the newest evicted, if any.
    pub fn remove(&self, name: &Name) -> Option<Certificate> {
        use sha2::{Digest, Sha256};
        let removed: Vec<Certificate> = self
            .matching(name)
            .filter_map(|cert| self.local.remove(&cert.name).map(|(_, c)| c))
            .collect();
        for cert in &removed {
            let key_name = cert.key_name();
            if let Some(mut names) = self.by_key.get_mut(&key_name) {
                names.retain(|cn| *cn != cert.name);
            }
            self.by_key.remove_if(&key_name, |_, names| names.is_empty());
            if !self.by_key.contains_key(&key_name) {
                let digest: [u8; 32] = Sha256::digest(&cert.public_key).into();
                self.by_digest.remove_if(&digest, |_, k| *k == key_name);
            }
        }
        pick_newest(removed, now_ns())
    }
}

/// The key names a lookup for `name` can fall under: the key of a full
/// certificate name or of a key name ([`crate::cert_name::key_name_of`]), and
/// for `<key>/<issuer-id>` (a certificate name without its version) that key.
fn key_candidates(name: &Name) -> Vec<Name> {
    let mut keys = vec![crate::cert_name::key_name_of(name)];
    let comps = name.components();
    if comps.len() >= 3 && comps[comps.len() - 3].value.as_ref() == b"KEY" {
        keys.push(Name::from_components(comps[..comps.len() - 1].iter().cloned()));
    }
    keys
}

/// Whether the certificate named `cert` is one `locator` (a KeyLocator: a
/// key name, a certificate name, or one without its version) resolves to: a
/// certificate *of the locator's own key* under that name. A KeyLocator never
/// resolves to another key's certificate — e.g. `/home/bob` to Data someone
/// published under `/home/bob/eve` — so the key a signature is checked with
/// is always the key the hierarchy floor and the schema judged.
pub(crate) fn resolves_to(locator: &Name, cert: &Name) -> bool {
    cert.has_prefix(locator) && key_candidates(locator).contains(&crate::cert_name::key_name_of(cert))
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
    fn remove_evicts_both_indices() {
        let pk = vec![9u8; 32];
        let name = Arc::new(Name::from_components([NameComponent::generic(
            Bytes::from_static(b"k9"),
        )]));
        let cache = CertCache::new();
        cache.insert(Certificate {
            name: Arc::clone(&name),
            public_key: Bytes::copy_from_slice(&pk),
            valid_from: 0,
            valid_until: u64::MAX,
            issuer: None,
            signed_region: None,
            sig_value: None,
            sig_type: ndn_packet::SignatureType::SignatureEd25519,
        });

        assert!(cache.remove(&name).is_some());
        assert!(cache.get(&name).is_none());
        use sha2::{Digest, Sha256};
        assert!(cache.get_by_key_digest(Sha256::digest(&pk).as_slice()).is_none());
        assert!(cache.remove(&name).is_none(), "second remove finds nothing");
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

    fn cert(name: &str, valid_from: u64, valid_until: u64) -> Certificate {
        Certificate {
            name: Arc::new(name.parse().unwrap()),
            public_key: Bytes::from_static(&[4; 32]),
            valid_from,
            valid_until,
            issuer: None,
            signed_region: None,
            sig_value: None,
            sig_type: ndn_packet::SignatureType::SignatureEd25519,
        }
    }

    /// A key name resolves to the key's newest valid certificate, a full
    /// certificate name to that certificate, and a legacy key-named
    /// certificate is found by its key name too.
    #[test]
    fn key_name_resolves_to_newest_valid_certificate() {
        let cache = CertCache::new();
        let key: Arc<Name> = Arc::new("/a/KEY/k".parse().unwrap());
        cache.insert(cert("/a/KEY/k", 1, u64::MAX)); // legacy key-named
        cache.insert(cert("/a/KEY/k/NDNCERT/v=2", 2, u64::MAX));
        cache.insert(cert("/a/KEY/k/NDNCERT/v=3", 3, u64::MAX));
        cache.insert(cert("/a/KEY/k/NDNCERT/v=4", 4, 5)); // expired
        cache.insert(cert("/a/KEY/other/NDNCERT/v=9", 9, u64::MAX));

        let got = cache.get(&key).unwrap();
        assert_eq!(got.name.to_string(), "/a/KEY/k/NDNCERT/v=3");
        assert_eq!(cache.get_valid(&key).unwrap().name, got.name);
        let exact: Arc<Name> = Arc::new("/a/KEY/k/NDNCERT/v=2".parse().unwrap());
        assert_eq!(cache.get(&exact).unwrap().name, exact);
        let issuer: Arc<Name> = Arc::new("/a/KEY/k/NDNCERT".parse().unwrap());
        assert_eq!(cache.get(&issuer).unwrap().name.to_string(), "/a/KEY/k/NDNCERT/v=3");
        assert_eq!(cache.all(&key).len(), 4);

        // An expired certificate alone: `get` still reports it, `get_valid` does not.
        let expired: Arc<Name> = Arc::new("/a/KEY/k/NDNCERT/v=4".parse().unwrap());
        assert!(cache.get(&expired).is_some());
        assert!(cache.get_valid(&expired).is_none());

        // Removing the key evicts every certificate of it, and only those.
        assert!(cache.remove(&key).is_some());
        assert!(cache.get(&key).is_none());
        assert!(cache.get(&Arc::new("/a/KEY/other".parse().unwrap())).is_some());
    }

    /// A KeyLocator resolves only to certificates of its own key: never to
    /// another key's certificate, nor to other Data, that lies under it.
    #[test]
    fn locator_never_resolves_to_another_keys_certificate() {
        let cache = CertCache::new();
        cache.insert(cert("/home/bob/eve/p", 1, u64::MAX));
        cache.insert(cert("/home/bob/eve/KEY/e/NDNCERT/v=1", 1, u64::MAX));
        cache.insert(cert("/a/KEY/k/extra", 1, u64::MAX));

        for locator in ["/home/bob", "/home", "/home/bob/eve", "/a/KEY/k", "/a/KEY"] {
            let locator: Arc<Name> = Arc::new(locator.parse().unwrap());
            assert!(cache.get(&locator).is_none(), "{locator} resolved to a foreign certificate");
            assert!(cache.all(&locator).is_empty());
            assert!(!resolves_to(&locator, &"/home/bob/eve/p".parse().unwrap()));
        }
        // Each still answers for its own key.
        let own: Arc<Name> = Arc::new("/home/bob/eve/p".parse().unwrap());
        assert!(cache.get(&own).is_some());
        let eve: Arc<Name> = Arc::new("/home/bob/eve/KEY/e".parse().unwrap());
        assert!(cache.get(&eve).is_some());
    }
}
