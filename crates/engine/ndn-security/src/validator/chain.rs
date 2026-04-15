use std::collections::HashSet;
use std::sync::Arc;

use ndn_packet::{Data, Name, SignatureType};

use crate::cert_cache::Certificate;
use crate::safe_data::TrustPath;
use crate::verifier::Verifier;
use crate::{SafeData, TrustError, VerifyOutcome};

use super::{ValidationResult, Validator, now_ns};

impl Validator {
    /// Validate a Data packet by walking the full certificate chain.
    ///
    /// Verifies the Data's signature, then walks up the chain — each
    /// certificate's signature is verified using the next certificate's
    /// public key — until a trust anchor is reached. Missing certificates
    /// are fetched via the `CertFetcher` if configured.
    pub async fn validate_chain(&self, data: &Data) -> ValidationResult {
        let Some(sig_info) = data.sig_info() else {
            return ValidationResult::Invalid(TrustError::InvalidSignature);
        };

        // DigestSha256 is self-contained: verify SHA-256(signed_region) == sig_value.
        // No key locator or trust chain is involved.
        if sig_info.sig_type == SignatureType::DigestSha256 {
            use sha2::{Digest, Sha256};
            let hash = Sha256::digest(data.signed_region());
            if hash.as_slice() == data.sig_value() {
                let safe = SafeData {
                    inner: Data::decode(data.raw().clone())
                        .expect("already decoded, re-decode cannot fail"),
                    trust_path: TrustPath::DigestSha256,
                    verified_at: now_ns(),
                };
                return ValidationResult::Valid(Box::new(safe));
            }
            return ValidationResult::Invalid(TrustError::InvalidSignature);
        }

        // Resolve the KeyLocator. NDN allows two forms: a Name pointing at
        // the signer's certificate, or a KeyDigest carrying SHA-256 of the
        // public key. The Name form is the common path; for the KeyDigest
        // form we look the cert up in the local cache by its key digest
        // (the cert must be pre-loaded — there's no way to fetch a cert
        // over the network when only its key digest is known).
        let first_key: Arc<Name> = if let Some(name) = &sig_info.key_locator {
            Arc::clone(name)
        } else if let Some(digest) = &sig_info.key_digest {
            match self.cert_cache.get_by_key_digest(digest) {
                Some(cert) => Arc::clone(&cert.name),
                None => return ValidationResult::Invalid(TrustError::InvalidSignature),
            }
        } else {
            return ValidationResult::Invalid(TrustError::InvalidSignature);
        };

        if !self
            .schema
            .read()
            .expect("schema RwLock poisoned")
            .allows(&data.name, &first_key)
        {
            return ValidationResult::Invalid(TrustError::SchemaMismatch);
        }

        let now = now_ns();
        let mut chain_names: Vec<Name> = Vec::new();
        let mut seen: HashSet<Arc<Name>> = HashSet::new();

        // Current entity to verify: starts with the Data packet itself.
        let mut current_signed_region: &[u8] = data.signed_region();
        let mut current_sig_value: &[u8] = data.sig_value();
        let mut current_key_name: Arc<Name> = first_key;

        // Owned buffers for intermediate cert signed regions / sig values.
        let mut owned_signed_region: bytes::Bytes;
        let mut owned_sig_value: bytes::Bytes;

        for _depth in 0..self.max_chain {
            if !seen.insert(Arc::clone(&current_key_name)) {
                return ValidationResult::Invalid(TrustError::ChainCycle {
                    name: current_key_name.to_string(),
                });
            }

            // Trust anchor terminates the chain.
            if let Some(anchor) = self.trust_anchors.get(&current_key_name) {
                if !anchor.is_valid_at(now) {
                    return ValidationResult::Invalid(TrustError::CertNotFound {
                        name: format!("expired trust anchor: {}", current_key_name),
                    });
                }
                return match self
                    .verifier
                    .verify(current_signed_region, current_sig_value, &anchor.public_key)
                    .await
                {
                    Ok(VerifyOutcome::Valid) => {
                        chain_names.push(current_key_name.as_ref().clone());
                        let safe = SafeData {
                            inner: Data::decode(data.raw().clone()).unwrap(),
                            trust_path: crate::safe_data::TrustPath::CertChain(chain_names),
                            verified_at: now,
                        };
                        ValidationResult::Valid(Box::new(safe))
                    }
                    Ok(VerifyOutcome::Invalid) => {
                        ValidationResult::Invalid(TrustError::InvalidSignature)
                    }
                    Err(e) => ValidationResult::Invalid(e),
                };
            }

            // Fetch or look up the certificate.
            let cert = match self.resolve_cert(&current_key_name).await {
                Some(c) => c,
                None => return ValidationResult::Pending,
            };

            if !cert.is_valid_at(now) {
                return ValidationResult::Invalid(TrustError::CertNotFound {
                    name: format!("expired or not-yet-valid: {}", current_key_name),
                });
            }

            // Verify the current entity's signature with this cert's public key.
            match self
                .verifier
                .verify(current_signed_region, current_sig_value, &cert.public_key)
                .await
            {
                Ok(VerifyOutcome::Valid) => {}
                Ok(VerifyOutcome::Invalid) => {
                    return ValidationResult::Invalid(TrustError::InvalidSignature);
                }
                Err(e) => return ValidationResult::Invalid(e),
            }

            chain_names.push(current_key_name.as_ref().clone());

            // Move up: verify this cert's own signature next.
            let Some(issuer) = &cert.issuer else {
                return ValidationResult::Invalid(TrustError::CertNotFound {
                    name: format!("cert has no issuer: {}", cert.name),
                });
            };
            let Some(sr) = &cert.signed_region else {
                return ValidationResult::Invalid(TrustError::CertNotFound {
                    name: format!("cert missing signed region: {}", cert.name),
                });
            };
            let Some(sv) = &cert.sig_value else {
                return ValidationResult::Invalid(TrustError::CertNotFound {
                    name: format!("cert missing sig value: {}", cert.name),
                });
            };

            owned_signed_region = sr.clone();
            owned_sig_value = sv.clone();
            current_signed_region = &owned_signed_region;
            current_sig_value = &owned_sig_value;
            current_key_name = Arc::clone(issuer);
        }

        ValidationResult::Invalid(TrustError::ChainTooDeep {
            limit: self.max_chain,
        })
    }

    /// Try to resolve a certificate from cache or by fetching.
    async fn resolve_cert(&self, name: &Arc<Name>) -> Option<Certificate> {
        if let Some(cert) = self.cert_cache.get(name) {
            return Some(cert);
        }
        if let Some(fetcher) = &self.cert_fetcher {
            fetcher.fetch(name).await.ok()
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TrustSchema;
    use crate::cert_cache::Certificate;
    use crate::signer::{Ed25519Signer, Signer};
    use crate::trust_schema::{NamePattern, PatternComponent};
    use bytes::Bytes;
    use ndn_packet::{Name, NameComponent};
    use std::sync::Arc;

    fn comp(s: &'static str) -> NameComponent {
        NameComponent::generic(Bytes::from_static(s.as_bytes()))
    }
    fn name1(c: &'static str) -> Name {
        Name::from_components([comp(c)])
    }

    /// Build a Data TLV signed with `signer`.
    async fn make_signed_data(
        signer: &Ed25519Signer,
        data_comp: &'static str,
        key_comp: &'static str,
    ) -> Bytes {
        use ndn_tlv::TlvWriter;

        let nc = {
            let mut w = TlvWriter::new();
            w.write_tlv(0x08, data_comp.as_bytes());
            w.finish()
        };
        let name_tlv = {
            let mut w = TlvWriter::new();
            w.write_tlv(0x07, &nc);
            w.finish()
        };

        let knc = {
            let mut w = TlvWriter::new();
            w.write_tlv(0x08, key_comp.as_bytes());
            w.finish()
        };
        let kname_tlv = {
            let mut w = TlvWriter::new();
            w.write_tlv(0x07, &knc);
            w.finish()
        };
        let kloc_tlv = {
            let mut w = TlvWriter::new();
            w.write_tlv(0x1c, &kname_tlv);
            w.finish()
        };
        let stype_tlv = {
            let mut w = TlvWriter::new();
            w.write_tlv(0x1b, &[7u8]);
            w.finish()
        };
        let sinfo_inner: Vec<u8> = stype_tlv.iter().chain(kloc_tlv.iter()).copied().collect();
        let sinfo_tlv = {
            let mut w = TlvWriter::new();
            w.write_tlv(0x16, &sinfo_inner);
            w.finish()
        };

        let signed_region: Vec<u8> = name_tlv.iter().chain(sinfo_tlv.iter()).copied().collect();
        let sig = signer.sign(&signed_region).await.unwrap();

        let sval_tlv = {
            let mut w = TlvWriter::new();
            w.write_tlv(0x17, &sig);
            w.finish()
        };
        let inner: Vec<u8> = signed_region
            .iter()
            .chain(sval_tlv.iter())
            .copied()
            .collect();
        let mut w = TlvWriter::new();
        w.write_tlv(0x06, &inner);
        w.finish()
    }

    /// Build a certificate Data packet: a Data whose name is `cert_name`,
    /// Content contains the subject's public key, signed by `issuer_signer`.
    async fn make_cert_data_packet(
        cert_name: &Name,
        subject_pk: &[u8],
        issuer_signer: &Ed25519Signer,
    ) -> Bytes {
        use ndn_tlv::TlvWriter;

        let name_inner = {
            let mut w = TlvWriter::new();
            for c in cert_name.components() {
                w.write_tlv(c.typ, &c.value);
            }
            w.finish()
        };
        let name_tlv = {
            let mut w = TlvWriter::new();
            w.write_tlv(0x07, &name_inner);
            w.finish()
        };

        let content_tlv = {
            let mut w = TlvWriter::new();
            w.write_nested(0x15, |w| {
                w.write_tlv(0x00, subject_pk);
            });
            w.finish()
        };

        let issuer_name_inner = {
            let mut w = TlvWriter::new();
            for c in issuer_signer.key_name().components() {
                w.write_tlv(c.typ, &c.value);
            }
            w.finish()
        };
        let sinfo_tlv = {
            let mut w = TlvWriter::new();
            w.write_nested(0x16, |w| {
                w.write_tlv(0x1b, &[7u8]);
                w.write_nested(0x1c, |w| {
                    w.write_tlv(0x07, &issuer_name_inner);
                });
            });
            w.finish()
        };

        let signed_region: Vec<u8> = name_tlv
            .iter()
            .chain(content_tlv.iter())
            .chain(sinfo_tlv.iter())
            .copied()
            .collect();
        let sig = issuer_signer.sign(&signed_region).await.unwrap();

        let sval_tlv = {
            let mut w = TlvWriter::new();
            w.write_tlv(0x17, &sig);
            w.finish()
        };
        let inner: Vec<u8> = signed_region
            .iter()
            .chain(sval_tlv.iter())
            .copied()
            .collect();
        let mut w = TlvWriter::new();
        w.write_tlv(0x06, &inner);
        w.finish()
    }

    /// Build a wildcard schema that allows any data -> any key.
    fn wildcard_schema() -> TrustSchema {
        use crate::trust_schema::SchemaRule;
        let mut schema = TrustSchema::new();
        schema.add_rule(SchemaRule {
            data_pattern: NamePattern(vec![PatternComponent::MultiCapture("_".into())]),
            key_pattern: NamePattern(vec![PatternComponent::MultiCapture("_".into())]),
        });
        schema
    }

    #[tokio::test]
    async fn chain_walk_data_to_anchor() {
        // Chain: Data(/data) -> cert(/key) -> anchor(/anchor)
        let anchor_seed = [20u8; 32];
        let anchor_name = name1("anchor");
        let anchor_signer = Ed25519Signer::from_seed(&anchor_seed, anchor_name.clone());
        let anchor_pk = ed25519_dalek::SigningKey::from_bytes(&anchor_seed)
            .verifying_key()
            .to_bytes();

        let key_seed = [21u8; 32];
        let key_name = name1("key");
        let key_signer = Ed25519Signer::from_seed(&key_seed, key_name.clone());
        let key_pk = ed25519_dalek::SigningKey::from_bytes(&key_seed)
            .verifying_key()
            .to_bytes();

        let cert_wire = make_cert_data_packet(&key_name, &key_pk, &anchor_signer).await;
        let cert_data = Data::decode(cert_wire).unwrap();
        let cert = Certificate::decode(&cert_data).unwrap();

        let data_bytes = make_signed_data(&key_signer, "data", "key").await;
        let data = Data::decode(data_bytes).unwrap();

        let validator = Validator::new(wildcard_schema());
        validator.add_trust_anchor(Certificate {
            name: Arc::new(anchor_name),
            public_key: Bytes::copy_from_slice(&anchor_pk),
            valid_from: 0,
            valid_until: u64::MAX,
            issuer: None,
            signed_region: None,
            sig_value: None,
        });
        validator.cert_cache().insert(cert);

        match validator.validate_chain(&data).await {
            ValidationResult::Valid(safe) => {
                assert_eq!(safe.inner.name, data.name);
            }
            ValidationResult::Invalid(e) => panic!("expected Valid, got Invalid: {e}"),
            ValidationResult::Pending => panic!("expected Valid, got Pending"),
        }
    }

    #[tokio::test]
    async fn chain_walk_missing_cert_returns_pending() {
        let key_seed = [22u8; 32];
        let key_name = name1("key");
        let key_signer = Ed25519Signer::from_seed(&key_seed, key_name);

        let data_bytes = make_signed_data(&key_signer, "data", "key").await;
        let data = Data::decode(data_bytes).unwrap();

        let validator = Validator::new(wildcard_schema());
        assert!(matches!(
            validator.validate_chain(&data).await,
            ValidationResult::Pending
        ));
    }

    /// Build a Data TLV signed with `signer` whose KeyLocator carries a
    /// KeyDigest (SHA-256 of `signer`'s public key) instead of a Name.
    /// Used to exercise the digest-form KeyLocator fallback in
    /// `validate_chain`.
    async fn make_signed_data_with_key_digest(
        signer: &Ed25519Signer,
        signer_pk: &[u8],
        data_comp: &'static str,
    ) -> Bytes {
        use ndn_tlv::TlvWriter;

        let nc = {
            let mut w = TlvWriter::new();
            w.write_tlv(0x08, data_comp.as_bytes());
            w.finish()
        };
        let name_tlv = {
            let mut w = TlvWriter::new();
            w.write_tlv(0x07, &nc);
            w.finish()
        };

        // KeyLocator carrying KeyDigest = SHA-256(public key).
        let digest = {
            use sha2::{Digest, Sha256};
            Sha256::digest(signer_pk)
        };
        let kloc_tlv = {
            let mut w = TlvWriter::new();
            w.write_nested(0x1c, |w| {
                w.write_tlv(0x1d, digest.as_slice());
            });
            w.finish()
        };
        let stype_tlv = {
            let mut w = TlvWriter::new();
            w.write_tlv(0x1b, &[7u8]); // Ed25519
            w.finish()
        };
        let sinfo_inner: Vec<u8> = stype_tlv.iter().chain(kloc_tlv.iter()).copied().collect();
        let sinfo_tlv = {
            let mut w = TlvWriter::new();
            w.write_tlv(0x16, &sinfo_inner);
            w.finish()
        };

        let signed_region: Vec<u8> = name_tlv.iter().chain(sinfo_tlv.iter()).copied().collect();
        let sig = signer.sign(&signed_region).await.unwrap();

        let sval_tlv = {
            let mut w = TlvWriter::new();
            w.write_tlv(0x17, &sig);
            w.finish()
        };
        let inner: Vec<u8> = signed_region
            .iter()
            .chain(sval_tlv.iter())
            .copied()
            .collect();
        let mut w = TlvWriter::new();
        w.write_tlv(0x06, &inner);
        w.finish()
    }

    #[tokio::test]
    async fn chain_walk_resolves_key_digest_via_cache() {
        // Same shape as chain_walk_data_to_anchor, but the Data's
        // KeyLocator is a KeyDigest, not a Name. The validator must
        // resolve the digest against the cert cache before the chain
        // walk proceeds.
        let anchor_seed = [30u8; 32];
        let anchor_name = name1("anchor");
        let anchor_signer = Ed25519Signer::from_seed(&anchor_seed, anchor_name.clone());
        let anchor_pk = ed25519_dalek::SigningKey::from_bytes(&anchor_seed)
            .verifying_key()
            .to_bytes();

        let key_seed = [31u8; 32];
        let key_name = name1("key");
        let key_signer = Ed25519Signer::from_seed(&key_seed, key_name.clone());
        let key_pk = ed25519_dalek::SigningKey::from_bytes(&key_seed)
            .verifying_key()
            .to_bytes();

        let cert_wire = make_cert_data_packet(&key_name, &key_pk, &anchor_signer).await;
        let cert_data = Data::decode(cert_wire).unwrap();
        let cert = Certificate::decode(&cert_data).unwrap();

        let data_bytes = make_signed_data_with_key_digest(&key_signer, &key_pk, "data").await;
        let data = Data::decode(data_bytes).unwrap();

        let validator = Validator::new(wildcard_schema());
        validator.add_trust_anchor(Certificate {
            name: Arc::new(anchor_name),
            public_key: Bytes::copy_from_slice(&anchor_pk),
            valid_from: 0,
            valid_until: u64::MAX,
            issuer: None,
            signed_region: None,
            sig_value: None,
        });
        validator.cert_cache().insert(cert);

        match validator.validate_chain(&data).await {
            ValidationResult::Valid(safe) => {
                assert_eq!(safe.inner.name, data.name);
            }
            ValidationResult::Invalid(e) => {
                panic!("expected Valid, got Invalid: {e}")
            }
            ValidationResult::Pending => panic!("expected Valid, got Pending"),
        }
    }

    #[tokio::test]
    async fn chain_walk_key_digest_uncached_returns_invalid() {
        // KeyDigest cannot be fetched over the network — if the cert is
        // not in the cache, validation must fail rather than hang.
        let key_seed = [32u8; 32];
        let key_name = name1("key");
        let key_signer = Ed25519Signer::from_seed(&key_seed, key_name);
        let key_pk = ed25519_dalek::SigningKey::from_bytes(&key_seed)
            .verifying_key()
            .to_bytes();

        let data_bytes = make_signed_data_with_key_digest(&key_signer, &key_pk, "data").await;
        let data = Data::decode(data_bytes).unwrap();

        let validator = Validator::new(wildcard_schema());
        match validator.validate_chain(&data).await {
            ValidationResult::Invalid(TrustError::InvalidSignature) => {}
            other => panic!("expected Invalid(InvalidSignature), got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn chain_walk_depth_limit() {
        let seed = [23u8; 32];
        let key_name = name1("key");
        let signer = Ed25519Signer::from_seed(&seed, key_name.clone());
        let pk = ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes();

        let cert_wire = make_cert_data_packet(&key_name, &pk, &signer).await;
        let cert_data = Data::decode(cert_wire).unwrap();
        let cert = Certificate::decode(&cert_data).unwrap();

        let data_bytes = make_signed_data(&signer, "data", "key").await;
        let data = Data::decode(data_bytes).unwrap();

        let validator = Validator::new(wildcard_schema());
        validator.cert_cache().insert(cert);

        match validator.validate_chain(&data).await {
            ValidationResult::Invalid(TrustError::ChainCycle { .. }) => {}
            other => panic!("expected ChainCycle, got: {other:?}"),
        }
    }
}
