use std::collections::HashSet;
use std::sync::Arc;

use dashmap::DashMap;
use ndn_packet::{Data, Name};

use crate::cert_cache::Certificate;
use crate::cert_fetcher::CertFetcher;
use crate::verifier::Verifier;
use crate::{CertCache, Ed25519Verifier, SafeData, TrustError, TrustSchema, VerifyOutcome};

/// Result of a validation attempt.
#[derive(Debug)]
pub enum ValidationResult {
    /// Signature verified and trust schema satisfied.
    Valid(Box<SafeData>),
    /// Signature was cryptographically invalid or schema rejected.
    Invalid(TrustError),
    /// Certificate chain is not yet resolved; validation is async.
    Pending,
}

/// Validates Data packets against a trust schema and certificate chain.
pub struct Validator {
    schema: TrustSchema,
    cert_cache: Arc<CertCache>,
    verifier: Ed25519Verifier,
    max_chain: usize,
    /// Trust anchors — implicitly trusted certificates (chain terminators).
    trust_anchors: Arc<DashMap<Arc<Name>, Certificate>>,
    /// Optional fetcher for retrieving missing certificates over NDN.
    cert_fetcher: Option<Arc<CertFetcher>>,
}

impl Validator {
    /// Create a validator with a private cert cache (no chain walking).
    pub fn new(schema: TrustSchema) -> Self {
        Self {
            schema,
            cert_cache: Arc::new(CertCache::new()),
            verifier: Ed25519Verifier,
            max_chain: 5,
            trust_anchors: Arc::new(DashMap::new()),
            cert_fetcher: None,
        }
    }

    /// Create a validator wired to shared infrastructure for chain walking.
    pub fn with_chain(
        schema: TrustSchema,
        cert_cache: Arc<CertCache>,
        trust_anchors: Arc<DashMap<Arc<Name>, Certificate>>,
        cert_fetcher: Option<Arc<CertFetcher>>,
        max_chain: usize,
    ) -> Self {
        Self {
            schema,
            cert_cache,
            verifier: Ed25519Verifier,
            max_chain,
            trust_anchors,
            cert_fetcher,
        }
    }

    /// Access the certificate cache.
    pub fn cert_cache(&self) -> &CertCache {
        &self.cert_cache
    }

    /// Register a trust anchor.
    pub fn add_trust_anchor(&self, cert: Certificate) {
        self.cert_cache.insert(cert.clone());
        self.trust_anchors.insert(Arc::clone(&cert.name), cert);
    }

    /// Check if a name is a trust anchor.
    pub fn is_trust_anchor(&self, name: &Name) -> bool {
        self.trust_anchors.iter().any(|r| r.key().as_ref() == name)
    }

    /// Validate a Data packet (single-hop, returns Pending if cert missing).
    ///
    /// For full chain walking with async cert fetching, use `validate_chain`.
    pub async fn validate(&self, data: &Data) -> ValidationResult {
        let Some(sig_info) = data.sig_info() else {
            return ValidationResult::Invalid(TrustError::InvalidSignature);
        };
        let Some(key_locator) = &sig_info.key_locator else {
            return ValidationResult::Invalid(TrustError::InvalidSignature);
        };

        if !self.schema.allows(&data.name, key_locator) {
            return ValidationResult::Invalid(TrustError::SchemaMismatch);
        }

        let Some(cert) = self.cert_cache.get(key_locator) else {
            return ValidationResult::Pending;
        };

        if !cert.is_valid_at(now_ns()) {
            return ValidationResult::Invalid(TrustError::CertNotFound {
                name: format!("expired or not-yet-valid: {}", key_locator),
            });
        }

        match self
            .verifier
            .verify(data.signed_region(), data.sig_value(), &cert.public_key)
            .await
        {
            Ok(VerifyOutcome::Valid) => {
                let safe = SafeData {
                    inner: Data::decode(data.raw().clone()).unwrap(),
                    trust_path: crate::safe_data::TrustPath::CertChain(vec![
                        key_locator.as_ref().clone(),
                    ]),
                    verified_at: now_ns(),
                };
                ValidationResult::Valid(Box::new(safe))
            }
            Ok(VerifyOutcome::Invalid) => ValidationResult::Invalid(TrustError::InvalidSignature),
            Err(e) => ValidationResult::Invalid(e),
        }
    }

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
        let Some(first_key) = &sig_info.key_locator else {
            return ValidationResult::Invalid(TrustError::InvalidSignature);
        };

        if !self.schema.allows(&data.name, first_key) {
            return ValidationResult::Invalid(TrustError::SchemaMismatch);
        }

        let now = now_ns();
        let mut chain_names: Vec<Name> = Vec::new();
        let mut seen: HashSet<Arc<Name>> = HashSet::new();

        // Current entity to verify: starts with the Data packet itself.
        let mut current_signed_region: &[u8] = data.signed_region();
        let mut current_sig_value: &[u8] = data.sig_value();
        let mut current_key_name: Arc<Name> = Arc::clone(first_key);

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

fn now_ns() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert_cache::Certificate;
    use crate::signer::{Ed25519Signer, Signer};
    use crate::trust_schema::{NamePattern, PatternComponent, SchemaRule};
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
    ///
    /// Structure: DATA > NAME(/data_comp) + SIGINFO(Ed25519, key=/key_comp) + SIGVALUE
    /// The signed region is NAME + SIGINFO (everything inside DATA before SIGVALUE).
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

    fn open_schema(data_comp: &'static str, key_comp: &'static str) -> TrustSchema {
        let mut schema = TrustSchema::new();
        schema.add_rule(SchemaRule {
            data_pattern: NamePattern(vec![PatternComponent::Literal(comp(data_comp))]),
            key_pattern: NamePattern(vec![PatternComponent::Literal(comp(key_comp))]),
        });
        schema
    }

    #[tokio::test]
    async fn no_sig_info_returns_invalid() {
        // A Data with no SignatureInfo (just name + content)
        use ndn_tlv::TlvWriter;
        let nc = {
            let mut w = TlvWriter::new();
            w.write_tlv(0x08, b"test");
            w.finish()
        };
        let name_tlv = {
            let mut w = TlvWriter::new();
            w.write_tlv(0x07, &nc);
            w.finish()
        };
        let inner: Vec<u8> = name_tlv.to_vec();
        let data_bytes = {
            let mut w = TlvWriter::new();
            w.write_tlv(0x06, &inner);
            w.finish()
        };
        let data = Data::decode(data_bytes).unwrap();

        let validator = Validator::new(TrustSchema::new());
        assert!(matches!(
            validator.validate(&data).await,
            ValidationResult::Invalid(_)
        ));
    }

    #[tokio::test]
    async fn schema_mismatch_returns_invalid() {
        let seed = [10u8; 32];
        let key_name = name1("key");
        let signer = Ed25519Signer::from_seed(&seed, key_name.clone());
        let data_bytes = make_signed_data(&signer, "data", "key").await;
        let data = Data::decode(data_bytes).unwrap();

        // Schema only allows /other → /key, not /data → /key
        let mut schema = TrustSchema::new();
        schema.add_rule(SchemaRule {
            data_pattern: NamePattern(vec![PatternComponent::Literal(comp("other"))]),
            key_pattern: NamePattern(vec![PatternComponent::Literal(comp("key"))]),
        });

        let validator = Validator::new(schema);
        assert!(matches!(
            validator.validate(&data).await,
            ValidationResult::Invalid(_)
        ));
    }

    #[tokio::test]
    async fn no_cert_returns_pending() {
        let seed = [11u8; 32];
        let key_name = name1("key");
        let signer = Ed25519Signer::from_seed(&seed, key_name);
        let data_bytes = make_signed_data(&signer, "data", "key").await;
        let data = Data::decode(data_bytes).unwrap();

        let validator = Validator::new(open_schema("data", "key"));
        assert!(matches!(
            validator.validate(&data).await,
            ValidationResult::Pending
        ));
    }

    #[tokio::test]
    async fn valid_signature_returns_valid() {
        let seed = [12u8; 32];
        let key_name = name1("key");
        let signer = Ed25519Signer::from_seed(&seed, key_name.clone());
        let data_bytes = make_signed_data(&signer, "data", "key").await;
        let data = Data::decode(data_bytes).unwrap();

        let vk_bytes = ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes();
        let cert = Certificate {
            name: Arc::new(key_name),
            public_key: Bytes::copy_from_slice(&vk_bytes),
            valid_from: 0,
            valid_until: u64::MAX,
            issuer: None,
            signed_region: None,
            sig_value: None,
        };
        let validator = Validator::new(open_schema("data", "key"));
        validator.cert_cache().insert(cert);

        assert!(matches!(
            validator.validate(&data).await,
            ValidationResult::Valid(_)
        ));
    }

    #[tokio::test]
    async fn expired_cert_returns_invalid() {
        let seed = [15u8; 32];
        let key_name = name1("key");
        let signer = Ed25519Signer::from_seed(&seed, key_name.clone());
        let data_bytes = make_signed_data(&signer, "data", "key").await;
        let data = Data::decode(data_bytes).unwrap();

        let vk_bytes = ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes();
        let cert = Certificate {
            name: Arc::new(key_name),
            public_key: Bytes::copy_from_slice(&vk_bytes),
            valid_from: 0,
            valid_until: 1, // expired in 1970
            issuer: None,
            signed_region: None,
            sig_value: None,
        };
        let validator = Validator::new(open_schema("data", "key"));
        validator.cert_cache().insert(cert);

        assert!(matches!(
            validator.validate(&data).await,
            ValidationResult::Invalid(_)
        ));
    }

    #[tokio::test]
    async fn invalid_signature_returns_invalid() {
        // Sign with seed A but put seed B's public key in the cert cache
        let seed_a = [13u8; 32];
        let seed_b = [14u8; 32];
        let key_name = name1("key");
        let signer = Ed25519Signer::from_seed(&seed_a, key_name.clone());
        let data_bytes = make_signed_data(&signer, "data", "key").await;
        let data = Data::decode(data_bytes).unwrap();

        let wrong_pk = ed25519_dalek::SigningKey::from_bytes(&seed_b)
            .verifying_key()
            .to_bytes();
        let cert = Certificate {
            name: Arc::new(key_name),
            public_key: Bytes::copy_from_slice(&wrong_pk),
            valid_from: 0,
            valid_until: u64::MAX,
            issuer: None,
            signed_region: None,
            sig_value: None,
        };
        let validator = Validator::new(open_schema("data", "key"));
        validator.cert_cache().insert(cert);

        assert!(matches!(
            validator.validate(&data).await,
            ValidationResult::Invalid(_)
        ));
    }

    // --- Chain-walking tests ---

    /// Build a certificate Data packet: a Data whose name is `cert_name`,
    /// Content contains the subject's public key, signed by `issuer_signer`.
    /// Returns the wire bytes.
    async fn make_cert_data_packet(
        cert_name: &Name,
        subject_pk: &[u8],
        issuer_signer: &Ed25519Signer,
    ) -> Bytes {
        use ndn_tlv::TlvWriter;

        // Name TLV
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

        // Content: public key
        let content_tlv = {
            let mut w = TlvWriter::new();
            w.write_nested(0x15, |w| {
                w.write_tlv(0x00, subject_pk);
            });
            w.finish()
        };

        // SignatureInfo with KeyLocator → issuer name
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
                w.write_tlv(0x1b, &[7u8]); // sig type
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

    /// Build a wildcard schema that allows any data → any key.
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
        // Chain: Data(/data) → cert(/key) → anchor(/anchor)
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

        // Build cert Data: /key signed by /anchor, containing key_pk
        let cert_wire = make_cert_data_packet(&key_name, &key_pk, &anchor_signer).await;
        let cert_data = Data::decode(cert_wire).unwrap();
        let cert = Certificate::decode(&cert_data).unwrap();

        // Build Data: /data signed by /key
        let data_bytes = make_signed_data(&key_signer, "data", "key").await;
        let data = Data::decode(data_bytes).unwrap();

        let validator = Validator::new(wildcard_schema());
        // Register anchor
        validator.add_trust_anchor(Certificate {
            name: Arc::new(anchor_name),
            public_key: Bytes::copy_from_slice(&anchor_pk),
            valid_from: 0,
            valid_until: u64::MAX,
            issuer: None,
            signed_region: None,
            sig_value: None,
        });
        // Insert intermediate cert
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

        // No certs, no anchors, no fetcher.
        let validator = Validator::new(wildcard_schema());
        assert!(matches!(
            validator.validate_chain(&data).await,
            ValidationResult::Pending
        ));
    }

    #[tokio::test]
    async fn chain_walk_depth_limit() {
        // Self-referencing cert: /key signed by /key (cycle).
        let seed = [23u8; 32];
        let key_name = name1("key");
        let signer = Ed25519Signer::from_seed(&seed, key_name.clone());
        let pk = ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes();

        // Cert for /key, signed by /key (self-signed but NOT a trust anchor).
        let cert_wire = make_cert_data_packet(&key_name, &pk, &signer).await;
        let cert_data = Data::decode(cert_wire).unwrap();
        let cert = Certificate::decode(&cert_data).unwrap();

        let data_bytes = make_signed_data(&signer, "data", "key").await;
        let data = Data::decode(data_bytes).unwrap();

        let validator = Validator::new(wildcard_schema());
        validator.cert_cache().insert(cert);

        // Should detect cycle, not loop forever.
        match validator.validate_chain(&data).await {
            ValidationResult::Invalid(TrustError::ChainCycle { .. }) => {} // expected
            other => panic!("expected ChainCycle, got: {other:?}"),
        }
    }
}
