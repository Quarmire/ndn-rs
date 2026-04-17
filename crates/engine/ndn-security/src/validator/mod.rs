mod chain;

use std::sync::{Arc, RwLock};

use dashmap::DashMap;
use ndn_packet::{Data, Name};

use crate::cert_cache::Certificate;
use crate::cert_fetcher::CertFetcher;
use crate::trust_schema::SchemaRule;
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
///
/// The active [`TrustSchema`] is stored in an `Arc<RwLock<TrustSchema>>` so it
/// can be replaced or extended at runtime without rebuilding the validator.
/// Reads (hot path) acquire a shared lock; writes (management API) acquire an
/// exclusive lock.
pub struct Validator {
    pub(super) schema: Arc<RwLock<TrustSchema>>,
    pub(super) cert_cache: Arc<CertCache>,
    pub(super) verifier: Ed25519Verifier,
    pub(super) max_chain: usize,
    /// Trust anchors — implicitly trusted certificates (chain terminators).
    pub(super) trust_anchors: Arc<DashMap<Arc<Name>, Certificate>>,
    /// Optional fetcher for retrieving missing certificates over NDN.
    pub(super) cert_fetcher: Option<Arc<CertFetcher>>,
}

impl Validator {
    /// Create a validator with a private cert cache (no chain walking).
    pub fn new(schema: TrustSchema) -> Self {
        Self {
            schema: Arc::new(RwLock::new(schema)),
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
            schema: Arc::new(RwLock::new(schema)),
            cert_cache,
            verifier: Ed25519Verifier,
            max_chain,
            trust_anchors,
            cert_fetcher,
        }
    }

    pub fn cert_cache(&self) -> &CertCache {
        &self.cert_cache
    }

    pub fn add_trust_anchor(&self, cert: Certificate) {
        self.cert_cache.insert(cert.clone());
        self.trust_anchors.insert(Arc::clone(&cert.name), cert);
    }

    pub fn is_trust_anchor(&self, name: &Name) -> bool {
        self.trust_anchors.iter().any(|r| r.key().as_ref() == name)
    }

    /// Replace the active trust schema.
    ///
    /// Takes effect immediately for all subsequent validations.
    pub fn set_schema(&self, schema: TrustSchema) {
        *self.schema.write().expect("schema RwLock poisoned") = schema;
    }

    pub fn add_schema_rule(&self, rule: SchemaRule) {
        self.schema
            .write()
            .expect("schema RwLock poisoned")
            .add_rule(rule);
    }

    /// Remove the rule at `index` from the active schema.
    ///
    /// Returns the removed rule, or `None` if `index` is out of bounds.
    pub fn remove_schema_rule(&self, index: usize) -> Option<SchemaRule> {
        let mut guard = self.schema.write().expect("schema RwLock poisoned");
        if index < guard.rules().len() {
            Some(guard.remove_rule(index))
        } else {
            None
        }
    }

    /// Snapshot the current schema rules as `(data_pattern, key_pattern)` text pairs.
    pub fn schema_rules_text(&self) -> Vec<(String, String)> {
        self.schema
            .read()
            .expect("schema RwLock poisoned")
            .rules()
            .iter()
            .map(|r| (r.data_pattern.to_string(), r.key_pattern.to_string()))
            .collect()
    }

    pub fn schema_snapshot(&self) -> TrustSchema {
        self.schema.read().expect("schema RwLock poisoned").clone()
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

        if !self
            .schema
            .read()
            .expect("schema RwLock poisoned")
            .allows(&data.name, key_locator)
        {
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
}

pub(crate) fn now_ns() -> u64 {
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
}
