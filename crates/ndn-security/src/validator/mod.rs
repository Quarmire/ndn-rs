mod chain;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use dashmap::DashMap;
use ndn_packet::{Data, Interest, Name};

use crate::cert_cache::Certificate;
use crate::cert_fetcher::CertFetcher;
use crate::trust_schema::SchemaRule;
use crate::verifier::verify_by_sig_type;
use crate::{CertCache, SafeData, TrustError, TrustSchema, VerifyOutcome};

/// Structured trace returned by [`Validator::trace`].
#[derive(Debug, Clone)]
pub struct ChainTrace {
    pub target: Name,
    /// Chain steps, ordered from `target` upward toward an anchor; each
    /// step records the cert name, its signer, and whether the signer is
    /// in the trust-anchor set.
    pub steps: Vec<ChainTraceStep>,
    /// Schema rules evaluated against each hop, in encounter order.
    pub rules_applied: Vec<TraceRuleApplied>,
    /// `Some` if the chain didn't reach an anchor; `None` when the final
    /// step is an anchor.
    pub failure: Option<TraceFailure>,
}

#[derive(Debug, Clone)]
pub struct ChainTraceStep {
    pub name: Name,
    pub signed_by: Name,
    pub is_anchor: bool,
}

#[derive(Debug, Clone)]
pub struct TraceRuleApplied {
    pub data_pattern: String,
    pub key_pattern: String,
    pub matches: bool,
}

#[derive(Debug, Clone)]
pub enum TraceFailure {
    /// Intermediate cert isn't cached and no fetcher resolved it.
    CertNotFound { name: Name },
    /// Cert has no KeyLocator-name signing reference (e.g. `DigestSha256`
    /// in the middle of an identity chain).
    NoKeyLocator { name: Name },
    /// Chain terminates at a self-signed cert that isn't in the
    /// trust-anchor set.
    AnchorNotTrusted { name: Name },
    /// Chain exceeded `Validator::max_chain` hops without reaching an
    /// anchor.
    ChainTooDeep { limit: usize },
}

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

/// Result of a signed-Interest validation. Mirrors [`ValidationResult`]
/// but carries no [`SafeData`] — Interest validation only surfaces the
/// verdict.
#[derive(Debug)]
pub enum InterestValidationOutcome {
    /// Signature verified and trust schema satisfied.
    Valid,
    /// Signature was cryptographically invalid or schema rejected.
    Invalid(TrustError),
    /// Signing certificate is not yet resolved.
    Pending,
}

/// Validates Data packets against a trust schema and certificate chain.
///
/// The active [`TrustSchema`] is stored in an `Arc<RwLock<TrustSchema>>` so
/// it can be replaced at runtime without rebuilding the validator. The
/// default policy is deny: validation fails unless schema, signature, and
/// chain all check out.
pub struct Validator {
    pub(super) schema: Arc<RwLock<TrustSchema>>,
    pub(super) cert_cache: Arc<CertCache>,
    pub(super) max_chain: usize,
    /// Implicitly trusted certificates that terminate a chain walk.
    pub(super) trust_anchors: Arc<DashMap<Arc<Name>, Certificate>>,
    pub(super) cert_fetcher: Option<Arc<CertFetcher>>,
    /// Monotonic counters bumped on terminal `Valid` / `Invalid` results;
    /// `Pending` is not counted (re-validation bumps when the cert lands).
    pub(super) verified_total: AtomicU64,
    pub(super) rejected_total: AtomicU64,
}

impl Validator {
    /// Create a validator with a private cert cache (no chain walking).
    pub fn new(schema: TrustSchema) -> Self {
        Self {
            schema: Arc::new(RwLock::new(schema)),
            cert_cache: Arc::new(CertCache::new()),
            max_chain: 5,
            trust_anchors: Arc::new(DashMap::new()),
            cert_fetcher: None,
            verified_total: AtomicU64::new(0),
            rejected_total: AtomicU64::new(0),
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
            max_chain,
            trust_anchors,
            cert_fetcher,
            verified_total: AtomicU64::new(0),
            rejected_total: AtomicU64::new(0),
        }
    }

    /// Snapshot `(verified_total, rejected_total)` since construction.
    /// `Pending` results don't bump these counters.
    pub fn counters(&self) -> (u64, u64) {
        (
            self.verified_total.load(Ordering::Relaxed),
            self.rejected_total.load(Ordering::Relaxed),
        )
    }

    pub(super) fn bump_verified(&self) {
        self.verified_total.fetch_add(1, Ordering::Relaxed);
    }
    pub(super) fn bump_rejected(&self) {
        self.rejected_total.fetch_add(1, Ordering::Relaxed);
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

    /// Replace the active trust schema; takes effect on the next validation.
    pub fn set_schema(&self, schema: TrustSchema) {
        *self.schema.write().expect("schema RwLock poisoned") = schema;
    }

    pub fn add_schema_rule(&self, rule: SchemaRule) {
        self.schema
            .write()
            .expect("schema RwLock poisoned")
            .add_rule(rule);
    }

    /// Remove the rule at `index`; returns `None` if out of bounds.
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

    /// Validate a Data packet (single-hop; returns `Pending` if the cert is
    /// missing). For chain walking with async cert fetching, use
    /// [`validate_chain`](Self::validate_chain).
    pub async fn validate(&self, data: &Data) -> ValidationResult {
        let result = self.validate_inner(data).await;
        match &result {
            ValidationResult::Valid(_) => self.bump_verified(),
            ValidationResult::Invalid(_) => self.bump_rejected(),
            ValidationResult::Pending => {}
        }
        result
    }

    async fn validate_inner(&self, data: &Data) -> ValidationResult {
        let Some(sig_info) = data.sig_info() else {
            return ValidationResult::Invalid(TrustError::InvalidSignature);
        };

        // DigestSha256 carries no KeyLocator; verify sig_value ==
        // SHA256(region). Trust is established at a higher layer.
        if sig_info.sig_type == ndn_packet::SignatureType::DigestSha256 {
            return match verify_by_sig_type(
                sig_info.sig_type,
                data.signed_region(),
                data.sig_value(),
                &[],
            )
            .await
            {
                Ok(VerifyOutcome::Valid) => {
                    let safe = SafeData {
                        inner: Data::decode(data.raw().clone()).unwrap(),
                        trust_path: crate::safe_data::TrustPath::DigestSha256,
                        verified_at: now_ns(),
                    };
                    ValidationResult::Valid(Box::new(safe))
                }
                Ok(VerifyOutcome::Invalid) => {
                    ValidationResult::Invalid(TrustError::InvalidSignature)
                }
                Err(e) => ValidationResult::Invalid(e),
            };
        }

        // KeyDigest-form requires chain walking via validate_chain().
        let key_name: std::sync::Arc<Name> = match &sig_info.key_locator {
            Some(ndn_packet::KeyLocator::Name(n)) => std::sync::Arc::new((**n).clone()),
            Some(ndn_packet::KeyLocator::KeyDigest(digest)) => {
                match self.cert_cache.get_by_key_digest(digest) {
                    Some(cert) => std::sync::Arc::clone(&cert.name),
                    None => return ValidationResult::Pending,
                }
            }
            None => return ValidationResult::Invalid(TrustError::InvalidSignature),
        };

        if !self
            .schema
            .read()
            .expect("schema RwLock poisoned")
            .allows(&data.name, &key_name)
        {
            return ValidationResult::Invalid(TrustError::SchemaMismatch);
        }

        let Some(cert) = self.cert_cache.get(&key_name) else {
            return ValidationResult::Pending;
        };

        if !cert.is_valid_at(now_ns()) {
            return ValidationResult::Invalid(TrustError::CertNotFound {
                name: format!("expired or not-yet-valid: {}", key_name),
            });
        }

        match verify_by_sig_type(
            sig_info.sig_type,
            data.signed_region(),
            data.sig_value(),
            &cert.public_key,
        )
        .await
        {
            Ok(VerifyOutcome::Valid) => {
                let safe = SafeData {
                    inner: Data::decode(data.raw().clone()).unwrap(),
                    trust_path: crate::safe_data::TrustPath::CertChain(vec![
                        key_name.as_ref().clone(),
                    ]),
                    verified_at: now_ns(),
                };
                ValidationResult::Valid(Box::new(safe))
            }
            Ok(VerifyOutcome::Invalid) => ValidationResult::Invalid(TrustError::InvalidSignature),
            Err(e) => ValidationResult::Invalid(e),
        }
    }

    /// Validate a signed Interest per NDN Packet Format v0.3 §5.4.
    ///
    /// The signed region is `Interest::signed_region()` (Name without the
    /// trailing PSDC ‖ ApplicationParameters ‖ InterestSignatureInfo);
    /// `sig_value` is `InterestSignatureValue` (TLV-TYPE 0x2E). Trust
    /// establishment matches the Data path.
    pub async fn validate_interest(&self, interest: &Interest) -> InterestValidationOutcome {
        let Some(sig_info) = interest.sig_info() else {
            return InterestValidationOutcome::Invalid(TrustError::InvalidSignature);
        };
        let Some(signed_region) = interest.signed_region() else {
            return InterestValidationOutcome::Invalid(TrustError::InvalidSignature);
        };
        let Some(sig_value) = interest.sig_value() else {
            return InterestValidationOutcome::Invalid(TrustError::InvalidSignature);
        };

        if sig_info.sig_type == ndn_packet::SignatureType::DigestSha256 {
            return match verify_by_sig_type(sig_info.sig_type, &signed_region, sig_value, &[]).await
            {
                Ok(VerifyOutcome::Valid) => InterestValidationOutcome::Valid,
                Ok(VerifyOutcome::Invalid) => {
                    InterestValidationOutcome::Invalid(TrustError::InvalidSignature)
                }
                Err(e) => InterestValidationOutcome::Invalid(e),
            };
        }

        let key_name: std::sync::Arc<Name> = match &sig_info.key_locator {
            Some(ndn_packet::KeyLocator::Name(n)) => std::sync::Arc::new((**n).clone()),
            Some(ndn_packet::KeyLocator::KeyDigest(digest)) => {
                match self.cert_cache.get_by_key_digest(digest) {
                    Some(cert) => std::sync::Arc::clone(&cert.name),
                    None => return InterestValidationOutcome::Pending,
                }
            }
            None => return InterestValidationOutcome::Invalid(TrustError::InvalidSignature),
        };

        if !self
            .schema
            .read()
            .expect("schema RwLock poisoned")
            .allows(&interest.name, &key_name)
        {
            return InterestValidationOutcome::Invalid(TrustError::SchemaMismatch);
        }

        let Some(cert) = self.cert_cache.get(&key_name) else {
            return InterestValidationOutcome::Pending;
        };

        if !cert.is_valid_at(now_ns()) {
            return InterestValidationOutcome::Invalid(TrustError::CertNotFound {
                name: format!("expired or not-yet-valid: {}", key_name),
            });
        }

        match verify_by_sig_type(
            sig_info.sig_type,
            &signed_region,
            sig_value,
            &cert.public_key,
        )
        .await
        {
            Ok(VerifyOutcome::Valid) => InterestValidationOutcome::Valid,
            Ok(VerifyOutcome::Invalid) => {
                InterestValidationOutcome::Invalid(TrustError::InvalidSignature)
            }
            Err(e) => InterestValidationOutcome::Invalid(e),
        }
    }
}

pub(crate) fn now_ns() -> u64 {
    use web_time::{SystemTime, UNIX_EPOCH};
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
            w.write_tlv(0x1b, &[5u8]); // SignatureSha256WithEd25519
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
            sig_type: ndn_packet::SignatureType::SignatureEd25519,
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
            sig_type: ndn_packet::SignatureType::SignatureEd25519,
        };
        let validator = Validator::new(open_schema("data", "key"));
        validator.cert_cache().insert(cert);

        assert!(matches!(
            validator.validate(&data).await,
            ValidationResult::Invalid(_)
        ));
    }

    /// Build a Data wire signed by `signer` with an explicit
    /// `SignatureType` code in the SignatureInfo.
    async fn make_signed_data_with_sig_type(
        signer: &dyn Signer,
        sig_type_code: u8,
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
            w.write_tlv(0x1b, &[sig_type_code]);
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

    /// HMAC-SHA-256 dispatches via `verify_by_sig_type`.
    #[tokio::test]
    async fn hmac_signed_data_validates_through_dispatch() {
        let key_bytes = [0x42u8; 32];
        let key_name = name1("hmac-key");
        let signer = crate::signer::HmacSha256Signer::new(&key_bytes, key_name.clone());
        let data_bytes = make_signed_data_with_sig_type(&signer, 4, "data", "hmac-key").await;
        let data = Data::decode(data_bytes).unwrap();

        let cert = Certificate {
            name: Arc::new(key_name),
            public_key: Bytes::copy_from_slice(&key_bytes),
            valid_from: 0,
            valid_until: u64::MAX,
            issuer: None,
            signed_region: None,
            sig_value: None,
            sig_type: ndn_packet::SignatureType::SignatureHmacWithSha256,
        };
        let validator = Validator::new(open_schema("data", "hmac-key"));
        validator.cert_cache().insert(cert);

        match validator.validate(&data).await {
            ValidationResult::Valid(_) => {}
            other => panic!("HMAC dispatch failed; expected Valid, got: {other:?}"),
        }
    }

    /// DigestSha256 reachable from `Validator::validate` (non-chain path).
    #[tokio::test]
    async fn digest_sha256_data_validates_through_dispatch() {
        use ndn_tlv::TlvWriter;
        use sha2::{Digest, Sha256};

        let nc = {
            let mut w = TlvWriter::new();
            w.write_tlv(0x08, b"data");
            w.finish()
        };
        let name_tlv = {
            let mut w = TlvWriter::new();
            w.write_tlv(0x07, &nc);
            w.finish()
        };
        let stype_tlv = {
            let mut w = TlvWriter::new();
            w.write_tlv(0x1b, &[0u8]); // SignatureType::DigestSha256
            w.finish()
        };
        let sinfo_tlv = {
            let mut w = TlvWriter::new();
            w.write_tlv(0x16, &stype_tlv);
            w.finish()
        };
        let signed_region: Vec<u8> = name_tlv.iter().chain(sinfo_tlv.iter()).copied().collect();
        let digest = Sha256::digest(&signed_region);
        let sval_tlv = {
            let mut w = TlvWriter::new();
            w.write_tlv(0x17, digest.as_slice());
            w.finish()
        };
        let inner: Vec<u8> = signed_region
            .iter()
            .chain(sval_tlv.iter())
            .copied()
            .collect();
        let mut w = TlvWriter::new();
        w.write_tlv(0x06, &inner);
        let data_bytes = w.finish();
        let data = Data::decode(data_bytes).unwrap();

        let validator = Validator::new(TrustSchema::new());
        match validator.validate(&data).await {
            ValidationResult::Valid(_) => {}
            other => {
                panic!("DigestSha256 not reachable on basic validate path; got: {other:?}")
            }
        }
    }

    /// Signed-Interest validation path returns `Valid` for a good signature.
    #[tokio::test]
    async fn validate_signed_interest_returns_valid() {
        use ndn_packet::Interest;
        use ndn_packet::encode::InterestBuilder;

        let seed = [42u8; 32];
        let key_name = name1("ki");
        let pubkey = ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes();

        let cmd_name: Name = "/audit/c11/cmd".parse().unwrap();
        let app_params = bytes::Bytes::from_static(b"params");
        let wire = InterestBuilder::new(cmd_name)
            .app_parameters(app_params)
            .sign_sync(
                ndn_packet::SignatureType::SignatureEd25519,
                Some(&key_name),
                |region| {
                    use ed25519_dalek::Signer as _;
                    let sig = ed25519_dalek::SigningKey::from_bytes(&seed).sign(region);
                    bytes::Bytes::copy_from_slice(&sig.to_bytes())
                },
            );
        let interest = Interest::decode(wire).expect("signed Interest must decode");

        let mut schema = TrustSchema::new();
        schema.add_rule(SchemaRule {
            data_pattern: NamePattern(vec![PatternComponent::MultiCapture("_".into())]),
            key_pattern: NamePattern(vec![PatternComponent::MultiCapture("_".into())]),
        });
        let validator = Validator::new(schema);
        validator.cert_cache().insert(Certificate {
            name: Arc::new(key_name),
            public_key: bytes::Bytes::copy_from_slice(&pubkey),
            valid_from: 0,
            valid_until: u64::MAX,
            issuer: None,
            signed_region: None,
            sig_value: None,
            sig_type: ndn_packet::SignatureType::SignatureEd25519,
        });

        match validator.validate_interest(&interest).await {
            InterestValidationOutcome::Valid => {}
            other => panic!("signed Interest must validate; got: {other:?}"),
        }
    }

    /// Unsigned Interest must surface as `Invalid`, not bypass validation.
    #[tokio::test]
    async fn unsigned_interest_returns_invalid() {
        use ndn_packet::Interest;
        use ndn_packet::encode::encode_interest;

        let cmd_name: Name = "/audit/c11/unsigned".parse().unwrap();
        let wire = encode_interest(&cmd_name, None);
        let interest = Interest::decode(wire).expect("plain Interest must decode");

        let validator = Validator::new(TrustSchema::new());
        match validator.validate_interest(&interest).await {
            InterestValidationOutcome::Invalid(_) => {}
            other => panic!("unsigned Interest must be Invalid; got: {other:?}"),
        }
    }

    /// Advertising sig type 1 (RSA) / 3 (ECDSA) with raw Ed25519 key
    /// bytes must surface as `InvalidKey` — the verifier is reached and
    /// rejects the malformed key, not silently dropped as unsupported.
    #[tokio::test]
    async fn rsa_and_ecdsa_verifiers_are_wired() {
        let signer = Ed25519Signer::from_seed(&[0xFFu8; 32], name1("k"));
        let key_bytes = signer.public_key_bytes();

        let key_name = name1("k");
        let cert = Certificate {
            name: Arc::new(key_name.clone()),
            public_key: Bytes::copy_from_slice(&key_bytes),
            valid_from: 0,
            valid_until: u64::MAX,
            issuer: None,
            signed_region: None,
            sig_value: None,
            sig_type: ndn_packet::SignatureType::SignatureSha256WithRsa,
        };
        let validator = Validator::new(open_schema("data", "k"));
        validator.cert_cache().insert(cert);

        for sig_type_code in [1u8, 3u8] {
            let data_bytes =
                make_signed_data_with_sig_type(&signer, sig_type_code, "data", "k").await;
            let data = Data::decode(data_bytes).unwrap();
            match validator.validate(&data).await {
                ValidationResult::Invalid(TrustError::InvalidKey) => {}
                other => panic!(
                    "sig type {sig_type_code} with non-DER key must yield InvalidKey, got: {other:?}"
                ),
            }
        }
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
            sig_type: ndn_packet::SignatureType::SignatureEd25519,
        };
        let validator = Validator::new(open_schema("data", "key"));
        validator.cert_cache().insert(cert);

        assert!(matches!(
            validator.validate(&data).await,
            ValidationResult::Invalid(_)
        ));
    }
}
