use std::collections::HashSet;
use std::sync::Arc;

use ndn_packet::{Data, Interest, KeyLocator, Name, SignatureType};

use crate::cert_cache::Certificate;
use crate::safe_data::TrustPath;
use crate::verifier::verify_by_sig_type;
use crate::{SafeData, TrustError, VerifyOutcome};

use super::{
    ChainTrace, ChainTraceStep, InterestValidationOutcome, TraceFailure, TraceRuleApplied,
    ValidationResult, Validator, now_ns,
};

/// Outcome of [`Validator::walk_to_anchor`] — the shared chain-walk core used by
/// both the Data and signed-Interest fetch-enabled validation paths.
enum WalkOutcome {
    /// The chain reached a trust anchor; carries the cert names walked.
    Anchored(Vec<Name>),
    /// A cert in the chain couldn't be resolved (cache miss + no/failed fetch).
    Pending,
    /// The chain is invalid (bad signature, schema mismatch, revoked, cycle, …).
    Invalid(TrustError),
}

impl Validator {
    /// Validate by walking the full certificate chain.
    ///
    /// Verifies the Data's signature, then each intermediate cert against
    /// its issuer's key, until a trust anchor terminates the walk. Missing
    /// certificates are fetched via the [`CertFetcher`] if configured.
    pub async fn validate_chain(&self, data: &Data) -> ValidationResult {
        let result = self.validate_chain_inner(data).await;
        match &result {
            ValidationResult::Valid(_) => self.bump_verified(),
            ValidationResult::Invalid(_) => self.bump_rejected(),
            ValidationResult::Pending => {}
        }
        result
    }

    async fn validate_chain_inner(&self, data: &Data) -> ValidationResult {
        let Some(sig_info) = data.sig_info() else {
            return ValidationResult::Invalid(TrustError::InvalidSignature);
        };

        if sig_info.sig_type == SignatureType::DigestSha256 {
            use sha2::{Digest, Sha256};
            let hash = Sha256::digest(data.signed_region());
            if hash.as_slice() == data.sig_value() {
                // Re-decode of already-validated bytes is infallible; propagate
                // instead of panicking in the security hot path (audit N-2).
                let Ok(inner) = Data::decode(data.raw().clone()) else {
                    return ValidationResult::Invalid(TrustError::InvalidSignature);
                };
                let safe = SafeData {
                    inner,
                    trust_path: TrustPath::DigestSha256,
                    verified_at: now_ns(),
                };
                return ValidationResult::Valid(Box::new(safe));
            }
            return ValidationResult::Invalid(TrustError::InvalidSignature);
        }

        // KeyDigest cannot drive a fetch — it requires a pre-loaded cert.
        let first_key: Arc<Name> = match &sig_info.key_locator {
            Some(ndn_packet::KeyLocator::Name(n)) => Arc::new((**n).clone()),
            Some(ndn_packet::KeyLocator::KeyDigest(digest)) => {
                match self.cert_cache.get_by_key_digest(digest) {
                    Some(cert) => Arc::clone(&cert.name),
                    None => return ValidationResult::Invalid(TrustError::InvalidSignature),
                }
            }
            None => return ValidationResult::Invalid(TrustError::InvalidSignature),
        };

        // The chain is walked against the schema/anchors of the context
        // governing this name (the per-namespace skeleton-key fix), with missing
        // intermediates fetched via the `CertFetcher` if configured.
        match self
            .walk_to_anchor(
                &data.name,
                first_key,
                data.signed_region(),
                data.sig_value(),
                sig_info.sig_type,
            )
            .await
        {
            WalkOutcome::Anchored(chain_names) => {
                let Ok(inner) = Data::decode(data.raw().clone()) else {
                    return ValidationResult::Invalid(TrustError::InvalidSignature);
                };
                let safe = SafeData {
                    inner,
                    trust_path: TrustPath::CertChain(chain_names),
                    verified_at: now_ns(),
                };
                ValidationResult::Valid(Box::new(safe))
            }
            WalkOutcome::Pending => ValidationResult::Pending,
            WalkOutcome::Invalid(e) => ValidationResult::Invalid(e),
        }
    }

    /// Validate a **signed Interest** (e.g. an NFD command) by walking its
    /// certificate chain to a trust anchor, fetching the signer's cert — and any
    /// intermediates — via the [`CertFetcher`] if configured. Unlike
    /// [`Validator::validate_interest`] (which trusts any cert already in the
    /// cache), this verifies the signer cert actually chains to an anchor, so it
    /// is safe to use with a network fetcher: an unknown self-signed key is
    /// rejected rather than fetched-and-trusted.
    pub async fn validate_interest_chain(&self, interest: &Interest) -> InterestValidationOutcome {
        let Some(sig_info) = interest.sig_info() else {
            return InterestValidationOutcome::Invalid(TrustError::InvalidSignature);
        };
        let Some(signed_region) = interest.signed_region() else {
            return InterestValidationOutcome::Invalid(TrustError::InvalidSignature);
        };
        let Some(sig_value) = interest.sig_value() else {
            return InterestValidationOutcome::Invalid(TrustError::InvalidSignature);
        };

        if sig_info.sig_type == SignatureType::DigestSha256 {
            return match verify_by_sig_type(sig_info.sig_type, &signed_region, sig_value, &[]).await
            {
                Ok(VerifyOutcome::Valid) => InterestValidationOutcome::Valid,
                Ok(VerifyOutcome::Invalid) => {
                    InterestValidationOutcome::Invalid(TrustError::InvalidSignature)
                }
                Err(e) => InterestValidationOutcome::Invalid(e),
            };
        }

        let first_key: Arc<Name> = match &sig_info.key_locator {
            Some(KeyLocator::Name(n)) => Arc::new((**n).clone()),
            Some(KeyLocator::KeyDigest(digest)) => match self.cert_cache.get_by_key_digest(digest) {
                Some(cert) => Arc::clone(&cert.name),
                None => return InterestValidationOutcome::Pending,
            },
            None => return InterestValidationOutcome::Invalid(TrustError::InvalidSignature),
        };

        match self
            .walk_to_anchor(
                &interest.name,
                first_key,
                &signed_region,
                sig_value,
                sig_info.sig_type,
            )
            .await
        {
            WalkOutcome::Anchored(_) => InterestValidationOutcome::Valid,
            WalkOutcome::Pending => InterestValidationOutcome::Pending,
            WalkOutcome::Invalid(e) => InterestValidationOutcome::Invalid(e),
        }
    }

    /// Shared chain-walk core for the Data and signed-Interest paths: starting
    /// from `(first_signed_region, first_sig_value)` signed by `first_key`, walk
    /// cert → issuer until a trust anchor of the context governing
    /// `context_name` terminates the chain. Missing certs are fetched via the
    /// [`CertFetcher`] if configured (→ [`WalkOutcome::Pending`] on a miss).
    async fn walk_to_anchor(
        &self,
        context_name: &Name,
        first_key: Arc<Name>,
        first_signed_region: &[u8],
        first_sig_value: &[u8],
        first_sig_type: SignatureType,
    ) -> WalkOutcome {
        let ctx = self.keyring.context_for(context_name);
        if !ctx.authorizes(context_name, &first_key) {
            return WalkOutcome::Invalid(TrustError::SchemaMismatch);
        }
        let anchors = ctx.anchors();

        let now = now_ns();
        let mut chain_names: Vec<Name> = Vec::new();
        let mut seen: HashSet<Arc<Name>> = HashSet::new();

        let mut current_signed_region: &[u8] = first_signed_region;
        let mut current_sig_value: &[u8] = first_sig_value;
        let mut current_key_name: Arc<Name> = first_key;
        let mut current_sig_type: SignatureType = first_sig_type;

        let mut owned_signed_region: bytes::Bytes;
        let mut owned_sig_value: bytes::Bytes;

        for _depth in 0..self.max_chain {
            if !seen.insert(Arc::clone(&current_key_name)) {
                return WalkOutcome::Invalid(TrustError::ChainCycle {
                    name: current_key_name.to_string(),
                });
            }

            // A chain that passes through a key revoked by the selected context
            // is rejected — how an issuing-CA compromise is contained by a pulled
            // context bump (no re-bootstrap).
            if ctx.is_revoked(&current_key_name) {
                return WalkOutcome::Invalid(TrustError::Revoked {
                    name: current_key_name.to_string(),
                });
            }

            if let Some(anchor) = anchors.get(&current_key_name) {
                if !anchor.is_valid_at(now) {
                    return WalkOutcome::Invalid(TrustError::CertNotFound {
                        name: format!("expired trust anchor: {}", current_key_name),
                    });
                }
                return match verify_by_sig_type(
                    current_sig_type,
                    current_signed_region,
                    current_sig_value,
                    &anchor.public_key,
                )
                .await
                {
                    Ok(VerifyOutcome::Valid) => {
                        chain_names.push(current_key_name.as_ref().clone());
                        WalkOutcome::Anchored(chain_names)
                    }
                    Ok(VerifyOutcome::Invalid) => {
                        WalkOutcome::Invalid(TrustError::InvalidSignature)
                    }
                    Err(e) => WalkOutcome::Invalid(e),
                };
            }

            let cert = match self.resolve_cert(&current_key_name).await {
                Some(c) => c,
                None => return WalkOutcome::Pending,
            };

            if !cert.is_valid_at(now) {
                return WalkOutcome::Invalid(TrustError::CertNotFound {
                    name: format!("expired or not-yet-valid: {}", current_key_name),
                });
            }

            match verify_by_sig_type(
                current_sig_type,
                current_signed_region,
                current_sig_value,
                &cert.public_key,
            )
            .await
            {
                Ok(VerifyOutcome::Valid) => {}
                Ok(VerifyOutcome::Invalid) => {
                    return WalkOutcome::Invalid(TrustError::InvalidSignature);
                }
                Err(e) => return WalkOutcome::Invalid(e),
            }

            chain_names.push(current_key_name.as_ref().clone());

            let Some(issuer) = &cert.issuer else {
                return WalkOutcome::Invalid(TrustError::CertNotFound {
                    name: format!("cert has no issuer: {}", cert.name),
                });
            };
            let Some(sr) = &cert.signed_region else {
                return WalkOutcome::Invalid(TrustError::CertNotFound {
                    name: format!("cert missing signed region: {}", cert.name),
                });
            };
            let Some(sv) = &cert.sig_value else {
                return WalkOutcome::Invalid(TrustError::CertNotFound {
                    name: format!("cert missing sig value: {}", cert.name),
                });
            };

            owned_signed_region = sr.clone();
            owned_sig_value = sv.clone();
            current_signed_region = &owned_signed_region;
            current_sig_value = &owned_sig_value;
            current_key_name = Arc::clone(issuer);
            current_sig_type = cert.sig_type;
        }

        WalkOutcome::Invalid(TrustError::ChainTooDeep {
            limit: self.max_chain,
        })
    }

    /// Walk the trust chain rooted at `target_name` and return a
    /// structured trace: cert names, signed-by edges, and which schema
    /// rules applied at each hop. Read-only — does not bump counters or
    /// consume cert-fetch budget.
    pub async fn trace(&self, target_name: &Name) -> ChainTrace {
        if self.is_trust_anchor(target_name) {
            return ChainTrace {
                target: target_name.clone(),
                steps: vec![ChainTraceStep {
                    name: target_name.clone(),
                    signed_by: target_name.clone(),
                    is_anchor: true,
                }],
                rules_applied: Vec::new(),
                failure: None,
            };
        }

        let target_arc = Arc::new(target_name.clone());
        let mut steps: Vec<ChainTraceStep> = Vec::new();
        let mut rules_applied: Vec<TraceRuleApplied> = Vec::new();
        let mut current = match self.resolve_cert(&target_arc).await {
            Some(c) => c,
            None => {
                return ChainTrace {
                    target: target_name.clone(),
                    steps,
                    rules_applied,
                    failure: Some(TraceFailure::CertNotFound {
                        name: target_name.clone(),
                    }),
                };
            }
        };

        for _ in 0..=self.max_chain {
            // Issuer = the KeyLocator name on the cert's own signature.
            // Self-signed (issuer == name) is only treated as an anchor
            // when the anchor set actually contains it.
            let issuer = match &current.issuer {
                Some(n) => (**n).clone(),
                None => {
                    steps.push(ChainTraceStep {
                        name: (*current.name).clone(),
                        signed_by: (*current.name).clone(),
                        is_anchor: false,
                    });
                    return ChainTrace {
                        target: target_name.clone(),
                        steps,
                        rules_applied,
                        failure: Some(TraceFailure::NoKeyLocator {
                            name: (*current.name).clone(),
                        }),
                    };
                }
            };

            // Scope the read lock so its guard doesn't span the
            // subsequent `resolve_cert(...).await`; fresh bindings per
            // rule since `NamePattern::matches` consumes them.
            {
                let schema = self.keyring.context_for(&current.name).schema_snapshot();
                for r in schema.rules() {
                    let mut bindings = std::collections::HashMap::new();
                    let data_ok = r.data_pattern.matches(&current.name, &mut bindings);
                    let key_ok = data_ok && r.key_pattern.matches(&issuer, &mut bindings);
                    rules_applied.push(TraceRuleApplied {
                        data_pattern: r.data_pattern.to_string(),
                        key_pattern: r.key_pattern.to_string(),
                        matches: key_ok,
                    });
                }
            }

            let is_anchor = self.is_trust_anchor(&issuer);
            steps.push(ChainTraceStep {
                name: (*current.name).clone(),
                signed_by: issuer.clone(),
                is_anchor: false,
            });
            if is_anchor {
                steps.push(ChainTraceStep {
                    name: issuer.clone(),
                    signed_by: issuer,
                    is_anchor: true,
                });
                return ChainTrace {
                    target: target_name.clone(),
                    steps,
                    rules_applied,
                    failure: None,
                };
            }

            // Self-signed without being an anchor = broken root.
            if issuer == *current.name {
                return ChainTrace {
                    target: target_name.clone(),
                    steps,
                    rules_applied,
                    failure: Some(TraceFailure::AnchorNotTrusted { name: issuer }),
                };
            }
            let next_arc = Arc::new(issuer.clone());
            current = match self.resolve_cert(&next_arc).await {
                Some(c) => c,
                None => {
                    return ChainTrace {
                        target: target_name.clone(),
                        steps,
                        rules_applied,
                        failure: Some(TraceFailure::CertNotFound { name: issuer }),
                    };
                }
            };
        }

        ChainTrace {
            target: target_name.clone(),
            steps,
            rules_applied,
            failure: Some(TraceFailure::ChainTooDeep {
                limit: self.max_chain,
            }),
        }
    }

    async fn resolve_cert(&self, name: &Arc<Name>) -> Option<Certificate> {
        if let Some(cert) = self.cert_cache.get(name) {
            return Some(cert);
        }
        if let Some(fetcher) = self.cert_fetcher.get() {
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

    async fn make_cert_data_packet(
        cert_name: &Name,
        subject_pk: &[u8],
        issuer_signer: &Ed25519Signer,
    ) -> Bytes {
        crate::manager::encode_cert_data(cert_name, subject_pk, issuer_signer, 0, u64::MAX)
            .await
            .expect("encode_cert_data must succeed in tests")
    }

    fn wildcard_schema() -> TrustSchema {
        use crate::trust_schema::SchemaRule;
        let mut schema = TrustSchema::new();
        schema.add_rule(SchemaRule {
            data_pattern: NamePattern(vec![PatternComponent::MultiCapture("_".into())]),
            key_pattern: NamePattern(vec![PatternComponent::MultiCapture("_".into())]),
        });
        schema
    }

    /// Chain: Data(/data) -> cert(/key) -> anchor(/anchor).
    #[tokio::test]
    async fn chain_walk_data_to_anchor() {
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
            sig_type: ndn_packet::SignatureType::SignatureEd25519,
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

    /// Build a signed command Interest with `signer`, KeyLocator = `key_name`.
    async fn make_signed_interest(signer: &Ed25519Signer, key_name: &Name, cmd: &str) -> Bytes {
        use ndn_packet::encode::InterestBuilder;
        let name: Name = cmd.parse().unwrap();
        InterestBuilder::new(name)
            .sign_fallible(signer.sig_type(), Some(key_name), |region: &[u8]| {
                let region = Bytes::copy_from_slice(region);
                async move { signer.sign(&region).await.map_err(|_| ()) }
            })
            .await
            .expect("sign command interest")
    }

    fn anchor_cert(name: Name, pk: [u8; 32]) -> Certificate {
        Certificate {
            name: Arc::new(name),
            public_key: Bytes::copy_from_slice(&pk),
            valid_from: 0,
            valid_until: u64::MAX,
            issuer: None,
            signed_region: None,
            sig_value: None,
            sig_type: ndn_packet::SignatureType::SignatureEd25519,
        }
    }

    /// A signed command whose signer cert is *not* cached but *is* fetchable and
    /// chains to a trust anchor validates via the [`CertFetcher`].
    #[tokio::test]
    async fn validate_interest_chain_fetches_signer_cert() {
        use crate::cert_fetcher::{CertFetcher, FetchFn};
        use ndn_packet::Interest;
        use std::time::Duration;

        let ca_seed = [30u8; 32];
        let ca_name = name1("ca");
        let ca_signer = Ed25519Signer::from_seed(&ca_seed, ca_name.clone());
        let ca_pk = ed25519_dalek::SigningKey::from_bytes(&ca_seed)
            .verifying_key()
            .to_bytes();

        let op_seed = [31u8; 32];
        let op_key_name = Name::from_components([comp("op"), comp("KEY"), comp("k1")]);
        let op_signer = Ed25519Signer::from_seed(&op_seed, op_key_name.clone());
        let op_pk = ed25519_dalek::SigningKey::from_bytes(&op_seed)
            .verifying_key()
            .to_bytes();
        // Operator cert signed by the CA, named exactly the KeyLocator name.
        let op_cert_wire = make_cert_data_packet(&op_key_name, &op_pk, &ca_signer).await;
        let cert_wire = op_cert_wire;

        let interest_wire =
            make_signed_interest(&op_signer, &op_key_name, "/localhop/nfd/rib/register").await;
        let interest = Interest::decode(interest_wire).unwrap();

        let validator = Validator::new(wildcard_schema());
        validator.add_trust_anchor(anchor_cert(ca_name, ca_pk));

        // Fetcher returns the operator cert; it is NOT pre-inserted into the cache.
        let want = op_key_name.clone();
        let fetch_fn: FetchFn = Arc::new(move |name: Name| {
            let wire = cert_wire.clone();
            let want = want.clone();
            Box::pin(async move { (name == want).then(|| Data::decode(wire).unwrap()) })
        });
        let fetcher = Arc::new(CertFetcher::new(
            validator.cert_cache_arc(),
            fetch_fn,
            Duration::from_secs(1),
        ));
        validator.set_cert_fetcher(fetcher).ok();

        assert!(
            matches!(
                validator.validate_interest_chain(&interest).await,
                crate::InterestValidationOutcome::Valid
            ),
            "command should validate after fetching the signer cert"
        );
    }

    /// A fetched cert that does NOT chain to a trust anchor (self-signed) is
    /// rejected — the fetcher resolves it, but the walk finds no anchor.
    #[tokio::test]
    async fn validate_interest_chain_rejects_untrusted_fetched_cert() {
        use crate::cert_fetcher::{CertFetcher, FetchFn};
        use ndn_packet::Interest;
        use std::time::Duration;

        let ca_seed = [40u8; 32];
        let ca_name = name1("ca");
        let ca_pk = ed25519_dalek::SigningKey::from_bytes(&ca_seed)
            .verifying_key()
            .to_bytes();

        // Operator self-signs its own cert (issuer = itself, not the CA).
        let op_seed = [41u8; 32];
        let op_key_name = Name::from_components([comp("rogue"), comp("KEY"), comp("k1")]);
        let op_signer = Ed25519Signer::from_seed(&op_seed, op_key_name.clone());
        let op_pk = ed25519_dalek::SigningKey::from_bytes(&op_seed)
            .verifying_key()
            .to_bytes();
        let op_cert_wire = make_cert_data_packet(&op_key_name, &op_pk, &op_signer).await;
        let cert_wire = op_cert_wire;

        let interest_wire =
            make_signed_interest(&op_signer, &op_key_name, "/localhop/nfd/rib/register").await;
        let interest = Interest::decode(interest_wire).unwrap();

        let validator = Validator::new(wildcard_schema());
        validator.add_trust_anchor(anchor_cert(ca_name, ca_pk)); // trusts the CA, not the rogue

        let want = op_key_name.clone();
        let fetch_fn: FetchFn = Arc::new(move |name: Name| {
            let wire = cert_wire.clone();
            let want = want.clone();
            Box::pin(async move { (name == want).then(|| Data::decode(wire).unwrap()) })
        });
        let fetcher = Arc::new(CertFetcher::new(
            validator.cert_cache_arc(),
            fetch_fn,
            Duration::from_secs(1),
        ));
        validator.set_cert_fetcher(fetcher).ok();

        assert!(
            !matches!(
                validator.validate_interest_chain(&interest).await,
                crate::InterestValidationOutcome::Valid
            ),
            "a self-signed cert that doesn't chain to an anchor must be rejected"
        );
    }

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
            w.write_tlv(0x1b, &[5u8]); // SignatureEd25519
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
            sig_type: ndn_packet::SignatureType::SignatureEd25519,
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

    /// `counters()` starts at `(0, 0)` and bumps verified when a chain
    /// walk reaches an anchor.
    #[tokio::test]
    async fn counters_bump_on_terminal_validate_results() {
        let validator = Validator::new(wildcard_schema());
        assert_eq!(validator.counters(), (0, 0));

        let seed = [11u8; 32];
        let key_name = name1("key");
        let signer = Ed25519Signer::from_seed(&seed, key_name.clone());
        let pk = ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes();
        let cert_wire = make_cert_data_packet(&key_name, &pk, &signer).await;
        let cert = Certificate::decode(&Data::decode(cert_wire).unwrap()).unwrap();
        validator.add_trust_anchor(cert);

        let data_bytes = make_signed_data(&signer, "data", "key").await;
        let data = Data::decode(data_bytes).unwrap();

        match validator.validate_chain(&data).await {
            ValidationResult::Valid(_) => {}
            other => panic!("expected Valid, got {other:?}"),
        }
        let (v, r) = validator.counters();
        assert_eq!(v, 1, "verified counter must bump on Valid result");
        assert_eq!(r, 0, "rejected counter should not bump on Valid");
    }

    /// `trace()` against an anchor returns a single-step anchored result.
    #[tokio::test]
    async fn trace_anchor_returns_single_step_no_failure() {
        let seed = [44u8; 32];
        let key_name = name1("anchor-key");
        let signer = Ed25519Signer::from_seed(&seed, key_name.clone());
        let pk = ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes();
        let cert_wire = make_cert_data_packet(&key_name, &pk, &signer).await;
        let cert = Certificate::decode(&Data::decode(cert_wire).unwrap()).unwrap();
        let validator = Validator::new(wildcard_schema());
        validator.add_trust_anchor(cert);

        let trace = validator.trace(&key_name).await;
        assert!(trace.failure.is_none(), "anchor trace must succeed");
        assert_eq!(trace.steps.len(), 1);
        assert!(trace.steps[0].is_anchor);
        assert_eq!(trace.steps[0].name, key_name);
    }

    /// `trace()` against an unknown name surfaces `CertNotFound`.
    #[tokio::test]
    async fn trace_unknown_name_returns_cert_not_found() {
        let validator = Validator::new(wildcard_schema());
        let target = name1("unknown");
        let trace = validator.trace(&target).await;
        match trace.failure {
            Some(TraceFailure::CertNotFound { name }) => assert_eq!(name, target),
            other => panic!("expected CertNotFound, got {other:?}"),
        }
    }

    /// `trace()` does not bump validator counters.
    #[tokio::test]
    async fn trace_does_not_bump_counters() {
        let validator = Validator::new(wildcard_schema());
        let (v0, r0) = validator.counters();
        let _ = validator.trace(&name1("anything")).await;
        let (v1, r1) = validator.counters();
        assert_eq!((v0, r0), (v1, r1));
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

    /// A chain that is otherwise valid (good signatures, terminating at a held
    /// anchor) is **rejected** when a key in it is revoked by the governing
    /// context — the verifier auto-consults the context's revocation list at
    /// every hop.
    #[tokio::test]
    async fn chain_walk_rejects_a_revoked_key() {
        use crate::Keyring;
        use crate::cert_cache::CertCache;
        use crate::trust_context::SignedTrustContext;
        use dashmap::DashMap;

        // Anchor → /key cert → data signed by /key — the chain_walk_data_to_anchor
        // shape, which validates Valid without a revocation.
        let anchor_seed = [60u8; 32];
        let anchor_name = name1("anchor");
        let anchor_signer = Ed25519Signer::from_seed(&anchor_seed, anchor_name.clone());
        let anchor_pk = ed25519_dalek::SigningKey::from_bytes(&anchor_seed)
            .verifying_key()
            .to_bytes();

        let key_seed = [61u8; 32];
        let key_name = name1("key");
        let key_signer = Ed25519Signer::from_seed(&key_seed, key_name.clone());
        let key_pk = ed25519_dalek::SigningKey::from_bytes(&key_seed)
            .verifying_key()
            .to_bytes();

        let cert_wire = make_cert_data_packet(&key_name, &key_pk, &anchor_signer).await;
        let cert = Certificate::decode(&Data::decode(cert_wire).unwrap()).unwrap();
        let data = Data::decode(make_signed_data(&key_signer, "data", "key").await).unwrap();

        // A context that holds the anchor but has revoked `/key`.
        let ambient = SignedTrustContext::ambient(wildcard_schema(), Arc::new(DashMap::new()))
            .with_revocation(key_name.clone());
        ambient.add_anchor(Certificate {
            name: Arc::new(anchor_name),
            public_key: Bytes::copy_from_slice(&anchor_pk),
            valid_from: 0,
            valid_until: u64::MAX,
            issuer: None,
            signed_region: None,
            sig_value: None,
            sig_type: ndn_packet::SignatureType::SignatureEd25519,
        });
        let keyring = Arc::new(Keyring::with_ambient(Arc::new(ambient)));
        let cert_cache = Arc::new(CertCache::new());
        cert_cache.insert(cert);
        let validator = Validator::with_keyring(keyring, cert_cache, None, 5);

        match validator.validate_chain(&data).await {
            ValidationResult::Invalid(TrustError::Revoked { name }) => {
                assert_eq!(name, key_name.to_string());
            }
            other => panic!("expected Invalid(Revoked), got {other:?}"),
        }
    }
}
