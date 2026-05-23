use std::collections::HashSet;
use std::sync::Arc;

use ndn_packet::{Data, Name, SignatureType};

use crate::cert_cache::Certificate;
use crate::safe_data::TrustPath;
use crate::verifier::verify_by_sig_type;
use crate::{SafeData, TrustError, VerifyOutcome};

use super::{
    ChainTrace, ChainTraceStep, TraceFailure, TraceRuleApplied, ValidationResult, Validator, now_ns,
};

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

        let mut current_signed_region: &[u8] = data.signed_region();
        let mut current_sig_value: &[u8] = data.sig_value();
        let mut current_key_name: Arc<Name> = first_key;
        let mut current_sig_type: SignatureType = sig_info.sig_type;

        let mut owned_signed_region: bytes::Bytes;
        let mut owned_sig_value: bytes::Bytes;

        for _depth in 0..self.max_chain {
            if !seen.insert(Arc::clone(&current_key_name)) {
                return ValidationResult::Invalid(TrustError::ChainCycle {
                    name: current_key_name.to_string(),
                });
            }

            if let Some(anchor) = self.trust_anchors.get(&current_key_name) {
                if !anchor.is_valid_at(now) {
                    return ValidationResult::Invalid(TrustError::CertNotFound {
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

            let cert = match self.resolve_cert(&current_key_name).await {
                Some(c) => c,
                None => return ValidationResult::Pending,
            };

            if !cert.is_valid_at(now) {
                return ValidationResult::Invalid(TrustError::CertNotFound {
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
                    return ValidationResult::Invalid(TrustError::InvalidSignature);
                }
                Err(e) => return ValidationResult::Invalid(e),
            }

            chain_names.push(current_key_name.as_ref().clone());

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
            current_sig_type = cert.sig_type;
        }

        ValidationResult::Invalid(TrustError::ChainTooDeep {
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
                let schema_guard = self.schema.read().expect("schema RwLock poisoned");
                for r in schema_guard.rules() {
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
}
