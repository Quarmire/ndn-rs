use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use ndn_packet::{Data, Interest, KeyLocator, Name, SignatureType};

use crate::cert_cache::Certificate;
use crate::cert_name::{is_cert_name, is_cert_of, is_reserved_non_cert, key_name_of};
use crate::safe_data::TrustPath;
use crate::verifier::{DIGEST_NO_SIGNER, not_public_key, verify_by_sig_type};
use crate::{SafeData, TrustError, VerifyOutcome};

use super::{
    ChainTrace, ChainTraceStep, InterestValidationOutcome, TraceFailure, TraceRuleApplied,
    ValidationResult, Validator, now_ns, own_certificate,
};

/// A signing hop of a chain walk whose authorization waits for its signer's
/// certificate (see [`SignedTrustContext::authorizes_hop`](crate::SignedTrustContext::authorizes_hop)).
enum Hop {
    /// The validated packet itself, by this name.
    Packet(Name),
    /// A certificate of the chain.
    Cert(Arc<Name>),
}

/// Outcome of [`Validator::walk_to_anchor`] — the shared chain-walk core used by
/// both the Data and signed-Interest fetch-enabled validation paths.
enum WalkOutcome {
    /// The chain reached a trust anchor — or, under
    /// [`Validator::accept_signed`], the packet's signer verified it; carries
    /// the cert names walked.
    Trusted(Vec<Name>),
    /// A cert in the chain couldn't be resolved (cache miss + no/failed fetch);
    /// carries the name of the first unresolved cert.
    Pending(Arc<Name>),
    /// The chain is invalid (bad signature, schema mismatch, revoked, cycle, …).
    Invalid(TrustError),
}

/// How long a refused certificate answers for its key
/// ([`Validator::refused_certs`]) when no fetcher is attached; with one, as
/// long as the fetcher would not fetch that key again anyway
/// ([`CertFetcher::retry_after`](crate::CertFetcher::retry_after)).
const REFUSED_CERT_TTL: Duration = Duration::from_secs(8);
/// Bound on [`Validator::refused_certs`]; past it, expired entries are
/// swept, and a new refusal is not remembered while none has expired.
const REFUSED_CERTS_MAX: usize = 256;

impl Validator {
    /// Validate by walking the full certificate chain.
    ///
    /// Verifies the Data's signature, then each intermediate cert against
    /// its issuer's key, until a trust anchor terminates the walk. Missing
    /// certificates are fetched via the `CertFetcher` if configured.
    pub async fn validate_chain(&self, data: &Data) -> ValidationResult {
        let (result, _missing) = self.validate_chain_inner(data, true).await;
        self.bump_for_result(&result);
        result
    }

    /// Validate by walking the full certificate chain using **only certs
    /// already cached** — never awaits the `CertFetcher`. On a cache miss
    /// returns `(Pending, Some(missing_cert_name))` so the caller can fetch that
    /// cert off the hot path and re-validate later (the forwarder's
    /// `ValidationStage` does exactly this: an inline network fetch would stall
    /// the pipeline that has to deliver the cert's own Data). The name is `Some`
    /// iff the result is `Pending`. Counters bump as for [`Self::validate_chain`].
    pub async fn validate_chain_cached(
        &self,
        data: &Data,
    ) -> (ValidationResult, Option<Arc<Name>>) {
        let (result, missing) = self.validate_chain_inner(data, false).await;
        self.bump_for_result(&result);
        (result, missing)
    }

    fn bump_for_result(&self, result: &ValidationResult) {
        match result {
            ValidationResult::Valid(_) => self.bump_verified(),
            ValidationResult::Invalid(_) => self.bump_rejected(),
            ValidationResult::Pending => {}
        }
    }

    async fn validate_chain_inner(
        &self,
        data: &Data,
        fetch: bool,
    ) -> (ValidationResult, Option<Arc<Name>>) {
        let result = |r: ValidationResult| (r, None);
        // An adoption in progress decides its own context Data (and nothing
        // else); with no expectation this is one atomic load.
        if let Some(r) = self.admit_expected_context(data).await {
            return result(r);
        }
        let Some(sig_info) = data.sig_info() else {
            return result(ValidationResult::Invalid(TrustError::InvalidSignature));
        };

        if sig_info.sig_type == SignatureType::DigestSha256 {
            use sha2::{Digest, Sha256};
            let hash = Sha256::digest(data.signed_region());
            if hash.as_slice() == data.sig_value() {
                // Re-decode of already-validated bytes is infallible; propagate
                // instead of panicking in the security hot path (audit N-2).
                let Ok(inner) = Data::decode(data.raw().clone()) else {
                    return result(ValidationResult::Invalid(TrustError::InvalidSignature));
                };
                let safe = SafeData {
                    inner,
                    trust_path: TrustPath::DigestSha256,
                    verified_at: now_ns(),
                };
                return result(ValidationResult::Valid(Box::new(safe)));
            }
            return result(ValidationResult::Invalid(TrustError::InvalidSignature));
        }

        // KeyDigest cannot drive a fetch — it requires a pre-loaded cert.
        let first_key: Arc<Name> = match &sig_info.key_locator {
            Some(ndn_packet::KeyLocator::Name(n)) => Arc::new((**n).clone()),
            Some(ndn_packet::KeyLocator::KeyDigest(digest)) => {
                match self.cert_cache.get_by_key_digest(digest) {
                    Some(cert) => Arc::clone(&cert.name),
                    None => return result(ValidationResult::Invalid(TrustError::InvalidSignature)),
                }
            }
            None => return result(ValidationResult::Invalid(TrustError::InvalidSignature)),
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
                fetch,
                Some(data),
            )
            .await
        {
            WalkOutcome::Trusted(chain_names) => {
                let Ok(inner) = Data::decode(data.raw().clone()) else {
                    return result(ValidationResult::Invalid(TrustError::InvalidSignature));
                };
                let safe = SafeData {
                    inner,
                    trust_path: TrustPath::CertChain(chain_names),
                    verified_at: now_ns(),
                };
                result(ValidationResult::Valid(Box::new(safe)))
            }
            WalkOutcome::Pending(missing) => (ValidationResult::Pending, Some(missing)),
            WalkOutcome::Invalid(e) => {
                // A certificate refused with a final verdict answers for its
                // key for a while (`refused_certs`): Data parked waiting for
                // that key is then re-walked through it and refused with the
                // same verdict (e.g. its issuer is revoked) at once, instead
                // of timing out while the fetch could not change the answer.
                if is_cert_name(&data.name)
                    && !is_reserved_non_cert(&data.name)
                    && let Ok(cert) = Certificate::decode(data)
                {
                    self.remember_refused(cert);
                }
                result(ValidationResult::Invalid(e))
            }
        }
    }

    /// Validate a **signed Interest** (e.g. an NFD command) by walking its
    /// certificate chain to a trust anchor, fetching the signer's cert — and any
    /// intermediates — via the `CertFetcher` if configured. Unlike
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

        // A digest names no signer: no chain to walk, nothing authenticated.
        if sig_info.sig_type == SignatureType::DigestSha256 {
            return InterestValidationOutcome::Invalid(not_public_key(
                "DigestSha256 (0)",
                DIGEST_NO_SIGNER,
            ));
        }

        let first_key: Arc<Name> = match &sig_info.key_locator {
            Some(KeyLocator::Name(n)) => Arc::new((**n).clone()),
            Some(KeyLocator::KeyDigest(digest)) => {
                match self.cert_cache.get_by_key_digest(digest) {
                    Some(cert) => Arc::clone(&cert.name),
                    None => return InterestValidationOutcome::Pending,
                }
            }
            None => return InterestValidationOutcome::Invalid(TrustError::InvalidSignature),
        };

        match self
            .walk_to_anchor(
                &interest.name,
                first_key,
                &signed_region,
                sig_value,
                sig_info.sig_type,
                true,
                None,
            )
            .await
        {
            WalkOutcome::Trusted(_) => InterestValidationOutcome::Valid,
            WalkOutcome::Pending(_) => InterestValidationOutcome::Pending,
            WalkOutcome::Invalid(e) => InterestValidationOutcome::Invalid(e),
        }
    }

    /// Shared chain-walk core for the Data and signed-Interest paths: starting
    /// from `(first_signed_region, first_sig_value)` signed by `first_key`, walk
    /// cert → issuer until a trust anchor of the context governing
    /// `context_name` terminates the chain. Missing certs are fetched via the
    /// `CertFetcher` when `fetch` is set and one is configured (→
    /// [`WalkOutcome::Pending`] naming the unresolved cert on a miss). Under
    /// [`Validator::accept_signed`] the walk ends at the packet's verified
    /// signer.
    ///
    /// KeyLocators name a key (or one certificate of it); each resolves to the
    /// key's newest valid certificate, or to the anchor of that key. Every hop
    /// is authorized with [`SignedTrustContext::authorizes_hop`]: a
    /// certificate hop once its issuer is resolved, so a schema written over
    /// certificate names sees the issuer's certificate name.
    ///
    /// `packet` is the validated Data (`None` for an Interest). A certificate
    /// signed by its own key is its own signer's certificate: it is never
    /// fetched — the fetch would be answered by this very packet, which waits
    /// for it. A chain ending at a self-signed certificate that is no anchor
    /// is refused ([`TrustError::UntrustedSelfSigned`]). A certificate packet
    /// refused for any reason is remembered for its key
    /// ([`Self::refused_certs`]) by the Data validation that refused it.
    ///
    /// [`SignedTrustContext::authorizes_hop`]: crate::SignedTrustContext::authorizes_hop
    #[allow(clippy::too_many_arguments)]
    async fn walk_to_anchor(
        &self,
        context_name: &Name,
        first_key: Arc<Name>,
        first_signed_region: &[u8],
        first_sig_value: &[u8],
        first_sig_type: SignatureType,
        fetch: bool,
        packet: Option<&Data>,
    ) -> WalkOutcome {
        let ctx = self.keyring.context_for(context_name);
        let authoritative = ctx.schema_is_authoritative();

        let now = now_ns();
        let mut chain_names: Vec<Name> = Vec::new();
        let mut seen: HashSet<Arc<Name>> = HashSet::new();

        // The hop whose authorization waits for its signer to resolve: the
        // packet's own hop when its KeyLocator alone (or its key name) is not
        // enough — a schema over certificate names needs the signer's
        // certificate — then each certificate, checked against its issuer.
        let mut pending: Option<Hop> = (!ctx.authorizes_hop(context_name, &first_key, None))
            .then(|| Hop::Packet(context_name.clone()));
        let hop_refused = |hop: &Option<Hop>, signer: &Name, signer_cert: &Name| match hop {
            Some(Hop::Packet(name)) if !ctx.authorizes_hop(name, signer, Some(signer_cert)) => {
                Some(WalkOutcome::Invalid(TrustError::SchemaMismatch))
            }
            // Every certificate hop is authorized by the context's
            // certification rule (anchor, identity prefix, or the context's
            // CA within its namespace), so an enrolled device cannot certify
            // another device's key.
            Some(Hop::Cert(cert)) if !ctx.authorizes_certification(cert, signer) => {
                let cas: Vec<String> = ctx.ca_endpoints().iter().map(Name::to_string).collect();
                Some(WalkOutcome::Invalid(TrustError::CertNotAuthorized {
                    cert: cert.to_string(),
                    issuer: signer.to_string(),
                    why: format!(
                        "under the trust context for {ns} a key certifies only names under its \
                         own identity, unless it is a trust anchor of the context or a key of \
                         the context's CA ({cas}) certifying a name under {ns}; have the key \
                         certified by the namespace CA (enroll the device)",
                        ns = ctx.namespace(),
                        cas = if cas.is_empty() { "none named".to_string() } else { cas.join(", ") },
                    ),
                }))
            }
            // An authoritative schema also governs every certificate hop, as
            // LVS validation does: e.g. a device key is accepted only when the
            // CA certified it, not when another device self-issued it.
            Some(Hop::Cert(cert))
                if authoritative && !ctx.authorizes_hop(cert, signer, Some(signer_cert)) =>
            {
                Some(WalkOutcome::Invalid(TrustError::CertNotAuthorized {
                    cert: cert.to_string(),
                    issuer: signer.to_string(),
                    why: format!(
                        "the trust schema does not let this issuer certify it (see why with \
                         `ndn-fwd schema explain {cert} {signer}`); re-enroll the key with the \
                         CA the schema names"
                    ),
                }))
            }
            _ => None,
        };

        let mut current_signed_region: &[u8] = first_signed_region;
        let mut current_sig_value: &[u8] = first_sig_value;
        let mut current_key_name: Arc<Name> = first_key;
        let mut current_sig_type: SignatureType = first_sig_type;

        let mut owned_signed_region: bytes::Bytes;
        let mut owned_sig_value: bytes::Bytes;

        for depth in 0..self.max_chain {
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

            // Anchors match by key: a KeyLocator naming the anchor's key or any
            // certificate of it terminates the chain there.
            if let Some(anchor) = ctx.anchor_for(&current_key_name) {
                if !anchor.is_valid_at(now) {
                    return WalkOutcome::Invalid(TrustError::CertNotFound {
                        name: format!("expired trust anchor: {}", current_key_name),
                    });
                }
                if let Some(refused) = hop_refused(&pending, &current_key_name, &anchor.name) {
                    return refused;
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
                        WalkOutcome::Trusted(chain_names)
                    }
                    Ok(VerifyOutcome::Invalid) => {
                        WalkOutcome::Invalid(TrustError::InvalidSignature)
                    }
                    Err(e) => WalkOutcome::Invalid(e),
                };
            }

            let cached = self.cert_cache.get_valid(&current_key_name);
            // The packet certifies the key that signed it (self-signed): a
            // certificate of the KeyLocator's key, or a legacy key-named
            // certificate whose KeyLocator names itself.
            let own = match packet {
                Some(p) if depth == 0 && cached.is_none() => {
                    if is_cert_name(&p.name) && is_cert_of(&p.name, &key_name_of(&current_key_name))
                    {
                        Certificate::decode(p).ok()
                    } else {
                        own_certificate(p, &current_key_name)
                    }
                }
                _ => None,
            };
            // `verified`: the certificate already verified the current signature.
            let (cert, verified) = match cached.or(own) {
                Some(c) => (c, false),
                None => match self
                    .refused_signer(
                        &current_key_name,
                        current_signed_region,
                        current_sig_value,
                        current_sig_type,
                    )
                    .await
                {
                    Some(c) => (c, true),
                    None => match self.resolve_uncached(&current_key_name, fetch).await {
                        Some(c) => (c, false),
                        // Nothing can fetch the certificate that might authorize the
                        // packet: it is refused as before, not left pending forever.
                        // (A cache-only walk reports it missing, for its caller to fetch.)
                        None if fetch
                            && matches!(pending, Some(Hop::Packet(_)))
                            && self.cert_fetcher.get().is_none() =>
                        {
                            return WalkOutcome::Invalid(TrustError::SchemaMismatch);
                        }
                        None => return WalkOutcome::Pending(current_key_name),
                    },
                },
            };

            if !cert.is_valid_at(now) {
                return WalkOutcome::Invalid(TrustError::CertNotFound {
                    name: format!("expired or not-yet-valid: {}", cert.name),
                });
            }
            // A KeyLocator naming the key resolves to one of its certificates;
            // a revocation naming that certificate refuses it too.
            if ctx.is_revoked(&cert.name) {
                return WalkOutcome::Invalid(TrustError::Revoked {
                    name: cert.name.to_string(),
                });
            }
            // Data that merely shares the certificate name shape is no
            // certificate (an admin's NDNCERT decision
            // `<key>/ndncert-approve|ndncert-deny/<id>`).
            if crate::cert_name::is_reserved_non_cert(&cert.name) {
                return WalkOutcome::Invalid(TrustError::CertNotAuthorized {
                    cert: cert.name.to_string(),
                    issuer: current_key_name.to_string(),
                    why: "it is an admin's NDNCERT decision (`<key>/ndncert-approve/<id>` or \
                          `<key>/ndncert-deny/<id>`), not a certificate, and never answers for \
                          a key"
                        .to_string(),
                });
            }
            if let Some(refused) = hop_refused(&pending, &current_key_name, &cert.name) {
                return refused;
            }

            if !verified {
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
            }

            chain_names.push(current_key_name.as_ref().clone());
            if !self.require_anchor {
                return WalkOutcome::Trusted(chain_names);
            }

            let Some(issuer) = &cert.issuer else {
                return WalkOutcome::Invalid(TrustError::CertNotFound {
                    name: format!("cert has no issuer: {}", cert.name),
                });
            };
            // A self-signed certificate that is no anchor (an anchor of its
            // key ended the walk above) ends the chain: nothing vouches for it.
            if key_name_of(issuer) == cert.key_name() {
                return WalkOutcome::Invalid(TrustError::UntrustedSelfSigned {
                    cert: cert.name.to_string(),
                    namespace: ctx.namespace().to_string(),
                });
            }
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
            pending = Some(Hop::Cert(Arc::clone(&cert.name)));
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
        let mut current = match self.resolve_cert(&target_arc, true).await {
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
            current = match self.resolve_cert(&next_arc, true).await {
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

    /// The certificate `name` (a KeyLocator: key name or certificate name)
    /// resolves to. A cached certificate valid now wins. Otherwise a current
    /// one is fetched when `fetch` is set — a key whose cached certificate
    /// expired may have been renewed under a new certificate name. Without a
    /// fetch, `None` (pending) when a fetcher could still find a current
    /// certificate of the key, else the cached expired one so the caller
    /// reports it as expired.
    async fn resolve_cert(&self, name: &Arc<Name>, fetch: bool) -> Option<Certificate> {
        match self.cert_cache.get_valid(name) {
            Some(cert) => Some(cert),
            None => self.resolve_uncached(name, fetch).await,
        }
    }

    /// [`Self::resolve_cert`] once no certificate valid now is cached.
    async fn resolve_uncached(&self, name: &Arc<Name>, fetch: bool) -> Option<Certificate> {
        let cached = self.cert_cache.get(name);
        match self.cert_fetcher.get() {
            Some(fetcher) if fetch => fetcher.fetch(name).await.ok().or(cached),
            Some(_) if !is_cert_name(name) => None,
            _ => cached,
        }
    }

    /// Whether a walk resolves `name` (a KeyLocator) without fetching: a
    /// certificate valid now is cached, or a certificate of it was refused
    /// recently ([`Self::refused_certs`]). The forwarder's validation stage
    /// re-validates Data parked for `name` once this holds.
    pub fn can_resolve(&self, name: &Name) -> bool {
        self.cert_cache.get_valid(name).is_some() || self.refused_cert(name).is_some()
    }

    /// The refused certificate answering for `name`, while it does.
    fn refused_cert(&self, name: &Name) -> Option<Certificate> {
        if self.refused_certs.is_empty() {
            return None;
        }
        let entry = self.refused_certs.get(&key_name_of(name))?;
        let (cert, until) = entry.value();
        let now = now_ns();
        (now < *until && cert.is_valid_at(now) && cert.name.has_prefix(name)).then(|| cert.clone())
    }

    /// The refused certificate answering for `key`, if it verifies the
    /// current signature. One that does not cannot refuse the packet — a
    /// certificate anyone could have sent for that key name — so the key is
    /// resolved as usual instead.
    async fn refused_signer(
        &self,
        key: &Name,
        signed_region: &[u8],
        sig_value: &[u8],
        sig_type: SignatureType,
    ) -> Option<Certificate> {
        let cert = self.refused_cert(key)?;
        match verify_by_sig_type(sig_type, signed_region, sig_value, &cert.public_key).await {
            Ok(VerifyOutcome::Valid) => Some(cert),
            _ => None,
        }
    }

    /// Remember `cert`, a certificate packet just refused with a final
    /// verdict, as the answer for its key for as long as a fetch of that key
    /// would not be retried anyway.
    fn remember_refused(&self, cert: Certificate) {
        let now = now_ns();
        if self.refused_certs.len() >= REFUSED_CERTS_MAX {
            self.refused_certs.retain(|_, (_, until)| *until > now);
            if self.refused_certs.len() >= REFUSED_CERTS_MAX {
                return;
            }
        }
        let ttl = self
            .cert_fetcher
            .get()
            .map_or(REFUSED_CERT_TTL, |f| f.retry_after());
        let until = now.saturating_add(u64::try_from(ttl.as_nanos()).unwrap_or(u64::MAX));
        self.refused_certs.insert(cert.key_name(), (cert, until));
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

    /// `validate_chain_cached` never touches the fetcher and names the *first
    /// unresolved* cert — the Data's signer first, then (once that is cached)
    /// the deeper intermediate — so a caller can fetch exactly what is missing
    /// off the hot path, one hop at a time.
    #[tokio::test]
    async fn cached_walk_names_missing_cert_without_fetching() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let mid_seed = [23u8; 32];
        let mid_signer = Ed25519Signer::from_seed(&mid_seed, name1("mid"));
        let key_seed = [24u8; 32];
        let key_signer = Ed25519Signer::from_seed(&key_seed, name1("key"));
        let key_pk = ed25519_dalek::SigningKey::from_bytes(&key_seed)
            .verifying_key()
            .to_bytes();
        let data = Data::decode(make_signed_data(&key_signer, "data", "key").await).unwrap();

        let validator = Validator::new(wildcard_schema());
        let fetches = Arc::new(AtomicUsize::new(0));
        let f = Arc::clone(&fetches);
        let fetcher = Arc::new(crate::CertFetcher::new(
            validator.cert_cache_arc(),
            Arc::new(move |_| {
                f.fetch_add(1, Ordering::Relaxed);
                Box::pin(async { Err(crate::FetchMiss::Unanswered) })
            }),
            std::time::Duration::from_secs(1),
        ));
        assert!(validator.set_cert_fetcher(fetcher).is_ok());

        let (result, missing) = validator.validate_chain_cached(&data).await;
        assert!(matches!(result, ValidationResult::Pending));
        assert_eq!(missing.as_deref(), Some(&name1("key")));

        let key_cert = Data::decode(make_cert_data_packet(&name1("key"), &key_pk, &mid_signer).await)
            .unwrap();
        validator
            .cert_cache()
            .insert(Certificate::decode(&key_cert).unwrap());
        let (result, missing) = validator.validate_chain_cached(&data).await;
        assert!(matches!(result, ValidationResult::Pending));
        assert_eq!(missing.as_deref(), Some(&name1("mid")));

        assert_eq!(fetches.load(Ordering::Relaxed), 0, "cached walk must not fetch");
    }

    /// A self-signed certificate carries its own verifying key, so validating it
    /// never waits on the cache or a fetch for that key: a forwarder that fetched
    /// a root cert while resolving a chain would otherwise hold it pending behind
    /// its own fetch. Signature-only validation accepts it; the chain walk rejects
    /// it outright unless it is an anchor (it signs itself -- a cycle), and accepts
    /// it when it is one.
    #[tokio::test]
    async fn self_signed_cert_resolves_its_own_key() {
        let seed = [23u8; 32];
        let root = name1("root");
        let signer = Ed25519Signer::from_seed(&seed, root.clone());
        let pk = ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes();
        let cert = Data::decode(make_cert_data_packet(&root, &pk, &signer).await).unwrap();

        let validator = Validator::new(wildcard_schema());
        let verdict = validator.validate(&cert).await;
        assert!(
            matches!(verdict, ValidationResult::Valid(_)),
            "signature-only: a self-signed cert verifies against the key it carries, got {verdict:?}"
        );
        let verdict = validator.validate_chain(&cert).await;
        assert!(
            matches!(
                verdict,
                ValidationResult::Invalid(TrustError::UntrustedSelfSigned { .. })
            ),
            "chain walk: a self-signed cert that is not an anchor is untrusted, not pending; got {verdict:?}"
        );

        validator.add_trust_anchor(anchor_cert(root, pk));
        assert!(matches!(
            validator.validate_chain(&cert).await,
            ValidationResult::Valid(_)
        ));

        let mut forged = cert.raw().to_vec();
        *forged.last_mut().unwrap() ^= 0xFF;
        let forged = Data::decode(Bytes::from(forged)).unwrap();
        assert!(matches!(
            Validator::new(wildcard_schema()).validate(&forged).await,
            ValidationResult::Invalid(TrustError::InvalidSignature)
        ));
    }

    /// ndn-cxx names: KeyLocators name the KEY (`/p/KEY/k`), certificates carry
    /// two more components (`/p/KEY/k/<issuer>/<version>`). A cached cert and an
    /// anchor must both answer to their KEY name, and a self-signed cert whose
    /// KeyLocator names its KEY still carries its own verifying key.
    #[tokio::test]
    async fn key_name_locators_resolve_certs_and_anchors() {
        use crate::SignWith;
        use ndn_packet::encode::DataBuilder;

        let root = Ed25519Signer::from_seed(&[24; 32], "/root/KEY/r".parse().unwrap());
        let root_pk = root.public_key().unwrap();
        let root_cert = Data::decode(
            crate::manager::encode_cert_data(
                &"/root/KEY/r/self/v1".parse().unwrap(),
                &root_pk,
                &root,
                0,
                u64::MAX,
            )
            .await
            .unwrap(),
        )
        .unwrap();
        let key = Ed25519Signer::from_seed(&[25; 32], "/p/KEY/k".parse().unwrap());
        let key_cert = crate::manager::encode_cert_data(
            &"/p/KEY/k/root/v1".parse().unwrap(),
            &key.public_key().unwrap(),
            &root,
            0,
            u64::MAX,
        )
        .await
        .unwrap();
        let data = Data::decode(
            DataBuilder::new("/p/data".parse::<Name>().unwrap(), b"x")
                .sign_with_sync(&key)
                .unwrap(),
        )
        .unwrap();

        let validator = Validator::new(wildcard_schema());
        assert!(
            matches!(
                validator.validate(&root_cert).await,
                ValidationResult::Valid(_)
            ),
            "a self-signed cert located by its KEY name verifies against its own key"
        );
        validator.add_trust_anchor(Certificate::decode(&root_cert).unwrap());
        validator
            .cert_cache()
            .insert(Certificate::decode(&Data::decode(key_cert).unwrap()).unwrap());
        match validator.validate_chain(&data).await {
            ValidationResult::Valid(_) => {}
            other => panic!("KEY-name chain to a KEY-name anchor must validate, got {other:?}"),
        }
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
    /// chains to a trust anchor validates via the `CertFetcher`.
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
            Box::pin(async move {
                (name == want)
                    .then(|| Data::decode(wire).unwrap())
                    .ok_or(crate::FetchMiss::Unanswered)
            })
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
            Box::pin(async move {
                (name == want)
                    .then(|| Data::decode(wire).unwrap())
                    .ok_or(crate::FetchMiss::Unanswered)
            })
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

    /// A walk ends: at a self-signed certificate that is no anchor with the
    /// untrusted-root verdict (it once surfaced as a chain cycle), and at two
    /// keys certifying each other with a chain cycle.
    #[tokio::test]
    async fn chain_walk_ends_at_untrusted_root_and_at_cycle() {
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
            ValidationResult::Invalid(TrustError::UntrustedSelfSigned { .. }) => {}
            other => panic!("expected UntrustedSelfSigned, got: {other:?}"),
        }

        let a = Ed25519Signer::from_seed(&[24u8; 32], name1("ka"));
        let b = Ed25519Signer::from_seed(&[25u8; 32], name1("kb"));
        let validator = Validator::new(wildcard_schema());
        for (subject, issuer) in [(&a, &b), (&b, &a)] {
            let wire =
                make_cert_data_packet(subject.key_name(), &subject.public_key_bytes(), issuer)
                    .await;
            let cert = Certificate::decode(&Data::decode(wire).unwrap()).unwrap();
            validator.cert_cache().insert(cert);
        }
        let data = Data::decode(make_signed_data(&a, "data", "ka").await).unwrap();
        match validator.validate_chain(&data).await {
            ValidationResult::Invalid(TrustError::ChainCycle { .. }) => {}
            other => panic!("expected ChainCycle, got: {other:?}"),
        }
    }

    /// A chain of distinct keys longer than the validator's limit ends the
    /// walk with the depth verdict instead of walking on.
    #[tokio::test]
    async fn chain_walk_depth_limit() {
        const KEYS: [&str; 7] = ["k0", "k1", "k2", "k3", "k4", "k5", "k6"];
        let signers: Vec<Ed25519Signer> = KEYS
            .into_iter()
            .zip(70u8..)
            .map(|(k, seed)| Ed25519Signer::from_seed(&[seed; 32], name1(k)))
            .collect();
        let validator = Validator::new(wildcard_schema());
        for pair in signers.windows(2) {
            let (subject, issuer) = (&pair[0], &pair[1]);
            let wire =
                make_cert_data_packet(subject.key_name(), &subject.public_key_bytes(), issuer)
                    .await;
            validator
                .cert_cache()
                .insert(Certificate::decode(&Data::decode(wire).unwrap()).unwrap());
        }
        let data = Data::decode(make_signed_data(&signers[0], "data", "k0").await).unwrap();
        match validator.validate_chain(&data).await {
            ValidationResult::Invalid(TrustError::ChainTooDeep { .. }) => {}
            other => panic!("expected ChainTooDeep, got: {other:?}"),
        }
    }

    /// In a hierarchical context, an enrolled member's key cannot certify
    /// another device's key (no forging that device's Data), while the
    /// context's CA and an anchor of the context can.
    #[tokio::test]
    async fn a_member_cannot_certify_another_devices_key() {
        use crate::trust_context::SignedTrustContext;

        let anchor = |signer: &Ed25519Signer| Certificate {
            name: Arc::new(signer.key_name().clone()),
            public_key: Bytes::copy_from_slice(&signer.public_key_bytes()),
            valid_from: 0,
            valid_until: u64::MAX,
            issuer: None,
            signed_region: None,
            sig_value: None,
            sig_type: SignatureType::SignatureEd25519,
        };
        let key = |name: &str, seed: u8| Ed25519Signer::from_seed(&[seed; 32], n(name));
        let root = key("/home/bob/KEY/root", 80);
        let outside_anchor = key("/trust/KEY/a", 81);
        let ca = key("/home/bob/CA/KEY/ca", 82);
        let eve = key("/home/bob/member/eve/KEY/e", 83);
        let forged = key("/home/bob/member/alice/KEY/x", 84);
        let by_ca = key("/home/bob/member/alice/KEY/y", 85);
        let by_anchor = key("/home/bob/member/alice/KEY/z", 86);

        let ctx = SignedTrustContext::hierarchical(n("/home/bob")).with_ca_endpoint(n("/home/bob/CA"));
        assert!(ctx.add_anchor(anchor(&root)));
        assert!(ctx.add_anchor(anchor(&outside_anchor)));
        let validator = Validator::new(TrustSchema::hierarchical());
        validator.adopt_context(Arc::new(ctx));
        for (subject, issuer) in [
            (&ca, &root),
            (&eve, &ca),
            (&forged, &eve),
            (&by_ca, &ca),
            (&by_anchor, &outside_anchor),
        ] {
            let cert_name = subject.key_name().clone().append("NA").append_version(1);
            let wire = make_cert_data_packet(&cert_name, &subject.public_key_bytes(), issuer).await;
            validator
                .cert_cache()
                .insert(Certificate::decode(&Data::decode(wire).unwrap()).unwrap());
        }

        let doc = "/home/bob/member/alice/doc";
        match validator.validate_chain(&data_signed_by(doc, &forged)).await {
            ValidationResult::Invalid(TrustError::CertNotAuthorized { cert, issuer, .. }) => {
                assert!(n(&cert).has_prefix(forged.key_name()));
                assert_eq!(n(&issuer), *eve.key_name());
            }
            other => panic!("a member certified another device's key: {other:?}"),
        }
        for signer in [&by_ca, &by_anchor] {
            let result = validator.validate_chain(&data_signed_by(doc, signer)).await;
            assert!(matches!(result, ValidationResult::Valid(_)), "got {result:?}");
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

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    /// The key `/lab/eph/KEY/k1` (from `seed`) and its self-signed
    /// certificate Data `/lab/eph/KEY/k1/self/v=1`.
    async fn self_signed_key(seed: u8) -> (Ed25519Signer, Bytes) {
        let signer = Ed25519Signer::from_seed(&[seed; 32], n("/lab/eph/KEY/k1"));
        let cert = make_cert_data_packet(
            &n("/lab/eph/KEY/k1/self/v=1"),
            &signer.public_key_bytes(),
            &signer,
        )
        .await;
        (signer, cert)
    }

    /// Data `name` signed by `signer`, its KeyLocator naming `signer`'s key.
    fn data_signed_by(name: &str, signer: &Ed25519Signer) -> Data {
        let wire = ndn_packet::encode::DataBuilder::new(n(name), b"payload").sign_sync(
            SignatureType::SignatureEd25519,
            Some(signer.key_name()),
            |region| signer.sign_sync(region).unwrap(),
        );
        Data::decode(wire).unwrap()
    }

    /// Attach a fetcher answering every fetch with `served`; counts fetches.
    fn serve_on_fetch(
        validator: &Validator,
        served: Bytes,
    ) -> Arc<std::sync::atomic::AtomicUsize> {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let fetches = Arc::new(AtomicUsize::new(0));
        let f = Arc::clone(&fetches);
        let fetcher = Arc::new(crate::CertFetcher::new(
            validator.cert_cache_arc(),
            Arc::new(move |_| {
                f.fetch_add(1, Ordering::Relaxed);
                let data = Data::decode(served.clone()).map_err(|_| crate::FetchMiss::Unanswered);
                Box::pin(async move { data })
            }),
            std::time::Duration::from_secs(1),
        ));
        assert!(validator.set_cert_fetcher(fetcher).is_ok());
        fetches
    }

    fn fetch_count(fetches: &std::sync::atomic::AtomicUsize) -> usize {
        fetches.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// `accept_signed`: a self-signed certificate verifies itself — without a
    /// fetch of its own key, which on a forwarder would be answered by this
    /// very certificate, parked waiting for it — and Data signed by that key
    /// validates once the certificate is fetched; no trust anchor involved.
    #[tokio::test]
    async fn accept_signed_validates_self_signed_certificate_and_its_data() {
        let (signer, cert_wire) = self_signed_key(40).await;
        let validator = Validator::new(wildcard_schema()).accept_signed();
        let fetches = serve_on_fetch(&validator, cert_wire.clone());

        let cert = Data::decode(cert_wire).unwrap();
        let (result, missing) = validator.validate_chain_cached(&cert).await;
        assert!(matches!(result, ValidationResult::Valid(_)), "got {result:?}");
        assert!(missing.is_none());
        assert_eq!(fetch_count(&fetches), 0, "a self-signed cert is its own signer");

        let data = data_signed_by("/lab/eph/photo", &signer);
        let (result, missing) = validator.validate_chain_cached(&data).await;
        assert!(matches!(result, ValidationResult::Pending));
        assert_eq!(missing.as_deref(), Some(signer.key_name()));
        let result = validator.validate_chain(&data).await;
        assert!(matches!(result, ValidationResult::Valid(_)), "got {result:?}");
        assert_eq!(fetch_count(&fetches), 1);

        // A signature the certificate's key did not make still fails.
        let (impostor, _) = self_signed_key(41).await;
        let forged = data_signed_by("/lab/eph/photo", &impostor);
        assert!(matches!(
            validator.validate_chain(&forged).await,
            ValidationResult::Invalid(TrustError::InvalidSignature)
        ));
    }

    /// An anchored walk refuses a self-signed certificate that is no anchor
    /// with a verdict saying so — at once, without fetching its own key — and
    /// then refuses Data signed by that key at once too, while Data merely
    /// naming the key (signed by another) is resolved as usual.
    #[tokio::test]
    async fn anchored_walk_refuses_untrusted_self_signed_chain_without_fetching() {
        let (signer, cert_wire) = self_signed_key(42).await;
        let validator = Validator::new(wildcard_schema());
        let fetches = serve_on_fetch(&validator, cert_wire.clone());

        let cert = Data::decode(cert_wire).unwrap();
        let (result, missing) = validator.validate_chain_cached(&cert).await;
        match result {
            ValidationResult::Invalid(TrustError::UntrustedSelfSigned { cert, .. }) => {
                assert_eq!(cert, "/lab/eph/KEY/k1/self/v=1");
            }
            other => panic!("expected UntrustedSelfSigned, got {other:?}"),
        }
        assert!(missing.is_none());
        assert_eq!(fetch_count(&fetches), 0);
        assert!(validator.can_resolve(signer.key_name()));

        let data = data_signed_by("/lab/eph/photo", &signer);
        let (result, missing) = validator.validate_chain_cached(&data).await;
        assert!(
            matches!(result, ValidationResult::Invalid(TrustError::UntrustedSelfSigned { .. })),
            "got {result:?}"
        );
        assert!(missing.is_none());

        let (impostor, _) = self_signed_key(43).await;
        let other = data_signed_by("/lab/eph/photo", &impostor);
        let (result, missing) = validator.validate_chain_cached(&other).await;
        assert!(matches!(result, ValidationResult::Pending), "got {result:?}");
        assert_eq!(missing.as_deref(), Some(signer.key_name()));
        assert_eq!(fetch_count(&fetches), 0);
    }

    /// A fetched self-signed signer certificate ends an anchored walk with
    /// the untrusted-root verdict, not a chain cycle.
    #[tokio::test]
    async fn anchored_walk_refuses_data_whose_fetched_signer_is_self_signed() {
        let (signer, cert_wire) = self_signed_key(44).await;
        let validator = Validator::new(wildcard_schema());
        let fetches = serve_on_fetch(&validator, cert_wire);

        let data = data_signed_by("/lab/eph/photo", &signer);
        assert!(matches!(
            validator.validate_chain(&data).await,
            ValidationResult::Invalid(TrustError::UntrustedSelfSigned { .. })
        ));
        assert_eq!(fetch_count(&fetches), 1);
    }

    /// A self-signed certificate that IS an anchor still validates.
    #[tokio::test]
    async fn anchored_walk_accepts_self_signed_anchor_certificate() {
        let (_, cert_wire) = self_signed_key(45).await;
        let cert = Data::decode(cert_wire).unwrap();
        let validator = Validator::new(wildcard_schema());
        assert!(validator.add_trust_anchor(Certificate::decode(&cert).unwrap()));
        let (result, _) = validator.validate_chain_cached(&cert).await;
        assert!(matches!(result, ValidationResult::Valid(_)), "got {result:?}");
    }

    /// A certificate refused for its chain (its issuer is revoked) answers
    /// for its key: Data signed by that key gets the same verdict at once,
    /// not `Pending` on a certificate the fetch could only refuse again.
    #[tokio::test]
    async fn data_signed_by_a_refused_certificate_gets_its_verdict() {
        use crate::Keyring;
        use crate::cert_cache::CertCache;
        use crate::trust_context::SignedTrustContext;
        use dashmap::DashMap;

        let root = Ed25519Signer::from_seed(&[70; 32], n("/lab/KEY/root"));
        let ca = Ed25519Signer::from_seed(&[71; 32], n("/lab/CA/KEY/ca"));
        let member = Ed25519Signer::from_seed(&[72; 32], n("/lab/m/KEY/k1"));
        let ca_cert =
            make_cert_data_packet(&n("/lab/CA/KEY/ca/root/v=1"), &ca.public_key_bytes(), &root)
                .await;
        let member_cert =
            make_cert_data_packet(&n("/lab/m/KEY/k1/ca/v=1"), &member.public_key_bytes(), &ca)
                .await;

        let ambient = SignedTrustContext::ambient(wildcard_schema(), Arc::new(DashMap::new()))
            .with_revocation(ca.key_name().clone());
        ambient.add_anchor(Certificate {
            name: Arc::new(root.key_name().clone()),
            public_key: Bytes::copy_from_slice(&root.public_key_bytes()),
            valid_from: 0,
            valid_until: u64::MAX,
            issuer: None,
            signed_region: None,
            sig_value: None,
            sig_type: SignatureType::SignatureEd25519,
        });
        let cache = Arc::new(CertCache::new());
        cache.insert(Certificate::decode(&Data::decode(ca_cert).unwrap()).unwrap());
        let validator = Validator::with_keyring(
            Arc::new(Keyring::with_ambient(Arc::new(ambient))),
            cache,
            None,
            5,
        );

        let data = data_signed_by("/lab/m/photo", &member);
        let (result, _) = validator.validate_chain_cached(&data).await;
        assert!(matches!(result, ValidationResult::Pending), "got {result:?}");

        let (result, _) = validator
            .validate_chain_cached(&Data::decode(member_cert).unwrap())
            .await;
        assert!(
            matches!(result, ValidationResult::Invalid(TrustError::Revoked { .. })),
            "got {result:?}"
        );
        assert!(validator.can_resolve(member.key_name()));
        let (result, missing) = validator.validate_chain_cached(&data).await;
        assert!(
            matches!(result, ValidationResult::Invalid(TrustError::Revoked { .. })),
            "got {result:?}"
        );
        assert!(missing.is_none());
    }

    /// Symmetric signers keyed with `public_key` (anyone holds it), each
    /// naming `key_name` in its KeyLocator.
    fn mac_forgers(public_key: [u8; 32], key_name: &Name) -> Vec<Box<dyn Signer>> {
        vec![
            Box::new(crate::signer::HmacSha256Signer::new(&public_key, key_name.clone())),
            Box::new(crate::signer::Blake3KeyedSigner::new(public_key, key_name.clone())),
        ]
    }

    #[track_caller]
    fn assert_mac_refused(result: &ValidationResult) {
        assert!(
            matches!(result, ValidationResult::Invalid(TrustError::NotPublicKeySignature { .. })),
            "a MAC keyed with a public key must be refused as no public-key signature: {result:?}"
        );
    }

    /// A MAC keyed with a signer's public key is a forgery anyone can make.
    /// The chain walk refuses it at every hop: Data "signed" so by a trust
    /// anchor, by a certified key, and a certificate "issued" so by the
    /// anchor (the Data under it genuinely signed). Genuine chains validate.
    #[tokio::test]
    async fn chain_walk_refuses_a_mac_keyed_with_a_public_key() {
        let anchor = Ed25519Signer::from_seed(&[40u8; 32], n("/lab/KEY/root"));
        let member = Ed25519Signer::from_seed(&[41u8; 32], n("/lab/m/KEY/k1"));
        let validator = Validator::new(wildcard_schema());
        validator.add_trust_anchor(anchor_cert(
            anchor.key_name().clone(),
            anchor.public_key_bytes(),
        ));
        // The single-hop `validate` resolves the anchor's key from the cache.
        validator.cert_cache().insert(anchor_cert(
            anchor.key_name().clone(),
            anchor.public_key_bytes(),
        ));
        let member_cert = make_cert_data_packet(
            &n("/lab/m/KEY/k1/root/v=1"),
            &member.public_key_bytes(),
            &anchor,
        )
        .await;
        validator
            .cert_cache()
            .insert(Certificate::decode(&Data::decode(member_cert).unwrap()).unwrap());

        let mac_signed = |signer: &dyn Signer, name: &str| {
            let wire = ndn_packet::encode::DataBuilder::new(n(name), b"forged").sign_sync(
                signer.sig_type(),
                Some(signer.key_name()),
                |region| signer.sign_sync(region).unwrap(),
            );
            Data::decode(wire).unwrap()
        };
        for forger in mac_forgers(anchor.public_key_bytes(), anchor.key_name()) {
            let data = mac_signed(forger.as_ref(), "/lab/by-anchor");
            assert_mac_refused(&validator.validate_chain(&data).await);
            assert_mac_refused(&validator.validate(&data).await);
        }
        for forger in mac_forgers(member.public_key_bytes(), member.key_name()) {
            let data = mac_signed(forger.as_ref(), "/lab/m/by-member");
            assert_mac_refused(&validator.validate_chain(&data).await);
            assert_mac_refused(&validator.validate(&data).await);
        }

        // A certificate "issued" with a MAC keyed with the anchor's public key.
        let intruder = Ed25519Signer::from_seed(&[42u8; 32], n("/lab/x/KEY/k1"));
        for forger in mac_forgers(anchor.public_key_bytes(), anchor.key_name()) {
            let forged_cert = crate::manager::encode_cert_data(
                &n("/lab/x/KEY/k1/root/v=1"),
                &intruder.public_key_bytes(),
                forger.as_ref(),
                0,
                u64::MAX,
            )
            .await
            .unwrap();
            let validator = Validator::new(wildcard_schema());
            validator.add_trust_anchor(anchor_cert(
                anchor.key_name().clone(),
                anchor.public_key_bytes(),
            ));
            validator
                .cert_cache()
                .insert(Certificate::decode(&Data::decode(forged_cert.clone()).unwrap()).unwrap());
            let data = data_signed_by("/lab/x/photo", &intruder);
            assert_mac_refused(&validator.validate_chain(&data).await);
            assert_mac_refused(&validator.validate_chain(&Data::decode(forged_cert).unwrap()).await);
        }

        let genuine = data_signed_by("/lab/m/photo", &member);
        assert!(matches!(
            validator.validate_chain(&genuine).await,
            ValidationResult::Valid(_)
        ));
    }

    /// A signed Interest "signed" with a MAC keyed with the signer's public
    /// key, or with only a DigestSha256 (no signer at all), is refused by
    /// both Interest paths; a genuinely signed one validates.
    #[tokio::test]
    async fn interest_validation_refuses_a_mac_or_a_digest() {
        use ndn_packet::Interest;
        use ndn_packet::encode::InterestBuilder;

        let anchor = Ed25519Signer::from_seed(&[43u8; 32], n("/lab/KEY/root"));
        let validator = Validator::new(wildcard_schema());
        validator.add_trust_anchor(anchor_cert(
            anchor.key_name().clone(),
            anchor.public_key_bytes(),
        ));
        validator.cert_cache().insert(anchor_cert(
            anchor.key_name().clone(),
            anchor.public_key_bytes(),
        ));
        let refused = |outcome: crate::InterestValidationOutcome| {
            matches!(
                outcome,
                crate::InterestValidationOutcome::Invalid(TrustError::NotPublicKeySignature { .. })
            )
        };

        for forger in mac_forgers(anchor.public_key_bytes(), anchor.key_name()) {
            let wire = InterestBuilder::new(n("/lab/cmd"))
                .app_parameters(Bytes::from_static(b"p"))
                .sign_sync(forger.sig_type(), Some(forger.key_name()), |region| {
                    forger.sign_sync(region).unwrap()
                });
            let interest = Interest::decode(wire).unwrap();
            assert!(refused(validator.validate_interest_chain(&interest).await));
            assert!(refused(validator.validate_interest(&interest).await));
        }

        let digest = InterestBuilder::new(n("/lab/cmd"))
            .app_parameters(Bytes::from_static(b"p"))
            .sign_digest_sha256();
        let interest = Interest::decode(digest).unwrap();
        assert!(refused(validator.validate_interest_chain(&interest).await));
        assert!(refused(validator.validate_interest(&interest).await));

        let wire = make_signed_interest(&anchor, anchor.key_name(), "/lab/cmd").await;
        let interest = Interest::decode(wire).unwrap();
        assert!(matches!(
            validator.validate_interest_chain(&interest).await,
            crate::InterestValidationOutcome::Valid
        ));
        assert!(matches!(
            validator.validate_interest(&interest).await,
            crate::InterestValidationOutcome::Valid
        ));
    }
}
