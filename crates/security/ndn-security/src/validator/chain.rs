use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use ndn_packet::{Data, Interest, KeyLocator, Name, SignatureType};

use crate::cert_cache::Certificate;
use crate::cert_name::{is_cert_name, is_cert_of, is_reserved_non_cert, key_name_of};
use crate::safe_data::TrustPath;
use crate::verifier::{DIGEST_NO_SIGNER, not_public_key, verify_by_sig_type};
use crate::{SafeData, TrustError, VerifyOutcome};

use super::durable::{SignerRule, pick_verifying, signer_rule};
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
    /// A copy of this certificate of the chain was refused and dropped from
    /// the cache: its own signature does not verify under its issuer's
    /// vouched-for key (its bytes were altered on the way, or never
    /// signed), or a signature failed under it and nothing vouched for it.
    /// The refusal is of that copy, not of the key: another copy may be
    /// honest.
    RefusedCopy(Arc<Name>),
}

/// Where a walk took the certificate of a hop's key from, which decides
/// what a signature failing under it says (trust-context.md §6.5).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Source {
    /// A trust anchor, or a certificate the cache holds vouched for: it is
    /// authentic, so a signature failing under it is forged.
    Vouched,
    /// A certificate the cache holds unverified; `fetched`: this walk
    /// fetched it.
    Unverified { fetched: bool },
    /// The packet's own certificate, or a refused certificate the validator
    /// remembers: not the cache's, and a signature failing under it refuses
    /// the signed bytes.
    Uncached,
}

impl Source {
    /// A certificate the cache holds: vouched for, or unverified (fetched by
    /// an earlier walk).
    fn of_cache(vouched: bool) -> Self {
        if vouched {
            Self::Vouched
        } else {
            Self::Unverified { fetched: false }
        }
    }
}

/// Whether a hop's signature is known to verify under the key's
/// certificate.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Sig {
    Verified,
    Failed,
    Unchecked,
}

/// The first hop of a walk whose signature failed under an unverified
/// certificate: the walk goes on to the anchors, which tell whether that
/// copy or the signed bytes are forged.
struct Suspect {
    /// The certificate whose signature failed; `None`: the packet's own.
    signed: Option<Certificate>,
    /// The unverified certificate of the key it failed under.
    key: Certificate,
    /// Where `key` is in the walk's taken certificates.
    from: usize,
}

/// The unverified certificates a walk took, in chain order, each with
/// whether this walk fetched it.
type Taken = Vec<(Certificate, bool)>;

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
        let (result, _missing) = self.validate_chain_inner(data, true, false).await;
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
        let (result, missing) = self.validate_chain_inner(data, false, false).await;
        self.bump_for_result(&result);
        (result, missing)
    }

    /// Validate Data by the **durable** rule (`docs/specs/trust-context.md`
    /// §6.3): its verdict depends on a clock only to refuse a lapsed key
    /// whose role needs a cut. The same walk as [`Self::validate_chain`] —
    /// signatures, schema and hierarchy, certificate authorization, anchors,
    /// revocations — except that:
    ///
    /// - no ValidityPeriod is checked, of an anchor or of a certificate: a
    ///   key's certificate proves the key was authorized, and its authority
    ///   over Data ends by a revocation in the trust context. A key's
    ///   certificate is any one of it, cached or fetched, that verifies the
    ///   signature, the newest NotBefore first;
    /// - the key that signed the packet itself (depth 0: its KeyLocator, and
    ///   the certificate whose public key verifies the packet) is judged by
    ///   the durable rule: revoked without a cut, refused; revoked with a
    ///   cut ([`RevocationCut`](crate::RevocationCut)), excused only when
    ///   the cut's key digest (if set) is that certificate's public key and
    ///   an exact entry, or a range — with the cut's manifest (if set)
    ///   listing exactly the packet's implicit digest — accepts it; not
    ///   revoked but of a device role listed in DataRequiresCut
    ///   ([`SignedTrustContext::requires_cut_for`](crate::SignedTrustContext::requires_cut_for)),
    ///   accepted only while a certificate of the key with that public key
    ///   is valid now. Revoked keys higher in the chain (issuers) are
    ///   refused as by [`Self::validate_chain`].
    ///
    /// A packet refused by the durable rule at depth 0 is refused with
    /// [`TrustError::Revoked`] only once its signature and chain check out
    /// (an authentic packet of that key); a forgery naming such a key gets
    /// the verdict its signature or chain earns. A packet whose signer is
    /// revoked without a cut is refused at once, as every packet of that key
    /// is. A cut-manifest packet the verdict needs is fetched by its full
    /// name through the [`CertFetcher`](crate::CertFetcher), as a
    /// certificate is (each level of the manifest tree in turn); when it
    /// cannot be had the result is `Pending`.
    ///
    /// For Data only: signed Interests, commands and trust-context adoption
    /// stay live ([`Self::validate_interest_chain`], [`Self::validate_chain`]).
    pub async fn validate_durable(&self, data: &Data) -> ValidationResult {
        let (result, _missing) = self.validate_chain_inner(data, true, true).await;
        self.bump_for_result(&result);
        result
    }

    /// [`Self::validate_durable`] using only certificates and cut-manifest
    /// packets already held, as [`Self::validate_chain_cached`] does:
    /// `(Pending, Some(missing))` names what to fetch before validating
    /// again — a certificate, or a cut-manifest packet by its full name
    /// ([`is_full_name`](crate::is_full_name);
    /// [`CertFetcher::fetch_missing`](crate::CertFetcher::fetch_missing)
    /// fetches either) — see [`Self::can_resolve_durable`].
    pub async fn validate_durable_cached(
        &self,
        data: &Data,
    ) -> (ValidationResult, Option<Arc<Name>>) {
        let (result, missing) = self.validate_chain_inner(data, false, true).await;
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
        durable: bool,
    ) -> (ValidationResult, Option<Arc<Name>>) {
        let result = |r: ValidationResult| (r, None);
        // An adoption in progress decides its own context Data (and nothing
        // else); with no expectation this is one atomic load.
        if let Some(r) = self.admit_expected_context(data).await {
            return result(r);
        }
        // A person's names whose namespace is not held: refused whatever
        // signs them; a digest, which vouches for nothing, passes
        // integrity-only as under every name (see `unheld_person`).
        let digest = data
            .sig_info()
            .is_some_and(|s| s.sig_type == SignatureType::DigestSha256);
        if let Some(refused) = self.unheld_person(&data.name, digest) {
            return result(ValidationResult::Invalid(refused));
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
        if let Some(refused) = self.unanchored(&data.name) {
            return result(ValidationResult::Invalid(refused));
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
                durable,
                false,
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
            // A refused copy of a certificate on the chain, dropped: it is
            // missing, as one never cached is.
            WalkOutcome::Pending(missing) | WalkOutcome::RefusedCopy(missing) => {
                (ValidationResult::Pending, Some(missing))
            }
            WalkOutcome::Invalid(e) => {
                // A certificate refused with a final verdict answers for its
                // key for a while (`refused_certs`): Data parked waiting for
                // that key is then re-walked through it and refused with the
                // same verdict (e.g. its issuer is revoked) at once, instead
                // of timing out while the fetch could not change the answer.
                // A signature that does not verify is a verdict on these
                // bytes, not on the key: another copy may be honest, so that
                // refusal answers for nothing.
                if !matches!(e, TrustError::InvalidSignature)
                    && is_cert_name(&data.name)
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
        if let Some(refused) = self.unheld_person(&interest.name, false) {
            return InterestValidationOutcome::Invalid(refused);
        }
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
        if let Some(refused) = self.unanchored(&interest.name) {
            return InterestValidationOutcome::Invalid(refused);
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
                false,
                false,
            )
            .await
        {
            WalkOutcome::Trusted(_) => InterestValidationOutcome::Valid,
            WalkOutcome::Pending(_) | WalkOutcome::RefusedCopy(_) => {
                InterestValidationOutcome::Pending
            }
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
    /// signer — but for a name in a person's namespace (`/user/<h>`), which
    /// is walked to the anchors under every posture.
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
    /// refused for its chain or its key (not for its own signature) is
    /// remembered for its key ([`Self::refused_certs`]) by the Data
    /// validation that refused it.
    ///
    /// Certificates cached vouched for answer before unverified ones
    /// ([`CertCache`](crate::CertCache)); trust-context.md §6.5:
    ///
    /// - a walk that reaches an anchor vouches for every unverified
    ///   certificate it took ([`CertCache::admit`](crate::CertCache));
    /// - a signature that fails under a vouched-for key (or an anchor) is
    ///   forged: the packet's own refuses the packet, a certificate's is a
    ///   refused copy, evicted by its bytes;
    /// - a signature that fails under an unverified certificate says nothing
    ///   yet of which is forged: the walk goes on to the anchors with that
    ///   key, and reaching them vouches for the key (the signed bytes are
    ///   forged, as above), while not reaching them refuses the key's copy;
    /// - a walk that ends without reaching an anchor drops the unverified
    ///   certificates it took — but for a cache-only walk waiting for a
    ///   missing certificate whose fetch has not failed, which resumes once
    ///   it is fetched.
    ///
    /// A refused copy is not the packet's refusal: a fetching walk walks once
    /// more, which fetches the certificate again, and refuses the packet
    /// `InvalidSignature` only if that copy is refused too; a cache-only
    /// walk names the certificate missing ([`WalkOutcome::RefusedCopy`]),
    /// for its caller to fetch. A fetching walk also walks once more after
    /// dropping unverified certificates an earlier walk fetched.
    ///
    /// `durable` (Data only, see [`Self::validate_durable`]): no
    /// ValidityPeriod is checked, a key resolves to any of its certificates
    /// that verifies the signature (the newest NotBefore first), and a
    /// revocation of the packet's own signer is excused by its key's cut, or
    /// else, for a key with a cut, reported once the rest of the chain checks
    /// out ([`revocation_of`]).
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
        durable: bool,
        cert_walk: bool,
    ) -> WalkOutcome {
        let mut walks = 0;
        let outcome = loop {
            walks += 1;
            let mut again = false;
            let outcome = self
                .walk_once(
                    context_name,
                    Arc::clone(&first_key),
                    first_signed_region,
                    first_sig_value,
                    first_sig_type,
                    fetch,
                    packet,
                    durable,
                    cert_walk,
                    &mut again,
                )
                .await;
            let more = again || matches!(outcome, WalkOutcome::RefusedCopy(_));
            if !(fetch && more && walks < 2) {
                break outcome;
            }
        };
        match outcome {
            WalkOutcome::RefusedCopy(_) if fetch => {
                WalkOutcome::Invalid(TrustError::InvalidSignature)
            }
            other => other,
        }
    }

    /// One walk of [`Self::walk_to_anchor`]. Sets `again` when it dropped
    /// unverified certificates an earlier walk fetched, which a fetching
    /// walk fetches afresh by walking once more. `cert_walk`: the signed
    /// bytes are a certificate's, `context_name` its name, so its first hop
    /// is a certificate hop (a renewal vouched for, `vouch_renewal`).
    #[allow(clippy::too_many_arguments)]
    async fn walk_once(
        &self,
        context_name: &Name,
        first_key: Arc<Name>,
        first_signed_region: &[u8],
        first_sig_value: &[u8],
        first_sig_type: SignatureType,
        fetch: bool,
        packet: Option<&Data>,
        durable: bool,
        cert_walk: bool,
        again: &mut bool,
    ) -> WalkOutcome {
        let ctx = self.keyring.context_for(context_name);
        let authoritative = ctx.schema_is_authoritative();
        // Durable walks are for Data; a walk without a packet is live.
        let durable = durable && packet.is_some();
        let require_anchor = self.anchor_required(context_name);

        let now = now_ns();
        // Durable: the refusal of the packet's own signer by the durable
        // rule ([`durable::signer_rule`]), reported only if the chain
        // otherwise checks out (so it is about an authentic packet of that
        // key), and the cut-manifest packet that verdict waits for.
        let mut revoked_signer: Option<TrustError> = None;
        let mut missing_manifest: Option<Arc<Name>> = None;
        // The packet, while the walk is at its own signer (depth 0) of a
        // durable walk: the signer the durable rule judges.
        let signed_packet = |depth: usize| packet.filter(|_| durable && depth == 0);
        let trusted = |chain_names: Vec<Name>,
                       revoked: Option<TrustError>,
                       missing: Option<Arc<Name>>| match (revoked, missing) {
            (Some(refused), _) => WalkOutcome::Invalid(refused),
            (None, Some(missing)) => WalkOutcome::Pending(missing),
            (None, None) => WalkOutcome::Trusted(chain_names),
        };
        let mut chain_names: Vec<Name> = Vec::new();
        let mut seen: HashSet<Arc<Name>> = HashSet::new();
        let mut taken: Taken = Vec::new();
        let mut suspect: Option<Suspect> = None;
        // The walk ends without reaching an anchor.
        macro_rules! fail {
            ($outcome:expr) => {
                return self.unvouched($outcome, &taken, suspect, fetch, again)
            };
        }

        // The hop whose authorization waits for its signer to resolve: the
        // packet's own hop when its KeyLocator alone (or its key name) is not
        // enough — a schema over certificate names needs the signer's
        // certificate — then each certificate, checked against its issuer.
        let mut pending: Option<Hop> = if cert_walk {
            Some(Hop::Cert(Arc::new(context_name.clone())))
        } else {
            (!ctx.authorizes_hop(context_name, &first_key, None))
                .then(|| Hop::Packet(context_name.clone()))
        };
        let hop_refused = |hop: &Option<Hop>, signer: &Name, signer_cert: &Name| match hop {
            Some(Hop::Packet(name)) if !ctx.authorizes_hop(name, signer, Some(signer_cert)) => {
                Some(WalkOutcome::Invalid(TrustError::SchemaMismatch))
            }
            // Every certificate hop is authorized by the context's
            // certification rule (anchor, identity prefix, or the context's
            // CA within its namespace), so an enrolled device cannot certify
            // another device's key.
            Some(Hop::Cert(cert)) if !ctx.authorizes_certification(cert, signer) => {
                let why = if ctx.has_shared_user_floor() {
                    // The ambient context refuses only across /user/<x>.
                    "/user is shared by every person, so under the trust anchors this node \
                     holds for names no adopted context covers, a key under one /user/<x> \
                     certifies no key under another /user/<y>; adopt the trust context of the \
                     certificate's /user/<y>, or add its own root as a trust anchor"
                        .to_string()
                } else {
                    let cas: Vec<String> = ctx.ca_endpoints().iter().map(Name::to_string).collect();
                    format!(
                        "under the trust context for {ns} a key certifies only names under its \
                         own identity, unless it is a trust anchor of the context or a key of \
                         the context's CA ({cas}) certifying a name under {ns}; have the key \
                         certified by the namespace CA (enroll the device)",
                        ns = ctx.namespace(),
                        cas = if cas.is_empty() {
                            "none named".to_string()
                        } else {
                            cas.join(", ")
                        },
                    )
                };
                Some(WalkOutcome::Invalid(TrustError::CertNotAuthorized {
                    cert: cert.to_string(),
                    issuer: signer.to_string(),
                    why,
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
        // The certificate whose own signature the current hop checks: none
        // at the packet's hop (depth 0).
        let mut checking: Option<Certificate> = None;

        for depth in 0..self.max_chain {
            if !seen.insert(Arc::clone(&current_key_name)) {
                fail!(WalkOutcome::Invalid(TrustError::ChainCycle {
                    name: current_key_name.to_string(),
                }));
            }

            // A chain that passes through a key revoked by the selected context
            // is rejected — how an issuing-CA compromise is contained by a pulled
            // context bump (no re-bootstrap). A durable walk leaves the
            // packet's own signer, when its key has a cut, to the durable
            // rule once the certificate that verifies the packet is known.
            match revocation_of(&ctx, &current_key_name, signed_packet(depth).is_some()) {
                Revocation::Clear | Revocation::ByCut => {}
                Revocation::Refused(refused) => fail!(WalkOutcome::Invalid(refused)),
            }

            // Anchors match by key: a KeyLocator naming the anchor's key or any
            // certificate of it terminates the chain there. A durable walk
            // does not judge the anchor's ValidityPeriod.
            if let Some(anchor) = ctx.anchor_for(&current_key_name) {
                if !durable && !anchor.is_valid_at(now) {
                    fail!(WalkOutcome::Invalid(TrustError::CertNotFound {
                        name: format!("expired trust anchor: {}", current_key_name),
                    }));
                }
                if let Some(refused) = hop_refused(&pending, &current_key_name, &anchor.name) {
                    fail!(refused);
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
                        if let Some(p) = signed_packet(depth) {
                            match self
                                .durable_signer(
                                    &ctx,
                                    p,
                                    &current_key_name,
                                    &anchor,
                                    fetch,
                                    require_anchor,
                                )
                                .await
                            {
                                SignerRule::Clear => {}
                                SignerRule::Refused(refused) => {
                                    revoked_signer.get_or_insert(refused);
                                }
                                SignerRule::Missing(name) => {
                                    missing_manifest = Some(Arc::new(name))
                                }
                            }
                        }
                        chain_names.push(current_key_name.as_ref().clone());
                        match self.reached_anchor(&taken, suspect) {
                            Some(refused) => refused,
                            None => trusted(chain_names, revoked_signer, missing_manifest),
                        }
                    }
                    Ok(VerifyOutcome::Invalid) => {
                        match self.bad_signature(&checking, None, &mut suspect, &taken, false) {
                            Some(refused) => refused,
                            None => unreachable!("an anchor's key is authentic"),
                        }
                    }
                    Err(e) => {
                        self.unvouched(WalkOutcome::Invalid(e), &taken, suspect, fetch, again)
                    }
                };
            }

            // Live: the key's newest certificate valid now. Durable: its
            // newest certificate of any validity that verifies the signature.
            // One vouched for before an unverified one.
            let cached = if durable {
                match self
                    .durable_cached(
                        &current_key_name,
                        current_signed_region,
                        current_sig_value,
                        current_sig_type,
                    )
                    .await
                {
                    Ok(cached) => cached,
                    Err(e) => fail!(WalkOutcome::Invalid(e)),
                }
            } else {
                self.cert_cache
                    .resolve(&current_key_name)
                    .map(|(cert, vouched)| (cert, Source::of_cache(vouched), Sig::Unchecked))
            };
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
            let resolved = cached.or_else(|| own.map(|c| (c, Source::Uncached, Sig::Unchecked)));
            let (cert, source, sig) = match resolved {
                Some(resolved) => resolved,
                None => match self
                    .refused_signer(
                        &current_key_name,
                        current_signed_region,
                        current_sig_value,
                        current_sig_type,
                        durable,
                    )
                    .await
                {
                    Some(c) => (c, Source::Uncached, Sig::Verified),
                    None => match self.resolve_uncached(&current_key_name, fetch).await {
                        Some((c, source)) => (c, source, Sig::Unchecked),
                        // Nothing can fetch the certificate that might authorize the
                        // packet: it is refused as before, not left pending forever.
                        // (A cache-only walk reports it missing, for its caller to fetch.)
                        None if fetch
                            && matches!(pending, Some(Hop::Packet(_)))
                            && self.cert_fetcher.get().is_none() =>
                        {
                            fail!(WalkOutcome::Invalid(TrustError::SchemaMismatch));
                        }
                        None => fail!(WalkOutcome::Pending(current_key_name)),
                    },
                },
            };
            if let Source::Unverified { fetched } = source {
                taken.push((cert.clone(), fetched));
            }

            if !durable && !cert.is_valid_at(now) {
                fail!(WalkOutcome::Invalid(TrustError::CertNotFound {
                    name: format!("expired or not-yet-valid: {}", cert.name),
                }));
            }
            // A KeyLocator naming the key resolves to one of its certificates;
            // a revocation naming that certificate refuses it too (left to
            // the durable rule as the key's own revocation above).
            match revocation_of(&ctx, &cert.name, signed_packet(depth).is_some()) {
                Revocation::Clear | Revocation::ByCut => {}
                Revocation::Refused(refused) => fail!(WalkOutcome::Invalid(refused)),
            }
            // Data that merely shares the certificate name shape is no
            // certificate (an admin's NDNCERT decision
            // `<key>/ndncert-approve|ndncert-deny/<id>`).
            if crate::cert_name::is_reserved_non_cert(&cert.name) {
                fail!(WalkOutcome::Invalid(TrustError::CertNotAuthorized {
                    cert: cert.name.to_string(),
                    issuer: current_key_name.to_string(),
                    why: "it is an admin's NDNCERT decision (`<key>/ndncert-approve/<id>` or \
                          `<key>/ndncert-deny/<id>`), not a certificate, and never answers for \
                          a key"
                        .to_string(),
                }));
            }
            if let Some(refused) = hop_refused(&pending, &current_key_name, &cert.name) {
                fail!(refused);
            }

            let verifies = match sig {
                Sig::Verified => true,
                Sig::Failed => false,
                Sig::Unchecked => match verify_by_sig_type(
                    current_sig_type,
                    current_signed_region,
                    current_sig_value,
                    &cert.public_key,
                )
                .await
                {
                    Ok(VerifyOutcome::Valid) => true,
                    Ok(VerifyOutcome::Invalid) => false,
                    Err(e) => fail!(WalkOutcome::Invalid(e)),
                },
            };
            if !verifies
                && let Some(refused) = self.bad_signature(
                    &checking,
                    Some((&cert, source)),
                    &mut suspect,
                    &taken,
                    require_anchor,
                )
            {
                return refused;
            }
            // The packet's own signer, now that the certificate whose
            // public key verifies it is known.
            if verifies && let Some(p) = signed_packet(depth) {
                match self
                    .durable_signer(&ctx, p, &current_key_name, &cert, fetch, require_anchor)
                    .await
                {
                    SignerRule::Clear => {}
                    SignerRule::Refused(refused) => {
                        revoked_signer.get_or_insert(refused);
                    }
                    SignerRule::Missing(name) => missing_manifest = Some(Arc::new(name)),
                }
            }

            chain_names.push(current_key_name.as_ref().clone());
            if !require_anchor {
                return trusted(chain_names, revoked_signer, missing_manifest);
            }

            let Some(issuer) = &cert.issuer else {
                fail!(WalkOutcome::Invalid(TrustError::CertNotFound {
                    name: format!("cert has no issuer: {}", cert.name),
                }));
            };
            // A self-signed certificate that is no anchor (an anchor of its
            // key ended the walk above) ends the chain: nothing vouches for it.
            if key_name_of(issuer) == cert.key_name() {
                fail!(WalkOutcome::Invalid(TrustError::UntrustedSelfSigned {
                    cert: cert.name.to_string(),
                    namespace: ctx.namespace().to_string(),
                }));
            }
            let Some(sr) = &cert.signed_region else {
                fail!(WalkOutcome::Invalid(TrustError::CertNotFound {
                    name: format!("cert missing signed region: {}", cert.name),
                }));
            };
            let Some(sv) = &cert.sig_value else {
                fail!(WalkOutcome::Invalid(TrustError::CertNotFound {
                    name: format!("cert missing sig value: {}", cert.name),
                }));
            };

            owned_signed_region = sr.clone();
            owned_sig_value = sv.clone();
            current_signed_region = &owned_signed_region;
            current_sig_value = &owned_sig_value;
            current_key_name = Arc::clone(issuer);
            current_sig_type = cert.sig_type;
            pending = Some(Hop::Cert(Arc::clone(&cert.name)));
            checking = Some(cert);
        }

        fail!(WalkOutcome::Invalid(TrustError::ChainTooDeep {
            limit: self.max_chain,
        }));
    }

    /// A walk reached an anchor: every unverified certificate it took — from
    /// the suspect's key up, with a suspect — verified up to it, and is
    /// vouched for from now on. With a suspect, the bytes signed under the
    /// suspect's key, now vouched for, are forged: the refusal.
    fn reached_anchor(&self, taken: &Taken, suspect: Option<Suspect>) -> Option<WalkOutcome> {
        let from = suspect.as_ref().map_or(0, |s| s.from);
        for (cert, _) in &taken[from..] {
            self.cert_cache.admit(cert);
        }
        suspect.map(|s| self.forged(&s.signed))
    }

    /// A hop's signature — of `signed` (`None`: the packet's own) — failed
    /// under `key` (`None`: an anchor) and its source. Under a key vouched
    /// for, the signed bytes are forged ([`Self::forged`]). Under an
    /// unverified one, nothing tells yet which is: a walk that must reach an
    /// anchor goes on with that key as the suspect (`None`); one that need
    /// not (accept-signed) refuses the key's copy, as does a second failure
    /// under an unverified key.
    fn bad_signature(
        &self,
        signed: &Option<Certificate>,
        key: Option<(&Certificate, Source)>,
        suspect: &mut Option<Suspect>,
        taken: &Taken,
        require_anchor: bool,
    ) -> Option<WalkOutcome> {
        let Some((key, Source::Unverified { .. })) = key else {
            let refused = self.forged(signed);
            // The chain above an earlier suspect met forged bytes: nothing
            // vouched for that suspect.
            if let Some(first) = suspect.take() {
                self.cert_cache.drop_unverified(&first.key);
            }
            return Some(refused);
        };
        if let Some(first) = suspect.take() {
            self.cert_cache.drop_unverified(&first.key);
            self.cert_cache.drop_unverified(key);
            return Some(WalkOutcome::RefusedCopy(Arc::clone(&first.key.name)));
        }
        if !require_anchor {
            return Some(if self.cert_cache.drop_unverified(key) {
                WalkOutcome::RefusedCopy(Arc::clone(&key.name))
            } else {
                WalkOutcome::Invalid(TrustError::InvalidSignature)
            });
        }
        *suspect = Some(Suspect {
            signed: signed.clone(),
            key: key.clone(),
            from: taken.len() - 1,
        });
        None
    }

    /// `signed` (`None`: the packet itself) does not verify under a key
    /// vouched for: the packet is refused `InvalidSignature`; a certificate
    /// is a refused copy, evicted by its bytes.
    fn forged(&self, signed: &Option<Certificate>) -> WalkOutcome {
        match signed {
            Some(cert) if self.cert_cache.evict(cert) => {
                WalkOutcome::RefusedCopy(Arc::clone(&cert.name))
            }
            _ => WalkOutcome::Invalid(TrustError::InvalidSignature),
        }
    }

    /// A walk ends with `outcome` without reaching an anchor. The unverified
    /// certificates it took vouch for nothing and are dropped (`again` set
    /// when an earlier walk fetched one of them), and with a suspect the
    /// suspect's copy is refused instead — but a cache-only walk waiting for
    /// a missing certificate keeps them while the fetch of what is missing
    /// has not failed: it resumes once its caller fetches it.
    fn unvouched(
        &self,
        outcome: WalkOutcome,
        taken: &Taken,
        suspect: Option<Suspect>,
        fetch: bool,
        again: &mut bool,
    ) -> WalkOutcome {
        if !fetch && let WalkOutcome::Pending(missing) = &outcome {
            if self.fetch_failed(missing) {
                for (cert, _) in taken {
                    self.cert_cache.drop_unverified(cert);
                }
            }
            return outcome;
        }
        let mut stale = false;
        for (cert, fetched) in taken {
            stale |= self.cert_cache.drop_unverified(cert) && !fetched;
        }
        match suspect {
            Some(first) => WalkOutcome::RefusedCopy(Arc::clone(&first.key.name)),
            None => {
                *again = stale;
                outcome
            }
        }
    }

    /// Whether the last fetch of `name` brought no certificate, and the
    /// fetcher would not ask for it again yet.
    fn fetch_failed(&self, name: &Name) -> bool {
        self.cert_fetcher
            .get()
            .is_some_and(|f| f.failed_recently(name))
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
            None => self
                .resolve_uncached(name, fetch)
                .await
                .map(|(cert, _)| cert),
        }
    }

    /// [`Self::resolve_cert`] once no certificate valid now is cached, with
    /// where it came from: fetched now, or (expired) cached.
    async fn resolve_uncached(
        &self,
        name: &Arc<Name>,
        fetch: bool,
    ) -> Option<(Certificate, Source)> {
        let cached = || {
            self.cert_cache
                .get_any(name)
                .map(|(cert, vouched)| (cert, Source::of_cache(vouched)))
        };
        match self.cert_fetcher.get() {
            Some(fetcher) if fetch => match fetcher.fetch(name).await {
                Ok(cert) => Some((cert, Source::Unverified { fetched: true })),
                Err(_) => cached(),
            },
            Some(_) if !is_cert_name(name) => None,
            _ => cached(),
        }
    }

    /// Whether a walk resolves `name` (a KeyLocator) without fetching: a
    /// certificate valid now is cached, or a certificate of it was refused
    /// recently (the validator's refused-certificate memory). The forwarder's validation stage
    /// re-validates Data parked for `name` once this holds.
    pub fn can_resolve(&self, name: &Name) -> bool {
        self.cert_cache.get_valid(name).is_some() || self.refused_cert(name, false).is_some()
    }

    /// [`Self::can_resolve`] for a durable walk ([`Self::validate_durable_cached`]):
    /// a certificate of any validity is cached under `name`, or one was
    /// refused recently. An expired certificate a fetch brought in resolves
    /// the key, as the durable walk takes it. A full name (ending in an
    /// ImplicitSha256DigestComponent) is a cut-manifest packet the walk
    /// named missing: it resolves once held
    /// ([`CertCache::cut_manifests`](crate::CertCache::cut_manifests)).
    pub fn can_resolve_durable(&self, name: &Name) -> bool {
        if crate::cert_fetcher::is_full_name(name) {
            return self.cert_cache.cut_manifests().contains(name);
        }
        !self.cert_cache.all(name).is_empty() || self.refused_cert(name, true).is_some()
    }

    /// The refused certificate answering for `name`, while it does. A live
    /// walk (`durable` unset) takes it only while it is valid now.
    fn refused_cert(&self, name: &Name, durable: bool) -> Option<Certificate> {
        if self.refused_certs.is_empty() {
            return None;
        }
        let entry = self.refused_certs.get(&key_name_of(name))?;
        let (cert, until) = entry.value();
        let now = now_ns();
        (now < *until && (durable || cert.is_valid_at(now)) && cert.name.has_prefix(name))
            .then(|| cert.clone())
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
        durable: bool,
    ) -> Option<Certificate> {
        let cert = self.refused_cert(key, durable)?;
        match verify_by_sig_type(sig_type, signed_region, sig_value, &cert.public_key).await {
            Ok(VerifyOutcome::Valid) => Some(cert),
            _ => None,
        }
    }

    /// A durable walk's certificate for `key` from the cache: of the cached
    /// certificates `key` resolves to, valid now or not, the newest
    /// (NotBefore, then name) whose public key verifies the current
    /// signature, one vouched for before an unverified one. `Ok(None)` when
    /// none is cached (resolve it otherwise). When some are cached and none
    /// verifies, the newest — vouched for first — as the certificate the
    /// signature failed under ([`Sig::Failed`]), as a live walk refuses a
    /// signature its cached certificate does not verify. An error when a
    /// signature cannot be checked at all.
    async fn durable_cached(
        &self,
        key: &Name,
        signed_region: &[u8],
        sig_value: &[u8],
        sig_type: SignatureType,
    ) -> Result<Option<(Certificate, Source, Sig)>, TrustError> {
        let (vouched, unverified) = self.cert_cache.all_by_kind(key);
        let mut failed = None;
        for (certs, source) in [
            (vouched, Source::Vouched),
            (unverified, Source::Unverified { fetched: false }),
        ] {
            let newest = certs
                .iter()
                .max_by(|a, b| {
                    (a.valid_from, a.name.as_ref()).cmp(&(b.valid_from, b.name.as_ref()))
                })
                .cloned();
            match pick_verifying(certs, signed_region, sig_value, sig_type) {
                Ok(Some(cert)) => return Ok(Some((cert, source, Sig::Verified))),
                Ok(None) => {}
                Err(TrustError::InvalidSignature) => {
                    failed = failed.or(newest.map(|cert| (cert, source, Sig::Failed)));
                }
                Err(e) => return Err(e),
            }
        }
        Ok(failed)
    }

    /// The durable rule on the packet's own signer `locator`, verified by
    /// `verifying` ([`signer_rule`]). A fetching walk (`fetch`, with a
    /// fetcher attached) first fetches what the verdict waits for: each
    /// missing cut-manifest packet on the entry's path, by its full name.
    ///
    /// For a lapsed key whose role needs a cut, a current certificate of the
    /// key renews it (it may have been renewed). A walk that must reach an
    /// anchor (`require_anchor`) takes only one vouched for: it vouches for
    /// an unverified one it holds, or fetches (`fetch`), by walking it to
    /// the anchors ([`Self::vouch_renewal`]), and the verdict waits for a
    /// certificate that walk names missing. One that reaches for no anchor
    /// fetches a current certificate and trusts it as resolved.
    async fn durable_signer(
        &self,
        ctx: &crate::SignedTrustContext,
        packet: &Data,
        locator: &Name,
        verifying: &Certificate,
        fetch: bool,
        require_anchor: bool,
    ) -> SignerRule {
        let fetcher = self.cert_fetcher.get().filter(|_| fetch);
        let rule = || {
            signer_rule(
                ctx,
                &self.cert_cache,
                packet,
                locator,
                verifying,
                now_ns(),
                !require_anchor,
            )
        };
        let mut renewal_asked = false;
        // Each fetch brings one more level of the manifest tree.
        for _ in 0..=crate::cut_manifest::MAX_DEPTH {
            let rule = rule();
            match (&rule, fetcher) {
                (SignerRule::Missing(name), Some(fetcher)) => {
                    if fetcher
                        .fetch_missing(&Arc::new(name.clone()), None)
                        .await
                        .is_err()
                    {
                        return rule;
                    }
                }
                (SignerRule::Refused(TrustError::Revoked { why, .. }), _)
                    if *why == TrustError::REVOKED_LAPSED && !renewal_asked =>
                {
                    renewal_asked = true;
                    if require_anchor {
                        match self.vouch_renewal(locator, verifying, fetch).await {
                            Ok(true) => {}
                            Ok(false) => return rule,
                            Err(missing) => return SignerRule::Missing(missing.as_ref().clone()),
                        }
                    } else {
                        let Some(fetcher) = fetcher else { return rule };
                        if fetcher.fetch(&Arc::new(locator.clone())).await.is_err() {
                            return rule;
                        }
                    }
                }
                _ => return rule,
            }
        }
        rule()
    }

    /// Vouch for a renewal of the key `locator` names: a certificate of it
    /// with `verifying`'s public key, valid now, held unverified — or, with
    /// none and `fetch`, fetched — walked to the anchors as a certificate
    /// (its issuer's chain). `Ok(true)` once one reached them and is vouched
    /// for; `Ok(false)` when none could be, each dropped; `Err` naming the
    /// certificate a cache-only walk waits for. Boxed, and `Send` by its
    /// type: a walk judging a packet's signer walks the renewal in turn.
    fn vouch_renewal<'a>(
        &'a self,
        locator: &'a Name,
        verifying: &'a Certificate,
        fetch: bool,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<bool, Arc<Name>>> + Send + 'a>> {
        Box::pin(async move {
            let key = key_name_of(locator);
            let now = now_ns();
            let renews =
                |c: &Certificate| c.public_key == verifying.public_key && c.is_valid_at(now);
            let mut renewals: Vec<Certificate> = self
                .cert_cache
                .all_by_kind(&key)
                .1
                .into_iter()
                .filter(renews)
                .collect();
            if renewals.is_empty()
                && fetch
                && let Some(fetcher) = self.cert_fetcher.get()
                && let Ok(cert) = fetcher.fetch(&Arc::new(key.clone())).await
                && renews(&cert)
            {
                renewals.push(cert);
            }
            for cert in renewals {
                let (Some(issuer), Some(region), Some(sig)) =
                    (&cert.issuer, &cert.signed_region, &cert.sig_value)
                else {
                    self.cert_cache.drop_unverified(&cert);
                    continue;
                };
                let walked = self
                    .walk_to_anchor(
                        &cert.name,
                        Arc::clone(issuer),
                        region,
                        sig,
                        cert.sig_type,
                        fetch,
                        None,
                        false,
                        true,
                    )
                    .await;
                match walked {
                    WalkOutcome::Trusted(_) if self.anchor_required(&cert.name) => {
                        self.cert_cache.admit(&cert);
                        return Ok(true);
                    }
                    WalkOutcome::Pending(missing) | WalkOutcome::RefusedCopy(missing) if !fetch => {
                        return Err(missing);
                    }
                    _ => {
                        self.cert_cache.drop_unverified(&cert);
                    }
                }
            }
            Ok(false)
        })
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

/// How a chain hop through `name` (a key or certificate name) stands with
/// the revocations of its context ([`revocation_of`]).
enum Revocation {
    /// No Revocation covers it.
    Clear,
    /// Refused at once.
    Refused(TrustError),
    /// The packet's own signer in a durable walk, revoked with a cut: the
    /// durable rule judges it once the certificate that verifies the packet
    /// is known ([`signer_rule`]), so that only an authentic packet of the
    /// key is reported outside its cut (a forgery at a name the cut lists
    /// gets the verdict its signature earns).
    ByCut,
}

/// The [`Revocation`] of a chain hop through `name` under `ctx`.
/// `durable_signer`: the hop is the packet's own signer in a durable walk.
/// A key revoked without a cut is refused at once, as before cuts existed:
/// every packet it signed is refused whatever its bytes, and the
/// certificates of such a key and of its issuers are usually withdrawn, so
/// waiting for them would leave the packet unverifiable instead of revoked.
fn revocation_of(ctx: &crate::SignedTrustContext, name: &Name, durable_signer: bool) -> Revocation {
    if !ctx.is_revoked(name) {
        return Revocation::Clear;
    }
    if durable_signer && ctx.revocation_cut(&key_name_of(name)).is_some() {
        return Revocation::ByCut;
    }
    Revocation::Refused(TrustError::Revoked {
        name: name.to_string(),
        why: TrustError::REVOKED,
    })
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

        let key_cert =
            Data::decode(make_cert_data_packet(&name1("key"), &key_pk, &mid_signer).await).unwrap();
        validator
            .cert_cache()
            .insert(Certificate::decode(&key_cert).unwrap());
        let (result, missing) = validator.validate_chain_cached(&data).await;
        assert!(matches!(result, ValidationResult::Pending));
        assert_eq!(missing.as_deref(), Some(&name1("mid")));

        assert_eq!(
            fetches.load(Ordering::Relaxed),
            0,
            "cached walk must not fetch"
        );
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

    /// `refuse_without_anchors`: with no anchor in the governing context,
    /// key-signed Data is refused at once (no certificate is asked for) by
    /// every Data path; DigestSha256 Data still validates; once an anchor is
    /// added the chain is walked as usual.
    #[tokio::test]
    async fn refuse_without_anchors_refuses_until_an_anchor_is_added() {
        let signer = Ed25519Signer::from_seed(&[26u8; 32], name1("key"));
        let data = Data::decode(make_signed_data(&signer, "data", "key").await).unwrap();
        let validator = Validator::new(wildcard_schema()).refuse_without_anchors();

        match validator.validate_chain_cached(&data).await {
            (ValidationResult::Invalid(TrustError::NoTrustAnchors { .. }), None) => {}
            other => panic!("expected NoTrustAnchors with nothing to fetch, got: {other:?}"),
        }
        assert!(matches!(
            validator.validate(&data).await,
            ValidationResult::Invalid(TrustError::NoTrustAnchors { .. })
        ));
        let digest = Data::decode(
            ndn_packet::encode::DataBuilder::new(name1("data"), b"x").sign_digest_sha256(),
        )
        .unwrap();
        assert!(matches!(
            validator.validate_chain(&digest).await,
            ValidationResult::Valid(_)
        ));

        validator.add_trust_anchor(Certificate {
            name: Arc::new(signer.key_name().clone()),
            public_key: Bytes::copy_from_slice(&signer.public_key_bytes()),
            valid_from: 0,
            valid_until: u64::MAX,
            issuer: None,
            signed_region: None,
            sig_value: None,
            sig_type: SignatureType::SignatureEd25519,
        });
        assert!(matches!(
            validator.validate_chain(&data).await,
            ValidationResult::Valid(_)
        ));
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

        let ctx =
            SignedTrustContext::hierarchical(n("/home/bob")).with_ca_endpoint(n("/home/bob/CA"));
        assert!(ctx.add_anchor(anchor(&root)));
        assert!(ctx.add_anchor(anchor(&outside_anchor)));
        let validator = Validator::new(TrustSchema::hierarchical());
        validator.adopt_context(Arc::new(ctx)).unwrap();
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
        match validator
            .validate_chain(&data_signed_by(doc, &forged))
            .await
        {
            ValidationResult::Invalid(TrustError::CertNotAuthorized { cert, issuer, .. }) => {
                assert!(n(&cert).has_prefix(forged.key_name()));
                assert_eq!(n(&issuer), *eve.key_name());
            }
            other => panic!("a member certified another device's key: {other:?}"),
        }
        for signer in [&by_ca, &by_anchor] {
            let result = validator.validate_chain(&data_signed_by(doc, signer)).await;
            assert!(
                matches!(result, ValidationResult::Valid(_)),
                "got {result:?}"
            );
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
            ValidationResult::Invalid(TrustError::Revoked { name, .. }) => {
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
    fn serve_on_fetch(validator: &Validator, served: Bytes) -> Arc<std::sync::atomic::AtomicUsize> {
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
        assert!(
            matches!(result, ValidationResult::Valid(_)),
            "got {result:?}"
        );
        assert!(missing.is_none());
        assert_eq!(
            fetch_count(&fetches),
            0,
            "a self-signed cert is its own signer"
        );

        let data = data_signed_by("/lab/eph/photo", &signer);
        let (result, missing) = validator.validate_chain_cached(&data).await;
        assert!(matches!(result, ValidationResult::Pending));
        assert_eq!(missing.as_deref(), Some(signer.key_name()));
        let result = validator.validate_chain(&data).await;
        assert!(
            matches!(result, ValidationResult::Valid(_)),
            "got {result:?}"
        );
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
            matches!(
                result,
                ValidationResult::Invalid(TrustError::UntrustedSelfSigned { .. })
            ),
            "got {result:?}"
        );
        assert!(missing.is_none());

        let (impostor, _) = self_signed_key(43).await;
        let other = data_signed_by("/lab/eph/photo", &impostor);
        let (result, missing) = validator.validate_chain_cached(&other).await;
        assert!(
            matches!(result, ValidationResult::Pending),
            "got {result:?}"
        );
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
        assert!(
            matches!(result, ValidationResult::Valid(_)),
            "got {result:?}"
        );
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
        assert!(
            matches!(result, ValidationResult::Pending),
            "got {result:?}"
        );

        let (result, _) = validator
            .validate_chain_cached(&Data::decode(member_cert).unwrap())
            .await;
        assert!(
            matches!(
                result,
                ValidationResult::Invalid(TrustError::Revoked { .. })
            ),
            "got {result:?}"
        );
        assert!(validator.can_resolve(member.key_name()));
        let (result, missing) = validator.validate_chain_cached(&data).await;
        assert!(
            matches!(
                result,
                ValidationResult::Invalid(TrustError::Revoked { .. })
            ),
            "got {result:?}"
        );
        assert!(missing.is_none());
    }

    /// A copy of a certificate whose signature was altered on the way (one
    /// byte of it flipped, as a faulty or hostile link does) is refused
    /// where the walk checks it against its issuer — and is not kept: the
    /// cache stops answering for its key with it, so the next copy, which
    /// may be honest, is asked for. A cache-only walk names the certificate
    /// missing (its caller fetches it and validates again); a fetching walk
    /// asks again at once and validates with the honest copy.
    #[tokio::test]
    async fn a_certificate_copy_refused_as_forged_is_evicted_and_asked_for_again() {
        let root = Ed25519Signer::from_seed(&[80; 32], n("/lab/KEY/root"));
        let member = Ed25519Signer::from_seed(&[81; 32], n("/lab/m/KEY/k1"));
        let cert_name = n("/lab/m/KEY/k1/root/v=1");
        let honest = make_cert_data_packet(&cert_name, &member.public_key_bytes(), &root).await;
        // The SignatureValue is the packet's last element.
        let mut altered = honest.to_vec();
        *altered.last_mut().unwrap() ^= 0x5a;
        let forged = Certificate::decode(&Data::decode(Bytes::from(altered)).unwrap()).unwrap();

        let validator = Validator::new(wildcard_schema());
        validator.add_trust_anchor(anchor_cert(
            root.key_name().clone(),
            root.public_key_bytes(),
        ));
        validator.cert_cache().insert(forged.clone());
        let data = data_signed_by("/lab/m/photo", &member);

        let (result, missing) = validator.validate_durable_cached(&data).await;
        assert!(
            matches!(result, ValidationResult::Pending),
            "a forged copy of the signer's certificate refused the honest Data: {result:?}"
        );
        assert_eq!(missing.as_deref(), Some(&cert_name));
        assert!(
            validator.cert_cache().all(member.key_name()).is_empty(),
            "the refused copy is still cached"
        );

        validator.cert_cache().insert(forged);
        let fetches = serve_on_fetch(&validator, honest);
        let result = validator.validate_durable(&data).await;
        assert!(
            matches!(result, ValidationResult::Valid(_)),
            "got {result:?}"
        );
        assert_eq!(
            fetch_count(&fetches),
            1,
            "the certificate is asked for again"
        );
    }

    /// A certificate packet refused for its own signature (a forwarder
    /// validating a copy altered on the way) does not answer for its key:
    /// Data that key signed waits for the certificate, as with none held,
    /// instead of being refused through the forged copy.
    #[tokio::test]
    async fn a_certificate_packet_refused_as_forged_answers_for_nothing() {
        let root = Ed25519Signer::from_seed(&[82; 32], n("/lab/KEY/root"));
        let member = Ed25519Signer::from_seed(&[83; 32], n("/lab/m/KEY/k1"));
        let cert_name = n("/lab/m/KEY/k1/root/v=1");
        let honest = make_cert_data_packet(&cert_name, &member.public_key_bytes(), &root).await;
        let mut altered = honest.to_vec();
        *altered.last_mut().unwrap() ^= 0x5a;

        let validator = Validator::new(wildcard_schema());
        validator.add_trust_anchor(anchor_cert(
            root.key_name().clone(),
            root.public_key_bytes(),
        ));
        let (result, _) = validator
            .validate_durable_cached(&Data::decode(Bytes::from(altered)).unwrap())
            .await;
        assert!(
            matches!(
                result,
                ValidationResult::Invalid(TrustError::InvalidSignature)
            ),
            "got {result:?}"
        );

        let data = data_signed_by("/lab/m/photo", &member);
        let (result, missing) = validator.validate_durable_cached(&data).await;
        assert!(
            matches!(result, ValidationResult::Pending),
            "the forged copy refused the honest Data: {result:?}"
        );
        assert_eq!(missing.as_deref(), Some(member.key_name()));
    }

    /// Attach a fetcher answering each fetch under one of `served`'s key
    /// names with the next of its packets (the last again once they run
    /// out), with no failure back-off; counts the fetches of each.
    fn serve_in_turn(
        validator: &Validator,
        served: Vec<(Name, Vec<Bytes>)>,
    ) -> Arc<Vec<std::sync::atomic::AtomicUsize>> {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let counts: Arc<Vec<AtomicUsize>> =
            Arc::new(served.iter().map(|_| AtomicUsize::new(0)).collect());
        let c = Arc::clone(&counts);
        let fetcher = crate::CertFetcher::new(
            validator.cert_cache_arc(),
            Arc::new(move |name: Name| {
                let data = served
                    .iter()
                    .position(|(key, _)| name.has_prefix(key))
                    .ok_or(crate::FetchMiss::Absent)
                    .and_then(|i| {
                        let nth = c[i].fetch_add(1, Ordering::Relaxed);
                        let packets = &served[i].1;
                        Data::decode(packets[nth.min(packets.len() - 1)].clone())
                            .map_err(|_| crate::FetchMiss::Unanswered)
                    });
                Box::pin(async move { data })
            }),
            std::time::Duration::from_secs(1),
        )
        .with_negative_ttl(std::time::Duration::ZERO);
        assert!(validator.set_cert_fetcher(Arc::new(fetcher)).is_ok());
        counts
    }

    /// The member key `/lab/m/KEY/k1` (from `seed`), its honest certificate
    /// `/lab/m/KEY/k1/root/v=1` issued by `root`, and a copy of it holding
    /// Mallory's public key, which she signed as if she were the root.
    async fn member_with_forged_copy(
        root: &Ed25519Signer,
        seed: u8,
    ) -> (Ed25519Signer, Bytes, Bytes) {
        let member = Ed25519Signer::from_seed(&[seed; 32], n("/lab/m/KEY/k1"));
        let mallory = Ed25519Signer::from_seed(&[seed + 1; 32], root.key_name().clone());
        let cert_name = n("/lab/m/KEY/k1/root/v=1");
        let honest = make_cert_data_packet(&cert_name, &member.public_key_bytes(), root).await;
        let forged = make_cert_data_packet(&cert_name, &mallory.public_key_bytes(), &mallory).await;
        (member, honest, forged)
    }

    /// A fetched copy of the signer's certificate holding another public
    /// key (Mallory answering the fetch, or a link altering it) refuses no
    /// honest packet beyond the walk that met it: that walk cannot vouch for
    /// the copy (its own signature fails under the anchor), drops it and
    /// asks again, and the honest copy — vouched for once the walk reaches
    /// the anchor — validates the packet and answers from then on; a packet
    /// that copy's key signed is refused, at no fetch (spec §6.5).
    #[tokio::test]
    async fn a_fetched_signer_certificate_with_a_forged_public_key_refuses_no_honest_packet() {
        let root = Ed25519Signer::from_seed(&[84; 32], n("/lab/KEY/root"));
        let (member, honest, forged) = member_with_forged_copy(&root, 85).await;
        let validator = Validator::new(wildcard_schema());
        validator.add_trust_anchor(anchor_cert(
            root.key_name().clone(),
            root.public_key_bytes(),
        ));
        let fetches = serve_in_turn(
            &validator,
            vec![(member.key_name().clone(), vec![forged, honest])],
        );
        let data = data_signed_by("/lab/m/photo", &member);

        let result = validator.validate_durable(&data).await;
        assert!(
            matches!(result, ValidationResult::Valid(_)),
            "the honest Data, a forged copy of its signer's certificate fetched first: {result:?}"
        );
        assert_eq!(fetch_count(&fetches[0]), 2, "asked for again once");
        for _ in 0..2 {
            assert!(matches!(
                validator.validate_chain(&data).await,
                ValidationResult::Valid(_)
            ));
        }
        let hers = data_signed_by(
            "/lab/m/forged",
            &Ed25519Signer::from_seed(&[86; 32], n("/lab/m/KEY/k1")),
        );
        let result = validator.validate_durable(&hers).await;
        assert!(
            matches!(
                result,
                ValidationResult::Invalid(TrustError::InvalidSignature)
            ),
            "Mallory's packet under the member's key: {result:?}"
        );
        assert_eq!(
            fetch_count(&fetches[0]),
            2,
            "the vouched-for copy answers: no more fetches"
        );
    }

    /// The same through a cache-only walk (a forwarder's validation stage,
    /// which fetches what a walk names missing and validates again): the
    /// walk that meets the forged copy drops it and names the certificate
    /// missing, and once it is fetched again the honest packet validates.
    #[tokio::test]
    async fn a_cache_only_walk_drops_a_fetched_copy_with_a_forged_public_key() {
        let root = Ed25519Signer::from_seed(&[87; 32], n("/lab/KEY/root"));
        let (member, honest, forged) = member_with_forged_copy(&root, 88).await;
        let validator = Validator::new(wildcard_schema());
        validator.add_trust_anchor(anchor_cert(
            root.key_name().clone(),
            root.public_key_bytes(),
        ));
        let fetches = serve_in_turn(
            &validator,
            vec![(member.key_name().clone(), vec![forged, honest])],
        );
        let fetcher = Arc::clone(validator.cert_fetcher().unwrap());
        let data = data_signed_by("/lab/m/photo", &member);

        let (result, missing) = validator.validate_durable_cached(&data).await;
        assert!(
            matches!(result, ValidationResult::Pending),
            "got {result:?}"
        );
        fetcher
            .fetch_missing(&missing.unwrap(), None)
            .await
            .unwrap();
        let (result, missing) = validator.validate_durable_cached(&data).await;
        assert!(
            matches!(result, ValidationResult::Pending),
            "the honest Data, a forged copy of its signer's certificate cached: {result:?}"
        );
        fetcher
            .fetch_missing(&missing.unwrap(), None)
            .await
            .unwrap();
        let (result, _) = validator.validate_durable_cached(&data).await;
        assert!(
            matches!(result, ValidationResult::Valid(_)),
            "after the certificate is fetched again: {result:?}"
        );
        assert_eq!(fetch_count(&fetches[0]), 2);
    }

    /// A fetched copy of an *issuer's* certificate holding another public
    /// key refuses no honest packet beyond its walk either, and costs no
    /// fetch per validation: the walk drops that copy (not the honest
    /// certificate below it, which it cannot tell apart until the issuer is
    /// vouched for), fetches it again and validates; every later validation
    /// answers from the certificates it vouched for.
    #[tokio::test]
    async fn a_fetched_issuer_certificate_with_a_forged_public_key_refuses_no_honest_packet() {
        let root = Ed25519Signer::from_seed(&[90; 32], n("/lab/KEY/root"));
        let ca = Ed25519Signer::from_seed(&[91; 32], n("/lab/CA/KEY/ca"));
        let member = Ed25519Signer::from_seed(&[92; 32], n("/lab/m/KEY/k1"));
        let mallory = Ed25519Signer::from_seed(&[93; 32], n("/lab/KEY/root"));
        let ca_name = n("/lab/CA/KEY/ca/root/v=1");
        let ca_honest = make_cert_data_packet(&ca_name, &ca.public_key_bytes(), &root).await;
        let ca_forged =
            make_cert_data_packet(&ca_name, &mallory.public_key_bytes(), &mallory).await;
        let member_cert =
            make_cert_data_packet(&n("/lab/m/KEY/k1/ca/v=1"), &member.public_key_bytes(), &ca)
                .await;
        let validator = Validator::new(wildcard_schema());
        validator.add_trust_anchor(anchor_cert(
            root.key_name().clone(),
            root.public_key_bytes(),
        ));
        let fetches = serve_in_turn(
            &validator,
            vec![
                (member.key_name().clone(), vec![member_cert]),
                (ca.key_name().clone(), vec![ca_forged, ca_honest]),
            ],
        );
        let data = data_signed_by("/lab/m/photo", &member);

        let result = validator.validate_durable(&data).await;
        assert!(
            matches!(result, ValidationResult::Valid(_)),
            "the honest Data, a forged copy of its issuer's certificate fetched first: {result:?}"
        );
        let counts = || (fetch_count(&fetches[0]), fetch_count(&fetches[1]));
        assert_eq!(counts(), (1, 2), "(member, CA) certificate fetches");
        for _ in 0..3 {
            assert!(matches!(
                validator.validate_durable(&data).await,
                ValidationResult::Valid(_)
            ));
            assert!(matches!(
                validator.validate_chain(&data).await,
                ValidationResult::Valid(_)
            ));
        }
        assert_eq!(counts(), (1, 2), "no fetch per validation");
    }

    /// A fetched copy of the signer's certificate that Mallory issued
    /// herself (the honest public key, her own key as its issuer) refuses no
    /// honest packet beyond its walk: a chain that does not reach an anchor
    /// vouches for none of the copies it took, so a later walk fetches them
    /// again rather than meeting the same copy.
    #[tokio::test]
    async fn a_fetched_certificate_copy_issued_by_another_key_does_not_outlive_its_walk() {
        let root = Ed25519Signer::from_seed(&[94; 32], n("/lab/KEY/root"));
        let member = Ed25519Signer::from_seed(&[95; 32], n("/lab/m/KEY/k1"));
        let (mallory, mallory_cert) = self_signed_key(96).await;
        let cert_name = n("/lab/m/KEY/k1/root/v=1");
        let honest = make_cert_data_packet(&cert_name, &member.public_key_bytes(), &root).await;
        let hers = make_cert_data_packet(&cert_name, &member.public_key_bytes(), &mallory).await;
        let validator = Validator::new(wildcard_schema());
        validator.add_trust_anchor(anchor_cert(
            root.key_name().clone(),
            root.public_key_bytes(),
        ));
        let fetches = serve_in_turn(
            &validator,
            vec![
                (member.key_name().clone(), vec![hers, honest]),
                (mallory.key_name().clone(), vec![mallory_cert]),
            ],
        );
        let data = data_signed_by("/lab/m/photo", &member);

        let result = validator.validate_durable(&data).await;
        assert!(
            matches!(result, ValidationResult::Invalid(_)),
            "a chain ending at Mallory's own key: {result:?}"
        );
        let result = validator.validate_durable(&data).await;
        assert!(
            matches!(result, ValidationResult::Valid(_)),
            "the honest Data, once its signer's certificate is fetched again: {result:?}"
        );
        assert_eq!(fetch_count(&fetches[0]), 2);
    }

    /// Symmetric signers keyed with `public_key` (anyone holds it), each
    /// naming `key_name` in its KeyLocator.
    fn mac_forgers(public_key: [u8; 32], key_name: &Name) -> Vec<Box<dyn Signer>> {
        vec![
            Box::new(crate::signer::HmacSha256Signer::new(
                &public_key,
                key_name.clone(),
            )),
            Box::new(crate::signer::Blake3KeyedSigner::new(
                public_key,
                key_name.clone(),
            )),
        ]
    }

    #[track_caller]
    fn assert_mac_refused(result: &ValidationResult) {
        assert!(
            matches!(
                result,
                ValidationResult::Invalid(TrustError::NotPublicKeySignature { .. })
            ),
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
            assert_mac_refused(
                &validator
                    .validate_chain(&Data::decode(forged_cert).unwrap())
                    .await,
            );
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

    // ── durable (Data) validation ───────────────────────────────────────────

    mod durable {
        use super::*;
        use crate::cert_cache::CertCache;
        use crate::{Keyring, RevocationCut, SignedTrustContext};

        /// 2001-09-09, a NotBefore long past.
        const PAST: u64 = 1_000_000_000_000_000_000;
        /// 2017-07-14, a NotAfter long past.
        const EXPIRED: u64 = 1_500_000_000_000_000_000;
        /// 2286-11-20, a NotBefore not reached yet.
        const FUTURE: u64 = 10_000_000_000_000_000_000;

        const PHONE: &str = "/home/bob/member/phone/KEY/k1";
        const CA: &str = "/home/bob/CA/KEY/ca";

        fn signer(name: &str, seed: u8) -> Ed25519Signer {
            Ed25519Signer::from_seed(&[seed; 32], n(name))
        }

        /// The certificate `<key>/<issuer-id>/v=1` of `subject`, issued by
        /// `issuer`, valid `from..=until`.
        async fn cert(
            subject: &Ed25519Signer,
            issuer: &Ed25519Signer,
            issuer_id: &str,
            from: u64,
            until: u64,
        ) -> Bytes {
            crate::manager::encode_cert_data(
                &subject
                    .key_name()
                    .clone()
                    .append(issuer_id)
                    .append_version(1),
                &subject.public_key_bytes(),
                issuer,
                from,
                until,
            )
            .await
            .unwrap()
        }

        fn decoded(wire: &Bytes) -> Certificate {
            Certificate::decode(&Data::decode(wire.clone()).unwrap()).unwrap()
        }

        /// `/home/bob/member/phone/32=log/<collection>/seq=<seq>`.
        fn log_name(collection: &str, seq: u64) -> Name {
            log_prefix(collection).append_sequence_num(seq)
        }

        fn log_prefix(collection: &str) -> Name {
            n("/home/bob/member/phone")
                .append_component(NameComponent::keyword(Bytes::from_static(b"log")))
                .append(collection)
        }

        fn signed(name: Name, content: &[u8], by: &Ed25519Signer) -> Data {
            let wire = ndn_packet::encode::DataBuilder::new(name, content).sign_sync(
                SignatureType::SignatureEd25519,
                Some(by.key_name()),
                |region| by.sign_sync(region).unwrap(),
            );
            Data::decode(wire).unwrap()
        }

        /// The namespace `/home/bob`: root `/home/bob/KEY/root` (anchor valid
        /// until `anchor_until`), CA `/home/bob/CA/KEY/ca` certified by the
        /// root, and the phone's key certified by the CA, valid
        /// `leaf_from..=leaf_until`. `edit` shapes the context (revocations,
        /// cuts). The phone's certificate is cached unless `cache_leaf` is
        /// unset (it is then served by a fetcher).
        struct Bob {
            validator: Validator,
            phone: Ed25519Signer,
            leaf: Bytes,
        }

        async fn bob(
            anchor_until: u64,
            (leaf_from, leaf_until): (u64, u64),
            cache_leaf: bool,
            edit: impl FnOnce(SignedTrustContext) -> SignedTrustContext,
        ) -> Bob {
            let root = signer("/home/bob/KEY/root", 70);
            let ca = signer(CA, 71);
            let phone = signer(PHONE, 72);
            let anchor = decoded(&cert(&root, &root, "self", PAST, anchor_until).await);
            let ca_cert = decoded(&cert(&ca, &root, "root", PAST, u64::MAX).await);
            let leaf = cert(&phone, &ca, "CA", leaf_from, leaf_until).await;

            let ctx = edit(
                SignedTrustContext::hierarchical(n("/home/bob"))
                    .with_ca_endpoint(n("/home/bob/CA"))
                    .with_version(1),
            );
            // Inserted directly: `add_anchor` refuses an anchor expired now.
            ctx.anchors().insert(Arc::clone(&anchor.name), anchor);
            let keyring = Arc::new(Keyring::new());
            keyring.adopt(Arc::new(ctx)).unwrap();
            let cache = Arc::new(CertCache::new());
            cache.insert(ca_cert);
            if cache_leaf {
                cache.insert(decoded(&leaf));
            }
            Bob {
                validator: Validator::with_keyring(keyring, cache, None, 5),
                phone,
                leaf,
            }
        }

        fn valid(result: &ValidationResult) -> bool {
            matches!(result, ValidationResult::Valid(_))
        }

        /// The key a `Revoked` refusal names, if that is the refusal.
        fn revoked_key(result: &ValidationResult) -> Option<Name> {
            match result {
                ValidationResult::Invalid(TrustError::Revoked { name, .. }) => {
                    Some(key_name_of(&name.parse().unwrap()))
                }
                _ => None,
            }
        }

        fn phone_cut() -> RevocationCut {
            let mut cut = RevocationCut::new(n(PHONE));
            cut.add_run(&log_prefix("notes"), 1, 3);
            cut
        }

        #[tokio::test]
        async fn expired_certificates_and_anchors_do_not_refuse_data() {
            let cases = [
                ("expired leaf", u64::MAX, (PAST, EXPIRED)),
                ("leaf not yet valid", u64::MAX, (FUTURE, u64::MAX)),
                ("expired anchor", EXPIRED, (PAST, u64::MAX)),
            ];
            for (why, anchor_until, leaf) in cases {
                let bob = bob(anchor_until, leaf, true, |c| c).await;
                let data = signed(log_name("notes", 2), b"v", &bob.phone);
                assert!(
                    valid(&bob.validator.validate_durable(&data).await),
                    "{why}: durable"
                );
                assert!(
                    valid(&bob.validator.validate_durable_cached(&data).await.0),
                    "{why}: durable, cache only"
                );
                assert!(
                    matches!(
                        bob.validator.validate_chain(&data).await,
                        ValidationResult::Invalid(_)
                    ),
                    "{why}: live stays refused"
                );
            }
        }

        #[tokio::test]
        async fn a_revoked_key_without_a_cut_signs_nothing() {
            let bob = bob(u64::MAX, (PAST, u64::MAX), true, |c| {
                c.with_revocation(n(PHONE))
            })
            .await;
            let data = signed(log_name("notes", 2), b"v", &bob.phone);
            let result = bob.validator.validate_durable(&data).await;
            assert_eq!(revoked_key(&result), Some(n(PHONE)), "{result:?}");
        }

        #[tokio::test]
        async fn a_cut_admits_exactly_what_it_lists_whatever_the_dates() {
            for leaf in [(PAST, u64::MAX), (PAST, EXPIRED), (FUTURE, u64::MAX)] {
                let bob = bob(u64::MAX, leaf, true, |c| {
                    c.with_revocation(n(PHONE)).with_revocation_cut(phone_cut())
                })
                .await;
                let inside = signed(log_name("notes", 3), b"v", &bob.phone);
                assert!(valid(&bob.validator.validate_durable(&inside).await));
                assert!(valid(
                    &bob.validator.validate_durable_cached(&inside).await.0
                ));
                // Live walks ignore cuts: the key stays revoked for them.
                assert!(revoked_key(&bob.validator.validate_chain(&inside).await).is_some());

                for outside in [
                    log_name("notes", 4),
                    log_name("photos", 2),
                    log_name("notes", 2).append("x"),
                    log_prefix("notes"),
                ] {
                    let data = signed(outside.clone(), b"v", &bob.phone);
                    let result = bob.validator.validate_durable(&data).await;
                    assert_eq!(
                        revoked_key(&result),
                        Some(n(PHONE)),
                        "{outside}: {result:?}"
                    );
                }
            }
        }

        #[tokio::test]
        async fn an_exact_readmission_binds_the_bytes() {
            let phone = signer(PHONE, 72);
            let kept = signed(log_name("notes", 9), b"honest", &phone);
            let mut cut = phone_cut();
            cut.readmit(
                kept.name
                    .as_ref()
                    .clone()
                    .append_implicit_digest(kept.implicit_digest()),
            )
            .unwrap();
            let bob = bob(u64::MAX, (PAST, u64::MAX), true, |c| {
                c.with_revocation(n(PHONE)).with_revocation_cut(cut)
            })
            .await;
            assert!(valid(&bob.validator.validate_durable(&kept).await));
            let other = signed(log_name("notes", 9), b"thief", &bob.phone);
            let result = bob.validator.validate_durable(&other).await;
            assert_eq!(revoked_key(&result), Some(n(PHONE)), "{result:?}");
        }

        #[tokio::test]
        async fn a_forgery_naming_a_revoked_key_is_not_reported_revoked() {
            let bob = bob(u64::MAX, (PAST, u64::MAX), true, |c| {
                c.with_revocation(n(PHONE)).with_revocation_cut(phone_cut())
            })
            .await;
            let thief = signer(PHONE, 99);
            for name in [log_name("notes", 2), log_name("notes", 7)] {
                let forged = signed(name.clone(), b"v", &thief);
                let result = bob.validator.validate_durable(&forged).await;
                assert!(
                    matches!(
                        result,
                        ValidationResult::Invalid(TrustError::InvalidSignature)
                    ),
                    "{name}: {result:?}"
                );
            }
        }

        #[tokio::test]
        async fn a_revoked_issuer_is_refused_even_with_a_cut() {
            let mut ca_cut = RevocationCut::new(n(CA));
            ca_cut.add_run(&log_prefix("notes"), 0, u64::MAX);
            let bob = bob(u64::MAX, (PAST, u64::MAX), true, |c| {
                c.with_revocation(n(CA)).with_revocation_cut(ca_cut)
            })
            .await;
            let data = signed(log_name("notes", 2), b"v", &bob.phone);
            let result = bob.validator.validate_durable(&data).await;
            assert_eq!(revoked_key(&result), Some(n(CA)), "{result:?}");
        }

        /// D11: the certificate of a key revoked with a cut still resolves —
        /// fetched by a reader that caches none — and verifies in-cut Data.
        #[tokio::test]
        async fn a_cut_keys_certificate_is_fetched_and_verifies_in_cut_data() {
            let bob = bob(u64::MAX, (PAST, EXPIRED), false, |c| {
                c.with_revocation(n(PHONE)).with_revocation_cut(phone_cut())
            })
            .await;
            let inside = signed(log_name("notes", 1), b"v", &bob.phone);

            // Cache only: the certificate is named missing, then resolves
            // once a fetch brought it in, although it expired.
            let (pending, missing) = bob.validator.validate_durable_cached(&inside).await;
            assert!(matches!(pending, ValidationResult::Pending));
            let missing = missing.expect("the missing certificate is named");
            assert_eq!(key_name_of(&missing), n(PHONE));
            assert!(!bob.validator.can_resolve_durable(&missing));

            let fetches = serve_on_fetch(&bob.validator, bob.leaf.clone());
            assert!(valid(&bob.validator.validate_durable(&inside).await));
            assert_eq!(fetch_count(&fetches), 1);
            assert!(bob.validator.can_resolve_durable(&missing));
            assert!(!bob.validator.can_resolve(&missing), "live: expired");
            assert!(valid(
                &bob.validator.validate_durable_cached(&inside).await.0
            ));
        }

        /// A compromised-root recovery revokes the old CA without a cut and
        /// its certificate is no longer served. A member's certificate
        /// issued by that CA, and the member's Data under it, are refused as
        /// revoked — a final verdict — not left waiting for the withdrawn
        /// CA certificate.
        #[tokio::test]
        async fn under_an_issuer_revoked_without_a_cut_data_is_revoked_not_unverifiable() {
            let bob = bob(u64::MAX, (PAST, u64::MAX), false, |c| {
                c.with_revocation(n(CA))
            })
            .await;
            assert!(bob.validator.cert_cache().remove(&n(CA)).is_some());

            // The member's certificate packet, as the forwarder's fetch
            // brings it in: its signer is the revoked CA.
            let leaf = Data::decode(bob.leaf.clone()).unwrap();
            let (result, missing) = bob.validator.validate_durable_cached(&leaf).await;
            assert_eq!(revoked_key(&result), Some(n(CA)), "{result:?}");
            assert!(missing.is_none());

            // The member's Data waiting for that certificate resolves through
            // the refusal, and gets the same final verdict.
            let data = signed(log_name("notes", 2), b"v", &bob.phone);
            assert!(bob.validator.can_resolve_durable(&n(PHONE)));
            let (result, _) = bob.validator.validate_durable_cached(&data).await;
            assert_eq!(revoked_key(&result), Some(n(CA)), "{result:?}");
        }

        /// The phone's own public key digest, as a cut binds it.
        fn phone_key_digest() -> [u8; 32] {
            crate::public_key_digest(&signer(PHONE, 72).public_key_bytes())
        }

        /// F5: a cut bound to the phone's public key excuses only Data that
        /// key verifies. A certificate of another public key under the
        /// phone's key name (mis-issued or re-certified) earns nothing from
        /// the cut, even at an in-range name.
        #[tokio::test]
        async fn a_cut_bound_to_a_key_excuses_only_that_public_key() {
            let mut cut = phone_cut();
            cut.set_key_digest(phone_key_digest());
            let bob = bob(u64::MAX, (PAST, u64::MAX), true, |c| {
                c.with_revocation(n(PHONE)).with_revocation_cut(cut)
            })
            .await;
            let other = signer(PHONE, 99);
            let ca = signer(CA, 71);
            let recertified = cert(&other, &ca, "CA2", FUTURE, u64::MAX).await;
            bob.validator.cert_cache().insert(decoded(&recertified));

            let honest = signed(log_name("notes", 2), b"v", &bob.phone);
            assert!(valid(&bob.validator.validate_durable(&honest).await));
            let forged = signed(log_name("notes", 2), b"v", &other);
            for result in [
                bob.validator.validate_durable(&forged).await,
                bob.validator.validate_durable_cached(&forged).await.0,
            ] {
                assert_eq!(revoked_key(&result), Some(n(PHONE)), "{result:?}");
            }
        }

        /// The manifest listing the phone's honest entries notes/1 and
        /// notes/2 (notes/3 is in the run but not listed).
        fn notes_manifest(entries: &[&Data]) -> crate::cut_manifest::BuiltManifest {
            let listed: Vec<(Name, u64, [u8; 32])> = entries
                .iter()
                .map(|d| {
                    let (seq, prefix) = d.name.components().split_last().unwrap();
                    (
                        Name::from_components(prefix.iter().cloned()),
                        seq.as_sequence_num().unwrap(),
                        d.implicit_digest(),
                    )
                })
                .collect();
            crate::cut_manifest::build(&n("/home/bob"), &n(PHONE), &listed).unwrap()
        }

        /// F3: with a manifest, an in-range name is accepted only with the
        /// bytes the manifest lists. The manifest is pending until held
        /// (named by its full name, fetched like a certificate), and other
        /// bytes at a listed name, or an unlisted in-range name, are refused.
        #[tokio::test]
        async fn a_manifest_binds_the_bytes_at_an_in_range_name() {
            let phone = signer(PHONE, 72);
            let one = signed(log_name("notes", 1), b"honest 1", &phone);
            let two = signed(log_name("notes", 2), b"honest 2", &phone);
            let manifest = notes_manifest(&[&one, &two]);
            let mut cut = phone_cut();
            cut.set_manifest(manifest.root.clone()).unwrap();
            let bob = bob(u64::MAX, (PAST, u64::MAX), true, |c| {
                c.with_revocation(n(PHONE)).with_revocation_cut(cut)
            })
            .await;

            let (pending, missing) = bob.validator.validate_durable_cached(&two).await;
            assert!(matches!(pending, ValidationResult::Pending), "{pending:?}");
            assert_eq!(missing.as_deref(), Some(&manifest.root));
            assert!(!bob.validator.can_resolve_durable(&manifest.root));

            // A fetching walk brings the manifest in by its full name.
            let fetches = serve_on_fetch(&bob.validator, manifest.packets[0].clone());
            assert!(valid(&bob.validator.validate_durable(&two).await));
            assert_eq!(fetch_count(&fetches), 1);
            assert!(bob.validator.can_resolve_durable(&manifest.root));
            assert!(valid(&bob.validator.validate_durable_cached(&one).await.0));

            let thief = signed(log_name("notes", 2), b"thief", &bob.phone);
            let unlisted = signed(log_name("notes", 3), b"in the run", &bob.phone);
            for data in [&thief, &unlisted] {
                let result = bob.validator.validate_durable_cached(data).await.0;
                assert_eq!(revoked_key(&result), Some(n(PHONE)), "{result:?}");
            }
        }

        /// F2: under `DataRequiresCut guest`, Data of a guest key is
        /// accepted while a certificate of the key that verifies it is valid
        /// by the reader's clock, refused as revoked once it lapsed, and
        /// accepted again once the key is revoked with a cut accepting it;
        /// a member key (role not listed) keeps the clock-free rule (k1).
        #[tokio::test]
        async fn data_requires_cut_ends_a_lapsed_guest_key_until_its_cut() {
            const GUEST: &str = "/home/bob/guest/ann/KEY/g";
            let guest_log = |seq: u64| {
                n("/home/bob/guest/ann")
                    .append_component(NameComponent::keyword(Bytes::from_static(b"log")))
                    .append("notes")
                    .append_sequence_num(seq)
            };
            let setup = |until: u64, edit: fn(SignedTrustContext) -> SignedTrustContext| async move {
                let root = signer("/home/bob/KEY/root", 70);
                let ca = signer(CA, 71);
                let guest = signer(GUEST, 73);
                let anchor = decoded(&cert(&root, &root, "self", PAST, u64::MAX).await);
                let ctx = edit(
                    SignedTrustContext::hierarchical(n("/home/bob"))
                        .with_ca_endpoint(n("/home/bob/CA"))
                        .with_version(1)
                        .with_data_requires_cut("guest"),
                );
                ctx.anchors().insert(Arc::clone(&anchor.name), anchor);
                let keyring = Arc::new(Keyring::new());
                keyring.adopt(Arc::new(ctx)).unwrap();
                let cache = Arc::new(CertCache::new());
                cache.insert(decoded(&cert(&ca, &root, "root", PAST, u64::MAX).await));
                cache.insert(decoded(&cert(&guest, &ca, "CA", PAST, until).await));
                (Validator::with_keyring(keyring, cache, None, 5), guest)
            };

            let (validator, guest) = setup(u64::MAX, |c| c).await;
            let data = signed(guest_log(1), b"v", &guest);
            assert!(
                valid(&validator.validate_durable(&data).await),
                "valid certificate"
            );

            let (validator, guest) = setup(EXPIRED, |c| c).await;
            let data = signed(guest_log(1), b"v", &guest);
            for result in [
                validator.validate_durable(&data).await,
                validator.validate_durable_cached(&data).await.0,
            ] {
                assert_eq!(revoked_key(&result), Some(n(GUEST)), "lapsed: {result:?}");
            }

            let (validator, guest) = setup(EXPIRED, |c| {
                let mut cut = RevocationCut::new(n(GUEST));
                cut.add_run(
                    &n("/home/bob/guest/ann")
                        .append_component(NameComponent::keyword(Bytes::from_static(b"log")))
                        .append("notes"),
                    1,
                    1,
                );
                c.with_revocation(n(GUEST)).with_revocation_cut(cut)
            })
            .await;
            assert!(
                valid(
                    &validator
                        .validate_durable(&signed(guest_log(1), b"v", &guest))
                        .await
                ),
                "the cut decides alone"
            );
            let outside = validator
                .validate_durable(&signed(guest_log(2), b"v", &guest))
                .await;
            assert_eq!(revoked_key(&outside), Some(n(GUEST)), "{outside:?}");

            // A member key is not listed: its expired certificate refuses
            // nothing (k1).
            let bob = bob(u64::MAX, (PAST, EXPIRED), true, |c| {
                c.with_data_requires_cut("guest")
            })
            .await;
            let data = signed(log_name("notes", 2), b"v", &bob.phone);
            assert!(valid(&bob.validator.validate_durable(&data).await));
        }

        /// A lapsed guest key is renewed only by a certificate vouched for:
        /// an unverified copy of the key with a later validity — Mallory's,
        /// signed as if by the CA — leaves its Data refused as lapsed, and is
        /// dropped; an honest renewal the CA issued, fetched, is walked to
        /// the anchor, vouched for, and renews the key (spec §6.5).
        #[tokio::test]
        async fn only_a_renewal_vouched_for_renews_a_lapsed_key() {
            const GUEST: &str = "/home/bob/guest/ann/KEY/g";
            let root = signer("/home/bob/KEY/root", 70);
            let ca = signer(CA, 71);
            let guest = signer(GUEST, 73);
            let anchor = decoded(&cert(&root, &root, "self", PAST, u64::MAX).await);
            let ctx = SignedTrustContext::hierarchical(n("/home/bob"))
                .with_ca_endpoint(n("/home/bob/CA"))
                .with_version(1)
                .with_data_requires_cut("guest");
            ctx.anchors().insert(Arc::clone(&anchor.name), anchor);
            let keyring = Arc::new(Keyring::new());
            keyring.adopt(Arc::new(ctx)).unwrap();
            let cache = Arc::new(CertCache::new());
            cache.insert(decoded(&cert(&ca, &root, "root", PAST, u64::MAX).await));
            cache.insert(decoded(&cert(&guest, &ca, "CA", PAST, EXPIRED).await));
            let validator = Validator::with_keyring(keyring, cache, None, 5);
            let forged = decoded(&cert(&guest, &signer(CA, 99), "CA2", PAST, u64::MAX).await);
            let honest = cert(&guest, &ca, "CA3", PAST, u64::MAX).await;
            let data = signed(
                n("/home/bob/guest/ann")
                    .append_component(NameComponent::keyword(Bytes::from_static(b"log")))
                    .append("notes")
                    .append_sequence_num(1),
                b"v",
                &guest,
            );

            assert!(validator.cert_cache().insert_unverified(forged.clone()));
            let (result, _) = validator.validate_durable_cached(&data).await;
            assert_eq!(
                revoked_key(&result),
                Some(n(GUEST)),
                "an unverified copy with a later validity renewed the lapsed key: {result:?}"
            );
            assert!(validator.cert_cache().insert_unverified(forged.clone()));
            let result = validator.validate_durable(&data).await;
            assert_eq!(revoked_key(&result), Some(n(GUEST)), "{result:?}");
            assert!(
                validator.cert_cache().all(&forged.name).is_empty(),
                "the copy no walk could vouch for is still cached"
            );

            let fetches = serve_on_fetch(&validator, honest);
            let result = validator.validate_durable(&data).await;
            assert!(valid(&result), "an honest renewal, fetched: {result:?}");
            assert_eq!(fetch_count(&fetches), 1);
            assert!(valid(&validator.validate_durable_cached(&data).await.0));
        }
    }
}
