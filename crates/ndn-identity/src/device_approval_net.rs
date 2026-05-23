//! Cross-process NDNCERT device-approval over reflexive forwarding.
//!
//! Bridges the in-process [`PendingApprovalStore`] (which the CA's
//! `DeviceApprovalChallenge` reads) to a *remote* approver device, using the
//! `ndn-app` reflexive seam. The approver never needs an inbound route: it
//! advertises with a reflexive name, and the CA pulls the signed approval back
//! along the reverse path.
//!
//! ```text
//!   approver --forward Interest /<ca>/CA/APPROVE-FEED (+R, +approver id)--> CA
//!   CA       --reverse Interest R/approve (+cert_name,+request_id)-------> approver
//!   approver --reverse Data: sig over approval_statement----------------> CA
//!   CA verifies the sig against the approver's key, calls approve_signed,
//!   then answers the forward Interest to release the approver.
//! ```
//!
//! This module is the **per-cycle core** of the transport — one approval
//! round-trip. The long-running APPROVE-FEED producer that loops it, multi-
//! request correlation, and resolving an approver's key from a principal's
//! `trustedApprovers` DID-Document field (here abstracted as a
//! `resolve_pubkey` closure) are wired by the caller / a later layer.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use ndn_app::Consumer;
use ndn_app::{AppError, Producer, random_reflexive_name};
use ndn_cert::challenge::device_approval::{PendingApprovalStore, approval_statement};
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_packet::{Interest, Name};
use ndn_packet::Data;
use ndn_security::did::{UniversalResolver, name_to_did};
use ndn_security::{
    Ed25519Verifier, Signer, ValidationResult, Validator, VerifyOutcome, Verifier,
};
use ndn_cert::challenge::device_approval::approval_data_name;

use crate::error::IdentityError;

/// Suffix the CA appends to the approver's reflexive name for the reverse pull.
const APPROVE_SUFFIX: &str = "approve";

/// Carried in the approver's forward Interest: which identity is offering to
/// approve (so the CA can resolve the key to verify against).
#[derive(Serialize, Deserialize)]
struct ApproverHello {
    approver: String,
}

/// Carried in the CA's reverse Interest: which enrollment to approve.
#[derive(Serialize, Deserialize)]
struct ApprovalAsk {
    cert_name: String,
    request_id: String,
}

/// Decides whether an approver identity may approve an enrollment for a given
/// subject name — the *authorization* gate layered on top of the
/// *authentication* that [`resolve_approver_key`] provides.
///
/// Async because the canonical implementation ([`DidApproverAuthorizer`])
/// resolves the principal's published `trustedApprovers` DID-Document entry.
/// [`StaticTrustedApprovers`] is the local-policy form.
pub trait ApproverAuthorizer: Send + Sync {
    fn is_authorized<'a>(
        &'a self,
        approver: &'a str,
        cert_name: &'a Name,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>>;
}

/// A static `(principal-prefix → approver)` allowlist: `approver` may approve
/// any enrollment whose subject name falls under `principal`. Local policy,
/// not published.
#[derive(Default)]
pub struct StaticTrustedApprovers {
    rules: Vec<(Name, String)>,
}

impl StaticTrustedApprovers {
    pub fn new() -> Self {
        Self::default()
    }

    /// Permit `approver` to approve enrollments for names under `principal`.
    pub fn allow(mut self, principal: Name, approver: impl Into<String>) -> Self {
        self.rules.push((principal, approver.into()));
        self
    }
}

impl ApproverAuthorizer for StaticTrustedApprovers {
    fn is_authorized<'a>(
        &'a self,
        approver: &'a str,
        cert_name: &'a Name,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        let ok = self
            .rules
            .iter()
            .any(|(principal, allowed)| allowed == approver && cert_name.has_prefix(principal));
        Box::pin(async move { ok })
    }
}

/// Authorizes any approver for any name. The default for flows that gate
/// elsewhere; **never** appropriate for a real CA.
pub struct AllowAnyApprover;

impl ApproverAuthorizer for AllowAnyApprover {
    fn is_authorized<'a>(
        &'a self,
        _approver: &'a str,
        _cert_name: &'a Name,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        Box::pin(async move { true })
    }
}

/// Authorizes against the principal's **published** `trustedApprovers` — the
/// service entries on its resolved DID Document (sourced from the principal
/// cert's signed `AdditionalDescription`; see
/// [`ndn_security::did::TRUSTED_APPROVERS_DESCRIPTION_KEY`]). `principal_of`
/// maps a subject cert name to the principal whose document is consulted (e.g.
/// strip the device suffix: `/lab/alice/devices/laptop` → `/lab/alice`).
pub type PrincipalOf = Box<dyn Fn(&Name) -> Option<Name> + Send + Sync>;

pub struct DidApproverAuthorizer {
    resolver: Arc<UniversalResolver>,
    principal_of: PrincipalOf,
}

impl DidApproverAuthorizer {
    pub fn new(
        resolver: Arc<UniversalResolver>,
        principal_of: impl Fn(&Name) -> Option<Name> + Send + Sync + 'static,
    ) -> Self {
        Self {
            resolver,
            principal_of: Box::new(principal_of),
        }
    }
}

impl ApproverAuthorizer for DidApproverAuthorizer {
    fn is_authorized<'a>(
        &'a self,
        approver: &'a str,
        cert_name: &'a Name,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        Box::pin(async move {
            let Some(principal) = (self.principal_of)(cert_name) else {
                return false;
            };
            let Ok(doc) = self.resolver.resolve_document(&name_to_did(&principal)).await else {
                return false;
            };
            doc.trusted_approvers().iter().any(|a| a == approver)
        })
    }
}

/// Approver side — offer to approve enrollments, completing one cycle.
///
/// Advertises to `ca_approve_prefix` with a fresh reflexive name and answers
/// the CA's reverse pull: `decide(cert_name, request_id)` chooses whether to
/// approve; if it does, the approval statement is signed with `signer`. Returns
/// `Ok(true)` if this cycle approved, `Ok(false)` if it declined. An empty
/// reverse Data signals a decline to the CA.
pub async fn offer_approval<D, Fut>(
    consumer: &mut Consumer,
    ca_approve_prefix: impl Into<Name>,
    approver_name: &str,
    signer: &dyn Signer,
    decide: D,
    timeout: Duration,
) -> Result<bool, IdentityError>
where
    D: Fn(String, String) -> Fut,
    Fut: Future<Output = bool>,
{
    let reflexive = random_reflexive_name();
    let hello = serde_json::to_vec(&ApproverHello {
        approver: approver_name.to_string(),
    })
    .map_err(|e| IdentityError::Enrollment(format!("encode approver hello: {e}")))?;
    let forward = InterestBuilder::new(ca_approve_prefix.into())
        .app_parameters(hello)
        .lifetime(timeout);

    let approved = Arc::new(AtomicBool::new(false));
    let approved_cb = Arc::clone(&approved);
    let decide = Arc::new(decide);

    consumer
        .fetch_reflexive(forward, reflexive, timeout, move |reverse: Interest| {
            let approved_cb = Arc::clone(&approved_cb);
            let decide = Arc::clone(&decide);
            async move {
                let ask: ApprovalAsk = match reverse.app_parameters() {
                    Some(p) => serde_json::from_slice(p).map_err(|e| {
                        ndn_app::AppError::Protocol(format!("decode approval ask: {e}"))
                    })?,
                    None => {
                        return Err(ndn_app::AppError::Protocol(
                            "reverse approval Interest has no parameters".into(),
                        ));
                    }
                };
                let reverse_name = (*reverse.name).clone();
                if decide(ask.cert_name.clone(), ask.request_id.clone()).await {
                    let sig = signer
                        .sign(&approval_statement(&ask.cert_name, &ask.request_id))
                        .await
                        .map_err(|e| ndn_app::AppError::Protocol(format!("sign approval: {e}")))?;
                    approved_cb.store(true, Ordering::SeqCst);
                    Ok(DataBuilder::new(reverse_name, &sig).build())
                } else {
                    // Empty content = decline.
                    Ok(DataBuilder::new(reverse_name, &[][..]).build())
                }
            }
        })
        .await?;

    Ok(approved.load(Ordering::SeqCst))
}

/// CA side — pull a signed approval from the approver that sent
/// `approver_forward` and, if it verifies, record it in `store`.
///
/// `resolve_pubkey` maps an approver identity to its raw public key (the real
/// implementation resolves the principal's `trustedApprovers` DID-Document
/// entry; tests pass a fixed map). The pulled signature is verified over
/// [`approval_statement`] before [`PendingApprovalStore::approve_signed`] is
/// called. Returns `Ok(true)` when an approval was recorded.
///
/// Call this from the APPROVE-FEED producer's serve handler with a *side*
/// [`Consumer`], then answer `approver_forward` to release the approver.
pub async fn pull_and_record_approval<R>(
    side: &mut Consumer,
    store: &PendingApprovalStore,
    approver_forward: &Interest,
    cert_name: &str,
    request_id: &str,
    resolve_pubkey: R,
    timeout: Duration,
) -> Result<bool, IdentityError>
where
    R: Fn(&str) -> Option<Vec<u8>>,
{
    let hello = parse_hello(approver_forward)?;
    let pubkey = resolve_pubkey(&hello.approver).ok_or_else(|| {
        IdentityError::Enrollment(format!("approver {} is not a trusted approver", hello.approver))
    })?;

    let reflexive = approver_forward.reflexive_name().ok_or_else(|| {
        IdentityError::Enrollment("approver forward Interest carries no reflexive name".into())
    })?;
    let ask = serde_json::to_vec(&ApprovalAsk {
        cert_name: cert_name.to_string(),
        request_id: request_id.to_string(),
    })
    .map_err(|e| IdentityError::Enrollment(format!("encode approval ask: {e}")))?;

    let name = (**reflexive).clone().append(APPROVE_SUFFIX);
    let data = side
        .fetch_with(
            InterestBuilder::new(name)
                .app_parameters(ask)
                .lifetime(timeout),
        )
        .await?;

    let sig = match data.content() {
        Some(c) if !c.is_empty() => c.to_vec(),
        // Empty / absent content is the approver's decline.
        _ => return Ok(false),
    };

    let statement = approval_statement(cert_name, request_id);
    match Ed25519Verifier.verify(&statement, &sig, &pubkey).await {
        Ok(VerifyOutcome::Valid) => {
            store.approve_signed(request_id, &hello.approver, pubkey, sig);
            Ok(true)
        }
        _ => Ok(false),
    }
}

/// Resolve an approver identity (an NDN name or a `did:ndn:` URI) to its raw
/// Ed25519 public key via the DID resolver — the real `resolve_pubkey`,
/// backed by `ndn_security::did` (the implementation `ndn-did` re-exports).
/// `None` if the DID can't be resolved or carries no Ed25519 key.
///
/// Note: this *authenticates* the approver (it controls the key it claims). It
/// does not yet *authorise* it for a given enrollment — that gate is the
/// principal's `trustedApprovers` DID-Document entry, still to be added.
pub async fn resolve_approver_key(resolver: &UniversalResolver, approver: &str) -> Option<Vec<u8>> {
    let did = if approver.starts_with("did:") {
        approver.to_string()
    } else {
        name_to_did(&approver.parse::<Name>().ok()?)
    };
    let doc = resolver.resolve_document(&did).await.ok()?;
    doc.ed25519_public_key().map(|k| k.to_vec())
}

/// As [`pull_and_record_approval`], but resolve the approver's key from the
/// DID resolver (production path) instead of a fixed `resolve_pubkey` closure,
/// and gate on `authorizer` (the `trustedApprovers` check) *before* pulling —
/// an approver not authorized for `cert_name` is never contacted.
#[allow(clippy::too_many_arguments)]
pub async fn pull_and_record_approval_with_resolver(
    side: &mut Consumer,
    store: &PendingApprovalStore,
    approver_forward: &Interest,
    cert_name: &str,
    request_id: &str,
    resolver: &UniversalResolver,
    authorizer: &dyn ApproverAuthorizer,
    timeout: Duration,
) -> Result<bool, IdentityError> {
    let hello = parse_hello(approver_forward)?;

    // Authorization gate: is this approver permitted to approve this name?
    let subject: Name = cert_name
        .parse()
        .map_err(|_| IdentityError::Name(cert_name.to_string()))?;
    if !authorizer.is_authorized(&hello.approver, &subject).await {
        return Ok(false);
    }

    let resolved = resolve_approver_key(resolver, &hello.approver).await;
    let resolve = move |name: &str| {
        if name == hello.approver {
            resolved.clone()
        } else {
            None
        }
    };
    pull_and_record_approval(
        side,
        store,
        approver_forward,
        cert_name,
        request_id,
        resolve,
        timeout,
    )
    .await
}

/// Approver-side service: re-offer approval each cycle until the connection
/// closes. Each cycle is one [`offer_approval`]; a cycle that times out (no
/// enrollment needed approval in the window) simply re-offers. Returns `Ok(())`
/// when the forwarder connection closes.
pub async fn run_approver<D, Fut>(
    consumer: &mut Consumer,
    ca_approve_prefix: Name,
    approver_name: &str,
    signer: &dyn Signer,
    decide: D,
    cycle_timeout: Duration,
) -> Result<(), IdentityError>
where
    D: Fn(String, String) -> Fut + Clone,
    Fut: Future<Output = bool>,
{
    loop {
        match offer_approval(
            consumer,
            ca_approve_prefix.clone(),
            approver_name,
            signer,
            decide.clone(),
            cycle_timeout,
        )
        .await
        {
            Ok(_) | Err(IdentityError::App(AppError::Timeout)) => continue,
            Err(IdentityError::App(AppError::Closed)) => return Ok(()),
            Err(e) => return Err(e),
        }
    }
}

/// CA-side APPROVE-FEED service: run `producer` as the feed, and on each
/// approver forward Interest, if an enrollment is pending, pull and record the
/// signed approval (resolving the approver's key via `resolver`). When nothing
/// is pending the forward Interest is held (no response) so the approver's
/// Interest simply times out and re-offers — no busy polling. Returns when the
/// producer connection closes.
///
/// `side` is a *separate* `Consumer` on the CA's connection for the reverse
/// pull (the producer face is busy receiving forward Interests).
///
/// Correlation is oldest-pending-first; per-principal scoping arrives with
/// `trustedApprovers`.
pub async fn serve_approve_feed(
    producer: Producer,
    side: Consumer,
    store: PendingApprovalStore,
    resolver: Arc<UniversalResolver>,
    authorizer: Arc<dyn ApproverAuthorizer>,
    timeout: Duration,
) -> Result<(), IdentityError> {
    let side = Arc::new(tokio::sync::Mutex::new(side));
    producer
        .serve(move |interest, responder| {
            let side = Arc::clone(&side);
            let store = store.clone();
            let resolver = Arc::clone(&resolver);
            let authorizer = Arc::clone(&authorizer);
            async move {
                let Some(req) = store.pending().into_iter().next() else {
                    // Nothing to approve: hold the Interest (drop the responder).
                    return;
                };
                {
                    let mut sc = side.lock().await;
                    let _ = pull_and_record_approval_with_resolver(
                        &mut sc,
                        &store,
                        &interest,
                        &req.cert_name,
                        &req.id,
                        &resolver,
                        authorizer.as_ref(),
                        timeout,
                    )
                    .await;
                }
                responder
                    .respond((*interest.name).clone(), b"ok".to_vec())
                    .await
                    .ok();
            }
        })
        .await?;
    Ok(())
}

/// Parse the [`ApproverHello`] from an approver's forward Interest.
fn parse_hello(forward: &Interest) -> Result<ApproverHello, IdentityError> {
    match forward.app_parameters() {
        Some(p) => serde_json::from_slice(p)
            .map_err(|e| IdentityError::Enrollment(format!("decode approver hello: {e}"))),
        None => Err(IdentityError::Enrollment(
            "approver forward Interest has no parameters".into(),
        )),
    }
}

/// Approver side (**canonical**) — like [`offer_approval`], but answers the
/// CA's reverse pull with a real *signed approval Data* named
/// `<cert_name>/ndncert-approve/<request_id>`
/// ([`ndn_cert::challenge::device_approval::approval_data_name`]), wrapped as
/// the reverse Data's content. The CA validates that inner Data through its
/// trust schema with the real `(data_name, signer-cert-name)` pair — exactly
/// how NDN trust schemas are evaluated (python-ndn / ndnd). Pair with
/// [`serve_approve_feed_validated`].
pub async fn offer_signed_approval<D, Fut>(
    consumer: &mut Consumer,
    ca_approve_prefix: impl Into<Name>,
    approver_name: &str,
    signer: &dyn Signer,
    decide: D,
    timeout: Duration,
) -> Result<bool, IdentityError>
where
    D: Fn(String, String) -> Fut,
    Fut: Future<Output = bool>,
{
    let reflexive = random_reflexive_name();
    let hello = serde_json::to_vec(&ApproverHello {
        approver: approver_name.to_string(),
    })
    .map_err(|e| IdentityError::Enrollment(format!("encode approver hello: {e}")))?;
    let forward = InterestBuilder::new(ca_approve_prefix.into())
        .app_parameters(hello)
        .lifetime(timeout);

    let approved = Arc::new(AtomicBool::new(false));
    let approved_cb = Arc::clone(&approved);
    let decide = Arc::new(decide);

    consumer
        .fetch_reflexive(forward, reflexive, timeout, move |reverse: Interest| {
            let approved_cb = Arc::clone(&approved_cb);
            let decide = Arc::clone(&decide);
            async move {
                let ask: ApprovalAsk = match reverse.app_parameters() {
                    Some(p) => serde_json::from_slice(p).map_err(|e| {
                        ndn_app::AppError::Protocol(format!("decode approval ask: {e}"))
                    })?,
                    None => {
                        return Err(ndn_app::AppError::Protocol(
                            "reverse approval Interest has no parameters".into(),
                        ));
                    }
                };
                let reverse_name = (*reverse.name).clone();
                if decide(ask.cert_name.clone(), ask.request_id.clone()).await {
                    let approval_name = approval_data_name(&ask.cert_name, &ask.request_id)
                        .ok_or_else(|| {
                            ndn_app::AppError::Protocol("unparseable cert name for approval".into())
                        })?;
                    let key_locator = signer.cert_name().unwrap_or_else(|| signer.key_name()).clone();
                    let sig_type = signer.sig_type();
                    let inner = DataBuilder::new(approval_name, &[][..])
                        .sign(sig_type, Some(&key_locator), |region| {
                            let r = region.to_vec();
                            async move { signer.sign(&r).await.unwrap_or_default() }
                        })
                        .await;
                    approved_cb.store(true, Ordering::SeqCst);
                    Ok(DataBuilder::new(reverse_name, &inner).build())
                } else {
                    Ok(DataBuilder::new(reverse_name, &[][..]).build())
                }
            }
        })
        .await?;

    Ok(approved.load(Ordering::SeqCst))
}

/// CA side (**canonical**) — pull the approver's *signed approval Data* and
/// validate it through `validator`: signature + certificate chain + **trust
/// schema**, evaluated over the real `(data_name, signer-cert-name)`. The
/// schema is where approver authorization lives (a rule like
/// `/lab/<site>/devices/<**rest> /ndncert-approve/<id> => /lab/<site>/devices/.../KEY/<**k>`).
/// On a valid approval whose name binds to `(cert_name, request_id)`, records
/// it via [`PendingApprovalStore::approve_validated`]. Returns `Ok(true)` when
/// recorded.
pub async fn pull_and_validate_approval(
    side: &mut Consumer,
    store: &PendingApprovalStore,
    approver_forward: &Interest,
    cert_name: &str,
    request_id: &str,
    validator: &Validator,
    timeout: Duration,
) -> Result<bool, IdentityError> {
    let reflexive = approver_forward.reflexive_name().ok_or_else(|| {
        IdentityError::Enrollment("approver forward Interest carries no reflexive name".into())
    })?;
    let ask = serde_json::to_vec(&ApprovalAsk {
        cert_name: cert_name.to_string(),
        request_id: request_id.to_string(),
    })
    .map_err(|e| IdentityError::Enrollment(format!("encode approval ask: {e}")))?;
    let name = (**reflexive).clone().append("approve");
    let reverse = side
        .fetch_with(
            InterestBuilder::new(name)
                .app_parameters(ask)
                .lifetime(timeout),
        )
        .await?;

    // Content is the inner signed approval Data; empty = decline.
    let inner_wire = match reverse.content() {
        Some(c) if !c.is_empty() => bytes::Bytes::copy_from_slice(c),
        _ => return Ok(false),
    };
    let inner = Data::decode(inner_wire)
        .map_err(|e| IdentityError::Enrollment(format!("decode approval data: {e}")))?;

    // Bind the approval to THIS enrollment (the request_id nonce is in the name).
    if approval_data_name(cert_name, request_id).as_ref() != Some(&*inner.name) {
        return Ok(false);
    }

    // Canonical: validate through the trust schema (signature + chain + schema).
    match validator.validate(&inner).await {
        ValidationResult::Valid(_) => {
            let approver = inner
                .sig_info()
                .and_then(|si| si.key_locator_name())
                .map(|n| n.to_string())
                .unwrap_or_default();
            store.approve_validated(request_id, approver, inner.sig_value().to_vec());
            Ok(true)
        }
        _ => Ok(false),
    }
}

/// CA-side APPROVE-FEED loop using the canonical [`pull_and_validate_approval`]
/// (trust-schema authorization). Mirrors [`serve_approve_feed`] but takes a
/// [`Validator`] instead of a resolver + [`ApproverAuthorizer`].
pub async fn serve_approve_feed_validated(
    producer: Producer,
    side: Consumer,
    store: PendingApprovalStore,
    validator: Arc<Validator>,
    timeout: Duration,
) -> Result<(), IdentityError> {
    let side = Arc::new(tokio::sync::Mutex::new(side));
    producer
        .serve(move |interest, responder| {
            let side = Arc::clone(&side);
            let store = store.clone();
            let validator = Arc::clone(&validator);
            async move {
                let Some(req) = store.pending().into_iter().next() else {
                    return;
                };
                {
                    let mut sc = side.lock().await;
                    let _ = pull_and_validate_approval(
                        &mut sc,
                        &store,
                        &interest,
                        &req.cert_name,
                        &req.id,
                        &validator,
                        timeout,
                    )
                    .await;
                }
                responder
                    .respond((*interest.name).clone(), b"ok".to_vec())
                    .await
                    .ok();
            }
        })
        .await?;
    Ok(())
}
