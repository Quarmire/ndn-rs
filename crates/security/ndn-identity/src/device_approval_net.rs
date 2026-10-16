//! Cross-process NDNCERT device-approval over reflexive forwarding.
//!
//! Bridges the in-process `PendingApprovalStore` (which the CA's
//! `DeviceApprovalChallenge` reads) to a *remote* approver device, using the
//! `ndn-app` reflexive seam. The approver never needs an inbound route: it
//! advertises with a reflexive name, and the CA pulls the signed approval back
//! along the reverse path.
//!
//! ```text
//!   approver --forward Interest /<ca>/CA/APPROVE-FEED (+R, +approver id)--> CA
//!   CA       --reverse Interest R/approve (+cert_name,+request_id)-------> approver
//!   approver --reverse Data: signed Data <cert>/ndncert-approve/<id>----> CA
//!   CA validates it (signature + chain + trust schema), calls
//!   approve_validated, then answers the forward Interest to release the approver.
//! ```
//!
//! Approver side: [`offer_signed_approval`] (one cycle) / [`run_approver`]
//! (loop). CA side: [`pull_and_validate_approval`] (one cycle) /
//! [`serve_approve_feed_validated`] / [`ApprovalFeed`] (the feed loop).

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use ndn_app::Consumer;
use ndn_app::{AppError, Producer, random_reflexive_name};
use ndn_cert::challenge::device_approval::{PendingApprovalStore, approval_data_name};
use ndn_packet::Data;
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_packet::{Interest, Name};
use ndn_security::{Signer, ValidationResult, Validator};

use crate::error::IdentityError;

/// Suffix the CA appends to the approver's reflexive name for the reverse pull.
const APPROVE_SUFFIX: &str = "approve";

/// Carried in the approver's forward Interest: which identity is offering to
/// approve. Informational — the CA authorizes via the validated approval Data.
#[derive(Serialize)]
struct ApproverHello {
    approver: String,
}

/// Carried in the CA's reverse Interest: which enrollment to approve.
#[derive(Serialize, Deserialize)]
struct ApprovalAsk {
    cert_name: String,
    request_id: String,
}

/// A request currently awaiting approval, as the feed sees it.
#[derive(Debug, Clone)]
pub struct PendingApproval {
    pub request_id: String,
    pub cert_name: String,
}

/// Where the cross-device approval transport reads pending requests and records
/// outcomes. ndncert's `PendingApprovalStore` implements it (adapter below).
///
/// The transport functions are generic over this trait, so they don't depend on
/// the concrete ndncert store — other capabilities (capability tokens, the
/// trust fob) can supply their own sink. This is the seam for a future
/// `ndn-approve` extraction; see
/// `.claude/notes/trust-fob-and-cross-device-auth-2026-05-23.md`.
pub trait ApprovalSink: Send + Sync {
    /// Requests currently awaiting approval (oldest first).
    fn pending(&self) -> Vec<PendingApproval>;
    /// Record a validator-checked approval (canonical path).
    fn record_validated(&self, request_id: &str, approver: &str, signature: Vec<u8>);
}

impl ApprovalSink for PendingApprovalStore {
    fn pending(&self) -> Vec<PendingApproval> {
        PendingApprovalStore::pending(self)
            .into_iter()
            .map(|r| PendingApproval {
                request_id: r.id,
                cert_name: r.cert_name,
            })
            .collect()
    }

    fn record_validated(&self, request_id: &str, approver: &str, signature: Vec<u8>) {
        self.approve_validated(request_id, approver, signature);
    }
}

/// Approver-side service: re-offer approval each cycle until the connection
/// closes. Each cycle is one [`offer_signed_approval`] (pairs with the
/// canonical [`serve_approve_feed_validated`] / [`ApprovalFeed`] CA side); a
/// cycle that times out (no enrollment needed approval in the window) simply
/// re-offers. Returns `Ok(())` when the forwarder connection closes.
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
        match offer_signed_approval(
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

/// Approver side — offer to approve enrollments, completing one cycle.
///
/// Advertises to `ca_approve_prefix` with a fresh reflexive name and answers
/// the CA's reverse pull: `decide(cert_name, request_id)` chooses whether to
/// approve; if it does, the reply wraps a real *signed approval Data* named
/// `<cert_name>/ndncert-approve/<request_id>`
/// ([`ndn_cert::challenge::device_approval::approval_data_name`]), signed with
/// `signer`, as the reverse Data's content. An empty reverse Data signals a
/// decline. The CA validates the inner Data through its trust schema with the
/// real `(data_name, signer-cert-name)` pair — exactly how NDN trust schemas
/// are evaluated (python-ndn / ndnd). Pair with
/// [`serve_approve_feed_validated`]. Returns `Ok(true)` if this cycle
/// approved, `Ok(false)` if it declined.
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
                    let key_locator = signer
                        .cert_name()
                        .unwrap_or_else(|| signer.key_name())
                        .clone();
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
pub async fn pull_and_validate_approval<S>(
    side: &mut Consumer,
    sink: &S,
    approver_forward: &Interest,
    pending: &PendingApproval,
    validator: &Validator,
    timeout: Duration,
) -> Result<bool, IdentityError>
where
    S: ApprovalSink + ?Sized,
{
    let reflexive = approver_forward.reflexive_name().ok_or_else(|| {
        IdentityError::Enrollment("approver forward Interest carries no reflexive name".into())
    })?;
    let ask = serde_json::to_vec(&ApprovalAsk {
        cert_name: pending.cert_name.clone(),
        request_id: pending.request_id.clone(),
    })
    .map_err(|e| IdentityError::Enrollment(format!("encode approval ask: {e}")))?;
    let name = (**reflexive).clone().append(APPROVE_SUFFIX);
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
    if approval_data_name(&pending.cert_name, &pending.request_id).as_ref() != Some(&*inner.name) {
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
            sink.record_validated(&pending.request_id, &approver, inner.sig_value().to_vec());
            Ok(true)
        }
        _ => Ok(false),
    }
}

/// CA-side APPROVE-FEED loop: run `producer` as the feed, and on each approver
/// forward Interest, if an enrollment is pending (oldest first), pull the
/// signed approval Data and validate it via [`pull_and_validate_approval`]
/// (trust-schema authorization). When nothing is pending the forward Interest
/// is held (no response) so the approver's Interest times out and re-offers —
/// no busy polling. `side` is a *separate* `Consumer` on the CA's connection
/// for the reverse pull. Returns when the producer connection closes.
pub async fn serve_approve_feed_validated<S>(
    producer: Producer,
    side: Consumer,
    sink: S,
    validator: Arc<Validator>,
    timeout: Duration,
) -> Result<(), IdentityError>
where
    S: ApprovalSink + Clone + Send + Sync + 'static,
{
    let side = Arc::new(tokio::sync::Mutex::new(side));
    producer
        .serve(move |interest, responder| {
            let side = Arc::clone(&side);
            let sink = sink.clone();
            let validator = Arc::clone(&validator);
            async move {
                let Some(req) = sink.pending().into_iter().next() else {
                    return;
                };
                {
                    let mut sc = side.lock().await;
                    let _ = pull_and_validate_approval(
                        &mut sc, &sink, &interest, &req, &validator, timeout,
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

/// Default per-cycle reverse-pull timeout for [`ApprovalFeed`].
pub const DEFAULT_APPROVAL_TIMEOUT: Duration = Duration::from_secs(2);

/// Ergonomic builder for the canonical (validator-checked) APPROVE-FEED.
///
/// Bundles the [`ApprovalSink`] + [`Validator`] + timeout so a caller doesn't
/// hand-assemble [`serve_approve_feed_validated`]'s arguments:
///
/// ```ignore
/// use std::time::Duration;
/// ApprovalFeed::validated(store, validator)   // store: impl ApprovalSink, validator: Arc<Validator>
///     .timeout(Duration::from_secs(5))
///     .serve(producer, side)                  // producer serves /<ca>/CA/APPROVE-FEED
///     .await?;
/// ```
///
/// [`NdncertCa::serve_with_feed`](crate::NdncertCa::serve_with_feed) runs one
/// of these alongside the CA's `/CA/*` service.
pub struct ApprovalFeed<S> {
    sink: S,
    validator: Arc<Validator>,
    timeout: Duration,
}

impl<S> ApprovalFeed<S>
where
    S: ApprovalSink + Clone + Send + Sync + 'static,
{
    /// Canonical feed: each approval Data is validated through `validator`
    /// (signature + certificate chain + trust schema).
    pub fn validated(sink: S, validator: Arc<Validator>) -> Self {
        Self {
            sink,
            validator,
            timeout: DEFAULT_APPROVAL_TIMEOUT,
        }
    }

    /// Per-cycle reverse-pull timeout (default [`DEFAULT_APPROVAL_TIMEOUT`]).
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Run the feed until the producer connection closes. `producer` serves the
    /// APPROVE-FEED prefix; `side` is a *separate* consumer for the reverse pull
    /// (the producer face is busy receiving forward Interests).
    pub async fn serve(self, producer: Producer, side: Consumer) -> Result<(), IdentityError> {
        serve_approve_feed_validated(producer, side, self.sink, self.validator, self.timeout).await
    }
}
