//! Waiting for an admin's decision on the device's requests, and finishing
//! the enrollment the moment one is approved.
//!
//! One state machine, [`wait_for_decision`], serves both a device that
//! waits in the background until the request ends ([`spawn_status_watch`]:
//! every pending record, at start and as soon as a new one is recorded,
//! across restarts) and an app that waits for a bounded time when asked
//! (a deadline):
//!
//! - one held status Interest outstanding at the CA at a time
//!   ([`ndn_identity::request_status_via_engine`], lifetime
//!   [`ndn_cert::approval::STATUS_LIFETIME`], shortened to what is left
//!   before a deadline but never below
//!   [`ndn_cert::approval::STATUS_ANSWER_MARGIN`]), sent again as soon as the
//!   CA answers pending or the Interest expires;
//! - on the CA-signed answer: approved — the issuance exchange runs at once
//!   and the certificate is installed ([`crate::enroll::install`]); denied or
//!   expired — the record says why (and what to do) and the key is deleted.
//!   An answer that is not the CA's changes nothing;
//! - when the CA cannot be asked, or answers early (it stopped; a relay's
//!   aggregated Interest of another device answered), it asks again after a
//!   pause doubling from [`RETRY_FIRST`] to [`RETRY_MAX`] (logged once per
//!   outage), with short Interests
//!   ([`ndn_cert::approval::STATUS_PROBE_LIFETIME`]) until the CA holds one
//!   again.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ndn_cert::approval::{
    STATUS_ANSWER_MARGIN, STATUS_LIFETIME, STATUS_PROBE_LIFETIME, status_hold,
};
use ndn_cert::{
    ApprovalEnrollError, ApprovalPoll, OutgoingRequest, OutgoingState, RequestStatus, RequestStore,
};
use ndn_packet::Name;
use ndn_security::Signer;
use tokio_util::sync::CancellationToken;

use crate::enroll::{Enrolling, discard, expire_overdue, install, request_store};
use crate::{KeyUnavailable, KeyVault, Participant};

/// The first pause after the CA could not be asked (or answered a status
/// early); it doubles up to [`RETRY_MAX`] while that goes on.
pub const RETRY_FIRST: Duration = Duration::from_secs(1);
pub const RETRY_MAX: Duration = Duration::from_secs(60);

/// What [`wait_for_decision`] ended with.
#[derive(Debug)]
pub enum Waited {
    /// The record ended (issued, or failed / denied / expired with why), or
    /// was no longer pending when the wait began: the record as kept now.
    Ended(OutgoingRequest),
    /// Still pending when the deadline came (or the wait was cancelled):
    /// the record as kept now, and why the CA could not be asked, if it
    /// could not.
    Pending {
        request: OutgoingRequest,
        not_reached: Option<String>,
    },
    /// No record of the key is kept.
    NotRecorded,
    /// The records could not be read before the deadline (or the wait was
    /// cancelled): why.
    Unreadable(String),
}

/// Finish the device's requests for an admin's approval, until `cancel`:
/// each pending record is waited on by its own task ([`wait_for_decision`]
/// without a deadline) — at start (a request made before a restart
/// resumes) and as soon as an enrollment records a new one.
pub fn spawn_status_watch(
    p: Arc<Participant>,
    vault: Arc<dyn KeyVault>,
    cancel: CancellationToken,
) {
    tokio::spawn(async move {
        // Per request key: its watch task.
        let mut watching: HashMap<String, tokio::task::JoinHandle<()>> = HashMap::new();
        loop {
            watching.retain(|_, task| !task.is_finished());
            let listed = request_store(vault.as_ref())
                .and_then(|store| store.list().map_err(|e| crate::refusal(500, e.to_string())));
            let read_again = match listed {
                Ok(list) => {
                    for request in list
                        .into_iter()
                        .filter(|r| r.state == OutgoingState::Pending)
                    {
                        if let std::collections::hash_map::Entry::Vacant(slot) =
                            watching.entry(request.key_name)
                        {
                            let (p, vault, key, cancel) = (
                                Arc::clone(&p),
                                Arc::clone(&vault),
                                slot.key().clone(),
                                cancel.child_token(),
                            );
                            let task = tokio::spawn(async move {
                                wait_for_decision(&p, vault.as_ref(), &key, None, &cancel).await;
                            });
                            slot.insert(task);
                        }
                    }
                    None
                }
                Err(e) => {
                    tracing::warn!(
                        target: "security",
                        error = %e.reason,
                        "cannot read this node's requests for an admin's approval; reading them \
                         again in {}s",
                        RETRY_MAX.as_secs()
                    );
                    Some(RETRY_MAX)
                }
            };
            tokio::select! {
                _ = cancel.cancelled() => return,
                _ = p.requests_changed.notified() => {}
                _ = tokio::time::sleep(read_again.unwrap_or(RETRY_MAX)), if read_again.is_some() => {}
            }
        }
    });
}

/// The record of `key_name` as kept now, with its store.
fn current(
    vault: &dyn KeyVault,
    key_name: &str,
) -> Result<(RequestStore, Option<OutgoingRequest>), String> {
    let store = request_store(vault).map_err(|e| e.reason)?;
    let found = store
        .list()
        .map_err(|e| e.to_string())?
        .into_iter()
        .find(|r| r.key_name == key_name);
    Ok((store, found))
}

/// Wait for the CA's decision on the device's request for `key_name` (see
/// the [module docs](self)) until it ends, `until` passes, or `cancel`.
/// Without a deadline it never gives up while the record is pending.
pub async fn wait_for_decision(
    p: &Participant,
    vault: &dyn KeyVault,
    key_name: &str,
    until: Option<Instant>,
    cancel: &CancellationToken,
) -> Waited {
    let mut retry = RETRY_FIRST;
    let mut unreachable = false;
    let mut probing = false;
    let mut not_reached: Option<String> = None;
    let still_pending = |request: OutgoingRequest, not_reached: Option<String>| Waited::Pending {
        request,
        not_reached,
    };
    loop {
        // The record as kept now: another task may have ended it.
        let (store, mut request) = match current(vault, key_name) {
            Ok((store, Some(request))) if request.state == OutgoingState::Pending => {
                (store, request)
            }
            Ok((_, Some(request))) => return Waited::Ended(request),
            Ok((_, None)) => return Waited::NotRecorded,
            Err(e) => {
                tracing::warn!(target: "security", key = %key_name, error = %e, "cannot read a request record; reading it again in {}s", RETRY_MAX.as_secs());
                if until.is_some_and(|deadline| {
                    deadline.saturating_duration_since(Instant::now()) <= RETRY_MAX
                }) {
                    return Waited::Unreadable(e);
                }
                tokio::select! {
                    _ = cancel.cancelled() => return Waited::Unreadable(e),
                    _ = tokio::time::sleep(RETRY_MAX) => continue,
                }
            }
        };
        if request.overdue(crate::now_secs()) {
            if let Err(e) = expire_overdue(vault, &store, p.words()) {
                tracing::warn!(target: "security", key = %key_name, error = %e.reason, "a request past its expiry could not be ended here");
            }
            return match current(vault, key_name) {
                Ok((_, Some(ended))) => Waited::Ended(ended),
                _ => Waited::Ended(request),
            };
        }
        let id = request.request_id.clone();
        let (Ok(namespace), Ok(ca_prefix)) = (
            request.namespace.parse::<Name>(),
            request.ca_prefix.parse::<Name>(),
        ) else {
            request.state = OutgoingState::Failed {
                reason: p.words().request_names_no_ca(),
            };
            record(&store, &request);
            return Waited::Ended(request);
        };
        let longest = if probing {
            STATUS_PROBE_LIFETIME
        } else {
            STATUS_LIFETIME
        };
        let lifetime = match until {
            Some(deadline) => deadline
                .saturating_duration_since(Instant::now())
                .min(longest)
                .max(STATUS_ANSWER_MARGIN),
            None => longest,
        };
        let asked = Instant::now();
        let status = tokio::select! {
            _ = cancel.cancelled() => return still_pending(request, not_reached),
            status = ndn_identity::request_status_via_engine(
                p.engine(),
                p.keyring(),
                &namespace,
                &ca_prefix,
                &id,
                &request.key_name,
                lifetime,
            ) => status,
        };
        if status.is_ok() && unreachable {
            unreachable = false;
            tracing::info!(target: "security", request = %id, ca = %ca_prefix, "the CA is reachable again; waiting for its decision");
        }
        let pause = match status {
            Ok(RequestStatus::Pending { expires_secs, .. }) => {
                not_reached = None;
                if expires_secs != request.expires_secs && expires_secs != 0 {
                    request.expires_secs = expires_secs;
                    record(&store, &request);
                }
                // The CA answers pending shortly before the Interest
                // expires. An earlier answer is followed by a pause,
                // growing while they keep coming early, and short
                // Interests until the CA holds one again.
                if asked.elapsed() < status_hold(Some(lifetime)) / 2 {
                    probing = true;
                    Some(retry)
                } else {
                    probing = false;
                    retry = RETRY_FIRST;
                    None
                }
            }
            Ok(RequestStatus::Approved { .. }) => {
                match issue(p, vault, &store, request.clone()).await {
                    Issue::Ended(request) => return Waited::Ended(request),
                    // The status said approved, the exchange says pending (the
                    // CA was replaced in between): wait, never loop fast.
                    Issue::Pending => Some(retry),
                    Issue::Retry(why) => {
                        tracing::warn!(target: "security", request = %id, error = %why, "approved, but the certificate is not kept yet; the key and the request are kept, asking again in {}s", retry.as_secs());
                        not_reached = Some(why);
                        Some(retry)
                    }
                }
            }
            Ok(RequestStatus::Denied { reason, .. }) => {
                return Waited::Ended(end(
                    vault,
                    &store,
                    request,
                    |reason| OutgoingState::Denied { reason },
                    &reason,
                ));
            }
            Ok(RequestStatus::Expired { reason, .. }) => {
                return Waited::Ended(end(
                    vault,
                    &store,
                    request,
                    |reason| OutgoingState::Expired { reason },
                    &reason,
                ));
            }
            Err(e @ ApprovalEnrollError::UntrustedAnswer(_)) => {
                tracing::warn!(target: "security", request = %id, error = %e, "asking again in {}s", retry.as_secs());
                not_reached = Some(e.to_string());
                probing = true;
                Some(retry)
            }
            Err(e) => {
                if !unreachable {
                    unreachable = true;
                    tracing::warn!(
                        target: "security",
                        request = %id,
                        error = %e,
                        "the CA could not be asked about a request for an admin's approval; asking \
                         again after a pause growing from {}s to {}s",
                        RETRY_FIRST.as_secs(),
                        RETRY_MAX.as_secs()
                    );
                }
                not_reached = Some(e.to_string());
                probing = true;
                Some(retry)
            }
        };
        if let Some(deadline) = until {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining <= STATUS_ANSWER_MARGIN || pause.is_some_and(|pause| remaining <= pause) {
                return still_pending(request, not_reached);
            }
        }
        if let Some(pause) = pause {
            retry = (retry * 2).min(RETRY_MAX);
            tokio::select! {
                _ = cancel.cancelled() => return still_pending(request, not_reached),
                _ = tokio::time::sleep(pause) => {}
            }
        }
    }
}

/// End `request` on the CA-signed denial or expiry `reason`: its key is
/// deleted and the record says why (`state`).
fn end(
    vault: &dyn KeyVault,
    store: &RequestStore,
    mut request: OutgoingRequest,
    state: impl FnOnce(String) -> OutgoingState,
    reason: &str,
) -> OutgoingRequest {
    let reason = match request.key_name.parse::<Name>() {
        Ok(key) => match vault.discard(&key) {
            Ok(()) => format!("{reason}; the key {key} was deleted"),
            Err(e) => format!(
                "{reason}; the key {key} could not be deleted ({e}): delete it from {}",
                vault.location()
            ),
        },
        Err(_) => reason.to_owned(),
    };
    tracing::warn!(target: "security", request = %request.request_id, error = %reason, "request for an admin's approval ended");
    request.state = state(reason);
    record(store, &request);
    request
}

/// What the issuance exchange of an approved request did.
enum Issue {
    /// The record ended (issued, or failed / denied / expired with why).
    Ended(OutgoingRequest),
    /// The CA still answers pending: keep waiting.
    Pending,
    /// The CA could not be asked, or the key not read: ask again (why).
    Retry(String),
}

/// Run the issuance exchange for `request`, which the CA says is approved:
/// a fresh NEW → CHALLENGE exchange resuming it
/// ([`ndn_identity::poll_approval_via_engine`]); the certificate is
/// installed as an enrollment would ([`install`]) and the record says
/// `issued`. A final refusal ends the record (the key is deleted).
async fn issue(
    p: &Participant,
    vault: &dyn KeyVault,
    store: &RequestStore,
    mut request: OutgoingRequest,
) -> Issue {
    let id = request.request_id.clone();
    let parsed = (
        request.namespace.parse::<Name>(),
        request.ca_prefix.parse::<Name>(),
        request.identity.parse::<Name>(),
        request.key_name.parse::<Name>(),
    );
    let (Ok(namespace), Ok(ca_prefix), Ok(identity), Ok(key)) = parsed else {
        request.state = OutgoingState::Failed {
            reason: p.words().request_names_no_key(),
        };
        record(store, &request);
        return Issue::Ended(request);
    };
    let signer: Arc<dyn Signer> = match vault.signer(&key) {
        Ok(signer) => signer,
        Err(KeyUnavailable::Unreadable(why)) => return Issue::Retry(why),
        Err(KeyUnavailable::Gone(why)) => {
            request.state = OutgoingState::Failed {
                reason: p.words().request_key_gone(&key, why),
            };
            record(store, &request);
            return Issue::Ended(request);
        }
    };
    let poll = ndn_identity::poll_approval_via_engine(
        p.engine(),
        p.keyring(),
        &namespace,
        &ca_prefix,
        Arc::clone(&signer),
        Some(&id),
        None,
    )
    .await;
    match poll {
        Ok(ApprovalPoll::Pending(_)) => Issue::Pending,
        Ok(ApprovalPoll::Issued(issued)) => {
            let _one_at_a_time = p.enrolling.lock().await;
            let enrolling = Enrolling {
                namespace,
                identity,
                previous_identity: vault.default_identity().ok().flatten(),
                adopted_context: None,
                context_check: None,
            };
            request.state = match install(
                p,
                vault,
                &key,
                signer,
                &issued,
                enrolling,
                &p.words().approval_used(),
            )
            .await
            {
                Ok(info) => {
                    tracing::info!(
                        target: "security",
                        request = %id,
                        certificate = %info.certificate,
                        signing_now = info.signing_now,
                        "an admin approved the request: enrolled"
                    );
                    OutgoingState::Issued {
                        certificate: info.certificate,
                    }
                }
                Err(e) => {
                    tracing::error!(target: "security", request = %id, error = %e.reason, "approved, but the certificate was not kept");
                    OutgoingState::Failed { reason: e.reason }
                }
            };
            record(store, &request);
            Issue::Ended(request)
        }
        Err(e) if !e.is_final() => Issue::Retry(e.to_string()),
        Err(e) => {
            discard(vault, &key);
            let reason = format!("{e}; the key {key} was deleted");
            tracing::warn!(target: "security", request = %id, error = %reason, "request for an admin's approval ended");
            request.state = OutgoingState::ended(&e, reason);
            record(store, &request);
            Issue::Ended(request)
        }
    }
}

/// Save `request`'s new state (a failure is logged: the record stays as it
/// was, and is waited on again later).
fn record(store: &RequestStore, request: &OutgoingRequest) {
    if let Err(e) = store.save(request) {
        tracing::error!(
            target: "security",
            request = %request.request_id,
            state = request.state.as_str(),
            error = %e,
            "could not record a request's new state"
        );
    }
}
