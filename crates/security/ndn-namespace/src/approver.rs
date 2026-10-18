//! Listing and deciding requests for an admin's approval, on the CA host and
//! on a remote admin device.
//!
//! The device picks the path per namespace by whether it runs that
//! namespace's CA ([`ndn_cert::approval`]):
//!
//! - **this device runs the CA** (`local`, its [`ApprovalStore`]): the CA's
//!   durable records are read and decided directly. The approver recorded
//!   is the local operator the host names (`uid 1000 (alice)`); the issued
//!   certificate's attestation names them and claims no signature.
//! - **this device is an admin device of a namespace whose CA runs
//!   elsewhere** (its vault holds a current, unrevoked admin certificate of
//!   the namespace, an [`AdminCredential`]): the pending list is fetched
//!   from `<ca>/CA/PENDING` with an Interest signed by the admin key, and a
//!   decision is a Data `<requester key>/ndncert-approve|deny/<request id>`
//!   signed by the admin key — an approval carries the verification code
//!   shown, a denial its reason — pushed to `<ca>/CA/APPROVAL` with the
//!   admin certificate's chain. The CA validates it under the namespace's
//!   trust context and records the admin key with the signed Data as
//!   evidence.
//!
//! A request is named by its request id or its six-digit verification code,
//! which the requesting device shows too: comparing the two is the check
//! that it is the right device.
//!
//! [`list`] and [`decide`] take the admin credentials as a function, called
//! only when the remote path is needed: a CA host's own decision does not
//! read its admin keys. A host builds them with [`admin_credentials`] from
//! its [`KeyVault`] (all of them, one per namespace), or from a vault that
//! holds only the identity it has loaded.

use std::sync::Arc;

use bytes::Bytes;
use ndn_cert::roles::{Role, parse_device_key};
use ndn_cert::{ApprovalRecord, ApprovalStore, ApproverError, Decision, RefusalKind};
use ndn_mgmt_wire::control_response::status;
use ndn_packet::{Data, Name};
use ndn_security::{Certificate, Signer};

use crate::{KeyVault, Participant, TrustRefusal, refusal};

/// An admin key of this device in a namespace whose CA runs elsewhere.
#[derive(Clone)]
pub struct AdminCredential {
    pub namespace: Name,
    /// The CA that issued the admin certificate (`/<ns>` for `/<ns>/CA`).
    pub ca_prefix: Name,
    pub key: Name,
    pub signer: Arc<dyn Signer>,
    /// The admin certificate, then the issuer certificates kept for its
    /// chain ([`KeyVault::issuers`]): what the CA walks to the namespace
    /// root.
    pub chain: Vec<Bytes>,
}

/// The requests a device can see: its own CA's records (oldest first),
/// then each administered namespace's in credential order, and a note for
/// each namespace whose requests could not be listed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Listing {
    pub records: Vec<ApprovalRecord>,
    pub notes: Vec<String>,
}

/// This device's admin keys, one per namespace (the newest valid
/// certificate): a device key `/<ns>/admin/<device>/KEY/…` of a namespace
/// whose trust context the participant holds, with a current certificate
/// the context does not revoke, issued by a CA other than `local_ca` (this
/// device's own, decided locally). A key whose signer is unavailable is
/// skipped with a warning.
pub fn admin_credentials(
    p: &Participant,
    vault: &dyn KeyVault,
    local_ca: Option<&Name>,
) -> Result<Vec<AdminCredential>, TrustRefusal> {
    let unreadable = |e: String| {
        refusal(
            status::SERVER_ERROR,
            format!("cannot read this node's admin keys: {e}"),
        )
    };
    let keys = vault.keys().map_err(unreadable)?;
    let namespaces: Vec<Name> = p
        .keyring()
        .contexts()
        .iter()
        .map(|c| c.namespace().clone())
        .collect();
    let kept: Vec<Bytes> = vault.issuers();
    let mut out: Vec<(u64, AdminCredential)> = Vec::new();
    for key in keys {
        let Some(namespace) = namespaces
            .iter()
            .find(|ns| parse_device_key(ns, &key).is_some_and(|d| d.role == Role::Admin))
        else {
            continue;
        };
        let Some(wire) = vault.issued_certificate(&key).map_err(unreadable)? else {
            continue;
        };
        let Some((data, cert)) = Data::decode(wire)
            .ok()
            .and_then(|d| Certificate::decode(&d).ok().map(|c| (d, c)))
        else {
            continue;
        };
        if !cert.is_valid_now() {
            continue;
        }
        let context = p.keyring().context_for(&cert.name);
        if context.is_revoked(&cert.name) {
            continue;
        }
        let Some(ca_prefix) = ndn_cert::issuing_ca_prefix(&cert) else {
            continue;
        };
        if local_ca == Some(&ca_prefix) {
            continue;
        }
        let signer = match vault.signer(&key) {
            Ok(signer) => signer,
            Err(e) => {
                tracing::warn!(target: "security", key = %key, error = %e, "an admin certificate's key cannot sign; it decides nothing");
                continue;
            }
        };
        let chain = ndn_cert::approval::admin_chain(&data, &cert, &kept);
        let candidate = AdminCredential {
            namespace: namespace.clone(),
            ca_prefix,
            key,
            signer,
            chain,
        };
        match out
            .iter_mut()
            .find(|(_, c)| c.namespace == candidate.namespace)
        {
            Some(slot) if slot.0 < cert.valid_from => *slot = (cert.valid_from, candidate),
            Some(_) => {}
            None => out.push((cert.valid_from, candidate)),
        }
    }
    Ok(out.into_iter().map(|(_, c)| c).collect())
}

/// Every request this device can see: `local` (its own CA's store, `None`
/// when it runs no CA that takes approval requests) and what each
/// administered namespace's CA answers. Refused only when nothing at all
/// could be listed.
pub async fn list(
    p: &Participant,
    local: Option<&ApprovalStore>,
    credentials: impl FnOnce() -> Result<Vec<AdminCredential>, TrustRefusal>,
) -> Result<Listing, TrustRefusal> {
    let creds = credentials()?;
    if local.is_none() && creds.is_empty() {
        return Err(nothing_here(p));
    }
    let local = local.map(|store| store.records());
    let mut remote = Vec::with_capacity(creds.len());
    for cred in &creds {
        remote.push(match fetch(p, cred).await {
            Ok(records) => Ok(records),
            Err(e) => Err(unlisted(cred, e)),
        });
    }
    merge_listing(local, remote)
}

/// Decide the pending request `target` names (its request id or its
/// verification code): at this device's own CA (`local`) first, decided by
/// `operator`; else at the CA of the one administered namespace that has
/// it, with that namespace's admin key. Returns the request as decided.
pub async fn decide(
    p: &Participant,
    local: Option<&ApprovalStore>,
    credentials: impl FnOnce() -> Result<Vec<AdminCredential>, TrustRefusal>,
    target: &str,
    decision: Decision,
    operator: &str,
) -> Result<ApprovalRecord, TrustRefusal> {
    // This device's own CA first: its local operator decides.
    let mut local_miss = None;
    if let Some(store) = local {
        match store.find_pending(target) {
            Ok(_) => {
                return store
                    .decide_locally(target, decision, operator)
                    .map_err(TrustRefusal::from);
            }
            Err(r) if r.kind == RefusalKind::NotFound => local_miss = Some(r),
            Err(r) => return Err(r.into()),
        }
    }
    let creds = credentials()?;
    if creds.is_empty() {
        return Err(match local_miss {
            Some(miss) => miss.into(),
            None => nothing_here(p),
        });
    }
    // The namespaces this device administers: ask each CA what is pending.
    let mut found: Vec<(&AdminCredential, ApprovalRecord)> = Vec::new();
    let mut failed = Vec::new();
    for cred in &creds {
        match fetch(p, cred).await {
            Ok(records) => match ndn_cert::approval::find_pending_in(&records, target) {
                Ok(record) => found.push((cred, record)),
                Err(r) if r.kind == RefusalKind::NotFound => {}
                Err(r) => return Err(approver_refusal(cred, ApproverError::Refused(r))),
            },
            Err(e) => failed.push(approver_refusal(cred, e)),
        }
    }
    let (cred, record) = match found.len() {
        1 => found.remove(0),
        0 => {
            let mut reason = p.words().no_pending_request(
                target,
                if local.is_some() {
                    "this node's CA or at the CAs of the namespaces it administers"
                } else {
                    "the CAs of the namespaces this node administers"
                },
            );
            let mut code = status::NOT_FOUND;
            if let Some(first) = failed.first() {
                code = first.status_code;
                let reasons: Vec<&str> = failed.iter().map(|r| r.reason.as_str()).collect();
                reason.push_str(&format!(
                    "; not every CA could be asked: {}",
                    reasons.join("; ")
                ));
            }
            return Err(refusal(code, reason));
        }
        _ => {
            let at: Vec<String> = found
                .iter()
                .map(|(c, r)| format!("{} ({})", r.request_id, c.ca_prefix))
                .collect();
            return Err(refusal(
                409,
                format!(
                    "requests in several namespaces show {target:?}: {}; decide by request id",
                    at.join(", ")
                ),
            ));
        }
    };
    tracing::info!(
        target: "security",
        operator = %operator,
        admin_key = %cred.key,
        request = %record.request_id,
        ca = %cred.ca_prefix,
        decision = ?decision,
        "deciding a request at the namespace's CA with this device's admin key"
    );
    ndn_identity::push_decision_via_engine(
        p.engine(),
        p.keyring(),
        &cred.namespace,
        &record,
        &decision,
        &cred.signer,
        &cred.chain,
    )
    .await
    .map_err(|e| approver_refusal(cred, e))
}

/// Nothing to approve on this device, and how to change that.
fn nothing_here(p: &Participant) -> TrustRefusal {
    refusal(status::NOT_FOUND, p.words().nothing_to_approve())
}

/// The pending requests at `cred`'s CA.
async fn fetch(
    p: &Participant,
    cred: &AdminCredential,
) -> Result<Vec<ApprovalRecord>, ApproverError> {
    ndn_identity::fetch_pending_via_engine(
        p.engine(),
        p.keyring(),
        &cred.namespace,
        &cred.ca_prefix,
        &cred.signer,
        &cred.chain,
    )
    .await
}

/// A refused remote listing or decision, with what to do.
fn approver_refusal(cred: &AdminCredential, e: ApproverError) -> TrustRefusal {
    match e {
        ApproverError::Refused(r) => {
            let mut r = TrustRefusal::from(r);
            r.reason = format!("the CA {} refused: {}", cred.ca_prefix, r.reason);
            r
        }
        ApproverError::CaUnreachable { .. } => refusal(504, e.to_string()),
        ApproverError::BadAnswer(_) => refusal(502, e.to_string()),
        ApproverError::Signing(_) => refusal(status::SERVER_ERROR, e.to_string()),
    }
}

/// The listing note for a namespace whose CA could not be asked: why, and
/// what to do. The refusal (status and reason) is what [`list`] answers
/// when no namespace at all could be listed.
fn unlisted(cred: &AdminCredential, e: ApproverError) -> (TrustRefusal, String) {
    let ns = &cred.namespace;
    let unreachable = match &e {
        ApproverError::CaUnreachable { detail, .. } => Some(detail.clone()),
        _ => None,
    };
    let r = approver_refusal(cred, e);
    let note = match unreachable {
        Some(detail) => format!(
            "{ns}: unreachable ({detail}); its requests are not shown — retry when it is up"
        ),
        None => format!(
            "{ns}: not listed ({}); its requests are not shown",
            r.reason
        ),
    };
    (r, note)
}

/// Merge this device's own CA's records (`local`, `None` when it runs no
/// CA) with what each administered namespace's CA answered: the records
/// that could be listed, and a note for each namespace that could not.
/// Refused only when nothing at all could be listed — a CA host keeps
/// seeing its own queue while another namespace's CA is down.
fn merge_listing(
    local: Option<Vec<ApprovalRecord>>,
    remote: Vec<Result<Vec<ApprovalRecord>, (TrustRefusal, String)>>,
) -> Result<Listing, TrustRefusal> {
    let mut listed = local.is_some();
    let mut listing = Listing {
        records: local.unwrap_or_default(),
        notes: Vec::new(),
    };
    let mut first_failure = None;
    for answer in remote {
        match answer {
            Ok(records) => {
                listed = true;
                listing.records.extend(records);
            }
            Err((r, note)) => {
                first_failure.get_or_insert(r.status_code);
                listing.notes.push(note);
            }
        }
    }
    match first_failure {
        Some(code) if !listed => Err(refusal(
            code,
            format!(
                "could not list the pending requests of any namespace this node administers: {}",
                listing.notes.join("; ")
            ),
        )),
        _ => Ok(listing),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_cert::ApprovalState;

    fn record(id: &str, namespace: &str) -> ApprovalRecord {
        ApprovalRecord {
            request_id: id.into(),
            ca_prefix: namespace.into(),
            key_name: format!("{namespace}/node/relay/KEY/k"),
            public_key_sha256: String::new(),
            role: None,
            device: None,
            code: "482 913".into(),
            created_secs: 0,
            expires_secs: 0,
            invite: false,
            state: ApprovalState::Pending,
        }
    }

    fn unreachable(ns: &str) -> (TrustRefusal, String) {
        (
            refusal(504, "no answer"),
            format!(
                "{ns}: unreachable (no answer); its requests are not shown — retry when it is up"
            ),
        )
    }

    #[test]
    fn list_shows_local_rows_when_remote_unreachable() {
        // A CA host that also administers /work: /work's CA is down, its
        // own queue still lists, with a note naming what is missing.
        let listing = merge_listing(
            Some(vec![record("1a", "/home")]),
            vec![Err(unreachable("/work"))],
        )
        .expect("the local CA's rows are listed");
        assert_eq!(listing.records, vec![record("1a", "/home")]);
        assert_eq!(listing.notes, vec![unreachable("/work").1]);

        // An admin device: one CA answers, another is down.
        let listing = merge_listing(
            None,
            vec![Ok(vec![record("2b", "/home")]), Err(unreachable("/work"))],
        )
        .expect("the reachable namespace's rows are listed");
        assert_eq!(listing.records, vec![record("2b", "/home")]);
        assert_eq!(listing.notes.len(), 1);

        // Nothing could be listed: refused, saying which and why.
        let r = merge_listing(None, vec![Err(unreachable("/work"))]).unwrap_err();
        assert_eq!(r.status_code, 504);
        assert!(r.reason.contains("/work: unreachable"), "{}", r.reason);
    }
}
