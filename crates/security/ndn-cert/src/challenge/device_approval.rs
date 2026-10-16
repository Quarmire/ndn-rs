//! Device-approval challenge — a request is approved by another already-
//! approved device under the same identity, via an in-process
//! `PendingApprovalStore` the approver dashboard writes to. Cross-process
//! approvals arrive through `ndn_identity::device_approval_net`'s validated
//! approval feed, which records them with
//! [`PendingApprovalStore::approve_validated`].

use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
};

use base64::Engine as _;

use crate::{
    attestation::{AttestationSet, ChallengeAttestation},
    challenge::{ChallengeHandler, ChallengeOutcome, ChallengeState},
    error::CertError,
    protocol::CertRequest,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalState {
    Pending,
    Approved,
    Denied(String),
}

#[derive(Debug, Clone)]
pub struct ApprovalRequest {
    pub id: String,
    pub cert_name: String,
    pub description: String,
    pub state: ApprovalState,
    /// For cross-process approvals: the approving device's identity name.
    /// `None` for the in-process (unsigned) flow.
    pub approver: Option<String>,
    /// The signature value of the approver's signed approval Data, already
    /// validated upstream (see [`PendingApprovalStore::approve_validated`]).
    /// Empty for the in-process flow.
    pub signed_approval: Vec<u8>,
}

/// The NDN name of the approver's *signed approval Data* for one request:
/// `<cert_name>/ndncert-approve/<request_id>`. This is a real Data name signed
/// by the approver, so a CA can validate it through its trust schema with the
/// real `(data_name, signer_cert_name)` pair — matching canonical LVS usage
/// (python-ndn / ndnd). Binding the request id into the name stops an approval
/// being replayed onto a different enrollment. Returns `None` if `cert_name`
/// is unparseable.
pub fn approval_data_name(cert_name: &str, request_id: &str) -> Option<ndn_packet::Name> {
    let name: ndn_packet::Name = cert_name.parse().ok()?;
    Some(name.append("ndncert-approve").append(request_id))
}

#[derive(Clone, Default)]
pub struct PendingApprovalStore {
    inner: Arc<Mutex<StoreInner>>,
}

#[derive(Default)]
struct StoreInner {
    next_id: u64,
    requests: HashMap<String, ApprovalRequest>,
}

impl PendingApprovalStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns a monotonic `req-N` id (opaque to the wire).
    pub fn submit(&self, cert_name: impl Into<String>, description: impl Into<String>) -> String {
        let mut guard = self.inner.lock().expect("PendingApprovalStore poisoned");
        guard.next_id += 1;
        let id = format!("req-{}", guard.next_id);
        guard.requests.insert(
            id.clone(),
            ApprovalRequest {
                id: id.clone(),
                cert_name: cert_name.into(),
                description: description.into(),
                state: ApprovalState::Pending,
                approver: None,
                signed_approval: Vec::new(),
            },
        );
        id
    }

    /// In-process approval (no cryptographic evidence). Returns `true` only
    /// if the request existed and was `Pending`.
    pub fn approve(&self, id: &str) -> bool {
        let mut guard = self.inner.lock().expect("PendingApprovalStore poisoned");
        match guard.requests.get_mut(id) {
            Some(r) if matches!(r.state, ApprovalState::Pending) => {
                r.state = ApprovalState::Approved;
                true
            }
            _ => false,
        }
    }

    /// Record a **validator-checked** cross-process approval: the caller has
    /// already validated the approver's signed approval Data through a
    /// `Validator` (signature + cert chain + trust schema), so authentication
    /// and authorization are done. `approver` is the validated signer name and
    /// `signature` its Data's signature value (recorded as attestation
    /// evidence). The challenge does not re-verify. Returns `true` only if the
    /// request existed and was `Pending`.
    pub fn approve_validated(
        &self,
        id: &str,
        approver: impl Into<String>,
        signature: Vec<u8>,
    ) -> bool {
        let mut guard = self.inner.lock().expect("PendingApprovalStore poisoned");
        match guard.requests.get_mut(id) {
            Some(r) if matches!(r.state, ApprovalState::Pending) => {
                r.approver = Some(approver.into());
                r.signed_approval = signature;
                r.state = ApprovalState::Approved;
                true
            }
            _ => false,
        }
    }

    /// Returns `true` only if the request existed and was `Pending`.
    pub fn deny(&self, id: &str, reason: impl Into<String>) -> bool {
        let mut guard = self.inner.lock().expect("PendingApprovalStore poisoned");
        match guard.requests.get_mut(id) {
            Some(r) if matches!(r.state, ApprovalState::Pending) => {
                r.state = ApprovalState::Denied(reason.into());
                true
            }
            _ => false,
        }
    }

    pub fn get(&self, id: &str) -> Option<ApprovalRequest> {
        let guard = self.inner.lock().expect("PendingApprovalStore poisoned");
        guard.requests.get(id).cloned()
    }

    pub fn pending(&self) -> Vec<ApprovalRequest> {
        let guard = self.inner.lock().expect("PendingApprovalStore poisoned");
        guard
            .requests
            .values()
            .filter(|r| matches!(r.state, ApprovalState::Pending))
            .cloned()
            .collect()
    }
}

pub struct DeviceApprovalChallenge {
    store: PendingApprovalStore,
}

impl DeviceApprovalChallenge {
    pub fn new(store: PendingApprovalStore) -> Self {
        Self { store }
    }
}

impl ChallengeHandler for DeviceApprovalChallenge {
    fn challenge_type(&self) -> &'static str {
        "device-approval"
    }

    fn begin<'a>(
        &'a self,
        req: &'a CertRequest,
    ) -> Pin<Box<dyn Future<Output = Result<ChallengeState, CertError>> + Send + 'a>> {
        Box::pin(async move {
            let cert_name = req.name.to_string();
            let id = self.store.submit(cert_name, String::new());
            Ok(ChallengeState {
                challenge_type: "device-approval".to_string(),
                data: serde_json::json!({ "request_id": id }),
            })
        })
    }

    fn verify<'a>(
        &'a self,
        state: &'a ChallengeState,
        parameters: &'a serde_json::Map<String, serde_json::Value>,
    ) -> Pin<Box<dyn Future<Output = Result<ChallengeOutcome, CertError>> + Send + 'a>> {
        Box::pin(async move {
            let id = match state.data.get("request_id").and_then(|v| v.as_str()) {
                Some(s) => s.to_string(),
                None => parameters
                    .get("request_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            };
            let entry = match self.store.get(&id) {
                Some(e) => e,
                None => {
                    return Ok(ChallengeOutcome::Denied(format!(
                        "no pending approval request for id {id:?}"
                    )));
                }
            };
            match entry.state {
                ApprovalState::Approved => {
                    let attestation = Some(build_attestation(&entry, &id));
                    Ok(ChallengeOutcome::Approved { attestation })
                }
                ApprovalState::Denied(reason) => Ok(ChallengeOutcome::Denied(reason)),
                ApprovalState::Pending => Ok(ChallengeOutcome::Pending {
                    status_message: format!(
                        "Awaiting device approval for {} (id {id})",
                        entry.cert_name
                    ),
                    remaining_tries: 30,
                    remaining_time_secs: 600,
                    next_state: ChallengeState {
                        challenge_type: "device-approval".to_string(),
                        data: serde_json::json!({ "request_id": id }),
                    },
                }),
            }
        })
    }
}

/// Build the attestation for an approved request. For the unsigned
/// in-process flow this is a `request_id`-only leaf. For a cross-process
/// approval (validated upstream) it records the approver identity and its
/// signature as independent evidence.
fn build_attestation(entry: &ApprovalRequest, id: &str) -> AttestationSet {
    let mut leaf = ChallengeAttestation::of_kind("device-approval");
    leaf.handler_name = Some("device-approval".to_string());
    leaf = leaf.with_evidence("request_id", serde_json::json!(id));

    if let Some(approver) = &entry.approver {
        leaf = leaf.with_evidence("approved_by", serde_json::json!(approver));
        leaf.signature =
            Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&entry.signed_approval));
    }
    AttestationSet::single(leaf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_assigns_monotonic_ids() {
        let store = PendingApprovalStore::new();
        let a = store.submit("/lab/alice", "alice's laptop");
        let b = store.submit("/lab/bob", "bob's phone");
        assert_ne!(a, b);
        assert!(a.starts_with("req-"));
        assert!(b.starts_with("req-"));
    }

    #[test]
    fn submitted_request_starts_pending() {
        let store = PendingApprovalStore::new();
        let id = store.submit("/lab/alice", "");
        let r = store.get(&id).expect("present");
        assert_eq!(r.state, ApprovalState::Pending);
        assert_eq!(r.cert_name, "/lab/alice");
        assert_eq!(store.pending().len(), 1);
    }

    #[test]
    fn approve_flips_pending_to_approved() {
        let store = PendingApprovalStore::new();
        let id = store.submit("/lab/alice", "");
        assert!(store.approve(&id));
        let r = store.get(&id).expect("present");
        assert_eq!(r.state, ApprovalState::Approved);
        assert!(store.pending().is_empty());
    }

    #[test]
    fn approve_unknown_id_is_noop() {
        let store = PendingApprovalStore::new();
        assert!(!store.approve("nope"));
    }

    #[test]
    fn approve_already_resolved_is_noop() {
        let store = PendingApprovalStore::new();
        let id = store.submit("/lab/alice", "");
        assert!(store.deny(&id, "rejected"));
        assert!(!store.approve(&id));
        let r = store.get(&id).expect("present");
        match r.state {
            ApprovalState::Denied(reason) => assert_eq!(reason, "rejected"),
            other => panic!("expected Denied, got {other:?}"),
        }
    }

    #[test]
    fn deny_records_reason() {
        let store = PendingApprovalStore::new();
        let id = store.submit("/lab/eve", "");
        assert!(store.deny(&id, "not on the team"));
        let r = store.get(&id).expect("present");
        assert_eq!(r.state, ApprovalState::Denied("not on the team".to_owned()));
    }

    fn req(name: &str) -> CertRequest {
        CertRequest {
            name: name.to_owned(),
            public_key: String::new(),
            not_before: 0,
            not_after: 0,
        }
    }

    /// Drive the challenge to its single approval round and return the id.
    async fn begin_request(
        challenge: &DeviceApprovalChallenge,
        name: &str,
    ) -> (ChallengeState, String) {
        let state = challenge.begin(&req(name)).await.unwrap();
        let id = state.data["request_id"].as_str().unwrap().to_string();
        (state, id)
    }

    #[tokio::test]
    async fn unsigned_approval_attestation_has_no_signature() {
        let store = PendingApprovalStore::new();
        let challenge = DeviceApprovalChallenge::new(store.clone());
        let (state, id) = begin_request(&challenge, "/lab/alice").await;
        assert!(store.approve(&id));

        let outcome = challenge
            .verify(&state, &serde_json::Map::new())
            .await
            .unwrap();
        let set = match outcome {
            ChallengeOutcome::Approved { attestation } => attestation.unwrap(),
            other => panic!("expected Approved, got {other:?}"),
        };
        let leaf = &set.leaves[0];
        assert_eq!(leaf.kind, "device-approval");
        assert!(
            leaf.signature.is_none(),
            "in-process flow carries no signature"
        );
        assert!(leaf.evidence.contains_key("request_id"));
        assert!(!leaf.evidence.contains_key("approved_by"));
    }

    #[tokio::test]
    async fn validated_approval_records_approver_and_signature() {
        let store = PendingApprovalStore::new();
        let challenge = DeviceApprovalChallenge::new(store.clone());
        let (state, id) = begin_request(&challenge, "/lab/alice").await;

        let approver = "/lab/alice/devices/phone/KEY/k1";
        assert!(store.approve_validated(&id, approver, vec![1, 2, 3]));

        let outcome = challenge
            .verify(&state, &serde_json::Map::new())
            .await
            .unwrap();
        let set = match outcome {
            ChallengeOutcome::Approved { attestation } => attestation.unwrap(),
            other => panic!("expected Approved, got {other:?}"),
        };
        let leaf = &set.leaves[0];
        assert_eq!(leaf.kind, "device-approval");
        assert!(
            leaf.signature.is_some(),
            "validated flow records the signature"
        );
        assert_eq!(
            leaf.evidence.get("approved_by").unwrap(),
            &serde_json::json!(approver)
        );
    }
}
