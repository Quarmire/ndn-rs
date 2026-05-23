//! Device-approval challenge — a request is approved by another already-
//! approved device under the same identity, via an in-process
//! [`PendingApprovalStore`] the approver dashboard writes to.

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
    /// The approver's raw public key, against which [`signed_approval`] is
    /// verified. Empty for the in-process flow.
    ///
    /// [`signed_approval`]: Self::signed_approval
    pub approver_pubkey: Vec<u8>,
    /// The approver's signature for this request. Its meaning depends on
    /// [`validated`](Self::validated): the signature over [`approval_statement`]
    /// (statement path) or the signature value of the approver's signed
    /// approval Data (canonical, validator-checked path). Empty for the
    /// in-process flow.
    pub signed_approval: Vec<u8>,
    /// `true` when the approval was recorded via [`approve_validated`] — i.e.
    /// the caller already validated the approver's *signed approval Data*
    /// through a `Validator` (signature + chain + trust schema), the canonical
    /// path. The challenge then trusts it without re-verifying.
    ///
    /// [`approve_validated`]: PendingApprovalStore::approve_validated
    pub validated: bool,
}

/// The canonical bytes a cross-process approver signs to attest to one
/// request: ties the approval to the exact requested cert name and the
/// per-request id (the nonce), so a signature can't be replayed onto a
/// different enrollment. Used by the trait-authorizer path
/// (`StaticTrustedApprovers` / `DidApproverAuthorizer`).
pub fn approval_statement(cert_name: &str, request_id: &str) -> Vec<u8> {
    format!("ndncert-approve:{cert_name}:{request_id}").into_bytes()
}

/// The NDN name of the approver's *signed approval Data* for one request:
/// `<cert_name>/ndncert-approve/<request_id>`. This is a real Data name signed
/// by the approver, so a CA can validate it through its trust schema with the
/// real `(data_name, signer_cert_name)` pair — matching canonical LVS usage
/// (python-ndn / ndnd), unlike the synthetic statement bytes. Returns `None`
/// if `cert_name` is unparseable.
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
                approver_pubkey: Vec::new(),
                signed_approval: Vec::new(),
                validated: false,
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

    /// Cross-process approval: record the approving device's identity, its
    /// public key, and its signature over [`approval_statement`]. The
    /// challenge handler verifies the signature before satisfying, and the
    /// resulting attestation carries it as independent evidence. Returns
    /// `true` only if the request existed and was `Pending`.
    pub fn approve_signed(
        &self,
        id: &str,
        approver: impl Into<String>,
        approver_pubkey: Vec<u8>,
        signature: Vec<u8>,
    ) -> bool {
        let mut guard = self.inner.lock().expect("PendingApprovalStore poisoned");
        match guard.requests.get_mut(id) {
            Some(r) if matches!(r.state, ApprovalState::Pending) => {
                r.approver = Some(approver.into());
                r.approver_pubkey = approver_pubkey;
                r.signed_approval = signature;
                r.validated = false;
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
                r.approver_pubkey = Vec::new();
                r.signed_approval = signature;
                r.validated = true;
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
                None => {
                    parameters
                        .get("request_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string()
                }
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
                    let attestation = match build_signed_attestation(&entry, &id).await {
                        Ok(set) => Some(set),
                        // A recorded signature that doesn't verify is a hard
                        // denial — the approval can't be trusted.
                        Err(reason) => return Ok(ChallengeOutcome::Denied(reason)),
                    };
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
/// signed approval it verifies the approver's signature over
/// [`approval_statement`] and records the approver identity + signature as
/// independent evidence; a signature that fails to verify is an error.
async fn build_signed_attestation(
    entry: &ApprovalRequest,
    id: &str,
) -> Result<AttestationSet, String> {
    let mut leaf = ChallengeAttestation::of_kind("device-approval");
    leaf.handler_name = Some("device-approval".to_string());
    leaf = leaf.with_evidence("request_id", serde_json::json!(id));

    if let Some(approver) = &entry.approver {
        // Validator-checked (canonical) approvals are already verified upstream
        // — record the evidence without re-verifying. Statement-path approvals
        // (StaticTrustedApprovers / DidApproverAuthorizer) carry the approver's
        // pubkey, so re-verify the statement signature here.
        if !entry.validated {
            use ndn_security::{Ed25519Verifier, Verifier, VerifyOutcome};
            let statement = approval_statement(&entry.cert_name, id);
            let outcome = Ed25519Verifier
                .verify(&statement, &entry.signed_approval, &entry.approver_pubkey)
                .await
                .map_err(|e| format!("approver signature verification errored: {e}"))?;
            if !matches!(outcome, VerifyOutcome::Valid) {
                return Err(format!(
                    "approver {approver} signature over the approval statement is invalid"
                ));
            }
        }
        leaf = leaf.with_evidence("approved_by", serde_json::json!(approver));
        leaf.signature = Some(
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&entry.signed_approval),
        );
    }
    Ok(AttestationSet::single(leaf))
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
    async fn begin_request(challenge: &DeviceApprovalChallenge, name: &str) -> (ChallengeState, String) {
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
        assert!(leaf.signature.is_none(), "in-process flow carries no signature");
        assert!(leaf.evidence.contains_key("request_id"));
        assert!(!leaf.evidence.contains_key("approved_by"));
    }

    #[tokio::test]
    async fn signed_approval_verifies_and_records_signature() {
        use ndn_security::{Ed25519Signer, Signer};
        use ndn_packet::Name;

        let store = PendingApprovalStore::new();
        let challenge = DeviceApprovalChallenge::new(store.clone());
        let (state, id) = begin_request(&challenge, "/lab/alice").await;

        let approver: Name = "/lab/alice/devices/phone".parse().unwrap();
        let signer = Ed25519Signer::from_seed(&[7u8; 32], approver.clone());
        let pubkey = signer.public_key().unwrap().to_vec();
        let sig = signer
            .sign(&approval_statement("/lab/alice", &id))
            .await
            .unwrap();
        assert!(store.approve_signed(&id, approver.to_string(), pubkey, sig.to_vec()));

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
        assert!(leaf.signature.is_some(), "signed flow records the signature");
        assert_eq!(
            leaf.evidence.get("approved_by").unwrap(),
            &serde_json::json!(approver.to_string())
        );
    }

    #[tokio::test]
    async fn forged_signature_is_denied() {
        use ndn_security::{Ed25519Signer, Signer};
        use ndn_packet::Name;

        let store = PendingApprovalStore::new();
        let challenge = DeviceApprovalChallenge::new(store.clone());
        let (state, id) = begin_request(&challenge, "/lab/alice").await;

        let approver: Name = "/lab/alice/devices/phone".parse().unwrap();
        let signer = Ed25519Signer::from_seed(&[7u8; 32], approver.clone());
        let pubkey = signer.public_key().unwrap().to_vec();
        // Sign a DIFFERENT statement than the one the handler reconstructs.
        let wrong = signer
            .sign(&approval_statement("/lab/mallory", &id))
            .await
            .unwrap();
        assert!(store.approve_signed(&id, approver.to_string(), pubkey, wrong.to_vec()));

        let outcome = challenge
            .verify(&state, &serde_json::Map::new())
            .await
            .unwrap();
        match outcome {
            ChallengeOutcome::Denied(reason) => assert!(reason.contains("invalid")),
            other => panic!("expected Denied on signature mismatch, got {other:?}"),
        }
    }
}
