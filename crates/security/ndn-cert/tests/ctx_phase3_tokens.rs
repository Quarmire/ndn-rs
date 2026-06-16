//! Phase 3 witnesses: enrollment-token TTL, scope, single-use, and the
//! `token AND device-approval` approval gate.
//!
//! Backs `testbed/tests/audit/ctx0{3,4,5,6}_*.sh`. See
//! `.claude/notes/trust-context/trust-context-model-2026-05-25.md` §6.

use std::time::Duration;

use ndn_cert::challenge::combinator::AllOf;
use ndn_cert::challenge::device_approval::{DeviceApprovalChallenge, PendingApprovalStore};
use ndn_cert::protocol::CertRequest;
use ndn_cert::{ChallengeHandler, ChallengeOutcome, TokenChallenge, TokenStore};
use ndn_packet::Name;

fn req(name: &str) -> CertRequest {
    CertRequest {
        name: name.to_owned(),
        public_key: String::new(),
        not_before: 0,
        not_after: 0,
    }
}

fn token_params(t: &str) -> serde_json::Map<String, serde_json::Value> {
    let mut m = serde_json::Map::new();
    m.insert("token".to_string(), serde_json::Value::String(t.to_owned()));
    m
}

async fn verify_token(ch: &TokenChallenge, req_name: &str, token: &str) -> ChallengeOutcome {
    let state = ch.begin(&req(req_name)).await.unwrap();
    ch.verify(&state, &token_params(token)).await.unwrap()
}

fn is_approved(o: &ChallengeOutcome) -> bool {
    matches!(o, ChallengeOutcome::Approved { .. })
}

/// CTX.03 (single-use): a redeemed token re-presented is rejected.
#[tokio::test]
async fn ctx03_redeemed_token_reuse_rejected() {
    let store = TokenStore::new();
    store.add("one-shot");
    let ch = TokenChallenge::new(store);

    let first = verify_token(&ch, "/home/bob/alice", "one-shot").await;
    assert!(is_approved(&first), "first use must be approved");

    let second = verify_token(&ch, "/home/bob/alice", "one-shot").await;
    assert!(
        matches!(second, ChallengeOutcome::Denied(_)),
        "a redeemed token must be inert on reuse"
    );
}

/// CTX.04 (TTL): a token past its TTL is rejected.
#[tokio::test]
async fn ctx04_expired_token_rejected() {
    let store = TokenStore::new();
    // Already expired (zero TTL means expires_at = now; a later check is >).
    store.add_scoped("stale", Some(Duration::from_nanos(0)), None);
    std::thread::sleep(Duration::from_millis(2));
    let ch = TokenChallenge::new(store);

    let outcome = verify_token(&ch, "/home/bob/alice", "stale").await;
    match outcome {
        ChallengeOutcome::Denied(r) => assert!(r.contains("expired"), "got: {r}"),
        other => panic!("expired token must be denied, got {other:?}"),
    }
}

/// CTX.05 (scope): a scoped token cannot mint a cert outside its name scope,
/// but works inside it.
#[tokio::test]
async fn ctx05_scoped_token_enforced() {
    let store = TokenStore::new();
    let scope: Name = "/home/bob/guests".parse().unwrap();
    store.add_scoped("guest-invite", None, Some(scope));
    let ch = TokenChallenge::new(store);

    // Outside scope → denied, and (crucially) the token is NOT consumed.
    let outside = verify_token(&ch, "/home/bob/admin/mallory", "guest-invite").await;
    match outside {
        ChallengeOutcome::Denied(r) => assert!(r.contains("scope"), "got: {r}"),
        other => panic!("out-of-scope must be denied, got {other:?}"),
    }

    // Inside scope → approved.
    let inside = verify_token(&ch, "/home/bob/guests/phone", "guest-invite").await;
    assert!(is_approved(&inside), "in-scope request must be approved");
}

/// Scope is enforced even when the token is a *sub* of a combinator: the
/// combinator threads each sub's `begin` state (which stashes the requested
/// name) across rounds, so an out-of-scope request is denied by the token sub.
#[tokio::test]
async fn ctx05b_scoped_token_under_allof_enforced() {
    use ndn_cert::challenge::combinator::AllOf;
    use ndn_cert::challenge::device_approval::{DeviceApprovalChallenge, PendingApprovalStore};

    let tokens = TokenStore::new();
    let scope: Name = "/home/bob/guests".parse().unwrap();
    tokens.add_scoped("guest-invite", None, Some(scope));
    let approvals = PendingApprovalStore::new();

    let gate = AllOf::new(vec![
        Box::new(TokenChallenge::new(tokens)),
        Box::new(DeviceApprovalChallenge::new(approvals)),
    ]);

    // Out-of-scope request: the token sub (subchallenge 0) must deny, even
    // though it's nested in the combinator.
    let state = gate.begin(&req("/home/bob/admin/mallory")).await.unwrap();
    let mut p0 = token_params("guest-invite");
    p0.insert("subchallenge".into(), serde_json::Value::String("0".into()));
    match gate.verify(&state, &p0).await.unwrap() {
        ChallengeOutcome::Denied(r) => assert!(r.contains("scope"), "got: {r}"),
        other => panic!("out-of-scope token under AllOf must be denied, got {other:?}"),
    }

    // In-scope request: the token sub passes (gate then awaits approval).
    let state = gate.begin(&req("/home/bob/guests/phone")).await.unwrap();
    let mut p0 = token_params("guest-invite");
    p0.insert("subchallenge".into(), serde_json::Value::String("0".into()));
    assert!(
        matches!(
            gate.verify(&state, &p0).await.unwrap(),
            ChallengeOutcome::Pending { .. }
        ),
        "in-scope token under AllOf must pass its sub (gate still pending on approval)"
    );
}

/// CTX.06 (approval gate): `token AND device-approval` blocks issuance until an
/// admin approves — a leaked token alone yields no cert.
#[tokio::test]
async fn ctx06_approval_gate_blocks_without_admin() {
    let tokens = TokenStore::new();
    tokens.add("invite-tok");
    let approvals = PendingApprovalStore::new();

    let gate = AllOf::new(vec![
        Box::new(TokenChallenge::new(tokens)),
        Box::new(DeviceApprovalChallenge::new(approvals.clone())),
    ]);

    let state = gate.begin(&req("/home/bob/newdev")).await.unwrap();

    // Round 1: satisfy the token sub (subchallenge 0). Not enough on its own —
    // the gate stays Pending awaiting device-approval.
    let mut p0 = token_params("invite-tok");
    p0.insert("subchallenge".into(), serde_json::Value::String("0".into()));
    let after_token = gate.verify(&state, &p0).await.unwrap();
    let pending_state = match after_token {
        ChallengeOutcome::Pending { next_state, .. } => next_state,
        other => panic!("token alone must NOT approve; expected Pending, got {other:?}"),
    };

    // Round 2 before any admin action: device-approval is still Pending →
    // a leaked token alone gets nothing.
    let mut p1 = serde_json::Map::new();
    p1.insert("subchallenge".into(), serde_json::Value::String("1".into()));
    let blocked = gate.verify(&pending_state, &p1).await.unwrap();
    assert!(
        matches!(blocked, ChallengeOutcome::Pending { .. }),
        "without admin approval the gate must stay blocked, got {blocked:?}"
    );

    // Admin approves the (single) pending request.
    let pending = approvals.pending();
    assert_eq!(
        pending.len(),
        1,
        "device-approval must have registered a request"
    );
    assert!(approvals.approve(&pending[0].id));

    // Round 2 again: now both subs are satisfied → Approved.
    let approved = gate.verify(&pending_state, &p1).await.unwrap();
    assert!(
        is_approved(&approved),
        "with token + admin approval the gate must approve, got {approved:?}"
    );
}
