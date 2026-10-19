//! The CA side of enrollment by approval resists unauthenticated requesters:
//! an unsigned decision learns nothing about a request, one key name holds
//! one pending request, pending requests are capped, and a request the CA
//! could not save does not spend its one-time invite.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use ndn_cert::approval::{MAX_PENDING, MAX_PENDING_PER_PREFIX, decision_name};
use ndn_cert::roles::Role;
use ndn_cert::{
    ApprovalRecord, ApprovalStore, CaSnapshot, CaStore, CertError, ChallengeHandler,
    ChallengeOutcome, ChallengeState, Decision, DeviceApprovalChallenge, RefusalKind, TokenStore,
};
use ndn_packet::Name;
use ndn_packet::encode::DataBuilder;
use ndn_security::Keyring;

const TTL: Duration = Duration::from_secs(3600);

fn ns() -> Name {
    "/home/bob".parse().unwrap()
}

fn state(key: &str, public_key: &[u8]) -> ChallengeState {
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public_key);
    ChallengeState {
        challenge_type: ndn_cert::approval::DEVICE_APPROVAL.to_string(),
        data: serde_json::json!({ "key": key, "public_key": b64 }),
    }
}

async fn ask(
    ch: &DeviceApprovalChallenge,
    key: &str,
    public_key: &[u8],
    params: serde_json::Map<String, serde_json::Value>,
) -> ChallengeOutcome {
    ch.verify(&state(key, public_key), &params).await.unwrap()
}

/// The request id of a pending outcome; panics otherwise.
fn pending_id(outcome: &ChallengeOutcome) -> String {
    match outcome {
        ChallengeOutcome::Pending { next_state, .. } => {
            next_state.data["request"].as_str().unwrap().to_owned()
        }
        other => panic!("expected a pending request: {other:?}"),
    }
}

fn denied(outcome: ChallengeOutcome) -> String {
    match outcome {
        ChallengeOutcome::Denied(why) => why,
        other => panic!("expected a refusal: {other:?}"),
    }
}

#[tokio::test]
async fn unsigned_decision_reveals_no_code() {
    let store = ApprovalStore::new(ns(), Some(ns()), TTL);
    let ch = DeviceApprovalChallenge::new(store.clone());
    let id = pending_id(&ask(&ch, "/home/bob/node/vps/KEY/k", b"pk", Default::default()).await);
    let record = store.get(&id).unwrap();
    let name = decision_name(&record, &Decision::Approve).unwrap();
    let wire = DataBuilder::new(name, b"not the code").sign_digest_sha256();

    let refusal = store
        .apply_signed(&wire, &Arc::new(Keyring::new()), &[], |_| false)
        .await
        .unwrap_err();
    assert_eq!(refusal.kind, RefusalKind::Unauthorized, "{refusal:?}");
    assert!(!refusal.reason.contains(&record.code), "{}", refusal.reason);
    assert!(store.get(&id).unwrap().is_pending());
}

#[tokio::test]
async fn second_pending_request_for_key_is_refused() {
    let store = ApprovalStore::new(ns(), Some(ns()), TTL);
    let ch = DeviceApprovalChallenge::new(store.clone());
    let key = "/home/bob/node/vps/KEY/k";
    let id = pending_id(&ask(&ch, key, b"victim", Default::default()).await);

    let why = denied(ask(&ch, key, b"attacker", Default::default()).await);
    assert!(why.contains(&id), "{why}");
    assert_eq!(store.pending().len(), 1);
    // The first requester still resumes its own request.
    assert_eq!(
        pending_id(&ask(&ch, key, b"victim", Default::default()).await),
        id
    );
}

#[tokio::test]
async fn pending_requests_are_capped() {
    let store = ApprovalStore::new(ns(), Some(ns()), TTL);
    let ch = DeviceApprovalChallenge::new(store.clone());
    let mut opened = 0;
    let mut group = 0;
    while opened < MAX_PENDING {
        for d in 0..MAX_PENDING_PER_PREFIX.min(MAX_PENDING - opened) {
            let key = format!("/home/bob/g{group}/d{d}/KEY/k");
            pending_id(&ask(&ch, &key, key.as_bytes(), Default::default()).await);
            opened += 1;
        }
        if group == 0 {
            let key = format!("/home/bob/g0/d{MAX_PENDING_PER_PREFIX}/KEY/k");
            denied(ask(&ch, &key, key.as_bytes(), Default::default()).await);
            assert_eq!(store.pending().len(), opened);
        }
        group += 1;
    }
    let key = format!("/home/bob/g{group}/d0/KEY/k");
    denied(ask(&ch, &key, key.as_bytes(), Default::default()).await);
    assert_eq!(store.pending().len(), MAX_PENDING);
}

/// Loads no records and fails every write.
struct FailingStore;

impl CaStore for FailingStore {
    fn load(&self) -> Result<CaSnapshot, CertError> {
        Ok(CaSnapshot::default())
    }
    fn record_issued(&self, _: &str, _: &[u8]) -> Result<(), CertError> {
        Err(CertError::Storage("disk full".into()))
    }
    fn record_revoked(&self, _: &str) -> Result<(), CertError> {
        Err(CertError::Storage("disk full".into()))
    }
    fn approval_records(&self) -> Result<Vec<ApprovalRecord>, CertError> {
        Ok(Vec::new())
    }
}

#[tokio::test]
async fn failed_save_keeps_invite() {
    let tokens = TokenStore::new();
    tokens.add("invite-token").unwrap();
    let mut params = serde_json::Map::new();
    params.insert("token".into(), "invite-token".into());
    let key = "/home/bob/node/vps/KEY/k";

    let failing = ApprovalStore::with_store(ns(), Some(ns()), TTL, Arc::new(FailingStore)).unwrap();
    let ch = DeviceApprovalChallenge::new(failing.clone()).requiring_invite(
        ns(),
        vec![Role::Node],
        tokens.clone(),
    );
    denied(ask(&ch, key, b"pk", params.clone()).await);
    assert!(failing.pending().is_empty());
    assert!(
        tokens.is_live("invite-token"),
        "the failed request spent the invite"
    );

    // Once storage works the same invite opens the request, and only then is spent.
    let working = ApprovalStore::new(ns(), Some(ns()), TTL);
    let ch = DeviceApprovalChallenge::new(working.clone()).requiring_invite(
        ns(),
        vec![Role::Node],
        tokens.clone(),
    );
    let id = pending_id(&ask(&ch, key, b"pk", params).await);
    assert!(working.get(&id).unwrap().invite);
    assert!(!tokens.is_live("invite-token"));
}

/// A PENDING Interest is answered once: replayed (same SignatureNonce and
/// SignatureTime from the same key), or signed outside the grace window,
/// it is refused as unauthorized.
#[tokio::test]
async fn a_replayed_or_stale_pending_interest_is_refused() {
    use ndn_cert::approval::{LISTING_SIG_TIME_GRACE, check_listing_fresh};
    use ndn_packet::Interest;
    use ndn_packet::encode::InterestBuilder;
    use ndn_security::{Ed25519Signer, ReplayGuard, Signer};

    let key: Name = "/home/bob/admin/laptop/KEY/k".parse().unwrap();
    let signer: Arc<dyn Signer> = Arc::new(Ed25519Signer::from_seed(&[3; 32], key.clone()));
    let sign = Arc::clone(&signer);
    let wire = InterestBuilder::new("/home/bob/CA/PENDING".parse::<Name>().unwrap())
        .must_be_fresh()
        .app_parameters(Vec::new())
        .sign_fallible(signer.sig_type(), Some(&key), |region| {
            let region = region.to_vec();
            async move { sign.sign(&region).await }
        })
        .await
        .unwrap();
    let interest = Interest::decode(wire).unwrap();
    let signed_at = interest.sig_info().unwrap().sig_time.unwrap();

    let seen = ReplayGuard::new(64, false);
    assert!(check_listing_fresh(&interest, &seen, signed_at).is_ok());
    let replayed = check_listing_fresh(&interest, &seen, signed_at + 1_000).unwrap_err();
    assert_eq!(replayed.kind, RefusalKind::Unauthorized);
    // Past the window it is refused even by a CA that never saw it (one
    // that restarted since).
    let late = signed_at + LISTING_SIG_TIME_GRACE.as_millis() as u64 + 1;
    let stale = check_listing_fresh(&interest, &ReplayGuard::new(64, false), late).unwrap_err();
    assert_eq!(stale.kind, RefusalKind::Unauthorized);
}
