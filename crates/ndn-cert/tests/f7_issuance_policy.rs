//! F7 — registry-pluggable IssuancePolicy at the CA, end-to-end.
//!
//! Drives a full client↔CA flow (NEW → CHALLENGE) with NopChallenge
//! (always passes) and verifies that the CA's `IssuancePolicy` is the
//! decisive gate post-challenge:
//!
//! - With the default `AcceptAllIssuance`, NopChallenge → cert issued.
//!   Regression check that F7 didn't break the pre-existing flow.
//! - With a registry-style policy that denies based on
//!   `challenge_type`, NopChallenge → STATUS_FAILURE returned to the
//!   client even though the challenge phase succeeded. This is the
//!   load-bearing F7 claim — registries can plug in their own
//!   issuance gate without forking ndn-cert.

use std::sync::Arc;
use std::time::Duration;

use ndn_cert::ca::{CaConfig, CaState};
use ndn_cert::challenge::ChallengeHandler;
use ndn_cert::client::EnrollmentSession;
use ndn_cert::{
    AcceptAllIssuance, HierarchicalPolicy, IssuanceContext, IssuanceDecision, IssuancePolicy,
    NopChallenge,
};
use ndn_packet::Name;
use ndn_security::{Ed25519Signer, SecurityManager};

/// Build a CA with a fresh signing identity and the supplied
/// IssuancePolicy. Returns the CA state plus the SecurityManager
/// so the trust anchor it minted can be inspected.
fn make_ca(issuance: Box<dyn IssuancePolicy>) -> (Arc<CaState>, Arc<SecurityManager>, Name) {
    let mgr = Arc::new(SecurityManager::new());
    let ca_key_name: Name = "/registry/CA/KEY/k1/self/v=1".parse().unwrap();
    mgr.generate_ed25519(ca_key_name.clone()).unwrap();
    let ca_pubkey = mgr
        .get_signer_sync(&ca_key_name)
        .unwrap()
        .public_key()
        .unwrap();
    let ca_cert = mgr
        .issue_self_signed(&ca_key_name, ca_pubkey, 365 * 24 * 3600 * 1_000)
        .unwrap();
    mgr.add_trust_anchor(ca_cert);

    let challenges: Vec<Box<dyn ChallengeHandler>> = vec![Box::new(NopChallenge)];
    let config = CaConfig {
        prefix: "/registry/CA".parse().unwrap(),
        info: "F7 test CA".into(),
        default_validity: Duration::from_secs(86_400),
        max_validity: Duration::from_secs(7 * 86_400),
        challenges,
        policy: Box::new(HierarchicalPolicy),
        issuance,
        emit_attestations: false,
    };
    let state = Arc::new(CaState::new(config, Arc::clone(&mgr)));
    (state, mgr, ca_key_name)
}

/// Client-side: build a fresh signer + cert request, run the
/// EnrollmentSession against the CA via in-process method calls.
/// Returns `Ok(session)` if both the NEW and CHALLENGE legs accept,
/// `Err(_)` if the client surfaces the CA's STATUS_FAILURE.
async fn run_enrollment(
    state: Arc<CaState>,
    requested_name: &str,
    challenge_type: &str,
) -> Result<EnrollmentSession, ndn_cert::CertError> {
    let key_name: Name = format!("{requested_name}/KEY/k1").parse().unwrap();
    let seed = [0xCDu8; 32];
    let signer = Arc::new(Ed25519Signer::from_seed(&seed, key_name.clone()));
    let mut session = EnrollmentSession::new(key_name, signer, 86_400);

    // NEW.
    let new_body = session.new_request_body().await.unwrap();
    let new_resp = state.handle_new(&new_body).await.unwrap();
    session.handle_new_response(&new_resp).unwrap();

    // CHALLENGE — NopChallenge accepts an empty parameter map and
    // approves immediately.
    let chal_body = session
        .challenge_request_body(challenge_type, serde_json::Map::new())
        .unwrap();
    let request_id = session.request_id().unwrap().to_string();
    let chal_resp = state
        .handle_challenge(&request_id, &chal_body)
        .await
        .unwrap();
    session.handle_challenge_response(&chal_resp)?;

    Ok(session)
}

#[tokio::test]
async fn f7_default_policy_issues_cert() {
    // Regression: with AcceptAllIssuance (the default), the existing
    // NopChallenge flow still issues a cert.
    let (state, _mgr, _ca_key) = make_ca(Box::new(AcceptAllIssuance));
    let session = run_enrollment(state, "/registry/zone-a/device/x", "nop")
        .await
        .expect("default policy should issue");
    assert!(
        session.is_complete(),
        "AcceptAllIssuance should issue cert after challenge approval"
    );
    assert!(session.issued_cert_name().is_some());
}

/// Registry policy: post-challenge, require challenge_type == "token"
/// (so NopChallenge requests are denied at the issuance gate even
/// though the challenge phase succeeded).
struct RequireTokenPolicy;
impl IssuancePolicy for RequireTokenPolicy {
    fn decide(&self, ctx: &IssuanceContext<'_>) -> IssuanceDecision {
        if ctx.challenge_type == "token" {
            IssuanceDecision::Issue {
                validity: ctx.default_validity,
            }
        } else {
            IssuanceDecision::Deny(format!(
                "registry requires `token` challenge, got `{}`",
                ctx.challenge_type
            ))
        }
    }
}

#[tokio::test]
async fn f7_registry_policy_denies_post_challenge() {
    // Custom policy that rejects any non-token challenge type at the
    // issuance gate. NopChallenge still passes the *challenge* phase,
    // but the issuance hook intercepts and denies — so the client
    // observes a STATUS_FAILURE rather than a successful cert.
    let (state, _mgr, _ca_key) = make_ca(Box::new(RequireTokenPolicy));
    let result = run_enrollment(state, "/registry/zone-a/device/y", "nop").await;
    let err = match result {
        Ok(_) => panic!("registry IssuancePolicy should have denied post-challenge"),
        Err(e) => e,
    };
    let msg = err.to_string();
    assert!(
        msg.contains("registry requires `token`"),
        "deny reason should propagate to client: {msg}"
    );
}
