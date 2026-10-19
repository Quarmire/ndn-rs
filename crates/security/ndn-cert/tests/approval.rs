//! Enrollment by an admin's approval on a namespace CA (`/home/bob`): a
//! pending request survives restarts of either side, only a current admin
//! key decides remotely, the approver is recorded and attested, the
//! requester learns a denial or an expiry — at once through its held
//! status Interest, and only from the CA — an expired request is neither
//! listed nor decided and the CA prunes it, and both screens show one code.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use ndn_cert::approval::{
    DEFAULT_REQUEST_TTL, MAX_HELD_PER_REQUEST, MAX_HELD_STATUS, STATUS_ANSWER_MARGIN,
    STATUS_LIFETIME,
};
use ndn_cert::ca::{CaConfig, CaState};
use ndn_cert::challenge::ChallengeHandler;
use ndn_cert::{
    ApprovalEnrollError, ApprovalPoll, ApprovalRecord, ApprovalService, ApprovalState,
    ApprovalStore, Approver, ApproverError, AttestationSet, CaExchange, CaStore, CertError,
    Decision, DeviceApprovalChallenge, FileCaStore, HierarchicalPolicy, IssuedCertificate,
    NewRootStore, RefusalKind, RequestStatus, RolePolicy, adopt_with_tofu, anchor_fingerprint,
    ca_key_name, fetch_pending, init_namespace_in_pib, new_device_key_name, poll_approval,
    push_decision, request_status, verification_code,
};
use ndn_cert::{
    ApprovalPolicy, BumpError, RootStore, bump_context_schema, namespace_schema,
    open_context_update, read_stored_context,
};
use ndn_packet::encode::DataBuilder;
use ndn_packet::{Data, Interest, Name};
use ndn_security::{
    AdvertisedRelay, Ed25519Signer, FilePib, Keyring, LinkPolicy, SecurityManager, Signer,
};
use ndn_security::{
    Certificate, EnrollmentHint, SchemaBlob, ValidationResult, Validator, compile_lvs_to_binary,
};

fn ns() -> Name {
    "/home/bob".parse().unwrap()
}

/// Routes Interests straight into a `CaState` and its approval service.
/// `<ns>/CA/APPROVAL`, `<ns>/CA/PENDING` and `<ns>/CA/STATUS/<id>` answers
/// are signed by the CA key, as the clients require; a status Interest is
/// held as the CA's producer holds it.
#[derive(Clone)]
struct CaWire {
    ca: Arc<CaState>,
    approvals: ApprovalStore,
    service: ApprovalService,
}

impl CaWire {
    async fn ca_signed(&self, name: Name, body: &[u8]) -> Result<Data, CertError> {
        let (signer, cert) = self
            .ca
            .response_signer()
            .ok_or_else(|| CertError::Transport("the CA has no signing key".into()))?;
        let wire = DataBuilder::new(name, body)
            .sign_fallible(signer.sig_type(), Some(&cert), |region| {
                let region = region.to_vec();
                async move { signer.sign(&region).await }
            })
            .await
            .map_err(CertError::Security)?;
        Data::decode(wire).map_err(|e| CertError::Transport(format!("{e:?}")))
    }
}

impl CaExchange for CaWire {
    async fn express(&mut self, interest_wire: Bytes) -> Result<Data, CertError> {
        let proto = CertError::Transport;
        let interest =
            Interest::decode(interest_wire).map_err(|e| proto(format!("decode: {e:?}")))?;
        let comps = interest.name.components();
        let verb = |v: &[u8]| comps.iter().position(|c| c.value.as_ref() == v);
        let params = || interest.app_parameters().cloned().unwrap_or_default();
        let name = interest.name.as_ref().clone();
        let body = if verb(b"APPROVAL").is_some() {
            let body = self.service.handle_decision(&params()).await;
            return self.ca_signed(name, &body).await;
        } else if verb(b"PENDING").is_some() {
            let body = self.service.handle_listing(&interest).await;
            return self.ca_signed(name, &body).await;
        } else if verb(b"STATUS").is_some() {
            let request_id = ndn_cert::approval::status_request_id(&ns(), &name)
                .ok_or_else(|| proto(format!("not a status name: {name}")))?;
            let held = self.service.hold_status(&request_id).map_err(proto)?;
            let hold = ndn_cert::approval::status_hold(interest.lifetime());
            let body = self.service.answer_status(&held, hold).await;
            return self.ca_signed(name, &body).await;
        } else if verb(b"NEW").is_some() {
            self.ca.handle_new(&params()).await?
        } else if let Some(i) = verb(b"CHALLENGE") {
            let rid: String = comps[i + 1]
                .value
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            self.ca.handle_challenge(&rid, &params()).await?
        } else {
            let wire = self
                .ca
                .cert_for_interest(&interest.name, interest.selectors().can_be_prefix)
                .ok_or_else(|| proto(format!("no served cert {}", interest.name)))?;
            return Data::decode(Bytes::from(wire)).map_err(|e| proto(format!("{e:?}")));
        };
        let reply = DataBuilder::new(name, &body).sign_digest_sha256();
        Data::decode(reply).map_err(|e| proto(format!("{e:?}")))
    }
}

/// The root device of `/home/bob`, initialized into its PIB as `ndn-fwd init`
/// does (the context names the CA `/home/bob/CA`): the CA key and certificate,
/// the CA's on-disk store, and a keyring that adopted the namespace's context
/// (shared by the CA host, requesters and admin devices here).
struct RootDevice {
    mgr: Arc<SecurityManager>,
    keyring: Arc<Keyring>,
    dir: tempfile::TempDir,
}

impl RootDevice {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let pib = FilePib::new(dir.path()).unwrap();
        let out = init_namespace_in_pib(&pib, &ns(), "desk", false, &NewRootStore::File)
            .await
            .unwrap();
        let mgr = SecurityManager::new();
        mgr.register_signer(out.ca_key.clone(), pib.get_signer(&out.ca_key).unwrap());
        mgr.cert_cache().insert(out.ca_cert.clone());
        let context = Data::decode(out.init.context_data.raw().clone()).unwrap();
        let keyring = Arc::new(Keyring::new());
        adopt_with_tofu(
            &keyring,
            &context,
            &ns(),
            &anchor_fingerprint(&out.init.anchor),
        )
        .unwrap();
        Self {
            mgr: Arc::new(mgr),
            keyring,
            dir,
        }
    }

    /// (Re)start the namespace CA from its store: role issuance, attestations
    /// in issued certificates, the `device-approval` challenge with request
    /// TTL `ttl`, and the APPROVAL / PENDING endpoints.
    fn start_ca(&self, ttl: Duration) -> CaWire {
        let store = Arc::new(FileCaStore::open(self.dir.path().join("ca")).unwrap());
        let approvals = ApprovalStore::with_store(ns(), Some(ns()), ttl, store.clone()).unwrap();
        let challenges: Vec<Box<dyn ChallengeHandler>> =
            vec![Box::new(DeviceApprovalChallenge::new(approvals.clone()))];
        let mut config = CaConfig::new(
            ns(),
            "namespace CA".to_string(),
            Duration::from_secs(90 * 86_400),
            Duration::from_secs(90 * 86_400),
            challenges,
            Box::new(HierarchicalPolicy),
        )
        .with_signing_key(ca_key_name(&ns()))
        .emit_attestations(true);
        config.issuance = Box::new(RolePolicy::new(ns()));
        let ca = Arc::new(CaState::with_store(config, Arc::clone(&self.mgr), store).unwrap());
        CaWire {
            service: ApprovalService::new(
                approvals.clone(),
                Arc::clone(&self.keyring),
                Arc::clone(&ca),
            ),
            ca,
            approvals,
        }
    }
}

/// A fresh key (`seed`) for `/home/bob/<role>/<device>`.
fn key(role: &str, device: &str, seed: u8) -> Arc<dyn Signer> {
    let identity = ns().append(role).append(device);
    Arc::new(Ed25519Signer::from_seed(
        &[seed; 32],
        new_device_key_name(&identity).unwrap(),
    ))
}

/// One requester poll (a fresh NEW → CHALLENGE exchange).
async fn poll(
    rd: &RootDevice,
    ca: &CaWire,
    key: &Arc<dyn Signer>,
    resume: Option<&str>,
) -> Result<ApprovalPoll, ApprovalEnrollError> {
    poll_approval(
        &mut ca.clone(),
        &rd.keyring,
        &ns(),
        &ns(),
        Arc::clone(key),
        resume,
        None,
    )
    .await
}

/// Open a request for `key`; its request id and the code the requester shows.
async fn request(rd: &RootDevice, ca: &CaWire, key: &Arc<dyn Signer>) -> (String, String) {
    match poll(rd, ca, key, None).await {
        Ok(ApprovalPoll::Pending(p)) => (p.request_id, p.code),
        other => panic!(
            "expected a pending request for {}: {other:?}",
            key.key_name()
        ),
    }
}

async fn issued(
    rd: &RootDevice,
    ca: &CaWire,
    key: &Arc<dyn Signer>,
    id: &str,
) -> IssuedCertificate {
    match poll(rd, ca, key, Some(id)).await {
        Ok(ApprovalPoll::Issued(issued)) => issued,
        other => panic!("expected request {id} issued: {other:?}"),
    }
}

/// A device key and its certificate chain (certificate first).
struct Device {
    key: Arc<dyn Signer>,
    chain: Vec<Bytes>,
}

/// A device certified by the CA, approved by its local operator.
async fn device(rd: &RootDevice, ca: &CaWire, role: &str, name: &str, seed: u8) -> Device {
    let key = key(role, name, seed);
    let (id, _) = request(rd, ca, &key).await;
    ca.approvals
        .decide_locally(&id, Decision::Approve, "uid 0 (setup)")
        .unwrap();
    let cert = issued(rd, ca, &key, &id).await;
    Device {
        key,
        chain: vec![cert.data.raw().clone()],
    }
}

async fn push(
    rd: &RootDevice,
    ca: &CaWire,
    record: &ApprovalRecord,
    decision: &Decision,
    by: &Device,
) -> Result<ApprovalRecord, ApproverError> {
    push_decision(
        &mut ca.clone(),
        &rd.keyring,
        &ns(),
        record,
        decision,
        &by.key,
        &by.chain,
    )
    .await
}

async fn listing(
    rd: &RootDevice,
    ca: &CaWire,
    by: &Device,
) -> Result<Vec<ApprovalRecord>, ApproverError> {
    fetch_pending(
        &mut ca.clone(),
        &rd.keyring,
        &ns(),
        &ns(),
        &by.key,
        &by.chain,
    )
    .await
}

#[track_caller]
fn assert_refused<T: std::fmt::Debug>(result: Result<T, ApproverError>, kind: RefusalKind) {
    match result {
        Err(ApproverError::Refused(refusal)) => assert_eq!(refusal.kind, kind, "{refusal:?}"),
        other => panic!("expected a {kind:?} refusal: {other:?}"),
    }
}

/// A pending request lives in the CA's store and the requester needs only
/// its request id: after both restart, an admin's remote approval lets the
/// requester's next poll fetch a certificate for its key, chained to the root.
#[tokio::test]
async fn a_pending_request_survives_restarts_of_the_ca_and_the_requester() {
    let rd = RootDevice::new().await;
    let ca = rd.start_ca(DEFAULT_REQUEST_TTL);
    let admin = device(&rd, &ca, "admin", "laptop", 1).await;
    let requester = key("node", "vps", 2);
    let (request_id, _) = request(&rd, &ca, &requester).await;
    drop(ca);

    let ca = rd.start_ca(DEFAULT_REQUEST_TTL);
    let pending = listing(&rd, &ca, &admin).await.unwrap();
    let record = pending
        .iter()
        .find(|r| r.request_id == request_id)
        .expect("the request is still pending after the CA restarted");
    push(&rd, &ca, record, &Decision::Approve, &admin)
        .await
        .unwrap();

    let cert = issued(&rd, &ca, &requester, &request_id).await;
    assert!(
        cert.cert.name.has_prefix(requester.key_name()),
        "{}",
        cert.cert.name
    );
    assert!(
        cert.issuers
            .iter()
            .any(|d| d.name.has_prefix(&ca_key_name(&ns()))),
        "the chain walk went through the CA certificate to the root"
    );
}

/// Only a current admin key decides remotely: member and node keys, a key
/// without a certificate, a bad signature and a revoked admin are refused;
/// so is a decision naming another request or key, or carrying a wrong
/// code. None of them changes the request.
#[tokio::test]
async fn only_a_current_admin_key_decides_a_request_remotely() {
    let rd = RootDevice::new().await;
    let ca = rd.start_ca(DEFAULT_REQUEST_TTL);
    let admin = device(&rd, &ca, "admin", "laptop", 1).await;
    let member = device(&rd, &ca, "member", "phone", 2).await;
    let node = device(&rd, &ca, "node", "vps", 3).await;
    let revoked = device(&rd, &ca, "admin", "old", 4).await;
    assert!(
        !ca.ca
            .revoke_issued_under(&ns().append("admin").append("old"))
            .revoked
            .is_empty()
    );
    let uncertified = Device {
        key: key("admin", "evil", 5),
        chain: Vec::new(),
    };
    let forged = Device {
        key: Arc::new(Ed25519Signer::from_seed(
            &[6; 32],
            admin.key.key_name().clone(),
        )),
        chain: admin.chain.clone(),
    };

    let (id, _) = request(&rd, &ca, &key("node", "pi", 7)).await;
    let (other_id, _) = request(&rd, &ca, &key("admin", "tablet", 8)).await;
    let record = ca.approvals.get(&id).unwrap();
    let other = ca.approvals.get(&other_id).unwrap();
    let still_pending = || assert!(ca.approvals.get(&id).unwrap().is_pending());

    for by in [&member, &node, &uncertified, &forged, &revoked] {
        assert_refused(
            push(&rd, &ca, &record, &Decision::Approve, by).await,
            RefusalKind::Unauthorized,
        );
        still_pending();
    }

    let other_request = ApprovalRecord {
        request_id: other.request_id.clone(),
        ..record.clone()
    };
    let other_key = ApprovalRecord {
        key_name: other.key_name.clone(),
        ..record.clone()
    };
    let unknown = ApprovalRecord {
        request_id: "00000000000000ff".into(),
        ..record.clone()
    };
    let wrong_code = ApprovalRecord {
        code: if record.code == "000 000" {
            "111 111"
        } else {
            "000 000"
        }
        .into(),
        ..record.clone()
    };
    for (mismatched, kind) in [
        (other_request, RefusalKind::BadRequest),
        (other_key, RefusalKind::BadRequest),
        (unknown, RefusalKind::NotFound),
        (wrong_code, RefusalKind::BadRequest),
    ] {
        assert_refused(
            push(&rd, &ca, &mismatched, &Decision::Approve, &admin).await,
            kind,
        );
        still_pending();
        assert!(ca.approvals.get(&other_id).unwrap().is_pending());
    }

    let decided = push(&rd, &ca, &record, &Decision::Approve, &admin)
        .await
        .unwrap();
    assert!(matches!(decided.state, ApprovalState::Approved { .. }));
}

/// The approver is recorded and attested in the issued certificate: a local
/// operator by who they are and no signature (none exists); an admin key by
/// its signed decision.
#[tokio::test]
async fn the_issued_certificate_attests_who_approved_it() {
    let rd = RootDevice::new().await;
    let ca = rd.start_ca(DEFAULT_REQUEST_TTL);
    let leaf = |cert: &IssuedCertificate| {
        let set = AttestationSet::from_cert(&cert.cert).expect("an attestation");
        assert_eq!(set.leaves.len(), 1, "{set:?}");
        set.leaves[0].clone()
    };
    let evidence = |leaf: &ndn_cert::ChallengeAttestation, k: &str| {
        leaf.evidence
            .get(k)
            .and_then(|v| v.as_str())
            .map(str::to_owned)
    };

    let local = key("admin", "laptop", 1);
    let (id, _) = request(&rd, &ca, &local).await;
    let record = ca
        .approvals
        .decide_locally(&id, Decision::Approve, "uid 1000 (alice)")
        .unwrap();
    let who = Approver::LocalOperator {
        who: "uid 1000 (alice)".into(),
    };
    assert!(matches!(&record.state, ApprovalState::Approved { by, .. } if *by == who));
    let cert = issued(&rd, &ca, &local, &id).await;
    let operator = leaf(&cert);
    assert_eq!(
        evidence(&operator, "approver_kind").as_deref(),
        Some("local-operator")
    );
    assert_eq!(
        evidence(&operator, "approved_by").as_deref(),
        Some("uid 1000 (alice)")
    );
    assert_eq!(operator.signature, None);

    let admin = Device {
        key: local,
        chain: vec![cert.data.raw().clone()],
    };
    let remote = key("node", "vps", 2);
    let (id, _) = request(&rd, &ca, &remote).await;
    let record = push(
        &rd,
        &ca,
        &ca.approvals.get(&id).unwrap(),
        &Decision::Approve,
        &admin,
    )
    .await
    .unwrap();
    let ApprovalState::Approved {
        by: Approver::AdminKey {
            key,
            evidence: signed,
        },
        ..
    } = record.state
    else {
        panic!("{record:?}");
    };
    let attested = leaf(&issued(&rd, &ca, &remote, &id).await);
    assert_eq!(
        evidence(&attested, "approver_kind").as_deref(),
        Some("admin-key")
    );
    assert_eq!(evidence(&attested, "approved_by"), Some(key));
    assert_eq!(attested.signature, Some(signed));
}

/// The requester learns a denial (reason and approver), an expired request,
/// and a request the CA never had — each final, saying to ask again.
#[tokio::test]
async fn the_requester_learns_a_denial_or_an_expiry() {
    let rd = RootDevice::new().await;
    let ca = rd.start_ca(DEFAULT_REQUEST_TTL);
    let admin = device(&rd, &ca, "admin", "laptop", 1).await;
    let requester = key("node", "vps", 2);
    let (id, _) = request(&rd, &ca, &requester).await;
    let deny = Decision::Deny {
        reason: "not one of my devices".into(),
    };
    push(&rd, &ca, &ca.approvals.get(&id).unwrap(), &deny, &admin)
        .await
        .unwrap();
    match poll(&rd, &ca, &requester, Some(&id)).await {
        Err(ApprovalEnrollError::Denied(why)) => {
            assert!(why.contains("not one of my devices"), "{why}");
            assert!(why.contains(&admin.key.key_name().to_string()), "{why}");
        }
        other => panic!("expected denied: {other:?}"),
    }

    let never = poll(&rd, &ca, &key("node", "pi", 3), Some("00000000000000ff")).await;
    assert!(
        matches!(&never, Err(ApprovalEnrollError::Expired(why)) if why.contains("ask again")),
        "{never:?}"
    );

    let short = RootDevice::new().await;
    let ca = short.start_ca(Duration::from_secs(1));
    let requester = key("node", "vps", 4);
    let (id, _) = request(&short, &ca, &requester).await;
    tokio::time::sleep(Duration::from_millis(2_100)).await;
    let expired = poll(&short, &ca, &requester, Some(&id)).await;
    assert!(
        matches!(&expired, Err(ApprovalEnrollError::Expired(why)) if why.contains("ask again")),
        "{expired:?}"
    );
}

/// One status Interest of `lifetime` for request `id` of `key`.
async fn status(
    rd: &RootDevice,
    ca: &CaWire,
    id: &str,
    key: &Arc<dyn Signer>,
    lifetime: Duration,
) -> Result<RequestStatus, ApprovalEnrollError> {
    let key_name = key.key_name().to_string();
    request_status(
        &mut ca.clone(),
        &rd.keyring,
        &ns(),
        &ns(),
        id,
        &key_name,
        lifetime,
    )
    .await
}

/// A status Interest held for a pending request is answered the moment an
/// admin's decision is recorded — not when its lifetime ends — with the
/// CA-signed state (a denial with its reason and who denied); a decided,
/// expired or unknown request is answered at once, and so is a status
/// Interest living no longer than the CA's answer margin.
#[tokio::test]
async fn a_held_status_is_answered_when_the_decision_is_recorded() {
    let rd = Arc::new(RootDevice::new().await);
    let ca = rd.start_ca(DEFAULT_REQUEST_TTL);
    let at_once = Duration::from_secs(1);
    let waiting = |id: &str, key: &Arc<dyn Signer>| {
        let (rd, ca, id, key) = (Arc::clone(&rd), ca.clone(), id.to_owned(), Arc::clone(key));
        tokio::spawn(async move { status(&rd, &ca, &id, &key, STATUS_LIFETIME).await })
    };

    let denied = key("node", "vps", 1);
    let (id, _) = request(&rd, &ca, &denied).await;
    let now = tokio::time::timeout(
        at_once,
        status(&rd, &ca, &id, &denied, STATUS_ANSWER_MARGIN),
    )
    .await
    .expect("a check-now status is answered at once");
    assert!(matches!(now, Ok(RequestStatus::Pending { .. })), "{now:?}");

    let held = waiting(&id, &denied);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!held.is_finished(), "held while the request is pending");
    ca.approvals
        .decide_locally(
            &id,
            Decision::Deny {
                reason: "not my relay".into(),
            },
            "uid 1000 (alice)",
        )
        .unwrap();
    let answer = tokio::time::timeout(at_once, held)
        .await
        .expect("answered when the decision is recorded")
        .unwrap();
    match answer {
        Ok(RequestStatus::Denied { reason, .. }) => {
            assert!(reason.contains("not my relay"), "{reason}");
            assert!(reason.contains("uid 1000 (alice)"), "{reason}");
        }
        other => panic!("expected denied: {other:?}"),
    }
    let again = tokio::time::timeout(at_once, status(&rd, &ca, &id, &denied, STATUS_LIFETIME))
        .await
        .expect("a decided request is answered at once");
    assert!(
        matches!(again, Ok(RequestStatus::Denied { .. })),
        "{again:?}"
    );

    let approved = key("admin", "tablet", 2);
    let (id, _) = request(&rd, &ca, &approved).await;
    let held = waiting(&id, &approved);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!held.is_finished(), "held while the request is pending");
    ca.approvals
        .decide_locally(&id, Decision::Approve, "uid 1000 (alice)")
        .unwrap();
    let answer = tokio::time::timeout(at_once, held)
        .await
        .expect("answered when the decision is recorded")
        .unwrap();
    assert!(
        matches!(answer, Ok(RequestStatus::Approved { .. })),
        "{answer:?}"
    );
    issued(&rd, &ca, &approved, &id).await;

    let unknown = tokio::time::timeout(
        at_once,
        status(
            &rd,
            &ca,
            "00000000000000ff",
            &key("node", "pi", 3),
            STATUS_LIFETIME,
        ),
    )
    .await
    .expect("an unknown request is answered at once");
    assert!(
        matches!(&unknown, Ok(RequestStatus::Expired { reason, .. }) if reason.contains("ask again")),
        "{unknown:?}"
    );

    let short = Arc::new(RootDevice::new().await);
    let ca = short.start_ca(Duration::from_secs(1));
    let expiring = key("node", "vps", 4);
    let (id, _) = request(&short, &ca, &expiring).await;
    let answer = tokio::time::timeout(
        Duration::from_secs(4),
        status(&short, &ca, &id, &expiring, STATUS_LIFETIME),
    )
    .await
    .expect("answered when the request expires undecided");
    assert!(
        matches!(&answer, Ok(RequestStatus::Expired { reason, .. }) if reason.contains("ask again")),
        "{answer:?}"
    );
}

/// The CA holds a bounded number of status Interests: per request and in
/// all; one more is refused saying why, and a slot given back is usable
/// again.
#[tokio::test]
async fn the_ca_holds_a_bounded_number_of_status_interests() {
    let rd = RootDevice::new().await;
    let ca = rd.start_ca(DEFAULT_REQUEST_TTL);
    let per_request: Vec<_> = (0..MAX_HELD_PER_REQUEST)
        .map(|_| ca.service.hold_status("a").unwrap())
        .collect();
    let refused = ca.service.hold_status("a").map(drop).unwrap_err();
    assert!(refused.contains("limit per request"), "{refused}");
    drop(per_request);
    let mut all: Vec<_> = (0..MAX_HELD_STATUS)
        .map(|i| {
            ca.service
                .hold_status(&format!("{:016x}", i / MAX_HELD_PER_REQUEST))
                .unwrap()
        })
        .collect();
    let refused = ca.service.hold_status("b").map(drop).unwrap_err();
    assert!(refused.contains("its limit"), "{refused}");
    all.pop();
    ca.service
        .hold_status("b")
        .expect("a slot given back is usable again");
}

/// A CA that stops answers the status Interests it holds at once (pending,
/// CA-signed), and any arriving after, so devices ask the restarted CA
/// instead of waiting out their Interests; it returns once all are out.
#[tokio::test]
async fn a_stopping_ca_answers_the_status_it_holds() {
    let rd = Arc::new(RootDevice::new().await);
    let ca = rd.start_ca(DEFAULT_REQUEST_TTL);
    let requester = key("node", "vps", 1);
    let (id, _) = request(&rd, &ca, &requester).await;
    let held = {
        let (rd, ca, id, key) = (
            Arc::clone(&rd),
            ca.clone(),
            id.clone(),
            Arc::clone(&requester),
        );
        tokio::spawn(async move { status(&rd, &ca, &id, &key, STATUS_LIFETIME).await })
    };
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!held.is_finished(), "held while the request is pending");
    tokio::time::timeout(
        Duration::from_secs(1),
        ca.service.release_held(Duration::from_secs(1)),
    )
    .await
    .expect("released at once");
    let answer = held.await.unwrap();
    assert!(
        matches!(answer, Ok(RequestStatus::Pending { .. })),
        "{answer:?}"
    );
    let later = tokio::time::timeout(
        Duration::from_secs(1),
        status(&rd, &ca, &id, &requester, STATUS_LIFETIME),
    )
    .await
    .expect("a stopping CA holds nothing");
    assert!(
        matches!(later, Ok(RequestStatus::Pending { .. })),
        "{later:?}"
    );
}

/// Answers to a status Interest, as a neighbour may forge them; anything
/// else goes to the CA.
struct Forger {
    ca: CaWire,
    /// The forged Data's wire.
    forged: Bytes,
}

impl CaExchange for Forger {
    async fn express(&mut self, interest_wire: Bytes) -> Result<Data, CertError> {
        let interest = Interest::decode(interest_wire.clone()).unwrap();
        if interest
            .name
            .components()
            .iter()
            .any(|c| c.value.as_ref() == b"STATUS")
        {
            return Ok(Data::decode(self.forged.clone()).unwrap());
        }
        self.ca.express(interest_wire).await
    }
}

/// A requester acts on a denial only if the CA signed it about its request
/// and key: an unsigned denial, one signed by an admin key of the namespace
/// (only the CA key signs `<ca>/CA/…`), and CA-signed answers about another
/// key or another request are untrusted — not final, so nothing is done —
/// and the request stays pending at the CA.
#[tokio::test]
async fn a_forged_or_unsigned_denial_is_not_acted_on() {
    let rd = RootDevice::new().await;
    let ca = rd.start_ca(DEFAULT_REQUEST_TTL);
    let admin = device(&rd, &ca, "admin", "laptop", 1).await;
    let requester = key("node", "vps", 2);
    let (id, _) = request(&rd, &ca, &requester).await;
    let name = ndn_cert::approval::status_name(&ns(), &id);
    let denial = |request_id: &str, key_name: &str| {
        serde_json::to_vec(&RequestStatus::Denied {
            request_id: request_id.into(),
            key_name: key_name.into(),
            reason: "forged".into(),
        })
        .unwrap()
    };
    let mine = denial(&id, &requester.key_name().to_string());

    let unsigned = DataBuilder::new(name.clone(), &mine).sign_digest_sha256();
    let by_admin = {
        let signer = Arc::clone(&admin.key);
        DataBuilder::new(name.clone(), &mine)
            .sign_fallible(signer.sig_type(), Some(admin.key.key_name()), |region| {
                let region = region.to_vec();
                async move { signer.sign(&region).await }
            })
            .await
            .unwrap()
    };
    let other_key = ca
        .ca_signed(name.clone(), &denial(&id, "/home/bob/node/pi/KEY/k"))
        .await
        .unwrap()
        .raw()
        .clone();
    let other_request = ca
        .ca_signed(
            name.clone(),
            &denial("00000000000000ff", &requester.key_name().to_string()),
        )
        .await
        .unwrap()
        .raw()
        .clone();

    for (what, forged) in [
        ("unsigned", unsigned),
        ("signed by an admin key", by_admin),
        ("about another key", other_key),
        ("about another request", other_request),
    ] {
        let answer = request_status(
            &mut Forger {
                ca: ca.clone(),
                forged,
            },
            &rd.keyring,
            &ns(),
            &ns(),
            &id,
            &requester.key_name().to_string(),
            STATUS_LIFETIME,
        )
        .await;
        match &answer {
            Err(e @ ApprovalEnrollError::UntrustedAnswer(_)) => assert!(!e.is_final(), "{what}"),
            other => panic!("a denial {what} must be untrusted: {other:?}"),
        }
        assert!(ca.approvals.get(&id).unwrap().is_pending(), "{what}");
    }
}

/// The CA's clock passes a request's expiry: the request leaves the pending
/// list an admin fetches and cannot be decided (by code locally, by a signed
/// approval remotely); the requester's next poll is told it expired, and the
/// CA forgets it. One TTL after its expiry the CA prunes a request nobody
/// asked about from its store, as it does a decision past its keep time.
/// The records are aged as the CA keeps them, durably in its store, and
/// read by a restarted CA.
#[tokio::test]
async fn an_expired_request_is_neither_listed_nor_decided_and_is_pruned() {
    let rd = RootDevice::new().await;
    let ca = rd.start_ca(DEFAULT_REQUEST_TTL);
    let admin = device(&rd, &ca, "admin", "laptop", 1).await;
    let late = key("node", "vps", 2);
    let (late_id, late_code) = request(&rd, &ca, &late).await;
    let stale = key("node", "pi", 3);
    let (stale_id, _) = request(&rd, &ca, &stale).await;
    let denied = key("member", "tv", 4);
    let (denied_id, _) = request(&rd, &ca, &denied).await;
    let deny = Decision::Deny {
        reason: "not mine".into(),
    };
    ca.approvals
        .decide_locally(&denied_id, deny, "uid 0 (setup)")
        .unwrap();
    let current = key("node", "nas", 5);
    let (current_id, _) = request(&rd, &ca, &current).await;
    let approved_late = ca.approvals.get(&late_id).unwrap();
    drop(ca);

    let store = FileCaStore::open(rd.dir.path().join("ca")).unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let ttl = DEFAULT_REQUEST_TTL.as_secs();
    for (id, expires) in [
        (&late_id, now - 60),
        (&stale_id, now - ttl - 60),
        (&denied_id, now - 60),
    ] {
        let mut record = store
            .approval_records()
            .unwrap()
            .into_iter()
            .find(|r| &r.request_id == id)
            .unwrap();
        record.expires_secs = expires;
        store.record_approval(&record).unwrap();
    }
    let stored = || -> Vec<String> {
        store
            .approval_records()
            .unwrap()
            .into_iter()
            .map(|r| r.request_id)
            .collect()
    };

    let ca = rd.start_ca(DEFAULT_REQUEST_TTL);
    let kept = stored();
    assert!(
        !kept.contains(&stale_id),
        "pending one TTL past its expiry: pruned"
    );
    assert!(
        !kept.contains(&denied_id),
        "a decision past its keep time: pruned"
    );
    assert!(
        kept.contains(&late_id),
        "kept to tell the requester it expired"
    );
    assert!(kept.contains(&current_id));

    let listed = listing(&rd, &ca, &admin).await.unwrap();
    assert!(listed.iter().all(|r| r.request_id != late_id), "{listed:?}");
    assert!(
        listed.iter().any(|r| r.request_id == current_id),
        "{listed:?}"
    );
    let local = ca
        .approvals
        .decide_locally(&late_code, Decision::Approve, "uid 0 (setup)")
        .unwrap_err();
    assert_eq!(local.kind, RefusalKind::NotFound, "{local:?}");
    assert_refused(
        push(&rd, &ca, &approved_late, &Decision::Approve, &admin).await,
        RefusalKind::Conflict,
    );
    assert!(
        ca.approvals.get(&late_id).unwrap().is_pending(),
        "nothing changed"
    );

    let expired = poll(&rd, &ca, &late, Some(&late_id)).await;
    assert!(
        matches!(&expired, Err(ApprovalEnrollError::Expired(why)) if why.contains("ask again")),
        "{expired:?}"
    );
    assert!(!stored().contains(&late_id), "told once, then forgotten");
    let pruned = poll(&rd, &ca, &stale, Some(&stale_id)).await;
    assert!(
        matches!(&pruned, Err(ApprovalEnrollError::Expired(why)) if why.contains("ask again")),
        "{pruned:?}"
    );
}

/// The code the requester computes from its own key equals the CA's code
/// for that request; another key or another request id gives another code.
#[tokio::test]
async fn both_screens_show_one_code_bound_to_the_key_and_request() {
    let rd = RootDevice::new().await;
    let ca = rd.start_ca(DEFAULT_REQUEST_TTL);
    let admin = device(&rd, &ca, "admin", "laptop", 1).await;
    let requester = key("node", "vps", 2);
    let (id, code) = request(&rd, &ca, &requester).await;
    let listed = listing(&rd, &ca, &admin).await.unwrap();
    let record = listed.iter().find(|r| r.request_id == id).unwrap();
    assert_eq!(record.code, code);

    let pk = requester.public_key().unwrap();
    let other_pk = key("node", "vps", 3).public_key().unwrap();
    assert_eq!(verification_code(&ns(), &pk, &id), code);
    assert_ne!(verification_code(&ns(), &other_pk, &id), code);
    assert_ne!(verification_code(&ns(), &pk, "00000000000000ff"), code);
}

/// The pending list is answered to a current admin key only, with each
/// request's role, device and code.
#[tokio::test]
async fn only_an_admin_key_lists_pending_requests() {
    let rd = RootDevice::new().await;
    let ca = rd.start_ca(DEFAULT_REQUEST_TTL);
    let admin = device(&rd, &ca, "admin", "laptop", 1).await;
    let member = device(&rd, &ca, "member", "phone", 2).await;
    let (id, code) = request(&rd, &ca, &key("node", "vps", 3)).await;

    assert_refused(listing(&rd, &ca, &member).await, RefusalKind::Unauthorized);
    let listed = listing(&rd, &ca, &admin).await.unwrap();
    let record = listed.iter().find(|r| r.request_id == id).unwrap();
    assert_eq!(record.role.as_deref(), Some("node"));
    assert_eq!(record.device.as_deref(), Some("vps"));
    assert_eq!(record.code, code);
}

/// An admin's certificate key is public: a decision or a pending listing
/// "signed" with a symmetric MAC keyed by it (HmacWithSha256, BLAKE3-keyed;
/// KeyLocator the admin's key) is a forgery anyone could make. The CA
/// refuses both — the MAC is no public-key signature — and nothing changes.
#[tokio::test]
async fn a_mac_keyed_with_an_admin_public_key_neither_decides_nor_lists() {
    use ndn_security::{Blake3KeyedSigner, HmacSha256Signer};

    let rd = RootDevice::new().await;
    let ca = rd.start_ca(DEFAULT_REQUEST_TTL);
    let admin = device(&rd, &ca, "admin", "laptop", 1).await;
    let (id, _) = request(&rd, &ca, &key("node", "vps", 2)).await;
    let record = ca.approvals.get(&id).unwrap();

    let admin_cert = Certificate::decode(&Data::decode(admin.chain[0].clone()).unwrap()).unwrap();
    let public = admin_cert.public_key.clone();
    let raw: [u8; 32] = ndn_security::spki::unwrap_ed25519(&public)
        .unwrap_or_else(|| public.as_ref().try_into().expect("an Ed25519 key"));
    let admin_key = admin.key.key_name().clone();
    let forgers: [Arc<dyn Signer>; 3] = [
        Arc::new(HmacSha256Signer::new(&public, admin_key.clone())),
        Arc::new(HmacSha256Signer::new(&raw, admin_key.clone())),
        Arc::new(Blake3KeyedSigner::new(raw, admin_key)),
    ];
    for key in forgers {
        let forger = Device {
            key,
            chain: admin.chain.clone(),
        };
        for result in [
            push(&rd, &ca, &record, &Decision::Approve, &forger)
                .await
                .map(|_| ()),
            listing(&rd, &ca, &forger).await.map(|_| ()),
        ] {
            match result {
                Err(ApproverError::Refused(refusal)) => {
                    assert_eq!(refusal.kind, RefusalKind::Unauthorized, "{refusal:?}");
                    assert!(
                        refusal.reason.contains("not a public-key signature"),
                        "refused for the MAC: {}",
                        refusal.reason
                    );
                }
                other => panic!("a MAC keyed with the admin's public key was accepted: {other:?}"),
            }
        }
        assert!(ca.approvals.get(&id).unwrap().is_pending());
    }

    // The admin's real signature still decides.
    let decided = push(&rd, &ca, &record, &Decision::Approve, &admin)
        .await
        .unwrap();
    assert!(matches!(decided.state, ApprovalState::Approved { .. }));
}

/// The generated schema `ndn-fwd init` wrote before admins could deny or
/// list requests remotely — today's without the `#deny` and `#pending`
/// rules, as that generator produced it — and the hint of that time (an
/// invite AND an approval, no approval roles named).
fn old_generated_schema() -> (Vec<SchemaBlob>, EnrollmentHint) {
    let schema = namespace_schema(&ns()).unwrap();
    let lvs: String = schema
        .lvs_source
        .lines()
        .filter(|l| !l.starts_with("#deny:") && !l.starts_with("#pending:"))
        .map(|l| format!("{l}\n"))
        .collect();
    let blobs = vec![
        SchemaBlob::lvs(compile_lvs_to_binary(&lvs).unwrap()),
        SchemaBlob::native_text(schema.native_rules),
    ];
    let hint = EnrollmentHint {
        challenges: vec!["token".into(), "device-approval".into()],
        require_all: true,
        approval_roles: Vec::new(),
    };
    (blobs, hint)
}

/// Adopt `data` into the root device's keyring as an update of the version
/// it holds: the continuity rule, as a refresh does.
async fn adopt_update(rd: &RootDevice, data: &Data) {
    let held = rd.keyring.contexts().pop().unwrap();
    let (next, _) = open_context_update(&held, data).await.unwrap();
    rd.keyring.adopt_update_from(&held, Arc::new(next)).unwrap();
}

/// Whether Data `by` produces under its own identity `identity` validates
/// under the keyring's context, its chain walked to the root.
async fn produces(rd: &RootDevice, identity: &Name, by: &Device) -> bool {
    let cert = Data::decode(by.chain[0].clone()).unwrap();
    rd.mgr
        .cert_cache()
        .insert(Certificate::decode(&cert).unwrap());
    let key = Arc::clone(&by.key);
    let wire = DataBuilder::new(identity.clone().append("notes").append("1"), b"hello")
        .sign_fallible(by.key.sig_type(), Some(cert.name.as_ref()), move |region| {
            let (key, region) = (Arc::clone(&key), region.to_vec());
            async move { key.sign(&region).await }
        })
        .await
        .unwrap();
    let validator =
        Validator::with_keyring(Arc::clone(&rd.keyring), rd.mgr.cert_cache_arc(), None, 4);
    let data = Data::decode(wire).unwrap();
    matches!(
        validator.validate_chain_cached(&data).await.0,
        ValidationResult::Valid(_)
    )
}

/// A namespace held with the old generated schema refuses an admin's remote
/// denial and listing; the root-signed update to the current schema adds
/// exactly those rules, removes none, is adopted by the continuity rule,
/// and then the same admin denies and lists — while a member's Data still
/// validates. Signing the old schema over the new one is a narrowing,
/// refused without consent, naming the rules devices would lose.
#[tokio::test]
async fn a_schema_update_gives_an_older_namespace_the_decision_rules() {
    let rd = RootDevice::new().await;
    let ca = rd.start_ca(DEFAULT_REQUEST_TTL);
    let admin = device(&rd, &ca, "admin", "laptop", 1).await;
    let member = device(&rd, &ca, "member", "phone", 2).await;
    let phone = ns().append("member").append("phone");
    let root = RootStore::open(&FilePib::open(rd.dir.path()).unwrap())
        .unwrap()
        .expect("the root device")
        .signer(None)
        .await
        .unwrap();
    let (_, v1) = read_stored_context(rd.dir.path(), &ns()).unwrap().unwrap();

    // The namespace as an earlier `ndn-fwd init` left it.
    let (old_schema, old_hint) = old_generated_schema();
    let old = bump_context_schema(root.as_ref(), &v1, &old_schema, &old_hint, None, None, true)
        .await
        .unwrap()
        .unwrap();
    adopt_update(&rd, &old.bump.data).await;
    let (id, _) = request(&rd, &ca, &key("node", "vps", 3)).await;
    let deny = Decision::Deny {
        reason: "not my relay".into(),
    };
    assert_refused(listing(&rd, &ca, &admin).await, RefusalKind::Unauthorized);
    assert_refused(
        push(&rd, &ca, &ca.approvals.get(&id).unwrap(), &deny, &admin).await,
        RefusalKind::Unauthorized,
    );
    assert!(ca.approvals.get(&id).unwrap().is_pending());
    assert!(produces(&rd, &phone, &member).await);

    let current = namespace_schema(&ns()).unwrap().blobs();
    let hint = ApprovalPolicy::default().to_hint();
    let update = bump_context_schema(
        root.as_ref(),
        &old.bump.data,
        &current,
        &hint,
        None,
        None,
        false,
    )
    .await
    .unwrap()
    .expect("the old schema lacks rules");
    let change = &update.change;
    assert_eq!(change.added.len(), 2, "{:?}", change.added);
    assert!(
        change
            .added
            .iter()
            .any(|r| r.starts_with("#deny:") && r.contains("ndncert-deny"))
    );
    assert!(
        change
            .added
            .iter()
            .any(|r| r.starts_with("#pending:") && r.contains("PENDING"))
    );
    assert!(change.removed.is_empty());
    assert_eq!(
        update.bump.context.version(),
        old.bump.context.version() + 1
    );
    assert_eq!(update.bump.context.enrollment_hint(), Some(&hint));
    adopt_update(&rd, &update.bump.data).await;

    let listed = listing(&rd, &ca, &admin).await.unwrap();
    assert!(listed.iter().any(|r| r.request_id == id));
    let denied = push(&rd, &ca, &ca.approvals.get(&id).unwrap(), &deny, &admin)
        .await
        .unwrap();
    assert!(
        matches!(denied.state, ApprovalState::Denied { .. }),
        "{denied:?}"
    );
    assert!(produces(&rd, &phone, &member).await);

    let again = bump_context_schema(
        root.as_ref(),
        &update.bump.data,
        &current,
        &hint,
        None,
        None,
        false,
    )
    .await;
    assert!(matches!(again, Ok(None)), "nothing to sign: {again:?}");
    match bump_context_schema(
        root.as_ref(),
        &update.bump.data,
        &old_schema,
        &hint,
        None,
        None,
        false,
    )
    .await
    {
        Err(BumpError::Narrowing { removed, .. }) => {
            assert_eq!(removed.len(), 2, "{removed:?}");
            assert!(removed.iter().any(|r| r.contains("ndncert-deny")));
            assert!(removed.iter().any(|r| r.contains("PENDING")));
        }
        other => panic!("a narrowing needs consent: {other:?}"),
    }
}

/// A schema update carries the held link policy and relays unchanged unless
/// `[ca]` states others; a widening applies as is, a narrowing only with
/// consent.
#[tokio::test]
async fn a_schema_update_changes_the_link_policy_never_narrowing_silently() {
    let rd = RootDevice::new().await;
    let root = RootStore::open(&FilePib::open(rd.dir.path()).unwrap())
        .unwrap()
        .expect("the root device")
        .signer(None)
        .await
        .unwrap();
    let (_, v1) = read_stored_context(rd.dir.path(), &ns()).unwrap().unwrap();
    let schema = namespace_schema(&ns()).unwrap().blobs();
    let hint = ApprovalPolicy::default().to_hint();
    let held = LinkPolicy {
        roles: vec!["admin".into(), "node".into()],
        relay_roles: vec!["node".into()],
        enrollment_links: true,
        direct_paths: true,
        direct_pairs: LinkPolicy::default_direct_pairs(),
    };
    let v2 = bump_context_schema(root.as_ref(), &v1, &schema, &hint, Some(&held), None, true)
        .await
        .unwrap()
        .expect("another link policy");
    assert_eq!(v2.bump.context.stated_link_policy(), Some(&held));

    // No [ca] link keys: the held policy is carried, field for field.
    let other_hint = ApprovalPolicy {
        invite_also: true,
        ..ApprovalPolicy::default()
    }
    .to_hint();
    let v3 = bump_context_schema(
        root.as_ref(),
        &v2.bump.data,
        &schema,
        &other_hint,
        None,
        None,
        false,
    )
    .await
    .unwrap()
    .expect("another hint");
    assert!(!v3.change.changes_link());
    assert_eq!(v3.bump.context.stated_link_policy(), Some(&held));

    // Widening: a role added, a relay role added.
    let wider = LinkPolicy {
        roles: vec!["admin".into(), "node".into(), "member".into()],
        relay_roles: vec!["node".into(), "admin".into()],
        enrollment_links: true,
        direct_paths: true,
        direct_pairs: LinkPolicy::default_direct_pairs(),
    };
    let v4 = bump_context_schema(
        root.as_ref(),
        &v3.bump.data,
        &schema,
        &other_hint,
        Some(&wider),
        None,
        false,
    )
    .await
    .unwrap()
    .expect("a wider link policy");
    assert!(v4.change.link_narrowed.is_empty());
    assert_eq!(v4.bump.context.stated_link_policy(), Some(&wider));

    // Each narrowing is refused without consent and applies with it.
    let mut fewer_pairs = LinkPolicy::default_direct_pairs();
    fewer_pairs.retain(|(a, b)| !(a == "node" && b == "node"));
    for narrower in [
        LinkPolicy {
            roles: vec!["admin".into(), "node".into()],
            ..wider.clone()
        },
        LinkPolicy {
            relay_roles: vec!["node".into()],
            ..wider.clone()
        },
        LinkPolicy {
            enrollment_links: false,
            ..wider.clone()
        },
        LinkPolicy {
            direct_paths: false,
            ..wider.clone()
        },
        LinkPolicy {
            direct_pairs: fewer_pairs,
            ..wider.clone()
        },
    ] {
        let refused = bump_context_schema(
            root.as_ref(),
            &v4.bump.data,
            &schema,
            &other_hint,
            Some(&narrower),
            None,
            false,
        )
        .await;
        assert!(
            matches!(&refused, Err(BumpError::LinkNarrowing { narrowed, .. }) if narrowed.len() == 1),
            "{refused:?}"
        );
        let applied = bump_context_schema(
            root.as_ref(),
            &v4.bump.data,
            &schema,
            &other_hint,
            Some(&narrower),
            None,
            true,
        )
        .await
        .unwrap()
        .expect("consented narrowing");
        assert_eq!(applied.bump.context.stated_link_policy(), Some(&narrower));
    }

    // Direct paths off -> on widens: no consent needed.
    let no_direct = LinkPolicy {
        direct_paths: false,
        ..wider.clone()
    };
    let v5 = bump_context_schema(
        root.as_ref(),
        &v4.bump.data,
        &schema,
        &other_hint,
        Some(&no_direct),
        None,
        true,
    )
    .await
    .unwrap()
    .expect("direct paths off");
    let v6 = bump_context_schema(
        root.as_ref(),
        &v5.bump.data,
        &schema,
        &other_hint,
        Some(&wider),
        None,
        false,
    )
    .await
    .unwrap()
    .expect("direct paths back on");
    assert!(v6.change.link_narrowed.is_empty());
    assert_eq!(v6.bump.context.stated_link_policy(), Some(&wider));

    // Advertising a relay widens; the next version carries it; dropping it
    // needs consent.
    let relay = AdvertisedRelay {
        device: "/home/bob/node/vps".parse().unwrap(),
        key: None,
        endpoints: vec!["vps.example.net:6367".into()],
        preference: 0,
    };
    let v7 = bump_context_schema(
        root.as_ref(),
        &v6.bump.data,
        &schema,
        &other_hint,
        None,
        Some(std::slice::from_ref(&relay)),
        false,
    )
    .await
    .unwrap()
    .expect("a relay added");
    assert_eq!(v7.bump.context.relays(), std::slice::from_ref(&relay));
    let v8 = bump_context_schema(
        root.as_ref(),
        &v7.bump.data,
        &schema,
        &hint,
        None,
        None,
        false,
    )
    .await
    .unwrap()
    .expect("another hint");
    assert_eq!(
        v8.bump.context.relays(),
        [relay],
        "carried to the next version"
    );
    let refused = bump_context_schema(
        root.as_ref(),
        &v8.bump.data,
        &schema,
        &hint,
        None,
        Some(&[]),
        false,
    )
    .await;
    assert!(
        matches!(&refused, Err(BumpError::RelayNarrowing { dropped, .. }) if dropped.len() == 1),
        "{refused:?}"
    );
    let v9 = bump_context_schema(
        root.as_ref(),
        &v8.bump.data,
        &schema,
        &hint,
        None,
        Some(&[]),
        true,
    )
    .await
    .unwrap()
    .expect("consented narrowing");
    assert!(v9.bump.context.relays().is_empty());
}

/// Nothing an unsigned NEW/CHALLENGE answer says ends a request: a denial
/// in it keeps the approved key until a CA-signed STATUS says denied.
#[test]
fn unauthenticated_denial_keeps_key() {
    for e in [
        ApprovalEnrollError::Denied("denied by someone".into()),
        ApprovalEnrollError::Expired("gone".into()),
        ApprovalEnrollError::CaRefused("unreadable answer".into()),
        ApprovalEnrollError::NameRefused("taken".into()),
    ] {
        assert!(!e.is_final(), "{e}");
    }
    assert!(ApprovalEnrollError::Signing("no key".into()).is_final());
}

/// An issued certificate failing its checks (e.g. a stale trust context)
/// leaves the approval standing: retry, and say how.
#[test]
fn stale_issued_cert_is_retryable() {
    let e = ApprovalEnrollError::IssuedCertificate("does not chain to the root".into());
    assert!(!e.is_final());
    assert!(e.to_string().contains("refresh"), "{e}");
}

/// A pending request past its expiry plus the grace ends locally: its
/// sealed key is deleted, it is no longer outstanding, a new one may go out.
#[test]
fn expired_outgoing_request_ends_locally() {
    use ndn_cert::approval::{OUTGOING_EXPIRY_GRACE, OutgoingRequest, OutgoingState, RequestStore};
    let dir = tempfile::tempdir().unwrap();
    let store = RequestStore::open(dir.path().join("requests")).unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let request = |device: &str, expires_secs| OutgoingRequest {
        namespace: "/home/bob".into(),
        ca_prefix: "/home/bob".into(),
        identity: format!("/home/bob/device/{device}"),
        key_name: format!("/home/bob/device/{device}/KEY/1"),
        request_id: device.into(),
        code: "0000".into(),
        created_secs: 1,
        expires_secs,
        state: OutgoingState::Pending,
    };
    let stale = request("old", now - OUTGOING_EXPIRY_GRACE.as_secs() - 10);
    let live = request("new", now + 3600);
    for r in [&stale, &live] {
        store.save(r).unwrap();
        store.save_sealed_key(&r.key_name, b"sealed").unwrap();
    }
    assert_eq!(store.outstanding(&stale.identity).unwrap(), None);
    let ended = store.expire_overdue().unwrap();
    assert_eq!(ended.len(), 1);
    match &ended[0].state {
        OutgoingState::Expired { reason } => {
            assert!(
                reason.contains("never answered") && reason.contains("ask again"),
                "{reason}"
            )
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(store.sealed_key(&stale.key_name).unwrap(), None);
    assert!(store.sealed_key(&live.key_name).unwrap().is_some());
    assert_eq!(store.outstanding(&live.identity).unwrap(), Some(live));
}
