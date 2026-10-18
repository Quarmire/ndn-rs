//! The local refusal: when the validation stage reaches a final verdict
//! against a Data (revoked signer, forged signature, a signing certificate
//! not to be had where it was fetched), each **local** downstream whose
//! Interest it answered gets a Nack carrying `NackReason::Refused(<why>)` at
//! once; a non-local downstream gets nothing (to the network a refused Data
//! is a dropped one). Data still waiting for a certificate has no verdict
//! yet and is refused to nobody.
//!
//! Faces: `LOCAL` an in-proc app face (Local scope), `REMOTE` a downstream
//! and `UPSTREAM` the producer side, both network-kind (NonLocal), so the
//! Data arriving from `UPSTREAM` is validated.

use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use ndn_engine::{EngineBuilder, EngineConfig, ShutdownHandle};
use ndn_face_local::{InProcFace, InProcHandle};
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_packet::lp::{LpPacket, encode_lp_nack};
use ndn_packet::{Data, NackReason, Name, Refusal, SignatureType};
use ndn_security::{
    CertCache, CertFetcher, Certificate, Ed25519Signer, FetchFn, FetchMiss, Keyring,
    SignedTrustContext, Signer, Validator,
};
use ndn_transport::{FaceId, FaceKind};

const LOCAL: u64 = 1;
const REMOTE: u64 = 2;
const UPSTREAM: u64 = 3;

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

async fn recv_timeout(h: &InProcHandle, ms: u64) -> Option<Bytes> {
    tokio::time::timeout(Duration::from_millis(ms), h.recv())
        .await
        .ok()
        .flatten()
}

/// The refusal a reply carries, `None` for anything else.
fn refusal_of(wire: &Bytes) -> Option<Refusal> {
    LpPacket::decode(wire.clone())
        .ok()?
        .nack?
        .reason?
        .refusal()
}

fn anchor_cert(signer: &Ed25519Signer) -> Certificate {
    Certificate {
        name: Arc::new(signer.key_name().clone()),
        public_key: Bytes::copy_from_slice(&signer.public_key_bytes()),
        valid_from: 0,
        valid_until: u64::MAX,
        issuer: None,
        signed_region: None,
        sig_value: None,
        sig_type: SignatureType::SignatureEd25519,
    }
}

fn signed_data(name: &str, signer: &Ed25519Signer) -> Bytes {
    DataBuilder::new(n(name), b"payload").sign_sync(
        SignatureType::SignatureEd25519,
        Some(signer.key_name()),
        |region| signer.sign_sync(region).unwrap(),
    )
}

/// A validator for `/t` anchored at `root`, with `member`'s certificate
/// (issued by `root`) cached, `member` revoked when `revoked`, and a
/// certificate fetcher that never finds anything (slowly).
async fn validator(root: &Ed25519Signer, member: &Ed25519Signer, revoked: bool) -> Validator {
    let never: FetchFn = Arc::new(|_| {
        Box::pin(async {
            tokio::time::sleep(Duration::from_secs(5)).await;
            Err(FetchMiss::Unanswered)
        })
    });
    validator_fetching(root, member, revoked, never).await
}

/// [`validator`], with a certificate fetcher that fetches through `fetch`.
async fn validator_fetching(
    root: &Ed25519Signer,
    member: &Ed25519Signer,
    revoked: bool,
    fetch: FetchFn,
) -> Validator {
    let mut ctx = SignedTrustContext::hierarchical(n("/t"));
    if revoked {
        ctx = ctx.with_revocation(member.key_name().clone());
    }
    assert!(ctx.add_anchor(anchor_cert(root)));
    let keyring = Arc::new(Keyring::new());
    assert!(keyring.adopt(Arc::new(ctx)));
    let cache = Arc::new(CertCache::new());
    let cert_wire = ndn_security::encode_cert_data(
        member.key_name(),
        &member.public_key_bytes(),
        root,
        0,
        u64::MAX,
    )
    .await
    .unwrap();
    cache.insert(Certificate::decode(&Data::decode(cert_wire).unwrap()).unwrap());
    let fetcher = Arc::new(CertFetcher::new(
        Arc::clone(&cache),
        fetch,
        Duration::from_secs(5),
    ));
    Validator::with_keyring(keyring, cache, Some(fetcher), 5)
}

struct Rig {
    local: InProcHandle,
    remote: InProcHandle,
    upstream: InProcHandle,
    /// The Interest as the upstream received it.
    forwarded: Bytes,
    shutdown: ShutdownHandle,
}

/// Both downstreams ask for `name`; the Interest reaches `UPSTREAM`
/// (non-local unless `local_upstream`: a forwarder on this host).
async fn rig_with(validator: Validator, name: &str, local_upstream: bool) -> Rig {
    let (local_face, local) = InProcFace::new(FaceId(LOCAL), 64);
    let (remote_face, remote) = InProcFace::new_kind(FaceId(REMOTE), 64, FaceKind::Tcp);
    let (up_face, upstream) = if local_upstream {
        InProcFace::new(FaceId(UPSTREAM), 64)
    } else {
        InProcFace::new_kind(FaceId(UPSTREAM), 64, FaceKind::Tcp)
    };
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .validator(Arc::new(validator))
        .face(local_face)
        .face(remote_face)
        .face(up_face)
        .build()
        .await
        .expect("engine build");
    engine.fib().add_nexthop(&n("/t"), FaceId(UPSTREAM), 0);
    let interest = || {
        InterestBuilder::new(n(name))
            .lifetime(Duration::from_secs(4))
            .build()
    };
    local.send(interest()).await.expect("send Interest");
    let forwarded = recv_timeout(&upstream, 500)
        .await
        .expect("the Interest reaches the upstream");
    remote.send(interest()).await.expect("send Interest");
    assert!(
        recv_timeout(&upstream, 200).await.is_none(),
        "the second Interest is aggregated"
    );
    Rig {
        local,
        remote,
        upstream,
        forwarded,
        shutdown,
    }
}

async fn rig(validator: Validator, name: &str) -> Rig {
    rig_with(validator, name, false).await
}

fn nack_reason(wire: &Bytes) -> Option<NackReason> {
    LpPacket::decode(wire.clone()).ok()?.nack?.reason
}

/// The upstream answers the forwarded Interest with a refusal Nack.
async fn upstream_refuses(rig: &Rig) {
    let lp = LpPacket::decode(rig.forwarded.clone());
    let interest = match lp {
        Ok(lp) => lp.fragment.expect("LP-framed Interest"),
        Err(_) => rig.forwarded.clone(),
    };
    let nack = encode_lp_nack(NackReason::Refused(Refusal::Revoked), &interest);
    rig.upstream.send(nack).await.expect("send Nack");
}

/// A refusal from a non-local upstream is an unverified claim: the local
/// downstream hears NoRoute, never "refused"; the non-local one gets the
/// Nack too (it is an ordinary Nack now).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_remote_refusal_is_relayed_as_no_route() {
    let root = Ed25519Signer::from_seed(&[1; 32], n("/t/KEY/root"));
    let member = Ed25519Signer::from_seed(&[2; 32], n("/t/m/KEY/k"));
    let rig = rig(validator(&root, &member, false).await, "/t/m/doc").await;
    upstream_refuses(&rig).await;
    for h in [&rig.local, &rig.remote] {
        let got = recv_timeout(h, 500).await.expect("the downstream hears back");
        assert_eq!(nack_reason(&got), Some(NackReason::NoRoute));
    }
    rig.shutdown.shutdown().await;
}

/// A refusal from a forwarder on this host (a local upstream) reaches the
/// local downstream as a refusal; the non-local one learns only that this
/// path has nothing (NoRoute), as from a non-local upstream.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_local_refusal_is_relayed_to_local_downstreams_only() {
    let root = Ed25519Signer::from_seed(&[1; 32], n("/t/KEY/root"));
    let member = Ed25519Signer::from_seed(&[2; 32], n("/t/m/KEY/k"));
    let rig = rig_with(validator(&root, &member, false).await, "/t/m/doc", true).await;
    upstream_refuses(&rig).await;
    let got = recv_timeout(&rig.local, 500).await.expect("the local app hears back");
    assert_eq!(refusal_of(&got), Some(Refusal::Revoked));
    let got = recv_timeout(&rig.remote, 500).await.expect("the remote downstream hears back");
    assert_eq!(nack_reason(&got), Some(NackReason::NoRoute));
    rig.shutdown.shutdown().await;
}

/// The enclosed Interest of a Nack, decoded.
fn enclosed(wire: &Bytes) -> ndn_packet::Interest {
    let lp = LpPacket::decode(wire.clone()).expect("an LP-framed Nack");
    ndn_packet::Interest::decode(lp.fragment.expect("a Fragment")).expect("an Interest")
}

/// A relayed Nack is built for each downstream, as a refusal this node
/// makes is: it encloses that downstream's own Interest (its nonce, its
/// parameters) and echoes its PitToken, so a consumer matching replies by
/// PitToken, or a strict decoder checking the ParametersSha256Digest, still
/// finds its pending Interest.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_relayed_nack_carries_each_downstreams_own_interest_and_pit_token() {
    use ndn_packet::lp::{LpHeaders, encode_lp_with_headers};

    let root = Ed25519Signer::from_seed(&[1; 32], n("/t/KEY/root"));
    let member = Ed25519Signer::from_seed(&[2; 32], n("/t/m/KEY/k"));
    let (local_face, local) = InProcFace::new(FaceId(LOCAL), 64);
    let (remote_face, remote) = InProcFace::new_kind(FaceId(REMOTE), 64, FaceKind::Tcp);
    let (up_face, upstream) = InProcFace::new(FaceId(UPSTREAM), 64);
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .validator(Arc::new(validator(&root, &member, false).await))
        .face(local_face)
        .face(remote_face)
        .face(up_face)
        .build()
        .await
        .expect("engine build");
    engine.fib().add_nexthop(&n("/t"), FaceId(UPSTREAM), 0);

    let interest = || {
        InterestBuilder::new(n("/t/m/CA/NEW"))
            .app_parameters(b"request".to_vec())
            .lifetime(Duration::from_secs(4))
            .build()
    };
    let (mine, theirs) = (interest(), interest());
    let token = Bytes::from_static(&[0xCA, 0xFE, 0x00, 0x01]);
    let headers = LpHeaders {
        pit_token: Some(token.clone()),
        ..Default::default()
    };
    local.send(encode_lp_with_headers(&mine, &headers)).await.expect("send Interest");
    let forwarded = recv_timeout(&upstream, 500).await.expect("the Interest reaches the upstream");
    remote.send(theirs.clone()).await.expect("send Interest");
    assert!(recv_timeout(&upstream, 200).await.is_none(), "the second Interest is aggregated");
    let forwarded = match LpPacket::decode(forwarded.clone()) {
        Ok(lp) => lp.fragment.expect("LP-framed Interest"),
        Err(_) => forwarded,
    };
    upstream
        .send(encode_lp_nack(NackReason::Refused(Refusal::Revoked), &forwarded))
        .await
        .expect("send Nack");

    for (h, sent, pit_token, reason) in [
        (&local, &mine, Some(token), NackReason::Refused(Refusal::Revoked)),
        (&remote, &theirs, None, NackReason::NoRoute),
    ] {
        let got = recv_timeout(h, 500).await.expect("the downstream hears back");
        let lp = LpPacket::decode(got.clone()).unwrap();
        assert_eq!(lp.nack.and_then(|n| n.reason), Some(reason));
        assert_eq!(lp.pit_token, pit_token, "the downstream's PitToken comes back");
        let sent = ndn_packet::Interest::decode(sent.clone()).unwrap();
        let back = enclosed(&got);
        assert_eq!(back.name, sent.name);
        assert_eq!(back.nonce(), sent.nonce(), "its own nonce, not the forwarded one");
        assert_eq!(back.parameters_portion(), sent.parameters_portion(), "its parameters");
    }
    shutdown.shutdown().await;
}

/// One Data consumes a face's exact Interest and its CanBePrefix Interest
/// at a shorter prefix: each pending Interest gets its refusal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_pending_interest_of_a_face_gets_its_refusal() {
    let root = Ed25519Signer::from_seed(&[1; 32], n("/t/KEY/root"));
    let member = Ed25519Signer::from_seed(&[2; 32], n("/t/m/KEY/k"));
    let (local_face, local) = InProcFace::new(FaceId(LOCAL), 64);
    let (up_face, upstream) = InProcFace::new_kind(FaceId(UPSTREAM), 64, FaceKind::Tcp);
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .validator(Arc::new(validator(&root, &member, true).await))
        .face(local_face)
        .face(up_face)
        .build()
        .await
        .expect("engine build");
    engine.fib().add_nexthop(&n("/t"), FaceId(UPSTREAM), 0);
    let exact = InterestBuilder::new(n("/t/m/doc")).lifetime(Duration::from_secs(4)).build();
    let prefix = InterestBuilder::new(n("/t/m"))
        .can_be_prefix()
        .lifetime(Duration::from_secs(4))
        .build();
    for i in [exact, prefix] {
        local.send(i).await.expect("send Interest");
        recv_timeout(&upstream, 500).await.expect("the Interest reaches the upstream");
    }
    upstream.send(signed_data("/t/m/doc", &member)).await.expect("send Data");
    let mut names = Vec::new();
    for _ in 0..2 {
        let got = recv_timeout(&local, 500).await.expect("a refusal for each Interest");
        assert_eq!(refusal_of(&got), Some(Refusal::Revoked));
        names.push(enclosed(&got).name.to_string());
    }
    names.sort();
    assert_eq!(names, ["/t/m", "/t/m/doc"]);
    shutdown.shutdown().await;
}

/// The local downstream gets the refusal at once; the remote one nothing.
async fn assert_refused_locally_only(rig: Rig, data: Bytes, want: Refusal) {
    rig.upstream.send(data).await.expect("send Data");
    let got = recv_timeout(&rig.local, 500).await.expect("the local app hears back");
    assert_eq!(refusal_of(&got), Some(want));
    assert!(
        recv_timeout(&rig.remote, 300).await.is_none(),
        "a non-local downstream gets neither the Data nor a refusal"
    );
    rig.shutdown.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoked_data_is_refused_to_the_local_consumer_only() {
    let root = Ed25519Signer::from_seed(&[1; 32], n("/t/KEY/root"));
    let member = Ed25519Signer::from_seed(&[2; 32], n("/t/m/KEY/k"));
    let rig = rig(validator(&root, &member, true).await, "/t/m/doc").await;
    assert_refused_locally_only(rig, signed_data("/t/m/doc", &member), Refusal::Revoked).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forged_data_is_refused_to_the_local_consumer_only() {
    let root = Ed25519Signer::from_seed(&[1; 32], n("/t/KEY/root"));
    let member = Ed25519Signer::from_seed(&[2; 32], n("/t/m/KEY/k"));
    let rig = rig(validator(&root, &member, false).await, "/t/m/doc").await;
    let mut forged = BytesMut::from(&signed_data("/t/m/doc", &member)[..]);
    let last = forged.len() - 1;
    forged[last] ^= 0x01; // inside the signature value
    assert_refused_locally_only(rig, forged.freeze(), Refusal::BadSignature).await;
}

/// Control: valid Data reaches both downstreams.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn valid_data_reaches_both_downstreams() {
    let root = Ed25519Signer::from_seed(&[1; 32], n("/t/KEY/root"));
    let member = Ed25519Signer::from_seed(&[2; 32], n("/t/m/KEY/k"));
    let rig = rig(validator(&root, &member, false).await, "/t/m/doc").await;
    rig.upstream
        .send(signed_data("/t/m/doc", &member))
        .await
        .unwrap();
    for h in [&rig.local, &rig.remote] {
        let got = recv_timeout(h, 500).await.expect("Data delivered");
        assert_eq!(refusal_of(&got), None);
    }
    rig.shutdown.shutdown().await;
}

/// Data whose signer's certificate is still being fetched has no verdict:
/// nobody is told anything.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pending_data_is_refused_to_nobody() {
    let root = Ed25519Signer::from_seed(&[1; 32], n("/t/KEY/root"));
    let member = Ed25519Signer::from_seed(&[2; 32], n("/t/m/KEY/k"));
    let stranger = Ed25519Signer::from_seed(&[3; 32], n("/t/s/KEY/k"));
    let rig = rig(validator(&root, &member, false).await, "/t/s/doc").await;
    rig.upstream
        .send(signed_data("/t/s/doc", &stranger))
        .await
        .unwrap();
    for h in [&rig.local, &rig.remote] {
        let got = recv_timeout(h, 400).await;
        assert!(got.is_none(), "pending Data answered: {got:?}");
    }
    rig.shutdown.shutdown().await;
}

/// Data whose signer's certificate the fetch was told is not to be had
/// where it was asked (a NoRoute Nack) cannot be verified now: refused
/// `unverifiable` (refused for now, not final), told to the local consumer
/// at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn data_whose_certificate_is_absent_is_refused_unverifiable() {
    let root = Ed25519Signer::from_seed(&[1; 32], n("/t/KEY/root"));
    let member = Ed25519Signer::from_seed(&[2; 32], n("/t/m/KEY/k"));
    let stranger = Ed25519Signer::from_seed(&[3; 32], n("/t/s/KEY/k"));
    let no_route: FetchFn = Arc::new(|_| Box::pin(async { Err(FetchMiss::Absent) }));
    let validator = validator_fetching(&root, &member, false, no_route).await;
    let rig = rig(validator, "/t/s/doc").await;
    assert_refused_locally_only(
        rig,
        signed_data("/t/s/doc", &stranger),
        Refusal::Unverifiable,
    )
    .await;
}
