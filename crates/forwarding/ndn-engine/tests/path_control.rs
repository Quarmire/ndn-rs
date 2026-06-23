//! G3 MAP-Me redirect end-to-end through the forwarder: a signed `PathControl`
//! Redirect (the Interest Update) arriving on a face repoints the prefix's FIB
//! next-hop toward that face (the producer's new location) and is propagated down the
//! old trail. Also pins the security gate (an unsigned/untrusted IU is ignored) and
//! the loop guard (a stale sequence is dropped).

use std::sync::Arc;
use std::time::{Duration, Instant};

use ndn_engine::{EngineBuilder, EngineConfig};
use ndn_face_local::{InProcFace, InProcHandle};
use ndn_packet::Name;
use ndn_packet::encode::InterestBuilder;
use ndn_pathcontrol::{PathControl, PathOp};
use ndn_security::cert_cache::Certificate;
use ndn_security::signer::Ed25519Signer;
use ndn_security::trust_schema::{NamePattern, PatternComponent, SchemaRule, TrustSchema};
use ndn_security::{SignWith, Validator};
use ndn_transport::{FaceId, FaceKind};

const NEW: u64 = 1; // face the IU arrives on (producer's new location)
const OLD: u64 = 2; // face the prefix currently points at (old location)
const KEY: &str = "/alice/KEY/k1";

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

fn open_schema() -> TrustSchema {
    let mut s = TrustSchema::new();
    s.add_rule(SchemaRule {
        data_pattern: NamePattern(vec![PatternComponent::MultiCapture("_".into())]),
        key_pattern: NamePattern(vec![PatternComponent::MultiCapture("_".into())]),
    });
    s
}

fn validator_trusting(signer: &Ed25519Signer, key: &Name) -> Validator {
    let v = Validator::new(open_schema());
    v.cert_cache().insert(Certificate {
        name: Arc::new(key.clone()),
        public_key: bytes::Bytes::copy_from_slice(&signer.public_key_bytes()),
        valid_from: 0,
        valid_until: u64::MAX,
        issuer: None,
        signed_region: None,
        sig_value: None,
        sig_type: ndn_packet::SignatureType::SignatureEd25519,
    });
    v
}

/// A signed Redirect IU for `target` at `seq`, ready to inject on a face.
fn signed_iu(signer: &Ed25519Signer, target: &Name, seq: u64) -> bytes::Bytes {
    let pc = PathControl::new(target.clone(), PathOp::Redirect, seq);
    InterestBuilder::new(pc.to_name())
        .app_parameters(Vec::new())
        .sign_with_sync(signer)
        .expect("sign IU")
}

async fn recv_timeout(h: &InProcHandle) -> Option<bytes::Bytes> {
    tokio::time::timeout(Duration::from_millis(500), h.recv()).await.ok().flatten()
}

async fn fib_faces(engine: &ndn_engine::ForwarderEngine, target: &Name) -> Vec<FaceId> {
    engine
        .fib()
        .lpm(target)
        .map(|e| e.nexthops.iter().map(|nh| nh.face_id).collect())
        .unwrap_or_default()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redirect_iu_rewrites_fib_and_walks_the_trail() {
    let key = n(KEY);
    let signer = Ed25519Signer::from_seed(&[7u8; 32], key.clone());
    let target = n("/alice/video");

    let (f_new, h_new) = InProcFace::new_kind(FaceId(NEW), 64, FaceKind::Tcp);
    let (f_old, h_old) = InProcFace::new_kind(FaceId(OLD), 64, FaceKind::Tcp);
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .validator(Arc::new(validator_trusting(&signer, &key)))
        .with_producer_mobility()
        .face(f_new)
        .face(f_old)
        .build()
        .await
        .unwrap();

    // Prefix currently reaches the producer via the OLD face.
    engine.fib().add_nexthop(&target, FaceId(OLD), 0);
    assert_eq!(fib_faces(&engine, &target).await, vec![FaceId(OLD)]);

    // The producer moved: a signed Redirect IU arrives on the NEW face.
    h_new.send(signed_iu(&signer, &target, 1)).await.unwrap();

    // FIB is repointed to the NEW face…
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(2) {
        if fib_faces(&engine, &target).await == vec![FaceId(NEW)] {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        fib_faces(&engine, &target).await,
        vec![FaceId(NEW)],
        "Redirect must repoint the prefix to the face the IU arrived on"
    );
    // …and the IU is propagated down the old trail (out the OLD face).
    assert!(
        recv_timeout(&h_old).await.is_some(),
        "the IU must walk on toward the previous attachment"
    );

    shutdown.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unsigned_or_untrusted_iu_is_ignored() {
    let key = n(KEY);
    let signer = Ed25519Signer::from_seed(&[7u8; 32], key.clone());
    let target = n("/alice/video");

    let (f_new, h_new) = InProcFace::new_kind(FaceId(NEW), 64, FaceKind::Tcp);
    let (f_old, _h_old) = InProcFace::new_kind(FaceId(OLD), 64, FaceKind::Tcp);
    // Validator trusts a *different* key, so the IU's signer is untrusted.
    let other = Ed25519Signer::from_seed(&[8u8; 32], n("/mallory/KEY/k1"));
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .validator(Arc::new(validator_trusting(&other, &n("/mallory/KEY/k1"))))
        .with_producer_mobility()
        .face(f_new)
        .face(f_old)
        .build()
        .await
        .unwrap();
    engine.fib().add_nexthop(&target, FaceId(OLD), 0);

    // A correctly-signed IU, but by a key the forwarder does not trust for this prefix.
    h_new.send(signed_iu(&signer, &target, 1)).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        fib_faces(&engine, &target).await,
        vec![FaceId(OLD)],
        "an untrusted IU must not rewrite the FIB (anti prefix-hijack)"
    );

    shutdown.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_sequence_is_dropped() {
    let key = n(KEY);
    let signer = Ed25519Signer::from_seed(&[7u8; 32], key.clone());
    let target = n("/alice/video");

    let (f_new, h_new) = InProcFace::new_kind(FaceId(NEW), 64, FaceKind::Tcp);
    let (f_old, h_old) = InProcFace::new_kind(FaceId(OLD), 64, FaceKind::Tcp);
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .validator(Arc::new(validator_trusting(&signer, &key)))
        .with_producer_mobility()
        .face(f_new)
        .face(f_old)
        .build()
        .await
        .unwrap();
    engine.fib().add_nexthop(&target, FaceId(OLD), 0);

    // seq=5 redirects to NEW.
    h_new.send(signed_iu(&signer, &target, 5)).await.unwrap();
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(2)
        && fib_faces(&engine, &target).await != vec![FaceId(NEW)]
    {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(fib_faces(&engine, &target).await, vec![FaceId(NEW)]);

    // A stale seq=3 arriving on the OLD face must NOT redirect back (loop guard).
    h_old.send(signed_iu(&signer, &target, 3)).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        fib_faces(&engine, &target).await,
        vec![FaceId(NEW)],
        "a stale (older) sequence must be dropped, leaving the FIB at the newer redirect"
    );

    shutdown.shutdown().await;
}
