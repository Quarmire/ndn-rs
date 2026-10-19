//! `SecurityProfile::Default` with no `SecurityManager` fails closed: there
//! are no trust anchors, so every Data from a non-local face that names a
//! signer is refused at once with the final local refusal `untrusted-root`,
//! without a certificate fetch. It never degrades to signature-only
//! checking; `AcceptSigned` and `Disabled` are chosen explicitly. Local faces
//! are not validated under any profile.
//!
//! Faces: `LOCAL` the consumer, an in-proc app face (Local scope);
//! `UPSTREAM` the producer side, network-kind (NonLocal) unless a test makes
//! it local.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_engine::{EngineBuilder, EngineConfig, ForwarderEngine, ShutdownHandle};
use ndn_face_local::{InProcFace, InProcHandle};
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_packet::lp::LpPacket;
use ndn_packet::{Data, Name, Refusal, SignatureType};
use ndn_security::{
    CertFetcher, Ed25519Signer, FetchFn, SecurityProfile, Signer, encode_cert_data,
};
use ndn_transport::{FaceId, FaceKind};

const LOCAL: u64 = 1;
const UPSTREAM: u64 = 2;

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
    LpPacket::decode(wire.clone()).ok()?.nack?.reason?.refusal()
}

/// The Data a reply carries, `None` for a Nack or anything else.
fn data_of(wire: &Bytes) -> Option<Data> {
    let wire = match LpPacket::decode(wire.clone()) {
        Ok(lp) if lp.nack.is_none() => lp.fragment?,
        Ok(_) => return None,
        Err(_) => wire.clone(),
    };
    Data::decode(wire).ok()
}

/// A key nobody certified: `/t/KEY/k`.
fn stranger() -> Ed25519Signer {
    Ed25519Signer::from_seed(&[5; 32], n("/t/KEY/k"))
}

fn signed_data(name: &str, signer: &Ed25519Signer) -> Bytes {
    DataBuilder::new(n(name), b"payload").sign_sync(
        SignatureType::SignatureEd25519,
        Some(signer.key_name()),
        |region| signer.sign_sync(region).unwrap(),
    )
}

/// `/t/doc` signed Ed25519 by `signer` with a KeyDigest KeyLocator (as ndf's
/// compute records are), which no certificate fetch can resolve.
fn key_digest_signed_data(signer: &Ed25519Signer) -> Bytes {
    use ndn_tlv::TlvWriter;
    use sha2::{Digest, Sha256};

    let mut w = TlvWriter::new();
    w.write_nested(0x07, |w| {
        w.write_tlv(0x08, b"t");
        w.write_tlv(0x08, b"doc");
    });
    w.write_tlv(0x15, b"payload");
    w.write_nested(0x16, |w| {
        w.write_tlv(0x1b, &[5u8]); // SignatureEd25519
        w.write_nested(0x1c, |w| {
            w.write_tlv(0x1d, Sha256::digest(signer.public_key_bytes()).as_slice());
        });
    });
    let signed_region = w.finish();
    let sig = signer.sign_sync(&signed_region).unwrap();
    let mut inner = signed_region.to_vec();
    let mut w = TlvWriter::new();
    w.write_tlv(0x17, &sig);
    inner.extend_from_slice(&w.finish());
    let mut w = TlvWriter::new();
    w.write_tlv(0x06, &inner);
    w.finish()
}

struct Rig {
    engine: ForwarderEngine,
    local: InProcHandle,
    upstream: InProcHandle,
    shutdown: ShutdownHandle,
}

/// An engine under `profile` with no SecurityManager; the consumer asks for
/// `/t/doc` and the Interest reaches `UPSTREAM` (a forwarder on this host
/// when `local_upstream`).
async fn rig(profile: SecurityProfile, local_upstream: bool) -> Rig {
    let (local_face, local) = InProcFace::new(FaceId(LOCAL), 64);
    let (up_face, upstream) = if local_upstream {
        InProcFace::new(FaceId(UPSTREAM), 64)
    } else {
        InProcFace::new_kind(FaceId(UPSTREAM), 64, FaceKind::Tcp)
    };
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .security_profile(profile)
        .face(local_face)
        .face(up_face)
        .build()
        .await
        .expect("engine build");
    engine.fib().add_nexthop(&n("/t"), FaceId(UPSTREAM), 0);
    local
        .send(
            InterestBuilder::new(n("/t/doc"))
                .lifetime(Duration::from_secs(4))
                .build(),
        )
        .await
        .expect("send Interest");
    recv_timeout(&upstream, 500)
        .await
        .expect("the Interest reaches the upstream");
    Rig {
        engine,
        local,
        upstream,
        shutdown,
    }
}

/// The consumer is told `untrusted-root` at once — a final verdict — and the
/// engine asks the upstream for no certificate.
async fn assert_refused_untrusted_root(rig: Rig, data: Bytes) {
    rig.upstream.send(data).await.expect("send Data");
    let got = recv_timeout(&rig.local, 500)
        .await
        .expect("the consumer hears back well before any fetch timeout");
    let refusal = refusal_of(&got).expect("a refusal Nack, not the Data");
    assert_eq!(refusal, Refusal::UntrustedRoot);
    assert!(refusal.is_final());
    assert!(
        recv_timeout(&rig.upstream, 200).await.is_none(),
        "no certificate is fetched: no anchor could end the chain"
    );
    rig.shutdown.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn default_refuses_key_signed_data_from_a_non_local_face() {
    let rig = rig(SecurityProfile::Default, false).await;
    assert_refused_untrusted_root(rig, signed_data("/t/doc", &stranger())).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn default_refuses_key_digest_signed_data_from_a_non_local_face() {
    let rig = rig(SecurityProfile::Default, false).await;
    assert_refused_untrusted_root(rig, key_digest_signed_data(&stranger())).await;
}

/// A DigestSha256 Data names no signer: its digest is checked (integrity
/// only), as with a SecurityManager.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn default_passes_digest_sha256_data() {
    let rig = rig(SecurityProfile::Default, false).await;
    rig.upstream
        .send(DataBuilder::new(n("/t/doc"), b"payload").sign_digest_sha256())
        .await
        .unwrap();
    let got = recv_timeout(&rig.local, 500).await.expect("Data delivered");
    assert!(data_of(&got).is_some(), "got {got:?}");
    rig.shutdown.shutdown().await;
}

/// Data from a local face (an app, or a forwarder on this host) is not
/// validated, under `Default` as under every profile.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn default_leaves_local_faces_unvalidated() {
    let rig = rig(SecurityProfile::Default, true).await;
    rig.upstream
        .send(signed_data("/t/doc", &stranger()))
        .await
        .unwrap();
    let got = recv_timeout(&rig.local, 500).await.expect("Data delivered");
    assert!(data_of(&got).is_some(), "got {got:?}");
    rig.shutdown.shutdown().await;
}

/// Anchors added to the engine's validator after build are honoured: the
/// names they govern are validated in full instead of refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn default_validates_once_an_anchor_is_added() {
    let rig = rig(SecurityProfile::Default, false).await;
    let signer = stranger();
    let validator = rig.engine.validator().expect("Default has a validator");
    validator.add_trust_anchor(ndn_security::Certificate {
        name: Arc::new(signer.key_name().clone()),
        public_key: Bytes::copy_from_slice(&signer.public_key_bytes()),
        valid_from: 0,
        valid_until: u64::MAX,
        issuer: None,
        signed_region: None,
        sig_value: None,
        sig_type: SignatureType::SignatureEd25519,
    });
    rig.upstream
        .send(signed_data("/t/doc", &signer))
        .await
        .unwrap();
    let got = recv_timeout(&rig.local, 500).await.expect("Data delivered");
    assert!(data_of(&got).is_some(), "got {got:?}");
    rig.shutdown.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disabled_passes_signed_data_from_a_non_local_face() {
    let rig = rig(SecurityProfile::Disabled, false).await;
    assert!(rig.engine.validator().is_none());
    rig.upstream
        .send(signed_data("/t/doc", &stranger()))
        .await
        .unwrap();
    let got = recv_timeout(&rig.local, 500).await.expect("Data delivered");
    assert!(data_of(&got).is_some(), "got {got:?}");
    rig.shutdown.shutdown().await;
}

/// `AcceptSigned` accepts Data validly signed by a key nobody certified, once
/// the key's self-signed certificate is fetched; a forged one is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accept_signed_accepts_validly_signed_data_from_an_unknown_key() {
    let rig = rig(SecurityProfile::AcceptSigned, false).await;
    let signer = Arc::new(stranger());
    let cert_wire = encode_cert_data(
        &n("/t/KEY/k/self/v=1"),
        &signer.public_key_bytes(),
        signer.as_ref(),
        0,
        u64::MAX,
    )
    .await
    .unwrap();
    let validator = rig
        .engine
        .validator()
        .expect("AcceptSigned has a validator");
    let fetch: FetchFn = Arc::new(move |_| {
        let cert_wire = cert_wire.clone();
        Box::pin(async move { Ok(Data::decode(cert_wire).unwrap()) })
    });
    assert!(
        validator
            .set_cert_fetcher(Arc::new(CertFetcher::new(
                validator.cert_cache_arc(),
                fetch,
                Duration::from_secs(2),
            )))
            .is_ok()
    );
    rig.upstream
        .send(signed_data("/t/doc", &signer))
        .await
        .unwrap();
    let got = recv_timeout(&rig.local, 2000)
        .await
        .expect("Data delivered");
    assert!(data_of(&got).is_some(), "got {got:?}");
    rig.shutdown.shutdown().await;
}
