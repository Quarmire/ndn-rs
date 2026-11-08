//! A forwarder under the `default` security profile whose security manager
//! holds its own self-certifying namespace `/user/<hB>` — its root a PIB
//! trust anchor, loaded into the ambient context as every PIB anchor is —
//! refuses Data in a person's namespace it does not hold (`/user/<hA>/…`),
//! even when a key certified under its own root signed it, and caches
//! nothing of it: a person's names are judged only by their own trust
//! context (trust-context.md §4.5.6, §6.1). Once it holds `/user/<hA>`,
//! Alice's genuine Data is forwarded.
//!
//! Faces: `LOCAL` the consumer, an in-proc app face; `UPSTREAM` the
//! producer side, network-kind (validated).

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_engine::{EngineBuilder, EngineConfig, ShutdownHandle};
use ndn_face_local::{InProcFace, InProcHandle};
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_packet::lp::LpPacket;
use ndn_packet::{Data, Name, Refusal, SignatureType};
use ndn_security::self_certifying::{Genesis, self_certifying_name};
use ndn_security::{Certificate, SecurityManager, SecurityProfile, SignedTrustContext};
use ndn_transport::{FaceId, FaceKind};

const LOCAL: u64 = 1;
const UPSTREAM: u64 = 2;

async fn recv_timeout(h: &InProcHandle, ms: u64) -> Option<Bytes> {
    tokio::time::timeout(Duration::from_millis(ms), h.recv())
        .await
        .ok()
        .flatten()
}

fn refusal_of(wire: &Bytes) -> Option<Refusal> {
    LpPacket::decode(wire.clone()).ok()?.nack?.reason?.refusal()
}

fn data_of(wire: &Bytes) -> Option<Data> {
    let wire = match LpPacket::decode(wire.clone()) {
        Ok(lp) if lp.nack.is_none() => lp.fragment?,
        Ok(_) => return None,
        Err(_) => wire.clone(),
    };
    Data::decode(wire).ok()
}

/// A person's root key (from `seed`) in `mgr` and its self-signed anchor,
/// which `mgr` adds to its ambient anchors as `from_pib` loads a PIB's.
fn person(mgr: &SecurityManager, seed: u8) -> (Name, Name, Certificate) {
    let seed = [seed; 32];
    let pk = ndn_security::Ed25519Signer::from_seed(&seed, Name::root()).public_key_bytes();
    let ns = self_certifying_name(&pk);
    let key = ns.clone().append("KEY").append("root");
    mgr.generate_ed25519_from_seed(key.clone(), &seed).unwrap();
    let anchor = mgr
        .issue_self_signed(&key, Bytes::copy_from_slice(&pk), u64::MAX)
        .unwrap();
    (ns, key, anchor)
}

/// Hold `ns` in `holder`'s keyring from its genesis, signed in `mgr`.
async fn hold(
    holder: &SecurityManager,
    mgr: &SecurityManager,
    ns: &Name,
    key: &Name,
    anchor: &Certificate,
) {
    let ctx = SignedTrustContext::hierarchical(ns.clone()).with_version(1);
    ctx.add_anchor(anchor.clone());
    let signer = mgr.get_signer_sync(key).unwrap();
    let data = ctx.sign_into_data_async(signer.as_ref()).await.unwrap();
    let genesis = Genesis::open_received(&data).await.unwrap();
    holder
        .keyring()
        .adopt_genesis(&genesis, Arc::clone(genesis.context()))
        .unwrap();
}

/// A key `key` in `mgr` certified by `issuer`; its certificate.
async fn certified(mgr: &SecurityManager, key: &Name, issuer: &Name) -> Certificate {
    mgr.generate_ed25519(key.clone()).unwrap();
    let pk = mgr.get_signer_sync(key).unwrap().public_key().unwrap();
    mgr.certify(key, pk, issuer, 3_600_000).await.unwrap()
}

fn signed(mgr: &SecurityManager, name: &Name, key: &Name) -> Bytes {
    let signer = mgr.get_signer_sync(key).unwrap();
    DataBuilder::new(name.clone(), b"payload")
        .freshness(Duration::from_secs(60))
        .sign_sync(SignatureType::SignatureEd25519, Some(key), |region| {
            signer.sign_sync(region).unwrap()
        })
}

struct Rig {
    local: InProcHandle,
    upstream: InProcHandle,
    shutdown: ShutdownHandle,
}

/// The forwarder of Bob's node: profile `default` over `bob`, routing
/// `/user` to `UPSTREAM`.
async fn forwarder(bob: Arc<SecurityManager>) -> Rig {
    let (local_face, local) = InProcFace::new(FaceId(LOCAL), 64);
    let (up_face, upstream) = InProcFace::new_kind(FaceId(UPSTREAM), 64, FaceKind::Tcp);
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .security(bob)
        .security_profile(SecurityProfile::Default)
        .face(local_face)
        .face(up_face)
        .build()
        .await
        .expect("engine build");
    engine
        .fib()
        .add_nexthop(&"/user".parse().unwrap(), FaceId(UPSTREAM), 0);
    Rig {
        local,
        upstream,
        shutdown,
    }
}

/// The consumer asks for `name`; whether the Interest reached the upstream.
async fn ask(rig: &Rig, name: &Name) -> bool {
    rig.local
        .send(
            InterestBuilder::new(name.clone())
                .lifetime(Duration::from_secs(4))
                .build(),
        )
        .await
        .expect("send Interest");
    recv_timeout(&rig.upstream, 500).await.is_some()
}

/// Bob's node: his own `/user/<hB>` held, as `init_self_certifying_in_pib`
/// leaves it (genesis adopted, root a PIB trust anchor), and his phone's
/// key certified by his root.
async fn bob() -> (Arc<SecurityManager>, Name) {
    let bob = Arc::new(SecurityManager::new());
    let (ns, root, anchor) = person(&bob, 1);
    hold(&bob, &bob, &ns, &root, &anchor).await;
    let phone = ns.append("phone").append("KEY").append("d");
    certified(&bob, &phone, &root).await;
    (bob, phone)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_key_under_the_own_root_never_vouches_for_a_persons_namespace_not_held() {
    let (bob, phone) = bob().await;
    let alice_mgr = SecurityManager::new();
    let (alice, _, _) = person(&alice_mgr, 2);
    let doc = alice.append("doc");
    let rig = forwarder(Arc::clone(&bob)).await;

    assert!(ask(&rig, &doc).await, "the Interest reaches the upstream");
    rig.upstream
        .send(signed(&bob, &doc, &phone))
        .await
        .expect("send Data");
    let got = recv_timeout(&rig.local, 500)
        .await
        .expect("the consumer hears back");
    assert!(
        data_of(&got).is_none(),
        "Data in /user/<hA>, not held, signed by a key of Bob's own root, was forwarded"
    );
    assert_eq!(
        refusal_of(&got),
        Some(Refusal::UntrustedRoot),
        "got {got:?}"
    );
    assert!(
        ask(&rig, &doc).await,
        "the refused Data was cached: a second Interest did not reach the upstream"
    );
    rig.shutdown.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_persons_genuine_data_is_forwarded_once_their_namespace_is_held() {
    let (bob, _) = bob().await;
    let alice_mgr = SecurityManager::new();
    let (alice, root, anchor) = person(&alice_mgr, 2);
    hold(&bob, &alice_mgr, &alice, &root, &anchor).await;
    let phone = alice.clone().append("phone").append("KEY").append("a");
    bob.cert_cache()
        .insert(certified(&alice_mgr, &phone, &root).await);
    let doc = alice.append("phone").append("doc");
    let rig = forwarder(Arc::clone(&bob)).await;

    assert!(ask(&rig, &doc).await, "the Interest reaches the upstream");
    rig.upstream
        .send(signed(&alice_mgr, &doc, &phone))
        .await
        .expect("send Data");
    let got = recv_timeout(&rig.local, 500)
        .await
        .expect("the consumer hears back");
    assert!(data_of(&got).is_some(), "Alice's genuine Data: got {got:?}");
    rig.shutdown.shutdown().await;
}
