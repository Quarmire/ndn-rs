//! Self-certifying namespaces `/user/<0xA1: SHA-256(raw Ed25519 root)>`
//! through ndn-cert (trust-context.md §4.5). Each test guards one invariant:
//!
//! - init names a namespace from its own new Ed25519 root (or a given one),
//!   and refuses a self-certifying name its root does not hash to;
//! - a forged genesis is refused whatever link carries it, and a second
//!   genesis of a held namespace is a fork;
//! - the name alone adopts the namespace: version 1 checked against it, the
//!   newest reached by continuity, and a restart keeps it;
//! - the name survives a recovery after a compromise, and a root moved to a
//!   P-256 key: followers keep following, and a fresh device adopts by name;
//! - after a recovery, a line longer than an ordinary refresh walks is
//!   still followed, by a holder, a fresh device and a restart;
//! - a self-certifying namespace is never initialised twice: its version 1
//!   is a pure function of its key (the same bytes on every device, at any
//!   time), and a key held already whose genesis answers on the network is
//!   refused before anything is written.

use std::sync::Arc;

use bytes::Bytes;
use ndn_cert::{
    AdoptError, AnchorLink, CaExchange, CatchUpStop, CertError, ContextRefresh, GenesisCheck,
    GenesisKey, MAX_CATCH_UP_VERSIONS, NamespaceInitError, NamespacePolicies, NewRootStore,
    OldRoot, PersistedNamespace, RecoveryPlan, RecoverySeed, RootStore, Unfetched, VersionSource,
    add_recovery_anchor, adopt_anchor_link, adopt_by_name, anchor_fingerprint,
    bump_context_revoking, follow_versions, init_namespace_in_pib_with,
    init_self_certifying_in_pib_with, load_persisted_contexts, persist_adoption, rdr_metadata_name,
    recover_namespace_in_pib, recovery_anchor, recovery_version, refresh_context, reissue_version,
};
use ndn_packet::encode::DataBuilder;
use ndn_packet::{Data, Interest, Name, NameComponent};
use ndn_security::self_certifying::{
    GenesisError, SELF_CERTIFYING, personal_prefix, self_certifying_name,
};
use ndn_security::{
    CertCache, EcdsaP256Signer, Ed25519Signer, FilePib, Keyring, SecurityManager,
    SignedTrustContext, Signer, ValidationResult, Validator,
};
use ndn_trust_envelope::TrustEnvelope;

/// A root device of a self-certifying namespace named from `key`.
struct Root {
    _dir: tempfile::TempDir,
    pib: FilePib,
    out: PersistedNamespace,
}

impl Root {
    async fn new(key: &GenesisKey) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let pib = FilePib::new(dir.path()).unwrap();
        let out = init_self_certifying_in_pib_with(
            &pib,
            key,
            "desk",
            &NewRootStore::File,
            &NamespacePolicies::default(),
        )
        .await
        .unwrap();
        Self {
            _dir: dir,
            pib,
            out,
        }
    }

    fn ns(&self) -> Name {
        self.out.init.context.namespace().clone()
    }

    async fn root(&self) -> Arc<dyn Signer> {
        RootStore::open_for(&self.pib, &self.ns())
            .unwrap()
            .unwrap()
            .signer(None)
            .await
            .unwrap()
    }

    /// Version 1, the genesis: the root anchor alone.
    fn genesis(&self) -> &Data {
        self.out
            .init
            .genesis
            .as_ref()
            .expect("a self-certifying init signs a genesis")
            .data()
    }

    /// Version 2, which init signs after the genesis: the CA, schema and
    /// policies.
    fn v2(&self) -> &Data {
        &self.out.init.context_data
    }
}

fn open(data: &Data) -> SignedTrustContext {
    futures::executor::block_on(SignedTrustContext::open_signed(data))
        .unwrap()
        .0
}

/// Every version of `ns` a node serves: RDR metadata naming the newest, and
/// each by its exact name.
struct Upstream {
    ns: Name,
    versions: Vec<Bytes>,
}

impl Upstream {
    fn serving(ns: &Name, versions: &[&Data]) -> Self {
        Self {
            ns: ns.clone(),
            versions: versions.iter().map(|d| d.raw().clone()).collect(),
        }
    }
}

impl CaExchange for Upstream {
    async fn express(&mut self, interest: Bytes) -> Result<Data, CertError> {
        let interest = Interest::decode(interest).unwrap();
        let meta_name = rdr_metadata_name(&self.ns);
        if *interest.name == meta_name {
            let newest = Data::decode(self.versions.last().unwrap().clone()).unwrap();
            let version = newest
                .name
                .components()
                .last()
                .unwrap()
                .as_version()
                .unwrap();
            let wire = DataBuilder::new(
                meta_name.append_version(version).append_segment(0),
                &newest.name.encode_to_tlv(),
            )
            .build();
            return Ok(Data::decode(wire).unwrap());
        }
        self.versions
            .iter()
            .map(|wire| Data::decode(wire.clone()).unwrap())
            .find(|d| *d.name == *interest.name)
            .ok_or_else(|| CertError::Transport(format!("no reply for {}", interest.name)))
    }
}

/// `Upstream` through this node's validating forwarder, which drops what
/// its validator does not admit.
struct Forwarded<'a> {
    upstream: Upstream,
    forwarder: &'a Validator,
}

impl CaExchange for Forwarded<'_> {
    async fn express(&mut self, interest: Bytes) -> Result<Data, CertError> {
        let data = self.upstream.express(interest).await?;
        match self.forwarder.validate_chain_cached(&data).await.0 {
            ValidationResult::Valid(_) => Ok(data),
            other => Err(CertError::Transport(format!("dropped: {other:?}"))),
        }
    }
}

/// A node holding `ns` adopted by name from `versions`.
async fn follower(ns: &Name, versions: &[&Data]) -> Arc<Keyring> {
    let keyring = Arc::new(Keyring::new());
    adopt_by_name(
        &keyring,
        None,
        &mut Upstream::serving(ns, versions),
        ns,
        None,
    )
    .await
    .unwrap();
    keyring
}

#[tokio::test]
async fn init_names_the_namespace_from_its_new_ed25519_root() {
    let key = GenesisKey::generate().unwrap();
    let root = Root::new(&key).await;
    assert_eq!(root.ns(), self_certifying_name(&key.public_key()));
    assert_eq!(root.ns(), key.namespace());
    assert_eq!(
        root.out.init.anchor.public_key.as_ref(),
        &key.public_key()[..]
    );
    assert_eq!(open(root.genesis()).version(), 1);
    assert_eq!(root.out.init.context.version(), 2);
    // The bytes ndf-rs's `record::personal_root` makes from the same key.
    let seed = [3u8; 32];
    let given = GenesisKey::from_seed(seed);
    let pk = Ed25519Signer::from_seed(&seed, Name::root()).public_key_bytes();
    use sha2::Digest;
    let digest: [u8; 32] = sha2::Sha256::digest(pk).into();
    let expected = personal_prefix().append_component(NameComponent::new(
        SELF_CERTIFYING,
        Bytes::copy_from_slice(&digest),
    ));
    assert_eq!(given.namespace(), expected);
    // The root device holds its own namespace after a restart.
    let keyring = Keyring::new();
    for (path, loaded) in load_persisted_contexts(root.pib.root(), &keyring).unwrap() {
        loaded.unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    }
    assert_eq!(keyring.version_of(&root.ns()), Some(2));
    // Made again, even from the same key, it would be a second line after
    // its genesis.
    let again = init_self_certifying_in_pib_with(
        &root.pib,
        &key,
        "desk",
        &NewRootStore::File,
        &NamespacePolicies::default(),
    )
    .await
    .err()
    .expect("a self-certifying namespace was made again");
    assert!(
        matches!(again, NamespaceInitError::GenesisExists { .. }),
        "{again}"
    );
    assert!(again.to_string().contains("ndn-fwd recover"), "{again}");
}

#[tokio::test]
async fn init_refuses_a_self_certifying_name_its_new_root_does_not_hash_to() {
    let dir = tempfile::tempdir().unwrap();
    let pib = FilePib::new(dir.path()).unwrap();
    let someone = self_certifying_name(&[1u8; 32]);
    let refused = init_namespace_in_pib_with(
        &pib,
        &someone,
        "desk",
        false,
        &NewRootStore::File,
        &NamespacePolicies::default(),
    )
    .await
    .err()
    .expect("a self-certifying name was given to a new root");
    assert!(
        matches!(refused, NamespaceInitError::SelfCertifying { .. }),
        "{refused}"
    );
    let why = refused.to_string();
    assert!(why.contains("--self-certifying"), "{why}");
    assert!(RootStore::open_for(&pib, &someone).unwrap().is_none());
    // A self-certifying component anywhere else names nobody.
    let misplaced = Name::root()
        .append("home")
        .append_component(NameComponent::new(
            SELF_CERTIFYING,
            Bytes::from_static(&[1; 32]),
        ));
    let refused = init_namespace_in_pib_with(
        &pib,
        &misplaced,
        "desk",
        false,
        &NewRootStore::File,
        &NamespacePolicies::default(),
    )
    .await
    .err()
    .expect("a misplaced self-certifying component");
    assert!(
        matches!(refused, NamespaceInitError::SelfCertifyingName(_)),
        "{refused}"
    );
}

/// Mallory signs a version 1 of Alice's name listing Alice's anchor (it is
/// public) beside her own, and hands it out with her own fingerprint.
/// Before the genesis rule a link with that fingerprint adopted it.
#[tokio::test]
async fn a_forged_genesis_is_refused_whatever_link_carries_it() {
    let alice = Root::new(&GenesisKey::generate().unwrap()).await;
    let ns = alice.ns();
    let mallory: Arc<dyn Signer> = Arc::new(Ed25519Signer::from_seed(
        &[66; 32],
        ns.clone().append("KEY").append("mallory"),
    ));
    let mallory_anchor = recovery_anchor(Arc::clone(&mallory)).await.unwrap();
    let forged = SignedTrustContext::decode_content(alice.genesis().content().unwrap(), 1).unwrap();
    forged.add_anchor(mallory_anchor.clone());
    let forged = forged.sign_into_data_async(mallory.as_ref()).await.unwrap();

    let keyring = Keyring::new();
    let refused =
        ndn_cert::adopt_with_tofu(&keyring, &forged, &ns, &anchor_fingerprint(&mallory_anchor))
            .expect_err("a forged genesis was adopted");
    assert!(
        matches!(refused, AdoptError::Genesis(GenesisError::Mismatch { .. })),
        "{refused}"
    );
    let link = AnchorLink {
        namespace: ns.clone(),
        expected_fingerprint: anchor_fingerprint(&mallory_anchor),
        min_version: None,
        context_data: Some(Data::decode(forged.raw().clone()).unwrap()),
    };
    let refused =
        ndn_cert::adopt_anchor_link(&keyring, None, &mut Upstream::serving(&ns, &[]), &link)
            .await
            .expect_err("a forged genesis was adopted from a link");
    assert!(matches!(refused, AdoptError::Genesis(_)), "{refused}");
    // Served by name, too.
    let refused = adopt_by_name(
        &keyring,
        None,
        &mut Upstream::serving(&ns, &[&forged]),
        &ns,
        None,
    )
    .await
    .expect_err("a forged genesis was adopted by name");
    assert!(matches!(refused, AdoptError::Genesis(_)), "{refused}");
    assert!(keyring.is_empty());

    // Two different versions 1: once the genuine one is held, the other is
    // a fork, whatever signed it.
    let keyring = follower(&ns, &[alice.genesis()]).await;
    let other = SignedTrustContext::decode_content(alice.genesis().content().unwrap(), 1)
        .unwrap()
        .with_ca_endpoint(ns.clone().append("elsewhere"));
    let other = other
        .sign_into_data_async(alice.root().await.as_ref())
        .await
        .unwrap();
    let refused = ndn_cert::adopt_with_tofu(
        &keyring,
        &other,
        &ns,
        &anchor_fingerprint(&alice.out.init.anchor),
    )
    .expect_err("a second genesis replaced the held one");
    assert!(matches!(refused, AdoptError::Fork(1)), "{refused}");
}

#[tokio::test]
async fn a_self_certifying_namespace_is_adopted_by_its_name_alone() {
    let alice = Root::new(&GenesisKey::generate().unwrap()).await;
    let ns = alice.ns();
    let revoked = ns
        .clone()
        .append("member")
        .append("old")
        .append("KEY")
        .append("k");
    let v3 = bump_context_revoking(
        alice.root().await.as_ref(),
        alice.v2(),
        std::slice::from_ref(&revoked),
        &[],
    )
    .await
    .unwrap()
    .unwrap()
    .data;

    // The link names the namespace only.
    let envelope = TrustEnvelope::Anchor {
        namespace: Some(ns.to_string()),
        fingerprint: None,
        version: None,
        context_data: None,
        context_content: None,
    };
    let link = AnchorLink::from_envelope(&envelope).unwrap();
    let keyring = Keyring::new();
    let adopted = ndn_cert::adopt_anchor_link(
        &keyring,
        None,
        &mut Upstream::serving(&ns, &[alice.genesis(), alice.v2(), &v3]),
        &link,
    )
    .await
    .unwrap();
    assert_eq!(adopted.context.version(), 3);
    assert!(adopted.context.is_revoked(&revoked));
    let earlier: Vec<u64> = adopted
        .earlier
        .iter()
        .map(|s| s.context.version())
        .collect();
    // Version 3 is signed by the root, an anchor of the genesis: reached
    // from it directly.
    assert_eq!(earlier, [1]);
    assert_eq!(keyring.version_of(&ns), Some(3));

    // Through a validating forwarder that holds nothing: told to expect the
    // name's genesis root.
    let keyring = Arc::new(Keyring::new());
    let validator =
        Validator::with_keyring(Arc::clone(&keyring), Arc::new(CertCache::new()), None, 4);
    let mut forwarded = Forwarded {
        upstream: Upstream::serving(&ns, &[alice.genesis(), alice.v2(), &v3]),
        forwarder: &validator,
    };
    let adopted = adopt_by_name(&keyring, Some(&validator), &mut forwarded, &ns, None)
        .await
        .unwrap();
    assert_eq!(keyring.version_of(&ns), Some(3));

    // Kept with its genesis, a restart holds it again, by the same check.
    let dir = tempfile::tempdir().unwrap();
    persist_adoption(dir.path(), &adopted).unwrap();
    let restarted = Keyring::new();
    for (path, loaded) in load_persisted_contexts(dir.path(), &restarted).unwrap() {
        loaded.unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    }
    assert_eq!(restarted.version_of(&ns), Some(3));
    // Without its genesis it is not taken.
    std::fs::remove_file(ndn_cert::context_version_path(dir.path(), &ns, 1)).unwrap();
    let restarted = Keyring::new();
    let loaded = load_persisted_contexts(dir.path(), &restarted).unwrap();
    assert!(loaded.iter().all(|(_, r)| r.is_err()), "{loaded:?}");
    assert!(restarted.is_empty());
}

#[tokio::test]
async fn the_name_survives_a_recovery_after_a_compromise() {
    let alice = Root::new(&GenesisKey::generate().unwrap()).await;
    let ns = alice.ns();
    let seed = RecoverySeed::generate().unwrap();
    let kit = recovery_anchor(Arc::new(seed.signer(&ns))).await.unwrap();
    let v3 = add_recovery_anchor(alice.root().await.as_ref(), alice.v2(), &kit)
        .await
        .unwrap()
        .data;
    let follower = follower(&ns, &[alice.genesis(), alice.v2(), &v3]).await;

    let dir = tempfile::tempdir().unwrap();
    let pib = FilePib::new(dir.path()).unwrap();
    let recovered = recover_namespace_in_pib(
        &pib,
        &v3,
        &seed.signer(&ns),
        "phone",
        OldRoot::Compromised,
        &[],
        &[],
        &NewRootStore::File,
    )
    .await
    .unwrap();
    let v4 = &recovered.version.bump.data;
    let v5 = &recovered.root_version.data;
    assert_eq!(open(v5).namespace(), &ns);
    assert!(open(v5).is_revoked(&alice.out.init.anchor_key));
    assert_ne!(
        anchor_fingerprint(&recovered.anchor),
        anchor_fingerprint(&alice.out.init.anchor)
    );

    // The follower walks to the recovered root under the same name.
    let res = refresh_context(
        &follower,
        None,
        &mut Upstream::serving(&ns, &[alice.genesis(), alice.v2(), &v3, v4, v5]),
        &ns,
    )
    .await;
    assert!(matches!(res, Ok(ContextRefresh::Updated(_))), "{res:?}");
    assert_eq!(follower.version_of(&ns), Some(5));

    // A fresh device adopts it by name: the genesis signed by the old
    // (now revoked) root, then each version by continuity.
    let fresh = Keyring::new();
    let adopted = adopt_by_name(
        &fresh,
        None,
        &mut Upstream::serving(&ns, &[alice.genesis(), alice.v2(), &v3, v4, v5]),
        &ns,
        None,
    )
    .await
    .unwrap();
    let earlier: Vec<u64> = adopted
        .earlier
        .iter()
        .map(|s| s.context.version())
        .collect();
    assert_eq!(earlier, [1, 2, 3, 4]);
    assert_eq!(fresh.version_of(&ns), Some(5));
    assert!(fresh.contexts()[0].is_anchor(&recovered.anchor.key_name()));
}

/// A link carrying a recovered self-certifying namespace's newest version
/// inline (as an introduction's credentials carry it) is not enough for a
/// device that does not hold the namespace: it is taken only from its
/// genesis, so the adoption fetches — version 1, then the versions to the
/// newest — and a host binding it to a network must give it one
/// (`AnchorLink::fetches`). An inline genesis needs nothing fetched.
#[tokio::test]
async fn an_inline_later_version_of_a_namespace_not_held_is_reached_from_its_genesis() {
    let alice = Root::new(&GenesisKey::generate().unwrap()).await;
    let ns = alice.ns();
    let seed = RecoverySeed::generate().unwrap();
    let kit = recovery_anchor(Arc::new(seed.signer(&ns))).await.unwrap();
    let v3 = add_recovery_anchor(alice.root().await.as_ref(), alice.v2(), &kit)
        .await
        .unwrap()
        .data;
    let dir = tempfile::tempdir().unwrap();
    let recovered = recover_namespace_in_pib(
        &FilePib::new(dir.path()).unwrap(),
        &v3,
        &seed.signer(&ns),
        "phone",
        OldRoot::Compromised,
        &[],
        &[],
        &NewRootStore::File,
    )
    .await
    .unwrap();
    let v4 = &recovered.version.bump.data;
    let v5 = &recovered.root_version.data;
    let inline = |data: &Data| AnchorLink {
        namespace: ns.clone(),
        expected_fingerprint: anchor_fingerprint(&recovered.anchor),
        min_version: Some(open(data).version()),
        context_data: Some(Data::decode(data.raw().clone()).unwrap()),
    };

    let fresh = Keyring::new();
    assert!(!inline(alice.genesis()).fetches(&fresh));
    let link = inline(v5);
    assert!(link.fetches(&fresh));
    let adopted = adopt_anchor_link(
        &fresh,
        None,
        &mut Upstream::serving(&ns, &[alice.genesis(), alice.v2(), &v3, v4, v5]),
        &link,
    )
    .await
    .unwrap();
    assert!(adopted.fetched);
    assert_eq!(fresh.version_of(&ns), Some(5));
    // Held now: the same link moves it on by continuity alone, offline.
    assert!(!link.fetches(&fresh));
}

/// The root moves to a P-256 key (as a YubiKey's PIV slot holds): a
/// recovery onto it, then the version it re-issues. Only version 1 is
/// judged against the name, so the name stays.
#[tokio::test]
async fn the_name_survives_its_root_moving_to_a_p256_key() {
    let alice = Root::new(&GenesisKey::generate().unwrap()).await;
    let ns = alice.ns();
    let seed = RecoverySeed::generate().unwrap();
    let kit = recovery_anchor(Arc::new(seed.signer(&ns))).await.unwrap();
    let v3 = add_recovery_anchor(alice.root().await.as_ref(), alice.v2(), &kit)
        .await
        .unwrap()
        .data;
    let follower = follower(&ns, &[alice.genesis(), alice.v2(), &v3]).await;

    let mgr = SecurityManager::new();
    let piv = ns.clone().append("KEY").append("piv");
    mgr.install_signer(EcdsaP256Signer::generate(piv.clone()).unwrap());
    let p256: Arc<dyn Signer> = mgr.get_signer_sync(&piv).unwrap();
    let p256_anchor = mgr
        .issue_self_signed(&piv, p256.public_key().unwrap(), u64::MAX)
        .unwrap();
    let plan = RecoveryPlan {
        new_root: &p256_anchor,
        new_root_device_keys: &[],
        old_root: OldRoot::Destroyed,
        kept_kits: &[],
        cuts: &[],
    };
    let v4 = recovery_version(&seed.signer(&ns), &v3, &plan)
        .await
        .unwrap()
        .bump
        .data;
    let v5 = reissue_version(p256.as_ref(), &v4).await.unwrap().data;
    assert_eq!(
        v5.sig_info().unwrap().sig_type,
        ndn_packet::SignatureType::SignatureSha256WithEcdsa
    );

    let res = refresh_context(
        &follower,
        None,
        &mut Upstream::serving(&ns, &[alice.genesis(), alice.v2(), &v3, &v4, &v5]),
        &ns,
    )
    .await;
    assert!(matches!(res, Ok(ContextRefresh::Updated(_))), "{res:?}");
    assert_eq!(follower.version_of(&ns), Some(5));

    let fresh = Keyring::new();
    adopt_by_name(
        &fresh,
        None,
        &mut Upstream::serving(&ns, &[alice.genesis(), alice.v2(), &v3, &v4, &v5]),
        &ns,
        None,
    )
    .await
    .unwrap();
    assert_eq!(fresh.version_of(&ns), Some(5));
    assert!(fresh.contexts()[0].is_anchor(&piv));
}

/// More versions after a recovery than an ordinary refresh walks: for a
/// self-certifying name the walk is the only way to them (a walk from the
/// genesis is longer still), so a holder far behind, a fresh device and a
/// restart each follow the whole line.
#[tokio::test]
async fn a_long_line_after_a_recovery_is_followed_whatever_its_length() {
    let alice = Root::new(&GenesisKey::generate().unwrap()).await;
    let ns = alice.ns();
    let seed = RecoverySeed::generate().unwrap();
    let kit = recovery_anchor(Arc::new(seed.signer(&ns))).await.unwrap();
    let v3 = add_recovery_anchor(alice.root().await.as_ref(), alice.v2(), &kit)
        .await
        .unwrap()
        .data;
    let follower = follower(&ns, &[alice.genesis(), alice.v2(), &v3]).await;

    let dir = tempfile::tempdir().unwrap();
    let pib = FilePib::new(dir.path()).unwrap();
    let recovered = recover_namespace_in_pib(
        &pib,
        &v3,
        &seed.signer(&ns),
        "phone",
        OldRoot::Compromised,
        &[],
        &[],
        &NewRootStore::File,
    )
    .await
    .unwrap();
    let new_root = RootStore::open_for(&pib, &ns)
        .unwrap()
        .unwrap()
        .signer(None)
        .await
        .unwrap();
    let copy = |d: &Data| Data::decode(d.raw().clone()).unwrap();
    let mut line = vec![
        copy(alice.genesis()),
        copy(alice.v2()),
        v3,
        copy(&recovered.version.bump.data),
        copy(&recovered.root_version.data),
    ];
    while (line.len() as u64) < MAX_CATCH_UP_VERSIONS + 8 {
        let gone = ns
            .clone()
            .append("member")
            .append(format!("m{}", line.len()).as_str())
            .append("KEY")
            .append("k");
        let next = bump_context_revoking(
            new_root.as_ref(),
            line.last().unwrap(),
            std::slice::from_ref(&gone),
            &[],
        )
        .await
        .unwrap()
        .unwrap()
        .data;
        line.push(next);
    }
    let newest = line.len() as u64;
    let served: Vec<&Data> = line.iter().collect();

    let res = refresh_context(&follower, None, &mut Upstream::serving(&ns, &served), &ns).await;
    assert!(matches!(res, Ok(ContextRefresh::Updated(_))), "{res:?}");
    assert_eq!(follower.version_of(&ns), Some(newest));

    let fresh = Keyring::new();
    let adopted = adopt_by_name(
        &fresh,
        None,
        &mut Upstream::serving(&ns, &served),
        &ns,
        None,
    )
    .await
    .unwrap();
    assert_eq!(fresh.version_of(&ns), Some(newest));

    let kept = tempfile::tempdir().unwrap();
    persist_adoption(kept.path(), &adopted).unwrap();
    let restarted = Keyring::new();
    for (path, loaded) in load_persisted_contexts(kept.path(), &restarted).unwrap() {
        loaded.unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    }
    assert_eq!(restarted.version_of(&ns), Some(newest));
}

/// A source with nothing more before the walk's last position: a walk past
/// its time, or a store keeping no version in between.
struct NothingUntilLast {
    last: u64,
    newest: Option<Data>,
}

impl VersionSource for NothingUntilLast {
    async fn fetch(
        &mut self,
        position: u64,
        _from: &SignedTrustContext,
    ) -> Result<Data, Unfetched> {
        match self.newest.take() {
            Some(data) if position == self.last => Ok(data),
            newest => {
                self.newest = newest;
                Err(Unfetched::MissingUntil {
                    next: u64::MAX,
                    reason: "the walk fetches for 40s at most".into(),
                })
            }
        }
    }
}

/// A self-certifying walk is not bounded by position, so its length must
/// not cost: the newest version's name is not authenticated, and an
/// upstream naming `v=2^64-1` must not make the walk step through every
/// position once nothing more is fetched.
#[tokio::test]
async fn an_unbounded_walk_passes_over_what_it_cannot_fetch_at_once() {
    let alice = Root::new(&GenesisKey::generate().unwrap()).await;
    let last = u64::MAX;
    let stop = follow_versions(
        alice.out.init.genesis.as_ref().unwrap().context(),
        2..=last,
        &mut NothingUntilLast {
            last,
            newest: Some(Data::decode(alice.genesis().raw().clone()).unwrap()),
        },
    )
    .await
    .expect_err("v1 offered as the newest does not follow");
    assert!(
        matches!(
            stop,
            CatchUpStop::Missing { first: 2, last: through, version, .. }
                if through == last - 1 && version == last
        ),
        "{stop}"
    );
}

/// Version 1 of a self-certifying namespace is a pure function of its key:
/// made again from the same seed — on another device, after a reinstall,
/// at another time, in memory or in a PIB — it is the same Data, byte for
/// byte, never a second genesis (a fork every holder of the first refuses).
/// It carries the root anchor alone; what the namespace states besides
/// (its CA, schema, policies, relays) is in the versions after it.
#[tokio::test]
async fn version_1_is_a_pure_function_of_the_seed() {
    let seed = [9u8; 32];
    let genesis_of = |device: &'static str| async move {
        let dir = tempfile::tempdir().unwrap();
        let pib = FilePib::new(dir.path()).unwrap();
        let out = init_self_certifying_in_pib_with(
            &pib,
            &GenesisKey::from_seed(seed).offline(),
            device,
            &NewRootStore::File,
            &NamespacePolicies::default(),
        )
        .await
        .unwrap();
        let ns = out.init.context.namespace().clone();
        std::fs::read(ndn_cert::context_version_path(dir.path(), &ns, 1)).unwrap()
    };
    let first = genesis_of("desk").await;
    // Every field that could hold the time of signing (a certificate
    // version in milliseconds, a validity period in seconds) differs now.
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let second = genesis_of("phone").await;
    assert!(
        first == second,
        "the same seed signed two different versions 1"
    );
    let in_memory = ndn_cert::init_self_certifying(
        &SecurityManager::new(),
        &GenesisKey::from_seed(seed).offline(),
    )
    .unwrap();
    assert!(
        in_memory.genesis.as_ref().unwrap().data().raw().as_ref() == first.as_slice(),
        "an in-memory init from the same seed signed another version 1"
    );
    // Pinned across releases: a device on another ndn-rs release signs
    // these very bytes from this key, or the two fork at version 1. A
    // change here is a change of every self-certifying namespace's genesis.
    use sha2::Digest;
    let digest: String = sha2::Sha256::digest(&first)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(
        digest,
        "e53e2f61d2fc5793d0a083edf24d7b0dd699c04b9888326ed8fb4e50a2745ee3"
    );

    let genesis = ndn_security::self_certifying::Genesis::open_received(
        &Data::decode(Bytes::from(first)).unwrap(),
    )
    .await
    .unwrap();
    let ctx = genesis.context();
    assert_eq!(ctx.anchors().len(), 1, "v1 lists the root anchor alone");
    assert!(ctx.ca_endpoints().is_empty(), "no CA in v1");
    assert!(ctx.enrollment_hint().is_none(), "no policy in v1");
    assert!(ctx.relays().is_empty(), "no relay in v1");
}

/// A key held already ([`GenesisKey::from_seed`], ndf-rs's personal key)
/// makes its namespace only once looked for on the network: a genesis of
/// it that answers means the namespace exists — made on another device,
/// or before a reinstall — and making it again would sign versions after
/// that genesis every holder refuses. Refused before anything is written,
/// saying why and what to do. What is no genesis of it (no answer, or a
/// version 1 another key signed) does not refuse, and the init states
/// what was looked for; so does an init explicitly not looked for.
#[tokio::test]
async fn init_from_a_held_key_whose_genesis_answers_is_refused() {
    let seed = [11u8; 32];
    let first = Root::new(&GenesisKey::from_seed(seed).offline()).await;
    let ns = first.ns();
    assert_eq!(first.out.init.genesis_check, Some(GenesisCheck::Unchecked));

    // Another device of the same person, holding the same key.
    let dir = tempfile::tempdir().unwrap();
    let pib = FilePib::new(dir.path()).unwrap();
    let refused = GenesisKey::from_seed(seed)
        .probe(&mut Upstream::serving(&ns, &[first.genesis(), first.v2()]))
        .await
        .expect_err("a held key whose genesis answers was made again");
    assert!(
        matches!(refused, NamespaceInitError::GenesisReachable { .. }),
        "{refused}"
    );
    let why = refused.to_string();
    for said in ["already exists", "Adopt", "ndn-fwd recover"] {
        assert!(why.contains(said), "{why}");
    }
    assert!(pib.list_keys().unwrap().is_empty(), "nothing written");
    assert!(RootStore::open_for(&pib, &ns).unwrap().is_none());

    // No genesis answers, or only one another key signed: made, stating so.
    let mallory: Arc<dyn Signer> = Arc::new(Ed25519Signer::from_seed(
        &[66; 32],
        ns.clone().append("KEY").append("mallory"),
    ));
    let forged = SignedTrustContext::decode_content(first.genesis().content().unwrap(), 1).unwrap();
    forged.add_anchor(recovery_anchor(Arc::clone(&mallory)).await.unwrap());
    let forged = forged.sign_into_data_async(mallory.as_ref()).await.unwrap();
    for served in [vec![], vec![&forged]] {
        let key = GenesisKey::from_seed(seed)
            .probe(&mut Upstream::serving(&ns, &served))
            .await
            .unwrap();
        assert!(
            matches!(key.check(), GenesisCheck::NoneReachable { .. }),
            "{key:?}"
        );
    }
    let key = GenesisKey::from_seed(seed)
        .probe(&mut Upstream::serving(&ns, &[]))
        .await
        .unwrap();
    let made = init_self_certifying_in_pib_with(
        &pib,
        &key,
        "phone",
        &NewRootStore::File,
        &NamespacePolicies::default(),
    )
    .await
    .unwrap();
    assert!(matches!(
        made.init.genesis_check,
        Some(GenesisCheck::NoneReachable { .. })
    ));
    assert_eq!(
        GenesisKey::generate().unwrap().check(),
        &GenesisCheck::NewKey
    );
}
