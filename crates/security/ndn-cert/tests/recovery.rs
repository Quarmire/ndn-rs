//! Recovery kits and `recover` (`ndn_cert::recovery`). Each test guards one
//! invariant:
//!
//! - a kit never contains or stores the root key;
//! - a kit whose key is not a recovery anchor cannot recover, and nothing is
//!   written;
//! - a mistyped word list is refused (checksum) before anything can sign;
//! - `destroyed` keeps the certificates the old CA issued valid;
//! - `compromised` makes every chain through the old CA invalid, and keeps
//!   no recovery anchor the operator did not vouch for;
//! - holders of version `N` adopt the recovered `N+1` by continuity, and
//!   refuse a version the revoked old root signs;
//! - a node offline across a recovery and a later root-signed version
//!   catches up version by version, and a forged or missing version in
//!   between stops it with nothing changed;
//! - after a recovery the newest version is signed by the new root, so a
//!   device holding nothing adopts with the root's expected fingerprint;
//! - revoking a kit removes its power.

use std::sync::Arc;

use bytes::Bytes;
use ndn_cert::{
    AnchorLink, CaExchange, CatchUpStop, CertError, ContextRefresh, FileKit,
    MAX_CATCH_UP_VERSIONS, NewRootStore, OldRoot, PersistedNamespace, RecoveryError,
    RecoverySeed, RefreshError, RootSecret, RootStore, UpdateRefusal, add_recovery_anchor,
    anchor_fingerprint, bump_context_revoking, init_namespace_in_pib, open_context_update,
    rdr_metadata_name, read_stored_context, recover_namespace_in_pib, recovery_anchor,
    recovery_version, refresh_context, remove_recovery_anchor, seal_file_kit,
};
use ndn_packet::encode::DataBuilder;
use ndn_packet::{Data, Interest, Name};
use ndn_security::{
    CertCache, Certificate, Ed25519Signer, FilePib, KeyRole, Keyring, SecurityManager,
    SignedTrustContext, Signer, ValidationResult, Validator,
};

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// A root device: namespace /home/bob, plaintext root (so the test can read
/// it), and its stored context.
struct RootDevice {
    _dir: tempfile::TempDir,
    pib: FilePib,
    out: PersistedNamespace,
}

impl RootDevice {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let pib = FilePib::new(dir.path()).unwrap();
        let out = init_namespace_in_pib(&pib, &n("/home/bob"), "desk", false, &NewRootStore::File)
            .await
            .unwrap();
        Self {
            _dir: dir,
            pib,
            out,
        }
    }

    async fn root(&self) -> Arc<dyn Signer> {
        RootStore::open(&self.pib)
            .unwrap()
            .unwrap()
            .signer(None)
            .await
            .unwrap()
    }

    fn held(&self) -> (SignedTrustContext, Data) {
        read_stored_context(self.pib.root(), &n("/home/bob"))
            .unwrap()
            .unwrap()
    }

    /// A member device certificate the CA issues now.
    async fn member_cert(&self) -> Certificate {
        let mgr = SecurityManager::new();
        mgr.register_signer(
            self.out.ca_key.clone(),
            self.pib.get_signer(&self.out.ca_key).unwrap(),
        );
        let member =
            ndn_security::Ed25519Signer::from_seed(&[9; 32], n("/home/bob/member/phone/KEY/k1"));
        mgr.certify_as(
            &n("/home/bob/member/phone/KEY/k1"),
            bytes::Bytes::copy_from_slice(&member.public_key_bytes()),
            &self.out.ca_key,
            30 * 86_400 * 1000,
            ndn_security::cert_name::NDNCERT_ISSUER,
            None,
        )
        .await
        .unwrap()
    }
}

/// Add a word kit to the root device's context; returns the seed and the
/// new version's Data.
async fn add_word_kit(root_dev: &RootDevice, held: &Data) -> (RecoverySeed, Data) {
    let seed = RecoverySeed::generate().unwrap();
    let anchor = recovery_anchor(Arc::new(seed.signer(&n("/home/bob"))))
        .await
        .unwrap();
    let bump = add_recovery_anchor(root_dev.root().await.as_ref(), held, &anchor)
        .await
        .unwrap();
    (seed, bump.data)
}

fn open(data: &Data) -> SignedTrustContext {
    futures::executor::block_on(SignedTrustContext::open_signed(data))
        .unwrap()
        .0
}

/// Whether `cert` validates under `ctx`, with `issuers` known.
async fn validates(ctx: SignedTrustContext, cert: &Certificate, issuers: &[&Certificate]) -> bool {
    let keyring = Arc::new(Keyring::new());
    assert!(keyring.adopt(Arc::new(ctx)));
    let validator = Validator::with_keyring(keyring, Arc::new(CertCache::new()), None, 8);
    for issuer in issuers {
        validator.cert_cache().insert((*issuer).clone());
    }
    let data = Data::decode(cert.data_wire().unwrap()).unwrap();
    matches!(
        validator.validate_chain_cached(&data).await.0,
        ValidationResult::Valid(_)
    )
}

#[tokio::test]
async fn a_kit_never_contains_or_stores_the_root_key() {
    let root_dev = RootDevice::new().await;
    let root_pkcs8 = root_dev
        .pib
        .export_pkcs8(&root_dev.out.init.anchor_key)
        .unwrap();
    let root_seed = ndn_security::safebag::pkcs8_to_ed25519_seed(&root_pkcs8).unwrap();
    let before: Vec<_> = std::fs::read_dir(root_dev.pib.root()).unwrap().collect();

    let (_, held) = root_dev.held();
    let seed = RecoverySeed::generate().unwrap();
    let kit = seed.signer(&n("/home/bob"));
    let anchor = recovery_anchor(Arc::new(seed.signer(&n("/home/bob"))))
        .await
        .unwrap();
    assert_ne!(
        kit.public_key_bytes()[..],
        root_dev.out.init.anchor.public_key[..]
    );
    assert!(kit.key_name().has_prefix(&n("/home/bob/KEY")));

    // The words encode the kit's seed, not the root's.
    let words = seed.to_words();
    let back = RecoverySeed::from_words(&words).unwrap();
    assert_eq!(
        back.signer(&n("/home/bob")).public_key_bytes(),
        kit.public_key_bytes()
    );
    assert_ne!(
        RecoverySeed::from_words(&words)
            .unwrap()
            .signer(&Name::root())
            .public_key_bytes(),
        ndn_security::Ed25519Signer::from_seed(&root_seed, Name::root()).public_key_bytes()
    );

    // A file kit holds the recovery key and nothing of the root.
    let uri = seal_file_kit(
        &seed,
        &anchor,
        &n("/home/bob"),
        None,
        &RootSecret::new(b"kit".to_vec()),
    )
    .unwrap();
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), &uri).unwrap();
    let opened = FileKit::read(file.path())
        .unwrap()
        .open(&RootSecret::new(b"kit".to_vec()))
        .unwrap();
    assert_eq!(opened.public_key_bytes(), kit.public_key_bytes());
    let sealed = opened.to_pkcs8_der().unwrap();
    assert!(!contains(&sealed, &root_seed));
    assert!(!contains(uri.as_bytes(), &root_seed) && !contains(uri.as_bytes(), &root_pkcs8));

    // Adding it changes the context only; the PIB gains no key.
    let bump = add_recovery_anchor(root_dev.root().await.as_ref(), &held, &anchor)
        .await
        .unwrap();
    assert!(
        bump.context
            .has_key_role(&anchor.key_name(), KeyRole::RECOVERY_ANCHOR)
    );
    assert!(!root_dev.pib.has_private_key(&anchor.key_name()));
    let after: Vec<_> = std::fs::read_dir(root_dev.pib.root()).unwrap().collect();
    assert_eq!(before.len(), after.len());
}

#[tokio::test]
async fn a_kit_that_is_not_a_recovery_anchor_cannot_recover() {
    let root_dev = RootDevice::new().await;
    let (_, held) = root_dev.held();
    let (_, with_kit) = add_word_kit(&root_dev, &held).await;
    let stranger = RecoverySeed::generate().unwrap().signer(&n("/home/bob"));

    let replacement = tempfile::tempdir().unwrap();
    let pib = FilePib::new(replacement.path()).unwrap();
    let keys_before = pib.list_keys().unwrap();
    let err = recover_namespace_in_pib(
        &pib,
        &with_kit,
        &stranger,
        "phone",
        OldRoot::Destroyed,
        &[],
        &NewRootStore::File,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, RecoveryError::NotARecoveryAnchor { .. }),
        "{err}"
    );
    // The root itself is an anchor, but not a recovery key.
    let root = root_dev.root().await;
    let err = recovery_version(
        root.as_ref(),
        &with_kit,
        &ndn_cert::RecoveryPlan {
            new_root: &root_dev.out.init.anchor,
            new_root_device_keys: &[],
            old_root: OldRoot::Destroyed,
            kept_kits: &[],
        },
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, RecoveryError::NotARecoveryAnchor { .. }),
        "{err}"
    );
    // Nothing was written.
    assert!(RootStore::open(&pib).unwrap().is_none());
    assert_eq!(pib.list_keys().unwrap(), keys_before);
    assert!(!replacement.path().join("ca").exists());
}

/// BIP39 test vector: 32 bytes of 0x7f.
const VECTOR: &str = "legal winner thank year wave sausage worth useful legal winner thank \
                      year wave sausage worth useful legal winner thank year wave sausage \
                      worth title";

#[test]
fn a_mistyped_word_list_is_refused() {
    // The words are the seed: the test vector is the key of 0x7f × 32.
    let seed = RecoverySeed::from_words(VECTOR).unwrap();
    assert_eq!(
        seed.signer(&Name::root()).public_key_bytes(),
        ndn_security::Ed25519Signer::from_seed(&[0x7f; 32], Name::root()).public_key_bytes()
    );
    assert_eq!(
        *seed.to_words(),
        VECTOR.split_whitespace().collect::<Vec<_>>().join(" ")
    );
    // Case and spacing are forgiven.
    assert!(RecoverySeed::from_words(&format!("  {}  ", VECTOR.to_uppercase())).is_ok());

    let list: Vec<&str> = VECTOR.split_whitespace().collect();
    let mut swapped = list.clone();
    swapped.swap(0, 1);
    let mut typo = list.clone();
    typo[2] = "thing";
    let mut unknown = list.clone();
    unknown[0] = "notaword";
    for bad in [
        swapped.join(" "),
        typo.join(" "),
        unknown.join(" "),
        list[..23].join(" "),
    ] {
        assert!(
            matches!(
                RecoverySeed::from_words(&bad),
                Err(RecoveryError::BadWords(_))
            ),
            "{bad}"
        );
    }
}

/// Recover from `held` with `seed` into a fresh replacement PIB.
async fn recover(
    held: &Data,
    seed: &RecoverySeed,
    old_root: OldRoot,
) -> (tempfile::TempDir, ndn_cert::RecoveredNamespace) {
    let dir = tempfile::tempdir().unwrap();
    let pib = FilePib::new(dir.path()).unwrap();
    let recovered = recover_namespace_in_pib(
        &pib,
        held,
        &seed.signer(&n("/home/bob")),
        "phone",
        old_root,
        &[],
        &NewRootStore::File,
    )
    .await
    .unwrap();
    (dir, recovered)
}

#[tokio::test]
async fn destroyed_keeps_the_old_cas_certificates_valid() {
    let root_dev = RootDevice::new().await;
    let (_, held) = root_dev.held();
    let (seed, with_kit) = add_word_kit(&root_dev, &held).await;
    let member = root_dev.member_cert().await;
    let ca = &root_dev.out.ca_cert;

    let (_dir, recovered) = recover(&with_kit, &seed, OldRoot::Destroyed).await;
    let next = recovered.version.bump.context;
    assert!(
        next.is_anchor(&root_dev.out.init.anchor_key),
        "the old root stays an anchor"
    );
    assert!(next.is_anchor(&recovered.anchor.key_name()));
    assert!(next.revocations().is_empty());
    assert!(
        validates(open(&recovered.version.bump.data), &member, &[ca]).await,
        "a member certificate of the old CA still validates"
    );
    // The new CA's chain validates too, and its key is fresh.
    assert_ne!(recovered.ca_key, root_dev.out.ca_key);
    assert!(
        validates(
            open(&recovered.version.bump.data),
            &recovered.device_cert,
            &[&recovered.ca_cert]
        )
        .await
    );
}

#[tokio::test]
async fn compromised_invalidates_every_chain_through_the_old_ca() {
    let root_dev = RootDevice::new().await;
    let (_, held) = root_dev.held();
    let (seed, with_kit) = add_word_kit(&root_dev, &held).await;
    let member = root_dev.member_cert().await;
    let ca = &root_dev.out.ca_cert;
    assert!(validates(open(&with_kit), &member, &[ca]).await);

    let (_dir, recovered) = recover(&with_kit, &seed, OldRoot::Compromised).await;
    let next = open(&recovered.version.bump.data);
    assert!(!next.is_anchor(&root_dev.out.init.anchor_key));
    for key in [
        &root_dev.out.init.anchor_key,
        &root_dev.out.ca_key,
        &root_dev.out.device_key,
    ] {
        assert!(next.is_revoked(key), "{key} revoked");
    }
    assert!(
        !validates(next, &member, &[ca]).await,
        "old-CA chain refused"
    );
    assert!(
        validates(
            open(&recovered.version.bump.data),
            &recovered.device_cert,
            &[&recovered.ca_cert]
        )
        .await,
        "the new CA's chain validates"
    );
}

#[tokio::test]
async fn holders_adopt_the_recovered_version_and_refuse_the_revoked_old_root() {
    let root_dev = RootDevice::new().await;
    let (_, held) = root_dev.held();
    let (seed, with_kit) = add_word_kit(&root_dev, &held).await;
    let (_dir, recovered) = recover(&with_kit, &seed, OldRoot::Compromised).await;
    let n1 = &recovered.version.bump.data;

    // A node holding N adopts N+1 by continuity.
    let held_n = open(&with_kit);
    let (adopted, signer) = open_context_update(&held_n, n1).await.unwrap();
    assert_eq!(adopted.version(), held_n.version() + 1);
    assert_eq!(signer.key_name(), recovered.version.recovery_key);

    // The old root signs a newer version (listing itself again): refused.
    let content = n1.content().unwrap();
    let forged = SignedTrustContext::decode_content(content, held_n.version() + 2).unwrap();
    forged.add_anchor(root_dev.out.init.anchor.clone());
    let forged = forged
        .sign_into_data_async(root_dev.root().await.as_ref())
        .await
        .unwrap();
    let refused = open_context_update(&open(n1), &forged).await.unwrap_err();
    assert!(
        matches!(refused, UpdateRefusal::NotSignedByHeldAnchor { .. }),
        "{refused}"
    );
}

#[tokio::test]
async fn a_compromised_recovery_keeps_no_kit_nobody_vouched_for() {
    let ns = n("/home/bob");
    let root_dev = RootDevice::new().await;
    let (_, held) = root_dev.held();
    let (seed, with_kit) = add_word_kit(&root_dev, &held).await;
    // Whoever holds the stolen root adds a kit of their own; the owner has
    // a spare kit too.
    let (planted, with_planted) = add_word_kit(&root_dev, &with_kit).await;
    let (spare, with_spare) = add_word_kit(&root_dev, &with_planted).await;
    let planted = planted.signer(&ns);
    let spare = spare.signer(&ns);

    let dir = tempfile::tempdir().unwrap();
    let pib = FilePib::new(dir.path()).unwrap();
    let recovered = recover_namespace_in_pib(
        &pib,
        &with_spare,
        &seed.signer(&ns),
        "phone",
        OldRoot::Compromised,
        std::slice::from_ref(spare.key_name()),
        &NewRootStore::File,
    )
    .await
    .unwrap();
    let n1 = open(&recovered.version.bump.data);
    assert!(!n1.is_anchor(planted.key_name()));
    assert!(n1.is_revoked(planted.key_name()));
    assert!(n1.is_anchor(spare.key_name()) && n1.is_anchor(seed.signer(&ns).key_name()));

    // Nothing it did not vouch for can sign the next version; a kept kit can.
    let newest = open(&recovered.root_version.data);
    let content = recovered.root_version.data.content().unwrap();
    for (signer, adopted) in [(&planted, false), (&spare, true)] {
        let next = SignedTrustContext::decode_content(content, newest.version() + 1)
            .unwrap()
            .sign_into_data_async(signer)
            .await
            .unwrap();
        assert_eq!(
            open_context_update(&newest, &next).await.is_ok(),
            adopted,
            "{}",
            signer.key_name()
        );
    }
}

#[tokio::test]
async fn a_kit_to_keep_that_is_no_recovery_anchor_is_refused_before_anything_is_written() {
    let root_dev = RootDevice::new().await;
    let (_, held) = root_dev.held();
    let (seed, with_kit) = add_word_kit(&root_dev, &held).await;
    let stranger = RecoverySeed::generate().unwrap().signer(&n("/home/bob"));
    let kit_key = seed.signer(&n("/home/bob")).key_name().clone();

    let replacement = tempfile::tempdir().unwrap();
    let pib = FilePib::new(replacement.path()).unwrap();
    let keys_before = pib.list_keys().unwrap();
    for (old_root, kept) in [
        (OldRoot::Compromised, stranger.key_name().clone()),
        (OldRoot::Destroyed, kit_key),
    ] {
        recover_namespace_in_pib(
            &pib,
            &with_kit,
            &seed.signer(&n("/home/bob")),
            "phone",
            old_root,
            &[kept],
            &NewRootStore::File,
        )
        .await
        .unwrap_err();
    }
    assert!(RootStore::open(&pib).unwrap().is_none());
    assert_eq!(pib.list_keys().unwrap(), keys_before);
    assert!(!replacement.path().join("ca").exists());
}

#[tokio::test]
async fn revoking_a_kit_removes_its_power() {
    let root_dev = RootDevice::new().await;
    let (_, held) = root_dev.held();
    let (seed, with_kit) = add_word_kit(&root_dev, &held).await;
    let kit = seed.signer(&n("/home/bob"));
    let kit_key = kit.key_name().clone();

    let removed = remove_recovery_anchor(root_dev.root().await.as_ref(), &with_kit, &kit_key)
        .await
        .unwrap();
    let after = open(&removed.data);
    assert!(!after.is_anchor(&kit_key));
    assert!(after.is_revoked(&kit_key));
    assert!(!after.has_key_role(&kit_key, KeyRole::RECOVERY_ANCHOR));

    // It cannot recover any more…
    let replacement = tempfile::tempdir().unwrap();
    let pib = FilePib::new(replacement.path()).unwrap();
    let err = recover_namespace_in_pib(
        &pib,
        &removed.data,
        &kit,
        "phone",
        OldRoot::Destroyed,
        &[],
        &NewRootStore::File,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, RecoveryError::NotARecoveryAnchor { .. }),
        "{err}"
    );
    // …and a version it signs (listing itself again) is refused by holders.
    let forged =
        SignedTrustContext::decode_content(removed.data.content().unwrap(), after.version() + 1)
            .unwrap();
    forged.add_anchor(
        recovery_anchor(Arc::new(seed.signer(&n("/home/bob"))))
            .await
            .unwrap(),
    );
    let forged = forged.sign_into_data_async(&kit).await.unwrap();
    let refused = open_context_update(&after, &forged).await.unwrap_err();
    assert!(
        matches!(refused, UpdateRefusal::NotSignedByHeldAnchor { .. }),
        "{refused}"
    );
}

/// A node that kept every version it held, as a refreshing node reaches it:
/// RDR metadata naming the newest of `versions`, and each of them by its
/// exact name. Records the names asked for.
struct Upstream {
    versions: Vec<Bytes>,
    asked: Vec<Name>,
}

impl Upstream {
    fn serving(versions: &[&Data]) -> Self {
        Self {
            versions: versions.iter().map(|d| d.raw().clone()).collect(),
            asked: Vec::new(),
        }
    }
}

impl CaExchange for Upstream {
    async fn express(&mut self, interest: Bytes) -> Result<Data, CertError> {
        let interest = Interest::decode(interest).unwrap();
        self.asked.push((*interest.name).clone());
        let meta_name = rdr_metadata_name(&n("/home/bob"));
        if *interest.name == meta_name {
            let newest = Data::decode(self.versions.last().unwrap().clone()).unwrap();
            let version = newest.name.components().last().unwrap().as_version().unwrap();
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

/// `Upstream` seen through this node's validating forwarder, which drops
/// what its validator does not admit (as `ndn-fwd` does).
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

/// A node holding version `held`.
fn holding(held: &Data) -> Arc<Keyring> {
    let keyring = Arc::new(Keyring::new());
    assert!(keyring.adopt(Arc::new(open(held))));
    keyring
}

/// A node offline across a recovery and a later root-signed version: it
/// holds `N`; the namespace serves `N+1` (the recovery key), `N+2` (the new
/// root, same content) and `N+3` (the new root revokes a key). `N+3` is not
/// signed by an anchor of `N`, so the node follows `N+1`, `N+2`, `N+3` by
/// exact name, each under the continuity rule from the one before, and
/// adopts `N+3` — with or without a validating forwarder. A forged `N+1`,
/// a missing `N+1`, or a newest version further ahead than a walk goes,
/// stops it and changes nothing.
#[tokio::test]
async fn a_node_offline_across_a_recovery_catches_up_version_by_version() {
    let ns = n("/home/bob");
    let root_dev = RootDevice::new().await;
    let (_, held) = root_dev.held();
    let (seed, with_kit) = add_word_kit(&root_dev, &held).await;
    let (_dir, recovered) = recover(&with_kit, &seed, OldRoot::Destroyed).await;
    let new_root = recovered.root_store.signer(None).await.unwrap();
    let n1 = &recovered.version.bump.data;
    let n2 = &recovered.root_version.data;
    let revoked = n("/home/bob/member/phone/KEY/k1");
    let n3 = bump_context_revoking(new_root.as_ref(), n2, std::slice::from_ref(&revoked))
        .await
        .unwrap()
        .unwrap()
        .data;
    let v = open(&with_kit).version();
    assert!(matches!(
        open_context_update(&open(&with_kit), &n3).await,
        Err(UpdateRefusal::NotSignedByHeldAnchor { .. })
    ));

    let node = holding(&with_kit);
    let mut upstream = Upstream::serving(&[&with_kit, n1, n2, &n3]);
    let Ok(ContextRefresh::Updated(update)) = refresh_context(&node, None, &mut upstream, &ns).await
    else {
        panic!("the node did not follow the recovery");
    };
    let walked: Vec<u64> = update.walked.iter().map(|s| s.context.version()).collect();
    assert_eq!(walked, [v + 1, v + 2]);
    assert_eq!(update.walked[0].signer.key_name(), recovered.version.recovery_key);
    assert_eq!(update.walked[1].signer.key_name(), recovered.anchor.key_name());
    assert_eq!((update.previous, update.context.version()), (v, v + 3));
    assert_eq!(node.version_of(&ns), Some(v + 3));
    assert!(node.contexts()[0].is_revoked(&revoked));

    // Through a validating forwarder, told to expect each version in turn.
    let node = holding(&with_kit);
    let validator = Validator::with_keyring(Arc::clone(&node), Arc::new(CertCache::new()), None, 4);
    let mut forwarded = Forwarded {
        upstream: Upstream::serving(&[&with_kit, n1, n2, &n3]),
        forwarder: &validator,
    };
    let res = refresh_context(&node, Some(&validator), &mut forwarded, &ns).await;
    assert!(matches!(res, Ok(ContextRefresh::Updated(_))), "{res:?}");
    assert_eq!(node.version_of(&ns), Some(v + 3));

    // A forged N+1: a stranger signs N's content, listing itself.
    let stranger: Arc<dyn Signer> =
        Arc::new(Ed25519Signer::from_seed(&[7; 32], n("/home/bob/KEY/stranger")));
    let forged = SignedTrustContext::decode_content(with_kit.content().unwrap(), v + 1).unwrap();
    forged.add_anchor(recovery_anchor(Arc::clone(&stranger)).await.unwrap());
    let forged = forged.sign_into_data_async(stranger.as_ref()).await.unwrap();
    let node = holding(&with_kit);
    let mut upstream = Upstream::serving(&[&with_kit, &forged, n2, &n3]);
    match refresh_context(&node, None, &mut upstream, &ns).await {
        Err(RefreshError::Refused {
            refusal:
                UpdateRefusal::CatchUp {
                    stop: CatchUpStop::Refused { version, .. },
                    ..
                },
            ..
        }) => assert_eq!(version, v + 1),
        other => panic!("a forged intermediate version was not refused: {other:?}"),
    }
    assert_eq!(node.version_of(&ns), Some(v));

    // N+1 served by nobody: N+2 does not follow from N without it.
    let mut upstream = Upstream::serving(&[&with_kit, n2, &n3]);
    match refresh_context(&node, None, &mut upstream, &ns).await {
        Err(RefreshError::Refused {
            refusal:
                UpdateRefusal::CatchUp {
                    stop:
                        CatchUpStop::Missing {
                            first,
                            last,
                            version,
                            ..
                        },
                    ..
                },
            ..
        }) => assert_eq!((first, last, version), (v + 1, v + 1, v + 2)),
        other => panic!("a missing intermediate version was not reported: {other:?}"),
    }
    assert_eq!(node.version_of(&ns), Some(v));

    // Further ahead than a walk goes: refused before any version in
    // between is fetched.
    let far = v + MAX_CATCH_UP_VERSIONS + 2;
    let far = SignedTrustContext::decode_content(n3.content().unwrap(), far)
        .unwrap()
        .sign_into_data_async(new_root.as_ref())
        .await
        .unwrap();
    let mut upstream = Upstream::serving(&[&with_kit, &far]);
    let res = refresh_context(&node, None, &mut upstream, &ns).await;
    assert!(
        matches!(
            res,
            Err(RefreshError::Refused {
                refusal: UpdateRefusal::CatchUp {
                    stop: CatchUpStop::TooFar { .. },
                    ..
                },
                ..
            })
        ),
        "{res:?}"
    );
    assert_eq!(upstream.asked, [rdr_metadata_name(&ns), (*far.name).clone()]);
    assert_eq!(node.version_of(&ns), Some(v));
}

/// After a recovery the newest version is `N+2`, signed by the new root:
/// a device holding nothing adopts it from a link or invite naming the
/// root's fingerprint as the expected fingerprint. While `N+1` (signed by
/// the recovery key) was the newest, that link was refused — the expected
/// fingerprint must be the signer's, never merely an anchor the fetched
/// context lists.
#[tokio::test]
async fn after_a_recovery_the_root_fingerprint_adopts_a_fresh_device() {
    let ns = n("/home/bob");
    let root_dev = RootDevice::new().await;
    let (_, held) = root_dev.held();
    let (seed, with_kit) = add_word_kit(&root_dev, &held).await;
    let (_dir, recovered) = recover(&with_kit, &seed, OldRoot::Destroyed).await;
    let n1 = &recovered.version.bump.data;
    let n2 = &recovered.root_version.data;
    assert_eq!(open(n2).version(), open(n1).version() + 1);
    for key in [&recovered.anchor.key_name(), &recovered.version.recovery_key] {
        assert!(open(n2).is_anchor(key), "{key} is an anchor of N+2 as of N+1");
    }
    let link = AnchorLink {
        namespace: ns.clone(),
        expected_fingerprint: anchor_fingerprint(&recovered.anchor),
        min_version: None,
        context_data: None,
    };

    let fresh = Keyring::new();
    let mut upstream = Upstream::serving(&[&with_kit, n1]);
    assert!(
        ndn_cert::adopt_anchor_link(&fresh, None, &mut upstream, &link)
            .await
            .is_err(),
        "N+1 is signed by the recovery key, not the root the link names"
    );
    assert!(fresh.is_empty());

    let mut upstream = Upstream::serving(&[&with_kit, n1, n2]);
    let adopted = ndn_cert::adopt_anchor_link(&fresh, None, &mut upstream, &link)
        .await
        .unwrap();
    assert_eq!(adopted.context.version(), open(n2).version());
    assert_eq!(fresh.version_of(&ns), Some(open(n2).version()));
}
