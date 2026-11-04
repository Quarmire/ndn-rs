//! Revocation cuts across the versions the root device (or a recovery kit)
//! makes (`ndn_cert::context_update`, `ndn_cert::recovery`). Each test
//! guards one invariant:
//!
//! - a cut is signed only with the revocation of exactly its key, lists
//!   only that key's device log, names its public key, and carries its
//!   manifest when it has ranges;
//! - every producer of a version `N+1` from `N` carries every cut verbatim
//!   (another revocation, a schema update, a recovery kit added or revoked,
//!   a recovery's `N+1` and `N+2`, a re-admission of another key) — except
//!   an orphan cut (no revocation names its key), which a revocation and a
//!   recovery drop, and which never decides a key revoked later;
//! - a re-admission adds exact full names to the cut of a key revoked with
//!   one, never anything else, and signs nothing when the cut accepts them
//!   already;
//! - a compromised recovery takes cuts only for keys it newly revokes; the
//!   new CA re-certifies a key revoked with a cut only from a certificate
//!   whose public key is the one the cut names.

use std::sync::Arc;

use bytes::Bytes;
use ndn_cert::{
    ApprovalPolicy, BumpError, NewRootStore, OldRoot, PersistedNamespace, RecoveryError,
    RecoveryPlan, RecoverySeed, RootStore, add_recovery_anchor, bump_context_readmitting,
    bump_context_revoking, bump_context_schema, device_log_of, init_namespace_in_pib,
    namespace_schema, read_stored_context, recertify_cut_keys, recertify_cut_keys_in_pib,
    recover_namespace_in_pib, recovery_anchor, recovery_version, reissue_version,
    remove_recovery_anchor,
};
use ndn_packet::{Data, Name, NameComponent, tlv_type};
use ndn_security::{
    Certificate, Ed25519Signer, FilePib, LinkPolicy, RevocationCut, SecurityManager,
    SignedTrustContext, Signer, cut_manifest, public_key_digest,
};

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

/// `name` with an implicit digest component of `fill` octets: a full name.
fn full(name: &Name, fill: u8) -> Name {
    name.clone().append_component(NameComponent::new(
        tlv_type::IMPLICIT_SHA256,
        Bytes::from(vec![fill; 32]),
    ))
}

/// The log entry `seq` of collection `collection` of `key`'s device.
fn entry(key: &Name, collection: &str, seq: u64) -> Name {
    device_log_of(key)
        .append(collection)
        .append_component(NameComponent::sequence_num(seq))
}

fn open(data: &Data) -> SignedTrustContext {
    futures::executor::block_on(SignedTrustContext::open_signed(data))
        .unwrap()
        .0
}

/// A root device: namespace /home/bob, root in the PIB (`file` store).
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

    fn held(&self) -> Data {
        read_stored_context(self.pib.root(), &n("/home/bob"))
            .unwrap()
            .unwrap()
            .1
    }

    /// A certificate of the member key `key` with the public key of seed
    /// `seed`, issued by the namespace CA now.
    async fn member_cert(&self, key: &Name, seed: u8) -> Certificate {
        let mgr = SecurityManager::new();
        mgr.register_signer(
            self.out.ca_key.clone(),
            self.pib.get_signer(&self.out.ca_key).unwrap(),
        );
        mgr.certify_as(
            key,
            public_key(seed),
            &self.out.ca_key,
            30 * 86_400 * 1000,
            ndn_security::cert_name::NDNCERT_ISSUER,
            None,
        )
        .await
        .unwrap()
    }

    /// `held` with a cut for `key` beside its revocations — and no
    /// revocation of `key` — signed by the root: an orphan cut, as only
    /// whoever held a compromised root would sign.
    async fn plant_orphan(&self, held: &Data, cut: &RevocationCut) -> Data {
        let ctx = open(held);
        SignedTrustContext::decode_content(held.content().unwrap(), ctx.version() + 1)
            .unwrap()
            .with_revocation_cut(cut.clone())
            .sign_into_data_async(self.root().await.as_ref())
            .await
            .unwrap()
    }
}

/// The public key of the Ed25519 key of seed `seed`.
fn public_key(seed: u8) -> Bytes {
    let signer = Ed25519Signer::from_seed(&[seed; 32], n("/k"));
    Bytes::copy_from_slice(&signer.public_key_bytes())
}

const PHONE_SEED: u8 = 3;
const TABLET_SEED: u8 = 4;

/// The cut of `key` (public key of seed `seed`) accepting seqs 1..=`last`
/// of its device's `notes`, with its manifest.
fn cut_of(key: &Name, last: u64, seed: u8) -> RevocationCut {
    let notes = device_log_of(key).append("notes");
    let entries: Vec<(Name, u64, [u8; 32])> = (1..=last)
        .map(|s| (notes.clone(), s, [s as u8; 32]))
        .collect();
    let built = cut_manifest::build(&n("/home/bob"), key, &entries).unwrap();
    let mut cut = RevocationCut::new(key.clone());
    cut.add_run(&notes, 1, last);
    cut.set_key_digest(public_key_digest(&public_key(seed)));
    cut.set_manifest(built.root).unwrap();
    cut
}

fn phone() -> Name {
    n("/home/bob/member/phone/KEY/p")
}

fn tablet() -> Name {
    n("/home/bob/member/tablet/KEY/t")
}

/// `held` with `key` revoked with `cut`, signed by the root.
async fn revoke_with(root_dev: &RootDevice, held: &Data, key: &Name, cut: &RevocationCut) -> Data {
    bump_context_revoking(
        root_dev.root().await.as_ref(),
        held,
        std::slice::from_ref(key),
        std::slice::from_ref(cut),
    )
    .await
    .unwrap()
    .expect("a new version")
    .data
}

/// A recovery plan installing `new_root`, keeping no other kit.
fn recovery_plan<'a>(
    new_root: &'a Certificate,
    old_root: OldRoot,
    cuts: &'a [RevocationCut],
) -> RecoveryPlan<'a> {
    RecoveryPlan {
        new_root,
        new_root_device_keys: &[],
        old_root,
        kept_kits: &[],
        cuts,
    }
}

/// A revocation with a cut signs both in one version; without one it keeps
/// today's meaning; a cut of another key, a cut after the key's
/// revocation, and a cut listing outside the key's device log are refused.
#[tokio::test]
async fn a_cut_is_signed_only_with_the_revocation_of_its_key() {
    let root_dev = RootDevice::new().await;
    let root = root_dev.root().await;
    let v1 = root_dev.held();
    let cut = cut_of(&phone(), 4, PHONE_SEED);

    let v2 = revoke_with(&root_dev, &v1, &phone(), &cut).await;
    let ctx = open(&v2);
    assert!(ctx.is_revoked(&phone()));
    assert_eq!(ctx.revocation_cut(&phone()), Some(&cut));

    let bare = bump_context_revoking(root.as_ref(), &v1, &[tablet()], &[])
        .await
        .unwrap()
        .unwrap();
    assert!(bare.context.is_revoked(&tablet()));
    assert!(bare.context.revocation_cut(&tablet()).is_none());

    let given = std::slice::from_ref(&cut);
    assert!(matches!(
        bump_context_revoking(root.as_ref(), &v1, &[tablet()], given).await,
        Err(BumpError::CutOtherKey { .. })
    ));
    assert!(matches!(
        bump_context_revoking(root.as_ref(), &v2, &[phone()], given).await,
        Err(BumpError::CutAfterRevocation { .. })
    ));
    let mut outside = RevocationCut::new(phone());
    outside.add_seq(&device_log_of(&tablet()).append("notes"), 1);
    assert!(matches!(
        bump_context_revoking(root.as_ref(), &v1, &[phone()], &[outside]).await,
        Err(BumpError::CutOutsideLog { .. })
    ));
}

/// S5-03, S5-05: a new cut names the public key that signed what it
/// accepts (CutKeyDigest), and a cut with ranges carries its manifest (the
/// digest of every entry they accept): a range alone binds names, not
/// bytes, and a cut without a key digest would excuse any key later
/// certified under the name. Both are refused before anything is signed.
#[tokio::test]
async fn a_new_cut_names_its_public_key_and_carries_its_manifest() {
    let root_dev = RootDevice::new().await;
    let root = root_dev.root().await;
    let v1 = root_dev.held();
    let notes = device_log_of(&phone()).append("notes");

    let mut names_only = RevocationCut::new(phone());
    names_only.add_run(&notes, 1, 4);
    names_only.set_key_digest(public_key_digest(&public_key(PHONE_SEED)));
    assert!(matches!(
        bump_context_revoking(root.as_ref(), &v1, &[phone()], &[names_only]).await,
        Err(BumpError::CutWithoutManifest { .. })
    ));

    let full_cut = cut_of(&phone(), 4, PHONE_SEED);
    let mut no_digest = RevocationCut::new(phone());
    no_digest.add_run(&notes, 1, 4);
    no_digest
        .set_manifest(full_cut.manifest().unwrap().clone())
        .unwrap();
    assert!(matches!(
        bump_context_revoking(root.as_ref(), &v1, &[phone()], &[no_digest]).await,
        Err(BumpError::CutWithoutKeyDigest { .. })
    ));
}

/// S5-05: an orphan cut (one no revocation names, which only whoever held
/// a compromised root signs) never decides which packets of its key stay
/// accepted: revoking the key without giving its own cut is refused, and a
/// revocation of another key does not carry the orphan.
#[tokio::test]
async fn an_orphan_cut_is_never_carried_into_a_revocation() {
    let root_dev = RootDevice::new().await;
    let root = root_dev.root().await;
    let planted = root_dev
        .plant_orphan(&root_dev.held(), &cut_of(&tablet(), 9, 99))
        .await;

    assert!(matches!(
        bump_context_revoking(root.as_ref(), &planted, &[tablet()], &[]).await,
        Err(BumpError::OrphanCut { .. })
    ));
    let own = cut_of(&tablet(), 2, TABLET_SEED);
    let with_own = revoke_with(&root_dev, &planted, &tablet(), &own).await;
    assert_eq!(open(&with_own).revocation_cut(&tablet()), Some(&own));

    let other = bump_context_revoking(root.as_ref(), &planted, &[phone()], &[])
        .await
        .unwrap()
        .unwrap();
    assert!(
        other.context.revocation_cut(&tablet()).is_none(),
        "the orphan cut is not carried"
    );
}

/// Every version the root device makes from one holding a cut carries it
/// verbatim: another revocation, a schema update, a recovery kit added and
/// a kit revoked, a re-admission into another key's cut.
#[tokio::test]
async fn every_root_version_carries_every_cut() {
    let root_dev = RootDevice::new().await;
    let root = root_dev.root().await;
    let cut = cut_of(&phone(), 4, PHONE_SEED);
    let v2 = revoke_with(&root_dev, &root_dev.held(), &phone(), &cut).await;
    let carries = |data: &Data| assert_eq!(open(data).revocation_cut(&phone()), Some(&cut));

    let tablet_cut = cut_of(&tablet(), 2, TABLET_SEED);
    let v3 = revoke_with(&root_dev, &v2, &tablet(), &tablet_cut).await;
    carries(&v3);

    let schema = namespace_schema(&n("/home/bob")).unwrap().blobs();
    let link = LinkPolicy {
        roles: vec!["admin".into(), "node".into()],
        relay_roles: vec!["node".into()],
        enrollment_links: true,
        direct_paths: true,
        direct_pairs: LinkPolicy::default_direct_pairs(),
    };
    let hint = ApprovalPolicy::default().to_hint();
    let v4 = bump_context_schema(root.as_ref(), &v3, &schema, &hint, Some(&link), None, true)
        .await
        .unwrap()
        .expect("another link policy")
        .bump
        .data;
    carries(&v4);

    let seed = RecoverySeed::generate().unwrap();
    let kit = recovery_anchor(Arc::new(seed.signer(&n("/home/bob"))))
        .await
        .unwrap();
    let v5 = add_recovery_anchor(root.as_ref(), &v4, &kit)
        .await
        .unwrap()
        .data;
    carries(&v5);
    let v6 = remove_recovery_anchor(root.as_ref(), &v5, &kit.key_name())
        .await
        .unwrap()
        .data;
    carries(&v6);

    let readmitted = full(&entry(&tablet(), "notes", 9), 7);
    let v7 = bump_context_readmitting(
        root.as_ref(),
        &v6,
        &tablet(),
        std::slice::from_ref(&readmitted),
    )
    .await
    .unwrap()
    .expect("a new version")
    .data;
    carries(&v7);
    assert_eq!(
        open(&v7).revocation_cut(&tablet()).unwrap().ranges(),
        tablet_cut.ranges(),
        "a re-admission never changes the ranges"
    );
}

/// A re-admission adds exact full names of the key's device log to its cut
/// and nothing else; names the cut accepts already sign nothing; a key
/// without a cut, a name without its digest, and a name outside the key's
/// device log are refused.
#[tokio::test]
async fn a_readmission_adds_exact_names_to_an_existing_cut_only() {
    let root_dev = RootDevice::new().await;
    let root = root_dev.root().await;
    let cut = cut_of(&phone(), 4, PHONE_SEED);
    let v2 = revoke_with(&root_dev, &root_dev.held(), &phone(), &cut).await;

    let late = full(&entry(&phone(), "notes", 7), 1);
    let snapshot = full(
        &device_log_of(&phone()).append_component(NameComponent::sequence_num(2)),
        2,
    );
    let bump = bump_context_readmitting(
        root.as_ref(),
        &v2,
        &phone(),
        &[late.clone(), snapshot.clone(), late.clone()],
    )
    .await
    .unwrap()
    .expect("a new version");
    let readmitted = bump.context.revocation_cut(&phone()).unwrap();
    assert_eq!(readmitted.ranges(), cut.ranges());
    let mut exact = readmitted.exact().to_vec();
    exact.sort();
    let mut expected = vec![late.clone(), snapshot];
    expected.sort();
    assert_eq!(exact, expected);
    assert!(bump.added.is_empty(), "no key is revoked by it");

    // Present already, or accepted by a range: nothing to sign.
    let in_range = full(&entry(&phone(), "notes", 3), 9);
    assert!(
        bump_context_readmitting(root.as_ref(), &bump.data, &phone(), &[late, in_range])
            .await
            .unwrap()
            .is_none()
    );

    let v1 = root_dev.held();
    assert!(matches!(
        bump_context_readmitting(
            root.as_ref(),
            &v1,
            &phone(),
            &[full(&entry(&phone(), "notes", 7), 1)]
        )
        .await,
        Err(BumpError::ReadmitNoCut { .. })
    ));
    let bare = bump_context_revoking(root.as_ref(), &v2, &[tablet()], &[])
        .await
        .unwrap()
        .unwrap()
        .data;
    assert!(matches!(
        bump_context_readmitting(
            root.as_ref(),
            &bare,
            &tablet(),
            &[full(&entry(&tablet(), "notes", 1), 1)]
        )
        .await,
        Err(BumpError::ReadmitRevokedWithoutCut { .. })
    ));
    assert!(matches!(
        bump_context_readmitting(root.as_ref(), &v2, &phone(), &[entry(&phone(), "notes", 7)])
            .await,
        Err(BumpError::ReadmitNotFullName { .. })
    ));
    for outside in [
        full(&entry(&tablet(), "notes", 7), 1),
        full(&n("/home/bob/member/phone/summary"), 1),
        full(&device_log_of(&phone()), 1),
    ] {
        assert!(
            matches!(
                bump_context_readmitting(
                    root.as_ref(),
                    &v2,
                    &phone(),
                    std::slice::from_ref(&outside)
                )
                .await,
                Err(BumpError::ReadmitOutsideLog { .. })
            ),
            "{outside}"
        );
    }
    assert!(matches!(
        bump_context_readmitting(
            root.as_ref(),
            &v2,
            &n("/home/alice/member/phone/KEY/p"),
            &[]
        )
        .await,
        Err(BumpError::NotAKeyOfNamespace { .. })
    ));
}

/// A recovery's `N+1` and `N+2` carry the held cuts (old root destroyed or
/// compromised); with it compromised a cut is taken for a key it newly
/// revokes, and refused for any other key, twice for one key, or at all
/// with the old root destroyed. An orphan cut the held version carries
/// (S5-05: planted by whoever held the old root) is dropped from both and
/// reported.
#[tokio::test]
async fn a_recovery_carries_every_cut_and_takes_cuts_only_for_keys_it_revokes() {
    let root_dev = RootDevice::new().await;
    let root = root_dev.root().await;
    let ns = n("/home/bob");
    let cut = cut_of(&phone(), 4, PHONE_SEED);
    let v2 = revoke_with(&root_dev, &root_dev.held(), &phone(), &cut).await;
    let seed = RecoverySeed::generate().unwrap();
    let kit = recovery_anchor(Arc::new(seed.signer(&ns))).await.unwrap();
    let v3 = add_recovery_anchor(root.as_ref(), &v2, &kit)
        .await
        .unwrap()
        .data;
    let v3 = root_dev.plant_orphan(&v3, &cut_of(&tablet(), 9, 99)).await;

    let new_root_mgr = SecurityManager::new();
    let new_root_key = n("/home/bob/KEY/root2");
    new_root_mgr.generate_ed25519(new_root_key.clone()).unwrap();
    let new_root = new_root_mgr.get_signer_sync(&new_root_key).unwrap();
    let new_anchor = new_root_mgr
        .issue_self_signed_async(&new_root_key, new_root.public_key().unwrap(), u64::MAX)
        .await
        .unwrap();
    let admin_key = root_dev.out.device_key.clone();
    let admin_cut = cut_of(&admin_key, 3, 5);
    let signer = seed.signer(&ns);

    for (old_root, cuts) in [
        (OldRoot::Destroyed, &[][..]),
        (OldRoot::Compromised, std::slice::from_ref(&admin_cut)),
    ] {
        let plan = recovery_plan(&new_anchor, old_root, cuts);
        let version = recovery_version(&signer, &v3, &plan).await.unwrap();
        assert_eq!(
            version
                .dropped_cuts
                .iter()
                .map(|d| d.key.clone())
                .collect::<Vec<_>>(),
            vec![tablet()],
            "{old_root}"
        );
        let next = version.bump;
        let after = reissue_version(new_root.as_ref(), &next.data)
            .await
            .unwrap();
        for version in [&next.context, &after.context] {
            assert_eq!(version.revocation_cut(&phone()), Some(&cut), "{old_root}");
            assert_eq!(
                version.revocation_cut(&admin_key),
                cuts.first(),
                "{old_root}"
            );
            assert!(
                version.revocation_cut(&tablet()).is_none(),
                "{old_root}: the orphan cut is dropped"
            );
        }
    }

    let other = cut_of(&tablet(), 1, TABLET_SEED);
    let again = cut_of(&phone(), 9, PHONE_SEED);
    let twice = [admin_cut.clone(), admin_cut.clone()];
    for (old_root, cuts) in [
        (OldRoot::Destroyed, std::slice::from_ref(&admin_cut)),
        (OldRoot::Compromised, std::slice::from_ref(&other)),
        (OldRoot::Compromised, std::slice::from_ref(&again)),
        (OldRoot::Compromised, &twice[..]),
    ] {
        let plan = recovery_plan(&new_anchor, old_root, cuts);
        let refused = recovery_version(&signer, &v3, &plan).await;
        assert!(
            matches!(
                refused,
                Err(RecoveryError::CutsNeedCompromised
                    | RecoveryError::CutNotRevoked { .. }
                    | RecoveryError::DuplicateCut(_))
            ),
            "{old_root}: {refused:?}"
        );
    }
}

/// S5-05: after a compromised recovery the new CA certifies again a key
/// revoked with a cut only from a certificate whose public key is the one
/// the cut names (CutKeyDigest) — never a certificate of the key name with
/// another public key, however new, whoever gave it; a cut naming no public
/// key is never re-certified (reported). The recovery itself certifies
/// nothing: the operator confirms re-certification afterwards; running it
/// again certifies only what is still missing.
#[tokio::test]
async fn recertification_certifies_only_the_public_key_the_cut_names() {
    let root_dev = RootDevice::new().await;
    let root = root_dev.root().await;
    let ns = n("/home/bob");
    let v2 = revoke_with(
        &root_dev,
        &root_dev.held(),
        &phone(),
        &cut_of(&phone(), 4, PHONE_SEED),
    )
    .await;
    let v3 = revoke_with(
        &root_dev,
        &v2,
        &tablet(),
        &cut_of(&tablet(), 2, TABLET_SEED),
    )
    .await;
    // A cut made before cuts named their key's public key.
    let laptop = n("/home/bob/member/laptop/KEY/l");
    let mut old_cut = RevocationCut::new(laptop.clone());
    old_cut.add_run(&device_log_of(&laptop).append("notes"), 1, 2);
    let v4 = SignedTrustContext::decode_content(v3.content().unwrap(), open(&v3).version() + 1)
        .unwrap()
        .with_revocation(laptop.clone())
        .with_revocation_cut(old_cut)
        .sign_into_data_async(root.as_ref())
        .await
        .unwrap();
    let seed = RecoverySeed::generate().unwrap();
    let kit = recovery_anchor(Arc::new(seed.signer(&ns))).await.unwrap();
    let v5 = add_recovery_anchor(root.as_ref(), &v4, &kit)
        .await
        .unwrap()
        .data;

    let phone_cert = root_dev.member_cert(&phone(), PHONE_SEED).await;
    let laptop_cert = root_dev.member_cert(&laptop, 6).await;
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    // Certificates of the cut keys' names with other public keys, newer
    // than the genuine ones: what whoever held the old CA could hand over.
    let forged_phone = root_dev.member_cert(&phone(), 66).await;
    let forged_tablet = root_dev.member_cert(&tablet(), 77).await;
    let tablet_cert = root_dev.member_cert(&tablet(), TABLET_SEED).await;
    let dir = tempfile::tempdir().unwrap();
    let pib = FilePib::new(dir.path()).unwrap();
    pib.store_cert(&phone(), &phone_cert).unwrap();
    pib.store_cert(&phone(), &forged_phone).unwrap();
    pib.store_cert(&laptop, &laptop_cert).unwrap();

    let recovered = recover_namespace_in_pib(
        &pib,
        &v5,
        &seed.signer(&ns),
        "spare",
        OldRoot::Compromised,
        &[],
        &[],
        &NewRootStore::File,
    )
    .await
    .unwrap();
    // The device holds the recovered versions as the daemon would store them.
    ndn_cert::persist_context(
        dir.path(),
        &recovered.root_version.context,
        &recovered.root_version.data,
    )
    .unwrap();

    let first = recertify_cut_keys_in_pib(&pib, &ns, std::slice::from_ref(&forged_tablet))
        .await
        .unwrap();
    assert_eq!(first.issued.len(), 1);
    let issued = &first.issued[0];
    assert_eq!(issued.key_name(), phone());
    assert_eq!(
        issued.public_key, phone_cert.public_key,
        "never the forged key"
    );
    assert_ne!(issued.name, phone_cert.name);
    assert_eq!(
        issued
            .issuer
            .as_deref()
            .map(ndn_security::cert_name::key_name_of),
        Some(recovered.ca_key.clone())
    );
    assert_eq!(
        first.unheld,
        vec![tablet()],
        "the forged tablet is not used"
    );
    assert_eq!(first.no_key_digest, vec![laptop.clone()]);

    let again = recertify_cut_keys_in_pib(&pib, &ns, std::slice::from_ref(&tablet_cert))
        .await
        .unwrap();
    assert_eq!(
        again
            .issued
            .iter()
            .map(|c| (c.key_name(), c.public_key.clone()))
            .collect::<Vec<_>>(),
        vec![(tablet(), tablet_cert.public_key.clone())],
        "the phone is certified already"
    );
    assert!(again.unheld.is_empty());

    // The pure form certifies from the certificates given, nothing else,
    // and only the public key each cut names.
    let ca = pib.get_signer(&recovered.ca_key).unwrap();
    let pure = recertify_cut_keys(
        ca,
        &recovered.root_version.context,
        &[forged_phone, tablet_cert.clone()],
    )
    .await
    .unwrap();
    assert_eq!(
        pure.issued
            .iter()
            .map(|c| c.public_key.clone())
            .collect::<Vec<_>>(),
        vec![tablet_cert.public_key]
    );
    assert_eq!(pure.unheld, vec![phone()]);
    assert_eq!(pure.no_key_digest, vec![laptop]);
}
