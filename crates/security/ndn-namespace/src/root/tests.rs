//! The root-device operations on a PIB holding the roots of two namespaces
//! (`/a`, `/c`): each acts on the namespace named (or the only one / the
//! one covering the name) and leaves the other alone; refusals are asserted
//! by code and params, secrets by what was asked, in order.

use parking_lot::Mutex;
use std::path::{Path, PathBuf};

use ndn_cert::report::{ContextRefreshInfo, TrustRefusal, code};
use ndn_cert::{
    KitFormat, NewRootStore, OldRoot, PolicyInput, RootSecret, RootStoreKind, YubikeyKit,
    init_namespace_in_pib, read_stored_context,
};
use ndn_packet::{Data, Name};
use ndn_security::FilePib;
use tempfile::TempDir;

use super::init::{InitRequest, RootStoreChoice};
use super::kit::{KitRequest, KitSpec};
use super::recover::RecoverRequest;
use super::*;
use crate::admin::{HandedOver, SinkError};

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

/// Secrets from memory: every passphrase is `passphrase`, the kit words
/// those set; anything else is unavailable. Records each request.
struct Secrets {
    passphrase: &'static [u8],
    words: Mutex<Option<String>>,
    asked: Mutex<Vec<SecretRequest>>,
}

impl Secrets {
    fn new(passphrase: &'static [u8]) -> Self {
        Self {
            passphrase,
            words: Mutex::new(None),
            asked: Mutex::new(Vec::new()),
        }
    }

    fn asked(&self) -> Vec<SecretRequest> {
        self.asked.lock().clone()
    }
}

#[async_trait::async_trait]
impl SecretSource for Secrets {
    async fn secret(&self, request: &SecretRequest) -> Result<RootSecret, RootError> {
        self.asked.lock().push(request.clone());
        let unavailable = || {
            RootError::new(code::SECRET_UNAVAILABLE, "no secret was given")
                .with("secret", request.kind.as_str())
        };
        match request.kind {
            SecretKind::RootPassphrase | SecretKind::KitPassphrase => {
                Ok(RootSecret::new(self.passphrase.to_vec()))
            }
            SecretKind::KitWords => self
                .words
                .lock()
                .clone()
                .map(|w| RootSecret::new(w.into_bytes()))
                .ok_or_else(unavailable),
            SecretKind::RootPin | SecretKind::KitPin => Err(unavailable()),
        }
    }
}

/// The running device as reached.
enum Device {
    /// Nothing listens: versions are kept for its next start.
    NotRunning,
    /// A device using the PIB at the path, which refuses every version.
    Refusing(PathBuf),
}

#[async_trait::async_trait]
impl RunningDevice for Device {
    fn address(&self) -> String {
        "test-socket".into()
    }

    async fn reach(&self) -> Result<Reach, RootError> {
        Ok(match self {
            Device::NotRunning => Reach::NotRunning {
                error: "nothing listens".into(),
            },
            Device::Refusing(pib) => Reach::Running(Box::new(Session(pib.clone()))),
        })
    }
}

struct Session(PathBuf);

#[async_trait::async_trait]
impl DeviceSession for Session {
    async fn pib(&self) -> Result<PathBuf, RootError> {
        Ok(self.0.clone())
    }

    async fn take(&self, _data: &Data) -> Result<ContextRefreshInfo, SinkError<RootError>> {
        Err(SinkError::Refused(TrustRefusal::new(
            code::HAND_OVER_REFUSED,
            "refused",
        )))
    }

    async fn refresh(&self, _namespace: &Name) -> Result<Option<ContextRefreshInfo>, RootError> {
        Err(RootError::new(
            code::DEVICE_FAILED,
            "not asked in these tests",
        ))
    }

    async fn adopt(&self, _namespace: &Name, _fingerprint: &[u8; 32]) -> Result<u64, RootError> {
        Err(RootError::new(
            code::DEVICE_FAILED,
            "not asked in these tests",
        ))
    }
}

/// A PIB holding the roots of `/a` and `/c` (plaintext roots: no secret).
async fn two_roots() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let pib = FilePib::new(dir.path()).unwrap();
    for ns in ["/a", "/c"] {
        init_namespace_in_pib(&pib, &n(ns), "desk", false, &NewRootStore::File)
            .await
            .unwrap();
    }
    let path = dir.path().to_path_buf();
    (dir, path)
}

/// The held versions of `/a` and `/c`.
fn versions(pib: &Path) -> (u64, u64) {
    let v = |ns| {
        read_stored_context(pib, &n(ns))
            .unwrap()
            .unwrap()
            .0
            .version()
    };
    (v("/a"), v("/c"))
}

fn word_kit(namespace: Option<&str>) -> KitRequest {
    KitRequest {
        pib_dir: PathBuf::new(),
        namespace: namespace.map(n),
        format: KitFormat::Words,
        out: None,
        yubikey: YubikeyKit {
            serial: None,
            slot: ndn_cert::recovery::DEFAULT_KIT_SLOT.to_string(),
            touch_policy: "always".to_string(),
        },
        replace_slot: false,
    }
}

#[track_caller]
fn assert_code(e: &RootError, kind: ndn_cert::report::RefusalCode) {
    assert!(e.is(kind), "{} expected, got {:?}", kind.code, e.refusal);
}

#[tokio::test]
async fn several_roots_and_none_named_is_refused_listing_them() {
    let (_dir, pib) = two_roots().await;
    let secrets = Secrets::new(b"unused");
    let request = KitRequest {
        pib_dir: pib.clone(),
        ..word_kit(None)
    };
    let refusals = [
        kit::create(request, &Device::NotRunning, &secrets)
            .await
            .err()
            .unwrap(),
        schema::root_of(&pib, None).err().unwrap(),
        key::open(&pib)
            .unwrap()
            .move_to(None, RootStoreKind::SealedFile, &secrets)
            .await
            .err()
            .unwrap(),
    ];
    for e in &refusals {
        assert_code(e, code::SEVERAL_NAMESPACES);
        assert_eq!(e.param("namespaces"), Some("/a,/c"));
        assert_eq!(e.param("count"), Some("2"));
    }
    // A namespace named whose root this PIB does not hold.
    let roots = key::open(&pib).unwrap();
    for e in [
        schema::root_of(&pib, Some(&n("/b"))).err().unwrap(),
        roots.status(Some(&n("/b"))).err().unwrap(),
    ] {
        assert_code(&e, code::OTHER_NAMESPACE_ROOT);
        assert_eq!(e.param("requested"), Some("/b"));
        assert_eq!(e.param("namespace"), Some("/a,/c"));
    }
    let listed: Vec<Name> = roots
        .status(None)
        .unwrap()
        .into_iter()
        .map(|s| s.namespace)
        .collect();
    assert_eq!(listed, vec![n("/a"), n("/c")]);
    assert!(secrets.asked().is_empty(), "nothing asked before a refusal");
    assert_eq!(versions(&pib), (1, 1));
}

#[tokio::test]
async fn init_adds_a_root_beside_the_others_and_never_replaces_one() {
    let (_dir, pib) = two_roots().await;
    let secrets = Secrets::new(b"correct horse");
    let request = |ns: &str, root| InitRequest {
        pib_dir: pib.clone(),
        namespace: n(ns),
        device: "desk".into(),
        force: false,
        stated: PolicyInput::default(),
        root,
    };
    let made = init::init(request("/b", RootStoreChoice::SealedFile), &secrets)
        .await
        .unwrap();
    assert_eq!(made.persisted.init.context.namespace(), &n("/b"));
    assert_eq!(
        secrets.asked(),
        vec![SecretRequest {
            kind: SecretKind::RootPassphrase,
            purpose: SecretPurpose::CreateRoot,
            confirm: true,
        }]
    );
    let kinds: Vec<(Name, RootStoreKind)> = key::open(&pib)
        .unwrap()
        .status(None)
        .unwrap()
        .into_iter()
        .map(|s| (s.namespace, s.store.kind))
        .collect();
    assert_eq!(
        kinds,
        vec![
            (n("/a"), RootStoreKind::File),
            (n("/b"), RootStoreKind::SealedFile),
            (n("/c"), RootStoreKind::File),
        ]
    );
    let again = init::init(request("/a", RootStoreChoice::File), &secrets)
        .await
        .err()
        .unwrap();
    assert_code(&again, code::ALREADY_INITIALIZED);
    assert_eq!(versions(&pib), (1, 1));
}

#[tokio::test]
async fn a_revocation_changes_only_the_namespace_of_the_name() {
    let (_dir, pib) = two_roots().await;
    let secrets = Secrets::new(b"unused");
    let key = n("/a/member/phone/KEY/k");

    let planned = revoke::plan(&pib, &key, None).unwrap();
    assert_eq!(planned.root.context.namespace(), &n("/a"));
    let other = revoke::plan(&pib, &key, Some(&n("/c"))).err().unwrap();
    assert_code(&other, code::REVOKE_OTHER_NAMESPACE);
    assert_eq!(other.param("namespace"), Some("/a"));
    assert_eq!(other.param("requested"), Some("/c"));
    let outside = revoke::plan(&pib, &n("/b/member/x/KEY/k"), None)
        .err()
        .unwrap();
    assert_code(&outside, code::REVOKE_OUTSIDE_NAMESPACE);

    // A running device of another PIB is refused before the root unlocks.
    let elsewhere = tempfile::tempdir().unwrap();
    let refused = revoke::revoke(
        planned,
        &key,
        &pib,
        &Device::Refusing(elsewhere.path().to_path_buf()),
        &secrets,
    )
    .await
    .unwrap_err();
    assert_code(&refused, code::DEVICE_OTHER_PIB);

    // The running device refuses the version: nothing changed.
    let refused = revoke::revoke(
        revoke::plan(&pib, &key, None).unwrap(),
        &key,
        &pib,
        &Device::Refusing(pib.clone()),
        &secrets,
    )
    .await
    .unwrap_err();
    assert_code(&refused, code::VERSION_NOT_TAKEN);
    assert_eq!(refused.param("cause"), Some("hand-over-refused"));
    assert_eq!(
        (refused.param("held_version"), refused.param("version")),
        (Some("1"), Some("2"))
    );
    assert_eq!(versions(&pib), (1, 1));

    // No device runs: v2 of /a is kept for its next start; /c is untouched.
    let revoked = revoke::revoke(
        revoke::plan(&pib, &key, None).unwrap(),
        &key,
        &pib,
        &Device::NotRunning,
        &secrets,
    )
    .await
    .unwrap();
    assert_eq!(revoked.namespace, n("/a"));
    assert_eq!((revoked.held_version, revoked.version), (1, 2));
    assert_eq!(revoked.revoked, vec![key.clone()]);
    assert!(matches!(revoked.handed_over, HandedOver::Stored { .. }));
    assert_eq!(versions(&pib), (2, 1));

    let again = revoke::plan(&pib, &key, None).unwrap();
    assert!(again.adding.is_empty());
    let nothing = revoke::revoke(again, &key, &pib, &Device::NotRunning, &secrets)
        .await
        .unwrap_err();
    assert_code(&nothing, code::NOTHING_TO_SIGN);
    assert!(secrets.asked().is_empty(), "plaintext roots need no secret");
}

#[tokio::test]
async fn a_recovery_kit_changes_only_its_namespace() {
    let (_dir, pib) = two_roots().await;
    let secrets = Secrets::new(b"unused");
    let device = Device::NotRunning;
    let created = kit::create(
        KitRequest {
            pib_dir: pib.clone(),
            ..word_kit(Some("/c"))
        },
        &device,
        &secrets,
    )
    .await
    .unwrap();
    assert_eq!(created.namespace, n("/c"));
    assert_eq!((created.held_version, created.version), (1, 2));
    assert!(matches!(created.handed, Ok((HandedOver::Stored { .. }, 1))));
    assert_eq!(versions(&pib), (1, 2));

    let kits: Vec<(Name, usize)> = kit::list(&pib, None)
        .unwrap()
        .contexts
        .into_iter()
        .map(|c| (c.namespace, c.recovery_kits))
        .collect();
    assert_eq!(kits, vec![(n("/a"), 0), (n("/c"), 1)]);

    // The words open the kit of /c; it is no anchor of /a.
    *secrets.words.lock() = Some(created.words.as_ref().unwrap().to_words().to_string());
    let checked = kit::check(&pib, &KitSpec::Words, Some(&n("/c")), &secrets)
        .await
        .unwrap();
    assert_eq!(
        (checked.namespace, checked.key, checked.version),
        (n("/c"), created.key.clone(), 2)
    );
    let elsewhere = kit::check(&pib, &KitSpec::Words, Some(&n("/a")), &secrets)
        .await
        .unwrap_err();
    assert_code(&elsewhere, code::KIT_NOT_AN_ANCHOR);
    let purposes: Vec<SecretPurpose> = secrets.asked().into_iter().map(|r| r.purpose).collect();
    assert_eq!(
        purposes,
        vec![
            SecretPurpose::CheckKit { namespace: n("/c") },
            SecretPurpose::CheckKit { namespace: n("/a") },
        ]
    );

    // Revoking: in the namespace covering the key, or the one named.
    let outside = kit::revoke(&pib, &n("/b/KEY/r00"), None, &device, &secrets)
        .await
        .unwrap_err();
    assert_code(&outside, code::REVOKE_OUTSIDE_NAMESPACE);
    assert_eq!(outside.param("namespace"), Some("/a,/c"));
    let not_a_kit = kit::revoke(&pib, &created.key, Some(&n("/a")), &device, &secrets)
        .await
        .unwrap_err();
    assert_code(&not_a_kit, code::NOT_A_RECOVERY_KIT);
    assert_eq!(not_a_kit.param("namespace"), Some("/a"));
    let revoked = kit::revoke(&pib, &created.key, None, &device, &secrets)
        .await
        .unwrap();
    assert_eq!(revoked.namespace, n("/c"));
    assert_eq!((revoked.held_version, revoked.version), (2, 3));
    assert_eq!(revoked.recovery_kits, 0);
    assert_eq!(versions(&pib), (1, 3));
}

#[tokio::test]
async fn moving_a_root_asks_its_secrets_and_leaves_the_other_root() {
    let (_dir, pib) = two_roots().await;
    let secrets = Secrets::new(b"correct horse");
    let moved = key::open(&pib)
        .unwrap()
        .move_to(Some(&n("/a")), RootStoreKind::SealedFile, &secrets)
        .await
        .unwrap();
    assert_eq!(
        (moved.namespace, moved.from, moved.to.kind),
        (n("/a"), RootStoreKind::File, RootStoreKind::SealedFile)
    );
    assert_eq!(
        secrets.asked(),
        vec![SecretRequest {
            kind: SecretKind::RootPassphrase,
            purpose: SecretPurpose::SealRoot,
            confirm: true,
        }]
    );
    let kinds: Vec<RootStoreKind> = key::open(&pib)
        .unwrap()
        .status(None)
        .unwrap()
        .into_iter()
        .map(|s| s.store.kind)
        .collect();
    assert_eq!(kinds, vec![RootStoreKind::SealedFile, RootStoreKind::File]);

    // Signing in /a now unlocks that root with its passphrase.
    let key = n("/a/member/phone/KEY/k");
    let plan = revoke::plan(&pib, &key, None).unwrap();
    revoke::revoke(plan, &key, &pib, &Device::NotRunning, &secrets)
        .await
        .unwrap();
    assert_eq!(
        secrets.asked().last(),
        Some(&SecretRequest {
            kind: SecretKind::RootPassphrase,
            purpose: SecretPurpose::SignVersion(VersionChange::Revoke { name: key }),
            confirm: false,
        })
    );
    // A wrong passphrase signs nothing.
    let wrong = Secrets::new(b"wrong");
    let tablet = n("/a/member/tablet/KEY/k");
    let plan = revoke::plan(&pib, &tablet, None).unwrap();
    let refused = revoke::revoke(plan, &tablet, &pib, &Device::NotRunning, &wrong)
        .await
        .unwrap_err();
    assert_code(&refused, code::ROOT_NOT_UNLOCKED);
    assert_eq!(refused.param("cause"), Some("wrong-secret"));
    assert_eq!(versions(&pib), (2, 1));
}

#[tokio::test]
async fn a_schema_update_without_change_signs_nothing() {
    let (_dir, pib) = two_roots().await;
    let secrets = Secrets::new(b"unused");
    let root = schema::root_of(&pib, Some(&n("/c"))).unwrap();
    assert_eq!(root.context.namespace(), &n("/c"));
    let update = schema::plan_update(root, &PolicyInput::default(), false).unwrap();
    assert!(update.plan.change.is_empty());
    let nothing = schema::update(update, &pib, &Device::NotRunning, &secrets)
        .await
        .err()
        .unwrap();
    assert_code(&nothing, code::NOTHING_TO_SIGN);
    assert_eq!(versions(&pib), (1, 1));
}

#[tokio::test]
async fn a_recovery_is_refused_only_where_the_namespace_root_is_held() {
    let (_dir, pib) = two_roots().await;
    let secrets = Secrets::new(b"unused");
    let request = |ns: &str| RecoverRequest {
        pib_dir: pib.clone(),
        kit: KitSpec::Words,
        namespace: Some(n(ns)),
        device: "spare".into(),
        old_root: OldRoot::Destroyed,
        kept_kits: Vec::new(),
        from_held: false,
        root: RootStoreChoice::File,
    };
    let here = recover::recover(request("/a"), &Device::NotRunning, &secrets)
        .await
        .err()
        .unwrap();
    assert_code(&here, code::ALREADY_ROOT_DEVICE);
    assert_eq!(here.param("namespace"), Some("/a"));
    // The roots of other namespaces do not stop it: it goes on to the
    // running device, which must run.
    let next = recover::recover(request("/b"), &Device::NotRunning, &secrets)
        .await
        .err()
        .unwrap();
    assert_code(&next, code::DEVICE_NOT_RUNNING);
    assert!(secrets.asked().is_empty());
    assert_eq!(versions(&pib), (1, 1));
}
