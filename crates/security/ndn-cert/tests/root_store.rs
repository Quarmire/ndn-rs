//! Root stores (`ndn_cert::root_store`). Each test guards one invariant:
//!
//! - a sealed root never touches the disk in plaintext;
//! - a root operation without its unlock is refused, and a wrong passphrase
//!   never signs and leaves the store as it was;
//! - whether a node is the root device is decided without the private key;
//! - moving a root never loses it: the new store signs as the root before
//!   the old one is removed, and a refused move changes nothing.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ndn_cert::{
    BumpError, NewRootStore, PersistedNamespace, RootSecret, RootStore, RootStoreError,
    RootStoreKind, bump_context_revoking, init_namespace_in_pib, root_key_name,
};
use ndn_packet::Name;
use ndn_security::FilePib;
use ndn_security::safebag::SafeBag;

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

fn secret(s: &str) -> RootSecret {
    RootSecret::new(s.as_bytes().to_vec())
}

async fn init(pib: &FilePib, root: NewRootStore) -> PersistedNamespace {
    init_namespace_in_pib(pib, &n("/home/bob"), "desk", false, &root)
        .await
        .unwrap()
}

/// Every file under `dir` with its contents.
fn files(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else {
                out.insert(path.clone(), std::fs::read(&path).unwrap());
            }
        }
    }
    out
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[tokio::test]
async fn a_sealed_root_never_touches_the_disk_in_plaintext() {
    let dir = tempfile::tempdir().unwrap();
    let pib = FilePib::new(dir.path()).unwrap();
    let out = init(
        &pib,
        NewRootStore::SealedFile {
            passphrase: secret("correct horse battery staple"),
        },
    )
    .await;
    assert_eq!(out.root_store.kind(), RootStoreKind::SealedFile);
    let root = root_key_name(&n("/home/bob"));
    assert!(!pib.has_private_key(&root), "no root key in the FilePib");

    // The sealed bag opens with the passphrase; its seed and PKCS#8 appear
    // in no file of the PIB.
    let bag_path = dir.path().join("root").join("root.safebag");
    let bag = SafeBag::decode(&std::fs::read(&bag_path).unwrap()).unwrap();
    let pkcs8 = bag.decrypt_pkcs8(b"correct horse battery staple").unwrap();
    let seed = bag
        .decrypt_ed25519_seed(b"correct horse battery staple")
        .unwrap();
    for (path, body) in files(dir.path()) {
        assert!(
            !contains(&body, &seed),
            "{} holds the root seed",
            path.display()
        );
        assert!(
            !contains(&body, &pkcs8),
            "{} holds the root PKCS#8",
            path.display()
        );
    }
    // The CA and admin device keys stay in the FilePib (unattended use).
    assert!(pib.has_private_key(&out.ca_key));
    assert!(pib.has_private_key(&out.device_key));
}

#[tokio::test]
async fn a_root_operation_needs_the_unlock_and_a_wrong_one_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let pib = FilePib::new(dir.path()).unwrap();
    let out = init(
        &pib,
        NewRootStore::SealedFile {
            passphrase: secret("right"),
        },
    )
    .await;
    let store = RootStore::open(&pib).unwrap().expect("a root store");
    let before = files(dir.path());

    assert!(matches!(
        store.signer(None).await,
        Err(RootStoreError::UnlockNeeded { .. })
    ));
    assert!(matches!(
        store.signer(Some(&secret("wrong"))).await,
        Err(RootStoreError::WrongPassphrase { .. })
    ));
    assert_eq!(files(dir.path()), before, "the store is unchanged");

    // The right passphrase unlocks a signer that bumps the context.
    let signer = store.signer(Some(&secret("right"))).await.unwrap();
    let bump = bump_context_revoking(
        signer.as_ref(),
        &out.init.context_data,
        std::slice::from_ref(&out.device_key),
    )
    .await
    .unwrap()
    .expect("a new version");
    assert!(!bump.data.sig_value().is_empty());
    let (_, by) = ndn_cert::open_signed_context(&bump.data).unwrap();
    assert_eq!(by.public_key, out.init.anchor.public_key);
}

#[tokio::test]
async fn the_root_device_is_known_without_the_private_key() {
    let dir = tempfile::tempdir().unwrap();
    let pib = FilePib::new(dir.path()).unwrap();
    let out = init(
        &pib,
        NewRootStore::SealedFile {
            passphrase: secret("pw"),
        },
    )
    .await;
    let store = RootStore::open(&pib).unwrap().unwrap();
    assert!(store.holds_anchor_of(&out.init.context));

    // Another namespace's context is not this root's.
    let other_dir = tempfile::tempdir().unwrap();
    let other_pib = FilePib::new(other_dir.path()).unwrap();
    let other = init(&other_pib, NewRootStore::File).await;
    assert!(!store.holds_anchor_of(&other.init.context));

    // A PIB holds one namespace root.
    let refused = init_namespace_in_pib(&pib, &n("/home/eve"), "desk", true, &NewRootStore::File)
        .await
        .err()
        .expect("a second namespace root is refused");
    assert!(
        matches!(
            refused,
            ndn_cert::NamespaceInitError::RootStore(RootStoreError::OtherNamespace { .. })
        ),
        "{refused}"
    );
}

#[tokio::test]
async fn moving_a_file_root_seals_it_without_losing_it() {
    let dir = tempfile::tempdir().unwrap();
    let pib = FilePib::new(dir.path()).unwrap();
    let out = init(&pib, NewRootStore::File).await;
    let root = root_key_name(&n("/home/bob"));
    // A namespace made before root stores has no descriptor: it is found as
    // a `file` root all the same.
    std::fs::remove_file(dir.path().join("root").join("store.toml")).unwrap();
    let store = RootStore::open(&pib).unwrap().expect("legacy file root");
    assert!(store.is_legacy());
    assert_eq!(store.kind(), RootStoreKind::File);
    let before = files(dir.path());

    // Refused moves change nothing.
    for to in [RootStoreKind::YubikeyPiv, RootStoreKind::File] {
        assert!(
            matches!(
                store.move_to(&pib, to, None, None).await,
                Err(RootStoreError::Unmovable { .. })
            ),
            "{to}"
        );
    }
    // A sealed-file target without a passphrase is refused.
    assert!(
        store
            .move_to(&pib, RootStoreKind::SealedFile, None, None)
            .await
            .is_err()
    );
    if ndn_cert::os_keychain_reachable().is_err() {
        assert!(
            store
                .move_to(&pib, RootStoreKind::OsKeyring, None, None)
                .await
                .is_err()
        );
    }
    assert_eq!(files(dir.path()), before, "a refused move changes nothing");

    let moved = store
        .move_to(
            &pib,
            RootStoreKind::SealedFile,
            None,
            Some(&secret("sealed now")),
        )
        .await
        .unwrap();
    assert_eq!(moved.kind(), RootStoreKind::SealedFile);
    assert!(!pib.has_private_key(&root), "the plaintext root is gone");
    let reopened = RootStore::open(&pib).unwrap().unwrap();
    assert_eq!(reopened.kind(), RootStoreKind::SealedFile);
    assert!(!reopened.is_legacy());

    // Same key: it signs the next version of the context it anchors.
    let signer = reopened.signer(Some(&secret("sealed now"))).await.unwrap();
    assert!(
        bump_context_revoking(
            signer.as_ref(),
            &out.init.context_data,
            std::slice::from_ref(&out.device_key)
        )
        .await
        .unwrap()
        .is_some()
    );
    // A key that is no anchor does not.
    let device = pib.get_signer(&out.device_key).unwrap();
    assert!(matches!(
        bump_context_revoking(device.as_ref(), &out.init.context_data, &[]).await,
        Err(BumpError::NotAnAnchor { .. })
    ));
}
