//! Revocation by context bump and its distribution by refresh
//! (`ndn_cert::context_update`). Each test guards one invariant:
//!
//! - a revoked key's Data is refused by a node once it holds the bumped
//!   context, which only the root key can make;
//! - an update not signed by an anchor of the held version is never adopted;
//! - a lower or equal version never replaces the held one;
//! - a failed refresh never drops a good context.

use std::path::Path;
use std::sync::Arc;

use bytes::Bytes;
use ndn_cert::{
    BumpError, CaExchange, CertError, ContextRefresh, PersistedNamespace, RefreshError,
    UpdateRefusal, anchor_fingerprint, bump_context_revoking, open_context_update,
    rdr_metadata_name, refresh_context,
};
use ndn_packet::encode::DataBuilder;
use ndn_packet::{Data, Interest, Name};
use ndn_security::{CertCache, FilePib, Keyring, TrustError, ValidationResult, Validator};

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

/// A root device: namespace `/home/bob` initialized into a PIB at `dir`.
fn root_device(dir: &Path) -> (FilePib, PersistedNamespace) {
    let pib = FilePib::new(dir).unwrap();
    let ns = ndn_cert::init_namespace_in_pib(&pib, &n("/home/bob"), "desk", false).unwrap();
    (pib, ns)
}

/// An in-memory upstream: answers an Interest whose name equals a
/// registered one; records every Interest.
struct Upstream {
    replies: Vec<(Name, Bytes)>,
    sent: Vec<Name>,
}

impl Upstream {
    /// Serving `context` (a signed context Data) as the newest version.
    fn serving(context: &Data) -> Self {
        let ns = n("/home/bob");
        let versioned = (*context.name).clone();
        let version = versioned.components().last().unwrap().as_version().unwrap();
        let meta_name = rdr_metadata_name(&ns);
        let meta = DataBuilder::new(
            meta_name.clone().append_version(version).append_segment(0),
            &versioned.encode_to_tlv(),
        )
        .build();
        Self {
            replies: vec![(meta_name, meta), (versioned, context.raw().clone())],
            sent: Vec::new(),
        }
    }
}

impl CaExchange for Upstream {
    async fn express(&mut self, interest: Bytes) -> Result<Data, CertError> {
        let interest = Interest::decode(interest).unwrap();
        self.sent.push((*interest.name).clone());
        self.replies
            .iter()
            .find(|(name, _)| *name == *interest.name)
            .map(|(_, wire)| Data::decode(wire.clone()).unwrap())
            .ok_or_else(|| CertError::Transport(format!("no reply for {}", interest.name)))
    }
}

/// The upstream seen through this node's validating forwarder, which drops
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

/// A node (e.g. a relay) holding `/home/bob` v1, with a validator over its
/// keyring that knows the CA's and the device's certificates.
fn node_holding(root: &PersistedNamespace) -> (Arc<Keyring>, Validator) {
    let keyring = Arc::new(Keyring::new());
    ndn_cert::adopt_with_tofu(
        &keyring,
        &root.init.context_data,
        &n("/home/bob"),
        &anchor_fingerprint(&root.init.anchor),
    )
    .unwrap();
    let certs = Arc::new(CertCache::new());
    certs.insert(root.ca_cert.clone());
    certs.insert(root.device_cert.clone());
    let validator = Validator::with_keyring(Arc::clone(&keyring), certs, None, 4);
    (keyring, validator)
}

/// Data the root device's admin device `/home/bob/admin/desk` produces.
fn device_data(pib: &FilePib, root: &PersistedNamespace, suffix: &str) -> Data {
    let signer = pib.get_signer(&root.device_key).unwrap();
    let wire = DataBuilder::new(root.device_identity.clone().append(suffix), b"photo")
        .sign_sync(signer.sig_type(), Some(signer.key_name()), |region| {
            signer.sign_sync(region).unwrap()
        });
    Data::decode(wire).unwrap()
}

fn validate(v: &Validator, data: &Data) -> ValidationResult {
    futures::executor::block_on(v.validate_chain_cached(data)).0
}

#[tokio::test]
async fn revoked_key_is_refused_once_the_bumped_context_is_held() {
    let dir = tempfile::tempdir().unwrap();
    let (pib, root) = root_device(dir.path());
    let (relay, relay_validator) = node_holding(&root);
    assert!(matches!(
        validate(&relay_validator, &device_data(&pib, &root, "before")),
        ValidationResult::Valid(_)
    ));

    // The root device revokes the device's key: v2, signed by the root.
    let bump = bump_context_revoking(&pib, &root.init.context_data, &[root.device_key.clone()])
        .unwrap()
        .expect("a new version");
    assert_eq!(bump.context.version(), 2);
    assert_eq!(bump.added, [root.device_key.clone()]);
    // Everything else is carried over.
    assert_eq!(bump.context.ca_endpoints(), root.init.context.ca_endpoints());
    assert_eq!(bump.context.anchors().len(), 1);

    // The relay refreshes through its own validating forwarder.
    let mut upstream = Forwarded {
        upstream: Upstream::serving(&bump.data),
        forwarder: &relay_validator,
    };
    let refreshed =
        refresh_context(&relay, Some(&relay_validator), &mut upstream, &n("/home/bob"))
            .await
            .unwrap();
    let ContextRefresh::Updated(update) = refreshed else {
        panic!("expected an update: {refreshed:?}");
    };
    assert_eq!((update.previous, update.context.version()), (1, 2));
    assert_eq!(update.revoked, [root.device_key.clone()]);
    assert_eq!(update.data.raw(), bump.data.raw(), "kept verbatim to store and republish");
    assert_eq!(relay.version_of(&n("/home/bob")), Some(2));

    // Old and new Data of the revoked key are refused now; nothing else is.
    for suffix in ["before", "after"] {
        match validate(&relay_validator, &device_data(&pib, &root, suffix)) {
            ValidationResult::Invalid(TrustError::Revoked { name }) => {
                assert_eq!(name, root.device_key.to_string())
            }
            other => panic!("revoked key's Data accepted: {other:?}"),
        }
    }

    // A downstream node refreshes from the relay's copy: hop by hop.
    let (device, device_validator) = node_holding(&root);
    let mut from_relay = Forwarded {
        upstream: Upstream::serving(&update.data),
        forwarder: &device_validator,
    };
    let refreshed =
        refresh_context(&device, Some(&device_validator), &mut from_relay, &n("/home/bob"))
            .await
            .unwrap();
    assert!(matches!(refreshed, ContextRefresh::Updated(_)));
    assert!(!matches!(
        validate(&device_validator, &device_data(&pib, &root, "later")),
        ValidationResult::Valid(_)
    ));
}

#[tokio::test]
async fn an_update_not_signed_by_a_held_anchor_is_never_adopted() {
    let (genuine_dir, forged_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (_, genuine) = root_device(genuine_dir.path());
    // Another root for the same namespace name, with a higher version that
    // lists only itself — what an impersonator would serve.
    let (forged_pib, forged) = root_device(forged_dir.path());
    let forged_v2 = bump_context_revoking(
        &forged_pib,
        &forged.init.context_data,
        &[genuine.device_key.clone()],
    )
    .unwrap()
    .unwrap();

    // Through a validating forwarder: dropped there, with the reason.
    let (relay, relay_validator) = node_holding(&genuine);
    let mut upstream = Forwarded {
        upstream: Upstream::serving(&forged_v2.data),
        forwarder: &relay_validator,
    };
    let res = refresh_context(&relay, Some(&relay_validator), &mut upstream, &n("/home/bob")).await;
    match res {
        Err(RefreshError::Refused {
            refusal: UpdateRefusal::DroppedByForwarder(reason),
            held: 1,
            ..
        }) => assert!(reason.contains("not an anchor of the held version"), "{reason}"),
        other => panic!("forged update not refused at the forwarder: {other:?}"),
    }
    assert_eq!(relay.version_of(&n("/home/bob")), Some(1));

    // Without a validating forwarder: the continuity check refuses it.
    let res = refresh_context(
        &relay,
        None,
        &mut Upstream::serving(&forged_v2.data),
        &n("/home/bob"),
    )
    .await;
    assert!(
        matches!(
            res,
            Err(RefreshError::Refused {
                refusal: UpdateRefusal::NotSignedByHeldAnchor { .. },
                ..
            })
        ),
        "{res:?}"
    );
    assert_eq!(relay.version_of(&n("/home/bob")), Some(1));
    assert!(!relay.contexts()[0].is_revoked(&genuine.device_key));
}

#[tokio::test]
async fn a_lower_or_equal_version_never_replaces_the_held_one() {
    let dir = tempfile::tempdir().unwrap();
    let (pib, root) = root_device(dir.path());
    let v2 = bump_context_revoking(&pib, &root.init.context_data, &[root.device_key.clone()])
        .unwrap()
        .unwrap();
    let (relay, _) = node_holding(&root);
    let ns = n("/home/bob");
    let mut serving_v2 = Upstream::serving(&v2.data);
    assert!(matches!(
        refresh_context(&relay, None, &mut serving_v2, &ns).await,
        Ok(ContextRefresh::Updated(_))
    ));

    // An upstream still at v1 (a relay that has not refreshed, or a replay):
    // not even fetched.
    let mut serving_v1 = Upstream::serving(&root.init.context_data);
    let res = refresh_context(&relay, None, &mut serving_v1, &ns).await;
    assert!(
        matches!(res, Ok(ContextRefresh::UpstreamOlder { held: 2, offered: 1 })),
        "{res:?}"
    );
    assert_eq!(serving_v1.sent, [rdr_metadata_name(&ns)]);
    let mut serving_v2 = Upstream::serving(&v2.data);
    assert!(matches!(
        refresh_context(&relay, None, &mut serving_v2, &ns).await,
        Ok(ContextRefresh::Current { version: 2 })
    ));
    assert_eq!(relay.version_of(&ns), Some(2));

    // Offered directly, an equal or older genuine version is refused too.
    let held = relay.contexts().pop().unwrap();
    for data in [&v2.data, &root.init.context_data] {
        assert!(matches!(
            open_context_update(&held, data).await,
            Err(UpdateRefusal::NotNewer { held: 2, .. })
        ));
    }
    assert_eq!(relay.adopt_update(Arc::clone(&held)), Err(Some(2)));
    assert!(relay.contexts()[0].is_revoked(&root.device_key));
}

#[tokio::test]
async fn a_failed_refresh_never_drops_a_good_context() {
    let dir = tempfile::tempdir().unwrap();
    let (pib, root) = root_device(dir.path());
    let (relay, validator) = node_holding(&root);
    let ns = n("/home/bob");
    let v2 = bump_context_revoking(&pib, &root.init.context_data, &[root.device_key.clone()])
        .unwrap()
        .unwrap();

    // Nothing answers.
    let mut silent = Upstream {
        replies: Vec::new(),
        sent: Vec::new(),
    };
    let res = refresh_context(&relay, Some(&validator), &mut silent, &ns).await;
    assert!(matches!(res, Err(RefreshError::Fetch { held: 1, .. })), "{res:?}");
    // The metadata announces v2, the context itself never arrives.
    let mut half = Upstream::serving(&v2.data);
    half.replies.truncate(1);
    let res = refresh_context(&relay, Some(&validator), &mut half, &ns).await;
    assert!(matches!(res, Err(RefreshError::Fetch { .. })), "{res:?}");
    // A tampered v2 (one byte of its content flipped).
    let mut wire = v2.data.raw().to_vec();
    let at = wire.len() - 80;
    wire[at] ^= 0xff;
    if let Ok(tampered) = Data::decode(Bytes::from(wire)) {
        let res = refresh_context(&relay, None, &mut Upstream::serving(&tampered), &ns).await;
        assert!(res.is_err(), "{res:?}");
    }

    assert_eq!(relay.version_of(&ns), Some(1));
    assert!(matches!(
        validate(&validator, &device_data(&pib, &root, "still")),
        ValidationResult::Valid(_)
    ));
    // Not held at all: refused, nothing adopted.
    let res = refresh_context(&relay, None, &mut Upstream::serving(&v2.data), &n("/home/eve")).await;
    assert!(matches!(res, Err(RefreshError::NotHeld(_))), "{res:?}");
}

#[test]
fn only_the_root_key_bumps_and_never_against_the_root() {
    let (root_dir, other_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (pib, root) = root_device(root_dir.path());
    let held = &root.init.context_data;

    // A PIB without the root key (any other device).
    let other = FilePib::new(other_dir.path()).unwrap();
    assert!(matches!(
        bump_context_revoking(&other, held, &[root.device_key.clone()]),
        Err(BumpError::NotRootDevice { .. })
    ));
    // Another root key under the same name does not sign this namespace.
    let (forged_pib, _) = root_device(other_dir.path().join("forged").as_path());
    assert!(matches!(
        bump_context_revoking(&forged_pib, held, &[root.device_key.clone()]),
        Err(BumpError::NotRootDevice { .. })
    ));

    for name in ["/home/bob/KEY/root", "/home/bob"] {
        let res = bump_context_revoking(&pib, held, &[n(name)]);
        assert!(res.is_err(), "{name}: {res:?}");
    }
    assert!(matches!(
        bump_context_revoking(&pib, held, &[n("/home/bob/admin/desk")]),
        Err(BumpError::NotAKeyOfNamespace { .. })
    ));
    assert!(matches!(
        bump_context_revoking(&pib, held, &[n("/home/eve/member/x/KEY/k")]),
        Err(BumpError::NotAKeyOfNamespace { .. })
    ));

    // Revoking twice adds nothing.
    let v2 = bump_context_revoking(&pib, held, &[root.device_key.clone()])
        .unwrap()
        .unwrap();
    assert!(
        bump_context_revoking(&pib, &v2.data, &[root.device_key.clone()])
            .unwrap()
            .is_none()
    );
    // A certificate name designates its key.
    assert_eq!(
        ndn_cert::key_name_of(&root.device_key.clone().append("CA").append_version(3)),
        Some(root.device_key.clone())
    );
    assert_eq!(ndn_cert::key_name_of(&n("/home/bob/admin/desk")), None);
}
