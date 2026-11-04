//! Keep Data that a newly adopted trust context refuses from being served
//! out of the Content Store.
//!
//! The Content Store answers Interests without validating again: Data is
//! validated once, before it is admitted. When the node adopts a version of a
//! trust context that refuses what the one before accepted — it revokes a
//! key, a key's cut accepts less, or a role newly needs a cut
//! ([`Keyring::on_revocation`](ndn_security::Keyring::on_revocation)) —
//! Data it now refuses may already sit in the CS, or be on its way there.
//! After such an update, a cached Data is served only when it is *known
//! clear* by the durable rule the validation stage applies to Data
//! ([`ndn_security::chain_clear`], the code
//! [`Validator::validate_durable`](ndn_security::Validator::validate_durable)
//! shares): its chain, followed from its KeyLocator through the validator's
//! certificate cache — each hop through the cached certificate whose public
//! key verifies it — ends at an anchor (or a certificate with no issuer
//! above it) without passing a revoked issuer or certificate; its signer is
//! not revoked, or revoked with a cut that accepts it (key digest, ranges,
//! manifest, exact entries), and is no lapsed key whose role needs a cut;
//! and it is no certificate the context revokes — except a certificate of a
//! key revoked *with* a cut, kept because the Data the cut accepts needs it
//! to verify. Data whose chain cannot be followed that far (or whose cut's
//! manifest is not held) is not served either — after a restart the cache
//! holds only this node's own certificates, not those of other devices or
//! their CA — but evicted, so the next Interest fetches it and validation
//! judges it afresh. A context that revokes nothing and lists no role
//! needing a cut leaves every entry clear.
//!
//! Correctness rests on data, not on timing. Every entry `CsInsertStage`
//! admits carries the keyring's
//! [revocation epoch](ndn_security::Keyring::revocation_epoch) as
//! `ValidationStage` read it before validating. `CsLookupStage` compares an
//! entry's stamp with the current epoch on every hit (one atomic load); only
//! when they differ does [`recheck`] judge the entry against the revocations
//! held now, evicting it instead of serving it, or restamping it so it is
//! not judged again until the next revoking update. Since the epoch moves
//! only after the new context is in force, an entry stamped before an update
//! is re-checked at its first hit after it, whenever it was validated or
//! inserted. Persistent stores report entries from an earlier process as
//! stamped [`EARLIER_PROCESS_EPOCH`](ndn_store::EARLIER_PROCESS_EPOCH), so
//! each is re-checked once after a restart. Entries cached without
//! validation carry no stamp and are not re-checked.
//!
//! The engine also registers [`install`] on its validator's keyring, so each
//! revoking adoption evicts, under that context's namespace, every entry not
//! known clear. That only reclaims space early (and drops unstamped entries
//! a revocation covers): without it, those entries would still never be
//! served, but would hold cache capacity until hit or aged out.
//! The scan runs once per revoking update, which is rare, and completes
//! before the adoption call returns for every store whose scan does not
//! suspend (all in-tree stores); a store that does finish it on the runtime.

use std::pin::Pin;
use std::sync::{Arc, Weak};
use std::task::{Context, Waker};

use bytes::Bytes;
use ndn_packet::Data;
use ndn_runtime::Runtime;
use ndn_security::{CertCache, SignedTrustContext, Validator};
use ndn_store::{CsEntry, ErasedContentStore};

use crate::observability::targets as t;

/// Evict CS entries covered by each revocation `validator`'s keyring adopts.
pub(crate) fn install(
    validator: &Validator,
    cs: &Arc<dyn ErasedContentStore>,
    runtime: Arc<dyn Runtime>,
) {
    let cs = Arc::downgrade(cs);
    let certs = validator.cert_cache_arc();
    validator.keyring().on_revocation(move |ctx, revoked| {
        purge(&cs, &certs, &runtime, Arc::clone(ctx), revoked.len());
    });
}

fn purge(
    cs: &Weak<dyn ErasedContentStore>,
    certs: &Arc<CertCache>,
    runtime: &Arc<dyn Runtime>,
    ctx: Arc<SignedTrustContext>,
    newly_revoked: usize,
) {
    let Some(cs) = cs.upgrade() else {
        return;
    };
    let certs = Arc::clone(certs);
    let mut eviction: Pin<Box<dyn Future<Output = ()> + Send>> = Box::pin(async move {
        let namespace = ctx.namespace().clone();
        let version = ctx.version();
        let covered = move |wire: &Bytes| !known_clear(&ctx, &certs, wire);
        let evicted = cs.evict_matching_erased(&namespace, &covered).await;
        tracing::info!(
            target: t::SECURITY,
            namespace = %namespace,
            version,
            newly_revoked,
            evicted,
            "trust context revokes keys: evicted the cached Data they signed"
        );
    });
    if eviction
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending()
    {
        runtime.spawn(eviction);
    }
}

/// Judge a cached `entry` stamped before the keyring's revocation epoch moved
/// to `epoch` (loaded before this call, so before the context is read)
/// against the revocations held now. Known clear: restamped with `epoch` and
/// servable. Covered, not known clear, or no longer decodable: evicted unless
/// replaced meanwhile, and not servable. Returns whether it may be served.
pub(crate) async fn recheck(
    cs: &dyn ErasedContentStore,
    validator: &Validator,
    entry: &CsEntry,
    epoch: u64,
) -> bool {
    let ctx = validator.keyring().context_for(&entry.name);
    let servable = known_clear(&ctx, validator.cert_cache(), &entry.data);
    if servable {
        cs.restamp_erased(&entry.name, &entry.data, epoch).await;
    } else {
        let held = entry.data.clone();
        cs.evict_matching_erased(&entry.name, &move |wire: &Bytes| *wire == held)
            .await;
    }
    servable
}

/// Whether the Data in `wire` decodes and the durable re-check
/// ([`ndn_security::chain_clear`]) holds for it under `ctx`: the same rule
/// the validation stage applies to its signer (cut, key digest, manifest,
/// DataRequiresCut), each hop resolved to the cached certificate that
/// verifies it.
fn known_clear(ctx: &SignedTrustContext, certs: &CertCache, wire: &Bytes) -> bool {
    Data::decode(wire.clone()).is_ok_and(|data| ndn_security::chain_clear(ctx, certs, &data))
}

#[cfg(test)]
mod tests {
    //! Invariant: once a trust-context update revoking a key is adopted, Data
    //! signed through that key is never served from the Content Store,
    //! whenever it was validated or inserted (before the update, during it,
    //! after it, or by an earlier process into a persistent store); Data of
    //! keys the update does not revoke keeps being served.

    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use ndn_packet::encode::{DataBuilder, InterestBuilder};
    use ndn_packet::{Interest, Name, SignatureType};
    use ndn_security::{Certificate, Ed25519Signer, Keyring, Signer};
    use ndn_store::{
        AdmitAllPolicy, ContentStore, CsCapacity, CsEntryFilter, CsMeta, FjallCs, InsertResult,
        LruCs,
    };
    use ndn_transport::FaceId;

    use super::*;
    use crate::pipeline::{Action, DecodedPacket, PacketContext};
    use crate::stages::validation::{PendingQueueConfig, ValidationStage};
    use crate::stages::{CsInsertStage, CsLookupStage};

    const A_PHOTO: &str = "/home/bob/member/a/photo";
    const B_PHOTO: &str = "/home/bob/member/b/photo";

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    struct Key {
        name: Name,
        signer: Ed25519Signer,
    }

    impl Key {
        fn new(name: &str, seed: u8) -> Self {
            let name = n(name);
            let signer = Ed25519Signer::from_seed(&[seed; 32], name.clone());
            Self { name, signer }
        }

        fn anchor(&self) -> Certificate {
            Certificate {
                name: Arc::new(self.name.clone()),
                public_key: Bytes::copy_from_slice(&self.signer.public_key_bytes()),
                valid_from: 0,
                valid_until: u64::MAX,
                issuer: None,
                signed_region: None,
                sig_value: None,
                sig_type: SignatureType::SignatureEd25519,
            }
        }

        /// A Data packet this key signed, as it reaches the validation stage.
        fn data(&self, name: &str) -> PacketContext {
            let wire = DataBuilder::new(n(name), b"photo")
                .freshness(Duration::from_secs(60))
                .sign_sync(
                    SignatureType::SignatureEd25519,
                    Some(&self.name),
                    |region| self.signer.sign_sync(region).unwrap(),
                );
            let data = Data::decode(wire.clone()).unwrap();
            let mut ctx = PacketContext::new(wire, FaceId(1), 0);
            ctx.name = Some(Arc::clone(&data.name));
            ctx.packet = DecodedPacket::Data(Box::new(data));
            ctx
        }

        /// This key's certificate, issued by `issuer`.
        fn certified_by(&self, issuer: &Key) -> Certificate {
            let wire = DataBuilder::new(
                self.name.clone().append("NA").append_version(1),
                &self.signer.public_key_bytes(),
            )
            .sign_sync(
                SignatureType::SignatureEd25519,
                Some(&issuer.name),
                |region| issuer.signer.sign_sync(region).unwrap(),
            );
            Certificate::decode(&Data::decode(wire).unwrap()).unwrap()
        }
    }

    fn keys() -> (Key, Key) {
        (
            Key::new("/home/bob/member/a/KEY/1", 1),
            Key::new("/home/bob/member/b/KEY/2", 2),
        )
    }

    /// `/home/bob` with `keys` as anchors and `/home/bob/CA` as its CA, at
    /// `version`, revoking `revoked`.
    fn context(keys: &[&Key], version: u64, revoked: &[&Key]) -> Arc<SignedTrustContext> {
        let mut ctx = SignedTrustContext::hierarchical(n("/home/bob"))
            .with_ca_endpoint(n("/home/bob/CA"))
            .with_version(version);
        for key in revoked {
            ctx = ctx.with_revocation(key.name.clone());
        }
        for key in keys {
            assert!(ctx.add_anchor(key.anchor()));
        }
        Arc::new(ctx)
    }

    /// The engine's validation, CS-insert and CS-lookup stages over `cs`,
    /// sharing one validator as the engine builder wires them.
    struct Node {
        cs: Arc<dyn ErasedContentStore>,
        validation: ValidationStage,
        insert: CsInsertStage,
        lookup: CsLookupStage,
    }

    impl Node {
        /// `purge`: also install the eager purge, as the builder does.
        fn new(keyring: Arc<Keyring>, cs: Arc<dyn ErasedContentStore>, purge: bool) -> Self {
            Self::with_certs(keyring, cs, purge, Arc::new(CertCache::new()))
        }

        /// [`Self::new`] whose validator starts with `certs` cached.
        fn with_certs(
            keyring: Arc<Keyring>,
            cs: Arc<dyn ErasedContentStore>,
            purge: bool,
            certs: Arc<CertCache>,
        ) -> Self {
            let runtime = ndn_runtime::default_runtime();
            let validator = Arc::new(Validator::with_keyring(keyring, certs, None, 5));
            if purge {
                install(&validator, &cs, Arc::clone(&runtime));
            }
            Self {
                validation: ValidationStage::new(
                    Some(Arc::clone(&validator)),
                    PendingQueueConfig::default(),
                    runtime,
                ),
                insert: CsInsertStage {
                    cs: Arc::clone(&cs),
                    admission: Arc::new(AdmitAllPolicy),
                    admit_unverified: false,
                },
                lookup: CsLookupStage {
                    cs: Arc::clone(&cs),
                    validator: Some(validator),
                },
                cs,
            }
        }

        async fn validated(&self, ctx: PacketContext) -> PacketContext {
            match self.validation.process(ctx).await {
                Action::Satisfy(ctx) if ctx.verified => ctx,
                _ => panic!("Data must validate"),
            }
        }

        async fn insert(&self, ctx: PacketContext) {
            assert!(matches!(self.insert.process(ctx).await, Action::Satisfy(_)));
        }

        /// Validate, then cache, as the pipeline does with Data from a face.
        async fn receive(&self, ctx: PacketContext) {
            let ctx = self.validated(ctx).await;
            self.insert(ctx).await;
        }

        /// Whether the CS lookup stage answers an Interest for `name`.
        async fn serves(&self, name: &str) -> bool {
            let wire = InterestBuilder::new(n(name)).build();
            let interest = Interest::decode(wire.clone()).unwrap();
            let mut ctx = PacketContext::new(wire, FaceId(2), 0);
            ctx.name = Some(Arc::clone(&interest.name));
            ctx.packet = DecodedPacket::Interest(Box::new(interest));
            matches!(self.lookup.process(ctx).await, Action::Satisfy(_))
        }

        /// The revocation stamp of the entry held for `name`, if one is held.
        async fn stamp(&self, name: &str) -> Option<Option<u64>> {
            let entry = self.cs.get_erased(&Interest::new(n(name)), 0).await?;
            Some(entry.revocation_epoch)
        }
    }

    /// No purge runs, so the entries are still held when the update lands:
    /// the stamp alone keeps the revoked one from being served.
    #[tokio::test]
    async fn data_cached_before_a_revoking_update_is_never_served_after_it() {
        let (a, b) = keys();
        let keyring = Arc::new(Keyring::new());
        keyring.adopt(context(&[&a, &b], 1, &[]));
        let node = Node::new(Arc::clone(&keyring), Arc::new(LruCs::new(1 << 20)), false);
        node.receive(a.data(A_PHOTO)).await;
        node.receive(b.data(B_PHOTO)).await;
        assert!(node.serves(A_PHOTO).await && node.serves(B_PHOTO).await);

        keyring.adopt_update(context(&[&a, &b], 2, &[&a])).unwrap();

        assert!(
            !node.serves(A_PHOTO).await,
            "Data of a revoked key must not be served"
        );
        assert_eq!(node.stamp(A_PHOTO).await, None, "and is evicted at the hit");
        assert!(
            node.serves(B_PHOTO).await,
            "Data of a key not revoked is still served"
        );
        assert_eq!(
            node.stamp(B_PHOTO).await,
            Some(Some(keyring.revocation_epoch())),
            "re-stamped, so it is judged once per update"
        );
    }

    /// The update (and its purge) lands after the validation stage passed the
    /// Data and before the CS insert stage gets it.
    #[tokio::test]
    async fn data_validated_before_a_revoking_update_and_cached_after_it_is_never_served() {
        let (a, b) = keys();
        let keyring = Arc::new(Keyring::new());
        keyring.adopt(context(&[&a, &b], 1, &[]));
        let node = Node::new(Arc::clone(&keyring), Arc::new(LruCs::new(1 << 20)), true);
        let by_a = node.validated(a.data(A_PHOTO)).await;
        let by_b = node.validated(b.data(B_PHOTO)).await;

        keyring.adopt_update(context(&[&a, &b], 2, &[&a])).unwrap();
        node.insert(by_a).await;
        node.insert(by_b).await;

        assert!(
            !node.serves(A_PHOTO).await,
            "Data of a revoked key must not be served"
        );
        assert!(
            node.serves(B_PHOTO).await,
            "Data of a key not revoked is still served"
        );
    }

    /// A store that adopts `update` when the CS insert stage calls `insert`,
    /// before the entry lands: the update's purge scans before the entry is
    /// there to be found.
    struct UpdateDuringInsert {
        inner: LruCs,
        keyring: Arc<Keyring>,
        update: Arc<SignedTrustContext>,
        armed: AtomicBool,
    }

    impl ContentStore for UpdateDuringInsert {
        fn get(
            &self,
            interest: &Interest,
            now_ns: u64,
        ) -> impl Future<Output = Option<CsEntry>> + Send {
            self.inner.get(interest, now_ns)
        }

        fn insert(
            &self,
            data: Bytes,
            name: Arc<Name>,
            meta: CsMeta,
        ) -> impl Future<Output = InsertResult> + Send {
            if self.armed.swap(false, Ordering::SeqCst) {
                self.keyring.adopt_update(Arc::clone(&self.update)).unwrap();
            }
            self.inner.insert(data, name, meta)
        }

        fn evict(&self, name: &Name) -> impl Future<Output = bool> + Send {
            self.inner.evict(name)
        }

        fn capacity(&self) -> CsCapacity {
            ContentStore::capacity(&self.inner)
        }

        fn evict_matching(
            &self,
            prefix: &Name,
            matches: &CsEntryFilter,
        ) -> impl Future<Output = usize> + Send {
            self.inner.evict_matching(prefix, matches)
        }

        fn restamp(
            &self,
            name: &Name,
            data: &Bytes,
            epoch: u64,
        ) -> impl Future<Output = ()> + Send {
            self.inner.restamp(name, data, epoch)
        }
    }

    #[tokio::test]
    async fn data_cached_during_a_revoking_update_is_never_served() {
        let a = Key::new("/home/bob/member/a/KEY/1", 1);
        let keyring = Arc::new(Keyring::new());
        keyring.adopt(context(&[&a], 1, &[]));
        let cs = Arc::new(UpdateDuringInsert {
            inner: LruCs::new(1 << 20),
            keyring: Arc::clone(&keyring),
            update: context(&[&a], 2, &[&a]),
            armed: AtomicBool::new(true),
        });
        let node = Node::new(Arc::clone(&keyring), cs, true);

        node.receive(a.data(A_PHOTO)).await;
        assert_eq!(
            keyring.revocation_epoch(),
            1,
            "the update landed mid-insert"
        );
        assert!(
            !node.serves(A_PHOTO).await,
            "an entry the update's purge could not see yet must not be served"
        );
    }

    /// The keyring a restarted node loads before building its engine can
    /// hold the same epoch the persisted entries were stamped with, and no
    /// purge runs for revocations it already holds at startup.
    #[tokio::test]
    async fn a_persisted_entry_of_a_revoked_key_is_never_served_after_a_restart() {
        let (a, b) = keys();
        let c = Key::new("/home/bob/member/c/KEY/3", 3);
        let dir = tempfile::tempdir().unwrap();
        {
            let keyring = Arc::new(Keyring::new());
            keyring.adopt(context(&[&a, &b, &c], 1, &[]));
            keyring
                .adopt_update(context(&[&a, &b, &c], 2, &[&c]))
                .unwrap();
            let cs = Arc::new(FjallCs::open(dir.path(), 1 << 20).unwrap());
            let node = Node::new(Arc::clone(&keyring), cs, true);
            node.receive(a.data(A_PHOTO)).await;
            node.receive(b.data(B_PHOTO)).await;
            assert_eq!(node.stamp(A_PHOTO).await, Some(Some(1)));
        }

        let keyring = Arc::new(Keyring::new());
        keyring.adopt(context(&[&a, &b, &c], 3, &[&c, &a]));
        assert_eq!(
            keyring.revocation_epoch(),
            1,
            "the epoch the entries were stamped with in the earlier process"
        );
        let cs = Arc::new(FjallCs::open(dir.path(), 1 << 20).unwrap());
        let node = Node::new(Arc::clone(&keyring), cs, true);

        assert!(
            !node.serves(A_PHOTO).await,
            "persisted Data of a key revoked at startup must not be served"
        );
        assert!(
            node.serves(B_PHOTO).await,
            "persisted Data of a key not revoked is still served"
        );
        assert_eq!(
            node.stamp(B_PHOTO).await,
            Some(Some(1)),
            "re-stamped in this process"
        );
    }

    /// After a restart the validator's certificate cache holds none of the
    /// chain of another device's Data. A persisted entry signed by a device
    /// key that is not revoked itself, under a CA a later update revokes (a
    /// compromised-namespace recovery), is still never served.
    #[tokio::test]
    async fn a_persisted_entry_under_a_revoked_ca_is_never_served_after_a_restart() {
        const D_PHOTO: &str = "/home/bob/member/d/photo";
        let root = Key::new("/home/bob/KEY/0", 10);
        let ca = Key::new("/home/bob/CA/KEY/9", 11);
        let d = Key::new("/home/bob/member/d/KEY/4", 12);
        let (_, b) = keys();
        let dir = tempfile::tempdir().unwrap();
        {
            let keyring = Arc::new(Keyring::new());
            keyring.adopt(context(&[&root, &b], 1, &[]));
            let certs = Arc::new(CertCache::new());
            certs.insert(ca.certified_by(&root));
            certs.insert(d.certified_by(&ca));
            let cs = Arc::new(FjallCs::open(dir.path(), 1 << 20).unwrap());
            let node = Node::with_certs(Arc::clone(&keyring), cs, true, certs);
            node.receive(d.data(D_PHOTO)).await;
            node.receive(b.data(B_PHOTO)).await;
            assert!(node.serves(D_PHOTO).await);
        }

        let keyring = Arc::new(Keyring::new());
        keyring.adopt(context(&[&root, &b], 2, &[&ca]));
        let cs = Arc::new(FjallCs::open(dir.path(), 1 << 20).unwrap());
        let node = Node::new(Arc::clone(&keyring), cs, true);

        assert!(
            !node.serves(D_PHOTO).await,
            "persisted Data under a CA revoked at startup must not be served"
        );
        assert!(
            node.serves(B_PHOTO).await,
            "persisted Data of an anchor not revoked is still served"
        );
    }

    /// A key revoked with a cut keeps the Data its cut accepts — served from
    /// the CS and validated anew — while the rest it signed is purged and
    /// refused; its certificate stays, as in-cut Data needs it to verify.
    #[tokio::test]
    async fn a_cut_keeps_what_it_accepts_and_the_keys_certificate() {
        const IN_CUT: &str = "/home/bob/member/d/notes/seq=2";
        const OUT_OF_CUT: &str = "/home/bob/member/d/notes/seq=5";
        let root = Key::new("/home/bob/KEY/0", 10);
        let ca = Key::new("/home/bob/CA/KEY/9", 11);
        let d = Key::new("/home/bob/member/d/KEY/4", 12);
        let keyring = Arc::new(Keyring::new());
        keyring.adopt(context(&[&root], 1, &[]));
        let certs = Arc::new(CertCache::new());
        certs.insert(ca.certified_by(&root));
        certs.insert(d.certified_by(&ca));
        let node = Node::with_certs(
            Arc::clone(&keyring),
            Arc::new(LruCs::new(1 << 20)),
            true,
            Arc::clone(&certs),
        );
        node.receive(d.data(IN_CUT)).await;
        node.receive(d.data(OUT_OF_CUT)).await;

        let revoking = |cut: Option<ndn_security::RevocationCut>| {
            let mut ctx = SignedTrustContext::hierarchical(n("/home/bob"))
                .with_ca_endpoint(n("/home/bob/CA"))
                .with_version(2)
                .with_revocation(d.name.clone());
            if let Some(cut) = cut {
                ctx = ctx.with_revocation_cut(cut);
            }
            assert!(ctx.add_anchor(root.anchor()));
            ctx
        };
        let mut cut = ndn_security::RevocationCut::new(d.name.clone());
        cut.add_run(&n("/home/bob/member/d/notes"), 1, 3);
        keyring.adopt_update(Arc::new(revoking(Some(cut)))).unwrap();

        assert!(node.serves(IN_CUT).await, "in-cut Data is still served");
        assert!(!node.serves(OUT_OF_CUT).await, "out-of-cut Data is not");
        node.validated(d.data(IN_CUT)).await;
        assert!(matches!(
            node.validation.process(d.data(OUT_OF_CUT)).await,
            Action::Refuse(_, ndn_packet::Refusal::Revoked)
        ));

        let certificate = d.certified_by(&ca).data_wire().unwrap();
        let with_cut = keyring.context_for(&n("/home/bob"));
        assert!(
            known_clear(&with_cut, &certs, &certificate),
            "the certificate of a key revoked with a cut is kept"
        );
        assert!(
            !known_clear(&revoking(None), &certs, &certificate),
            "the certificate of a key revoked without a cut is not"
        );
    }

    /// A later version whose cut of the key accepts less (a shrunk run)
    /// is a revoking update: the Data the old cut kept and the new one does
    /// not is no longer served from the CS.
    #[tokio::test]
    async fn a_cut_that_shrinks_stops_serving_what_it_no_longer_accepts() {
        const KEPT: &str = "/home/bob/member/d/notes/seq=1";
        const DROPPED: &str = "/home/bob/member/d/notes/seq=2";
        let root = Key::new("/home/bob/KEY/0", 10);
        let ca = Key::new("/home/bob/CA/KEY/9", 11);
        let d = Key::new("/home/bob/member/d/KEY/4", 12);
        let keyring = Arc::new(Keyring::new());
        let version = |v: u64, last: u64| {
            let mut cut = ndn_security::RevocationCut::new(d.name.clone());
            cut.add_run(&n("/home/bob/member/d/notes"), 1, last);
            let ctx = SignedTrustContext::hierarchical(n("/home/bob"))
                .with_ca_endpoint(n("/home/bob/CA"))
                .with_version(v)
                .with_revocation(d.name.clone())
                .with_revocation_cut(cut);
            assert!(ctx.add_anchor(root.anchor()));
            Arc::new(ctx)
        };
        keyring.adopt(version(1, 3));
        let certs = Arc::new(CertCache::new());
        certs.insert(ca.certified_by(&root));
        certs.insert(d.certified_by(&ca));
        let node = Node::with_certs(
            Arc::clone(&keyring),
            Arc::new(LruCs::new(1 << 20)),
            false,
            certs,
        );
        node.receive(d.data(KEPT)).await;
        node.receive(d.data(DROPPED)).await;
        assert!(node.serves(KEPT).await && node.serves(DROPPED).await);

        keyring.adopt_update(version(2, 1)).unwrap();
        assert!(node.serves(KEPT).await, "still in the cut");
        assert!(
            !node.serves(DROPPED).await,
            "Data the shrunk cut no longer accepts must not be served"
        );
    }

    /// Two certificates name one key: an honest one from the current CA and
    /// one a compromised old CA issued for the attacker's public key. Data
    /// the attacker signed validated through the old CA; once the old CA is
    /// revoked, the CS re-check follows the certificate that verifies the
    /// Data (the old CA's), not the newest one of the key name, and stops
    /// serving it.
    #[tokio::test]
    async fn the_recheck_follows_the_certificate_that_verifies_the_data() {
        const FORGED: &str = "/home/bob/member/d/photo";
        let root = Key::new("/home/bob/KEY/0", 10);
        let old_ca = Key::new("/home/bob/CA/KEY/old", 11);
        let new_ca = Key::new("/home/bob/CA/KEY/new", 13);
        let honest = Key::new("/home/bob/member/d/KEY/4", 12);
        let attacker = Key::new("/home/bob/member/d/KEY/4", 66);
        // `<key>/<issuer-id>/v=1` of `subject`'s public key, signed by `issuer`.
        let cert = |subject: &Key, issuer_id: &str, issuer: &Key| {
            let wire = DataBuilder::new(
                subject.name.clone().append(issuer_id).append_version(1),
                &subject.signer.public_key_bytes(),
            )
            .sign_sync(
                SignatureType::SignatureEd25519,
                Some(&issuer.name),
                |region| issuer.signer.sign_sync(region).unwrap(),
            );
            Certificate::decode(&Data::decode(wire).unwrap()).unwrap()
        };
        let keyring = Arc::new(Keyring::new());
        keyring.adopt(context(&[&root], 1, &[]));
        let certs = Arc::new(CertCache::new());
        certs.insert(old_ca.certified_by(&root));
        certs.insert(new_ca.certified_by(&root));
        // The honest certificate is the newest of the key name.
        certs.insert(cert(&attacker, "a-old", &old_ca));
        certs.insert(cert(&honest, "b-new", &new_ca));
        let node = Node::with_certs(
            Arc::clone(&keyring),
            Arc::new(LruCs::new(1 << 20)),
            false,
            certs,
        );
        node.receive(attacker.data(FORGED)).await;
        assert!(node.serves(FORGED).await);

        keyring
            .adopt_update(context(&[&root], 2, &[&old_ca]))
            .unwrap();
        assert!(
            !node.serves(FORGED).await,
            "Data verified only through the revoked CA must not be served"
        );
    }

    /// The CS re-check applies the cut's manifest as validation does: after
    /// a revoking update whose cut lists the honest bytes at an in-range
    /// name, the honest packet is served and an in-range entry the manifest
    /// does not list is not; without the manifest held, nothing in range is
    /// known clear.
    #[tokio::test]
    async fn the_recheck_applies_the_cuts_manifest() {
        const HONEST: &str = "/home/bob/member/d/notes/seq=2";
        const UNLISTED: &str = "/home/bob/member/d/notes/seq=3";
        let root = Key::new("/home/bob/KEY/0", 10);
        let ca = Key::new("/home/bob/CA/KEY/9", 11);
        let d = Key::new("/home/bob/member/d/KEY/4", 12);
        let keyring = Arc::new(Keyring::new());
        keyring.adopt(context(&[&root], 1, &[]));
        let certs = Arc::new(CertCache::new());
        certs.insert(ca.certified_by(&root));
        certs.insert(d.certified_by(&ca));
        let node = Node::with_certs(
            Arc::clone(&keyring),
            Arc::new(LruCs::new(1 << 20)),
            false,
            Arc::clone(&certs),
        );
        let honest = d.data(HONEST);
        let honest_wire = honest.raw_bytes.clone();
        let honest_digest = Data::decode(honest_wire.clone()).unwrap().implicit_digest();
        let manifest = ndn_security::cut_manifest::build(
            &n("/home/bob"),
            &d.name,
            &[(n("/home/bob/member/d/notes"), 2, honest_digest)],
        )
        .unwrap();
        node.receive(honest).await;
        node.receive(d.data(UNLISTED)).await;

        let mut cut = ndn_security::RevocationCut::new(d.name.clone());
        cut.add_run(&n("/home/bob/member/d/notes"), 1, 3);
        cut.set_manifest(manifest.root.clone()).unwrap();
        let ctx = SignedTrustContext::hierarchical(n("/home/bob"))
            .with_ca_endpoint(n("/home/bob/CA"))
            .with_version(2)
            .with_revocation(d.name.clone())
            .with_revocation_cut(cut);
        assert!(ctx.add_anchor(root.anchor()));
        keyring.adopt_update(Arc::new(ctx)).unwrap();
        let held = keyring.context_for(&n(HONEST));
        assert!(
            !known_clear(&held, &certs, &honest_wire),
            "not known clear while the manifest is not held"
        );
        certs
            .cut_manifests()
            .insert(&Data::decode(manifest.packets[0].clone()).unwrap())
            .unwrap();
        assert!(known_clear(&held, &certs, &honest_wire));
        assert!(node.serves(HONEST).await, "the listed bytes are served");
        assert!(
            !node.serves(UNLISTED).await,
            "an in-range entry not listed is not"
        );
    }
}
