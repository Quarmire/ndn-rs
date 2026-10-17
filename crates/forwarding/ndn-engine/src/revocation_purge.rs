//! Drop cached Data whose signing key a newly adopted trust context revokes.
//!
//! The Content Store answers Interests without validating again: Data is
//! validated once, before it is admitted. When the node adopts a version of a
//! trust context that revokes a key, Data that key signed may already sit in
//! the CS, and would be served until its freshness ran out. The engine
//! registers [`install`] on its validator's keyring, so on every such adoption
//! (an update by refresh, a revocation on the root device, a context pushed by
//! sync) it evicts, under that context's namespace, every entry that the
//! revoked names cover:
//!
//! - its signing key, or any certificate up its chain as far as the
//!   validator's certificate cache knows it, is revoked; or
//! - the entry is itself a revoked key's certificate.
//!
//! Eviction instead of re-validating on a hit: the forwarding path stays
//! exactly as it is (no per-hit check, nothing at all while nothing is
//! revoked), and the scan runs once per revoking update, which is rare. The
//! eviction completes before the adoption call returns for every store whose
//! scan does not suspend (all in-tree stores); a store that does finish it on
//! the runtime.
//!
//! The scan cannot see Data that was validated just before the update and
//! is inserted after it. `ValidationStage` records the keyring's revocation
//! epoch before it validates, and `CsInsertStage` compares it with
//! [`Keyring::revocation_epoch`](ndn_security::Keyring::revocation_epoch)
//! twice, one atomic load each: before inserting, refusing Data that
//! [`revoked_now`] covers, and after, evicting it again with
//! [`evict_if_revoked`] if an update landed during the insert itself (the
//! update's epoch bump precedes its scan, so either the scan finds the
//! entry or the second load sees the bump). Only when the epoch moved is
//! the Data re-checked.

use std::pin::Pin;
use std::sync::{Arc, Weak};
use std::task::{Context, Waker};

use bytes::Bytes;
use ndn_packet::{Data, Name};
use ndn_runtime::Runtime;
use ndn_security::{CertCache, SignedTrustContext, Validator};
use ndn_store::ErasedContentStore;

use crate::observability::targets as t;

/// How far up a cached entry's chain to look for a revoked certificate.
const MAX_CHAIN: usize = 8;

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
        let covered = move |wire: &Bytes| covered_by_revocation(&ctx, &certs, wire);
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

/// Whether `data`'s name or signing chain is covered by a revocation of the
/// context that governs it now, by the same rules as the purge. For Data
/// validated before the keyring's revocation epoch last moved.
pub(crate) fn revoked_now(validator: &Validator, data: &Data) -> bool {
    let ctx = validator.keyring().context_for(&data.name);
    data_covered(&ctx, validator.cert_cache(), data)
}

/// Evict the entries named `name` (and under it) that the revocations of the
/// context governing `name` now cover; returns how many.
pub(crate) async fn evict_if_revoked(
    cs: &dyn ErasedContentStore,
    validator: &Validator,
    name: &Name,
) -> usize {
    let ctx = validator.keyring().context_for(name);
    let certs = validator.cert_cache_arc();
    let covered = move |wire: &Bytes| covered_by_revocation(&ctx, &certs, wire);
    cs.evict_matching_erased(name, &covered).await
}

/// Whether the Data in `wire` is a certificate `ctx` revokes, or is signed
/// by a key `ctx` revokes directly or anywhere up its chain.
fn covered_by_revocation(ctx: &SignedTrustContext, certs: &CertCache, wire: &Bytes) -> bool {
    Data::decode(wire.clone()).is_ok_and(|data| data_covered(ctx, certs, &data))
}

fn data_covered(ctx: &SignedTrustContext, certs: &CertCache, data: &Data) -> bool {
    if ctx.is_revoked(&data.name) {
        return true;
    }
    let mut signer: Option<Arc<Name>> = data.sig_info().and_then(|si| si.key_locator_name());
    for _ in 0..MAX_CHAIN {
        let Some(key) = signer else {
            return false;
        };
        if ctx.is_revoked(&key) {
            return true;
        }
        signer = certs.get(&key).and_then(|cert| cert.issuer);
    }
    false
}

#[cfg(test)]
mod tests {
    //! Invariant: Data validated before a revoking trust-context update is
    //! never inserted into, or served from, the Content Store after it,
    //! however the update interleaves with the validation and insert stages.

    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use ndn_packet::encode::DataBuilder;
    use ndn_packet::{Interest, SignatureType};
    use ndn_security::{Certificate, Ed25519Signer, Keyring, Signer};
    use ndn_store::{
        AdmitAllPolicy, ContentStore, CsCapacity, CsEntry, CsEntryFilter, CsMeta, InsertResult,
        LruCs,
    };
    use ndn_transport::FaceId;

    use super::*;
    use crate::pipeline::{Action, DecodedPacket, PacketContext};
    use crate::stages::validation::{PendingQueueConfig, ValidationStage};
    use crate::stages::{CsInsertStage, CsLookupStage};

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
    }

    /// `/home/bob` with both keys as anchors, at `version`, revoking `revoked`.
    fn context(keys: &[&Key], version: u64, revoked: Option<&Key>) -> Arc<SignedTrustContext> {
        let mut ctx = SignedTrustContext::hierarchical(n("/home/bob")).with_version(version);
        if let Some(key) = revoked {
            ctx = ctx.with_revocation(key.name.clone());
        }
        for key in keys {
            assert!(ctx.add_anchor(key.anchor()));
        }
        Arc::new(ctx)
    }

    /// The engine's validation and CS-insert stages over `cs`, with the
    /// purge installed as the engine builder installs it.
    fn stages(
        keyring: Arc<Keyring>,
        cs: Arc<dyn ErasedContentStore>,
    ) -> (ValidationStage, CsInsertStage) {
        let runtime = ndn_runtime::default_runtime();
        let validator = Arc::new(Validator::with_keyring(
            keyring,
            Arc::new(CertCache::new()),
            None,
            5,
        ));
        install(&validator, &cs, Arc::clone(&runtime));
        let validation = ValidationStage::new(
            Some(Arc::clone(&validator)),
            PendingQueueConfig::default(),
            runtime,
        );
        let insert = CsInsertStage {
            cs,
            admission: Arc::new(AdmitAllPolicy),
            admit_unverified: false,
            validator: Some(validator),
        };
        (validation, insert)
    }

    async fn validated(validation: &ValidationStage, ctx: PacketContext) -> PacketContext {
        match validation.process(ctx).await {
            Action::Satisfy(ctx) if ctx.verified => ctx,
            _ => panic!("Data must validate before the update"),
        }
    }

    async fn cached(cs: &dyn ErasedContentStore, name: &str) -> bool {
        cs.get_erased(&Interest::new(n(name))).await.is_some()
    }

    /// The update is adopted (and its purge has run) after the validation
    /// stage passed the Data and before the CS insert stage gets it.
    #[tokio::test]
    async fn data_validated_before_a_revoking_update_is_not_cached_after_it() {
        let (a, b) = (
            Key::new("/home/bob/member/a/KEY/1", 1),
            Key::new("/home/bob/member/b/KEY/2", 2),
        );
        let keyring = Arc::new(Keyring::new());
        keyring.adopt(context(&[&a, &b], 1, None));
        let cs: Arc<dyn ErasedContentStore> = Arc::new(LruCs::new(1 << 20));
        let (validation, insert) = stages(Arc::clone(&keyring), Arc::clone(&cs));

        let by_a = validated(&validation, a.data("/home/bob/member/a/photo")).await;
        let by_b = validated(&validation, b.data("/home/bob/member/b/photo")).await;
        assert_eq!(by_a.revocation_epoch, Some(0));

        keyring
            .adopt_update(context(&[&a, &b], 2, Some(&a)))
            .unwrap();
        assert_eq!(keyring.revocation_epoch(), 1);

        assert!(matches!(insert.process(by_a).await, Action::Satisfy(_)));
        assert!(matches!(insert.process(by_b).await, Action::Satisfy(_)));
        assert!(
            !cached(&*cs, "/home/bob/member/a/photo").await,
            "Data of the key revoked after validation must not be cached"
        );
        let lookup = CsLookupStage {
            cs: Arc::clone(&cs),
        };
        let interest =
            ndn_packet::encode::InterestBuilder::new(n("/home/bob/member/a/photo")).build();
        let mut ictx = PacketContext::new(interest.clone(), FaceId(2), 0);
        let decoded = Interest::decode(interest).unwrap();
        ictx.name = Some(Arc::clone(&decoded.name));
        ictx.packet = DecodedPacket::Interest(Box::new(decoded));
        assert!(
            matches!(lookup.process(ictx).await, Action::Continue(_)),
            "and never served from the CS"
        );
        assert!(
            cached(&*cs, "/home/bob/member/b/photo").await,
            "an update that revokes another key does not stop this one being cached"
        );
    }

    /// A store that adopts `update` when the CS insert stage calls `insert`,
    /// before the entry lands: the update (and its purge) falls between the
    /// stage's epoch check and the insert.
    struct UpdateDuringInsert {
        inner: LruCs,
        keyring: Arc<Keyring>,
        update: Arc<SignedTrustContext>,
        armed: AtomicBool,
    }

    impl ContentStore for UpdateDuringInsert {
        fn get(&self, interest: &Interest) -> impl Future<Output = Option<CsEntry>> + Send {
            self.inner.get(interest)
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
    }

    #[tokio::test]
    async fn an_update_adopted_during_the_insert_is_evicted_again() {
        let a = Key::new("/home/bob/member/a/KEY/1", 1);
        let keyring = Arc::new(Keyring::new());
        keyring.adopt(context(&[&a], 1, None));
        let cs = Arc::new(UpdateDuringInsert {
            inner: LruCs::new(1 << 20),
            keyring: Arc::clone(&keyring),
            update: context(&[&a], 2, Some(&a)),
            armed: AtomicBool::new(true),
        });
        let (validation, insert) = stages(
            Arc::clone(&keyring),
            Arc::clone(&cs) as Arc<dyn ErasedContentStore>,
        );

        let by_a = validated(&validation, a.data("/home/bob/member/a/photo")).await;
        assert!(matches!(insert.process(by_a).await, Action::Satisfy(_)));
        assert_eq!(
            keyring.revocation_epoch(),
            1,
            "the update landed mid-insert"
        );
        assert!(
            !cached(&*cs, "/home/bob/member/a/photo").await,
            "an entry the update's purge could not see yet must not stay cached"
        );
    }
}
