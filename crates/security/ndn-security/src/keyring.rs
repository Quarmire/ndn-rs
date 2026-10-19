//! [`Keyring`] — the set of [`SignedTrustContext`]s a node holds.
//!
//! Adopting a context is additive and orthogonal: a node may hold
//! `/home/bob`, `/work/acme`, and `/transit/city` at once, validating data
//! under each by its own schema and anchors. A [`Validator`](crate::Validator)
//! dispatches each packet to the context selected by [`context_for`] —
//! longest-prefix match on the data/command name — never "any anchor I hold."
//!
//! [`context_for`]: Keyring::context_for

use std::sync::atomic::Ordering;
use std::sync::{Arc, PoisonError, RwLock};

use portable_atomic::AtomicU64;

use dashmap::DashMap;
use ndn_packet::Name;

use crate::trust_context::SignedTrustContext;

/// Called once a context is adopted that revokes names the version it
/// replaces did not: the newly held context and those newly revoked names.
/// See [`Keyring::on_revocation`].
type RevocationListener = Arc<dyn Fn(&Arc<SignedTrustContext>, &[Name]) + Send + Sync>;

/// Called once a context (a new namespace, or a newer version) is adopted.
/// See [`Keyring::on_adoption`].
type AdoptionListener = Arc<dyn Fn(&Arc<SignedTrustContext>) + Send + Sync>;

/// A node's set of adopted trust contexts plus an ambient fallback context.
///
/// The `ambient` context (namespace `/`) backs the flat-anchor / single-schema
/// API on [`Validator`](crate::Validator) for backward compatibility; named
/// contexts adopted via [`adopt`](Self::adopt) take precedence by
/// longest-prefix match.
pub struct Keyring {
    contexts: DashMap<Name, Arc<SignedTrustContext>>,
    ambient: Arc<SignedTrustContext>,
    revocation_listeners: RwLock<Vec<RevocationListener>>,
    adoption_listeners: RwLock<Vec<AdoptionListener>>,
    /// Bumped each time an adopted version newly revokes names; see
    /// [`revocation_epoch`](Keyring::revocation_epoch).
    revocation_epoch: AtomicU64,
}

impl std::fmt::Debug for Keyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keyring")
            .field("contexts", &self.contexts)
            .field("ambient", &self.ambient)
            .finish_non_exhaustive()
    }
}

/// The names `new` revokes that `old` (the version it replaces, if any) did not.
fn newly_revoked(old: Option<&SignedTrustContext>, new: &SignedTrustContext) -> Vec<Name> {
    new.revocations()
        .iter()
        .filter(|r| old.is_none_or(|old| !old.revocations().contains(r)))
        .cloned()
        .collect()
}

impl Default for Keyring {
    fn default() -> Self {
        Self::new()
    }
}

impl Keyring {
    pub(crate) fn with_ambient(ambient: Arc<SignedTrustContext>) -> Self {
        Self {
            contexts: DashMap::new(),
            ambient,
            revocation_listeners: RwLock::new(Vec::new()),
            adoption_listeners: RwLock::new(Vec::new()),
            revocation_epoch: AtomicU64::new(0),
        }
    }

    /// An empty keyring with a **deny-by-default** ambient: a hierarchical root
    /// context with no anchors, so nothing validates until the holder adopts a
    /// context. The right starting point for a participant ("trust only what
    /// you join"), as opposed to the `Validator`-backed flat-anchor ambient.
    pub fn new() -> Self {
        Self::with_ambient(Arc::new(SignedTrustContext::hierarchical(
            ndn_packet::Name::root(),
        )))
    }

    /// The ambient (root-namespace) context — the validation target for names
    /// not covered by any adopted context.
    pub fn ambient(&self) -> &Arc<SignedTrustContext> {
        &self.ambient
    }

    /// Adopt a context into the keyring, keyed by its namespace.
    ///
    /// Anti-rollback: a context is accepted only if its `version` is **≥** the
    /// version currently held for the same namespace (a strictly older version
    /// is refused, so an attacker cannot serve a stale context to re-introduce
    /// a weakened schema or a revoked anchor). An *equal* version is accepted
    /// only when it encodes to the same content as the held one, and then
    /// changes nothing (re-adopting what is held); a differing context under
    /// the held version number — a fork — is refused. Returns `true` if
    /// adopted or already held.
    pub fn adopt(&self, ctx: Arc<SignedTrustContext>) -> bool {
        let ns = ctx.namespace().clone();
        let revoked = match self.contexts.entry(ns) {
            dashmap::mapref::entry::Entry::Occupied(mut held) => {
                if ctx.version() < held.get().version() {
                    return false;
                }
                if ctx.version() == held.get().version() {
                    return Arc::ptr_eq(held.get(), &ctx)
                        || held.get().encode_content() == ctx.encode_content();
                }
                let revoked = newly_revoked(Some(held.get().as_ref()), &ctx);
                held.insert(Arc::clone(&ctx));
                revoked
            }
            dashmap::mapref::entry::Entry::Vacant(slot) => {
                let revoked = newly_revoked(None, &ctx);
                slot.insert(Arc::clone(&ctx));
                revoked
            }
        };
        self.notify_revoked(&ctx, &revoked);
        self.notify_adopted(&ctx);
        true
    }

    /// Replace the held context of `ctx`'s namespace with `ctx` only if
    /// `ctx` is **strictly newer** — the rule for an update, where an equal
    /// version must not replace the held one either. Atomic against
    /// concurrent adoptions of the same namespace. `Err(Some(held))`: the
    /// held version is not older; `Err(None)`: nothing is held to update.
    pub fn adopt_update(&self, ctx: Arc<SignedTrustContext>) -> Result<(), Option<u64>> {
        let revoked = match self.contexts.get_mut(ctx.namespace()) {
            None => return Err(None),
            Some(held) if held.version() >= ctx.version() => return Err(Some(held.version())),
            Some(mut held) => {
                let revoked = newly_revoked(Some(held.as_ref()), &ctx);
                *held = Arc::clone(&ctx);
                revoked
            }
        };
        self.notify_revoked(&ctx, &revoked);
        self.notify_adopted(&ctx);
        Ok(())
    }

    /// Replace the held context of `ctx`'s namespace with `ctx` only if the
    /// held one is still `from` (the same `Arc`) — the version `ctx` was
    /// checked against as an update — and `ctx` is strictly newer. Lets a
    /// caller check an update without holding any lock (fetching it may
    /// take many round trips) and adopt it only if nothing changed the
    /// namespace meanwhile. Atomic against concurrent adoptions.
    /// `Err(Some(held))`: the held context is another one (or not older);
    /// `Err(None)`: nothing is held to update.
    pub fn adopt_update_from(
        &self,
        from: &Arc<SignedTrustContext>,
        ctx: Arc<SignedTrustContext>,
    ) -> Result<(), Option<u64>> {
        let revoked = match self.contexts.get_mut(ctx.namespace()) {
            None => return Err(None),
            Some(held) if !Arc::ptr_eq(&held, from) || held.version() >= ctx.version() => {
                return Err(Some(held.version()));
            }
            Some(mut held) => {
                let revoked = newly_revoked(Some(held.as_ref()), &ctx);
                *held = Arc::clone(&ctx);
                revoked
            }
        };
        self.notify_revoked(&ctx, &revoked);
        self.notify_adopted(&ctx);
        Ok(())
    }

    /// Run `listener` whenever this keyring adopts a context (by
    /// [`adopt`](Self::adopt), [`adopt_update`](Self::adopt_update) or
    /// [`adopt_update_from`](Self::adopt_update_from)) that
    /// revokes names the version it replaces did not — e.g. so a forwarder
    /// drops cached Data those keys signed. It runs synchronously on the
    /// adopting thread after the new context is in force and the
    /// [`revocation_epoch`](Self::revocation_epoch) is bumped, so it should
    /// only schedule work.
    pub fn on_revocation(
        &self,
        listener: impl Fn(&Arc<SignedTrustContext>, &[Name]) + Send + Sync + 'static,
    ) {
        self.revocation_listeners
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Arc::new(listener));
    }

    /// Run `listener` whenever this keyring adopts a context of a namespace
    /// it did not hold, or a newer version of one it holds (re-adopting the
    /// held version runs nothing) — e.g. so a host learns what a new version
    /// says (its relays, its link policy). It runs synchronously on the
    /// adopting thread after the context is in force and after the
    /// revocation listeners, so it should only schedule work.
    pub fn on_adoption(&self, listener: impl Fn(&Arc<SignedTrustContext>) + Send + Sync + 'static) {
        self.adoption_listeners
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Arc::new(listener));
    }

    fn notify_adopted(&self, ctx: &Arc<SignedTrustContext>) {
        let listeners = self
            .adoption_listeners
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        for listener in listeners {
            listener(ctx);
        }
    }

    /// How many adoptions so far newly revoked names. Read it before
    /// validating a packet; if it reads the same later, no revocation was
    /// adopted in between and the verdict still stands, and if it moved,
    /// check the packet against the revocations held now. One atomic load.
    /// It moves only on a revoking adoption, after the new context is in
    /// force and before the revocation listeners run.
    pub fn revocation_epoch(&self) -> u64 {
        self.revocation_epoch.load(Ordering::SeqCst)
    }

    fn notify_revoked(&self, ctx: &Arc<SignedTrustContext>, revoked: &[Name]) {
        if revoked.is_empty() {
            return;
        }
        // After the replacement (so a reader that sees the new epoch then
        // selects the new context) and before the listeners (so whatever the
        // purge they run misses, a later epoch check catches).
        self.revocation_epoch.fetch_add(1, Ordering::SeqCst);
        let listeners = self
            .revocation_listeners
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        for listener in listeners {
            listener(ctx, revoked);
        }
    }

    /// The version currently held for `namespace`, if any context is adopted.
    pub fn version_of(&self, namespace: &Name) -> Option<u64> {
        self.contexts.get(namespace).map(|c| c.version())
    }

    /// Drop a context by namespace; returns whether one was removed.
    pub fn forget(&self, namespace: &Name) -> bool {
        self.contexts.remove(namespace).is_some()
    }

    /// All adopted (non-ambient) contexts.
    pub fn contexts(&self) -> Vec<Arc<SignedTrustContext>> {
        self.contexts
            .iter()
            .map(|r| Arc::clone(r.value()))
            .collect()
    }

    /// Number of adopted (non-ambient) contexts.
    pub fn len(&self) -> usize {
        self.contexts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.contexts.is_empty()
    }

    /// Select the context governing `name`: the adopted context whose
    /// namespace is the longest prefix of `name`, else the ambient context.
    pub fn context_for(&self, name: &Name) -> Arc<SignedTrustContext> {
        let mut best: Option<Arc<SignedTrustContext>> = None;
        let mut best_len = 0usize;
        for r in self.contexts.iter() {
            let ns = r.key();
            // ns is a prefix of name, and longer (more specific) than any
            // match so far.
            if name.has_prefix(ns) && (best.is_none() || ns.len() > best_len) {
                best_len = ns.len();
                best = Some(Arc::clone(r.value()));
            }
        }
        best.unwrap_or_else(|| Arc::clone(&self.ambient))
    }

    /// Whether `name` is an anchor in *any* held context (ambient included).
    /// Anchor *termination* during a chain walk is still per-context; this is
    /// the membership query used by diagnostics.
    pub fn is_anchor(&self, name: &Name) -> bool {
        self.ambient.is_anchor(name) || self.contexts.iter().any(|r| r.value().is_anchor(name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    fn keyring() -> Keyring {
        let ambient = Arc::new(SignedTrustContext::accept_all(Name::root()));
        Keyring::with_ambient(ambient)
    }

    #[test]
    fn empty_keyring_falls_back_to_ambient() {
        let kr = keyring();
        let ctx = kr.context_for(&n("/home/bob/doc"));
        assert_eq!(ctx.namespace(), &Name::root());
    }

    #[test]
    fn longest_prefix_match_wins() {
        let kr = keyring();
        kr.adopt(Arc::new(SignedTrustContext::hierarchical(n("/home"))));
        kr.adopt(Arc::new(SignedTrustContext::hierarchical(n("/home/bob"))));
        kr.adopt(Arc::new(SignedTrustContext::hierarchical(n("/work/acme"))));

        assert_eq!(
            kr.context_for(&n("/home/bob/doc")).namespace(),
            &n("/home/bob")
        );
        assert_eq!(
            kr.context_for(&n("/home/alice/doc")).namespace(),
            &n("/home")
        );
        assert_eq!(
            kr.context_for(&n("/work/acme/sensor")).namespace(),
            &n("/work/acme")
        );
        // Unmatched namespace → ambient.
        assert_eq!(kr.context_for(&n("/transit/x")).namespace(), &Name::root());
    }

    #[test]
    fn forget_removes_context() {
        let kr = keyring();
        kr.adopt(Arc::new(SignedTrustContext::hierarchical(n("/home/bob"))));
        assert_eq!(kr.len(), 1);
        assert!(kr.forget(&n("/home/bob")));
        assert!(kr.is_empty());
        assert_eq!(
            kr.context_for(&n("/home/bob/doc")).namespace(),
            &Name::root()
        );
    }

    /// An update replaces the held context only when strictly newer.
    #[test]
    fn update_needs_a_strictly_newer_version() {
        let kr = keyring();
        let ctx = |v| Arc::new(SignedTrustContext::hierarchical(n("/home/bob")).with_version(v));
        assert_eq!(kr.adopt_update(ctx(2)), Err(None), "nothing held to update");
        kr.adopt(ctx(2));
        assert_eq!(kr.adopt_update(ctx(2)), Err(Some(2)), "equal is refused");
        assert_eq!(kr.adopt_update(ctx(1)), Err(Some(2)), "older is refused");
        assert_eq!(kr.adopt_update(ctx(3)), Ok(()));
        assert_eq!(kr.version_of(&n("/home/bob")), Some(3));
    }

    /// An update checked against one held version is never adopted over
    /// another one adopted meanwhile, even an older one.
    #[test]
    fn an_update_is_adopted_only_over_the_version_it_was_checked_against() {
        let kr = keyring();
        let ctx = |v| Arc::new(SignedTrustContext::hierarchical(n("/home/bob")).with_version(v));
        kr.adopt(ctx(2));
        let checked_against = kr.contexts().pop().unwrap();
        kr.adopt_update(ctx(3)).unwrap();
        assert_eq!(kr.adopt_update_from(&checked_against, ctx(5)), Err(Some(3)));
        assert_eq!(kr.version_of(&n("/home/bob")), Some(3));
        let held = kr.contexts().pop().unwrap();
        assert_eq!(kr.adopt_update_from(&held, ctx(5)), Ok(()));
    }

    /// A revoked key name covers that key and every certificate under it,
    /// and nothing beside it.
    #[test]
    fn revoking_a_key_covers_its_certificates() {
        let key = n("/home/bob/member/phone/KEY/k1");
        let ctx = SignedTrustContext::hierarchical(n("/home/bob")).with_revocation(key.clone());
        assert!(ctx.is_revoked(&key));
        assert!(ctx.is_revoked(&n("/home/bob/member/phone/KEY/k1/CA/v=7")));
        assert!(!ctx.is_revoked(&n("/home/bob/member/phone/KEY/k2")));
        assert!(!ctx.is_revoked(&n("/home/bob/member/phone")));
        assert!(!ctx.is_revoked(&n("/home/bob/member/phone/KEY/k10")));
    }

    /// Revocation listeners hear each name exactly once, when a version that
    /// first revokes it is adopted — by either adoption path — and never for
    /// an adoption that revokes nothing new. The revocation epoch moves with
    /// them, and has already moved when a listener runs.
    #[test]
    fn listeners_hear_only_newly_revoked_names() {
        let kr = Arc::new(keyring());
        let heard = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = Arc::clone(&heard);
        let weak = Arc::downgrade(&kr);
        kr.on_revocation(move |ctx, revoked| {
            let epoch = weak.upgrade().unwrap().revocation_epoch();
            sink.lock()
                .unwrap()
                .push((ctx.version(), revoked.to_vec(), epoch));
        });
        let (k1, k2) = (n("/home/bob/member/a/KEY/1"), n("/home/bob/member/b/KEY/2"));
        let base = || SignedTrustContext::hierarchical(n("/home/bob"));
        kr.adopt(Arc::new(base().with_version(1)));
        assert_eq!(kr.revocation_epoch(), 0, "nothing revoked yet");
        kr.adopt_update(Arc::new(base().with_version(2).with_revocation(k1.clone())))
            .unwrap();
        kr.adopt(Arc::new(
            base()
                .with_version(3)
                .with_revocation(k1.clone())
                .with_revocation(k2.clone()),
        ));
        kr.adopt_update(Arc::new(
            base()
                .with_version(4)
                .with_revocation(k1.clone())
                .with_revocation(k2.clone()),
        ))
        .unwrap();
        assert_eq!(*heard.lock().unwrap(), [(2, vec![k1], 1), (3, vec![k2], 2)]);
        assert_eq!(kr.revocation_epoch(), 2, "v4 revoked nothing new");
    }

    /// An equal version is a no-op when it is the same content, and a fork
    /// (refused, the held one stays) when it differs.
    #[test]
    fn an_equal_version_is_adopted_only_when_identical() {
        let kr = keyring();
        let base = || SignedTrustContext::hierarchical(n("/home/bob")).with_version(2);
        let held = Arc::new(base());
        assert!(kr.adopt(Arc::clone(&held)));
        assert!(kr.adopt(Arc::new(base())), "the same content again");
        assert!(Arc::ptr_eq(&kr.contexts().pop().unwrap(), &held), "nothing replaced");
        let fork = Arc::new(base().with_revocation(n("/home/bob/member/x/KEY/k")));
        assert!(!kr.adopt(fork), "a differing v2 is a fork");
        assert!(!kr.contexts().pop().unwrap().is_revoked(&n("/home/bob/member/x/KEY/k")));
        assert_eq!(kr.revocation_epoch(), 0);
    }
}
