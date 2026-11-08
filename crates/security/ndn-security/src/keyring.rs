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

use crate::self_certifying::{Genesis, SelfCertifyingNameError, self_certifying_digest};
use crate::trust_context::SignedTrustContext;

/// Called once a context is adopted that refuses what the version it
/// replaces accepted: the newly held context and the names it refuses anew
/// ([`newly_refused`]). See [`Keyring::on_revocation`].
type RevocationListener = Arc<dyn Fn(&Arc<SignedTrustContext>, &[Name]) + Send + Sync>;

/// Called once a context (a new namespace, or a newer version) is adopted.
/// See [`Keyring::on_adoption`].
type AdoptionListener = Arc<dyn Fn(&Arc<SignedTrustContext>) + Send + Sync>;

/// Why [`Keyring::adopt`] did not take a context: its namespace is held,
/// and `adopt` changes a held namespace never. A newer version of a held
/// namespace is taken only once checked under the held version's anchors
/// (the continuity rule — `ndn_cert::open_context_update`, or a walk
/// through the versions in between for a recovery) and then adopted with
/// [`Keyring::adopt_update_from`] over the held context the refusal carries.
#[derive(Debug, Clone, thiserror::Error)]
pub enum AdoptRefusal {
    /// It is older than the held version: a rollback.
    #[error(
        "{namespace} v{offered} is older than the held v{held}; only a newer version signed by \
         a held anchor replaces it",
        namespace = .held_ctx.namespace(),
        held = .held_ctx.version()
    )]
    Older {
        held_ctx: Arc<SignedTrustContext>,
        offered: u64,
    },
    /// It carries the held version number with other content: a fork.
    #[error(
        "{namespace} v{version} differs from the held v{version} (a fork); only a newer version \
         signed by a held anchor replaces it",
        namespace = .held_ctx.namespace(),
        version = .held_ctx.version()
    )]
    Fork { held_ctx: Arc<SignedTrustContext> },
    /// It is newer than the held version: taken only once checked under
    /// the held version's anchors, then adopted with
    /// [`Keyring::adopt_update_from`] over `held_ctx`.
    #[error(
        "{namespace} is already trusted (v{held} held): v{offered} replaces it only once it is \
         checked under the held version's anchors (a refresh of {namespace} does that, a \
         recovery included)",
        namespace = .held_ctx.namespace(),
        held = .held_ctx.version()
    )]
    Held {
        held_ctx: Arc<SignedTrustContext>,
        offered: u64,
    },
    /// A self-certifying namespace not held (`/user/<0xA1: …>`): taken only
    /// from its checked genesis, through
    /// [`Keyring::adopt_genesis`].
    #[error(
        "{namespace} is self-certifying: it is trusted only from its version 1 (genesis), \
         signed by the Ed25519 key the name hashes, and then by the continuity rule; adopt it \
         by name, which fetches and checks its genesis"
    )]
    GenesisRequired { namespace: Name },
    /// The namespace carries a self-certifying component where none may be.
    #[error(transparent)]
    Name(#[from] SelfCertifyingNameError),
    /// [`Keyring::adopt_genesis`] was given a context that is not of the
    /// genesis's namespace, or another version 1.
    #[error(
        "{offered} v{version} does not follow from the genesis of {genesis}: only a version of \
         {genesis} checked from its genesis is adopted with it"
    )]
    NotFromGenesis {
        genesis: Name,
        offered: Name,
        version: u64,
    },
}

/// A node's set of adopted trust contexts plus an ambient fallback context.
///
/// The `ambient` context (namespace `/`) backs the flat-anchor / single-schema
/// API on [`Validator`](crate::Validator) for backward compatibility; named
/// contexts adopted via [`adopt`](Self::adopt) take precedence by
/// longest-prefix match. A name in a person's self-certifying namespace
/// (`/user/<0xA1: …>`) is never judged by the ambient context: only by that
/// namespace's own context, else by a context that accepts nothing
/// ([`context_for`](Self::context_for)).
pub struct Keyring {
    /// The held contexts and what hangs off them, shared live by every
    /// view of this keyring ([`with_ambient_view`](Self::with_ambient_view)).
    held: Arc<Held>,
    ambient: Arc<SignedTrustContext>,
}

/// What the views of one keyring share: the held contexts, the listeners,
/// the revocation epoch, and the context that judges a person's names
/// whose namespace is not held.
struct Held {
    contexts: DashMap<Name, Arc<SignedTrustContext>>,
    revocation_listeners: RwLock<Vec<RevocationListener>>,
    adoption_listeners: RwLock<Vec<AdoptionListener>>,
    /// Bumped each time an adopted version refuses what the one it replaced
    /// accepted (newly revoked names, a cut that accepts less, a role newly
    /// needing a cut); see
    /// [`revocation_epoch`](Keyring::revocation_epoch).
    revocation_epoch: AtomicU64,
    /// No anchors, an empty schema: judges every name in a person's
    /// namespace not held, and accepts none of them.
    unheld: Arc<SignedTrustContext>,
}

impl std::fmt::Debug for Keyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keyring")
            .field("contexts", &self.held.contexts)
            .field("ambient", &self.ambient)
            .finish_non_exhaustive()
    }
}

/// What `new` refuses that `old` (the version it replaces, if any) did
/// not, as the names it concerns:
///
/// - each name `new` revokes that `old` did not;
/// - the key of each cut of `old` whose key `new` still revokes and whose
///   cut in `new` does not accept everything the old one did
///   ([`RevocationCut::covers`](crate::RevocationCut::covers): the cut
///   removed, a range or run shrunk, an exact entry dropped, its key digest
///   or manifest changed, added or removed);
/// - `/<ns>/<role>` for each DataRequiresCut role `new` lists that `old`
///   did not (that role's lapsed keys now need a cut).
///
/// Producers only ever add to a cut, but adopters do not rely on that: a
/// version that accepts less is revoking whatever its producer meant.
fn newly_refused(old: Option<&SignedTrustContext>, new: &SignedTrustContext) -> Vec<Name> {
    let mut names: Vec<Name> = new
        .revocations()
        .iter()
        .filter(|r| old.is_none_or(|old| !old.revocations().contains(r)))
        .cloned()
        .collect();
    if let Some(old) = old {
        for cut in old.revocation_cuts() {
            let key = cut.key();
            if new.is_revoked(key)
                && !new.revocation_cut(key).is_some_and(|now| now.covers(cut))
                && !names.contains(key)
            {
                names.push(key.clone());
            }
        }
    }
    for role in new.data_requires_cut() {
        if old.is_none_or(|old| !old.data_requires_cut().contains(role)) {
            names.push(new.namespace().clone().append(role));
        }
    }
    names
}

impl Default for Keyring {
    fn default() -> Self {
        Self::new()
    }
}

impl Keyring {
    pub(crate) fn with_ambient(ambient: Arc<SignedTrustContext>) -> Self {
        Self {
            held: Arc::new(Held {
                contexts: DashMap::new(),
                revocation_listeners: RwLock::new(Vec::new()),
                adoption_listeners: RwLock::new(Vec::new()),
                revocation_epoch: AtomicU64::new(0),
                unheld: Arc::new(SignedTrustContext::deny_all()),
            }),
            ambient,
        }
    }

    /// A view of this keyring with another ambient context: it shares this
    /// keyring's held contexts **live** — an adoption, update or forget
    /// through either is seen by both, and they share one revocation epoch
    /// and one set of listeners — but judges a name no held context covers
    /// with `ambient` instead (e.g. a phone's pinned peers, kept apart from
    /// the node's held namespaces). A person's names whose namespace is
    /// not held are refused by the view as by every keyring
    /// ([`context_for`](Self::context_for)), whatever `ambient` holds.
    pub fn with_ambient_view(&self, ambient: Arc<SignedTrustContext>) -> Keyring {
        Keyring {
            held: Arc::clone(&self.held),
            ambient,
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

    /// A keyring holding `ctx` alone, as a party's own credentials claim
    /// it: to check that party's proof against the context it carries
    /// before anything of it is trusted, never as a node's keyring. A
    /// self-certifying namespace is held here without its genesis — whether
    /// it is that namespace's is decided where it is adopted
    /// ([`adopt_genesis`](Self::adopt_genesis)). A namespace with a
    /// self-certifying component anywhere else is refused.
    pub fn of_claim(ctx: Arc<SignedTrustContext>) -> Result<Self, SelfCertifyingNameError> {
        self_certifying_digest(ctx.namespace())?;
        let keyring = Self::new();
        keyring.held.contexts.insert(ctx.namespace().clone(), ctx);
        Ok(keyring)
    }

    /// The ambient (root-namespace) context — the validation target for names
    /// not covered by any adopted context, except a person's names
    /// ([`context_for`](Self::context_for)).
    pub fn ambient(&self) -> &Arc<SignedTrustContext> {
        &self.ambient
    }

    /// Adopt a context of a namespace not held, keyed by its namespace.
    ///
    /// A held namespace is never changed here, whoever signed the context:
    /// re-adopting what is held (the same version, encoding to the same
    /// content) is a no-op `Ok`; anything else is refused with the held
    /// context ([`AdoptRefusal`]) — older (a rollback), the held version
    /// number with other content (a fork), or newer, which replaces the
    /// held one only through [`adopt_update_from`](Self::adopt_update_from)
    /// once checked under the held version's anchors. Atomic against
    /// concurrent adoptions of the same namespace.
    ///
    /// A self-certifying namespace (`/user/<0xA1: …>`,
    /// [`crate::self_certifying`]) not held is refused
    /// ([`AdoptRefusal::GenesisRequired`]): it is taken only from its checked
    /// genesis ([`adopt_genesis`](Self::adopt_genesis)). A namespace with a
    /// self-certifying component anywhere else is refused
    /// ([`AdoptRefusal::Name`]).
    pub fn adopt(&self, ctx: Arc<SignedTrustContext>) -> Result<(), AdoptRefusal> {
        let self_certifying = self_certifying_digest(ctx.namespace())?.is_some();
        self.adopt_entry(ctx, self_certifying)
    }

    /// Adopt the self-certifying namespace of `genesis` at `newest`: the
    /// genesis itself, or a later version the caller checked from it by
    /// the continuity rule (each version signed by an anchor of the one
    /// before it: `ndn_cert::open_context_update`, or a catch-up walk
    /// through the versions in between). Version 1 is judged against the
    /// name ([`Genesis`]); the versions after it, by continuity alone, so a
    /// recovery or a root moved to another key type keeps the name.
    ///
    /// `newest` must be of the genesis's namespace, and at version 1 it must
    /// be the genesis itself ([`AdoptRefusal::NotFromGenesis`]). A held
    /// namespace is changed here never, as by [`adopt`](Self::adopt).
    pub fn adopt_genesis(
        &self,
        genesis: &Genesis,
        newest: Arc<SignedTrustContext>,
    ) -> Result<(), AdoptRefusal> {
        if newest.namespace() != genesis.namespace()
            || (newest.version() == 1
                && newest.encode_content() != genesis.context().encode_content())
        {
            return Err(AdoptRefusal::NotFromGenesis {
                genesis: genesis.namespace().clone(),
                offered: newest.namespace().clone(),
                version: newest.version(),
            });
        }
        self.adopt_entry(newest, false)
    }

    /// [`adopt`](Self::adopt) once the namespace is judged: a namespace not
    /// held is refused when `needs_genesis`.
    fn adopt_entry(
        &self,
        ctx: Arc<SignedTrustContext>,
        needs_genesis: bool,
    ) -> Result<(), AdoptRefusal> {
        let ns = ctx.namespace().clone();
        let revoked = match self.held.contexts.entry(ns) {
            dashmap::mapref::entry::Entry::Occupied(held) => {
                let held = held.get();
                if Arc::ptr_eq(held, &ctx)
                    || (ctx.version() == held.version()
                        && held.encode_content() == ctx.encode_content())
                {
                    return Ok(());
                }
                let held_ctx = Arc::clone(held);
                let offered = ctx.version();
                return Err(match offered.cmp(&held_ctx.version()) {
                    std::cmp::Ordering::Less => AdoptRefusal::Older { held_ctx, offered },
                    std::cmp::Ordering::Equal => AdoptRefusal::Fork { held_ctx },
                    std::cmp::Ordering::Greater => AdoptRefusal::Held { held_ctx, offered },
                });
            }
            dashmap::mapref::entry::Entry::Vacant(_) if needs_genesis => {
                return Err(AdoptRefusal::GenesisRequired {
                    namespace: ctx.namespace().clone(),
                });
            }
            dashmap::mapref::entry::Entry::Vacant(slot) => {
                let revoked = newly_refused(None, &ctx);
                slot.insert(Arc::clone(&ctx));
                revoked
            }
        };
        self.notify_revoked(&ctx, &revoked);
        self.notify_adopted(&ctx);
        Ok(())
    }

    /// The context held for exactly `namespace`, if any.
    pub fn held(&self, namespace: &Name) -> Option<Arc<SignedTrustContext>> {
        self.held
            .contexts
            .get(namespace)
            .map(|c| Arc::clone(c.value()))
    }

    /// Replace the held context of `ctx`'s namespace with `ctx` only if
    /// `ctx` is **strictly newer** — the rule for an update, where an equal
    /// version must not replace the held one either. The caller has checked
    /// `ctx` under the held version's anchors (the continuity rule);
    /// [`adopt_update_from`](Self::adopt_update_from) also makes sure the
    /// held version is still the one checked against. Atomic against
    /// concurrent adoptions of the same namespace. `Err(Some(held))`: the
    /// held version is not older; `Err(None)`: nothing is held to update.
    pub fn adopt_update(&self, ctx: Arc<SignedTrustContext>) -> Result<(), Option<u64>> {
        let revoked = match self.held.contexts.get_mut(ctx.namespace()) {
            None => return Err(None),
            Some(held) if held.version() >= ctx.version() => return Err(Some(held.version())),
            Some(mut held) => {
                let revoked = newly_refused(Some(held.as_ref()), &ctx);
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
    /// checked against as an update, under its anchors (the continuity
    /// rule) — and `ctx` is strictly newer: the one way a held namespace
    /// moves on. Lets a caller check an update without holding any lock
    /// (fetching it may take many round trips) and adopt it only if nothing
    /// changed the namespace meanwhile. Atomic against concurrent
    /// adoptions. `Err(Some(held))`: the held context is another one (or
    /// not older); `Err(None)`: nothing is held to update.
    pub fn adopt_update_from(
        &self,
        from: &Arc<SignedTrustContext>,
        ctx: Arc<SignedTrustContext>,
    ) -> Result<(), Option<u64>> {
        let revoked = match self.held.contexts.get_mut(ctx.namespace()) {
            None => return Err(None),
            Some(held) if !Arc::ptr_eq(&held, from) || held.version() >= ctx.version() => {
                return Err(Some(held.version()));
            }
            Some(mut held) => {
                let revoked = newly_refused(Some(held.as_ref()), &ctx);
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
    /// [`adopt_update_from`](Self::adopt_update_from)) that refuses what
    /// the version it replaces accepted — it revokes names that version did
    /// not, a cut of a key it still revokes accepts less than before, or it
    /// lists a DataRequiresCut role anew — e.g. so a forwarder drops cached
    /// Data it no longer accepts. The listener gets those names: revoked
    /// names, the keys whose cut accepts less, `/<ns>/<role>` for a role.
    /// It runs synchronously on the adopting thread after the new context
    /// is in force and the [`revocation_epoch`](Self::revocation_epoch) is
    /// bumped, so it should only schedule work.
    pub fn on_revocation(
        &self,
        listener: impl Fn(&Arc<SignedTrustContext>, &[Name]) + Send + Sync + 'static,
    ) {
        self.held
            .revocation_listeners
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
        self.held
            .adoption_listeners
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Arc::new(listener));
    }

    fn notify_adopted(&self, ctx: &Arc<SignedTrustContext>) {
        let listeners = self
            .held
            .adoption_listeners
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        for listener in listeners {
            listener(ctx);
        }
    }

    /// How many revoking adoptions so far ([`on_revocation`](Self::on_revocation)
    /// says which are). Read it before validating a packet; if it reads the
    /// same later, no revoking version was adopted in between and the
    /// verdict still stands, and if it moved, check the packet against the
    /// context held now. One atomic load. It moves only on a revoking
    /// adoption, after the new context is in force and before the
    /// revocation listeners run.
    pub fn revocation_epoch(&self) -> u64 {
        self.held.revocation_epoch.load(Ordering::SeqCst)
    }

    fn notify_revoked(&self, ctx: &Arc<SignedTrustContext>, revoked: &[Name]) {
        if revoked.is_empty() {
            return;
        }
        // After the replacement (so a reader that sees the new epoch then
        // selects the new context) and before the listeners (so whatever the
        // purge they run misses, a later epoch check catches).
        self.held.revocation_epoch.fetch_add(1, Ordering::SeqCst);
        let listeners = self
            .held
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
        self.held.contexts.get(namespace).map(|c| c.version())
    }

    /// Drop a context by namespace; returns whether one was removed.
    pub fn forget(&self, namespace: &Name) -> bool {
        self.held.contexts.remove(namespace).is_some()
    }

    /// All adopted (non-ambient) contexts.
    pub fn contexts(&self) -> Vec<Arc<SignedTrustContext>> {
        self.held
            .contexts
            .iter()
            .map(|r| Arc::clone(r.value()))
            .collect()
    }

    /// Number of adopted (non-ambient) contexts.
    pub fn len(&self) -> usize {
        self.held.contexts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.held.contexts.is_empty()
    }

    /// Select the context governing `name`: the adopted context whose
    /// namespace is the longest prefix of `name`, else the ambient context.
    ///
    /// A name in a person's self-certifying namespace (`/user/<0xA1>/…`,
    /// [`in_personal_namespace`](crate::self_certifying::in_personal_namespace))
    /// is governed only by that namespace's own context: a held `/user` or
    /// `/` context never vouches for it, and neither does the ambient
    /// context, whatever anchors it holds (a forwarder's holds every PIB
    /// anchor, its own root included). Without its own context such a name
    /// is judged by a fixed context with no anchors and an empty schema,
    /// which accepts no signer, anchored or not (a DigestSha256 packet,
    /// which names none, stays integrity-only as under every name)
    /// ([`unheld_personal_namespace`](Self::unheld_personal_namespace) says
    /// which namespace to adopt; trust-context.md §4.5.6). That context's
    /// namespace is `/`, as the ambient's: a caller asking whether a held
    /// context covers a name uses [`held_for`](Self::held_for). It is
    /// shared, so never add anchors to or set the schema of a context
    /// this returns; adopt one instead.
    pub fn context_for(&self, name: &Name) -> Arc<SignedTrustContext> {
        match self.held_for(name) {
            Some(held) => held,
            None if crate::self_certifying::in_personal_namespace(name) => {
                Arc::clone(&self.held.unheld)
            }
            None => Arc::clone(&self.ambient),
        }
    }

    /// The held (adopted) context governing `name`, if any: the one whose
    /// namespace is the longest prefix of `name` — for a person's name,
    /// only their own namespace's ([`context_for`](Self::context_for)).
    /// `None` when the ambient context, or nothing, judges `name`.
    pub fn held_for(&self, name: &Name) -> Option<Arc<SignedTrustContext>> {
        let floor = if crate::self_certifying::in_personal_namespace(name) {
            2
        } else {
            0
        };
        let mut best: Option<Arc<SignedTrustContext>> = None;
        let mut best_len = 0usize;
        for r in self.held.contexts.iter() {
            let ns = r.key();
            // ns is a prefix of name, and longer (more specific) than any
            // match so far.
            if ns.len() >= floor && name.has_prefix(ns) && (best.is_none() || ns.len() > best_len) {
                best_len = ns.len();
                best = Some(Arc::clone(r.value()));
            }
        }
        best
    }

    /// The person's namespace `/user/<0xA1: …>` that `name` lies in, when
    /// this keyring does not hold it: every packet named `name` is refused
    /// until it is adopted by name ([`context_for`](Self::context_for)).
    /// `None` for a name in no person's namespace, or in one held.
    pub fn unheld_personal_namespace(&self, name: &Name) -> Option<Name> {
        let namespace = crate::self_certifying::personal_namespace_of(name)?;
        self.held_for(name).is_none().then_some(namespace)
    }

    /// Whether `name` is an anchor in *any* held context (ambient included).
    /// A name in a person's namespace is an anchor only of that
    /// namespace's own context ([`context_for`](Self::context_for)), never
    /// of the ambient or of another held context. Anchor *termination*
    /// during a chain walk is still per-context; this is the membership
    /// query used by diagnostics.
    pub fn is_anchor(&self, name: &Name) -> bool {
        if crate::self_certifying::in_personal_namespace(name) {
            return self.context_for(name).is_anchor(name);
        }
        self.ambient.is_anchor(name) || self.held.contexts.iter().any(|r| r.value().is_anchor(name))
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
        for ns in ["/home", "/home/bob", "/work/acme"] {
            kr.adopt(Arc::new(SignedTrustContext::hierarchical(n(ns))))
                .unwrap();
        }

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
    fn a_held_user_context_never_governs_a_persons_names() {
        let kr = keyring();
        kr.adopt(Arc::new(SignedTrustContext::hierarchical(n("/user"))))
            .unwrap();
        let person = crate::self_certifying::self_certifying_name(&[7; 32]);
        let doc = person.clone().append("doc");
        assert_eq!(kr.context_for(&doc).namespace(), &Name::root());
        assert_eq!(kr.context_for(&person).namespace(), &Name::root());
        // Ordinary names under /user are still its own.
        assert_eq!(
            kr.context_for(&n("/user/alice/doc")).namespace(),
            &n("/user")
        );
    }

    /// A person's name whose namespace is not held is judged by a context
    /// that accepts nothing — never by the ambient one, whatever it holds
    /// and accepts (here: everything).
    #[test]
    fn a_persons_name_not_held_is_never_judged_by_the_ambient_context() {
        let kr = keyring();
        let held = crate::self_certifying::self_certifying_name(&[1; 32]);
        let person = crate::self_certifying::self_certifying_name(&[7; 32]);
        let doc = person.clone().append("doc");
        let key = held.clone().append("KEY").append("k");
        assert!(
            kr.ambient().authorizes(&doc, &key),
            "the ambient accepts all"
        );
        for name in [&person, &doc] {
            let ctx = kr.context_for(name);
            assert!(
                !Arc::ptr_eq(&ctx, kr.ambient()),
                "{name} is judged by the ambient context"
            );
            assert!(
                ctx.anchors().is_empty() && !ctx.authorizes(name, &key),
                "{name} is judged by a context that accepts something"
            );
        }
    }

    #[test]
    fn forget_removes_context() {
        let kr = keyring();
        kr.adopt(Arc::new(SignedTrustContext::hierarchical(n("/home/bob"))))
            .unwrap();
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
        kr.adopt(ctx(2)).unwrap();
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
        kr.adopt(ctx(2)).unwrap();
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
    /// first revokes it is adopted — by any update path — and never for an
    /// adoption that revokes nothing new. The revocation epoch moves with
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
        kr.adopt(Arc::new(base().with_version(1))).unwrap();
        assert_eq!(kr.revocation_epoch(), 0, "nothing revoked yet");
        kr.adopt_update(Arc::new(base().with_version(2).with_revocation(k1.clone())))
            .unwrap();
        let held = kr.held(&n("/home/bob")).unwrap();
        kr.adopt_update_from(
            &held,
            Arc::new(
                base()
                    .with_version(3)
                    .with_revocation(k1.clone())
                    .with_revocation(k2.clone()),
            ),
        )
        .unwrap();
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
        kr.adopt(Arc::clone(&held)).unwrap();
        kr.adopt(Arc::new(base())).expect("the same content again");
        assert!(
            Arc::ptr_eq(&kr.contexts().pop().unwrap(), &held),
            "nothing replaced"
        );
        let fork = Arc::new(base().with_revocation(n("/home/bob/member/x/KEY/k")));
        assert!(
            matches!(kr.adopt(fork), Err(AdoptRefusal::Fork { .. })),
            "a differing v2 is a fork"
        );
        assert!(
            !kr.contexts()
                .pop()
                .unwrap()
                .is_revoked(&n("/home/bob/member/x/KEY/k"))
        );
        assert_eq!(kr.revocation_epoch(), 0);
    }

    /// `adopt` never replaces a held namespace: another party's newer
    /// version of it (Mallory's `/carol` v1000 under her own anchor) is
    /// refused with the held context and leaves it in force; an older one
    /// is a rollback; re-adopting the held one is a no-op; a vacant
    /// namespace adopts. Only the update path — a version checked under the
    /// held anchors (Carol's v4, or a recovery's version signed by a
    /// recovery anchor of the held one) — moves it on.
    #[test]
    fn adopt_never_replaces_a_held_namespace() {
        let kr = Arc::new(keyring());
        let adopted = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = Arc::clone(&adopted);
        kr.on_adoption(move |ctx| sink.lock().unwrap().push(ctx.version()));
        let carol = Arc::new(SignedTrustContext::hierarchical(n("/carol")).with_version(3));
        kr.adopt(Arc::clone(&carol))
            .expect("a vacant namespace adopts");
        let mallory = Arc::new(
            SignedTrustContext::hierarchical(n("/carol"))
                .with_version(1000)
                .with_revocation(n("/carol/member/phone/KEY/k")),
        );
        match kr.adopt(mallory) {
            Err(AdoptRefusal::Held {
                ref held_ctx,
                offered: 1000,
            }) => assert!(Arc::ptr_eq(held_ctx, &carol)),
            other => panic!("a newer version of a held namespace was not refused: {other:?}"),
        }
        assert!(
            Arc::ptr_eq(&kr.held(&n("/carol")).unwrap(), &carol),
            "a newer version of a held namespace replaced it outside the update path"
        );
        let older = Arc::new(SignedTrustContext::hierarchical(n("/carol")).with_version(2));
        assert!(matches!(
            kr.adopt(older),
            Err(AdoptRefusal::Older { offered: 2, .. })
        ));
        kr.adopt(Arc::new(
            SignedTrustContext::hierarchical(n("/carol")).with_version(3),
        ))
        .expect("re-adopting the held version is a no-op");
        assert!(Arc::ptr_eq(&kr.held(&n("/carol")).unwrap(), &carol));
        assert_eq!(
            *adopted.lock().unwrap(),
            [3],
            "refusals and no-ops adopt nothing"
        );

        let v4 = Arc::new(SignedTrustContext::hierarchical(n("/carol")).with_version(4));
        kr.adopt_update_from(&carol, Arc::clone(&v4)).unwrap();
        assert!(Arc::ptr_eq(&kr.held(&n("/carol")).unwrap(), &v4));
    }

    /// A version that accepts less of a revoked key than the version it
    /// replaces — its cut removed, a run shrunk, an exact entry dropped —
    /// is revoking: the epoch moves and the listeners hear that key. One
    /// that only adds to a cut (re-admission) is not.
    #[test]
    fn a_version_whose_cut_accepts_less_is_revoking() {
        use crate::RevocationCut;
        let kr = Arc::new(keyring());
        let heard = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = Arc::clone(&heard);
        kr.on_revocation(move |ctx, revoked| {
            sink.lock().unwrap().push((ctx.version(), revoked.to_vec()));
        });
        let key = n("/home/bob/member/phone/KEY/k1");
        let log = n("/home/bob/member/phone/log/notes");
        let exact = log
            .clone()
            .append_sequence_num(9)
            .append_implicit_digest([7; 32]);
        let cut = |last: u64, readmit: bool| {
            let mut cut = RevocationCut::new(key.clone());
            cut.add_run(&log, 1, last);
            if readmit {
                cut.readmit(exact.clone()).unwrap();
            }
            cut
        };
        let version = |v: u64, cut: Option<RevocationCut>| {
            let ctx = SignedTrustContext::hierarchical(n("/home/bob"))
                .with_version(v)
                .with_revocation(key.clone());
            Arc::new(match cut {
                Some(cut) => ctx.with_revocation_cut(cut),
                None => ctx,
            })
        };
        kr.adopt(version(1, Some(cut(5, false)))).unwrap();
        let epoch = kr.revocation_epoch();

        // Re-admission only adds: not revoking.
        kr.adopt_update(version(2, Some(cut(5, true)))).unwrap();
        assert_eq!(kr.revocation_epoch(), epoch, "an added exact entry");
        // Each of these accepts less than the version before it.
        kr.adopt_update(version(3, Some(cut(5, false)))).unwrap();
        assert_eq!(kr.revocation_epoch(), epoch + 1, "an exact entry dropped");
        kr.adopt_update(version(4, Some(cut(3, false)))).unwrap();
        assert_eq!(kr.revocation_epoch(), epoch + 2, "a run shrunk");
        kr.adopt_update(version(5, None)).unwrap();
        assert_eq!(kr.revocation_epoch(), epoch + 3, "the cut removed");
        // A role newly listed in DataRequiresCut: its lapsed keys' Data is
        // refused from now on.
        let with_role = SignedTrustContext::hierarchical(n("/home/bob"))
            .with_version(6)
            .with_revocation(key.clone())
            .with_data_requires_cut("guest");
        kr.adopt_update(Arc::new(with_role)).unwrap();
        assert_eq!(kr.revocation_epoch(), epoch + 4, "a role newly needs a cut");
        let heard = heard.lock().unwrap();
        let versions: Vec<u64> = heard.iter().map(|(v, _)| *v).collect();
        assert_eq!(versions, [1, 3, 4, 5, 6]);
        assert!(
            heard[1..4]
                .iter()
                .all(|(_, names)| names == std::slice::from_ref(&key))
        );
        assert_eq!(heard[4].1, [n("/home/bob/guest")]);
    }
}
