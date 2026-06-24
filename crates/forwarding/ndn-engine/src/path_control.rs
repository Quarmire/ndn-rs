//! Forwarder-side handling of [`PathControl`] messages (G3) — the one genuinely new
//! forwarder-core piece: a control Interest that mutates per-hop FIB/session state
//! *in transit* and walks onward, rather than being satisfied by Data.
//!
//! Each forwarder a PathControl traverses runs [`PathControlHandler::decide`]:
//! verify the signature (the FIB rewrite is authorized only by the prefix's trust —
//! else this is a prefix-hijack vector), apply the loop/staleness guard, mutate state
//! for the op, and report which faces to **propagate** the message onward to (so the
//! path-walk continues). The actual send stays in the dispatcher; this decides.
//!
//! - [`PathOp::Redirect`] (MAP-Me IU): repoint the prefix's next-hop to the face the
//!   message arrived on (toward the producer's new location), then propagate to the
//!   *old* next-hops (down the trail toward the previous attachment).
//! - [`PathOp::Teardown`] / [`PathOp::Refresh`]: notify registered
//!   [`PathControlObserver`]s (e.g. `ndn-pipes`) and propagate along the current route.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ndn_packet::{Interest, Name};
use ndn_pathcontrol::{PathControl, PathOp, SeqStore};
use ndn_security::{InterestValidationOutcome, Validator};
use ndn_transport::FaceId;

use crate::fib::Fib;

/// Number of sharded per-target locks (bounds memory vs an unbounded per-target map; a
/// hash collision merely over-serializes two targets, which is harmless).
const LOCK_SHARDS: usize = 64;

/// Pluggable **authorization** for a PathControl message — the seam that lets one
/// primitive carry two trust roots. MAP-Me's `Redirect` is authorized by the prefix's
/// signature ([`ValidatorAuthorizer`]); a pipe's `Teardown` is authorized by pipe
/// *membership* (the pipe key, verified by `ndn-pipes` — a different root entirely).
/// A node running both supplies an authorizer that routes by [`PathControl::op`].
/// Returning `false` drops the message (fail closed).
#[async_trait]
pub trait PathAuthorizer: Send + Sync {
    async fn authorize(&self, pc: &PathControl, interest: &Interest) -> bool;
}

/// The MAP-Me authorizer: a PathControl is authorized iff its Interest signature
/// verifies against the forwarder's prefix trust (only a key the prefix trusts may
/// rewrite its routes). The producer-mobility default.
pub struct ValidatorAuthorizer(pub Arc<Validator>);

#[async_trait]
impl PathAuthorizer for ValidatorAuthorizer {
    async fn authorize(&self, _pc: &PathControl, interest: &Interest) -> bool {
        matches!(
            self.0.validate_interest(interest).await,
            InterestValidationOutcome::Valid
        )
    }
}

/// Accepts **every** PathControl — i.e. permits unauthenticated in-transit FIB rewrites.
/// **Test / fully-trusted single-administrator deployments only.** There is deliberately
/// no `Option<authorizer>` on the handler; an open relay must be spelled out via this type
/// (and [`PathControlHandler::new_unauthenticated`]) so it can't be the default-looking path.
pub struct AllowAllAuthorizer;

#[async_trait]
impl PathAuthorizer for AllowAllAuthorizer {
    async fn authorize(&self, _pc: &PathControl, _interest: &Interest) -> bool {
        true
    }
}

/// Routes authorization **by op** so the two trust roots can't be crossed: a node that
/// runs both mechanisms wraps its `Redirect` root (prefix `Validator`) and its lifecycle
/// root (pipe membership) here, and `Redirect` can never be authorized by the membership
/// root (or vice-versa). Use this instead of installing a single op-agnostic authorizer.
pub struct OpRoutedAuthorizer {
    /// Authorizes `Redirect` (MAP-Me FIB rewrite) — typically a [`ValidatorAuthorizer`].
    pub redirect: Arc<dyn PathAuthorizer>,
    /// Authorizes `Teardown` / `Refresh` (session lifecycle) — typically pipe membership.
    pub lifecycle: Arc<dyn PathAuthorizer>,
}

#[async_trait]
impl PathAuthorizer for OpRoutedAuthorizer {
    async fn authorize(&self, pc: &PathControl, interest: &Interest) -> bool {
        match pc.op {
            PathOp::Redirect => self.redirect.authorize(pc, interest).await,
            PathOp::Teardown | PathOp::Refresh => self.lifecycle.authorize(pc, interest).await,
        }
    }
}

/// A consumer of pipe/session-lifecycle PathControl ops. `ndn-pipes` implements this
/// so a `Teardown`/`Refresh` walking the path closes or extends the live pipe, without
/// the forwarder knowing what a pipe is. `params` are the message's
/// ApplicationParameters (e.g. the pipe id + key), carrying the model-specific detail
/// the observer needs; `pc.target` is the walked prefix (e.g. the namespace).
pub trait PathControlObserver: Send + Sync {
    /// A `Teardown` reached this hop.
    fn on_teardown(&self, _pc: &PathControl, _params: &[u8]) {}
    /// A `Refresh` (keepalive) reached this hop.
    fn on_refresh(&self, _pc: &PathControl, _params: &[u8]) {}
}

/// Per-hop PathControl logic. Opt-in (installed via the engine builder); holds the FIB
/// to mutate, the per-target sequence guard, an optional validator (authorizes the
/// mutation), and any lifecycle observers.
pub struct PathControlHandler {
    fib: Arc<Fib>,
    seq: SeqStore,
    /// Authorizes the in-transit state mutation — **non-optional**: there is no fail-open
    /// path. An open relay must be built explicitly via [`new_unauthenticated`](Self::new_unauthenticated).
    authorizer: Arc<dyn PathAuthorizer>,
    observers: Vec<Arc<dyn PathControlObserver>>,
    /// Sharded per-target locks: the seq-admit and FIB write for one target run as a
    /// single critical section (closes the TOCTOU where two admitted Redirects race their
    /// FIB writes into the wrong order).
    locks: Vec<Mutex<()>>,
}

impl PathControlHandler {
    /// Build with an explicit authorizer (required). Pair with [`OpRoutedAuthorizer`] when
    /// a node runs both MAP-Me and pipe lifecycle so each op uses its own trust root.
    pub fn new(
        fib: Arc<Fib>,
        authorizer: Arc<dyn PathAuthorizer>,
        observers: Vec<Arc<dyn PathControlObserver>>,
    ) -> Self {
        // Volatile sequence guard: correct within a process, but its replay floor resets on
        // restart. Use [`new_with_seq_store`](Self::new_with_seq_store) with a persisted
        // `SeqStore` where cross-reboot replay protection is required (G3.1).
        Self::new_with_seq_store(fib, authorizer, observers, SeqStore::new())
    }

    /// Like [`new`](Self::new) but with a caller-supplied [`SeqStore`] — pass
    /// `SeqStore::with_persistence(..)` so the loop/staleness guard's floor survives a
    /// restart (closing the post-reboot replay window for captured signed messages without
    /// depending on a clock).
    pub fn new_with_seq_store(
        fib: Arc<Fib>,
        authorizer: Arc<dyn PathAuthorizer>,
        observers: Vec<Arc<dyn PathControlObserver>>,
        seq: SeqStore,
    ) -> Self {
        Self {
            fib,
            seq,
            authorizer,
            observers,
            locks: (0..LOCK_SHARDS).map(|_| Mutex::new(())).collect(),
        }
    }

    /// Build a handler that accepts **unauthenticated** PathControl (via
    /// [`AllowAllAuthorizer`]). **Test / fully-trusted deployments only** — it permits any
    /// peer to rewrite this node's FIB.
    pub fn new_unauthenticated(
        fib: Arc<Fib>,
        observers: Vec<Arc<dyn PathControlObserver>>,
    ) -> Self {
        Self::new(fib, Arc::new(AllowAllAuthorizer), observers)
    }

    /// The sharded lock for `target` (hash → shard; collisions only over-serialize).
    fn lock_for(&self, target: &Name) -> &Mutex<()> {
        let mut h = DefaultHasher::new();
        target.hash(&mut h);
        &self.locks[(h.finish() as usize) % LOCK_SHARDS]
    }

    /// Verify, loop-guard, apply the op's per-hop state mutation, and return the faces
    /// to **propagate** the message onward to (empty = walk ends here). `None` = the
    /// message was dropped (unauthenticated, or a stale/looping sequence).
    pub async fn decide(
        &self,
        pc: &PathControl,
        interest: &Interest,
        in_face: FaceId,
    ) -> Option<Vec<FaceId>> {
        // (1) Authorize via the pluggable trust root (prefix signature for MAP-Me,
        // pipe membership for a pipe teardown). Unauthorized control is dropped. Done
        // before taking the per-target lock since validation may be slow.
        if !self.authorizer.authorize(pc, interest).await {
            return None; // unauthorized control — drop (anti prefix-hijack / rogue teardown)
        }

        // Serialize the admit→apply critical section per target so concurrent admitted
        // messages can't reorder their FIB writes (no .await is held under this lock).
        let _guard = self.lock_for(&pc.target).lock().unwrap();

        // (2) Loop/staleness guard, keyed by (target, op) so independent mechanisms on the
        // same prefix don't starve each other (see SeqStore docs).
        if !self.seq.admit(&pc.target, pc.op, pc.seq) {
            return None;
        }

        // (3) The current next-hops point toward the *old* location — capture them
        // (minus the arrival face) to propagate the walk before we mutate.
        let old_faces: Vec<FaceId> = self
            .fib
            .lpm(&pc.target)
            .map(|e| {
                e.nexthops
                    .iter()
                    .map(|nh| nh.face_id)
                    .filter(|f| *f != in_face)
                    .collect()
            })
            .unwrap_or_default();

        match pc.op {
            PathOp::Redirect => {
                // Add/update the arrival face as a next-hop toward the producer's new
                // location (the MAP-Me trail step). We *merge* rather than replace the set
                // so a prefix served by multiple producers/paths doesn't lose its
                // alternatives on one IU; cost 0 reflects the IU's assertion that the
                // producer is currently reachable this way (the strategy can still fail
                // over to the retained alternatives).
                self.fib.add_nexthop(&pc.target, in_face, 0);
            }
            PathOp::Teardown => {
                // Observer-driven: the FIB isn't clobbered here (a pipe teardown is
                // session state, not a route — and a namespace may carry other pipes).
                // The observer reaps the model-specific state for the id in `params`.
                let params = interest.app_parameters().map(|b| b.as_ref()).unwrap_or(&[]);
                for o in &self.observers {
                    o.on_teardown(pc, params);
                }
            }
            PathOp::Refresh => {
                let params = interest.app_parameters().map(|b| b.as_ref()).unwrap_or(&[]);
                for o in &self.observers {
                    o.on_refresh(pc, params);
                }
            }
        }

        Some(old_faces)
    }
}
