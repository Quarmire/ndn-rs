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

use std::sync::Arc;

use async_trait::async_trait;
use ndn_packet::Interest;
use ndn_pathcontrol::{PathControl, PathOp, SeqStore};
use ndn_security::{InterestValidationOutcome, Validator};
use ndn_transport::FaceId;

use crate::fib::{Fib, FibNexthop};

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
    /// Authorizes the in-transit state mutation. `None` skips authorization (trusted /
    /// test deployments only) — a production handler must be built with one.
    authorizer: Option<Arc<dyn PathAuthorizer>>,
    observers: Vec<Arc<dyn PathControlObserver>>,
}

impl PathControlHandler {
    pub fn new(
        fib: Arc<Fib>,
        authorizer: Option<Arc<dyn PathAuthorizer>>,
        observers: Vec<Arc<dyn PathControlObserver>>,
    ) -> Self {
        Self {
            fib,
            seq: SeqStore::new(),
            authorizer,
            observers,
        }
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
        // pipe membership for a pipe teardown). Unauthorized control is dropped.
        if let Some(auth) = &self.authorizer
            && !auth.authorize(pc, interest).await
        {
            return None; // unauthorized control — drop (anti prefix-hijack / rogue teardown)
        }

        // (2) Loop/staleness guard: only strictly-newer sequences proceed.
        if !self.seq.admit(&pc.target, pc.seq) {
            return None;
        }

        // (3) The current next-hops point toward the *old* location — capture them
        // (minus the arrival face) to propagate the walk before we overwrite.
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
                // Repoint the prefix back toward where the update arrived (the new
                // location) — the MAP-Me trail step.
                self.fib.set_nexthops(
                    &pc.target,
                    vec![FibNexthop {
                        face_id: in_face,
                        cost: 0,
                    }],
                );
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
