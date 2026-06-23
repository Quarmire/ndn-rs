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

use ndn_packet::{Interest, Name};
use ndn_pathcontrol::{PathControl, PathOp, SeqStore};
use ndn_security::{InterestValidationOutcome, Validator};
use ndn_transport::FaceId;

use crate::fib::{Fib, FibNexthop};

/// A consumer of pipe/session-lifecycle PathControl ops. `ndn-pipes` implements this
/// so a `Teardown`/`Refresh` walking the path closes or extends the live pipe, without
/// the forwarder knowing what a pipe is.
pub trait PathControlObserver: Send + Sync {
    /// A `Teardown` for `target` reached this hop.
    fn on_teardown(&self, _target: &Name) {}
    /// A `Refresh` (keepalive) for `target` reached this hop.
    fn on_refresh(&self, _target: &Name) {}
}

/// Per-hop PathControl logic. Opt-in (installed via the engine builder); holds the FIB
/// to mutate, the per-target sequence guard, an optional validator (authorizes the
/// mutation), and any lifecycle observers.
pub struct PathControlHandler {
    fib: Arc<Fib>,
    seq: SeqStore,
    /// Authorizes the in-transit state mutation. `None` skips verification (trusted /
    /// test deployments only) — a production handler must be built with one.
    validator: Option<Arc<Validator>>,
    observers: Vec<Arc<dyn PathControlObserver>>,
}

impl PathControlHandler {
    pub fn new(
        fib: Arc<Fib>,
        validator: Option<Arc<Validator>>,
        observers: Vec<Arc<dyn PathControlObserver>>,
    ) -> Self {
        Self {
            fib,
            seq: SeqStore::new(),
            validator,
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
        // (1) Authorize: only a signature the prefix trusts may rewrite its routes.
        if let Some(v) = &self.validator
            && !matches!(
                v.validate_interest(interest).await,
                InterestValidationOutcome::Valid
            )
        {
            return None; // unauthenticated control — drop (anti prefix-hijack)
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
                self.fib.set_nexthops(&pc.target, vec![]);
                for o in &self.observers {
                    o.on_teardown(&pc.target);
                }
            }
            PathOp::Refresh => {
                for o in &self.observers {
                    o.on_refresh(&pc.target);
                }
            }
        }

        Some(old_faces)
    }
}
