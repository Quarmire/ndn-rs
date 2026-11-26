//! The budgets an ask passes **before** its signature is known good (docs/specs/channel.md, Judging
//! the asker, steps 2 and 4): they bound what an ask that is not yet attributed to anyone can cost
//! the sender, and they must not let one unauthenticated source use up what the genuine askers
//! need.
//!
//! What an ask names (its KeyLocator, its space) is whatever its sender wrote, so no budget can be
//! charged to a *named* key: a stranger would empty a member's. What the sender knows of an ask
//! before verifying it is the face it arrived over. Each budget is therefore two buckets, both of
//! which an ask must pass: one **per ingress face** (a face that floods is refused, the others are
//! not) and one for the **node**, a ceiling sized for what the work costs the CPU, never for how
//! many receivers a channel has (a face's own bucket carries a whole channel re-keying at once).
//!
//! * the **lookup** budget stands in front of the judging of standing, which reads the space's
//!   record under its lock: so a flood at wire rate cannot hold that lock against the space's
//!   other work;
//! * the **verification** budget stands in front of the signature check, the one expensive step.
//!
//! A refused ask is answered a `Congestion` Nack: the asker is told it is over a rate and asks
//! again signed afresh.
//!
//! What this cannot do: tell two sources apart behind one face. A router that forwards for many
//! sources shares its face's bucket among them; bounding its sources is that router's rate limit
//! on its own faces (channel.md 13.12).

use std::collections::HashMap;

use ndn_transport::FaceId;
use parking_lot::Mutex;

use crate::rt::Instant;

/// How many asks a budget passes: `rate` a second after a `burst` at once.
#[derive(Clone, Copy)]
pub(crate) struct Rate {
    pub(crate) rate: f64,
    pub(crate) burst: f64,
}

/// The lookup budget of one face: a whole channel's receivers (256) asking at once, several
/// times over.
pub(crate) const LOOKUPS_FACE: Rate = Rate {
    rate: 1024.0,
    burst: 1024.0,
};
/// The lookup budget of the node.
pub(crate) const LOOKUPS_NODE: Rate = Rate {
    rate: 8192.0,
    burst: 8192.0,
};
/// The verification budget of one face: a whole channel's receivers (256) asking after a re-key
/// pass at once, then 64 a second.
pub(crate) const VERIFIES_FACE: Rate = Rate {
    rate: 64.0,
    burst: 256.0,
};
/// The verification budget of the node: what verifying signatures may cost the CPU, 1,024 a
/// second (a fraction of one core), however many faces ask.
pub(crate) const VERIFIES_NODE: Rate = Rate {
    rate: 1024.0,
    burst: 1024.0,
};

/// The most faces a budget keeps a bucket of: those past it that were idle longest go.
const FACES_MAX: usize = 1024;

/// A token bucket: how many tokens it held at `at`.
#[derive(Clone, Copy)]
struct Bucket {
    tokens: f64,
    at: Instant,
}

impl Bucket {
    /// What it holds at `now`.
    fn held(&self, rate: Rate, now: Instant) -> f64 {
        (self.tokens + now.saturating_duration_since(self.at).as_secs_f64() * rate.rate)
            .min(rate.burst)
    }
}

/// One budget: a bucket per ingress face (`None`: a face the forwarder did not name) and one for
/// the node.
struct Gate {
    face: Rate,
    node: Rate,
    faces: HashMap<Option<FaceId>, Bucket>,
    all: Option<Bucket>,
}

impl Gate {
    fn new(face: Rate, node: Rate) -> Gate {
        Gate {
            face,
            node,
            faces: HashMap::new(),
            all: None,
        }
    }

    /// One token of the face's bucket **and** of the node's, or none of either.
    fn take(&mut self, face: Option<FaceId>, now: Instant) -> bool {
        if self.faces.len() >= FACES_MAX && !self.faces.contains_key(&face) {
            // Every bucket that has refilled is the same as none: drop those, then the idlest.
            let rate = self.face;
            self.faces.retain(|_, b| b.held(rate, now) < rate.burst);
            if self.faces.len() >= FACES_MAX {
                let idlest = self.faces.iter().min_by_key(|(_, b)| b.at);
                if let Some(idlest) = idlest.map(|(f, _)| *f) {
                    self.faces.remove(&idlest);
                }
            }
        }
        let held_face = self
            .faces
            .get(&face)
            .map_or(self.face.burst, |b| b.held(self.face, now));
        let held_node = self
            .all
            .as_ref()
            .map_or(self.node.burst, |b| b.held(self.node, now));
        if held_face < 1.0 || held_node < 1.0 {
            return false;
        }
        self.faces.insert(
            face,
            Bucket {
                tokens: held_face - 1.0,
                at: now,
            },
        );
        self.all = Some(Bucket {
            tokens: held_node - 1.0,
            at: now,
        });
        true
    }
}

/// The two budgets of the sender's setup.
pub(crate) struct Gates {
    lookups: Mutex<Gate>,
    verifies: Mutex<Gate>,
}

impl Default for Gates {
    fn default() -> Gates {
        Gates {
            lookups: Mutex::new(Gate::new(LOOKUPS_FACE, LOOKUPS_NODE)),
            verifies: Mutex::new(Gate::new(VERIFIES_FACE, VERIFIES_NODE)),
        }
    }
}

impl Gates {
    /// Whether an ask that arrived over `face` may have its standing looked up now.
    pub(crate) fn lookup(&self, face: Option<FaceId>, now: Instant) -> bool {
        self.lookups.lock().take(face, now)
    }

    /// Whether an ask that arrived over `face` may have its signature verified now.
    pub(crate) fn verify(&self, face: Option<FaceId>, now: Instant) -> bool {
        self.verifies.lock().take(face, now)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn face(n: u64) -> Option<FaceId> {
        Some(FaceId(n))
    }

    /// A face that floods empties its own bucket and no other face's: the others' asks pass.
    #[test]
    fn one_faces_flood_leaves_another_faces_budget_whole() {
        let gates = Gates::default();
        let t0 = Instant::now();
        let passed = (0..1000).filter(|_| gates.verify(face(1), t0)).count();
        assert_eq!(
            passed, VERIFIES_FACE.burst as usize,
            "its own burst, no more"
        );
        assert!(!gates.verify(face(1), t0 + Duration::from_millis(10)));
        assert!(
            gates.verify(face(1), t0 + Duration::from_millis(20)),
            "64 a second: a token every 15.6 ms"
        );
        let other = (0..300).filter(|_| gates.verify(face(2), t0)).count();
        assert_eq!(other, 256, "another face's bucket is whole");
        assert!(
            gates.verify(None, t0),
            "a face the forwarder did not name has a bucket of its own"
        );
    }

    /// Faces together cannot pass the node's ceiling, the CPU's bound.
    #[test]
    fn the_node_ceiling_holds_whatever_the_faces() {
        let gates = Gates::default();
        let t0 = Instant::now();
        let passed = (0..4000u64)
            .filter(|i| gates.verify(face(i % 100), t0))
            .count();
        assert_eq!(passed, VERIFIES_NODE.burst as usize);
    }

    /// The lookup budget is a bigger one than the verification budget: a flood the verification
    /// budget sheds still passes the lookup, which is cheap.
    #[test]
    fn the_lookup_budget_is_wider_than_the_verification_budget() {
        let gates = Gates::default();
        let t0 = Instant::now();
        let lookups = (0..5000).filter(|_| gates.lookup(face(1), t0)).count();
        assert_eq!(lookups, LOOKUPS_FACE.burst as usize);
        const { assert!(LOOKUPS_FACE.burst > VERIFIES_FACE.burst) };
    }

    /// A stranger that opens a face per ask cannot make the table of buckets grow without bound.
    #[test]
    fn the_buckets_kept_are_bounded() {
        let gates = Gates::default();
        let t0 = Instant::now();
        for i in 0..(2 * FACES_MAX as u64) {
            let _ = gates.verify(face(i), t0);
        }
        assert!(gates.verifies.lock().faces.len() <= FACES_MAX);
    }
}
