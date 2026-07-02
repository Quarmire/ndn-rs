//! Measurement provenance — the security "fifth cut" (principle P6).
//!
//! Signing proves *who* and *whether-altered*; it says nothing about *where the
//! emitter physically was* or *when the photons actually arrived*. So a
//! measurement carries not only how noisy it is (`sigma`) but how exposed it is
//! to an active adversary, and the combiner reasons over that exposure as a
//! **lattice**, never as a count of green checkmarks — because the failure modes
//! differ. An authenticated-but-not-distance-bounded sample is exposed to a
//! relayed/compromised peer that an unauthenticated-but-distance-bounded one is
//! not, and vice-versa; the combiner must know *which* threat each input is
//! exposed to, not how many boxes it ticks.

/// Identifies the authorised key that signed a measurement (for T2 key-diversity
/// checks). Opaque; the actual key material lives in the security layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyId(pub u64);

/// Identifies the bearer/face a measurement arrived over (for T1 path-diversity
/// checks — a single relay/wormhole controls one path).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PathId(pub u32);

/// Whether a measurement came from an authorised time authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Authenticity {
    /// Not from an authorised key — may influence *nothing* security-relevant.
    Unauthenticated,
    /// Signed by a key the trust schema authorises to speak for time in this
    /// namespace.
    AuthenticatedDomainPeer(KeyId),
}

impl Authenticity {
    /// A total order for the lattice meet: `AuthenticatedDomainPeer` outranks
    /// `Unauthenticated`.
    pub const fn rank(self) -> u8 {
        match self {
            Authenticity::Unauthenticated => 0,
            Authenticity::AuthenticatedDomainPeer(_) => 1,
        }
    }

    /// Whether this is from an authorised authority.
    pub const fn is_authenticated(self) -> bool {
        matches!(self, Authenticity::AuthenticatedDomainPeer(_))
    }

    /// The signing key, if authenticated.
    pub const fn key(self) -> Option<KeyId> {
        match self {
            Authenticity::AuthenticatedDomainPeer(k) => Some(k),
            Authenticity::Unauthenticated => None,
        }
    }
}

/// A measurement's exposure to an active adversary — the "adversary number"
/// that rides beside the "noise number".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MeasurementProvenance {
    /// Is there a PHY upper bound on physical distance to the emitter (T1)?
    /// `false` for common-view and ordinary time-of-flight — those are honest
    /// distances, not adversarial *upper* bounds.
    pub distance_bounded: bool,
    /// Is a fresh nonce/seq bound to this exchange (T3 replay)?
    pub replay_protected: bool,
    /// Authorisation status (T2).
    pub authenticity: Authenticity,
    /// Which bearer/face it arrived over (T1 path-diversity).
    pub path: PathId,
}

impl MeasurementProvenance {
    /// The **meet** (worst case) of two provenances, used when both jointly
    /// establish a fix. `distance_bounded`/`replay_protected` AND together (a
    /// fix is only as bounded as its weakest input) and authenticity takes the
    /// weaker rank. `path` is not meaningful for a meet, so the left path is
    /// kept as a representative.
    #[must_use]
    pub fn meet(self, other: MeasurementProvenance) -> MeasurementProvenance {
        let authenticity = if self.authenticity.rank() <= other.authenticity.rank() {
            self.authenticity
        } else {
            other.authenticity
        };
        MeasurementProvenance {
            distance_bounded: self.distance_bounded && other.distance_bounded,
            replay_protected: self.replay_protected && other.replay_protected,
            authenticity,
            path: self.path,
        }
    }
}

/// The T1 (relay/wormhole) requirement for an action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum T1Requirement {
    /// T1 not relevant to this action's stakes.
    NotRequired,
    /// The fix must be anchored against relay: either an input is genuinely
    /// distance-bounded, or at least `min_paths` inputs arrive over distinct
    /// bearers (a single wormhole controls one path, so it cannot fabricate
    /// agreement across disjoint paths).
    DistanceBoundedOrDisjointPaths {
        /// Minimum number of distinct paths that count as T1-disjoint.
        min_paths: usize,
    },
}

/// What a given action's stakes require of the measurements that establish it.
///
/// This is the operational form of the threat model: an action names its floor,
/// and [`admits`] decides whether a set of measurements clears it. Admission is
/// about **threat-diversity, not count** — two inputs exposed to the *same*
/// threat add no robustness against it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StakesFloor {
    /// T2: how many *distinct* authorised keys must agree (0 = authentication
    /// not required, for a low-stakes read).
    pub min_distinct_keys: usize,
    /// T3: whether every establishing measurement must be replay-protected.
    pub require_replay_protected: bool,
    /// T1: the relay/wormhole requirement.
    pub t1: T1Requirement,
}

impl StakesFloor {
    /// A low-stakes read: no authentication, no T1/T3 requirement. Suitable for
    /// e.g. a coarse display, never for authorising an action.
    pub const fn low() -> Self {
        Self {
            min_distinct_keys: 0,
            require_replay_protected: false,
            t1: T1Requirement::NotRequired,
        }
    }

    /// A high-stakes action (authorise a transmit slot, enforce a cert window):
    /// authenticated by at least one authority, replay-protected, and anchored
    /// against relay by a distance bound or ≥2 disjoint paths.
    pub const fn high() -> Self {
        Self {
            min_distinct_keys: 1,
            require_replay_protected: true,
            t1: T1Requirement::DistanceBoundedOrDisjointPaths { min_paths: 2 },
        }
    }
}

/// Count distinct values in a small slice without allocation (n is the number
/// of time sources — tiny). O(n²) is fine and keeps the crate no-alloc.
fn count_distinct<T: PartialEq + Copy>(xs: &[T]) -> usize {
    let mut n = 0;
    let mut i = 0;
    while i < xs.len() {
        let mut seen = false;
        let mut j = 0;
        while j < i {
            if xs[j] == xs[i] {
                seen = true;
                break;
            }
            j += 1;
        }
        if !seen {
            n += 1;
        }
        i += 1;
    }
    n
}

/// Decide whether a set of measurements clears an action's [`StakesFloor`].
///
/// This is §10.4 operationalised. The rule is deliberately *not* "AND some
/// booleans": it requires **independence with respect to the threat that
/// matters** — distinct authorised keys for T2, distinct paths (or a real
/// distance bound) for T1 — so an attacker who controls one exposure class
/// cannot manufacture apparent agreement. An empty set never admits anything.
pub fn admits(measurements: &[MeasurementProvenance], floor: &StakesFloor) -> bool {
    if measurements.is_empty() {
        return false;
    }

    // T2 — authentication + key diversity.
    if floor.min_distinct_keys > 0 {
        // Every establishing measurement must be authenticated; an unauthenticated
        // input can influence nothing security-relevant.
        if !measurements
            .iter()
            .all(|m| m.authenticity.is_authenticated())
        {
            return false;
        }
        // Count distinct authorised keys — two samples from the *same* key add
        // no robustness against that key being compromised.
        let mut keys = [KeyId(0); MAX_MEASUREMENTS];
        let mut k = 0;
        for m in measurements.iter().take(MAX_MEASUREMENTS) {
            if let Some(key) = m.authenticity.key() {
                keys[k] = key;
                k += 1;
            }
        }
        if count_distinct(&keys[..k]) < floor.min_distinct_keys {
            return false;
        }
    }

    // T3 — replay protection (meet).
    if floor.require_replay_protected && !measurements.iter().all(|m| m.replay_protected) {
        return false;
    }

    // T1 — relay/wormhole: a real distance bound, or path diversity.
    if let T1Requirement::DistanceBoundedOrDisjointPaths { min_paths } = floor.t1 {
        let has_bound = measurements.iter().any(|m| m.distance_bounded);
        if !has_bound {
            let mut paths = [PathId(0); MAX_MEASUREMENTS];
            let mut p = 0;
            for m in measurements.iter().take(MAX_MEASUREMENTS) {
                paths[p] = m.path;
                p += 1;
            }
            if count_distinct(&paths[..p]) < min_paths {
                return false;
            }
        }
    }

    true
}

/// Upper bound on how many measurements `admits` inspects for diversity without
/// allocating. Beyond this, extra measurements are ignored for the distinct-count
/// (they cannot *reduce* diversity, so this is safe — it can only make admission
/// stricter, never more permissive).
pub const MAX_MEASUREMENTS: usize = 32;

/// A value that carries its noise *and* its adversary exposure.
///
/// The named-time analogue of `SafeData`: just as unvalidated data cannot reach
/// forwarding, an unbounded/unauthenticated/replayable measurement cannot be
/// treated by the combiner as equal to a bounded/authenticated/fresh one — the
/// type carries the exposure and [`admits`] enforces it.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Measured<T> {
    /// The measured value.
    pub value: T,
    /// One-sigma noise of the measurement, nanoseconds.
    pub sigma_ns: u64,
    /// Adversary exposure.
    pub prov: MeasurementProvenance,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth(k: u64, path: u32, bounded: bool, replay: bool) -> MeasurementProvenance {
        MeasurementProvenance {
            distance_bounded: bounded,
            replay_protected: replay,
            authenticity: Authenticity::AuthenticatedDomainPeer(KeyId(k)),
            path: PathId(path),
        }
    }

    #[test]
    fn meet_is_worst_case() {
        let a = auth(1, 1, true, true);
        let b = MeasurementProvenance {
            distance_bounded: false,
            replay_protected: true,
            authenticity: Authenticity::Unauthenticated,
            path: PathId(2),
        };
        let m = a.meet(b);
        assert!(!m.distance_bounded, "one unbounded => meet unbounded");
        assert!(m.replay_protected);
        assert!(
            !m.authenticity.is_authenticated(),
            "one unauth => meet unauth"
        );
    }

    #[test]
    fn empty_set_admits_nothing() {
        assert!(!admits(&[], &StakesFloor::high()));
        assert!(!admits(&[], &StakesFloor::low()));
    }

    #[test]
    fn unauthenticated_cannot_clear_high() {
        let m = MeasurementProvenance {
            distance_bounded: true,
            replay_protected: true,
            authenticity: Authenticity::Unauthenticated,
            path: PathId(1),
        };
        assert!(!admits(&[m], &StakesFloor::high()));
    }

    #[test]
    fn two_samples_same_key_are_not_two_authorities() {
        // Distance-bounded + replay-protected + authenticated, but the *same*
        // key twice — fails min_distinct_keys=2 even though everything is green.
        let floor = StakesFloor {
            min_distinct_keys: 2,
            require_replay_protected: true,
            t1: T1Requirement::NotRequired,
        };
        let same = [auth(7, 1, true, true), auth(7, 2, true, true)];
        assert!(!admits(&same, &floor), "one key is not two authorities");
        let distinct = [auth(7, 1, true, true), auth(9, 2, true, true)];
        assert!(admits(&distinct, &floor));
    }

    #[test]
    fn t1_needs_bound_or_disjoint_paths() {
        // Two unbounded measurements over the SAME path add no T1 robustness.
        let same_path = [auth(1, 5, false, true), auth(2, 5, false, true)];
        assert!(!admits(&same_path, &StakesFloor::high()));
        // Two unbounded over DISTINCT paths clear T1.
        let disjoint = [auth(1, 5, false, true), auth(2, 6, false, true)];
        assert!(admits(&disjoint, &StakesFloor::high()));
        // A single genuinely distance-bounded measurement also clears T1.
        let bounded = [auth(1, 5, true, true)];
        let floor1 = StakesFloor {
            min_distinct_keys: 1,
            require_replay_protected: true,
            t1: T1Requirement::DistanceBoundedOrDisjointPaths { min_paths: 2 },
        };
        assert!(admits(&bounded, &floor1));
    }

    #[test]
    fn low_stakes_admits_a_bare_reading() {
        let bare = MeasurementProvenance {
            distance_bounded: false,
            replay_protected: false,
            authenticity: Authenticity::Unauthenticated,
            path: PathId(0),
        };
        assert!(admits(&[bare], &StakesFloor::low()));
    }
}
