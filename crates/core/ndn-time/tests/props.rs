//! Property tests for the named-time core. The crate is `#![no_std]`; these
//! integration tests link it into a `std` test binary, which is fine.

use ndn_time::capability::ClockCapability;
use ndn_time::combine::marzullo;
use ndn_time::interval::TimeInterval;
use ndn_time::provenance::{
    Authenticity, KeyId, MeasurementProvenance, PathId, StakesFloor, admits,
};
use proptest::prelude::*;

// Bounded so arithmetic stays in the meaningful (non-saturating) regime while
// still exercising the algorithms broadly.
fn arb_interval() -> impl Strategy<Value = TimeInterval> {
    (-1_000_000_000i64..1_000_000_000, 0u64..10_000_000).prop_map(|(c, r)| TimeInterval::new(c, r))
}

proptest! {
    // Marzullo never panics and never claims more support than it has inputs.
    #[test]
    fn marzullo_support_bounded_by_inputs(ivs in prop::collection::vec(arb_interval(), 0..40)) {
        match marzullo(&ivs) {
            None => prop_assert!(ivs.is_empty()),
            Some(c) => {
                prop_assert!(c.support >= 1);
                prop_assert!(c.support <= ivs.len());
                // The reported support must actually be realised: at least
                // `support` input intervals contain the combined center.
                let containing = ivs.iter().filter(|iv| iv.contains(c.interval.center_ns)).count();
                prop_assert!(containing >= c.support,
                    "support {} claimed but only {} intervals contain the center", c.support, containing);
            }
        }
    }

    // A point shared by every interval forces full support.
    #[test]
    fn universal_overlap_gets_full_support(
        centers in prop::collection::vec(-500_000i64..500_000, 1..20)
    ) {
        // Radius large enough that all intervals contain 0.
        let ivs: Vec<_> = centers.iter().map(|&c| TimeInterval::new(c, 1_000_000)).collect();
        let c = marzullo(&ivs).unwrap();
        prop_assert_eq!(c.support, ivs.len());
    }

    // Intersection is commutative and shrinks (never grows) the interval.
    #[test]
    fn intersect_commutes_and_shrinks(a in arb_interval(), b in arb_interval()) {
        match (a.intersect(&b), b.intersect(&a)) {
            (Some(ab), Some(ba)) => {
                prop_assert_eq!(ab.lo(), ba.lo());
                prop_assert_eq!(ab.hi(), ba.hi());
                prop_assert!(ab.width_ns() <= a.width_ns());
                prop_assert!(ab.width_ns() <= b.width_ns());
            }
            (None, None) => {}
            _ => prop_assert!(false, "intersection must be symmetric"),
        }
    }

    // Holdover uncertainty growth is monotone non-decreasing in elapsed time.
    #[test]
    fn holdover_growth_monotone(e1 in 0u64..1_000_000_000_000, delta in 0u64..1_000_000_000_000) {
        let h = ClockCapability::oscillator_tcxo().holdover;
        let e2 = e1.saturating_add(delta);
        prop_assert!(h.growth_ns(e1) <= h.growth_ns(e2));
    }
}

fn arb_prov() -> impl Strategy<Value = MeasurementProvenance> {
    (
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
        0u64..8,
        0u32..8,
    )
        .prop_map(
            |(bounded, replay, is_auth, key, path)| MeasurementProvenance {
                distance_bounded: bounded,
                replay_protected: replay,
                authenticity: if is_auth {
                    Authenticity::AuthenticatedDomainPeer(KeyId(key))
                } else {
                    Authenticity::Unauthenticated
                },
                path: PathId(path),
            },
        )
}

proptest! {
    // Admission never panics, and the high floor can never be cleared by a set
    // that contains any unauthenticated measurement (authentication is a meet).
    #[test]
    fn high_floor_rejects_any_unauthenticated(
        provs in prop::collection::vec(arb_prov(), 0..20)
    ) {
        let has_unauth = provs.iter().any(|p| !p.authenticity.is_authenticated());
        let admitted = admits(&provs, &StakesFloor::high());
        if admitted {
            prop_assert!(!has_unauth, "high floor admitted a set containing an unauthenticated sample");
        }
    }

    // The low floor admits exactly the non-empty sets.
    #[test]
    fn low_floor_admits_nonempty(provs in prop::collection::vec(arb_prov(), 0..20)) {
        prop_assert_eq!(admits(&provs, &StakesFloor::low()), !provs.is_empty());
    }
}
