//! Property tests for the named-time core. The crate is `#![no_std]`; these
//! integration tests link it into a `std` test binary, which is fine.

use ndn_time::capability::ClockCapability;
use ndn_time::combine::marzullo;
use ndn_time::election::{ElectionParams, anchor_weight};
use ndn_time::interval::TimeInterval;
use ndn_time::provenance::{
    Authenticity, KeyId, Measured, MeasurementProvenance, PathId, StakesFloor, admits,
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

    // The anchor election weight is always a valid weight in [0, 1] and is
    // monotone non-increasing in uncertainty (a looser clock never out-weights
    // a tighter one of the same capability/stratum).
    #[test]
    fn anchor_weight_in_unit_range_and_monotone(
        u1 in 0u64..10_000_000_000,
        du in 0u64..10_000_000_000,
        stratum in 0u8..8,
    ) {
        let caps = [
            ClockCapability::gnss_disciplined(),
            ClockCapability::oscillator_tcxo(),
            ClockCapability::esp32_rc(),
            ClockCapability::ntp_uplink(),
        ];
        let params = ElectionParams::default();
        let u2 = u1.saturating_add(du); // looser
        for cap in caps {
            let w1 = anchor_weight(&cap, u1, stratum, &params);
            let w2 = anchor_weight(&cap, u2, stratum, &params);
            prop_assert!((0.0..=1.0).contains(&w1), "weight {w1} out of [0,1]");
            prop_assert!((0.0..=1.0).contains(&w2));
            prop_assert!(w2 <= w1, "looser uncertainty must not raise the weight");
        }
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

fn a_prov() -> MeasurementProvenance {
    MeasurementProvenance {
        distance_bounded: true, // deliberately true, so common_view forcing false is observable
        replay_protected: true,
        authenticity: Authenticity::AuthenticatedDomainPeer(KeyId(1)),
        path: PathId(1),
    }
}

proptest! {
    // Two-way never panics on arbitrary timestamps (i128 intermediate, clamped).
    #[test]
    fn two_way_never_panics(t1 in any::<i64>(), t2 in any::<i64>(), t3 in any::<i64>(), t4 in any::<i64>()) {
        let _ = ndn_time::measure::two_way(t1, t2, t3, t4, 100, 100, a_prov());
    }

    // On a symmetric path, two-way recovers the injected offset exactly. The
    // four stamps are constructed from (offset, delay, turnaround): local reads
    // true time, remote reads true + offset.
    #[test]
    fn two_way_recovers_symmetric_offset(
        offset in -1_000_000_000i64..1_000_000_000,
        delay in 0i64..100_000_000,
        turn in 0i64..100_000_000,
        base in -1_000_000_000i64..1_000_000_000,
    ) {
        let t1 = base;                          // local send (local clock == true)
        let t2 = base + delay + offset;         // remote recv = (base+delay) + offset
        let t3 = base + delay + turn + offset;  // remote send = above + turnaround
        let t4 = base + 2 * delay + turn;       // local recv (local == true)
        let r = ndn_time::measure::two_way(t1, t2, t3, t4, 0, 0, a_prov());
        prop_assert_eq!(r.offset.value, offset);
    }

    // Common-view recovers A−B regardless of the emission time (the transmitter
    // cancels), and always forces distance_bounded false.
    #[test]
    fn common_view_recovers_offset_and_forces_unbounded(
        oa in -1_000_000i64..1_000_000,
        ob in -1_000_000i64..1_000_000,
        pa in 0u64..100_000,
        pb in 0u64..100_000,
        emit in -1_000_000_000i64..1_000_000_000,
    ) {
        // A reads true + oa, B reads true + ob; each stamps at emit + its prop.
        let rx_a = emit + pa as i64 + oa;
        let rx_b = emit + pb as i64 + ob;
        let m = ndn_time::measure::common_view(
            ndn_time::measure::RxObs { stamp_ns: rx_a, prop_ns: pa, prec_ns: 0 },
            ndn_time::measure::RxObs { stamp_ns: rx_b, prop_ns: pb, prec_ns: 0 },
            0,
            a_prov(),
        );
        prop_assert_eq!(m.value, oa - ob, "offset A − B, transmitter cancels");
        prop_assert!(!m.prov.distance_bounded, "a relay defeats common-view");
    }
}

use ndn_time::discipline::{PeerSample, TimePolicy, TimeState};

fn peer_sample(offset_ns: i64, sigma_ns: u64, key: u64, path: u32) -> PeerSample {
    PeerSample {
        offset: Measured {
            value: offset_ns,
            sigma_ns,
            prov: MeasurementProvenance {
                distance_bounded: false,
                replay_protected: true,
                authenticity: Authenticity::AuthenticatedDomainPeer(KeyId(key)),
                path: PathId(path),
            },
        },
        captured_mono_ns: 0,
        cap: ClockCapability::oscillator_tcxo(),
    }
}

proptest! {
    // The discipline pass never panics on arbitrary offsets/uncertainties.
    #[test]
    fn discipline_never_panics(
        offsets in prop::collection::vec(-1_000_000_000i64..1_000_000_000, 0..10),
        sigma in 1u64..10_000_000,
        local_wall in -1_000_000_000i64..1_000_000_000,
        now_mono in 0u64..100_000_000_000,
    ) {
        let policy = TimePolicy::default();
        let mut st = TimeState::new();
        for (i, &o) in offsets.iter().enumerate() {
            st.ingest(i as u64, peer_sample(o, sigma, i as u64, i as u32));
        }
        let _ = policy.discipline(&mut st, local_wall, now_mono);
    }

    // A cluster of authenticated, path-diverse peers agreeing around a true
    // offset yields an admitted fix whose interval contains that offset.
    #[test]
    fn discipline_fix_contains_the_true_offset(
        true_offset in -100_000_000i64..100_000_000,
        spread in 0i64..40_000,
        local_wall in -1_000_000_000i64..1_000_000_000,
    ) {
        let policy = TimePolicy::default();
        let mut st = TimeState::new();
        // Three peers within ±spread of the true offset, each ±50 µs — distinct
        // keys and paths so the high floor's T1/T2 diversity is met.
        let sigma = 50_000u64;
        st.ingest(1, peer_sample(true_offset - spread, sigma, 1, 1));
        st.ingest(2, peer_sample(true_offset, sigma, 2, 2));
        st.ingest(3, peer_sample(true_offset + spread, sigma, 3, 3));
        let c = policy.discipline(&mut st, local_wall, 0);
        prop_assert!(c.admitted, "three distinct authed peers clear the floor");
        // The combined fix interval (offset ± uncertainty) must contain the truth.
        let lo = c.offset_ns - c.uncertainty_ns as i64;
        let hi = c.offset_ns + c.uncertainty_ns as i64;
        prop_assert!(lo <= true_offset && true_offset <= hi,
            "fix [{lo},{hi}] must contain true offset {true_offset}");
    }
}
