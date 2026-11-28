//! The breadcrumb table of the `SideTable` (docs/specs/channel.md §14.13): a `QUERY` from a sink
//! goes up to the route's source and leaves `(route, token) -> ingress face`; the `ANSWER` from
//! the source consumes it and goes to that one face. Table-level invariants on a logical clock.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use ndn_engine::side::{
    SideConfig, SideDrop, SideId, SideLimits, SideOutcome, SideRate, SideStats, SideTable,
};
use ndn_transport::{FaceId, FaceKind, FaceTable, SideClass};

use crate::side_support::{Handle, answer, data_frame, face, query};

const T0: u64 = 1_000_000_000_000;
const MS: u64 = 1_000_000;

/// The limits of a table that bounds nothing a test does not name: a rate no test reaches.
fn roomy() -> SideLimits {
    SideLimits {
        query_rate: 1_000_000,
        query_burst: 1_000_000,
        ..SideLimits::default()
    }
}

struct Fx {
    faces: Arc<FaceTable>,
    table: SideTable,
    clock: Arc<AtomicU64>,
}

impl Fx {
    fn new() -> Self {
        Self::limits(roomy())
    }

    fn limits(limits: SideLimits) -> Self {
        let clock = Arc::new(AtomicU64::new(T0));
        let c = Arc::clone(&clock);
        Self {
            faces: Arc::new(FaceTable::new()),
            table: SideTable::with_clock(
                SideConfig {
                    limits,
                    ..SideConfig::default()
                },
                Arc::new(move || c.load(Ordering::Relaxed)),
            ),
            clock,
        }
    }

    fn app(&self, id: u64) -> Handle {
        let (f, h) = face(id, FaceKind::App);
        self.faces.insert(f);
        self.table.configure_face(FaceId(id), FaceKind::App);
        h
    }

    fn advance_ms(&self, ms: u64) {
        self.clock.fetch_add(ms * MS, Ordering::Relaxed);
    }

    fn now(&self) -> u64 {
        self.clock.load(Ordering::Relaxed)
    }

    /// Route `id` from `source` to each of `sinks`.
    fn route(&self, id: u64, source: u64, sinks: &[u64]) {
        for &sink in sinks {
            self.table
                .install(
                    SideId(id),
                    FaceId(source),
                    FaceId(sink),
                    Duration::from_secs(30),
                )
                .unwrap();
        }
    }

    fn on_frame(&self, from: u64, frame: Bytes) -> SideOutcome {
        self.table.on_frame(FaceId(from), frame, &self.faces)
    }

    fn stats(&self) -> SideStats {
        self.table.stats()
    }
}

#[test]
fn the_pit_limits_default_to_the_designed_values() {
    let l = SideLimits::default();
    assert_eq!(
        (l.pit_total, l.pit_per_face, l.pit_per_route),
        (16_384, 256, 1_024)
    );
    assert_eq!((l.query_rate, l.query_burst), (512, 128));
    assert_eq!(l.pit_route_reserve, 8);
    assert_eq!((l.route_query_rate, l.route_query_burst), (2_048, 512));
    assert_eq!(l.pit_ttl_max, Duration::from_secs(10));
}

#[test]
fn a_query_from_a_sink_reaches_the_source_and_leaves_a_breadcrumb() {
    let fx = Fx::new();
    let src = fx.app(10);
    let asker = fx.app(20);
    let other = fx.app(21);
    fx.route(1, 10, &[20, 21]);

    let q = query(1, 0xAA, 10, 80);
    assert_eq!(fx.on_frame(20, q.clone()), SideOutcome::Queried);

    let seen = src.side();
    assert_eq!(seen.len(), 1, "the source is handed the query once");
    assert_eq!(seen[0].frame, q, "the frame is not touched");
    assert_eq!(seen[0].class, SideClass::Datagram);
    assert_eq!(
        seen[0].ingress,
        Some(FaceId(20)),
        "with the sink as ingress"
    );
    assert!(asker.side().is_empty() && other.side().is_empty());
    let s = fx.stats();
    assert_eq!((s.breadcrumbs, s.queries), (1, 1));
}

#[test]
fn a_query_from_a_face_that_is_not_a_sink_is_wrong_source() {
    let fx = Fx::new();
    let src = fx.app(10);
    let _sink = fx.app(20);
    let _stranger = fx.app(30);
    fx.route(1, 10, &[20]);

    // A face that is not a sink, and the source itself (a query goes up, not down).
    for from in [30, 10] {
        assert_eq!(
            fx.on_frame(from, query(1, 0xAA, 10, 80)),
            SideOutcome::Dropped(SideDrop::WrongSource)
        );
    }
    // A sink that has lapsed is not one: it must be kept alive to ask.
    fx.advance_ms(31_000);
    assert_eq!(
        fx.on_frame(20, query(1, 0xAB, 10, 80)),
        SideOutcome::Dropped(SideDrop::WrongSource)
    );
    assert!(src.side().is_empty(), "nothing reached the source");
    let s = fx.stats();
    assert_eq!((s.wrong_source, s.breadcrumbs, s.queries), (3, 0, 0));
}

#[test]
fn an_answer_goes_to_the_one_ingress_face_and_consumes_the_breadcrumb() {
    let fx = Fx::new();
    let _src = fx.app(10);
    let a = fx.app(20);
    let b = fx.app(21);
    fx.route(1, 10, &[20, 21]);
    fx.on_frame(20, query(1, 0xA, 10, 80));
    fx.on_frame(21, query(1, 0xB, 10, 80));
    assert_eq!(fx.stats().breadcrumbs, 2);

    let reply = answer(SideClass::Datagram, 1, 0xA, 60);
    assert_eq!(fx.on_frame(10, reply.clone()), SideOutcome::Answered);
    let got = a.side();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].frame, reply);
    assert_eq!(got[0].class, SideClass::Datagram);
    assert_eq!(
        got[0].ingress,
        Some(FaceId(10)),
        "with the source as ingress"
    );
    assert!(b.side().is_empty(), "no other face is handed it");
    assert_eq!((fx.stats().breadcrumbs, fx.stats().answers), (1, 1));

    // An answer on the stream class goes down the stream class.
    let long = answer(SideClass::Stream, 1, 0xB, 6_000);
    assert_eq!(fx.on_frame(10, long), SideOutcome::Answered);
    assert_eq!(b.side()[0].class, SideClass::Stream);
    assert_eq!(a.side().len(), 1);
    assert_eq!(fx.stats().breadcrumbs, 0);
}

#[test]
fn a_second_answer_for_the_same_token_is_unmatched() {
    let fx = Fx::new();
    let _src = fx.app(10);
    let a = fx.app(20);
    let b = fx.app(21);
    fx.route(1, 10, &[20]);
    fx.route(2, 10, &[21]);
    fx.on_frame(20, query(1, 0xA, 10, 80));

    // The token names a breadcrumb of its own route only.
    assert_eq!(
        fx.on_frame(10, answer(SideClass::Datagram, 2, 0xA, 60)),
        SideOutcome::Dropped(SideDrop::Unmatched)
    );
    assert!(b.side().is_empty());

    assert_eq!(
        fx.on_frame(10, answer(SideClass::Datagram, 1, 0xA, 60)),
        SideOutcome::Answered
    );
    assert_eq!(
        fx.on_frame(10, answer(SideClass::Datagram, 1, 0xA, 60)),
        SideOutcome::Dropped(SideDrop::Unmatched),
        "the breadcrumb was consumed by the first"
    );
    assert_eq!(
        fx.on_frame(10, answer(SideClass::Datagram, 1, 0xC, 60)),
        SideOutcome::Dropped(SideDrop::Unmatched),
        "a token nobody asked is unmatched"
    );
    assert_eq!(a.side().len(), 1, "the asker saw one answer");
    assert_eq!(fx.stats().unmatched, 3);
}

#[test]
fn an_answer_from_a_face_that_is_not_the_source_is_dropped() {
    let fx = Fx::new();
    let _src = fx.app(10);
    let a = fx.app(20);
    let _b = fx.app(21);
    let _stranger = fx.app(30);
    fx.route(1, 10, &[20, 21]);
    fx.on_frame(20, query(1, 0xA, 10, 80));

    // Even a sink that knows the token cannot answer for the server, or burn the breadcrumb.
    for from in [20, 21, 30] {
        assert_eq!(
            fx.on_frame(from, answer(SideClass::Datagram, 1, 0xA, 60)),
            SideOutcome::Dropped(SideDrop::WrongSource)
        );
    }
    assert!(a.side().is_empty());
    let s = fx.stats();
    assert_eq!((s.wrong_source, s.breadcrumbs), (3, 1));
    assert_eq!(
        fx.on_frame(10, answer(SideClass::Datagram, 1, 0xA, 60)),
        SideOutcome::Answered,
        "the breadcrumb is still there for the source"
    );
}

#[test]
fn an_expired_breadcrumb_is_late() {
    let fx = Fx::new();
    let _src = fx.app(10);
    let a = fx.app(20);
    fx.route(1, 10, &[20]);
    // Ttl 5 is 500 ms.
    fx.on_frame(20, query(1, 0xA, 5, 80));
    fx.on_frame(20, query(1, 0xB, 5, 80));

    fx.advance_ms(499);
    assert_eq!(
        fx.on_frame(10, answer(SideClass::Datagram, 1, 0xA, 60)),
        SideOutcome::Answered,
        "an answer in time is delivered"
    );
    fx.advance_ms(1);
    assert_eq!(
        fx.on_frame(10, answer(SideClass::Datagram, 1, 0xB, 60)),
        SideOutcome::Dropped(SideDrop::Late),
        "at its expiry it is late"
    );
    assert_eq!(a.side().len(), 1);
    let s = fx.stats();
    assert_eq!((s.late, s.unmatched, s.breadcrumbs), (1, 0, 0));
    assert_eq!(
        fx.on_frame(10, answer(SideClass::Datagram, 1, 0xB, 60)),
        SideOutcome::Dropped(SideDrop::Unmatched),
        "a late answer consumed its breadcrumb"
    );
}

#[test]
fn a_ttl_is_clamped_to_100_ms_and_10_s() {
    let fx = Fx::new();
    let _src = fx.app(10);
    let _a = fx.app(20);
    fx.route(1, 10, &[20]);
    // 0 is read as the least, 255 as the most; neither is refused.
    assert_eq!(fx.on_frame(20, query(1, 0x1, 0, 80)), SideOutcome::Queried);
    assert_eq!(fx.on_frame(20, query(1, 0x4, 0, 80)), SideOutcome::Queried);
    assert_eq!(
        fx.on_frame(20, query(1, 0x2, 255, 80)),
        SideOutcome::Queried
    );
    // Ttl 100 is the 10 s the clamp allows.
    assert_eq!(
        fx.on_frame(20, query(1, 0x3, 100, 80)),
        SideOutcome::Queried
    );

    fx.advance_ms(99);
    assert_eq!(
        fx.on_frame(10, answer(SideClass::Datagram, 1, 0x1, 60)),
        SideOutcome::Answered
    );
    fx.advance_ms(1);
    assert_eq!(
        fx.on_frame(10, answer(SideClass::Datagram, 1, 0x4, 60)),
        SideOutcome::Dropped(SideDrop::Late),
        "a ttl of 0 is 100 ms"
    );
    fx.advance_ms(9_899);
    // 9.999 s since the queries: still live.
    assert_eq!(
        fx.on_frame(10, answer(SideClass::Datagram, 1, 0x2, 60)),
        SideOutcome::Answered
    );
    fx.advance_ms(1);
    assert_eq!(
        fx.on_frame(10, answer(SideClass::Datagram, 1, 0x3, 60)),
        SideOutcome::Dropped(SideDrop::Late),
        "no ttl keeps a breadcrumb beyond the limit"
    );
}

#[test]
fn the_sweep_frees_the_lapsed_and_their_counts() {
    let fx = Fx::limits(SideLimits {
        pit_per_face: 2,
        ..roomy()
    });
    let _src = fx.app(10);
    let _a = fx.app(20);
    fx.route(1, 10, &[20]);
    fx.on_frame(20, query(1, 0xA, 5, 80));
    fx.on_frame(20, query(1, 0xB, 50, 80));
    assert_eq!(
        fx.on_frame(20, query(1, 0xC, 5, 80)),
        SideOutcome::Dropped(SideDrop::PitFaceFull)
    );

    fx.advance_ms(600);
    fx.table.sweep(fx.now());
    assert_eq!(
        fx.stats().breadcrumbs,
        1,
        "the lapsed one went, the live one stays"
    );
    assert_eq!(
        fx.on_frame(10, answer(SideClass::Datagram, 1, 0xA, 60)),
        SideOutcome::Dropped(SideDrop::Unmatched),
        "swept, so unmatched, not late"
    );
    assert_eq!(
        fx.on_frame(20, query(1, 0xC, 5, 80)),
        SideOutcome::Queried,
        "the face's count was freed with it"
    );
}

#[test]
fn each_pit_bound_refuses_and_counts() {
    // The table: one breadcrumb too many.
    let fx = Fx::limits(SideLimits {
        pit_total: 2,
        ..roomy()
    });
    let src = fx.app(10);
    let _a = fx.app(20);
    let _b = fx.app(21);
    fx.route(1, 10, &[20]);
    fx.route(2, 10, &[21]);
    assert_eq!(fx.on_frame(20, query(1, 0x1, 10, 80)), SideOutcome::Queried);
    assert_eq!(fx.on_frame(21, query(2, 0x2, 10, 80)), SideOutcome::Queried);
    assert_eq!(
        fx.on_frame(20, query(1, 0x3, 10, 80)),
        SideOutcome::Dropped(SideDrop::PitFull)
    );
    let s = fx.stats();
    assert_eq!((s.pit_full, s.pit_face_full, s.pit_route_full), (1, 0, 0));
    assert_eq!(
        (s.breadcrumbs, src.side().len()),
        (2, 2),
        "the refused query left nothing and reached nobody"
    );
    // An answer makes room.
    fx.on_frame(10, answer(SideClass::Datagram, 1, 0x1, 60));
    assert_eq!(fx.on_frame(20, query(1, 0x3, 10, 80)), SideOutcome::Queried);

    // One ingress face: its own bound, and another face is not affected.
    let fx = Fx::limits(SideLimits {
        pit_per_face: 2,
        ..roomy()
    });
    let _src = fx.app(10);
    let _a = fx.app(20);
    let _b = fx.app(21);
    fx.route(1, 10, &[20, 21]);
    assert_eq!(fx.on_frame(20, query(1, 0x1, 10, 80)), SideOutcome::Queried);
    assert_eq!(fx.on_frame(20, query(1, 0x2, 10, 80)), SideOutcome::Queried);
    assert_eq!(
        fx.on_frame(20, query(1, 0x3, 10, 80)),
        SideOutcome::Dropped(SideDrop::PitFaceFull)
    );
    assert_eq!(fx.on_frame(21, query(1, 0x4, 10, 80)), SideOutcome::Queried);
    let s = fx.stats();
    assert_eq!((s.pit_full, s.pit_face_full, s.pit_route_full), (0, 1, 0));
    fx.on_frame(10, answer(SideClass::Datagram, 1, 0x1, 60));
    assert_eq!(fx.on_frame(20, query(1, 0x3, 10, 80)), SideOutcome::Queried);

    // One route: its own bound, and another route is not affected.
    let fx = Fx::limits(SideLimits {
        pit_per_route: 2,
        ..roomy()
    });
    let _src = fx.app(10);
    let _a = fx.app(20);
    let _b = fx.app(21);
    fx.route(1, 10, &[20, 21]);
    fx.route(2, 10, &[20]);
    assert_eq!(fx.on_frame(20, query(1, 0x1, 10, 80)), SideOutcome::Queried);
    assert_eq!(fx.on_frame(21, query(1, 0x2, 10, 80)), SideOutcome::Queried);
    assert_eq!(
        fx.on_frame(20, query(1, 0x3, 10, 80)),
        SideOutcome::Dropped(SideDrop::PitRouteFull)
    );
    assert_eq!(fx.on_frame(20, query(2, 0x3, 10, 80)), SideOutcome::Queried);
    let s = fx.stats();
    assert_eq!((s.pit_full, s.pit_face_full, s.pit_route_full), (0, 0, 1));
    fx.on_frame(10, answer(SideClass::Datagram, 1, 0x1, 60));
    assert_eq!(fx.on_frame(20, query(1, 0x5, 10, 80)), SideOutcome::Queried);
}

/// How many of `tokens` queries `from` has taken before the first refusal, and that refusal.
fn until_refused(
    fx: &Fx,
    route: u64,
    from: u64,
    tokens: std::ops::Range<u64>,
) -> (u64, SideOutcome) {
    let mut taken = 0;
    for token in tokens {
        match fx.on_frame(from, query(route, token, 10, 80)) {
            SideOutcome::Queried => taken += 1,
            refused => return (taken, refused),
        }
    }
    panic!("face {from} was never refused");
}

#[test]
fn one_sink_cannot_use_up_the_breadcrumbs_of_a_route_the_others_hold_a_share_of() {
    let fx = Fx::limits(SideLimits {
        pit_per_route: 64,
        ..roomy()
    });
    let _src = fx.app(10);
    for sink in [20, 21, 22, 23] {
        let _ = fx.app(sink);
    }
    fx.route(1, 10, &[20, 21, 22, 23]);
    let reserve = 8;

    // The hostile sink takes the route's room less the share held for each of the other three.
    let (taken, why) = until_refused(&fx, 1, 20, 1_000..2_000);
    assert_eq!(
        (taken, why),
        (
            64 - 3 * reserve,
            SideOutcome::Dropped(SideDrop::PitRouteFull)
        )
    );
    // Each of the others still gets its share.
    for (i, sink) in [21u64, 22, 23].into_iter().enumerate() {
        let base = 10_000 * (i as u64 + 1);
        for token in base..base + reserve {
            assert_eq!(
                fx.on_frame(sink, query(1, token, 10, 80)),
                SideOutcome::Queried,
                "sink {sink} token {token}"
            );
        }
    }
    // Beyond its share a sink waits for the route like any other.
    assert_eq!(
        fx.on_frame(21, query(1, 99_999, 10, 80)),
        SideOutcome::Dropped(SideDrop::PitRouteFull)
    );
    assert_eq!(fx.stats().breadcrumbs, 64);
}

#[test]
fn the_queries_of_all_the_sinks_of_a_route_are_bounded_on_the_way_up() {
    // Each face is far under its own rate; together they would put 512 queries a face into the
    // source's queue at once. The route has a rate of its own.
    let fx = Fx::new();
    let _src = fx.app(10);
    for sink in [20, 21, 22] {
        let _ = fx.app(sink);
    }
    fx.route(1, 10, &[20, 21, 22]);
    for token in 0..512u64 {
        let from = 20 + token % 3;
        assert_eq!(
            fx.on_frame(from, query(1, token, 10, 80)),
            SideOutcome::Queried,
            "token {token}"
        );
    }
    assert_eq!(
        fx.on_frame(22, query(1, 512, 10, 80)),
        SideOutcome::Dropped(SideDrop::QueryRate),
        "the 513th in quick succession"
    );
    let s = fx.stats();
    assert_eq!((s.query_rate_refused, s.breadcrumbs), (1, 512));
    // The refused query left nothing behind and the route refills.
    fx.advance_ms(1);
    assert_eq!(fx.on_frame(22, query(1, 512, 10, 80)), SideOutcome::Queried);
}

/// The route's `QUERY` rate is cut up per sink: four faces' worth of junk (each at its own
/// face rate, so each passes the face's check) fill the route's cell, and a fifth sink that
/// asks once a second still gets its query to the source from its own share.
#[test]
fn sinks_flooding_junk_cannot_starve_another_sink_of_the_route_rate() {
    // The face rate is the default 512 a second; the route takes 1,024, half of what the four
    // flooding faces offer, so the route's cell is full and stays full.
    let fx = Fx::limits(SideLimits {
        route_query_rate: 1_024,
        route_query_burst: 64,
        ..SideLimits::default()
    });
    let _src = fx.app(10);
    for sink in 20..=24 {
        let _ = fx.app(sink);
    }
    fx.route(1, 10, &[20, 21, 22, 23, 24]);

    let mut token = 0u64;
    let mut asked = 0;
    for ms in 0..5_000u64 {
        // Junk with a fresh token each time, ttl 1 (100 ms): a flooder is under every other
        // bound, and only the rates are in play.
        for flooder in 20..=23 {
            token += 1;
            let _ = fx.on_frame(flooder, query(1, token, 1, 80));
        }
        if ms % 1_000 == 500 {
            token += 1;
            asked += 1;
            assert_eq!(
                fx.on_frame(24, query(1, token, 1, 80)),
                SideOutcome::Queried,
                "the sink that sends one query a second was dropped at the forwarder at {ms} ms \
                 (query {asked}), behind four sinks flooding the route's rate"
            );
        }
        if ms % 100 == 99 {
            fx.table.sweep(fx.now());
        }
        fx.advance_ms(1);
    }
    let s = fx.stats();
    assert!(
        s.query_rate_refused > 1_000,
        "the flood was held back by the rates: {s:?}"
    );
    assert_eq!(asked, 5);
}

/// A lone active sink is not lowered by the others' shares being kept: the shares of the idle
/// sinks go to it, and the route takes what it always took (its burst, then its rate).
#[test]
fn a_lone_active_sink_gets_the_whole_route_rate_beside_idle_sinks() {
    let fx = Fx::limits(SideLimits {
        query_rate: 1_000_000,
        query_burst: 1_000_000,
        route_query_rate: 100,
        route_query_burst: 10,
        ..SideLimits::default()
    });
    let _src = fx.app(10);
    for sink in 20..=24 {
        let _ = fx.app(sink);
    }
    fx.route(1, 10, &[20, 21, 22, 23, 24]);

    let mut queried = 0u64;
    for token in 0..10_000u64 {
        if fx.on_frame(20, query(1, token, 1, 80)) == SideOutcome::Queried {
            queried += 1;
        }
        if token % 100 == 99 {
            fx.table.sweep(fx.now());
        }
        fx.advance_ms(1);
    }
    // 10 s at 100 a second and a burst of 10.
    assert!(
        (1_000..=1_012).contains(&queried),
        "a lone sink took {queried} of the 1,010 the route allows in 10 s"
    );
}

/// One round of junk while the route is full: each of `flooders` sends a query, with a token
/// no other has used.
/// (The engine sweeps lapsed breadcrumbs every second; here it is every round.)
fn flood(fx: &Fx, flooders: &[u64], token: &mut u64) {
    fx.table.sweep(fx.now());
    for &f in flooders {
        *token += 1;
        let _ = fx.on_frame(f, query(1, *token, 1, 80));
    }
}

/// A sink's share is its own: it is made with the sink and goes with it. A sink that joins
/// while the route is full gets its first query at once (its share is whole), not a burst of
/// them; a sink that leaves and joins again is a new sink with the same, and installing a
/// sink that is there gives it nothing: no way to a fresh allowance.
#[test]
fn a_sinks_share_is_made_with_it_and_a_new_sink_has_no_burst() {
    let fx = Fx::limits(SideLimits {
        query_rate: 1_000_000,
        query_burst: 1_000_000,
        route_query_rate: 1_024,
        route_query_burst: 64,
        ..SideLimits::default()
    });
    let _src = fx.app(10);
    for sink in 20..=25 {
        let _ = fx.app(sink);
    }
    let flooders = [20, 21, 23, 24];
    fx.route(1, 10, &flooders);
    // Four sinks offer about 4,000 a second to a route that takes 1,024: it is full.
    let mut token = 0u64;
    for _ in 0..200 {
        flood(&fx, &flooders, &mut token);
        fx.advance_ms(1);
    }

    // A new sink: one query now, a second not until its share (1,024 / 64 = 16 a second, one
    // per 62.5 ms) has refilled, with the route as full as ever.
    fx.route(1, 10, &[22]);
    flood(&fx, &flooders, &mut token);
    assert_eq!(
        fx.on_frame(22, query(1, 9_001, 1, 80)),
        SideOutcome::Queried
    );
    assert_eq!(
        fx.on_frame(22, query(1, 9_002, 1, 80)),
        SideOutcome::Dropped(SideDrop::QueryRate)
    );
    for _ in 0..62 {
        fx.advance_ms(1);
        flood(&fx, &flooders, &mut token);
    }
    assert_eq!(
        fx.on_frame(22, query(1, 9_003, 1, 80)),
        SideOutcome::Dropped(SideDrop::QueryRate)
    );
    fx.advance_ms(1);
    flood(&fx, &flooders, &mut token);
    assert_eq!(
        fx.on_frame(22, query(1, 9_004, 1, 80)),
        SideOutcome::Queried
    );

    // Installing a sink that is there refreshes it and gives it nothing.
    fx.route(1, 10, &[22]);
    flood(&fx, &flooders, &mut token);
    assert_eq!(
        fx.on_frame(22, query(1, 9_005, 1, 80)),
        SideOutcome::Dropped(SideDrop::QueryRate)
    );

    // A sink that left and joined again is a new one: its share is whole, but only one.
    fx.table.remove_face(FaceId(22));
    let _ = fx.app(22);
    fx.route(1, 10, &[22]);
    flood(&fx, &flooders, &mut token);
    assert_eq!(
        fx.on_frame(22, query(1, 9_006, 1, 80)),
        SideOutcome::Queried
    );
    assert_eq!(
        fx.on_frame(22, query(1, 9_007, 1, 80)),
        SideOutcome::Dropped(SideDrop::QueryRate)
    );
}

#[test]
fn a_query_going_up_is_charged_to_the_source_faces_rate() {
    let fx = Fx::new();
    let src = fx.app(10);
    let _a = fx.app(20);
    fx.route(1, 10, &[20]);
    fx.table
        .set_rate(FaceId(10), Some(SideRate { bytes_per_sec: 100 }));
    // The bucket holds a second's octets: two frames of 80 take it under, the third finds it empty.
    assert_eq!(fx.on_frame(20, query(1, 1, 10, 80)), SideOutcome::Queried);
    assert_eq!(fx.on_frame(20, query(1, 2, 10, 80)), SideOutcome::Queried);
    assert_eq!(
        fx.on_frame(20, query(1, 3, 10, 80)),
        SideOutcome::Dropped(SideDrop::Quota)
    );
    let s = fx.stats();
    assert_eq!(
        (s.quota, s.breadcrumbs, src.side().len()),
        (1, 2, 2),
        "the refused query left no breadcrumb and reached nobody"
    );
}

#[test]
fn a_duplicate_token_is_dropped() {
    let fx = Fx::new();
    let src = fx.app(10);
    let a = fx.app(20);
    let b = fx.app(21);
    fx.route(1, 10, &[20, 21]);
    assert_eq!(fx.on_frame(20, query(1, 0xA, 10, 80)), SideOutcome::Queried);
    assert_eq!(
        fx.on_frame(20, query(1, 0xA, 10, 80)),
        SideOutcome::Dropped(SideDrop::PitDup)
    );
    // Another face cannot take over a token that is in flight.
    assert_eq!(
        fx.on_frame(21, query(1, 0xA, 10, 80)),
        SideOutcome::Dropped(SideDrop::PitDup)
    );
    assert_eq!(src.side().len(), 1, "only the first reached the source");
    assert_eq!(fx.stats().pit_dup, 2);

    fx.on_frame(10, answer(SideClass::Datagram, 1, 0xA, 60));
    assert_eq!(a.side().len(), 1, "the answer went to the first asker");
    assert!(b.side().is_empty());
}

#[test]
fn a_query_the_source_could_not_take_removes_its_breadcrumb() {
    let fx = Fx::new();
    let src = fx.app(10);
    let _a = fx.app(20);
    fx.route(1, 10, &[20]);
    src.log.full.store(true, Ordering::Relaxed);
    assert_eq!(
        fx.on_frame(20, query(1, 0xA, 10, 80)),
        SideOutcome::Dropped(SideDrop::SinkFull)
    );
    let s = fx.stats();
    assert_eq!((s.sink_full, s.breadcrumbs, s.queries), (1, 0, 0));

    // The token is free again: the asker may try it once more.
    src.log.full.store(false, Ordering::Relaxed);
    assert_eq!(fx.on_frame(20, query(1, 0xA, 10, 80)), SideOutcome::Queried);
}

#[test]
fn a_face_that_goes_down_takes_its_breadcrumbs() {
    let fx = Fx::limits(SideLimits {
        pit_per_face: 1,
        ..roomy()
    });
    let _src = fx.app(10);
    let _a = fx.app(20);
    let b = fx.app(21);
    fx.route(1, 10, &[20, 21]);
    fx.on_frame(20, query(1, 0xA, 10, 80));
    fx.on_frame(21, query(1, 0xB, 10, 80));

    fx.table.remove_face(FaceId(20));
    assert_eq!(fx.stats().breadcrumbs, 1);
    assert_eq!(
        fx.on_frame(10, answer(SideClass::Datagram, 1, 0xA, 60)),
        SideOutcome::Dropped(SideDrop::Unmatched)
    );
    assert_eq!(
        fx.on_frame(10, answer(SideClass::Datagram, 1, 0xB, 60)),
        SideOutcome::Answered
    );
    assert_eq!(b.side().len(), 1);

    // A face that comes back under the same id starts with none held (its count was freed).
    let _a = fx.app(20);
    fx.route(1, 10, &[20]);
    assert_eq!(fx.on_frame(20, query(1, 0xC, 10, 80)), SideOutcome::Queried);

    // The source going takes the route and every breadcrumb on it.
    fx.on_frame(21, query(1, 0xD, 10, 80));
    assert_eq!(fx.stats().breadcrumbs, 2);
    fx.table.remove_face(FaceId(10));
    assert_eq!(fx.stats().breadcrumbs, 0);
}

#[test]
fn the_sweep_drops_the_breadcrumbs_of_faces_that_left_the_face_table() {
    let fx = Fx::new();
    let _src = fx.app(10);
    let _a = fx.app(20);
    fx.route(1, 10, &[20]);
    assert_eq!(fx.on_frame(20, query(1, 0xA, 10, 80)), SideOutcome::Queried);
    assert_eq!(fx.stats().breadcrumbs, 1);
    fx.faces.remove(FaceId(20));
    fx.table.drop_gone_faces(&fx.faces);
    assert_eq!(fx.stats().breadcrumbs, 0);
}

#[test]
fn a_barred_source_cannot_answer_and_a_barred_sink_can_still_ask() {
    let fx = Fx::new();
    let src = fx.app(10);
    let a = fx.app(20);
    fx.route(1, 10, &[20]);

    // A bar on a sink does not stop its query (it is its own request, as an `UP` is).
    fx.table
        .quarantine_for(FaceId(20), fx.now(), Duration::from_secs(60));
    assert_eq!(fx.on_frame(20, query(1, 0xA, 10, 80)), SideOutcome::Queried);
    assert_eq!(src.side().len(), 1);

    // A bar on the source drops what it sends, an answer too, and keeps the breadcrumb.
    fx.table
        .quarantine_for(FaceId(10), fx.now(), Duration::from_secs(60));
    assert_eq!(
        fx.on_frame(10, answer(SideClass::Datagram, 1, 0xA, 60)),
        SideOutcome::Dropped(SideDrop::Quarantined)
    );
    assert!(a.side().is_empty());
    let s = fx.stats();
    assert_eq!((s.quarantined, s.breadcrumbs), (1, 1));

    fx.table.lift(FaceId(10));
    assert_eq!(
        fx.on_frame(10, answer(SideClass::Datagram, 1, 0xA, 60)),
        SideOutcome::Answered
    );
}

#[test]
fn two_askers_behind_one_relay_get_their_own_answers_and_the_other_sees_nothing() {
    // Server app s (1) -- T1 -- link 2 | 3 -- T2 -- askers a (5) and b (6).
    let t1 = Fx::new();
    let t2 = Fx::new();
    let server = t1.app(1);
    let l1 = t1.app(2);
    let l2 = t2.app(3);
    let a = t2.app(5);
    let b = t2.app(6);
    t1.route(9, 1, &[2]);
    t2.route(9, 3, &[5, 6]);

    // Each asker asks; each hop forwards the query one hop up.
    t2.on_frame(5, query(9, 0xAAAA, 10, 100));
    t2.on_frame(6, query(9, 0xBBBB, 10, 100));
    assert_eq!(l2.side().len(), 2);
    for r in l2.side() {
        t1.on_frame(2, r.frame);
    }
    assert_eq!(server.side().len(), 2);
    assert!(
        server.side().iter().all(|r| r.ingress == Some(FaceId(2))),
        "the server's hop saw the relay's link as the ingress of both"
    );
    assert!(a.side().is_empty() && b.side().is_empty() && l1.side().is_empty());

    // The server answers b first. Only b's face gets it, at both hops.
    t1.on_frame(1, answer(SideClass::Datagram, 9, 0xBBBB, 70));
    assert_eq!(l1.side().len(), 1, "one frame down the link");
    t2.on_frame(3, l1.side()[0].frame.clone());
    assert_eq!(b.side().len(), 1);
    assert!(a.side().is_empty(), "the other asker sees nothing");

    t1.on_frame(1, answer(SideClass::Datagram, 9, 0xAAAA, 71));
    t2.on_frame(3, l1.side()[1].frame.clone());
    assert_eq!(a.side().len(), 1);
    assert_eq!(b.side().len(), 1, "and b still has only its own");
    assert_eq!(a.side()[0].frame.len(), 71);
    assert_eq!(b.side()[0].frame.len(), 70);
    assert_eq!((t1.stats().breadcrumbs, t2.stats().breadcrumbs), (0, 0));
}

#[test]
fn query_rate_per_face_holds() {
    let fx = Fx::limits(SideLimits {
        query_rate: 10,
        query_burst: 3,
        ..roomy()
    });
    let src = fx.app(10);
    let _a = fx.app(20);
    let _b = fx.app(21);
    fx.route(1, 10, &[20, 21]);

    // A burst of 3, then refused.
    for t in 1..=3u64 {
        assert_eq!(fx.on_frame(20, query(1, t, 10, 80)), SideOutcome::Queried);
    }
    assert_eq!(
        fx.on_frame(20, query(1, 4, 10, 80)),
        SideOutcome::Dropped(SideDrop::QueryRate)
    );
    let s = fx.stats();
    assert_eq!((s.query_rate_refused, s.breadcrumbs), (1, 3));
    assert_eq!(
        src.side().len(),
        3,
        "the refused query did not reach the source"
    );

    // It is the face's: another face is not held back by it.
    assert_eq!(fx.on_frame(21, query(1, 5, 10, 80)), SideOutcome::Queried);

    // And it refills at the rate: one query per 100 ms.
    fx.advance_ms(99);
    assert_eq!(
        fx.on_frame(20, query(1, 4, 10, 80)),
        SideOutcome::Dropped(SideDrop::QueryRate)
    );
    fx.advance_ms(1);
    assert_eq!(fx.on_frame(20, query(1, 4, 10, 80)), SideOutcome::Queried);
    assert_eq!(
        fx.on_frame(20, query(1, 6, 10, 80)),
        SideOutcome::Dropped(SideDrop::QueryRate)
    );
    assert_eq!(fx.stats().query_rate_refused, 3);
}

#[test]
fn a_query_or_an_answer_shorter_than_its_prefix_is_malformed() {
    let fx = Fx::new();
    let _src = fx.app(10);
    let _a = fx.app(20);
    fx.route(1, 10, &[20]);
    let q = query(1, 0xA, 10, 80);
    let a = answer(SideClass::Datagram, 1, 0xA, 80);
    assert_eq!(
        fx.on_frame(20, q.slice(..18)),
        SideOutcome::Dropped(SideDrop::Malformed)
    );
    assert_eq!(
        fx.on_frame(10, a.slice(..17)),
        SideOutcome::Dropped(SideDrop::Malformed)
    );
    // The shortest each may be passes.
    assert_eq!(fx.on_frame(20, q.slice(..19)), SideOutcome::Queried);
    assert_eq!(fx.on_frame(10, a.slice(..18)), SideOutcome::Answered);
    assert_eq!(fx.stats().malformed, 2);
}

#[test]
fn a_data_frame_is_untouched_by_the_breadcrumbs() {
    // The data path of `DATA` frames does not look at the breadcrumb table: a sink may not
    // send one up, and the source's reaches every sink.
    let fx = Fx::new();
    let _src = fx.app(10);
    let a = fx.app(20);
    let b = fx.app(21);
    fx.route(1, 10, &[20, 21]);
    fx.on_frame(20, query(1, 0xA, 10, 80));
    assert!(matches!(
        fx.on_frame(10, data_frame(1, 64)),
        SideOutcome::Routed {
            sinks: 2,
            delivered: 2,
            ..
        }
    ));
    assert_eq!((a.side().len(), b.side().len()), (1, 1));
    assert_eq!(fx.stats().breadcrumbs, 1);
}
