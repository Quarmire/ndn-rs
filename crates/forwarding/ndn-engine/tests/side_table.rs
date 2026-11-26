//! `SideTable`: the forwarder's generic fan-out table for side (channel)
//! frames. Table-level invariants with a logical clock: the bounds of §8.1,
//! the source check, the keep/unsub/expiry rules, the quarantine and the
//! per-face rate, and the fan-out that never blocks and never copies.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use ndn_engine::side::{
    SideConfig, SideDrop, SideId, SideLimits, SideOutcome, SideRate, SideRefusal, SideTable,
};
use ndn_transport::side_header::{SideKind, UpOp};
use ndn_transport::{FaceId, FaceKind, FaceTable, SideClass};

use crate::side_support::{Handle, data_frame, face, frame, up};

const T0: u64 = 1_000_000_000_000;
const SEC: u64 = 1_000_000_000;

struct Fx {
    faces: Arc<FaceTable>,
    table: SideTable,
    clock: Arc<AtomicU64>,
}

impl Fx {
    fn new() -> Self {
        Self::with(SideConfig::default())
    }

    fn with(config: SideConfig) -> Self {
        let clock = Arc::new(AtomicU64::new(T0));
        let c = Arc::clone(&clock);
        Self {
            faces: Arc::new(FaceTable::new()),
            table: SideTable::with_clock(config, Arc::new(move || c.load(Ordering::Relaxed))),
            clock,
        }
    }

    fn limits(limits: SideLimits) -> Self {
        Self::with(SideConfig {
            limits,
            ..SideConfig::default()
        })
    }

    /// A face of `kind`, in the face table and configured as the engine
    /// configures a face it adds.
    fn face(&self, id: u64, kind: FaceKind) -> Handle {
        let (f, h) = face(id, kind);
        self.faces.insert(f);
        self.table.configure_face(FaceId(id), kind);
        h
    }

    fn app(&self, id: u64) -> Handle {
        self.face(id, FaceKind::App)
    }

    fn advance(&self, secs: u64) {
        self.clock.fetch_add(secs * SEC, Ordering::Relaxed);
    }

    fn now(&self) -> u64 {
        self.clock.load(Ordering::Relaxed)
    }

    fn install(&self, id: u64, source: u64, sink: u64) -> Result<(), SideRefusal> {
        self.table.install(
            SideId(id),
            FaceId(source),
            FaceId(sink),
            Duration::from_secs(30),
        )
    }

    fn on_frame(&self, from: u64, frame: Bytes) -> SideOutcome {
        self.table.on_frame(FaceId(from), frame, &self.faces)
    }
}

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

#[test]
fn table_full_refuses_a_new_route_beyond_the_table_limit() {
    let fx = Fx::limits(SideLimits {
        routes: 2,
        ..SideLimits::default()
    });
    fx.install(1, 10, 20).unwrap();
    fx.install(2, 11, 21).unwrap();
    assert_eq!(fx.install(3, 12, 22), Err(SideRefusal::TableFull));
    // A full table still takes another receiver on a route it holds.
    fx.install(1, 10, 23).unwrap();
    assert_eq!(fx.table.stats().refused_table_full, 1);
    assert_eq!(fx.table.stats().routes, 2);
}

#[test]
fn source_full_refuses_a_route_beyond_what_one_upstream_face_may_feed() {
    let fx = Fx::limits(SideLimits {
        per_source_face: 2,
        ..SideLimits::default()
    });
    fx.install(1, 10, 20).unwrap();
    fx.install(2, 10, 21).unwrap();
    assert_eq!(fx.install(3, 10, 22), Err(SideRefusal::SourceFull));
    // Another source is not affected.
    fx.install(3, 11, 22).unwrap();
    assert_eq!(fx.table.stats().refused_source_full, 1);
}

#[test]
fn sink_cap_refuses_a_receiver_beyond_what_one_route_may_fan_out_to() {
    let fx = Fx::limits(SideLimits {
        sinks_per_route: 2,
        ..SideLimits::default()
    });
    fx.install(1, 10, 20).unwrap();
    fx.install(1, 10, 21).unwrap();
    assert_eq!(fx.install(1, 10, 22), Err(SideRefusal::SinkCap));
    // An existing receiver refreshes without counting against the cap.
    fx.install(1, 10, 21).unwrap();
    assert_eq!(fx.table.sinks(SideId(1)), 2);
    assert_eq!(fx.table.stats().refused_sink_cap, 1);
}

#[test]
fn sink_face_full_refuses_a_route_to_a_face_that_holds_its_limit() {
    let fx = Fx::limits(SideLimits {
        per_sink_face: 2,
        ..SideLimits::default()
    });
    fx.install(1, 10, 20).unwrap();
    fx.install(2, 11, 20).unwrap();
    assert_eq!(fx.install(3, 12, 20), Err(SideRefusal::SinkFaceFull));
    // The refused route was not left behind half-made.
    assert_eq!(fx.table.sinks(SideId(3)), 0);
    assert_eq!(fx.table.stats().routes, 2);
    assert_eq!(
        fx.table.routes_to(FaceId(12)),
        0,
        "no count for the refused source"
    );
    assert_eq!(fx.table.stats().refused_sink_face_full, 1);
}

#[test]
fn source_mismatch_refuses_a_second_source_for_one_id() {
    let fx = Fx::new();
    fx.install(1, 10, 20).unwrap();
    assert_eq!(fx.install(1, 11, 21), Err(SideRefusal::SourceMismatch));
    assert_eq!(
        fx.table.sinks(SideId(1)),
        1,
        "the second face did not become a sink"
    );
    assert_eq!(fx.table.stats().refused_source_mismatch, 1);
}

#[test]
fn sink_is_source_refuses_a_route_that_loops_back() {
    let fx = Fx::new();
    assert_eq!(fx.install(1, 10, 10), Err(SideRefusal::SinkIsSource));
    assert_eq!(fx.table.stats().routes, 0);
    assert_eq!(fx.table.stats().refused_sink_is_source, 1);
}

#[test]
fn a_quarantined_source_installs_nothing() {
    let fx = Fx::new();
    fx.table.quarantine(FaceId(10), fx.now() + 60 * SEC);
    assert_eq!(fx.install(1, 10, 20), Err(SideRefusal::Quarantined));
    assert_eq!(fx.table.stats().routes, 0);
    fx.advance(61);
    fx.install(1, 10, 20).unwrap();
}

#[test]
fn a_ttl_is_clamped_to_the_maximum_and_zero_means_the_default() {
    let fx = Fx::new();
    fx.install(1, 10, 20).unwrap();
    fx.table
        .install(SideId(2), FaceId(10), FaceId(21), secs(100_000))
        .unwrap();
    fx.table
        .install(SideId(3), FaceId(10), FaceId(22), Duration::ZERO)
        .unwrap();
    let ttl = |id: u64| {
        fx.table
            .list()
            .into_iter()
            .find(|r| r.id == id)
            .unwrap()
            .sinks[0]
            .expires_in
    };
    assert_eq!(ttl(2), secs(300), "clamped to ttl_max");
    assert_eq!(ttl(3), secs(30), "zero is ttl_default");
}

#[test]
fn frames_from_a_face_that_is_not_the_source_are_dropped_and_counted() {
    let fx = Fx::new();
    let _src = fx.app(10);
    let sink = fx.app(20);
    let other = fx.app(30);
    fx.install(1, 10, 20).unwrap();

    // From a face that is neither source nor sink, from the sink itself, and
    // from the source: only the last is routed.
    for from in [30, 20] {
        assert_eq!(
            fx.on_frame(from, data_frame(1, 64)),
            SideOutcome::Dropped(SideDrop::WrongSource)
        );
    }
    assert_eq!(
        fx.on_frame(10, data_frame(1, 64)),
        SideOutcome::Routed {
            sinks: 1,
            delivered: 1,
            dropped: 0
        }
    );
    assert_eq!(sink.side().len(), 1);
    assert!(other.side().is_empty());
    let s = fx.table.stats();
    assert_eq!((s.wrong_source, s.frames_in, s.frames_out), (2, 3, 1));
    assert_eq!(s.bytes_out, 64);
}

#[test]
fn a_frame_with_no_route_or_no_valid_header_is_dropped_and_counted() {
    let fx = Fx::new();
    let _a = fx.app(10);
    assert_eq!(
        fx.on_frame(10, data_frame(7, 64)),
        SideOutcome::Dropped(SideDrop::Unrouted)
    );
    // Too short for a header, an unassigned kind, an UP with a non-zero tail.
    assert_eq!(
        fx.on_frame(10, Bytes::from_static(&[0, 0x20, 1, 2])),
        SideOutcome::Dropped(SideDrop::Malformed)
    );
    let mut bad = data_frame(7, 64).to_vec();
    bad[1] = 0x23;
    assert_eq!(
        fx.on_frame(10, Bytes::from(bad)),
        SideOutcome::Dropped(SideDrop::Malformed)
    );
    let mut up_bad = up(7, UpOp::Keep).to_vec();
    up_bad[40] = 1;
    assert_eq!(
        fx.on_frame(10, Bytes::from(up_bad)),
        SideOutcome::Dropped(SideDrop::Malformed)
    );
    let s = fx.table.stats();
    assert_eq!((s.unrouted, s.malformed, s.frames_in), (1, 3, 4));
}

#[test]
fn a_frame_is_handed_to_each_sink_with_its_class_and_ingress_and_is_not_copied() {
    let fx = Fx::new();
    let _src = fx.app(10);
    let sinks = [fx.app(20), fx.app(21), fx.app(22)];
    for s in [20, 21, 22] {
        fx.install(1, 10, s).unwrap();
    }
    let stream = frame(SideClass::Stream, SideKind::Control, 1, 200);
    let out = fx.on_frame(10, stream.clone());
    assert_eq!(
        out,
        SideOutcome::Routed {
            sinks: 3,
            delivered: 3,
            dropped: 0
        }
    );
    for h in &sinks {
        let rec = h.side();
        assert_eq!(rec.len(), 1);
        assert_eq!(rec[0].class, SideClass::Stream);
        assert_eq!(rec[0].ingress, Some(FaceId(10)));
        assert_eq!(
            rec[0].frame.as_ptr(),
            stream.as_ptr(),
            "a reference-counted clone, not a copy"
        );
    }
}

#[test]
fn two_receivers_behind_one_relay_cost_the_senders_link_one_frame() {
    // Sender app a1 -- T1 -- link l1|l2 -- T2 -- receivers r2a, r2b.
    let t1 = Fx::new();
    let t2 = Fx::new();
    let a1 = t1.app(1);
    let l1 = t1.face(2, FaceKind::Udp);
    let l2 = t2.face(3, FaceKind::Udp);
    let r2a = t2.app(4);
    let r2b = t2.app(5);
    t1.install(9, 1, 2).unwrap();
    t2.install(9, 3, 4).unwrap();
    t2.install(9, 3, 5).unwrap();

    t1.on_frame(1, data_frame(9, 100));
    assert_eq!(l1.side().len(), 1, "the sender's link carries one frame");
    // The link delivers that one frame to the relay's face.
    t2.on_frame(3, l1.side()[0].frame.clone());
    assert_eq!(r2a.side().len(), 1);
    assert_eq!(r2b.side().len(), 1);
    assert!(a1.side().is_empty());
    assert!(l2.side().is_empty(), "nothing goes back toward the sender");
    assert_eq!(l1.side().len(), 1, "still one");
}

#[test]
fn a_congested_sink_drops_and_the_receiver_sees_the_gap() {
    let fx = Fx::new();
    let _src = fx.app(10);
    let slow = fx.app(20);
    let fast = fx.app(21);
    fx.install(1, 10, 20).unwrap();
    fx.install(1, 10, 21).unwrap();
    slow.log.full.store(true, Ordering::Relaxed);

    // The call returns (it never waits) and the other sink has the frame.
    let out = fx.on_frame(10, data_frame(1, 64));
    assert_eq!(
        out,
        SideOutcome::Routed {
            sinks: 2,
            delivered: 1,
            dropped: 1
        }
    );
    assert!(slow.side().is_empty());
    assert_eq!(fast.side().len(), 1);
    let s = fx.table.stats();
    assert_eq!((s.sink_full, s.frames_out), (1, 1));

    // Room again: the next frame reaches both, the loss stays counted.
    slow.log.full.store(false, Ordering::Relaxed);
    fx.on_frame(10, data_frame(1, 64));
    assert_eq!(slow.side().len(), 1);
    assert_eq!(fx.table.stats().sink_full, 1);
}

#[test]
fn a_sink_that_does_not_carry_the_class_counts_class_unsupported() {
    let fx = Fx::new();
    let _src = fx.app(10);
    let l2 = fx.face(20, FaceKind::Ethernet);
    fx.install(1, 10, 20).unwrap();
    l2.log.unsupported.store(true, Ordering::Relaxed);
    fx.on_frame(10, frame(SideClass::Stream, SideKind::Data, 1, 64));
    assert_eq!(fx.table.stats().class_unsupported, 1);
    assert_eq!(fx.table.stats().sink_full, 0);
}

#[test]
fn a_sink_lapses_after_its_ttl_and_keep_refreshes_it_through_each_hop_once_per_5_s() {
    // Sender app a1 -- T1 -- l1 | l2 -- T2 -- receiver app r2.
    let t1 = Fx::new();
    let t2 = Fx::new();
    let a1 = t1.app(1);
    let _l1 = t1.face(2, FaceKind::Udp);
    let l2 = t2.face(3, FaceKind::Udp);
    let r2 = t2.app(4);
    t1.install(9, 1, 2).unwrap(); // the Data's reverse path, 30 s
    t2.install(9, 3, 4).unwrap();

    // r2's heap sends a Keep; T2 refreshes r2 and forwards one upstream,
    // which T1 receives on l1, refreshes, and passes to a1.
    let keep_through = |at: u64| {
        let (t1_now, t2_now) = (t1.now(), t2.now());
        assert_eq!((t1_now, t2_now), (at, at), "clocks agree");
        let before_l2 = l2.side().len();
        let before_a1 = a1.side().len();
        t2.on_frame(4, up(9, UpOp::Keep));
        let forwarded_t2 = l2.side().len() - before_l2;
        if forwarded_t2 == 1 {
            t1.on_frame(2, l2.side().last().unwrap().frame.clone());
        }
        (forwarded_t2, a1.side().len() - before_a1)
    };

    let both = |s: u64| {
        t1.advance(s);
        t2.advance(s);
    };
    both(10);
    // The first Keep of a route is forwarded at once, at every hop.
    assert_eq!(keep_through(T0 + 10 * SEC), (1, 1));
    assert_eq!(l2.side().last().unwrap().ingress, Some(FaceId(4)));
    assert_eq!(a1.side().last().unwrap().ingress, Some(FaceId(2)));
    // Keeps 2 s and 4 s after the forwarded one refresh r2 but are not passed
    // on.
    both(2);
    assert_eq!(keep_through(T0 + 12 * SEC), (0, 0));
    both(2);
    assert_eq!(keep_through(T0 + 14 * SEC), (0, 0));
    // 5 s after the forwarded one, the next Keep is forwarded again.
    both(1);
    assert_eq!(keep_through(T0 + 15 * SEC), (1, 1));
    assert_eq!(l2.side().len(), 2);
    assert_eq!(a1.side().len(), 2);

    // The last refresh at t0+15 holds the sinks for 30 s from it: at +44
    // still there, at +46 gone at both hops; no Keep arrived.
    t1.advance(29);
    t2.advance(29);
    t1.table.sweep(t1.now());
    t2.table.sweep(t2.now());
    assert_eq!(
        (t1.table.sinks(SideId(9)), t2.table.sinks(SideId(9))),
        (1, 1)
    );
    t1.advance(2);
    t2.advance(2);
    t1.table.sweep(t1.now());
    t2.table.sweep(t2.now());
    assert_eq!(
        (t1.table.sinks(SideId(9)), t2.table.sinks(SideId(9))),
        (0, 0)
    );
    assert_eq!(
        t1.table.stats().routes + t2.table.stats().routes,
        0,
        "empty routes go too"
    );
    assert_eq!(t2.table.stats().sinks_lapsed, 1);
    assert!(r2.side().is_empty());

    // Frames now meet no route.
    assert_eq!(
        t1.on_frame(1, data_frame(9, 64)),
        SideOutcome::Dropped(SideDrop::Unrouted)
    );
}

#[test]
fn a_keep_from_a_face_that_is_not_a_sink_changes_nothing() {
    let fx = Fx::new();
    let src = fx.app(10);
    let _sink = fx.app(20);
    let _other = fx.app(30);
    fx.install(1, 10, 20).unwrap();
    fx.advance(25);
    // Another face, and the source itself, cannot refresh the sink.
    for from in [30, 10] {
        assert_eq!(
            fx.on_frame(from, up(1, UpOp::Keep)),
            SideOutcome::Dropped(SideDrop::WrongSource)
        );
    }
    fx.advance(10);
    fx.table.sweep(fx.now());
    assert_eq!(fx.table.sinks(SideId(1)), 0, "the sink lapsed at 30 s");
    assert!(src.side().is_empty(), "no Keep was forwarded");
}

#[test]
fn unsub_removes_only_the_senders_sink_and_the_route_when_empty() {
    let fx = Fx::new();
    let src = fx.app(10);
    let _a = fx.app(20);
    let _b = fx.app(21);
    let _stranger = fx.app(30);
    fx.install(1, 10, 20).unwrap();
    fx.install(1, 10, 21).unwrap();
    fx.install(2, 10, 20).unwrap(); // another route the same face sinks

    // A face that is not a sink cannot remove anything.
    assert_eq!(
        fx.on_frame(30, up(1, UpOp::Unsub)),
        SideOutcome::Dropped(SideDrop::WrongSource)
    );
    assert_eq!(fx.table.sinks(SideId(1)), 2);

    // The first receiver leaves: only its sink goes, nothing goes upstream
    // (the relay still has a receiver on the route).
    assert_eq!(
        fx.on_frame(20, up(1, UpOp::Unsub)),
        SideOutcome::Unsubscribed {
            route_removed: false,
            forwarded: false
        }
    );
    assert_eq!(fx.table.sinks(SideId(1)), 1);
    assert_eq!(
        fx.table.sinks(SideId(2)),
        1,
        "its sink on another route stays"
    );
    assert!(src.side().is_empty());

    // The last one leaves: the route goes and the Unsub is forwarded upstream.
    assert_eq!(
        fx.on_frame(21, up(1, UpOp::Unsub)),
        SideOutcome::Unsubscribed {
            route_removed: true,
            forwarded: true
        }
    );
    assert_eq!(fx.table.sinks(SideId(1)), 0);
    assert_eq!(fx.table.stats().routes, 1, "route 2 is untouched");
    let up_seen = src.side();
    assert_eq!(up_seen.len(), 1);
    assert_eq!(up_seen[0].ingress, Some(FaceId(21)));
    assert_eq!(&up_seen[0].frame[..], &up(1, UpOp::Unsub)[..]);
    // The id is free for a new route from any source.
    fx.install(1, 11, 22).unwrap();
}

#[test]
fn a_face_that_goes_down_takes_its_routes_with_it() {
    let fx = Fx::new();
    fx.install(1, 10, 20).unwrap();
    fx.install(1, 10, 21).unwrap();
    fx.install(2, 11, 20).unwrap();
    fx.install(3, 12, 22).unwrap();
    assert_eq!(fx.table.routes_to(FaceId(20)), 2);
    assert_eq!(fx.table.routes_to(FaceId(10)), 1);

    // A sink face: only its entries go; a route left without sinks goes.
    fx.table.remove_face(FaceId(20));
    assert_eq!(fx.table.sinks(SideId(1)), 1);
    assert_eq!(fx.table.sinks(SideId(2)), 0);
    assert_eq!(fx.table.stats().routes, 2);
    assert_eq!(fx.table.routes_to(FaceId(20)), 0);
    assert_eq!(
        fx.table.routes_to(FaceId(11)),
        0,
        "route 2's source count went with it"
    );

    // A source face: the whole route goes, and its sinks' counts with it.
    fx.table.remove_face(FaceId(10));
    assert_eq!(fx.table.sinks(SideId(1)), 0);
    assert_eq!(fx.table.routes_to(FaceId(21)), 0);
    assert_eq!(fx.table.stats().routes, 1);
    assert_eq!(fx.table.stats().sinks, 1);
}

#[test]
fn the_sweep_drops_the_routes_of_faces_that_left_the_face_table() {
    let fx = Fx::new();
    let _src = fx.app(10);
    let _a = fx.app(20);
    fx.install(1, 10, 20).unwrap();
    fx.install(2, 10, 99).unwrap(); // 99 was never a face
    fx.install(3, 98, 20).unwrap(); // nor 98
    fx.table.drop_gone_faces(&fx.faces);
    assert_eq!(fx.table.sinks(SideId(1)), 1, "live faces keep their route");
    assert_eq!(fx.table.sinks(SideId(2)), 0);
    assert_eq!(fx.table.sinks(SideId(3)), 0);
    assert_eq!(fx.table.stats().routes, 1);
}

#[test]
fn quarantine_doubles_on_repeat_and_resets_after_an_hour() {
    let fx = Fx::new();
    let _a = fx.app(10);
    let t = |s: u64| T0 + s * SEC;
    let bar = |s: u64| fx.table.bar(FaceId(10), t(s));

    assert_eq!(bar(0), secs(60));
    assert!(fx.table.is_quarantined(FaceId(10), t(59)));
    assert!(!fx.table.is_quarantined(FaceId(10), t(60)));
    // A repeat on the same face doubles the bar, whether or not the last has
    // ended: 120, 240, 480, 960, 1920, then 1 h and no more.
    assert_eq!(bar(61), secs(120));
    assert_eq!(bar(200), secs(240));
    assert_eq!(bar(500), secs(480));
    assert_eq!(bar(1_000), secs(960));
    assert_eq!(bar(2_000), secs(1_920));
    assert_eq!(bar(4_000), secs(3_600));
    assert_eq!(bar(8_000), secs(3_600), "capped at an hour");
    // The bar ends at 8_000 + 3_600; an hour clean after it, the count resets.
    assert_eq!(
        bar(8_000 + 3_600 + 3_599),
        secs(3_600),
        "not yet clean for an hour"
    );
    let last_end = 8_000 + 3_600 + 3_599 + 3_600;
    assert_eq!(
        bar(last_end + 3_600),
        secs(60),
        "an hour clean: back to 60 s"
    );
    // Another face's history is its own.
    assert_eq!(fx.table.bar(FaceId(11), t(0)), secs(60));
}

#[test]
fn a_barred_face_has_its_frames_and_keeps_dropped_and_ndn_traffic_is_not_the_tables() {
    let fx = Fx::new();
    let src = fx.app(10);
    let sink = fx.app(20);
    fx.install(1, 10, 20).unwrap();

    // The source is barred: its frames are dropped and counted, nothing is
    // delivered, the route stays.
    fx.table.bar(FaceId(10), fx.now());
    assert_eq!(
        fx.on_frame(10, data_frame(1, 64)),
        SideOutcome::Dropped(SideDrop::Quarantined)
    );
    assert!(sink.side().is_empty());
    assert_eq!(fx.table.stats().quarantined, 1);

    // A barred sink's Keeps are ignored: it lapses on schedule.
    fx.table.bar(FaceId(20), fx.now());
    fx.advance(20);
    assert_eq!(
        fx.on_frame(20, up(1, UpOp::Keep)),
        SideOutcome::Dropped(SideDrop::Quarantined)
    );
    fx.advance(11);
    fx.table.sweep(fx.now());
    assert_eq!(fx.table.sinks(SideId(1)), 0);
    assert!(src.side().is_empty());
    assert_eq!(fx.table.stats().quarantined, 2);
}

#[test]
fn an_explicit_quarantine_ends_at_the_time_given() {
    let fx = Fx::new();
    let _src = fx.app(10);
    let sink = fx.app(20);
    fx.install(1, 10, 20).unwrap();
    fx.table.quarantine(FaceId(10), fx.now() + 5 * SEC);
    fx.on_frame(10, data_frame(1, 64));
    fx.advance(5);
    fx.on_frame(10, data_frame(1, 64));
    assert_eq!(
        sink.side().len(),
        1,
        "only the frame after the bar got through"
    );
}

#[test]
fn the_side_rate_drops_over_rate_frames_and_a_radio_defaults_to_one_megabyte_a_second() {
    let fx = Fx::new();
    let _src = fx.app(10);
    let radio = fx.face(20, FaceKind::Wfb);
    let ether = fx.face(21, FaceKind::Ethernet);
    fx.install(1, 10, 20).unwrap();
    fx.install(1, 10, 21).unwrap();

    // 1 MB/s on the radio: a 1 MB burst passes, the next frame does not.
    for _ in 0..10 {
        fx.on_frame(10, data_frame(1, 100_000));
    }
    assert_eq!(radio.side().len(), 10);
    assert_eq!(ether.side().len(), 10, "Ethernet has no limit by default");
    fx.on_frame(10, data_frame(1, 100_000));
    assert_eq!(
        radio.side().len(),
        10,
        "the 11th within the second is over rate"
    );
    assert_eq!(ether.side().len(), 11);
    assert_eq!(fx.table.stats().quota, 1);
    assert_eq!(
        fx.table.stats().sink_full,
        0,
        "a quota drop is its own count"
    );

    // A tenth of a second refills 100 kB: one more frame.
    fx.clock.fetch_add(SEC / 10, Ordering::Relaxed);
    fx.on_frame(10, data_frame(1, 100_000));
    assert_eq!(radio.side().len(), 11);
    fx.on_frame(10, data_frame(1, 100_000));
    assert_eq!(radio.side().len(), 11);
    assert_eq!(fx.table.stats().quota, 2);

    // Configurable per face: a limit on the Ethernet face, none on the radio.
    fx.table.set_rate(
        FaceId(21),
        Some(SideRate {
            bytes_per_sec: 1_000,
        }),
    );
    fx.table.set_rate(FaceId(20), None);
    let before = ether.side().len();
    for _ in 0..3 {
        fx.on_frame(10, data_frame(1, 1_000));
    }
    assert_eq!(
        ether.side().len() - before,
        1,
        "1 kB burst, then the bucket is empty"
    );
    assert_eq!(radio.side().len(), 14);
}

#[test]
fn the_list_shows_each_route_with_its_source_sinks_and_counts() {
    let fx = Fx::new();
    let _src = fx.app(10);
    let _a = fx.app(20);
    let _b = fx.app(21);
    fx.install(7, 10, 20).unwrap();
    fx.install(7, 10, 21).unwrap();
    fx.install(5, 11, 20).unwrap();
    fx.on_frame(10, data_frame(7, 80));
    fx.on_frame(10, data_frame(7, 80));
    fx.advance(4);
    let list = fx.table.list();
    assert_eq!(
        list.iter().map(|r| r.id).collect::<Vec<_>>(),
        vec![5, 7],
        "ordered by id"
    );
    let r = &list[1];
    assert_eq!(r.source, FaceId(10));
    assert_eq!(
        r.sinks.iter().map(|s| s.face).collect::<Vec<_>>(),
        vec![FaceId(20), FaceId(21)]
    );
    assert_eq!((r.frames, r.bytes), (2, 160));
    assert_eq!(r.age, secs(4));
    assert_eq!(r.sinks[0].expires_in, secs(26));
}
