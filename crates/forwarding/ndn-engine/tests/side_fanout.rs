//! Side-frame fan-out through whole engines: the route a session Data's
//! `SideRoute` header installs at each hop of its reverse path, the frames that
//! follow it, `UP` keep-alives, and the cleanup when a face goes. Faces are
//! recording test transports; a hop chain is engines joined by paired faces.

use std::sync::atomic::Ordering;
use std::time::Duration;

use bytes::Bytes;
use ndn_engine::side::{SideConfig, SideId, SideLimits};
use ndn_engine::{EngineBuilder, EngineConfig, ForwarderEngine, ShutdownHandle};
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_packet::lp::{LpHeaders, LpPacket, SideRoute, encode_lp_with_headers, is_lp_packet};
use ndn_packet::{CachePolicyType, Data, Name};
use ndn_transport::side_header::UpOp;
use ndn_transport::{FaceId, FaceKind};
use tokio_util::sync::CancellationToken;

use crate::side_support::{
    Handle, TestFace, Warp, WarpRuntime, data_frame, datagram_only_face, face, no_side_face, pair,
    up,
};

const ID: u64 = 0x5E55_10C0_FFEE;

fn name() -> Name {
    "/chan/sess/1".parse().unwrap()
}

fn interest() -> Bytes {
    InterestBuilder::new(name())
        .lifetime(Duration::from_secs(4))
        .build()
}

fn data() -> Bytes {
    DataBuilder::new(name(), b"session").sign_digest_sha256()
}

/// The session Data as its sender answers: an LpPacket carrying the header.
fn labelled_data(id: u64, ttl_secs: u16) -> Bytes {
    encode_lp_with_headers(
        &data(),
        &LpHeaders {
            side_route: Some(SideRoute { id, ttl_secs }),
            ..LpHeaders::default()
        },
    )
}

async fn engine_with(
    config: EngineConfig,
    faces: Vec<TestFace>,
    route_to: u64,
) -> (ForwarderEngine, ShutdownHandle) {
    let mut b = EngineBuilder::new(config);
    for f in faces {
        b = b.face(f);
    }
    let (engine, shutdown) = b.build().await.expect("engine build");
    engine
        .fib()
        .add_nexthop(&"/chan".parse().unwrap(), FaceId(route_to), 0);
    (engine, shutdown)
}

/// An engine on `rt` with one app face, id 1, the sender's.
async fn engine_on(rt: std::sync::Arc<WarpRuntime>) -> (ForwarderEngine, ShutdownHandle) {
    let (s, _hs) = face(1, FaceKind::App);
    let (e, sd) = EngineBuilder::new(EngineConfig::default())
        .runtime(rt)
        .face(s)
        .build()
        .await
        .expect("engine build");
    e.fib().add_nexthop(&"/chan".parse().unwrap(), FaceId(1), 0);
    (e, sd)
}

async fn engine(faces: Vec<TestFace>, route_to: u64) -> (ForwarderEngine, ShutdownHandle) {
    engine_with(EngineConfig::default(), faces, route_to).await
}

/// Poll `cond` (every 5 ms, for 3 s).
async fn eventually(what: &str, mut cond: impl FnMut() -> bool) {
    for _ in 0..600 {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("never: {what}");
}

/// A receiver asks, the sender answers with `reply`; returns what the
/// receiver was sent.
async fn session(receiver: &Handle, sender: &Handle, reply: Bytes) -> Bytes {
    receiver.inject(interest());
    sender.wait_sent(1).await;
    sender.inject(reply);
    receiver.wait_sent(1).await.remove(0)
}

fn sinks_of(engine: &ForwarderEngine, id: u64) -> Vec<FaceId> {
    engine
        .side()
        .list()
        .into_iter()
        .find(|r| r.id == id)
        .map(|r| r.sinks.iter().map(|s| s.face).collect())
        .unwrap_or_default()
}

fn source_of(engine: &ForwarderEngine, id: u64) -> Option<FaceId> {
    engine
        .side()
        .list()
        .into_iter()
        .find(|r| r.id == id)
        .map(|r| r.source)
}

#[tokio::test]
async fn a_data_with_a_side_route_installs_a_route_at_each_hop_of_its_reverse_path() {
    // Sender app S -- E1 -- E2 -- E3 -- receiver app R.
    let (s, hs) = face(1, FaceKind::App);
    let ((l12, _h12), (l21, _h21)) = pair(2, 11, FaceKind::App);
    let ((l23, _h23), (l32, _h32)) = pair(12, 21, FaceKind::App);
    let (r, hr) = face(22, FaceKind::App);
    let (e1, _s1) = engine(vec![s, l12], 1).await;
    let (e2, _s2) = engine(vec![l21, l23], 11).await;
    let (e3, _s3) = engine(vec![l32, r], 21).await;

    let got = session(&hr, &hs, labelled_data(ID, 30)).await;

    // Each hop: the source is the face the Data came in on, the sink the face
    // that asked.
    assert_eq!(
        (source_of(&e1, ID), sinks_of(&e1, ID)),
        (Some(FaceId(1)), vec![FaceId(2)])
    );
    assert_eq!(
        (source_of(&e2, ID), sinks_of(&e2, ID)),
        (Some(FaceId(11)), vec![FaceId(12)])
    );
    assert_eq!(
        (source_of(&e3, ID), sinks_of(&e3, ID)),
        (Some(FaceId(21)), vec![FaceId(22)])
    );

    // The header went out again at every hop, so the next one did the same;
    // the receiver's face got it too, around the Data unchanged.
    assert!(is_lp_packet(&got));
    let lp = LpPacket::decode(got).unwrap();
    assert_eq!(
        lp.side_route,
        Some(SideRoute {
            id: ID,
            ttl_secs: 30
        })
    );
    let delivered = Data::decode(lp.fragment.unwrap()).unwrap();
    assert_eq!(*delivered.name, name());

    // A frame from the sender reaches the receiver byte for byte, with the
    // link it came over told to the receiver's face.
    let frame = data_frame(ID, 200);
    hs.inject(frame.clone());
    let seen = hr.wait_side(1).await;
    assert_eq!(seen[0].frame, frame);
    assert_eq!(seen[0].ingress, Some(FaceId(21)));
    assert_eq!(e1.side().stats().frames_out, 1);
    assert_eq!(e2.side().stats().frames_out, 1);
    assert_eq!(e3.side().stats().frames_out, 1);

    // The receiver's heap keeps the route alive: one Keep reaches the sender
    // through every hop.
    hr.inject(up(ID, UpOp::Keep));
    let keeps = hs.wait_side(1).await;
    assert_eq!(&keeps[0].frame[..], &up(ID, UpOp::Keep)[..]);
    assert_eq!(keeps[0].ingress, Some(FaceId(2)));
}

/// The session Data as its sender answers when it wants nothing of a setup cached:
/// `CachePolicy = NoCache` beside the header.
fn uncached_data(id: u64, ttl_secs: u16) -> Bytes {
    encode_lp_with_headers(
        &data(),
        &LpHeaders {
            side_route: Some(SideRoute { id, ttl_secs }),
            cache_policy: Some(CachePolicyType::NoCache),
            ..LpHeaders::default()
        },
    )
}

/// The names `engine`'s content store holds.
async fn cached_names(engine: &ForwarderEngine) -> Vec<Name> {
    engine
        .cs()
        .list_erased(&Name::root(), None, 64, 0)
        .await
        .entries
        .iter()
        .map(|e| (*e.name).clone())
        .collect()
}

#[tokio::test]
async fn a_nocache_data_is_cached_at_no_hop_of_its_path() {
    // Sender app S -- E1 -- E2 -- E3 -- receiver app R: the header that says "do not cache" is
    // hop by hop, so each forwarder passes it on, or the next one caches what the sender asked
    // to be kept nowhere.
    let (s, hs) = face(1, FaceKind::App);
    let ((l12, _h12), (l21, _h21)) = pair(2, 11, FaceKind::App);
    let ((l23, _h23), (l32, _h32)) = pair(12, 21, FaceKind::App);
    let (r, hr) = face(22, FaceKind::App);
    let (e1, _s1) = engine(vec![s, l12], 1).await;
    let (e2, _s2) = engine(vec![l21, l23], 11).await;
    let (e3, _s3) = engine(vec![l32, r], 21).await;

    let got = session(&hr, &hs, uncached_data(ID, 30)).await;

    let lp = LpPacket::decode(got).unwrap();
    assert_eq!(
        lp.cache_policy,
        Some(CachePolicyType::NoCache),
        "the receiver's face was given the Data without the NoCache the sender set"
    );
    for (hop, e) in [("E1", &e1), ("E2", &e2), ("E3", &e3)] {
        assert_eq!(
            cached_names(e).await,
            Vec::<Name>::new(),
            "{hop} cached a Data its sender marked NoCache"
        );
    }
}

#[tokio::test]
async fn a_data_that_is_not_nocache_is_cached_by_the_forwarders_past_the_first_hop() {
    // The control of the test above: without the header the same Data is kept, so an empty
    // store there says the header did it.
    let (s, hs) = face(1, FaceKind::App);
    let ((l12, _h12), (l21, _h21)) = pair(2, 11, FaceKind::App);
    let (r, hr) = face(22, FaceKind::App);
    let (e1, _s1) = engine(vec![s, l12], 1).await;
    let (e2, _s2) = engine(vec![l21, r], 11).await;

    session(&hr, &hs, labelled_data(ID, 30)).await;

    assert_eq!(cached_names(&e1).await, vec![name()], "E1 kept no copy");
    assert_eq!(cached_names(&e2).await, vec![name()], "E2 kept no copy");
}

#[tokio::test]
async fn a_data_that_matched_no_pit_entry_installs_nothing() {
    let (s, hs) = face(1, FaceKind::App);
    let (r, hr) = face(2, FaceKind::App);
    let (e, _sd) = engine(vec![s, r], 1).await;

    // No Interest was asked: the Data is unsolicited.
    hs.inject(labelled_data(ID, 30));
    eventually("the Data was processed", || {
        e.face_states()
            .get(&FaceId(1))
            .is_some_and(|s| s.counters.in_data.load(Ordering::Relaxed) == 1)
    })
    .await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(e.side().stats().routes, 0);
    assert!(sinks_of(&e, ID).is_empty());
    assert!(hr.sent().is_empty(), "nothing is forwarded either");

    // And a frame on that id meets no route.
    hs.inject(data_frame(ID, 64));
    eventually("the frame was counted", || e.side().stats().unrouted == 1).await;
    assert!(hr.side().is_empty());
}

#[tokio::test]
async fn a_forwarder_without_the_header_leaves_no_path() {
    // The Data is answered without the header (a forwarder on the path that
    // predates it strips it): nothing is installed from there on.
    let (s, hs) = face(1, FaceKind::App);
    let (r, hr) = face(2, FaceKind::App);
    let (e, _sd) = engine(vec![s, r], 1).await;

    let got = session(&hr, &hs, data()).await;
    assert!(!is_lp_packet(&got), "the Data is delivered as it was");
    assert_eq!(e.side().stats().routes, 0);

    hs.inject(data_frame(ID, 64));
    eventually("the frame was dropped unrouted", || {
        e.side().stats().unrouted == 1
    })
    .await;
    assert!(hr.side().is_empty(), "no path: the receiver gets no frame");
}

#[tokio::test]
async fn a_refused_install_still_delivers_the_data_without_the_header() {
    let (s, hs) = face(1, FaceKind::App);
    let (r, hr) = face(2, FaceKind::App);
    let config = EngineConfig {
        side: SideConfig {
            limits: SideLimits {
                routes: 0,
                ..SideLimits::default()
            },
            ..SideConfig::default()
        },
        ..EngineConfig::default()
    };
    let (e, _sd) = engine_with(config, vec![s, r], 1).await;

    let got = session(&hr, &hs, labelled_data(ID, 30)).await;
    assert!(
        !is_lp_packet(&got),
        "the refused face gets the Data without the header"
    );
    let delivered = Data::decode(got).unwrap();
    assert_eq!(*delivered.name, name());
    let stats = e.side().stats();
    assert_eq!((stats.routes, stats.refused_table_full), (0, 1));
}

#[tokio::test]
async fn a_header_on_a_data_from_a_quarantined_face_installs_nothing() {
    let (s, hs) = face(1, FaceKind::App);
    let (r, hr) = face(2, FaceKind::App);
    let (e, _sd) = engine(vec![s, r], 1).await;
    let barred = e.side().bar(FaceId(1), e.side().now());
    assert_eq!(barred, Duration::from_secs(60));

    // The Data still crosses the barred face and is delivered, without the
    // header; no route stands, and the refusal says why.
    let got = session(&hr, &hs, labelled_data(ID, 30)).await;
    assert!(!is_lp_packet(&got));
    let stats = e.side().stats();
    assert_eq!((stats.routes, stats.refused_quarantined), (0, 1));
}

#[tokio::test]
async fn a_quarantined_face_still_carries_ndn_traffic() {
    let (s, hs) = face(1, FaceKind::App);
    let (r, hr) = face(2, FaceKind::App);
    let (e, _sd) = engine(vec![s, r], 1).await;
    // A route stands from the face; then the face is barred.
    e.side()
        .install(SideId(ID), FaceId(1), FaceId(2), Duration::from_secs(30))
        .unwrap();
    e.side().bar(FaceId(1), e.side().now());

    // A marked frame from the barred face is dropped `quarantined`.
    hs.inject(data_frame(ID, 64));
    eventually("the frame was dropped quarantined", || {
        e.side().stats().quarantined == 1
    })
    .await;
    assert!(hr.side().is_empty());

    // NDN packets still cross it, in both directions: an Interest from the
    // receiver reaches the barred face's peer and the Data comes back.
    let got = session(&hr, &hs, data()).await;
    assert!(!is_lp_packet(&got));
    let delivered = Data::decode(got).unwrap();
    assert_eq!(*delivered.name, name());
    // And a second exchange over the same face.
    let second = InterestBuilder::new("/chan/sess/2".parse::<Name>().unwrap())
        .lifetime(Duration::from_secs(4))
        .build();
    hr.inject(second);
    hs.wait_sent(2).await;
}

#[tokio::test]
async fn a_congested_sink_does_not_stall_the_reader_and_the_others_still_get_the_frame() {
    let (s, hs) = face(1, FaceKind::App);
    let (slow, hslow) = face(2, FaceKind::App);
    let (fast, hfast) = face(3, FaceKind::App);
    let (e, _sd) = engine(vec![s, slow, fast], 1).await;
    e.side()
        .install(SideId(ID), FaceId(1), FaceId(2), Duration::from_secs(30))
        .unwrap();
    e.side()
        .install(SideId(ID), FaceId(1), FaceId(3), Duration::from_secs(30))
        .unwrap();
    hslow.log.full.store(true, Ordering::Relaxed);

    // Frames, then an NDN Interest on the same face: the reader is not stuck
    // behind the full sink.
    for _ in 0..50 {
        hs.inject(data_frame(ID, 64));
    }
    hs.inject(
        InterestBuilder::new("/chan/after".parse::<Name>().unwrap())
            .lifetime(Duration::from_secs(4))
            .build(),
    );
    hfast.wait_side(50).await;
    assert!(hslow.side().is_empty());
    let stats = e.side().stats();
    assert_eq!(
        stats.sink_full, 50,
        "every frame lost at the congested sink is counted"
    );
    assert_eq!(stats.frames_out, 50);
    eventually("the Interest after the frames was processed", || {
        e.face_states()
            .get(&FaceId(1))
            .is_some_and(|s| s.counters.in_interests.load(Ordering::Relaxed) == 1)
    })
    .await;
}

#[tokio::test]
async fn up_frames_through_the_reader_refresh_and_unsubscribe() {
    let (s, hs) = face(1, FaceKind::App);
    let (a, ha) = face(2, FaceKind::App);
    let (b, _hb) = face(3, FaceKind::App);
    let (e, _sd) = engine(vec![s, a, b], 1).await;
    for sink in [2, 3] {
        e.side()
            .install(SideId(ID), FaceId(1), FaceId(sink), Duration::from_secs(30))
            .unwrap();
    }
    // A stranger's Unsub changes nothing: the source cannot unsubscribe a sink.
    hs.inject(up(ID, UpOp::Unsub));
    eventually("counted wrong source", || {
        e.side().stats().wrong_source == 1
    })
    .await;
    assert_eq!(sinks_of(&e, ID).len(), 2);

    ha.inject(up(ID, UpOp::Unsub));
    eventually("a's sink removed", || sinks_of(&e, ID) == vec![FaceId(3)]).await;
    assert!(hs.side().is_empty(), "the relay still has a receiver");
}

#[tokio::test]
async fn a_face_that_goes_down_takes_its_routes_with_it_at_each_cleanup_site() {
    // The 1 s sweep that would also drop a face's routes never ends in these
    // runtimes (see `Warp`): what removes them is the site under test.
    let start = 1_000_000_000_000_000_000;

    // Site 1: ForwarderEngine::remove_face.
    {
        let (e, _sd) = engine_on(WarpRuntime::new(start, Warp::Frozen)).await;
        let (r, _hr) = face(2, FaceKind::App);
        e.add_face(r, CancellationToken::new());
        e.side()
            .install(SideId(ID), FaceId(1), FaceId(2), Duration::from_secs(30))
            .unwrap();
        e.remove_face(FaceId(2));
        assert_eq!(e.side().stats().routes, 0, "the sink face's route is gone");
    }

    // Site 2: the reader tail, when a face's connection closes. An on-demand
    // wire face, and an app face (whose routes go before its drain, not after).
    for kind in [FaceKind::Udp, FaceKind::App] {
        let (e, _sd) = engine_on(WarpRuntime::new(start, Warp::Frozen)).await;
        let (r, hr) = face(2, kind);
        e.add_face(r, CancellationToken::new());
        e.side()
            .install(SideId(ID), FaceId(1), FaceId(2), Duration::from_secs(30))
            .unwrap();
        e.side()
            .install(
                SideId(ID + 1),
                FaceId(2),
                FaceId(1),
                Duration::from_secs(30),
            )
            .unwrap();
        hr.close();
        eventually(
            &format!("{kind:?} face's routes went with its reader"),
            || e.side().stats().routes == 0,
        )
        .await;
    }

    // Site 3: the idle reaper (an on-demand connectionless face idle for
    // minutes). Its 30 s sleep is the only one the runtime shortens.
    {
        let rt = WarpRuntime::new(start, Warp::ReaperOnly);
        let (e, _sd) = engine_on(rt.clone()).await;
        let (r, _hr) = face(2, FaceKind::Udp);
        e.add_face(r, CancellationToken::new());
        e.side()
            .install(SideId(ID), FaceId(1), FaceId(2), Duration::from_secs(600))
            .unwrap();
        rt.advance(Duration::from_secs(6 * 60));
        eventually("the idle face was reaped", || {
            e.faces().get(FaceId(2)).is_none()
        })
        .await;
        assert_eq!(e.side().stats().routes, 0, "its route went with it");
    }
}

/// A connectionless on-demand face that carries only channel frames, in either
/// direction, is not idle: the reaper (which removes a face after 5 minutes
/// without traffic) leaves it and its routes alone; one that carries nothing
/// is still reaped.
#[tokio::test]
async fn a_face_that_carries_only_channel_frames_is_not_reaped() {
    let start = 1_000_000_000_000_000_000;
    let rt = WarpRuntime::new(start, Warp::ReaperOnly);
    let (e, _sd) = engine_on(rt.clone()).await; // sender app, face 1

    // Face 2 is a sink of a route fed by the app; face 3 is the source of a
    // route the app is a sink of. Both are Udp faces added on demand.
    let (sink, _hsink) = face(2, FaceKind::Udp);
    let (source, hsource) = face(3, FaceKind::Udp);
    e.add_face(sink, CancellationToken::new());
    e.add_face(source, CancellationToken::new());
    let (_app2, happ) = face(4, FaceKind::App);
    e.add_face(_app2, CancellationToken::new());
    e.side()
        .install(SideId(ID), FaceId(4), FaceId(2), Duration::from_secs(300))
        .unwrap();
    e.side()
        .install(
            SideId(ID + 1),
            FaceId(3),
            FaceId(1),
            Duration::from_secs(300),
        )
        .unwrap();

    // Eight minutes pass in two-minute steps; each step one frame goes out
    // to face 2 and one comes in from face 3. Neither face sees an NDN packet.
    for step in 1..=4 {
        rt.advance(Duration::from_secs(120));
        // A receiver's Keeps would hold the sinks (TTL is at most 300 s);
        // refresh them as a Data or a Keep does.
        for (id, src, sink) in [(ID, 4, 2), (ID + 1, 3, 1)] {
            e.side()
                .install(
                    SideId(id),
                    FaceId(src),
                    FaceId(sink),
                    Duration::from_secs(300),
                )
                .unwrap();
        }
        happ.inject(data_frame(ID, 64));
        hsource.inject(data_frame(ID + 1, 64));
        // Let the frames be routed and the reaper (30 ms real) run.
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            e.faces().get(FaceId(2)).is_some(),
            "the sink face was reaped at step {step}"
        );
        assert!(
            e.faces().get(FaceId(3)).is_some(),
            "the source face was reaped at step {step}"
        );
    }
    assert_eq!(e.side().stats().routes, 2);

    // Control: with no traffic at all the reaper does remove them.
    rt.advance(Duration::from_secs(6 * 60));
    eventually("idle faces are still reaped", || {
        e.faces().get(FaceId(2)).is_none() && e.faces().get(FaceId(3)).is_none()
    })
    .await;
}

#[tokio::test]
async fn the_engines_sweep_lapses_a_sink_on_the_engine_clock() {
    let rt = WarpRuntime::new(1_000_000_000_000_000_000, Warp::All);
    let (s, _hs) = face(1, FaceKind::App);
    let (r, _hr) = face(2, FaceKind::App);
    let (e, _sd) = EngineBuilder::new(EngineConfig::default())
        .runtime(rt.clone())
        .face(s)
        .face(r)
        .build()
        .await
        .expect("engine build");
    e.side()
        .install(SideId(ID), FaceId(1), FaceId(2), Duration::from_secs(30))
        .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        sinks_of(&e, ID).len(),
        1,
        "no time has passed on the engine clock"
    );
    rt.advance(Duration::from_secs(31));
    eventually("the sink lapsed", || e.side().stats().routes == 0).await;
    assert_eq!(e.side().stats().sinks_lapsed, 1);
}

#[tokio::test]
async fn a_side_rate_is_configurable_per_face_in_the_engine_config_and_defaults_by_kind() {
    let (s, hs) = face(1, FaceKind::App);
    let (radio, hradio) = face(2, FaceKind::Wfb);
    let (wire, hwire) = face(3, FaceKind::Ethernet);
    let config = EngineConfig {
        side: SideConfig {
            radio_rate: Some(ndn_engine::side::SideRate {
                bytes_per_sec: 100_000,
            }),
            ..SideConfig::default()
        },
        ..EngineConfig::default()
    };
    let (e, _sd) = engine_with(config, vec![s, radio, wire], 1).await;
    for sink in [2, 3] {
        e.side()
            .install(SideId(ID), FaceId(1), FaceId(sink), Duration::from_secs(30))
            .unwrap();
    }
    for _ in 0..4 {
        hs.inject(data_frame(ID, 60_000));
    }
    hwire.wait_side(4).await;
    eventually("the radio's quota drops were counted", || {
        e.side().stats().quota == 2
    })
    .await;
    assert_eq!(
        hradio.side().len(),
        2,
        "100 kB/s: two 60 kB frames of the burst"
    );
}

/// The forwarder tells what a face carries, as the face's medium says it (the engine learns
/// nothing of what a frame means): a face with a stream carries both classes, an Ethernet
/// segment's face the datagram class only, and a face the engine does not hold carries nothing.
#[tokio::test]
async fn the_engine_tells_which_side_classes_a_face_carries() {
    use ndn_transport::SideClass;
    let (app, _app) = face(1, FaceKind::App);
    let (ether, _ether) = datagram_only_face(2, FaceKind::Ethernet);
    let (e, _sd) = engine(vec![app, ether], 1).await;
    for class in [SideClass::Datagram, SideClass::Stream] {
        assert!(
            e.face_carries_side(FaceId(1), class),
            "{class:?} on a face with a stream"
        );
        assert!(
            !e.face_carries_side(FaceId(99), class),
            "a face the engine does not hold"
        );
    }
    assert!(e.face_carries_side(FaceId(2), SideClass::Datagram));
    assert!(
        !e.face_carries_side(FaceId(2), SideClass::Stream),
        "an Ethernet segment carries no stream"
    );
}

/// The side table runs on the engine's monotonic clock: a step of the host's wall clock (NTP, a
/// VM that resumed) neither lapses every sink nor lifts every bar.
#[tokio::test]
async fn a_step_of_the_wall_clock_neither_lapses_a_route_nor_lifts_a_bar() {
    let rt = WarpRuntime::new(1_000_000_000_000_000_000, Warp::All);
    let (s, _hs) = face(1, FaceKind::App);
    let (r, _hr) = face(2, FaceKind::App);
    let (e, _sd) = EngineBuilder::new(EngineConfig::default())
        .runtime(rt.clone())
        .face(s)
        .face(r)
        .build()
        .await
        .expect("engine build");
    e.side()
        .install(SideId(ID), FaceId(1), FaceId(2), Duration::from_secs(30))
        .unwrap();
    e.side().bar(FaceId(7), e.side().now());
    assert!(e.side().is_quarantined(FaceId(7), e.side().now()));

    rt.step_wall(Duration::from_secs(301));
    // The 1 s sweep runs every millisecond here: give it many turns.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        sinks_of(&e, ID).len(),
        1,
        "a wall-clock step of 301 s lapsed the route (sinks lapsed: {})",
        e.side().stats().sinks_lapsed
    );
    assert!(
        e.side().is_quarantined(FaceId(7), e.side().now()),
        "a wall-clock step of 301 s lifted the bar"
    );

    // Time that passes still lapses it.
    rt.advance(Duration::from_secs(31));
    eventually("the sink lapsed", || e.side().stats().routes == 0).await;
}

/// A face that cannot carry channel frames (a stream or IPC socket) is never made a sink, and
/// never a route's source: the Data goes on without the header, bare on a bare-TLV face, and
/// the refusal is counted.
#[tokio::test]
async fn a_face_that_carries_no_channel_frames_is_no_sink_and_no_source_and_gets_the_data_bare() {
    for (kind, lp) in [(FaceKind::Unix, false), (FaceKind::Tcp, true)] {
        // The receiver's face carries none.
        let (s, hs) = face(1, FaceKind::App);
        let (r, hr) = no_side_face(2, kind);
        let (e, _sd) = engine(vec![s, r], 1).await;
        let got = session(&hr, &hs, labelled_data(ID, 30)).await;
        assert_eq!(
            e.side().stats().routes,
            0,
            "{kind:?}: a route was installed to a face that carries no channel frames"
        );
        assert_eq!(e.side().stats().refused_not_carried, 1);
        if lp {
            let lp = LpPacket::decode(got).unwrap();
            assert_eq!(lp.side_route, None, "{kind:?}: the header was echoed");
        } else {
            assert!(
                !is_lp_packet(&got),
                "{kind:?}: the Data went to a bare-TLV face inside an LpPacket"
            );
        }

        // The upstream face carries none.
        let (s, hs) = no_side_face(1, kind);
        let (r, hr) = face(2, FaceKind::App);
        let (e, _sd) = engine(vec![s, r], 1).await;
        let got = session(&hr, &hs, labelled_data(ID, 30)).await;
        assert_eq!(
            e.side().stats().routes,
            0,
            "{kind:?}: a route was installed from a face that carries no channel frames"
        );
        assert!(
            !is_lp_packet(&got),
            "{kind:?}: the header was echoed on a route that was refused"
        );
    }
}

/// The source of a route is a face the Interest went out of: a labelled Data from any other face
/// installs nothing, and goes on without the header.
#[tokio::test]
async fn a_labelled_data_from_a_face_never_sent_the_interest_installs_nothing() {
    let (s, hs) = face(1, FaceKind::App);
    let (r, hr) = face(2, FaceKind::App);
    let (x, hx) = face(3, FaceKind::App);
    let (e, _sd) = engine(vec![s, r, x], 1).await;

    hr.inject(interest());
    hs.wait_sent(1).await; // the Interest went out of face 1 only
    hx.inject(labelled_data(ID, 30)); // the Data comes from face 3
    let got = hr.wait_sent(1).await.remove(0);

    assert_eq!(
        e.side().stats().routes,
        0,
        "a route was installed from a face the Interest never went out of (source: {:?})",
        source_of(&e, ID)
    );
    assert_eq!(e.side().stats().refused_not_asked, 1);
    assert!(!is_lp_packet(&got), "the header was echoed");
}

/// A route tells the datagram limit of its sinks as they are now (a sender sizes its frames to it),
/// the smallest over the sinks, following a face whose limit moves; a frame over what a sink takes
/// is refused to that sink whole, never cut, and counted, while the others get it.
#[tokio::test]
async fn a_route_tells_the_datagram_limit_of_its_sinks_as_they_are_now() {
    let (s, hs) = face(1, FaceKind::App);
    let (r1, hr1) = face(2, FaceKind::App);
    let (r2, hr2) = face(3, FaceKind::App);
    let (e, _sd) = engine(vec![s, r1, r2], 1).await;
    assert_eq!(e.side_datagram_limit(ID), None, "no route yet");

    // Both ask for the same name: one Interest goes to the sender, one Data comes back and
    // installs a sink for each.
    hr1.inject(interest());
    hr2.inject(interest());
    hs.wait_sent(1).await;
    hs.inject(labelled_data(ID, 30));
    eventually("both receivers are sinks", || sinks_of(&e, ID).len() == 2).await;
    assert_eq!(e.side_datagram_limit(ID), Some(10_000));
    assert_eq!(e.side_datagram_limit(ID + 1), None, "another route");

    // The smallest, read live.
    hr2.set_side_max(1_300);
    assert_eq!(e.side_datagram_limit(ID), Some(1_300));
    hr2.set_side_max(8_962);
    assert_eq!(e.side_datagram_limit(ID), Some(8_962));
    hr1.set_side_max(2_000);
    assert_eq!(e.side_datagram_limit(ID), Some(2_000));

    // A frame over one sink's limit is refused there, whole and counted; the other takes it.
    hr1.set_side_max(9_000);
    hr2.set_side_max(1_300);
    let big = data_frame(ID, 2_000);
    hs.inject(big.clone());
    let seen = hr1.wait_side(1).await;
    assert_eq!(seen[0].frame, big, "the frame a sink took is whole");
    eventually("the refusal is counted", || {
        e.side().stats().sink_error == 1
    })
    .await;
    assert!(hr2.side().is_empty(), "nothing reached the smaller sink");
    let stats = e.side().stats();
    assert_eq!((stats.frames_in, stats.frames_out), (1, 1), "{stats:?}");

    // A frame within the smallest goes to both, byte for byte.
    let small = data_frame(ID, 1_300);
    hs.inject(small.clone());
    let at_r2 = hr2.wait_side(1).await;
    assert_eq!(at_r2[0].frame, small);
    let at_r1 = hr1.wait_side(2).await;
    assert_eq!(at_r1[1].frame, small);
}

/// A sink that is full when a frame reaches it gets its turn before the reader takes the next
/// frame: a burst that is already queued at the source does not all find the link full because
/// the reader never let the link's own task drain it (a relay's fan-out is non-blocking, so what
/// a full sink refuses is lost). Here the "link" drains when its task runs, which on this
/// single-threaded runtime is only when the reader yields.
#[tokio::test]
async fn a_full_sink_gets_to_drain_between_two_frames_of_a_burst() {
    let (s, hs) = face(1, FaceKind::App);
    let (r, hr) = face(2, FaceKind::App);
    let (e, _sd) = engine(vec![s, r], 1).await;
    session(&hr, &hs, labelled_data(ID, 30)).await;
    eventually("the sink is installed", || sinks_of(&e, ID).len() == 1).await;

    const BURST: usize = 50;
    hr.log.full.store(true, Ordering::Relaxed);
    for _ in 0..BURST {
        hs.inject(data_frame(ID, 200));
    }
    // The link's task: it runs after the reader has taken the first frame and found the sink full.
    let log = std::sync::Arc::clone(&hr.log);
    tokio::spawn(async move { log.full.store(false, Ordering::Relaxed) });

    eventually("the whole burst was routed", || {
        e.side().stats().frames_in as usize >= BURST
    })
    .await;
    let stats = e.side().stats();
    assert_eq!(
        stats.sink_full, 1,
        "only the frame that found the sink full was lost: {stats:?}"
    );
    assert_eq!(hr.side().len(), BURST - 1, "{stats:?}");
}

/// A datagram frame that the application of the source face hands over itself
/// (`side_send_local`) while no sink has room is refused `Full` **to it and not lost**: nothing
/// of it is counted but `held_back` (not `sink_full`, not `frames_in`), a sink with room takes
/// the frame offered again, `side_room` says when, and a frame `on_frame` is meant to drop
/// (another face's, one of no route) is still counted as it counts.
#[tokio::test]
async fn a_frame_a_local_sender_hands_over_is_refused_to_it_while_no_sink_has_room() {
    let (s, hs) = face(1, FaceKind::App);
    let (r, hr) = face(2, FaceKind::App);
    let (e, _sd) = engine(vec![s, r], 1).await;
    session(&hr, &hs, labelled_data(ID, 30)).await;
    eventually("the sink is installed", || sinks_of(&e, ID).len() == 1).await;
    let frame = data_frame(ID, 1_200);
    assert!(e.side_room(&frame), "an empty sink has room");

    hr.log.full.store(true, Ordering::Relaxed);
    assert!(!e.side_room(&frame), "a full sink has none");
    for _ in 0..50 {
        assert_eq!(
            e.side_send_local(FaceId(1), data_frame(ID, 1_200)),
            Err(ndn_transport::SideRefused::Full)
        );
    }
    let stats = e.side().stats();
    assert_eq!(stats.held_back, 50, "{stats:?}");
    assert_eq!(
        (stats.sink_full, stats.frames_in, stats.frames_out),
        (0, 0, 0),
        "a frame told Full is not lost and not counted as seen: {stats:?}"
    );

    // With room again the frames are taken, offered again.
    hr.log.full.store(false, Ordering::Relaxed);
    assert!(e.side_room(&frame));
    for _ in 0..3 {
        assert_eq!(e.side_send_local(FaceId(1), data_frame(ID, 1_200)), Ok(()));
    }
    assert_eq!(hr.side().len(), 3);
    let stats = e.side().stats();
    assert_eq!(
        (stats.frames_in, stats.frames_out, stats.held_back),
        (3, 3, 50),
        "{stats:?}"
    );

    // What `on_frame` drops it still drops, counted there: a route nobody holds.
    assert_eq!(
        e.side_send_local(FaceId(1), data_frame(ID + 1, 1_200)),
        Ok(())
    );
    assert_eq!(e.side().stats().unrouted, 1);
    // A frame of the route from a face that is not its source is `wrong_source`, even when full.
    hr.log.full.store(true, Ordering::Relaxed);
    assert_eq!(e.side_send_local(FaceId(7), data_frame(ID, 1_200)), Ok(()));
    let stats = e.side().stats();
    assert_eq!((stats.wrong_source, stats.held_back), (1, 50), "{stats:?}");
    // A route with no live sink has nothing to wait for.
    assert!(e.side_room(&data_frame(ID + 1, 1_200)));
}
