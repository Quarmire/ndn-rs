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
use ndn_packet::{Data, Name};
use ndn_transport::side_header::UpOp;
use ndn_transport::{FaceId, FaceKind};
use tokio_util::sync::CancellationToken;

use crate::side_support::{Handle, TestFace, Warp, WarpRuntime, data_frame, face, pair, up};

const ID: u64 = 0x5E55_10_C0FFEE;

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
async fn a_header_on_a_data_from_a_quarantined_face_installs_nothing_and_ndn_traffic_goes_on() {
    let (s, hs) = face(1, FaceKind::App);
    let (r, hr) = face(2, FaceKind::App);
    let (e, _sd) = engine(vec![s, r], 1).await;
    let barred = e.side().bar(FaceId(1), e.side().now());
    assert_eq!(barred, Duration::from_secs(60));

    // The Interest and the Data still cross the barred face; the Data is
    // delivered without the header, and no route stands.
    let got = session(&hr, &hs, labelled_data(ID, 30)).await;
    assert!(!is_lp_packet(&got));
    let stats = e.side().stats();
    assert_eq!((stats.routes, stats.refused_quarantined), (0, 1));

    // A marked frame from the barred face is dropped `quarantined`.
    hs.inject(data_frame(ID, 64));
    eventually("the frame was dropped quarantined", || {
        e.side().stats().quarantined == 1
    })
    .await;
    assert!(hr.side().is_empty());

    // A second exchange over the same face still works.
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
