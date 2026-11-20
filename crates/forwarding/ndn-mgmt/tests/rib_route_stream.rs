//! The daemon tells the routes that come up in its RIB on
//! `/localhost/nfd/rib/notifications`, so an app that talks to it over IPC
//! learns a face carrying a prefix came up as an embedded one does
//! (`ndn_app::Connection::routes`): a link's route is told, a local
//! application's is not, the stream is local to the host, a client that was
//! left behind is told it missed some, and a device of the data layer over
//! IPC announces its sync group when a link route for it comes up.

#![cfg(unix)]

use std::os::fd::IntoRawFd;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::time::Duration;

use ndn_app::{Connection, EngineBuilder, ForwarderEngine, IpcConnection, Node, RouteNews};
use ndn_data::{Config, Device, Transport};
use ndn_engine::{EngineConfig, RibRoute};
use ndn_face_local::{InProcFace, InProcHandle};
use ndn_ipc::ForwarderClient;
use ndn_mgmt::{MgmtHandles, mount_management};
use ndn_packet::{Data, Interest, Name, encode::InterestBuilder};
use ndn_security::{SecurityManager, SignedTrustContext, TrustSchema, Validator};
use ndn_transport::{FaceId, FaceKind};
use tokio_util::sync::CancellationToken;

const STREAM: &str = "/localhost/nfd/rib/notifications";

fn n(uri: &str) -> Name {
    uri.parse().unwrap()
}

/// An engine with management mounted (the streams served), and the token
/// that ends it.
struct Daemon {
    engine: ForwarderEngine,
    cancel: CancellationToken,
    _shutdown: ndn_app::ShutdownHandle,
}

async fn daemon() -> Daemon {
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .build()
        .await
        .expect("engine build");
    let cancel = CancellationToken::new();
    tokio::spawn(mount_management(
        &engine,
        cancel.clone(),
        Arc::new(ndn_config::ForwarderConfig::default()),
        None,
        MgmtHandles::default(),
    ));
    tokio::time::sleep(Duration::from_millis(50)).await;
    Daemon {
        engine,
        cancel,
        _shutdown: shutdown,
    }
}

impl Daemon {
    /// A face of `kind` on the engine, and the end that talks to it.
    fn face(&self, kind: FaceKind) -> (FaceId, InProcHandle) {
        let id = self.engine.faces().alloc_id();
        let (face, handle) = InProcFace::new_kind(id, 64, kind);
        self.engine.add_face(face, self.cancel.child_token());
        (id, handle)
    }

    /// A route toward `prefix` on `face` is installed: the RIB entry, then
    /// the FIB (so it comes up).
    fn come_up(&self, prefix: &Name, face: FaceId) {
        self.engine.rib().add(
            prefix,
            RibRoute {
                face_id: face,
                origin: 255,
                cost: 0,
                flags: 1,
                expires_at: None,
            },
        );
        self.engine.rib().apply_to_fib(prefix, &self.engine.fib());
    }

    /// The route toward `prefix` on `face` is removed.
    fn go_down(&self, prefix: &Name, face: FaceId) {
        self.engine.rib().remove(prefix, face, 255);
        self.engine.rib().apply_to_fib(prefix, &self.engine.fib());
    }

    /// A client of the daemon over a socket pair, as a local application's.
    fn ipc(&self) -> Arc<IpcConnection> {
        let (engine_end, client_end) = UnixStream::pair().expect("socket pair");
        ndn_mgmt::mount_app_face_from_fd(
            engine_end.into_raw_fd(),
            &self.engine,
            self.cancel.child_token(),
        )
        .expect("mount the app face");
        let client = ForwarderClient::from_raw_fd(client_end.into_raw_fd()).expect("client");
        Arc::new(IpcConnection::new(client))
    }
}

/// Ask the stream for event `seq` over `handle`; the content of what
/// answers, or `None` when nothing does within `wait`.
async fn ask_raw(
    handle: &InProcHandle,
    prefix: &str,
    seq: u64,
    wait: Duration,
) -> Option<bytes::Bytes> {
    let name = n(prefix).append_sequence_num(seq);
    let interest = InterestBuilder::new(name.clone())
        .must_be_fresh()
        .lifetime(Duration::from_secs(3))
        .build();
    handle.send(interest).await.expect("send the Interest");
    let wire = tokio::time::timeout(wait, handle.recv()).await.ok()??;
    let data = Data::decode(wire).expect("Data");
    assert_eq!(*data.name, name, "answered at the requested name");
    Some(data.content().cloned().unwrap_or_default())
}

/// [`ask_raw`], the content as the stream's JSON.
async fn ask(
    handle: &InProcHandle,
    prefix: &str,
    seq: u64,
    wait: Duration,
) -> Option<serde_json::Value> {
    let content = ask_raw(handle, prefix, seq, wait).await?;
    Some(serde_json::from_slice(&content).expect("JSON content"))
}

/// The name of the Interest `wire` is (bare or in an LP packet).
fn interest_name(wire: bytes::Bytes) -> Option<Name> {
    let wire = if ndn_packet::lp::is_lp_packet(&wire) {
        ndn_packet::lp::LpPacket::decode(wire).ok()?.fragment?
    } else {
        wire
    };
    Interest::decode(wire).ok().map(|i| (*i.name).clone())
}

/// The next Interest `handle` is handed within `wait`.
async fn interest_within(handle: &InProcHandle, wait: Duration) -> Option<Name> {
    loop {
        let wire = tokio::time::timeout(wait, handle.recv()).await.ok()??;
        if let Some(name) = interest_name(wire) {
            return Some(name);
        }
    }
}

/// A route that comes up on a link is the next event of the stream, naming
/// the prefix and the face; one on a local application's face is none.
#[tokio::test]
async fn a_link_coming_up_is_told_and_a_local_registration_is_not() {
    let d = daemon().await;
    let (_, subscriber) = d.face(FaceKind::App);
    let first = ask(&subscriber, STREAM, 0, Duration::from_secs(5))
        .await
        .expect("the stream answers a subscriber starting at 0");
    assert_eq!(first["kind"], "resync", "{first}");
    let next = first["next"].as_u64().expect("next");

    let group = n("/alice/32=sync");
    let (local, _local_end) = d.face(FaceKind::App);
    let (link, _link_end) = d.face(FaceKind::Quic);
    d.come_up(&group, local);
    d.come_up(&group, link);

    let up = ask(&subscriber, STREAM, next, Duration::from_secs(5))
        .await
        .expect("the link's route is told");
    assert_eq!(up["kind"], "route-up", "{up}");
    assert_eq!(up["face_id"], link.0, "{up}");
    assert_eq!(up["name"], group.to_string(), "{up}");
    assert!(
        ask(&subscriber, STREAM, next + 1, Duration::from_millis(400))
            .await
            .is_none(),
        "the local application's route is told to no one"
    );
    d.cancel.cancel();
}

/// The stream is the host's: a face that is not local gets no answer from
/// `/localhost`, and nothing serves it under `/localhop` (the daemon's
/// `/localhop/nfd` handler answers a command, not the stream).
#[tokio::test]
async fn the_stream_is_local_to_the_host() {
    let d = daemon().await;
    let (_, remote) = d.face(FaceKind::Ethernet);
    assert!(
        ask_raw(&remote, STREAM, 0, Duration::from_millis(500))
            .await
            .is_none(),
        "a remote face is answered from /localhost"
    );
    let (_, local) = d.face(FaceKind::App);
    let under_localhop = ask_raw(
        &local,
        "/localhop/nfd/rib/notifications",
        0,
        Duration::from_millis(500),
    )
    .await;
    assert!(
        under_localhop.is_none_or(
            |content| serde_json::from_slice::<serde_json::Value>(&content)
                .ok()
                .and_then(|event| event.get("kind").cloned())
                .is_none()
        ),
        "the stream is served under /localhop"
    );
    assert!(
        ask(&local, STREAM, 0, Duration::from_secs(5))
            .await
            .is_some(),
        "a local face is answered"
    );
    d.cancel.cancel();
}

/// Wait for the subscription of `routes` to be in place: routes come up on
/// a link until one is told (the follower asks the daemon, so the first
/// ones may come up before it has).
async fn subscribed(d: &Daemon, routes: &mut ndn_app::RouteEvents) {
    let (link, _end) = d.face(FaceKind::Quic);
    for attempt in 0..40 {
        let probe = n(&format!("/probe/{attempt}"));
        d.come_up(&probe, link);
        if let Ok(Some(RouteNews::Up(_))) =
            tokio::time::timeout(Duration::from_millis(250), routes.next()).await
        {
            // Probes added since may still arrive.
            while tokio::time::timeout(Duration::from_millis(300), routes.next())
                .await
                .is_ok()
            {}
            return;
        }
    }
    panic!("the route stream was not followed: no route that came up was told in 10 s");
}

/// An IPC connection tells the routes that come up on a link and none of a
/// local application's (a registration over the connection itself, and a
/// local face's through the RIB); and its own prefix registration does not
/// wait behind the stream.
#[tokio::test]
async fn an_ipc_connection_tells_a_link_coming_up_and_not_local_registrations() {
    let d = daemon().await;
    let conn = d.ipc();
    let mut routes = conn
        .routes()
        .expect("an IPC connection tells the daemon's routes");
    subscribed(&d, &mut routes).await;

    let group = n("/alice/32=sync");
    // Its own registration, over the connection: an app face's route.
    tokio::time::timeout(Duration::from_secs(5), conn.register_prefix(&group))
        .await
        .expect("a registration does not wait behind the route stream")
        .expect("registered");
    // Another local application's, through the RIB.
    let (local, _local_end) = d.face(FaceKind::App);
    d.come_up(&n("/alice/32=sync/other"), local);
    assert_eq!(
        tokio::time::timeout(Duration::from_millis(500), routes.next())
            .await
            .ok(),
        None,
        "a local application's routes tell no one"
    );

    let (link, _link_end) = d.face(FaceKind::Quic);
    d.come_up(&group, link);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), routes.next())
            .await
            .expect("the link's route is told within 5 s"),
        Some(RouteNews::Up(group)),
    );
    d.cancel.cancel();
}

/// A client left behind (more routes came up than the daemon's feed or its
/// stream keeps) is told it missed some, never left believing it has seen
/// them all.
#[tokio::test]
async fn an_ipc_connection_left_behind_is_told_it_missed_routes() {
    let d = daemon().await;
    let conn = d.ipc();
    let mut routes = conn
        .routes()
        .expect("an IPC connection tells the daemon's routes");
    subscribed(&d, &mut routes).await;

    let (link, _end) = d.face(FaceKind::Quic);
    // No await between the routes: the daemon's tasks cannot take any.
    for i in 0..400 {
        d.come_up(&n(&format!("/flood/{i}")), link);
    }
    let missed = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(news) = routes.next().await {
            if news == RouteNews::Missed {
                return true;
            }
        }
        false
    })
    .await;
    assert_eq!(
        missed,
        Ok(true),
        "400 routes came up while nobody could take them, and none was told as missed"
    );
    d.cancel.cancel();
}

/// A device of the data layer on an IPC connection announces its sync group
/// when a link route for it comes up in the daemon: the announcement is
/// forwarded on the link.
#[tokio::test]
async fn a_device_over_ipc_announces_when_a_link_route_for_its_group_comes_up() {
    let d = daemon().await;
    let conn = d.ipc();
    let device = n("/alice/laptop");
    let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
    validator
        .adopt_context(Arc::new(SignedTrustContext::hierarchical(n("/alice"))))
        .unwrap();
    let keys = Arc::new(SecurityManager::new());
    keys.generate_ed25519_from_seed(device.clone().append("KEY").append("1"), &[7; 32])
        .unwrap();
    let dev = Device::start(
        Transport {
            node: Node::from_connection(Arc::clone(&conn) as Arc<dyn Connection>),
            sync: conn as Arc<dyn Connection>,
        },
        device,
        keys,
        validator,
        Arc::new(ndn_sync::MemoryStore::new()),
        Config {
            first_look: Duration::from_millis(50),
            ..Config::new()
        },
    )
    .await
    .expect("the device starts over IPC");

    // Its start-up announcements settle with no link to carry them.
    tokio::time::sleep(Duration::from_millis(600)).await;
    let group = n("/alice/32=sync");
    let (link, link_end) = d.face(FaceKind::Quic);
    // The join announcement went out with no link to carry it. A link
    // route for the group comes up; the device is told once it follows the
    // stream (the first routes may come up before it does: take it down
    // and up again until it is told).
    let mut told = None;
    for _ in 0..40 {
        d.come_up(&group, link);
        if let Some(name) = interest_within(&link_end, Duration::from_millis(400)).await {
            told = Some(name);
            break;
        }
        d.go_down(&group, link);
    }
    let told = told.expect(
        "a link route for the device's group came up and the device announced nothing on the link in 16 s",
    );
    assert!(
        told.has_prefix(&group),
        "the announcement is a Sync Interest of the group: {told}"
    );

    // A local application's route for the group is no face coming up: the
    // announcement is not made again, to the link or to it.
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let (local, local_end) = d.face(FaceKind::App);
    d.come_up(&group, local);
    assert!(
        interest_within(&link_end, Duration::from_millis(1500))
            .await
            .is_none(),
        "a local application's route announced the group again on the link"
    );
    assert!(
        interest_within(&local_end, Duration::from_millis(100))
            .await
            .is_none(),
        "a local application's route announced the group to it"
    );
    dev.shutdown();
    d.cancel.cancel();
}
