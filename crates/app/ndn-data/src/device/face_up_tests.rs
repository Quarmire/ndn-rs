//! A face that carries a joined sync group comes up (spec §12, "A face comes
//! up"): the device announces the group at once, at most once a second per
//! group, and only for a route that covers a group it joined. The forwarder
//! is a connection the case drives ([`Tell`]): it counts the Sync Interests
//! the device sends into each group and tells the routes the case gives it.

use super::durability_tests::device_over;
use super::group_tests::n;
use super::*;
use ndn_app::{AppError, FaceId, RouteEvents, RouteUp};
use tokio::sync::broadcast;

/// A connection that counts the Interests sent, by name, and whose routes
/// are the ones the case sends.
struct Tell {
    sent: Mutex<Vec<Name>>,
    routes: broadcast::Sender<RouteUp>,
}

impl Tell {
    fn new(capacity: usize) -> Arc<Tell> {
        Arc::new(Tell {
            sent: Mutex::new(Vec::new()),
            routes: broadcast::channel(capacity).0,
        })
    }

    /// The Interests sent so far into the group of namespace `ns`.
    fn into_group(&self, ns: &str) -> usize {
        let group = sync_group(&n(ns));
        self.sent
            .lock()
            .iter()
            .filter(|name| name.has_prefix(&group))
            .count()
    }

    /// A route toward `prefix` came up on a link.
    fn up(&self, prefix: &str) {
        let _ = self.routes.send(RouteUp {
            prefix: n(prefix),
            face: FaceId(7),
        });
    }
}

#[async_trait::async_trait]
impl Connection for Tell {
    async fn send(&self, wire: Bytes) -> Result<(), AppError> {
        if let Some(interest) = bare_interest(wire) {
            self.sent.lock().push((*interest.name).clone());
        }
        Ok(())
    }
    async fn recv(&self) -> Option<Bytes> {
        futures::future::pending().await
    }
    async fn register_prefix(&self, _prefix: &Name) -> Result<(), AppError> {
        Ok(())
    }
    fn routes(&self) -> Option<RouteEvents> {
        Some(RouteEvents::new(self.routes.subscribe(), |_| true))
    }
}

/// Alice's laptop over `tell`, its join announcement sent and settled.
async fn started(tell: &Arc<Tell>) -> Device {
    let dev = device_over(
        "/alice/laptop",
        Arc::new(ndn_sync::MemoryStore::new()),
        Arc::clone(tell) as Arc<dyn Connection>,
    )
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        tell.into_group("/alice") >= 1,
        "the join announcement went out"
    );
    dev
}

/// Wait until the Interests sent into `ns`'s group number `count`, or fail
/// at `limit`: `what` says what was expected.
async fn until_sent(tell: &Tell, ns: &str, count: usize, limit: Duration, what: &str) {
    let began = Instant::now();
    while tell.into_group(ns) < count {
        assert!(
            began.elapsed() < limit,
            "{what}: {} Interests sent into the group of {ns}, {count} expected within {limit:?}",
            tell.into_group(ns)
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// A route at the group, at its namespace, or above it announces the group
/// at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_route_that_covers_a_joined_group_announces_it_at_once() {
    for prefix in ["/alice/32=sync", "/alice", "/"] {
        let tell = Tell::new(16);
        let dev = started(&tell).await;
        let before = tell.into_group("/alice");
        tell.up(prefix);
        until_sent(
            &tell,
            "/alice",
            before + 1,
            Duration::from_millis(500),
            &format!("a route at {prefix} came up"),
        )
        .await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            tell.into_group("/alice"),
            before + 1,
            "one announcement for the route at {prefix}"
        );
        dev.shutdown();
    }
}

/// A route that covers no joined group announces nothing: another namespace,
/// a name under the namespace that is not its group, and a name under the
/// group (a Sync Interest is not under it, or is it the group's alone).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_route_that_covers_no_joined_group_announces_nothing() {
    let tell = Tell::new(16);
    let dev = started(&tell).await;
    let before = tell.into_group("/alice");
    for prefix in [
        "/bob",
        "/bob/32=sync",
        "/alice/member/laptop",
        "/alice/32=data/notes",
        "/alice/32=sync/probe",
    ] {
        tell.up(prefix);
    }
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert_eq!(
        tell.into_group("/alice"),
        before,
        "nothing was announced for a route that covers no group joined"
    );
    dev.shutdown();
}

/// A link that flaps (routes added again and again within a second) costs
/// one announcement at once and one at the end of the second, so the last
/// face up is told, and no more.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_flapping_link_announces_a_group_at_most_once_a_second() {
    let tell = Tell::new(64);
    let dev = started(&tell).await;
    let before = tell.into_group("/alice");
    let began = Instant::now();
    for _ in 0..10 {
        tell.up("/alice/32=sync");
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    assert!(
        began.elapsed() < Duration::from_millis(800),
        "the flapping took under the second: {:?}",
        began.elapsed()
    );
    // Within the second: the first, at once.
    assert_eq!(
        tell.into_group("/alice"),
        before + 1,
        "within the second of the first route: one announcement"
    );
    // At the end of the second: the one for the routes since.
    until_sent(
        &tell,
        "/alice",
        before + 2,
        Duration::from_millis(1500),
        "the last face up is told at the end of the second",
    )
    .await;
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert_eq!(
        tell.into_group("/alice"),
        before + 2,
        "two announcements for the flapping, no more"
    );
    dev.shutdown();
}

/// A route above every group announces each group joined, once; one
/// toward a group not joined announces nothing for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_route_above_every_group_announces_each_group_joined() {
    let tell = Tell::new(16);
    let dev = started(&tell).await;
    dev.inner.join(&n("/bob")).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let (alice, bob) = (tell.into_group("/alice"), tell.into_group("/bob"));
    assert!(bob >= 1, "the join announcement of the second group");
    tell.up("/");
    until_sent(
        &tell,
        "/alice",
        alice + 1,
        Duration::from_millis(500),
        "alice",
    )
    .await;
    until_sent(&tell, "/bob", bob + 1, Duration::from_millis(500), "bob").await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        (tell.into_group("/alice"), tell.into_group("/bob")),
        (alice + 1, bob + 1)
    );

    // A route toward the second group alone leaves the first be.
    tokio::time::sleep(Duration::from_millis(1000)).await;
    tell.up("/bob/32=sync");
    until_sent(
        &tell,
        "/bob",
        bob + 2,
        Duration::from_millis(500),
        "bob again",
    )
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        tell.into_group("/alice"),
        alice + 1,
        "not announced for /bob's route"
    );
    dev.shutdown();
}

/// A subscriber that fell behind (the forwarder's routes came faster than
/// it took them) cannot tell which came up: every group joined is announced.
#[tokio::test(flavor = "current_thread")]
async fn a_subscriber_that_missed_routes_announces_every_group_joined() {
    let tell = Tell::new(2);
    let dev = started(&tell).await;
    dev.inner.join(&n("/bob")).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let (alice, bob) = (tell.into_group("/alice"), tell.into_group("/bob"));
    // No await between the sends: the device's task cannot take any.
    for i in 0..8 {
        tell.up(&format!("/elsewhere/{i}"));
    }
    until_sent(
        &tell,
        "/alice",
        alice + 1,
        Duration::from_millis(500),
        "alice",
    )
    .await;
    until_sent(&tell, "/bob", bob + 1, Duration::from_millis(500), "bob").await;
    dev.shutdown();
}
