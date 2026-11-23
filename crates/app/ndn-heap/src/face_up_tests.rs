//! A face that carries a joined sync group comes up (spec §7, "A face comes
//! up"): the group is announced at once, at most once a second per group,
//! at most [`TOTAL_PER_SECOND`] a second across groups, and only for a route
//! that covers a group joined. The forwarder is a stream of routes the case
//! drives; the node is a list of groups and a callback that records the
//! announcements and when they were made. Time is the runtime's paused
//! clock: a second costs nothing and the cases are exact.

use super::*;
use crate::test_kit::n;
use futures::FutureExt;
use ndn_app::{AppError, FaceId, RouteEvents, RouteUp};
use parking_lot::Mutex;
use std::collections::BTreeSet;
use tokio::sync::broadcast;

/// A connection whose routes are the ones the case sends.
struct Tell {
    routes: broadcast::Sender<RouteUp>,
}

#[async_trait::async_trait]
impl Connection for Tell {
    async fn send(&self, _wire: bytes::Bytes) -> Result<(), AppError> {
        Ok(())
    }
    async fn recv(&self) -> Option<bytes::Bytes> {
        futures::future::pending().await
    }
    async fn register_prefix(&self, _prefix: &Name) -> Result<(), AppError> {
        Ok(())
    }
    fn routes(&self) -> Option<RouteEvents> {
        Some(RouteEvents::new(self.routes.subscribe(), |_| true))
    }
}

/// A connection that can tell no routes ([`Connection::routes`] is `None`).
struct Mute;

#[async_trait::async_trait]
impl Connection for Mute {
    async fn send(&self, _wire: bytes::Bytes) -> Result<(), AppError> {
        Ok(())
    }
    async fn recv(&self) -> Option<bytes::Bytes> {
        futures::future::pending().await
    }
    async fn register_prefix(&self, _prefix: &Name) -> Result<(), AppError> {
        Ok(())
    }
}

/// A node with `groups` joined, over a forwarder that tells routes through a
/// channel of `capacity`.
struct Rig {
    tell: Arc<Tell>,
    groups: Arc<Mutex<Vec<Name>>>,
    told: Arc<Mutex<Vec<(Name, Instant)>>>,
    began: Instant,
    face_up: FaceUp,
}

impl Rig {
    fn new(capacity: usize, groups: Vec<Name>) -> Rig {
        let tell = Arc::new(Tell {
            routes: broadcast::channel(capacity).0,
        });
        let groups = Arc::new(Mutex::new(groups));
        let told: Arc<Mutex<Vec<(Name, Instant)>>> = Arc::default();
        let face_up = FaceUp::spawn(
            Arc::clone(&tell) as Arc<dyn Connection>,
            {
                let groups = Arc::clone(&groups);
                move || groups.lock().clone()
            },
            {
                let told = Arc::clone(&told);
                move |group| {
                    let told = Arc::clone(&told);
                    async move { told.lock().push((group, Instant::now())) }.boxed()
                }
            },
        );
        Rig {
            tell,
            groups,
            told,
            began: Instant::now(),
            face_up,
        }
    }

    /// A route toward `prefix` came up on a link.
    fn up(&self, prefix: &str) {
        let _ = self.tell.routes.send(RouteUp {
            prefix: n(prefix),
            face: FaceId(7),
        });
    }

    /// How many times `group` was announced.
    fn told_of(&self, group: &str) -> usize {
        let group = n(group);
        self.told.lock().iter().filter(|(g, _)| *g == group).count()
    }

    fn told(&self) -> usize {
        self.told.lock().len()
    }

    /// When each announcement was made, since the rig began.
    fn times(&self) -> Vec<Duration> {
        self.told
            .lock()
            .iter()
            .map(|(_, t)| t.duration_since(self.began))
            .collect()
    }
}

/// Let the tasks run and the clock go `by` forward, tasks running at every
/// timer on the way.
async fn pass(by: Duration) {
    tokio::time::sleep(by).await;
}

const NOTES: &str = "/alice/32=sync/notes";
const DOCS: &str = "/alice/32=sync/docs";

/// A route at the group's owner prefix, at `<O>/32=sync`, at the group, or
/// above, announces the group at once.
#[tokio::test(start_paused = true)]
async fn a_route_that_covers_a_joined_group_announces_it_at_once() {
    for prefix in ["/alice/32=sync/notes", "/alice/32=sync", "/alice", "/"] {
        let rig = Rig::new(16, vec![n(NOTES)]);
        rig.up(prefix);
        pass(Duration::from_millis(1)).await;
        assert_eq!(
            rig.told_of(NOTES),
            1,
            "a route at {prefix} announces the group at once"
        );
        assert_eq!(rig.times()[0], Duration::ZERO, "at once, not after a wait");
        pass(Duration::from_secs(5)).await;
        assert_eq!(rig.told(), 1, "one announcement for the route at {prefix}");
    }
}

/// A route that covers no joined group announces nothing: another owner, a
/// name under the owner that is not a group, one under the group and a
/// sibling group.
#[tokio::test(start_paused = true)]
async fn a_route_that_covers_no_joined_group_announces_nothing() {
    let rig = Rig::new(16, vec![n(NOTES)]);
    for prefix in [
        "/bob",
        "/bob/32=sync",
        "/alice/member/laptop",
        "/alice/32=data/notes",
        "/alice/32=sync/probe",
        "/alice/32=sync/notes/deeper",
    ] {
        rig.up(prefix);
    }
    pass(Duration::from_secs(5)).await;
    assert_eq!(
        rig.told(),
        0,
        "nothing was announced for a route that covers no group joined"
    );
}

/// A link that flaps (routes added again and again within a second) costs
/// one announcement at once and one at the end of the second, so the last
/// face up is told, and no more.
#[tokio::test(start_paused = true)]
async fn a_flapping_link_announces_a_group_at_most_once_a_second() {
    let rig = Rig::new(64, vec![n(NOTES)]);
    for _ in 0..10 {
        rig.up("/alice/32=sync");
        pass(Duration::from_millis(30)).await;
    }
    assert_eq!(rig.told(), 1, "within the second of the first route: one");
    pass(Duration::from_secs(3)).await;
    let times = rig.times();
    assert_eq!(times.len(), 2, "two announcements for the flapping: {times:?}");
    assert_eq!(times[0], Duration::ZERO);
    assert_eq!(
        times[1], EVERY,
        "the second one at the end of the first one's second, so the last face up is told"
    );
}

/// A route above every group announces each group joined, once; one toward
/// a group alone leaves the others be.
#[tokio::test(start_paused = true)]
async fn a_route_above_every_group_announces_each_group_joined() {
    let rig = Rig::new(16, vec![n(NOTES), n(DOCS), n("/bob/32=sync/notes")]);
    rig.up("/alice");
    pass(Duration::from_millis(1)).await;
    assert_eq!(
        (
            rig.told_of(NOTES),
            rig.told_of(DOCS),
            rig.told_of("/bob/32=sync/notes")
        ),
        (1, 1, 0),
        "every group of alice, none of bob's"
    );
    pass(Duration::from_secs(2)).await;
    rig.up("/alice/32=sync/docs");
    pass(Duration::from_millis(1)).await;
    assert_eq!(
        (rig.told_of(NOTES), rig.told_of(DOCS)),
        (1, 2),
        "a route toward one group leaves the other be"
    );
}

/// A subscriber that fell behind (the routes came faster than it took them)
/// cannot tell which came up: every group joined is announced.
#[tokio::test(start_paused = true)]
async fn a_subscriber_that_missed_routes_announces_every_group_joined() {
    let rig = Rig::new(2, vec![n(NOTES), n(DOCS), n("/bob/32=sync/notes")]);
    // No await between the sends: the task cannot take any.
    for i in 0..8 {
        rig.up(&format!("/elsewhere/{i}"));
    }
    pass(Duration::from_millis(1)).await;
    assert_eq!(
        (
            rig.told_of(NOTES),
            rig.told_of(DOCS),
            rig.told_of("/bob/32=sync/notes")
        ),
        (1, 1, 1)
    );
}

/// 300 groups joined.
fn many() -> Vec<Name> {
    (0..300)
        .map(|i| n(&format!("/g{i}/32=sync/s")))
        .collect()
}

/// What `trigger` (a batch of routes that covers every group) sends: at most
/// [`TOTAL_PER_SECOND`] announcements in any second, every group announced
/// once and none dropped, all of them well within the group's period of half
/// a minute.
async fn capped_then_all_told(rig: Rig, trigger: impl FnOnce(&Rig)) {
    trigger(&rig);
    pass(Duration::from_millis(900)).await;
    let first = rig.told();
    assert!(
        first > 0,
        "nothing announced in the first 900 ms: the groups a route covers are told at once, up to the cap"
    );
    assert!(
        first <= TOTAL_PER_SECOND,
        "{first} announcements in the first 900 ms across 300 groups, at most {TOTAL_PER_SECOND} a second expected"
    );
    pass(Duration::from_secs(30)).await;
    let told: Vec<Name> = rig.told.lock().iter().map(|(g, _)| g.clone()).collect();
    let distinct: BTreeSet<&Name> = told.iter().collect();
    assert_eq!(told.len(), 300, "every group announced, none dropped");
    assert_eq!(distinct.len(), 300, "each group once");
    let times = rig.times();
    for at in &times {
        let within = times.iter().filter(|t| *t >= at && **t < *at + EVERY).count();
        assert!(
            within <= TOTAL_PER_SECOND,
            "{within} announcements within a second from {at:?}, at most {TOTAL_PER_SECOND} expected"
        );
    }
    let last = *times.iter().max().unwrap();
    assert!(
        last <= Duration::from_secs((300 / TOTAL_PER_SECOND) as u64 + 1),
        "all announced by {last:?}: well within the group's period of half a minute"
    );
}

/// A route above 300 groups does not announce them all at once: at most
/// [`TOTAL_PER_SECOND`] a second over every group, the rest in the seconds
/// that follow.
#[tokio::test(start_paused = true)]
async fn a_route_above_three_hundred_groups_announces_at_most_the_cap_a_second() {
    capped_then_all_told(Rig::new(16, many()), |rig| rig.up("/")).await;
}

/// A subscriber that lost events cannot tell which route came up, so every
/// group is a candidate: still at most [`TOTAL_PER_SECOND`] a second.
#[tokio::test(start_paused = true)]
async fn missed_routes_with_three_hundred_groups_announce_at_most_the_cap_a_second() {
    capped_then_all_told(Rig::new(2, many()), |rig| {
        for i in 0..8 {
            rig.up(&format!("/elsewhere/{i}"));
        }
    })
    .await;
}

/// Once the node stops it, no route announces anything, and an announcement
/// that was waiting for its second is never made.
#[tokio::test(start_paused = true)]
async fn a_stopped_face_up_announces_nothing_more() {
    let rig = Rig::new(16, vec![n(NOTES)]);
    rig.up("/alice");
    pass(Duration::from_millis(10)).await;
    rig.up("/alice");
    pass(Duration::from_millis(10)).await;
    assert_eq!(rig.told(), 1, "the second one waits for the end of the second");
    rig.face_up.stop();
    pass(Duration::from_secs(5)).await;
    assert_eq!(rig.told(), 1, "the waiting announcement was never made");
    rig.up("/alice");
    pass(Duration::from_secs(5)).await;
    assert_eq!(rig.told(), 1, "a route after the stop announces nothing");
}

/// A connection that cannot tell its routes leaves the periodic
/// announcement alone: there is no task and no announcement.
#[tokio::test(start_paused = true)]
async fn a_connection_that_tells_no_routes_announces_nothing() {
    let told: Arc<Mutex<usize>> = Arc::default();
    let face_up = FaceUp::spawn(
        Arc::new(Mute) as Arc<dyn Connection>,
        || vec![n(NOTES)],
        {
            let told = Arc::clone(&told);
            move |_| {
                let told = Arc::clone(&told);
                async move { *told.lock() += 1 }.boxed()
            }
        },
    );
    pass(Duration::from_secs(5)).await;
    assert_eq!(*told.lock(), 0);
    drop(face_up);
}
