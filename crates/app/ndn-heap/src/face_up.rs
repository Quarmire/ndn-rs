//! A face that carries a joined sync group comes up: the node announces that
//! group's state vector at once (spec §7, "A face comes up"), instead of at
//! the group's next period (half a minute). A version committed while no
//! link was up was announced to no one; the link coming up is when someone
//! can hear it.
//!
//! The trigger is the forwarder's own: a route whose prefix covers a joined
//! group, got into its FIB on a face that is not a local application's
//! ([`ndn_app::Connection::routes`]: an embedded engine's RIB, or a daemon's
//! `/localhost/nfd/rib/notifications` stream over IPC). The node learns
//! nothing about the link layer, and the forwarder nothing about sync
//! groups. A connection that cannot tell routes gives none, and the periodic
//! announcement alone runs.
//!
//! **What it does not touch.** Only the outgoing Sync Interest is sent, the
//! one the node's `announce` sends for every other reason. Nothing about the
//! devices heard ([`crate::heard`]) is set here: an announcement of ours is
//! no hearing of anyone. Suppression stays the sync driver's: an
//! announcement restarts the group's period, as a join does.
//!
//! **Why every joined group a route covers, with nothing to tell or not.**
//! The announcement is the one a join makes. A device with no counter in a
//! group announces the devices it heard there (and zero for itself, which
//! the vector omits): harmless to a member that has nothing newer, and what
//! a member that was away asks the others with, so each end of a link that
//! came up tells what it holds and learns what it missed.
//!
//! **Why a total bound, and why not only the face that came up.** The
//! announcements of a batch (a route at `/`, or events lost, with hundreds
//! of groups joined) are bounded across groups, not only per group:
//! [`TOTAL_PER_SECOND`] in any second, the rest deferred to the seconds that
//! follow, none dropped (a group's period of half a minute announces it
//! anyway, so even a deferral past it loses nothing). Sending only on the
//! face that came up would bound the work per link, not the burst: every
//! group a route covers is still announced, on one face instead of all, and
//! it needs a per-face send that the sync driver does not have (it sends
//! each packet through its one connection and the forwarder's strategy picks
//! the faces) and, for a batch that lost events, a face it cannot name. The
//! total bound is one gate on the one send the sync driver has.

use std::collections::{BTreeSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use futures::future::BoxFuture;
use ndn_app::{Connection, RouteEvents, RouteNews};
use ndn_foundation_types::Name;
use parking_lot::Mutex;
use tokio_util::sync::CancellationToken;

use crate::rt::{self, Instant, Tasks};

/// At most one announcement per group in this long: a link that flaps adds
/// its routes again and again.
pub(crate) const EVERY: Duration = Duration::from_secs(1);

/// At most this many announcements in any one second, over every group: a
/// batch that covers every group (a route at `/`, or events lost) with
/// hundreds of groups joined must not put them all on the link at once.
pub(crate) const TOTAL_PER_SECOND: usize = 32;

/// What to do with a group a route came up for.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// Announce now.
    Now,
    /// Announce in this long at the soonest (the end of the group's second
    /// since its last announcement, or the time the total of
    /// [`TOTAL_PER_SECOND`] has room, whichever is later): the caller waits,
    /// then asks [`Gate::due`] until it says to announce.
    After(Duration),
    /// An announcement is already waiting for its time: nothing to do, that
    /// one tells what this route brings too.
    Waiting,
}

/// Which groups are waiting their turn, and the announcements of all groups
/// made within the last [`EVERY`].
#[derive(Default)]
pub(crate) struct Gate {
    waiting: BTreeSet<Name>,
    /// Each announcement made within the last [`EVERY`] with its group,
    /// oldest first: never more than [`TOTAL_PER_SECOND`], and the newest of
    /// a group is when it was last announced.
    sent: VecDeque<(Instant, Name)>,
}

impl Gate {
    /// How long from `now` until `group` may be announced: its own second
    /// since its last announcement, and room in the total. Zero: it is
    /// announced now, and recorded as so.
    fn claim(&mut self, now: Instant, group: &Name) -> Duration {
        let left = |at: Instant| EVERY.saturating_sub(now.saturating_duration_since(at));
        while self.sent.front().is_some_and(|&(at, _)| left(at).is_zero()) {
            self.sent.pop_front();
        }
        let own = self.sent.iter().rev().find(|(_, g)| g == group);
        let total = self
            .sent
            .front()
            .filter(|_| self.sent.len() >= TOTAL_PER_SECOND);
        let wait = own.into_iter().chain(total).map(|&(at, _)| left(at)).max();
        let wait = wait.unwrap_or_default();
        if wait.is_zero() {
            self.waiting.remove(group);
            self.sent.push_back((now, group.clone()));
        }
        wait
    }

    /// A route came up for `group` at `now`.
    pub(crate) fn ask(&mut self, now: Instant, group: &Name) -> Verdict {
        if self.waiting.contains(group) {
            return Verdict::Waiting;
        }
        let wait = self.claim(now, group);
        if wait.is_zero() {
            return Verdict::Now;
        }
        self.waiting.insert(group.clone());
        Verdict::After(wait)
    }

    /// A wait of [`Verdict::After`] is over at `now`: `None` when `group` is
    /// to be announced now (once per wait), else the time to wait again (the
    /// total had no room: other groups' announcements took it).
    pub(crate) fn due(&mut self, now: Instant, group: &Name) -> Option<Duration> {
        Some(self.claim(now, group)).filter(|wait| !wait.is_zero())
    }
}

/// What the task and each announcement waiting for its turn share.
struct Shared {
    /// The names of every sync group the node has joined, as of the asking.
    groups: Box<dyn Fn() -> Vec<Name> + Send + Sync>,
    /// Send the group's state vector now (the node's `MultiSvs::announce`).
    announce: Box<dyn Fn(Name) -> BoxFuture<'static, ()> + Send + Sync>,
    gate: Mutex<Gate>,
    /// Cancelled when the node stops the task.
    stop: CancellationToken,
    /// The tasks the announcements run among.
    tasks: Arc<Tasks>,
}

impl Shared {
    /// The groups that a route toward `prefix` covers (the group, its owner's
    /// namespace, or above), all of them when `prefix` is `None`.
    fn covered_by(&self, prefix: Option<&Name>) -> Vec<Name> {
        (self.groups)()
            .into_iter()
            .filter(|g| prefix.is_none_or(|p| g.has_prefix(p)))
            .collect()
    }
}

/// The task that announces a group when a route covering it comes up. It ends
/// when the forwarder is gone, or when this is stopped or dropped.
pub(crate) struct FaceUp {
    stop: CancellationToken,
}

impl FaceUp {
    /// Follow the routes of `conn` and announce each group of `groups` that a
    /// route coming up covers, with `announce`; the task and each announcement
    /// waiting for its turn are among `tasks`. Nothing is followed, and
    /// nothing announced, when `conn` cannot tell its routes
    /// ([`Connection::routes`]).
    pub(crate) fn spawn(
        conn: Arc<dyn Connection>,
        tasks: Arc<Tasks>,
        groups: impl Fn() -> Vec<Name> + Send + Sync + 'static,
        announce: impl Fn(Name) -> BoxFuture<'static, ()> + Send + Sync + 'static,
    ) -> FaceUp {
        let stop = CancellationToken::new();
        if let Some(routes) = conn.routes() {
            let shared = Shared {
                groups: Box::new(groups),
                announce: Box::new(announce),
                gate: Mutex::default(),
                stop: stop.clone(),
                tasks: Arc::clone(&tasks),
            };
            tasks.spawn(run(routes, Arc::new(shared)));
        }
        FaceUp { stop }
    }

    /// End the task: no announcement is made after this returns, one waiting
    /// for its second is never made.
    pub(crate) fn stop(&self) {
        self.stop.cancel();
    }
}

impl Drop for FaceUp {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Announce each group a route comes up for, as a batch: once per group
/// however many routes of the batch cover it, at most once per [`EVERY`]
/// per group (the first at once, a later one at the end of the second, so
/// the last face up is told too), and at most [`TOTAL_PER_SECOND`] in any
/// second over every group (the rest wait for room, in the seconds that
/// follow, none dropped).
async fn run(mut routes: RouteEvents, shared: Arc<Shared>) {
    while let Some(Some(first)) = shared.stop.run_until_cancelled(routes.next()).await {
        let mut covered = BTreeSet::new();
        let mut news = Some(first);
        while let Some(item) = news {
            covered.extend(match item {
                RouteNews::Up(prefix) => shared.covered_by(Some(&prefix)),
                RouteNews::Missed => shared.covered_by(None),
            });
            news = routes.next_ready();
        }
        let now = Instant::now();
        for group in covered {
            let verdict = shared.gate.lock().ask(now, &group);
            match verdict {
                Verdict::Now => {
                    tracing::debug!(%group, "a face carrying the group came up: its state announced");
                    (shared.announce)(group).await;
                }
                Verdict::After(wait) => {
                    shared
                        .tasks
                        .spawn(announce_when_due(group, wait, Arc::clone(&shared)));
                }
                Verdict::Waiting => {}
            }
        }
    }
}

/// Wait `wait`, then until the gate has room for `group`, and announce it,
/// unless the task was stopped meanwhile.
async fn announce_when_due(group: Name, mut wait: Duration, shared: Arc<Shared>) {
    while shared
        .stop
        .run_until_cancelled(rt::sleep(wait))
        .await
        .is_some()
    {
        let due = shared.gate.lock().due(Instant::now(), &group);
        match due {
            Some(again) => wait = again,
            None => {
                tracing::debug!(%group, "a face carrying the group came up a while ago: its state announced");
                (shared.announce)(group).await;
                return;
            }
        }
    }
}

#[cfg(test)]
#[path = "face_up_tests.rs"]
mod tests;
