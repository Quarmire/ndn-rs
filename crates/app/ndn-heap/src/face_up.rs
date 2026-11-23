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

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use futures::future::{BoxFuture, Either, select};
use ndn_app::{Connection, RouteEvents, RouteNews};
use ndn_foundation_types::Name;
use parking_lot::Mutex;
use tokio::sync::Notify;

use crate::rt::{self, Instant};

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

/// When each group was last announced because a face came up, when the last
/// [`TOTAL_PER_SECOND`] announcements of all groups were made, and which
/// groups are waiting their turn.
#[derive(Default)]
pub(crate) struct Gate {
    last: BTreeMap<Name, Instant>,
    waiting: BTreeSet<Name>,
    /// Times of the announcements made within the last [`EVERY`], oldest
    /// first: never more than [`TOTAL_PER_SECOND`].
    sent: VecDeque<Instant>,
}

impl Gate {
    /// How long from `now` until `group` may be announced: its own second
    /// since its last announcement, and room in the total.
    fn wait(&mut self, now: Instant, group: &Name) -> Duration {
        while self
            .sent
            .front()
            .is_some_and(|&t| now.saturating_duration_since(t) >= EVERY)
        {
            self.sent.pop_front();
        }
        let own = self.last.get(group).map_or(Duration::ZERO, |&last| {
            EVERY.saturating_sub(now.saturating_duration_since(last))
        });
        let total = match self.sent.front() {
            Some(&oldest) if self.sent.len() >= TOTAL_PER_SECOND => {
                EVERY.saturating_sub(now.saturating_duration_since(oldest))
            }
            _ => Duration::ZERO,
        };
        own.max(total)
    }

    /// `group` is announced at `now`.
    fn record(&mut self, now: Instant, group: &Name) {
        self.last.insert(group.clone(), now);
        self.sent.push_back(now);
    }

    /// A route came up for `group` at `now`.
    pub(crate) fn ask(&mut self, now: Instant, group: &Name) -> Verdict {
        if self.waiting.contains(group) {
            return Verdict::Waiting;
        }
        let wait = self.wait(now, group);
        if wait.is_zero() {
            self.record(now, group);
            Verdict::Now
        } else {
            self.waiting.insert(group.clone());
            Verdict::After(wait)
        }
    }

    /// A wait of [`Verdict::After`] is over at `now`: `None` when `group` is
    /// to be announced now (once per wait), else the time to wait again (the
    /// total had no room: other groups' announcements took it).
    pub(crate) fn due(&mut self, now: Instant, group: &Name) -> Option<Duration> {
        let wait = self.wait(now, group);
        if !wait.is_zero() {
            return Some(wait);
        }
        self.waiting.remove(group);
        self.record(now, group);
        None
    }
}

/// Whether the node stopped the task, and a way to wake it to see so.
#[derive(Default)]
struct Stop {
    stopped: AtomicBool,
    wake: Notify,
}

impl Stop {
    fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::Relaxed)
    }
}

/// The sync groups of the node, all of them.
type Groups = Arc<dyn Fn() -> Vec<Name> + Send + Sync>;

/// Send the group's state vector now (the node's `MultiSvs::announce`).
type Announce = Arc<dyn Fn(Name) -> BoxFuture<'static, ()> + Send + Sync>;

/// The task that announces a group when a route covering it comes up. It ends
/// when the forwarder is gone, or when this is stopped or dropped.
pub(crate) struct FaceUp {
    stop: Arc<Stop>,
}

impl FaceUp {
    /// Follow the routes of `conn` and announce each group of `groups` (the
    /// names of every sync group the node has joined, as of the asking) that
    /// a route coming up covers, with `announce`. Nothing is followed, and
    /// nothing announced, when `conn` cannot tell its routes
    /// ([`Connection::routes`]).
    pub(crate) fn spawn(
        conn: Arc<dyn Connection>,
        groups: impl Fn() -> Vec<Name> + Send + Sync + 'static,
        announce: impl Fn(Name) -> BoxFuture<'static, ()> + Send + Sync + 'static,
    ) -> FaceUp {
        let stop = Arc::new(Stop::default());
        if let Some(routes) = conn.routes() {
            rt::spawn(run(
                routes,
                Arc::new(groups),
                Arc::new(announce),
                Arc::clone(&stop),
            ));
        }
        FaceUp { stop }
    }

    /// End the task: no announcement is made after this returns, one waiting
    /// for its second is never made.
    pub(crate) fn stop(&self) {
        self.stop.stopped.store(true, Ordering::Relaxed);
        self.stop.wake.notify_one();
    }
}

impl Drop for FaceUp {
    fn drop(&mut self) {
        self.stop();
    }
}

/// The groups among `groups` that a route toward `prefix` covers (the group,
/// its owner's namespace, or above), all of them when `prefix` is `None`.
fn covered_by(groups: &Groups, prefix: Option<&Name>) -> Vec<Name> {
    groups()
        .into_iter()
        .filter(|g| prefix.is_none_or(|p| g.has_prefix(p)))
        .collect()
}

/// Announce each group a route comes up for, as a batch: once per group
/// however many routes of the batch cover it, at most once per [`EVERY`]
/// per group (the first at once, a later one at the end of the second, so
/// the last face up is told too), and at most [`TOTAL_PER_SECOND`] in any
/// second over every group (the rest wait for room, in the seconds that
/// follow, none dropped).
async fn run(mut routes: RouteEvents, groups: Groups, announce: Announce, stop: Arc<Stop>) {
    let gate = Arc::new(Mutex::new(Gate::default()));
    loop {
        let first = {
            let next = pin!(routes.next());
            let stopped = pin!(stop.wake.notified());
            match select(next, stopped).await {
                Either::Left((Some(news), _)) => news,
                _ => return,
            }
        };
        if stop.is_stopped() {
            return;
        }
        let mut covered = BTreeSet::new();
        let mut news = Some(first);
        while let Some(item) = news {
            match item {
                RouteNews::Up(prefix) => covered.extend(covered_by(&groups, Some(&prefix))),
                RouteNews::Missed => covered.extend(covered_by(&groups, None)),
            }
            news = routes.next_ready();
        }
        let now = Instant::now();
        for group in covered {
            let verdict = gate.lock().ask(now, &group);
            match verdict {
                Verdict::Now => {
                    tracing::debug!(%group, "a face carrying the group came up: its state announced");
                    announce(group).await;
                }
                Verdict::After(wait) => {
                    rt::spawn(announce_when_due(
                        group,
                        wait,
                        Arc::clone(&gate),
                        Arc::clone(&announce),
                        Arc::clone(&stop),
                    ));
                }
                Verdict::Waiting => {}
            }
        }
    }
}

/// Wait `wait`, then until `gate` has room for `group`, and announce it,
/// unless the task was stopped meanwhile.
async fn announce_when_due(
    group: Name,
    mut wait: Duration,
    gate: Arc<Mutex<Gate>>,
    announce: Announce,
    stop: Arc<Stop>,
) {
    loop {
        rt::sleep(wait).await;
        if stop.is_stopped() {
            return;
        }
        let due = gate.lock().due(Instant::now(), &group);
        match due {
            Some(again) => wait = again,
            None => {
                tracing::debug!(%group, "a face carrying the group came up a while ago: its state announced");
                announce(group).await;
                return;
            }
        }
    }
}

#[cfg(test)]
#[path = "face_up_tests.rs"]
mod tests;
