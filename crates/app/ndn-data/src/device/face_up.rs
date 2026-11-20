//! A face that carries a joined sync group comes up: the device announces
//! that group's state vector at once (spec §12, "A face comes up"), instead
//! of at the group's next period (half a minute). A version committed while
//! no link was up was announced to no one; the link coming up is when
//! someone can hear it.
//!
//! The trigger is the forwarder's own: a route whose prefix covers a joined
//! group, got into its FIB on a face that is not a local application's
//! ([`ndn_app::Connection::routes`]: an embedded engine's RIB, or a
//! daemon's `/localhost/nfd/rib/notifications` stream over IPC). The device
//! learns nothing about the link layer, and the forwarder nothing about
//! sync groups. A connection that cannot tell routes gives none, and the
//! periodic announcement alone runs, as before.
//!
//! **What it does not touch.** Only the outgoing Sync Interest is sent, the
//! one [`MultiSvs::announce`] sends for [`Inner::hail`] and [`Inner::herald`]
//! too. Nothing about the devices heard ([`super::heard`]) or the freshness
//! of a read ([`SyncGroup::confirmed`], set by the Sync Interests that arrive,
//! in [`Inner::heard`]) is set here: an announcement of ours is no hearing
//! of anyone. Suppression stays the driver's: an announcement restarts the
//! group's period, as a join does.
//!
//! **Why every joined group a route covers, with nothing to tell or not.**
//! The announcement is the one a join makes. A device with no counter in a
//! group announces the devices it heard there (and zero for itself, which
//! the vector omits): harmless to a member that has nothing newer, and what
//! a member that was away asks the others with, so each end of a link that
//! came up tells what it holds and learns what it missed.
//!
//! **Why a total bound, and why not only the face that came up.** The
//! announcements of a batch (a route at `/`, or events lost, with hundreds of
//! groups joined) are bounded across groups, not only per group:
//! [`TOTAL_PER_SECOND`] in any second, the rest deferred to the seconds that
//! follow, none dropped (a group's period of half a minute announces it
//! anyway, so even a deferral past it loses nothing). Sending only on the
//! face that came up would bound the work per link, not the burst: every
//! group a route covers is still announced, on one face instead of all, and
//! it needs a per-face send that [`MultiSvs`] does not have (it sends each
//! packet through its one connection and the forwarder's strategy picks the
//! faces) and, for a batch that lost events, a face it cannot name. The
//! total bound is one gate on the one send the sync driver has.

use super::*;
use ndn_app::{RouteEvents, RouteNews};
use std::sync::Weak;

/// At most one announcement per group in this long: a link that flaps adds
/// its routes again and again.
pub(super) const EVERY: Duration = Duration::from_secs(1);

/// At most this many announcements in any one second, over every group: a
/// batch that covers every group (a route at `/`, or events lost) with
/// hundreds of groups joined must not put them all on the link at once.
pub(super) const TOTAL_PER_SECOND: usize = 32;

/// What to do with a group a route came up for.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Verdict {
    /// Announce now.
    Now,
    /// Announce in this long at the soonest (the end of the group's second
    /// since its last announcement, or the time the total of
    /// [`TOTAL_PER_SECOND`] has room, whichever is later): the caller
    /// waits, then asks [`Gate::due`] until it says to announce.
    After(Duration),
    /// An announcement is already waiting for its time: nothing to do,
    /// that one tells what this route brings too.
    Waiting,
}

/// When each group was last announced because a face came up, when the
/// last [`TOTAL_PER_SECOND`] announcements of all groups were made, and
/// which groups are waiting their turn.
#[derive(Default)]
pub(super) struct Gate {
    last: BTreeMap<Name, Instant>,
    waiting: BTreeSet<Name>,
    /// Times of the announcements made within the last [`EVERY`], oldest
    /// first: never more than [`TOTAL_PER_SECOND`].
    sent: VecDeque<Instant>,
}

impl Gate {
    /// How long from `now` until `ns`'s group may be announced: its own
    /// second since its last announcement, and room in the total.
    fn wait(&mut self, now: Instant, ns: &Name) -> Duration {
        while self
            .sent
            .front()
            .is_some_and(|&t| now.saturating_duration_since(t) >= EVERY)
        {
            self.sent.pop_front();
        }
        let own = self.last.get(ns).map_or(Duration::ZERO, |&last| {
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

    /// `ns`'s group is announced at `now`.
    fn record(&mut self, now: Instant, ns: &Name) {
        self.last.insert(ns.clone(), now);
        self.sent.push_back(now);
    }

    /// A route came up for `ns`'s group at `now`.
    pub(super) fn ask(&mut self, now: Instant, ns: &Name) -> Verdict {
        if self.waiting.contains(ns) {
            return Verdict::Waiting;
        }
        let wait = self.wait(now, ns);
        if wait.is_zero() {
            self.record(now, ns);
            Verdict::Now
        } else {
            self.waiting.insert(ns.clone());
            Verdict::After(wait)
        }
    }

    /// A wait of [`Verdict::After`] is over at `now`: `None` when `ns`'s
    /// group is to be announced now (once per wait), else the time to wait
    /// again (the total had no room: other groups' announcements took it).
    pub(super) fn due(&mut self, now: Instant, ns: &Name) -> Option<Duration> {
        let wait = self.wait(now, ns);
        if !wait.is_zero() {
            return Some(wait);
        }
        self.waiting.remove(ns);
        self.record(now, ns);
        None
    }
}

impl Inner {
    /// The namespaces of the groups joined whose prefix lies under `prefix`
    /// (a route at the group, at its namespace, or above), all of them when
    /// `prefix` is `None`.
    fn groups_under(&self, prefix: Option<&Name>) -> Vec<Name> {
        self.st
            .lock()
            .groups
            .keys()
            .filter(|ns| prefix.is_none_or(|p| sync_group(ns).has_prefix(p)))
            .cloned()
            .collect()
    }

    /// Announce each group a route comes up for, as a batch: once per group
    /// however many routes of the batch cover it, at most once per
    /// [`EVERY`] per group (the first at once, a later one at the end of
    /// the second, so the last face up is told too), and at most
    /// [`TOTAL_PER_SECOND`] in any second over every group (the rest wait
    /// for room, in the seconds that follow, none dropped).
    pub(super) async fn run_face_up(weak: Weak<Inner>, mut routes: RouteEvents) {
        let gate = Arc::new(Mutex::new(Gate::default()));
        while let Some(first) = routes.next().await {
            let Some(inner) = weak.upgrade() else { return };
            if inner.stopped.load(Ordering::Relaxed) {
                return;
            }
            let mut covered = BTreeSet::new();
            let mut news = Some(first);
            while let Some(item) = news {
                match item {
                    RouteNews::Up(prefix) => covered.extend(inner.groups_under(Some(&prefix))),
                    RouteNews::Missed => covered.extend(inner.groups_under(None)),
                }
                news = routes.next_ready();
            }
            let now = Instant::now();
            for ns in covered {
                let verdict = gate.lock().ask(now, &ns);
                match verdict {
                    Verdict::Now => {
                        tracing::debug!(me = %inner.device, %ns, "a face carrying the group came up: its state announced");
                        inner.svs.announce(sync_group(&ns)).await;
                    }
                    Verdict::After(mut wait) => {
                        let (weak, gate) = (Weak::clone(&weak), Arc::clone(&gate));
                        rt::spawn(async move {
                            loop {
                                rt::sleep(wait).await;
                                let Some(inner) = weak.upgrade() else { return };
                                if inner.stopped.load(Ordering::Relaxed) {
                                    return;
                                }
                                let due = gate.lock().due(Instant::now(), &ns);
                                match due {
                                    Some(again) => wait = again,
                                    None => {
                                        tracing::debug!(me = %inner.device, %ns, "a face carrying the group came up a while ago: its state announced");
                                        inner.svs.announce(sync_group(&ns)).await;
                                        return;
                                    }
                                }
                            }
                        });
                    }
                    Verdict::Waiting => {}
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ns() -> Name {
        "/alice".parse().unwrap()
    }

    /// The first route up is announced at once; the ones after it within
    /// the second wait for its end, once, whatever their number; a route
    /// after that second is announced at once again.
    #[test]
    fn the_first_is_at_once_a_later_one_waits_for_the_end_of_the_second() {
        let mut gate = Gate::default();
        let t0 = Instant::now();
        assert_eq!(gate.ask(t0, &ns()), Verdict::Now);
        assert_eq!(
            gate.ask(t0 + Duration::from_millis(100), &ns()),
            Verdict::After(Duration::from_millis(900)),
            "the end of the second since the last"
        );
        for ms in [200, 300, 800] {
            assert_eq!(
                gate.ask(t0 + Duration::from_millis(ms), &ns()),
                Verdict::Waiting,
                "{ms} ms: the waiting announcement tells it too"
            );
        }
        assert_eq!(
            gate.due(t0 + Duration::from_secs(1), &ns()),
            None,
            "announced"
        );
        assert_eq!(
            gate.due(t0 + Duration::from_secs(1), &ns()),
            Some(EVERY),
            "once: the group's second began again with that announcement"
        );
        assert_eq!(
            gate.ask(t0 + Duration::from_millis(1500), &ns()),
            Verdict::After(Duration::from_millis(500)),
            "the second restarts from the announcement that waited"
        );
        assert_eq!(gate.due(t0 + Duration::from_millis(2000), &ns()), None);
        assert_eq!(
            gate.ask(t0 + Duration::from_millis(3100), &ns()),
            Verdict::Now,
            "a route after a quiet second"
        );
    }

    /// Each group has its second.
    #[test]
    fn groups_are_gated_apart() {
        let mut gate = Gate::default();
        let t0 = Instant::now();
        let bob: Name = "/bob".parse().unwrap();
        assert_eq!(gate.ask(t0, &ns()), Verdict::Now);
        assert_eq!(gate.ask(t0, &bob), Verdict::Now);
        assert!(matches!(gate.ask(t0, &ns()), Verdict::After(_)));
        assert!(matches!(gate.ask(t0, &bob), Verdict::After(_)));
    }

    /// However many groups a batch covers, no second has more than
    /// [`TOTAL_PER_SECOND`] announcements, and every group is announced
    /// by the end: the deferred ones wait for room, none are dropped.
    #[test]
    fn the_total_of_a_second_is_capped_and_every_group_still_announced() {
        let mut gate = Gate::default();
        let t0 = Instant::now();
        let groups: Vec<Name> = (0..300)
            .map(|i| format!("/g{i}").parse().unwrap())
            .collect();
        let mut announced: Vec<(Duration, Name)> = Vec::new();
        let mut waits: Vec<(Duration, Name)> = Vec::new();
        for g in &groups {
            match gate.ask(t0, g) {
                Verdict::Now => announced.push((Duration::ZERO, g.clone())),
                Verdict::After(w) => waits.push((w, g.clone())),
                Verdict::Waiting => panic!("{g}: no group is waiting yet"),
            }
        }
        assert_eq!(announced.len(), TOTAL_PER_SECOND, "the first second's room");
        assert_eq!(waits.len(), 300 - TOTAL_PER_SECOND);
        // Each waiter wakes at its time and asks again, in the order of the
        // wakes (the order they were deferred in), until told to announce.
        let mut queue: std::collections::BinaryHeap<std::cmp::Reverse<(Duration, usize, Name)>> =
            waits
                .into_iter()
                .enumerate()
                .map(|(i, (w, g))| std::cmp::Reverse((w, i, g)))
                .collect();
        while let Some(std::cmp::Reverse((at, i, g))) = queue.pop() {
            match gate.due(t0 + at, &g) {
                None => announced.push((at, g)),
                Some(again) => queue.push(std::cmp::Reverse((at + again, i, g))),
            }
        }
        assert_eq!(announced.len(), 300, "none dropped");
        let distinct: BTreeSet<&Name> = announced.iter().map(|(_, g)| g).collect();
        assert_eq!(distinct.len(), 300, "each once");
        for (at, _) in &announced {
            let within = announced
                .iter()
                .filter(|(t, _)| *t >= *at && *t < *at + EVERY)
                .count();
            assert!(
                within <= TOTAL_PER_SECOND,
                "{within} announcements within a second from {at:?}, at most {TOTAL_PER_SECOND} expected"
            );
        }
        let last = announced.iter().map(|(t, _)| *t).max().unwrap();
        assert!(
            last <= Duration::from_secs((300 / TOTAL_PER_SECOND) as u64 + 1),
            "all announced by {last:?}: well within the group's period of half a minute"
        );
    }
}
