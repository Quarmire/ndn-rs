//! A face that carries a joined sync group comes up: the device announces
//! that group's state vector at once (spec §12, "A face comes up"), instead
//! of at the group's next period (half a minute). A version committed while
//! no link was up was announced to no one; the link coming up is when
//! someone can hear it.
//!
//! The trigger is the forwarder's own: a route whose prefix covers a joined
//! group, got into its FIB on a face that is not a local application's
//! ([`ndn_app::Connection::routes`]). The device learns nothing about the
//! link layer, and the forwarder nothing about sync groups. A connection
//! that cannot tell routes (an IPC one) gives none, and the periodic
//! announcement alone runs, as before.
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

use super::*;
use ndn_app::{RouteEvents, RouteNews};
use std::sync::Weak;

/// At most one announcement per group in this long: a link that flaps adds
/// its routes again and again.
pub(super) const EVERY: Duration = Duration::from_secs(1);

/// What to do with a group a route came up for.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Verdict {
    /// Announce now.
    Now,
    /// Announce in this long (the end of the second since the last): the
    /// caller waits, then asks [`Gate::due`].
    After(Duration),
    /// An announcement is already waiting for its time: nothing to do,
    /// that one tells what this route brings too.
    Waiting,
}

/// When each group was last announced because a face came up, and which are
/// waiting for the end of their second.
#[derive(Default)]
pub(super) struct Gate {
    last: BTreeMap<Name, Instant>,
    waiting: BTreeSet<Name>,
}

impl Gate {
    /// A route came up for `ns`'s group at `now`.
    pub(super) fn ask(&mut self, now: Instant, ns: &Name) -> Verdict {
        if self.waiting.contains(ns) {
            return Verdict::Waiting;
        }
        match self.last.get(ns) {
            Some(&last) if now.saturating_duration_since(last) < EVERY => {
                self.waiting.insert(ns.clone());
                Verdict::After(EVERY - now.saturating_duration_since(last))
            }
            _ => {
                self.last.insert(ns.clone(), now);
                Verdict::Now
            }
        }
    }

    /// The wait of [`Verdict::After`] is over at `now`: whether to announce
    /// `ns`'s group (it is, once per wait).
    pub(super) fn due(&mut self, now: Instant, ns: &Name) -> bool {
        if !self.waiting.remove(ns) {
            return false;
        }
        self.last.insert(ns.clone(), now);
        true
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
    /// however many routes of the batch cover it, and at most once per
    /// [`EVERY`] (the first at once, a later one at the end of the second,
    /// so the last face up is told too).
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
                    Verdict::After(wait) => {
                        let (weak, gate) = (Weak::clone(&weak), Arc::clone(&gate));
                        rt::spawn(async move {
                            rt::sleep(wait).await;
                            let Some(inner) = weak.upgrade() else { return };
                            if !inner.stopped.load(Ordering::Relaxed)
                                && gate.lock().due(Instant::now(), &ns)
                            {
                                tracing::debug!(me = %inner.device, %ns, "a face carrying the group came up in the last second: its state announced");
                                inner.svs.announce(sync_group(&ns)).await;
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
        assert!(gate.due(t0 + Duration::from_secs(1), &ns()), "announced");
        assert!(!gate.due(t0 + Duration::from_secs(1), &ns()), "once");
        assert_eq!(
            gate.ask(t0 + Duration::from_millis(1500), &ns()),
            Verdict::After(Duration::from_millis(500)),
            "the second restarts from the announcement that waited"
        );
        assert!(gate.due(t0 + Duration::from_millis(2000), &ns()));
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
}
