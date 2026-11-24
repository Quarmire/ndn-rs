//! Announcing a group's state again while no peer answers (spec §7.10): an own entry no peer is
//! seen to have taken, and a group joined whose peers were not heard.
//!
//! A change announced once is heard by a peer whose link did not drop it; one
//! that did hears it at the group's next periodic vector, half a minute by the
//! reference timing. The fetch is level-triggered by what the log wants, so
//! nothing a peer asks depends on a notice twice, but the *first* notice is
//! what makes a peer want the entry at all (a counter names it): a notice lost
//! on the way to the only peer that wants the entry costs that whole period.
//!
//! This device therefore announces its newest entry again, after a pause that
//! doubles from a quarter second and is capped at seconds
//! ([`fetch::retry_pause`]), until a peer is seen to have taken it: the group's
//! vector shows a peer carries this device's counter at that seq, or a peer
//! asked this device for that entry or a later one. A fixed few announcements
//! are made whatever is seen (a group has more than one peer, and one that took
//! the entry says nothing of the others), and at most [`HERALD_MAX`] in all: a
//! forged counter or an absent peer costs a bounded handful of Sync Interests
//! per change, never one a period. An announcement decides nothing at a peer: a
//! counter only names an entry to be fetched and judged (D17).
//!
//! A joined group is announced again in the same way while no notice of it was heard
//! ([`Herald::hail`]): the join announcement, or the vector a peer sent back to it, may be what a
//! lossy link dropped, and the group's next period is half a minute away. Peers that wrote
//! nothing never answer, so this too is bounded by [`HERALD_MAX`].

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use ndn_foundation_types::Name;
use ndn_sync::{MultiSvs, ObservedState};
use tokio_util::sync::CancellationToken;

use crate::fetch::retry_pause;
use crate::rt;
use crate::sync::TIMELINE;

/// The announcements made whatever is seen of the peers: one takes the notice,
/// and a group of several peers has several links that may have dropped it.
const HERALD_MIN: u32 = 3;

/// The most announcements made again for one change, or for one join: the pauses before them
/// (`retry_pause`) add up to about twenty seconds, within the group's period.
const HERALD_MAX: u32 = 8;

/// One group's announcing again of this device's own newest entry, and of the group when no one
/// was heard in it.
pub(crate) struct Herald {
    svs: Arc<MultiSvs>,
    group: Name,
    device: Name,
    /// The driver's observed state: what peers' vectors carry of this device.
    observed: Arc<ObservedState>,
    /// A notice of the group was heard (`Group::heard_any`, the same flag).
    heard: Arc<AtomicBool>,
    stop: CancellationToken,
    /// The highest seq of this device announced in the group.
    announced: AtomicU64,
    /// The highest seq of this device a peer asked for.
    taken: AtomicU64,
    /// A run of announcements is under way.
    running: AtomicBool,
}

impl Herald {
    pub(crate) fn new(
        svs: Arc<MultiSvs>,
        group: Name,
        device: Name,
        observed: Arc<ObservedState>,
        heard: Arc<AtomicBool>,
        stop: CancellationToken,
    ) -> Arc<Herald> {
        Arc::new(Herald {
            svs,
            group,
            device,
            observed,
            heard,
            stop,
            announced: AtomicU64::new(0),
            taken: AtomicU64::new(0),
            running: AtomicBool::new(false),
        })
    }

    /// This device joined the group and announced itself (the driver's join announcement):
    /// announce again, after each pause of the capped doubling, until a notice of the group is
    /// heard or [`HERALD_MAX`] were made. A peer that is ahead answers an announcement with its
    /// vector; one announcement and one answer both have to cross the link.
    pub(crate) fn hail(self: &Arc<Self>) {
        let herald = Arc::clone(self);
        rt::spawn(async move {
            for again in 0..HERALD_MAX {
                rt::sleep(retry_pause(again)).await;
                if herald.stop.is_cancelled() || herald.heard.load(Ordering::Relaxed) {
                    return;
                }
                tracing::trace!(target: TIMELINE, group = %herald.group, again, "announce");
                herald.svs.announce(herald.group.clone()).await;
            }
        });
    }

    /// A peer asked this device for its entry `seq` of the group's space.
    pub(crate) fn taken(&self, seq: u64) {
        self.taken.fetch_max(seq, Ordering::SeqCst);
    }

    /// This device announced its entry `seq` (the announcement went out
    /// already): see to it that it is announced again while no peer took it.
    pub(crate) fn announced(self: &Arc<Self>, seq: u64) {
        self.announced.fetch_max(seq, Ordering::SeqCst);
        if !self.running.swap(true, Ordering::SeqCst) {
            rt::spawn(Arc::clone(self).run());
        }
    }

    /// Whether a peer is seen to have taken the entry `seq`.
    fn seen_taken(&self, seq: u64) -> bool {
        self.taken.load(Ordering::SeqCst) >= seq
            || self
                .observed
                .seq_for(&self.device)
                .is_some_and(|carried| carried >= seq)
    }

    /// Announce again, after each pause, until the newest entry announced is
    /// taken (and the least number was made) or [`HERALD_MAX`] were. A newer
    /// entry announced meanwhile starts the pauses again.
    async fn run(self: Arc<Self>) {
        loop {
            let mut newest = self.announced.load(Ordering::SeqCst);
            let mut again = 0;
            loop {
                rt::sleep(retry_pause(again)).await;
                if self.stop.is_cancelled() {
                    self.running.store(false, Ordering::SeqCst);
                    return;
                }
                let now = self.announced.load(Ordering::SeqCst);
                if now != newest {
                    (newest, again) = (now, 0);
                    continue;
                }
                if again >= HERALD_MAX || (again >= HERALD_MIN && self.seen_taken(newest)) {
                    break;
                }
                tracing::trace!(target: TIMELINE, group = %self.group, again, "announce");
                self.svs.announce(self.group.clone()).await;
                again += 1;
            }
            self.running.store(false, Ordering::SeqCst);
            // An entry announced after the last look, while this run was
            // ending, was not seen by a run: take the flag back and go on.
            if self.announced.load(Ordering::SeqCst) == newest
                || self.running.swap(true, Ordering::SeqCst)
            {
                return;
            }
        }
    }
}
