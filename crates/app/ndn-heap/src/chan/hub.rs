//! What a node keeps of channels, and what runs them: the sender's table, the receiver's
//! sessions, the counters, the announce and the one maintenance task (docs/specs/channel.md,
//! Ended and renewed, Announce).
//!
//! The maintenance task runs every [`TICK`] and at once when the node wakes it (the members of a
//! space changed, a trust context was adopted). It decides nothing a call does not decide again
//! from what is held: an ask judges the entries held now, a frame checks [`is_current`]; the task
//! is what makes the consequence follow without waiting for either (a re-key, a dropped
//! receiver, a renewal, the announce).
//!
//! [`is_current`]: super::sessions::RecvSession::is_current

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, Weak};
use std::time::Duration;

use ndn_foundation_types::Name;
use ndn_packet::Interest;
use ndn_packet::encode::InterestBuilder;
use ndn_security::ReplayGuard;
use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use tokio::sync::Notify;

use super::answer::{ASK_CLOCK_WINDOW_MS, ChanAnswer};
use super::bar::BarSlot;
use super::channels::Channels;
use super::evidence::EvidenceLog;
use super::route::Routes;
use super::rx::{Receivers, RxStats};
use super::sessions::{EndReason, RecvSessions};
use super::standing::{Who, gate, standing};
use super::tx::Tx;
use super::wire::Announce;
use crate::node::NodeInner;
use crate::rt::{self, Instant};
use crate::wire::{chan_prefix, parse_chan_announce_name, sync_group_of};

/// How often the maintenance task looks at the channels without being woken.
pub(crate) const TICK: Duration = Duration::from_millis(250);

/// The shortest time between two announce-driven asks of one device.
pub(crate) const ANNOUNCE_ASK_EVERY: Duration = Duration::from_secs(10);

/// The most announce-driven asks one space has in progress.
pub(crate) const ANNOUNCE_PENDING_MAX: usize = 32;

/// The most octets of an announce's ApplicationParameters.
const ANNOUNCE_MAX: usize = 1024;

/// The asks of one key the replay guard remembers: an ask is good for 240 s
/// ([`ASK_CLOCK_WINDOW_MS`] either side of the sender's clock), and a key's asks are admitted at
/// 4 a second after a burst of 8, which is 968 in that time.
pub(crate) const REPLAY_PER_KEY: usize = 1024;

const _: () = assert!(REPLAY_PER_KEY as u64 >= 8 + 4 * (2 * ASK_CLOCK_WINDOW_MS / 1000));

/// A counter.
#[derive(Default)]
pub(crate) struct Counter(AtomicU64);

impl Counter {
    pub(crate) fn bump(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn add(&self, n: u64) {
        self.0.fetch_add(n, Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(crate) fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// What the setup counted: the proof of what an ask cost and why one was not answered.
#[derive(Default)]
pub(crate) struct Stats {
    /// Asks that reached the sender's judgement.
    pub(crate) asks: Counter,
    /// Asks that did not parse (name, digest, ask, key).
    pub(crate) malformed: Counter,
    /// Asks over 8 KiB.
    pub(crate) oversize: Counter,
    /// Asks of a key that stands for no space of this device.
    pub(crate) strangers: Counter,
    /// Asks over the asker's rate (counted after the signature verified).
    pub(crate) throttled: Counter,
    /// Asks whose `SignatureTime` was more than 120 s from this device's clock.
    pub(crate) stale: Counter,
    /// Asks over the budget of signature verifications (64 a second, whoever they name).
    pub(crate) shed: Counter,
    /// Asks whose signer's chain could not be judged yet.
    pub(crate) pending: Counter,
    /// Asks whose signature did not verify.
    pub(crate) unverified: Counter,
    /// Asks that were replays.
    pub(crate) replays: Counter,
    /// Signed refusals sent.
    pub(crate) refused: Counter,
    /// Sessions sent.
    pub(crate) answered: Counter,
    /// Channels re-keyed by a renewal.
    pub(crate) rekeys: Counter,
    /// Asks this device sent.
    pub(crate) asked: Counter,
    /// Sessions this device installed or renewed.
    pub(crate) installed: Counter,
    /// Announces sent.
    pub(crate) announces_sent: Counter,
    /// Announces heard.
    pub(crate) announces_heard: Counter,
    /// Announces of a device that is no writer of the space (a lookup and nothing else).
    pub(crate) announce_strangers: Counter,
    /// Announces of a writer that were not acted on (not wanted, over a limit, or of a device the
    /// record holds no admitted entry of).
    pub(crate) announce_ignored: Counter,
    /// Asks an announce made this device send.
    pub(crate) announce_asks: Counter,
    /// What the receiver counted: why each frame was dropped, and what each cost.
    pub(crate) rx: RxStats,
}

/// What the announces heard are limited by.
#[derive(Default)]
struct Heard {
    asked: HashMap<(Name, Name), Instant>,
    pending: HashMap<Name, usize>,
}

impl Heard {
    /// Whether an announce of `device` over `space` may make an ask at `now`: not one of that
    /// device sooner than [`ANNOUNCE_ASK_EVERY`] ago, and not past [`ANNOUNCE_PENDING_MAX`] in
    /// progress for the space. If it may, it is counted in progress.
    fn admit(&mut self, space: &Name, device: &Name, now: Instant) -> bool {
        let key = (space.clone(), device.clone());
        if self
            .asked
            .get(&key)
            .is_some_and(|at| now.saturating_duration_since(*at) < ANNOUNCE_ASK_EVERY)
        {
            return false;
        }
        if self.pending.get(space).copied().unwrap_or(0) >= ANNOUNCE_PENDING_MAX {
            return false;
        }
        if self.asked.len() > 4096 {
            self.asked
                .retain(|_, at| now.saturating_duration_since(*at) < ANNOUNCE_ASK_EVERY);
        }
        self.asked.insert(key, now);
        *self.pending.entry(space.clone()).or_default() += 1;
        true
    }

    fn done(&mut self, space: &Name) {
        if let Some(n) = self.pending.get_mut(space) {
            *n = n.saturating_sub(1);
        }
    }
}

/// What a node keeps of channels.
pub(crate) struct Chan {
    /// This device's channels as a sender.
    pub(crate) channels: Channels,
    /// The sessions this device holds as a receiver.
    pub(crate) sessions: RecvSessions,
    /// The sender's frame layer: its channels' writers and the fixed route's carrier.
    pub(crate) tx: Tx,
    /// The receiver: the channels this device takes frames of, and the `Items` it pushes to.
    pub(crate) rx: Receivers,
    /// The replay guard of the signed asks: it remembers the last [`REPLAY_PER_KEY`] asks of each
    /// key, which is the 240 s an ask is good for ([`ASK_CLOCK_WINDOW_MS`]) at the rate of 4 a
    /// second after a burst of 8. It is empty after a restart: what covers a restart is the clock
    /// window alone.
    pub(crate) replay: ReplayGuard,
    /// What was counted.
    pub(crate) stats: Stats,
    /// The node's routes in the forwarder it runs on ([`super::route`]).
    pub(crate) route: Arc<Routes>,
    /// What bars a face from channel frames when a frame it carried was forged.
    pub(crate) bar: BarSlot,
    /// The last [`super::evidence::EVIDENCE_KEPT`] frames shown not to be a sender's.
    pub(crate) evidence: EvidenceLog,
    /// Test seam: while set, the node's channels send no checkpoints (their sessions say
    /// `S_CKPT_MS` 0), so the tests of frames and batching see the frames they sent and nothing
    /// else. The checkpoint tests clear it.
    #[cfg(test)]
    pub(crate) checkpoints_off: std::sync::atomic::AtomicBool,
    wake: Arc<Notify>,
    listening: Mutex<HashMap<Name, usize>>,
    heard: Mutex<Heard>,
    /// Test seam: while set, the maintenance pass does nothing, so a test can show what the frame
    /// layer decides before the node's own pass has noticed a change.
    #[cfg(test)]
    pub(crate) tick_paused: std::sync::atomic::AtomicBool,
}

impl Chan {
    pub(crate) fn new() -> Chan {
        Chan {
            channels: Channels::default(),
            sessions: RecvSessions::default(),
            tx: Tx::default(),
            rx: Receivers::default(),
            replay: ReplayGuard::new(REPLAY_PER_KEY, false),
            stats: Stats::default(),
            route: Arc::new(Routes::default()),
            bar: BarSlot::default(),
            evidence: EvidenceLog::default(),
            #[cfg(test)]
            checkpoints_off: std::sync::atomic::AtomicBool::new(true),
            wake: Arc::new(Notify::new()),
            listening: Mutex::new(HashMap::new()),
            heard: Mutex::new(Heard::default()),
            #[cfg(test)]
            tick_paused: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Wake the maintenance task now.
    pub(crate) fn wake(&self) {
        self.wake.notify_one();
    }

    fn is_listening(&self, space: &Name) -> bool {
        self.listening.lock().get(space).is_some_and(|n| *n > 0)
    }
}

/// While held, announces of senders over a space make this device ask them: a `get` of the space
/// holds one, so a device that wants nothing live asks nobody.
pub(crate) struct Listen {
    node: Arc<NodeInner>,
    space: Name,
}

impl Drop for Listen {
    fn drop(&mut self) {
        let mut listening = self.node.chan.listening.lock();
        if let Some(n) = listening.get_mut(&self.space) {
            *n -= 1;
            if *n == 0 {
                listening.remove(&self.space);
            }
        }
    }
}

/// The future of a [`ChanPort::answer`].
#[cfg(not(target_arch = "wasm32"))]
pub(crate) type PortFuture<'a> = futures::future::BoxFuture<'a, ChanAnswer>;
/// The future of a [`ChanPort::answer`].
#[cfg(target_arch = "wasm32")]
pub(crate) type PortFuture<'a> = futures::future::LocalBoxFuture<'a, ChanAnswer>;

/// What the network half asks of the node for channels: the answer to an ask, and an announce
/// heard. The network half holds it weakly and only once the node is whole.
pub(crate) trait ChanPort: Send + Sync {
    /// Answer an ask (`serve::chan`).
    fn answer(&self, interest: Interest) -> PortFuture<'_>;
    /// An announce was heard on the sync face (never answered).
    fn heard(&self, interest: &Interest);
}

/// The port of a node, set once.
pub(crate) type PortCell = Arc<OnceLock<Weak<dyn ChanPort>>>;

impl ChanPort for NodeInner {
    fn answer(&self, interest: Interest) -> PortFuture<'_> {
        Box::pin(async move { self.chan_answer(&interest).await })
    }

    fn heard(&self, interest: &Interest) {
        self.chan_heard(interest);
    }
}

impl NodeInner {
    /// Hold the interest of announces over `space` until the guard drops.
    pub(crate) fn chan_listen(&self, space: &Name) -> Listen {
        *self.chan.listening.lock().entry(space.clone()).or_default() += 1;
        Listen {
            node: self.arc(),
            space: space.clone(),
        }
    }

    /// Push the announce of this device's channels over `space`: one unsigned Interest
    /// `<sync group>/32=chan/<digest>`, ApplicationParameters this device and its modes, lifetime 1 s,
    /// HopLimit 8. It is answered by nobody and cached nowhere; a receiver takes it as a hint.
    pub(crate) async fn chan_announce(&self, space: &Name) {
        let modes = self.chan.channels.modes(space);
        let Some(group) = sync_group_of(space).filter(|_| !modes.is_empty()) else {
            return;
        };
        let record = Announce {
            sender: self.device.clone(),
            modes,
        }
        .encode();
        let wire = InterestBuilder::new(chan_prefix(&group))
            .lifetime(Duration::from_secs(1))
            .hop_limit(8)
            .app_parameters(record.to_vec())
            .build();
        self.chan.channels.announced(space, Instant::now());
        if let Some(net) = self.net()
            && net.send_sync(wire).await.is_ok()
        {
            self.chan.stats.announces_sent.bump();
        }
    }

    /// An announce was heard (`ChanPort::heard`): a hint, and nothing more. It costs a lookup of
    /// the announcer's person in the record of the space; only a writer's device of which the
    /// record holds an admitted entry, while this device wants live data of the space, makes it
    /// ask, each device at most once in 10 s and at most 32 asks in progress for a space.
    pub(crate) fn chan_heard(&self, interest: &Interest) {
        let stats = &self.chan.stats;
        stats.announces_heard.bump();
        let Some((group, digest)) = parse_chan_announce_name(&interest.name) else {
            return;
        };
        let Some(params) = interest.app_parameters().cloned() else {
            return;
        };
        let digest_holds = interest
            .parameters_portion()
            .is_some_and(|portion| Sha256::digest(&portion).as_slice() == digest);
        if params.len() > ANNOUNCE_MAX || !digest_holds {
            return;
        }
        let Ok(Announce { sender, modes }) = Announce::decode(params) else {
            return;
        };
        if sender == self.device {
            return;
        }
        let Some(space) = self
            .member_spaces()
            .into_iter()
            .find(|s| sync_group_of(s).as_ref() == Some(&group))
        else {
            return;
        };
        let (writer, vouched) = self.space_of(&space).map_or((false, false), |held| {
            let person = self.person_of(&sender);
            let log = held.log.lock();
            (log.fold.is_writer(&person), log.vouches(&sender))
        });
        if !writer {
            stats.announce_strangers.bump();
            return;
        }
        // The announce is unsigned, so any name under a writer's namespace passes for one of
        // that writer's devices. Only a device the record holds an admitted entry of (its key was
        // judged for the space, its certificate is held) is worth an ask slot; any other is
        // asked by name (`ask_channel`), not by hint.
        if !vouched {
            stats.announce_ignored.bump();
            return;
        }
        let now = Instant::now();
        if !self.chan.is_listening(&space) || !self.chan.heard.lock().admit(&space, &sender, now) {
            stats.announce_ignored.bump();
            return;
        }
        stats.announce_asks.bump();
        let node = self.arc();
        self.tasks.spawn(async move {
            for mode in modes {
                let held = node.chan.sessions.find(&space, &sender, mode);
                if held.is_some_and(|s| s.usable(Instant::now())) {
                    continue;
                }
                match node.chan_ask(&space, &sender, mode).await {
                    Ok(session) => node.chan_release_unwanted(&session),
                    Err(why) => {
                        tracing::debug!(%space, %sender, ?mode, "announce-driven ask failed: {why}");
                    }
                }
            }
            node.chan.heard.lock().done(&space);
        });
    }

    /// Judge the receivers of this device's channels over `space` again from what is held now
    /// (offline, in one call): a receiver that no longer stands, or whose person left the audience,
    /// is dropped and the channel is re-keyed; a channel whose audience epoch moved is re-keyed.
    /// A device that is no writer of the space any more ends its channels of it. Returns what was
    /// done.
    pub(crate) fn chan_rejudge(&self, space: &Name, now: Instant) -> super::channels::Rejudged {
        let Some(held) = self.space_of(space).filter(|s| !s.follower) else {
            self.chan_close_space(space);
            return Default::default();
        };
        let log = held.log.lock();
        let judged_at = (
            self.judge.generation(),
            log.fold.version().load(Ordering::SeqCst),
        );
        if gate(&log, &self.judge, Who::Writer, "channels").is_err() {
            self.chan_close_space(space);
            return Default::default();
        }
        let sealed = log.sealed();
        // A sealed space may hold no epoch in force for a moment: the removal of a reader reached
        // the record before the owner's new epoch did (the old epoch's holders are no longer all
        // readers). Then nobody can be judged against an audience, and a receiver that still
        // stands is kept; the epoch that arrives is judged when it does.
        let audience = if sealed { log.fold.in_force() } else { None };
        let members = audience.as_ref().map(|e| log.fold.audience(e));
        let stands = |_device: &Name, key: &Name| {
            let Ok(person) = standing(&log, &self.judge, key, Who::Listed) else {
                return false;
            };
            members.as_ref().is_none_or(|m| m.contains(&person))
        };
        self.chan
            .channels
            .rejudged(space, judged_at, audience.as_ref(), now, stands)
    }

    /// One pass of the maintenance task at `now`.
    pub(crate) async fn chan_tick(&self, now: Instant) {
        #[cfg(test)]
        if self.chan.tick_paused.load(Ordering::SeqCst) {
            return;
        }
        // The sender: the record or the trust generation moved, so the receivers are judged
        // again; what ran out ends; the channels are announced when due or when they changed.
        let mut announce = Vec::new();
        for space in self.chan.channels.spaces() {
            let live = self.space_of(&space).map(|s| {
                let version = s.log.lock().fold.version().load(Ordering::SeqCst);
                (self.judge.generation(), version)
            });
            let moved = live.is_none_or(|live| {
                self.chan
                    .channels
                    .judged_at(&space)
                    .iter()
                    .any(|(_, at)| *at != live)
            });
            if moved {
                let done = self.chan_rejudge(&space, now);
                if !done.dropped.is_empty() || !done.rekeyed.is_empty() {
                    announce.push(space);
                }
            }
        }
        let (_lapsed, _ended) = self.chan.channels.expire(now);
        // An idle channel says it is alive: an empty checkpoint every 5 s, nothing else.
        for tx in self.chan.tx.all() {
            tx.idle_checkpoint(now);
        }
        announce.extend(self.chan.channels.announce_due(now));
        announce.sort();
        announce.dedup();
        for space in announce {
            self.chan_announce(&space).await;
        }
        // The receiver: what lapsed ends; a session whose counters moved is judged again; a
        // session due its renewal asks again (the same channel, a new key and lifetime).
        self.chan.sessions.lapse(now);
        for session in self.chan.sessions.all() {
            if !session.is_current() {
                let _ = session.recheck(self);
            }
        }
        // The routes of the forwarder the node runs on, if it attached one: `Keep`s due, a
        // session nobody takes any more, `Unsub`s, `NoPath`.
        self.chan_route_tick(now);
        // The channels whose session ended or was replaced tell their `Items`; held messages
        // past 50 ms are dropped.
        self.chan.rx.sweep(self, now);
        for session in self.chan.sessions.due(now) {
            session.renewal_failed(now);
            let node = self.arc();
            self.tasks.spawn(async move {
                let (space, sender, mode) = (
                    session.space().clone(),
                    session.sender().clone(),
                    session.mode(),
                );
                if let Err(why) = node.chan_ask(&space, &sender, mode).await {
                    tracing::debug!(%space, %sender, ?mode, "renewal failed: {why}");
                }
            });
        }
    }

    /// The task that runs [`Self::chan_tick`] every [`TICK`] and when woken, until the node stops.
    pub(crate) async fn chan_task(node: Weak<NodeInner>) {
        loop {
            let wake = {
                let Some(inner) = node.upgrade() else { return };
                inner.chan_tick(Instant::now()).await;
                Arc::clone(&inner.chan.wake)
            };
            let _ = rt::timeout(TICK, wake.notified()).await;
        }
    }

    /// This device's channels end with the node: every session of every space is dropped.
    pub(crate) fn chan_stop(&self) {
        for session in self.chan.sessions.all() {
            session.end(EndReason::Left);
        }
        self.chan.rx.close_all();
    }
}
