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

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, Weak};
use std::time::Duration;

use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_packet::Interest;
use ndn_packet::encode::InterestBuilder;
use ndn_security::ReplayGuard;
use ndn_transport::FaceId;
use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use tokio::sync::Notify;

use super::answer::{ASK_CLOCK_WINDOW_MS, ChanAnswer};
use super::bar::BarSlot;
use super::channels::Channels;
use super::evidence::EvidenceLog;
use super::gates::Gates;
use super::route::Routes;
use super::rx::{Receivers, RxStats};
use super::sessions::{EndReason, RecvSessions};
use super::standing::{Who, gate, standing};
use super::tx::Tx;
use super::verify::Bucket;
use super::wire::{Announce, ChannelMode};
use crate::node::NodeInner;
use crate::query::QueryOutcome;
use crate::rt::{self, Instant};
use crate::wire::{chan_prefix, is_device_name, parse_chan_announce_name, sync_group_of};

/// How often the maintenance task looks at the channels without being woken.
pub(crate) const TICK: Duration = Duration::from_millis(250);

/// The shortest time between two announce-driven asks of one device **for one mode**. The
/// announce is unsigned, so the claim "this device has a channel in this mode" is anyone's to
/// make; keying the limit by mode keeps a claim for a mode the device does not have from using
/// up the window of the mode it does.
pub(crate) const ANNOUNCE_ASK_EVERY: Duration = Duration::from_secs(10);

/// The most announce-driven asks one space has in progress.
pub(crate) const ANNOUNCE_PENDING_MAX: usize = 32;

/// The announce-driven asks (one per mode) of devices **the record holds no admitted entry of**
/// and that never answered one (a writer who has put nothing and was not heard from yet, or a
/// name nobody holds) a space may begin in a burst, and then a second: the announce is unsigned,
/// so any name under a writer's namespace passes for a device of hers, and the ask it makes
/// costs this device one signature and an Interest. The pool is its own, so a stranger's names
/// never take what the devices the record vouches for need. It is one pool for the space, not
/// one per claimed person: the persons are the writers of the record, and a pool each would
/// multiply what a stranger may make this device spend by their number.
pub(crate) const ANNOUNCE_UNVOUCHED_BURST: f64 = 4.0;

/// The rate, a second, at which [`ANNOUNCE_UNVOUCHED_BURST`] fills again.
pub(crate) const ANNOUNCE_UNVOUCHED_RATE: f64 = 1.0;

/// The most octets of an announce's ApplicationParameters.
const ANNOUNCE_MAX: usize = 1024;

/// The devices that answered an announce-driven ask this node remembers as vouched for (those
/// beyond it take the bucket, as a device never heard from does).
const ANNOUNCE_ANSWERED_MAX: usize = 1024;

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

    #[cfg(any(test, feature = "adversary"))]
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
    /// Announces of a writer that were not acted on (not wanted, over a limit, or a name that is
    /// no device's).
    pub(crate) announce_ignored: Counter,
    /// Asks an announce made this device send.
    pub(crate) announce_asks: Counter,
    /// What the receiver counted: why each frame was dropped, and what each cost.
    pub(crate) rx: RxStats,
}

/// What the announces heard are limited by.
#[derive(Default)]
pub(crate) struct Heard {
    /// When each `(space, device, mode)` was last let make an ask.
    asked: HashMap<(Name, Name, ChannelMode), Instant>,
    pending: HashMap<Name, usize>,
    /// Per space, what is left of the asks of devices the record holds no entry of and that
    /// never answered one.
    unvouched: HashMap<Name, Bucket>,
    /// The `(space, device)` pairs whose answer to an announce-driven ask was judged good: a
    /// signed answer by a key that stands as a writer, so the device is no name a stranger made
    /// up. At most [`ANNOUNCE_ANSWERED_MAX`].
    answered: HashSet<(Name, Name)>,
}

impl Heard {
    /// The modes of an announce of `device` over `space` that may make an ask at `now`, and none
    /// when it may make none: a mode is left out when it was asked of that device sooner than
    /// [`ANNOUNCE_ASK_EVERY`] ago, all are when [`ANNOUNCE_PENDING_MAX`] announces are in
    /// progress for the space, and, for a device the record holds no admitted entry of
    /// (`vouched` false) that never answered, each mode takes a token of the space's own bucket
    /// ([`ANNOUNCE_UNVOUCHED_BURST`]) and the modes beyond the tokens are left out. Nothing is
    /// spent, stamped or counted for a mode that is left out, or when `modes` is empty. If any
    /// is let through, the announce is counted in progress ([`Self::done`]).
    pub(crate) fn admit(
        &mut self,
        space: &Name,
        device: &Name,
        modes: &[ChannelMode],
        vouched: bool,
        now: Instant,
    ) -> Vec<ChannelMode> {
        let key = |mode: ChannelMode| (space.clone(), device.clone(), mode);
        let mut due: Vec<ChannelMode> = modes
            .iter()
            .copied()
            .filter(|mode| {
                self.asked
                    .get(&key(*mode))
                    .is_none_or(|at| now.saturating_duration_since(*at) >= ANNOUNCE_ASK_EVERY)
            })
            .collect();
        if due.is_empty() || self.pending.get(space).copied().unwrap_or(0) >= ANNOUNCE_PENDING_MAX {
            return Vec::new();
        }
        if !vouched && !self.answered.contains(&(space.clone(), device.clone())) {
            let bucket = self
                .unvouched
                .entry(space.clone())
                .or_insert_with(|| Bucket::new(ANNOUNCE_UNVOUCHED_RATE, ANNOUNCE_UNVOUCHED_BURST));
            let granted = due.iter().take_while(|_| bucket.take(now)).count();
            due.truncate(granted);
            if due.is_empty() {
                return due;
            }
        }
        if self.asked.len() > 4096 {
            self.asked
                .retain(|_, at| now.saturating_duration_since(*at) < ANNOUNCE_ASK_EVERY);
        }
        for mode in &due {
            self.asked.insert(key(*mode), now);
        }
        *self.pending.entry(space.clone()).or_default() += 1;
        due
    }

    /// The announce-driven asks of one announce over `space` are over.
    fn done(&mut self, space: &Name) {
        if let Some(n) = self.pending.get_mut(space) {
            *n = n.saturating_sub(1);
        }
    }

    /// `device` answered an announce-driven ask over `space` with a session judged good: later
    /// announces of it take no token of the bucket.
    pub(crate) fn answered(&mut self, space: &Name, device: &Name) {
        if self.answered.len() < ANNOUNCE_ANSWERED_MAX {
            self.answered.insert((space.clone(), device.clone()));
        }
    }

    /// Whether `device` answered an announce-driven ask over `space` (a test asks).
    #[cfg(test)]
    pub(crate) fn has_answered(&self, space: &Name, device: &Name) -> bool {
        self.answered.contains(&(space.clone(), device.clone()))
    }
}

#[cfg(test)]
thread_local! {
    /// The octets of ApplicationParameters [`announce_params`] hashed on this thread.
    pub(crate) static ANNOUNCE_HASHED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// The ApplicationParameters of an announce, if they are at most [`ANNOUNCE_MAX`] octets and
/// hash to `digest` (the name's `ParametersSha256Digest`, made as the Interest's is). The length
/// is checked first, so no more than 1 KiB (and the few octets of the TLV header) is ever
/// hashed, whatever the Interest carries.
pub(crate) fn announce_params(interest: &Interest, digest: &[u8]) -> Option<Bytes> {
    let params = interest.app_parameters()?;
    if params.len() > ANNOUNCE_MAX {
        return None;
    }
    let portion = interest.parameters_portion()?;
    #[cfg(test)]
    ANNOUNCE_HASHED.with(|n| n.set(n.get() + portion.len()));
    (Sha256::digest(&portion).as_slice() == digest).then(|| params.clone())
}

/// What a node keeps of channels.
pub(crate) struct Chan {
    /// This device's channels as a sender.
    pub(crate) channels: Channels,
    /// The budgets an ask passes before its signature is known good, per ingress face and for
    /// the node ([`super::gates`]).
    pub(crate) gates: Gates,
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
            gates: Gates::default(),
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
/// The future of a [`ChanPort::query`].
#[cfg(not(target_arch = "wasm32"))]
pub(crate) type QueryFuture<'a> = futures::future::BoxFuture<'a, QueryOutcome>;
/// The future of a [`ChanPort::query`].
#[cfg(target_arch = "wasm32")]
pub(crate) type QueryFuture<'a> = futures::future::LocalBoxFuture<'a, QueryOutcome>;

/// What the network half asks of the node for channels: the answer to an ask, and an announce
/// heard. The network half holds it weakly and only once the node is whole.
pub(crate) trait ChanPort: Send + Sync {
    /// Answer an ask (`serve::chan`) that arrived over the forwarder's face `ingress`, when the
    /// connection says which.
    fn answer(&self, interest: Interest, ingress: Option<FaceId>) -> PortFuture<'_>;
    /// Answer a query (`serve::query`) that arrived over the forwarder's face `ingress`: a
    /// signed answer, a Nack, or nothing.
    fn query(&self, interest: Interest, ingress: Option<FaceId>) -> QueryFuture<'_>;
    /// An announce was heard on the sync face (never answered).
    fn heard(&self, interest: &Interest);
}

/// The port of a node, set once.
pub(crate) type PortCell = Arc<OnceLock<Weak<dyn ChanPort>>>;

impl ChanPort for NodeInner {
    fn answer(&self, interest: Interest, ingress: Option<FaceId>) -> PortFuture<'_> {
        Box::pin(async move { self.chan_answer(&interest, ingress).await })
    }

    fn query(&self, interest: Interest, ingress: Option<FaceId>) -> QueryFuture<'_> {
        Box::pin(async move { self.query_answer(&interest, ingress).await })
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

    /// Push the announce of this device over `space`: one unsigned Interest
    /// `<sync group>/32=chan/<digest>`, ApplicationParameters this device, its channel modes and
    /// the prefixes it serves queries under (at most 16 names and 512 octets of name values,
    /// shortest first: the rest are left out), lifetime 1 s, HopLimit 8. A device with no
    /// channel announces its prefixes alone (no mode), and one with neither announces nothing:
    /// the hint of a device that stopped serving lapses after 90 s when no channel lets it say
    /// so. It is answered by nobody and cached nowhere; a receiver takes it as a hint.
    pub(crate) async fn chan_announce(&self, space: &Name) {
        let modes = self.chan.channels.modes(space);
        let serves = self.query_serves(space);
        let Some(group) = sync_group_of(space).filter(|_| !modes.is_empty() || !serves.is_empty())
        else {
            return;
        };
        let record = Announce {
            sender: self.device.clone(),
            modes,
            serves,
        }
        .encode();
        let wire = InterestBuilder::new(chan_prefix(&group))
            .lifetime(Duration::from_secs(1))
            .hop_limit(8)
            .app_parameters(record.to_vec())
            .build();
        let now = Instant::now();
        self.chan.channels.announced(space, now);
        self.query.server.announced(space, now);
        if let Some(net) = self.net()
            && net.send_sync(wire).await.is_ok()
        {
            self.chan.stats.announces_sent.bump();
        }
    }

    /// An announce was heard (`ChanPort::heard`): a hint, and nothing more. It costs, cheapest
    /// first: a hash of at most 1 KiB (the length is checked before it), a lookup of the
    /// announcer's person in the record of the space (the person its name lies in, which is no
    /// entry's to say), a table lookup of whether this device wants live data of the space and
    /// one of whether it holds a usable session of each announced mode already; only an announce
    /// of a writer's device with a mode no usable session covers can make an ask, each device
    /// for each mode at most once in 10 s, at most 32 announces with asks in progress for a
    /// space, and, for a device the record holds no admitted entry of that never answered one
    /// (a writer who has put nothing is such a device), each ask within a bucket of the space's
    /// own. Nothing is spent where no ask follows. The ask is the check: the answer is judged by
    /// signature from the certificates it carries, so nothing is fetched and a name no device
    /// answers costs one ask.
    pub(crate) fn chan_heard(&self, interest: &Interest) {
        let stats = &self.chan.stats;
        stats.announces_heard.bump();
        let Some((group, digest)) = parse_chan_announce_name(&interest.name) else {
            return;
        };
        let Some(params) = announce_params(interest, &digest) else {
            return;
        };
        let Ok(Announce {
            sender,
            modes,
            serves,
        }) = Announce::decode(params)
        else {
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
        // that writer's devices, whether or not the record holds an entry of it (a writer who
        // has put nothing holds none). What is cheap to say of a name is said before an ask
        // slot is spent: a device name, under no reserved prefix.
        if !vouched && (!is_device_name(&sender) || super::ask::is_reserved(&sender)) {
            stats.announce_ignored.bump();
            return;
        }
        // The prefixes it says it serves are a hint too, recorded whatever is decided about
        // asking it for a channel (a device that only serves has no mode to ask for); an
        // announce that lists none removes the device's hint.
        self.query
            .hints
            .record(&space, &sender, &serves, Instant::now());
        let now = Instant::now();
        if !self.chan.is_listening(&space) {
            stats.announce_ignored.bump();
            return;
        }
        // A mode a usable session covers needs no ask, so it takes no token and no slot.
        let modes: Vec<ChannelMode> = modes
            .into_iter()
            .filter(|mode| {
                !self
                    .chan
                    .sessions
                    .find(&space, &sender, *mode)
                    .is_some_and(|s| s.usable(now))
            })
            .collect();
        let asks = self
            .chan
            .heard
            .lock()
            .admit(&space, &sender, &modes, vouched, now);
        if asks.is_empty() {
            stats.announce_ignored.bump();
            return;
        }
        stats.announce_asks.bump();
        let node = self.arc();
        self.tasks.spawn(async move {
            for mode in asks {
                match node.chan_ask(&space, &sender, mode).await {
                    Ok(session) => {
                        node.chan.heard.lock().answered(&space, &sender);
                        node.chan_release_unwanted(&session);
                    }
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
        // The prefixes this device serves are announced as often, and the pair keys of askers
        // that no longer stand go with the move that removed them.
        announce.extend(
            self.query
                .server
                .announce_due(&self.query.table.spaces(), now),
        );
        self.query_rejudge();
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
