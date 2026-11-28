//! The sender's channel table (docs/specs/channel.md, Sender): one channel per (space, mode), its
//! random id, its key and key epoch, and the receivers it answered.
//!
//! The table is pure state. Every operation takes the instant it happens at (a monotonic clock
//! the caller reads, so a test moves it by hand) and decides nothing about trust: who may be a
//! receiver is the caller's judgement, made from signed data before the table is touched
//! ([`answer`](super::answer)). A channel is re-keyed
//!
//! * when a receiver that holds the current key asks again after half its lifetime (a renewal),
//!   unless the channel was re-keyed in the last [`REKEY_MIN`],
//! * at once when a receiver is dropped because it no longer stands, or left the audience, or
//!   the sealed space's epoch in force moved ([`Channels::rejudged`]),
//! * when a receiver's lease ran out ([`Channels::expire`]), once [`REKEY_MIN`] has passed since
//!   the last re-key (the lapses of a stretch are one re-key), and
//! * before the sequence passes 2^63 ([`Channels::note_seq`]).
//!
//! Re-keying is pulled: nothing is sent to a receiver. One that sees a frame under a key epoch
//! it does not hold asks again, and is given the current key if the sender still answers it.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::time::Duration;

use ndn_foundation_types::Name;
use parking_lot::Mutex;

use super::key::{ChannelKey, FrameKey};
use super::limits;
use super::wire::{ChannelMode, LIFETIME_MAX, LIFETIME_MIN};
use crate::rt::Instant;
use crate::wire::EpochId;

/// The most channels one sender keeps.
pub(crate) const CHANNELS_PER_SENDER: usize = 64;

/// The most receivers one channel keeps.
pub(crate) const RECEIVERS_PER_CHANNEL: usize = 256;

/// The most receivers (askers) one `Ask` channel keeps: a receiver of it holds a pair of keys
/// (about 200 octets with its replay window) and no frames are sent to it, so the cap is four
/// times the others'.
pub(crate) const ASKERS_PER_CHANNEL: usize = 1_024;

/// The receivers `mode`'s channel keeps at most.
pub(crate) const fn receivers_cap(mode: ChannelMode) -> usize {
    match mode {
        ChannelMode::Ask => ASKERS_PER_CHANNEL,
        _ => RECEIVERS_PER_CHANNEL,
    }
}

/// The most receivers of one channel one person's devices may hold. A person chooses how many
/// devices ask with her keys, so the channel's places are bounded per person: no member can fill
/// them for the others (the channel keeps 256, so at least eight people can always be receivers).
/// A person has few devices; 32 is the bound the owner device keeps of one person's grantees too.
pub(crate) const RECEIVERS_PER_PERSON: usize = 32;

/// The lifetime of a session when the ask names none that is usable (seconds): one hour.
pub(crate) const LIFETIME_DEFAULT: u64 = 3600;

/// How long past its lifetime a receiver that did not renew stays a receiver.
pub(crate) const LEASE_GRACE: Duration = Duration::from_secs(5);

/// How often a live channel is announced again.
pub(crate) const ANNOUNCE_EVERY: Duration = Duration::from_secs(30);

/// The sequence a channel is re-keyed before it passes: 2^63 ([`limits::SEQUENCE_LIMIT`]).
pub(crate) const SEQ_REKEY: u64 = limits::SEQUENCE_LIMIT;

/// The asks per second one asker key may make, and its burst.
const ASKS_PER_SEC: f64 = 4.0;
const ASKS_BURST: f64 = 8.0;

/// The most askers a rate limiter keeps a bucket of: those past it that were idle longest go.
const BUCKETS_MAX: usize = 4096;

/// The shortest time between two re-keys that a receiver's renewal or lapsed lease causes. A
/// re-key makes every other receiver ask again, so what an asker can do must not make it
/// frequent: a receiver's ask is a re-key at most every 5 minutes. A removed or revoked receiver,
/// a moved audience epoch and the sequence limit re-key at once, whenever they happen.
pub(crate) const REKEY_MIN: Duration = Duration::from_secs(300);

/// A session's lifetime for an ask of `wanted` seconds: the ask's, at least a minute and at most
/// 24 hours, and an ask of none is the default. Clamped, never refused: a lifetime of a second
/// would make every ask a renewal and the receiver's lease run out in six.
pub(crate) fn lifetime_for(wanted: u64) -> u64 {
    match wanted {
        0 => LIFETIME_DEFAULT,
        w => w.clamp(LIFETIME_MIN, LIFETIME_MAX),
    }
}

/// A receiver the channel answered.
#[derive(Clone, Debug)]
struct Receiver {
    /// The key that signed its last ask: what is judged again when the record changes.
    key: Name,
    /// The key epoch of the key it was last given.
    delivered: u32,
    /// When it was last given a key, and for how long.
    issued: Instant,
    lifetime: Duration,
    /// The person its key belongs to.
    person: Name,
    /// The receiver is given the stream's frames; `false`: its path has none.
    stream: bool,
}

impl Receiver {
    fn lease_until(&self) -> Instant {
        self.issued + self.lifetime + LEASE_GRACE
    }
}

/// What the frame layer reads on every emission, without the table's lock or a key derivation.
#[derive(Default)]
pub(crate) struct Live {
    /// How many receivers the channel has now.
    pub(crate) receivers: AtomicUsize,
    /// How many of them are reached over a path with no stream (datagram class only): while
    /// there is one, every message names itself and nothing that needs the stream is sent.
    pub(crate) datagram_only: AtomicUsize,
    /// The key epoch (whole) frames are sealed under now.
    pub(crate) key_epoch: AtomicU32,
    /// The channel ended: it was closed or expired, or its space ended it.
    pub(crate) closed: AtomicBool,
}

/// One channel: one sender, one space, one mode, one key at a time.
pub(crate) struct Channel {
    id: u64,
    key: ChannelKey,
    key_epoch: u32,
    /// By receiver device.
    receivers: BTreeMap<Name, Receiver>,
    /// The next sequence the sender will use.
    next_seq: u64,
    /// The audience epoch the receivers were judged by, in a sealed space.
    audience: Option<EpochId>,
    /// What the judges said when the receivers were last judged: `(Judge::generation(), the
    /// space's fold version)`.
    judged_at: (u64, u64),
    last_announce: Option<Instant>,
    /// When the key was last made: the channel's start, or its last re-key.
    last_rekey: Instant,
    /// A receiver's lease ran out since the last re-key, and the channel is to be re-keyed once
    /// [`REKEY_MIN`] allows.
    rekey_owed: bool,
    /// Since when the channel has had no receiver.
    empty_since: Option<Instant>,
    /// What the frame layer reads on every emission.
    live: Arc<Live>,
}

/// What a receiver is given.
#[derive(Clone)]
pub(crate) struct Admitted {
    /// The channel id.
    pub(crate) id: u64,
    /// The key epoch.
    pub(crate) key_epoch: u32,
    /// The key to wrap.
    pub(crate) key: ChannelKey,
    /// The next sequence the sender will use.
    pub(crate) seq: u64,
    /// The audience epoch the receiver was judged by.
    pub(crate) audience: Option<EpochId>,
    /// The session's lifetime in seconds.
    pub(crate) lifetime: u64,
    /// Whether this ask re-keyed the channel.
    pub(crate) rekeyed: bool,
    /// Whether the asker's device was never a receiver of the channel before this ask (it takes
    /// a place in the table, which [`RECEIVERS_PER_CHANNEL`] bounds): the sender's welcome
    /// follows on the stream.
    pub(crate) fresh: bool,
    /// The ask says `ASK_NEW` and the device is already listed: a claim the sender cannot check
    /// ("I let this channel go, start me again"). It is given the welcome only when the channel's
    /// replay limiter lets it through, like an `ASK_SINCE`, so no asker makes the stream replay
    /// at its own rate.
    pub(crate) claim: bool,
}

/// Which cap a refused ask hit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Cap {
    /// [`CHANNELS_PER_SENDER`].
    Channels,
    /// [`RECEIVERS_PER_CHANNEL`].
    Receivers,
    /// [`RECEIVERS_PER_PERSON`]: the asker's person already has that many devices as receivers.
    Person,
}

/// What the table needs to know of an asker the caller judged.
pub(crate) struct Asker<'a> {
    /// The asker's device: one receiver per device.
    pub(crate) device: &'a Name,
    /// The person the asker's key belongs to, as the caller's judgement named her: receivers are
    /// counted per person ([`RECEIVERS_PER_PERSON`]).
    pub(crate) person: &'a Name,
    /// The key that signed the ask.
    pub(crate) key: &'a Name,
    /// The lifetime the ask wants, in seconds (0: none named).
    pub(crate) wanted: u64,
    /// The ask says the asker holds no session of the channel (`ASK_NEW`): a receiver the sender
    /// remembers, which let the session go and asks again, says it is new again (the sender is not
    /// told when a receiver lets go, unless it was the last one behind the forwarder). It is a
    /// claim, not a fact: [`Admitted::claim`].
    pub(crate) new: bool,
    /// The ask's carriers, once the first hop toward the asker is judged, include a stream: the
    /// receiver is given the stream's frames (`HELLO`, binds, checkpoints, `END`). A receiver
    /// reached over a path with no stream is given the datagram class only.
    pub(crate) stream: bool,
}

/// What a channel gives the frame layer: the id and the key frames are sealed under now.
#[derive(Clone)]
pub(crate) struct SendKey {
    /// The channel id.
    pub(crate) id: u64,
    /// The key epoch; the frame header carries its low 8 bits.
    pub(crate) key_epoch: u32,
    /// The key frames of this channel are sealed under now.
    pub(crate) frame_key: FrameKey,
    /// What the frame layer reads without the table's lock.
    pub(crate) live: Arc<Live>,
}

/// What a re-judging did to one space's channels.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Rejudged {
    /// The receivers dropped, as `(mode, device)`.
    pub(crate) dropped: Vec<(ChannelMode, Name)>,
    /// The modes whose channel was re-keyed.
    pub(crate) rekeyed: Vec<ChannelMode>,
}

/// A token bucket: how many tokens it held at `at`.
#[derive(Clone, Copy)]
struct Bucket {
    tokens: f64,
    at: Instant,
}

impl Bucket {
    fn full(burst: f64, now: Instant) -> Bucket {
        Bucket {
            tokens: burst,
            at: now,
        }
    }

    /// What it holds at `now`: refilled at `rate` a second, at most `burst`.
    fn held(&self, rate: f64, burst: f64, now: Instant) -> f64 {
        (self.tokens + now.saturating_duration_since(self.at).as_secs_f64() * rate).min(burst)
    }

    /// One token, if it holds one.
    fn take(&mut self, rate: f64, burst: f64, now: Instant) -> bool {
        self.tokens = self.held(rate, burst, now);
        self.at = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// The token bucket of each asker key.
#[derive(Default)]
struct Buckets {
    by_key: HashMap<Name, Bucket>,
}

impl Buckets {
    /// Whether `key` may ask now: one token of its bucket.
    fn take(&mut self, key: &Name, now: Instant) -> bool {
        if self.by_key.len() >= BUCKETS_MAX && !self.by_key.contains_key(key) {
            // Every bucket that has refilled is the same as none: drop those, then the idlest.
            self.by_key
                .retain(|_, b| b.held(ASKS_PER_SEC, ASKS_BURST, now) < ASKS_BURST);
            if self.by_key.len() >= BUCKETS_MAX {
                let idlest = self.by_key.iter().min_by_key(|(_, b)| b.at);
                if let Some(idlest) = idlest.map(|(k, _)| k.clone()) {
                    self.by_key.remove(&idlest);
                }
            }
        }
        self.by_key
            .entry(key.clone())
            .or_insert_with(|| Bucket::full(ASKS_BURST, now))
            .take(ASKS_PER_SEC, ASKS_BURST, now)
    }
}

#[derive(Default)]
struct Table {
    channels: BTreeMap<(Name, ChannelMode), Channel>,
    buckets: Buckets,
}

/// A sender's channels.
#[derive(Default)]
pub(crate) struct Channels {
    table: Mutex<Table>,
}

/// A fresh random channel id.
fn random_id() -> u64 {
    let mut id = [0u8; 8];
    getrandom::getrandom(&mut id).expect("the operating system's randomness");
    u64::from_be_bytes(id)
}

impl Channel {
    fn new(audience: Option<EpochId>, judged_at: (u64, u64), now: Instant) -> Channel {
        Channel {
            id: random_id(),
            key: ChannelKey::random(),
            key_epoch: 0,
            receivers: BTreeMap::new(),
            next_seq: 1,
            audience,
            judged_at,
            last_announce: None,
            last_rekey: now,
            rekey_owed: false,
            empty_since: None,
            live: Arc::new(Live::default()),
        }
    }

    /// A new key at `now`: the next key epoch. Every receiver must ask again to hold it.
    fn rekey(&mut self, now: Instant) {
        self.key = ChannelKey::random();
        self.key_epoch = self.key_epoch.wrapping_add(1);
        self.live.key_epoch.store(self.key_epoch, Ordering::Release);
        self.last_rekey = now;
        self.rekey_owed = false;
    }

    /// Whether a renewal or a lapsed lease may re-key the channel at `now`: [`REKEY_MIN`] has
    /// passed since the key was made.
    fn rekey_allowed(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.last_rekey) >= REKEY_MIN
    }

    fn send_key(&self) -> SendKey {
        SendKey {
            id: self.id,
            key_epoch: self.key_epoch,
            frame_key: self.key.frame_key(self.id, self.key_epoch),
            live: Arc::clone(&self.live),
        }
    }

    /// Publish what the frame layer reads of the receivers: how many there are, and how many of
    /// them are reached over a path with no stream.
    fn sync_live(&self) {
        self.live
            .receivers
            .store(self.receivers.len(), Ordering::Release);
        self.live.datagram_only.store(
            self.receivers.values().filter(|r| !r.stream).count(),
            Ordering::Release,
        );
    }

    fn admitted(&self, receiver: &Receiver, rekeyed: bool, fresh: bool, claim: bool) -> Admitted {
        Admitted {
            id: self.id,
            key_epoch: self.key_epoch,
            key: self.key.clone(),
            seq: self.next_seq,
            audience: self.audience.clone(),
            lifetime: receiver.lifetime.as_secs(),
            rekeyed,
            fresh,
            claim,
        }
    }
}

impl Drop for Channel {
    fn drop(&mut self) {
        self.live.closed.store(true, Ordering::Release);
    }
}

/// A channel taken out of the table that is not over yet: its key is still the one in force, so
/// the sender can seal the `END` frame under it. Dropping it ends the channel: it is marked
/// closed ([`Live::closed`]) and the key is zeroed.
pub(crate) struct Ended(Channel);

impl Ended {
    /// The id and the key in force when the channel was taken out.
    pub(crate) fn key(&self) -> SendKey {
        self.0.send_key()
    }
}

impl Channels {
    /// Whether `key` may ask now: one token of its bucket (4 a second, burst 8). Charged only for
    /// an ask whose signature verified: the key an unverified ask names is whatever its sender
    /// wrote, so a bucket charged before the signature is an asker's for anyone to empty.
    pub(crate) fn throttle(&self, key: &Name, now: Instant) -> bool {
        self.table.lock().buckets.take(key, now)
    }

    /// Whether `key` has used up its bucket now (it holds less than one token). Charges nothing:
    /// the bucket drains only by asks whose signature verified, so no stranger can empty it by
    /// naming the key, and an ask that names a key in this state is the key's own flood or
    /// someone's copy of it: refused before its signature is checked, for it would be refused
    /// after.
    pub(crate) fn over_rate(&self, key: &Name, now: Instant) -> bool {
        self.table
            .lock()
            .buckets
            .by_key
            .get(key)
            .is_some_and(|b| b.held(ASKS_PER_SEC, ASKS_BURST, now) < 1.0)
    }

    /// Give `asker`, which the caller judged, the key of the channel of `(space, mode)`: the
    /// channel is made if there is none; the asker is added, or renewed. A receiver that already
    /// holds the current key and asks again after half its lifetime has the channel re-keyed if
    /// the last re-key was [`REKEY_MIN`] ago or more (a renewal re-keys; an ask sooner, or by one
    /// that holds an older key, is given the key as it is, and so is a renewal soon after a
    /// re-key: no receiver can make the others ask again at will).
    /// `judged_at` is what the judges said when the asker was judged.
    pub(crate) fn admit(
        &self,
        space: &Name,
        mode: ChannelMode,
        asker: &Asker<'_>,
        audience: Option<EpochId>,
        judged_at: (u64, u64),
        now: Instant,
    ) -> Result<Admitted, Cap> {
        let mut table = self.table.lock();
        let at = (space.clone(), mode);
        if !table.channels.contains_key(&at) {
            if table.channels.len() >= CHANNELS_PER_SENDER {
                return Err(Cap::Channels);
            }
            table
                .channels
                .insert(at.clone(), Channel::new(audience.clone(), judged_at, now));
        }
        let channel = table
            .channels
            .get_mut(&at)
            .expect("the channel was just made");
        // A channel opened before anyone asked has judged nobody: its audience epoch is the
        // one its first receiver is judged by.
        if channel.receivers.is_empty() {
            channel.audience = audience;
            channel.judged_at = judged_at;
        }
        let lifetime = Duration::from_secs(lifetime_for(asker.wanted));
        let known = channel.receivers.get(asker.device).cloned();
        if known.is_none() {
            // A place is taken only by a device the channel does not have. One person's
            // devices are bounded first (she can do something about that), then the channel.
            let hers = channel
                .receivers
                .values()
                .filter(|r| r.person == *asker.person)
                .count();
            if hers >= RECEIVERS_PER_PERSON {
                return Err(Cap::Person);
            }
            if channel.receivers.len() >= receivers_cap(mode) {
                return Err(Cap::Receivers);
            }
        }
        // A receiver that holds the current key and asks after half its lifetime renews: the
        // channel is re-keyed, unless it was re-keyed less than [`REKEY_MIN`] ago. Then the
        // receiver is given the key as it is: a lifetime short enough to make every ask a
        // renewal makes no re-key either.
        let renewal = known.as_ref().is_some_and(|r| {
            r.delivered == channel.key_epoch
                && now.saturating_duration_since(r.issued) >= r.lifetime / 2
        });
        let rekeyed = renewal && mode != ChannelMode::Ask && channel.rekey_allowed(now);
        if rekeyed {
            channel.rekey(now);
        }
        let receiver = Receiver {
            key: asker.key.clone(),
            delivered: channel.key_epoch,
            issued: now,
            lifetime,
            person: asker.person.clone(),
            stream: asker.stream,
        };
        channel
            .receivers
            .insert(asker.device.clone(), receiver.clone());
        channel.empty_since = None;
        channel.sync_live();
        let fresh = known.is_none();
        Ok(channel.admitted(&receiver, rekeyed, fresh, !fresh && asker.new))
    }

    /// Make the channel of `(space, mode)` if there is none (the sender's own start, before
    /// anyone asked). `Err` when the sender keeps [`CHANNELS_PER_SENDER`] already.
    pub(crate) fn open(
        &self,
        space: &Name,
        mode: ChannelMode,
        audience: Option<EpochId>,
        judged_at: (u64, u64),
        now: Instant,
    ) -> Result<SendKey, Cap> {
        let mut table = self.table.lock();
        let at = (space.clone(), mode);
        if !table.channels.contains_key(&at) {
            if table.channels.len() >= CHANNELS_PER_SENDER {
                return Err(Cap::Channels);
            }
            let mut channel = Channel::new(audience, judged_at, now);
            channel.empty_since = Some(now);
            table.channels.insert(at.clone(), channel);
        }
        Ok(table.channels[&at].send_key())
    }

    /// The id, key epoch and frame key of the channel of `(space, mode)`, if there is one.
    pub(crate) fn current(&self, space: &Name, mode: ChannelMode) -> Option<SendKey> {
        let table = self.table.lock();
        Some(table.channels.get(&(space.clone(), mode))?.send_key())
    }

    /// The modes of the channels of `space` that an announce lists: an `Ask` channel is not one
    /// (the prefixes a device serves say it answers queries, and the channel is the asker's).
    pub(crate) fn modes(&self, space: &Name) -> Vec<ChannelMode> {
        let table = self.table.lock();
        table
            .channels
            .keys()
            .filter(|(s, m)| s == space && *m != ChannelMode::Ask)
            .map(|(_, m)| *m)
            .collect()
    }

    /// The spaces that have channels.
    pub(crate) fn spaces(&self) -> Vec<Name> {
        let table = self.table.lock();
        let mut spaces: Vec<Name> = table.channels.keys().map(|(s, _)| s.clone()).collect();
        spaces.dedup();
        spaces
    }

    /// What the receivers of every channel of `space` were last judged by.
    pub(crate) fn judged_at(&self, space: &Name) -> Vec<(ChannelMode, (u64, u64))> {
        let table = self.table.lock();
        table
            .channels
            .iter()
            .filter(|((s, _), _)| s == space)
            .map(|((_, m), c)| (*m, c.judged_at))
            .collect()
    }

    /// The receivers of the channels of `space`: `(mode, device, key that signed its ask)`.
    #[cfg(test)]
    pub(crate) fn receivers(&self, space: &Name) -> Vec<(ChannelMode, Name, Name)> {
        let table = self.table.lock();
        let mut out = Vec::new();
        for ((s, mode), channel) in &table.channels {
            if s == space {
                for (device, r) in &channel.receivers {
                    out.push((*mode, device.clone(), r.key.clone()));
                }
            }
        }
        out
    }

    /// The caller judged the receivers of `space` again, against what the judges said at
    /// `judged_at` and the audience epoch `audience` now in force: `keep` says which of them
    /// stand. The others are dropped and the channel is re-keyed at once; a channel whose
    /// audience epoch moved is re-keyed too. Every channel of the space then holds `judged_at`.
    ///
    /// `audience` is `None` for a public space, and for a sealed one with no epoch in force at
    /// this instant (a removal reached the record before the owner's new epoch did): that says
    /// nothing of the audience, so no channel counts it as moved; the epoch that arrives next
    /// is a move, and re-keys again.
    pub(crate) fn rejudged(
        &self,
        space: &Name,
        judged_at: (u64, u64),
        audience: Option<&EpochId>,
        now: Instant,
        keep: impl Fn(&Name, &Name) -> bool,
    ) -> Rejudged {
        let mut table = self.table.lock();
        let mut out = Rejudged::default();
        for ((s, mode), channel) in &mut table.channels {
            if s != space {
                continue;
            }
            let gone: Vec<Name> = channel
                .receivers
                .iter()
                .filter(|(device, r)| !keep(device, &r.key))
                .map(|(device, _)| device.clone())
                .collect();
            for device in &gone {
                channel.receivers.remove(device);
                out.dropped.push((*mode, device.clone()));
            }
            channel.sync_live();
            let epoch_moved = audience.is_some_and(|a| channel.audience.as_ref() != Some(a));
            if !gone.is_empty() || epoch_moved {
                if audience.is_some() {
                    channel.audience = audience.cloned();
                }
                channel.rekey(now);
                out.rekeyed.push(*mode);
            }
            if channel.receivers.is_empty() && channel.empty_since.is_none() {
                channel.empty_since = Some(now);
            }
            channel.judged_at = judged_at;
        }
        out
    }

    /// End what ran out at `now`: a receiver whose lease passed (its channel is re-keyed once
    /// [`REKEY_MIN`] has passed since its last re-key: the receiver held a key and did not renew),
    /// and a channel with no receiver for a default lifetime.
    /// Returns the receivers dropped and the channels ended, as `(space, mode)`.
    #[allow(clippy::type_complexity)]
    pub(crate) fn expire(
        &self,
        now: Instant,
    ) -> (Vec<(Name, ChannelMode, Name)>, Vec<(Name, ChannelMode)>) {
        let mut table = self.table.lock();
        let (mut lapsed, mut ended) = (Vec::new(), Vec::new());
        for ((space, mode), channel) in &mut table.channels {
            let gone: Vec<Name> = channel
                .receivers
                .iter()
                .filter(|(_, r)| now >= r.lease_until())
                .map(|(d, _)| d.clone())
                .collect();
            for device in gone {
                channel.receivers.remove(&device);
                lapsed.push((space.clone(), *mode, device));
                if *mode != ChannelMode::Ask {
                    channel.rekey_owed = true;
                }
            }
            // A lapse is a key an absent receiver may still hold, not an emergency: the lapses of
            // a stretch are one re-key, made when [`REKEY_MIN`] has passed since the last.
            if channel.rekey_owed && channel.rekey_allowed(now) {
                channel.rekey(now);
            }
            channel.sync_live();
            if channel.receivers.is_empty() {
                let since = *channel.empty_since.get_or_insert(now);
                if now.saturating_duration_since(since) >= Duration::from_secs(LIFETIME_DEFAULT) {
                    ended.push((space.clone(), *mode));
                }
            }
        }
        for at in &ended {
            table.channels.remove(at);
        }
        (lapsed, ended)
    }

    /// The spaces whose channels are due an announce at `now` (never announced, or the last was
    /// [`ANNOUNCE_EVERY`] ago), each marked announced.
    pub(crate) fn announce_due(&self, now: Instant) -> Vec<Name> {
        let mut table = self.table.lock();
        let mut due = Vec::new();
        for ((space, _), channel) in &mut table.channels {
            let stale = channel
                .last_announce
                .is_none_or(|at| now.saturating_duration_since(at) >= ANNOUNCE_EVERY);
            if stale {
                channel.last_announce = Some(now);
                if !due.contains(space) {
                    due.push(space.clone());
                }
            }
        }
        due
    }

    /// The channels of `space` are announced at `now`: the next announce is [`ANNOUNCE_EVERY`]
    /// after it.
    pub(crate) fn announced(&self, space: &Name, now: Instant) {
        let mut table = self.table.lock();
        for ((s, _), channel) in &mut table.channels {
            if s == space {
                channel.last_announce = Some(now);
            }
        }
    }

    /// The frame layer sent up to `next_seq - 1`: the next sequence the sender will use. A
    /// channel at 2^63 is re-keyed before it goes on. Returns whether it was.
    pub(crate) fn note_seq(&self, space: &Name, mode: ChannelMode, next_seq: u64) -> bool {
        let mut table = self.table.lock();
        let Some(channel) = table.channels.get_mut(&(space.clone(), mode)) else {
            return false;
        };
        channel.next_seq = next_seq;
        if next_seq >= SEQ_REKEY {
            // Read here, not passed in: a channel gets this far once in 2^63 frames.
            channel.rekey(Instant::now());
            return true;
        }
        false
    }

    /// Take the channel of `(space, mode)` out of the table: every receiver's next ask is a new
    /// channel's. The channel's key stays in force, for the `END` frame to be sealed under, until
    /// the returned [`Ended`] is dropped, which marks the channel closed and zeroes the key.
    /// `None` when there was no such channel.
    pub(crate) fn close(&self, space: &Name, mode: ChannelMode) -> Option<Ended> {
        let channel = self.table.lock().channels.remove(&(space.clone(), mode))?;
        Some(Ended(channel))
    }

    /// Take every channel of `space` out of the table, as [`Self::close`] does one.
    pub(crate) fn close_space(&self, space: &Name) -> Vec<(ChannelMode, Ended)> {
        let mut table = self.table.lock();
        let modes: Vec<ChannelMode> = table
            .channels
            .keys()
            .filter(|(s, _)| s == space)
            .map(|(_, m)| *m)
            .collect();
        modes
            .into_iter()
            .filter_map(|mode| {
                let channel = table.channels.remove(&(space.clone(), mode))?;
                Some((mode, Ended(channel)))
            })
            .collect()
    }

    /// How many channels the sender keeps.
    #[cfg(test)]
    pub(crate) fn count(&self) -> usize {
        self.table.lock().channels.len()
    }

    /// How many receivers the channel of `(space, mode)` keeps.
    #[cfg(test)]
    pub(crate) fn receiver_count(&self, space: &Name, mode: ChannelMode) -> usize {
        self.table
            .lock()
            .channels
            .get(&(space.clone(), mode))
            .map_or(0, |c| c.receivers.len())
    }
}

#[cfg(test)]
#[path = "channels_tests.rs"]
mod tests;
