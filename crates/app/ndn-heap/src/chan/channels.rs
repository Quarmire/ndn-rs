//! The sender's channel table (docs/specs/channel.md, Sender): one channel per (space, mode), its
//! random id, its key and key epoch, and the receivers it answered.
//!
//! The table is pure state. Every operation takes the instant it happens at (a monotonic clock
//! the caller reads, so a test moves it by hand) and decides nothing about trust: who may be a
//! receiver is the caller's judgement, made from signed data before the table is touched
//! ([`answer`](super::answer)). A channel is re-keyed
//!
//! * when a receiver that holds the current key asks again after half its lifetime (a renewal),
//! * at once when a receiver is dropped because it no longer stands, or left the audience, or
//!   the sealed space's epoch in force moved ([`Channels::rejudged`]),
//! * when a receiver's lease ran out ([`Channels::expire`]), and
//! * before the sequence passes 2^63 ([`Channels::note_seq`]).
//!
//! Re-keying is pulled: nothing is sent to a receiver. One that sees a frame under a key epoch
//! it does not hold asks again, and is given the current key if the sender still answers it.

use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

use ndn_foundation_types::Name;
use parking_lot::Mutex;

use super::key::{ChannelKey, FrameKey};
use super::limits;
use super::wire::{ChannelMode, LIFETIME_MAX};
use crate::rt::Instant;
use crate::wire::EpochId;

/// The most channels one sender keeps.
pub(crate) const CHANNELS_PER_SENDER: usize = 64;

/// The most receivers one channel keeps.
pub(crate) const RECEIVERS_PER_CHANNEL: usize = 256;

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

/// A session's lifetime for an ask of `wanted` seconds: the ask's, at most 24 hours, and an
/// ask of none is the default. Clamped, never refused.
pub(crate) fn lifetime_for(wanted: u64) -> u64 {
    match wanted {
        0 => LIFETIME_DEFAULT,
        w => w.min(LIFETIME_MAX),
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
}

impl Receiver {
    fn lease_until(&self) -> Instant {
        self.issued + self.lifetime + LEASE_GRACE
    }
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
    /// Since when the channel has had no receiver.
    empty_since: Option<Instant>,
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
}

/// Which cap a refused ask hit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Cap {
    /// [`CHANNELS_PER_SENDER`].
    Channels,
    /// [`RECEIVERS_PER_CHANNEL`].
    Receivers,
}

/// What the table needs to know of an asker the caller judged.
pub(crate) struct Asker<'a> {
    /// The asker's device: one receiver per device.
    pub(crate) device: &'a Name,
    /// The key that signed the ask.
    pub(crate) key: &'a Name,
    /// The lifetime the ask wants, in seconds (0: none named).
    pub(crate) wanted: u64,
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
}

/// What a re-judging did to one space's channels.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Rejudged {
    /// The receivers dropped, as `(mode, device)`.
    pub(crate) dropped: Vec<(ChannelMode, Name)>,
    /// The modes whose channel was re-keyed.
    pub(crate) rekeyed: Vec<ChannelMode>,
}

/// The token bucket of each asker key.
#[derive(Default)]
struct Buckets {
    by_key: HashMap<Name, (f64, Instant)>,
}

impl Buckets {
    /// Whether `key` may ask now: one token of its bucket.
    fn take(&mut self, key: &Name, now: Instant) -> bool {
        if self.by_key.len() >= BUCKETS_MAX && !self.by_key.contains_key(key) {
            // Every bucket that has refilled is the same as none: drop those, then the idlest.
            self.by_key.retain(|_, (tokens, at)| {
                *tokens + now.saturating_duration_since(*at).as_secs_f64() * ASKS_PER_SEC
                    < ASKS_BURST
            });
            if self.by_key.len() >= BUCKETS_MAX {
                let idlest = self.by_key.iter().min_by_key(|(_, (_, at))| *at);
                if let Some(idlest) = idlest.map(|(k, _)| k.clone()) {
                    self.by_key.remove(&idlest);
                }
            }
        }
        let entry = self.by_key.entry(key.clone()).or_insert((ASKS_BURST, now));
        let refill = now.saturating_duration_since(entry.1).as_secs_f64() * ASKS_PER_SEC;
        entry.0 = (entry.0 + refill).min(ASKS_BURST);
        entry.1 = now;
        if entry.0 >= 1.0 {
            entry.0 -= 1.0;
            true
        } else {
            false
        }
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
    fn new(audience: Option<EpochId>, judged_at: (u64, u64)) -> Channel {
        Channel {
            id: random_id(),
            key: ChannelKey::random(),
            key_epoch: 0,
            receivers: BTreeMap::new(),
            next_seq: 1,
            audience,
            judged_at,
            last_announce: None,
            empty_since: None,
        }
    }

    /// A new key: the next key epoch. Every receiver must ask again to hold it.
    fn rekey(&mut self) {
        self.key = ChannelKey::random();
        self.key_epoch = self.key_epoch.wrapping_add(1);
    }

    fn admitted(&self, receiver: &Receiver, rekeyed: bool) -> Admitted {
        Admitted {
            id: self.id,
            key_epoch: self.key_epoch,
            key: self.key.clone(),
            seq: self.next_seq,
            audience: self.audience.clone(),
            lifetime: receiver.lifetime.as_secs(),
            rekeyed,
        }
    }
}

impl Channels {
    /// Whether `key` may ask now: one token of its bucket (4 a second, burst 8).
    pub(crate) fn throttle(&self, key: &Name, now: Instant) -> bool {
        self.table.lock().buckets.take(key, now)
    }

    /// Give `asker`, which the caller judged, the key of the channel of `(space, mode)`: the
    /// channel is made if there is none; the asker is added, or renewed. A receiver that already
    /// holds the current key and asks again after half its lifetime has the channel re-keyed
    /// (a renewal re-keys; an ask sooner, or by one that holds an older key, is given the key
    /// as it is, so no receiver can make the others ask again at will).
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
                .insert(at.clone(), Channel::new(audience.clone(), judged_at));
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
        if known.is_none() && channel.receivers.len() >= RECEIVERS_PER_CHANNEL {
            return Err(Cap::Receivers);
        }
        let renewal = known.as_ref().is_some_and(|r| {
            r.delivered == channel.key_epoch
                && now.saturating_duration_since(r.issued) >= r.lifetime / 2
        });
        if renewal {
            channel.rekey();
        }
        let receiver = Receiver {
            key: asker.key.clone(),
            delivered: channel.key_epoch,
            issued: now,
            lifetime,
        };
        channel
            .receivers
            .insert(asker.device.clone(), receiver.clone());
        channel.empty_since = None;
        Ok(channel.admitted(&receiver, renewal))
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
            let mut channel = Channel::new(audience, judged_at);
            channel.empty_since = Some(now);
            table.channels.insert(at.clone(), channel);
        }
        let channel = &table.channels[&at];
        Ok(SendKey {
            id: channel.id,
            key_epoch: channel.key_epoch,
            frame_key: channel.key.frame_key(channel.id, channel.key_epoch),
        })
    }

    /// The id, key epoch and frame key of the channel of `(space, mode)`, if there is one.
    pub(crate) fn current(&self, space: &Name, mode: ChannelMode) -> Option<SendKey> {
        let table = self.table.lock();
        let channel = table.channels.get(&(space.clone(), mode))?;
        Some(SendKey {
            id: channel.id,
            key_epoch: channel.key_epoch,
            frame_key: channel.key.frame_key(channel.id, channel.key_epoch),
        })
    }

    /// The modes of the channels of `space`.
    pub(crate) fn modes(&self, space: &Name) -> Vec<ChannelMode> {
        let table = self.table.lock();
        table
            .channels
            .keys()
            .filter(|(s, _)| s == space)
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
            let epoch_moved = channel.audience.as_ref() != audience;
            if !gone.is_empty() || epoch_moved {
                channel.audience = audience.cloned();
                channel.rekey();
                out.rekeyed.push(*mode);
            }
            if channel.receivers.is_empty() && channel.empty_since.is_none() {
                channel.empty_since = Some(now);
            }
            channel.judged_at = judged_at;
        }
        out
    }

    /// End what ran out at `now`: a receiver whose lease passed (its channel is re-keyed: it
    /// held a key and did not renew), and a channel with no receiver for a default lifetime.
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
                channel.rekey();
            }
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
            channel.rekey();
            return true;
        }
        false
    }

    /// End the channel of `(space, mode)`: its key is dropped (zeroed) and every receiver's next
    /// ask is a new channel's.
    pub(crate) fn close(&self, space: &Name, mode: ChannelMode) -> bool {
        self.table
            .lock()
            .channels
            .remove(&(space.clone(), mode))
            .is_some()
    }

    /// End every channel of `space`.
    pub(crate) fn close_space(&self, space: &Name) -> Vec<ChannelMode> {
        let mut table = self.table.lock();
        let modes: Vec<ChannelMode> = table
            .channels
            .keys()
            .filter(|(s, _)| s == space)
            .map(|(_, m)| *m)
            .collect();
        for mode in &modes {
            table.channels.remove(&(space.clone(), *mode));
        }
        modes
    }

    /// How many channels the sender keeps.
    pub(crate) fn count(&self) -> usize {
        self.table.lock().channels.len()
    }

    /// How many receivers the channel of `(space, mode)` keeps.
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
