//! The receiver's session store (docs/specs/channel.md, Receiver): one [`RecvSession`] per
//! (space, sender, mode), what a sender's signed answer gave this device.
//!
//! A session is **usable** until its lifetime plus a 5 s grace has passed on the monotonic clock,
//! counted from the receipt of the answer (no wall clock is read: a clock that steps changes
//! nothing). It holds the key of the epoch it was last given and, for [`REKEY_GRACE`] after the
//! receiver first saw the next key epoch, the key before it, so frames in flight under the old key
//! are not lost. The frame layer asks, per frame, [`RecvSession::is_current`] (two atomic loads:
//! the trust generation and the space's fold version it was judged under) and, when either moved,
//! [`RecvSession::recheck`], which judges the sender again from what the node holds, offline, and
//! drops the session with its reason if the sender no longer stands.
//!
//! A frame under a key epoch the session does not hold calls [`RecvSessions::unknown_epoch`], which
//! says whether to ask the sender again: at most once a second per sender.

use super::FastMap;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use ndn_foundation_types::Name;
use parking_lot::Mutex;

use super::aead::Aead;
use super::key::{ChannelKey, FrameKey};
use super::standing::{Who, gate, standing};
use super::wire::{Bind, CarrierOffer, ChannelMode, SessionRecord, Window};
use crate::node::NodeInner;
use crate::rt::Instant;
use crate::trust::Judge;
use crate::wire::EpochId;

/// How long the key before the current one is accepted after the receiver first saw the new key
/// epoch.
pub(crate) const REKEY_GRACE: Duration = Duration::from_secs(5);

/// How long past its lifetime a session is still used.
pub(crate) const LIFETIME_GRACE: Duration = Duration::from_secs(5);

/// The shortest time between two asks of one sender made because a frame came under a key epoch
/// this device does not hold.
pub(crate) const UNKNOWN_EPOCH_ASK_EVERY: Duration = Duration::from_secs(1);

/// The time between two attempts to renew a session whose renewal failed.
pub(crate) const RENEW_RETRY: Duration = Duration::from_secs(10);

/// Why a session ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EndReason {
    /// The sender (or, when it says so, this device) no longer stands as a member of the space by
    /// the entries held now.
    NotMember {
        /// What the entries say, and what to do.
        why: String,
    },
    /// A newer session of the same sender and mode took its place (the sender began a new
    /// channel).
    Replaced,
    /// Its lifetime and grace ran out and it was not renewed.
    Lapsed,
    /// This device left the space, or the node stopped.
    Left,
    /// The sender ended the channel (a `CONTROL` frame `END`): nothing more will come under it.
    Closed,
}

impl fmt::Display for EndReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EndReason::NotMember { why } => write!(f, "not a member: {why}"),
            EndReason::Replaced => f.write_str("the sender began a new channel"),
            EndReason::Lapsed => f.write_str("its lifetime ran out and it was not renewed"),
            EndReason::Left => f.write_str("this device left the space"),
            EndReason::Closed => f.write_str("the sender ended the channel"),
        }
    }
}

/// A key and what is derived from it once.
struct Held {
    epoch: u32,
    /// Kept so the key id and a later derivation need no second unwrap.
    _key: ChannelKey,
    frame: FrameKey,
}

/// What the sender's last answer set.
#[derive(Clone, Debug)]
pub(crate) struct Terms {
    /// The AEAD of the frames.
    pub(crate) aead: Aead,
    /// The largest frame on a datagram carrier.
    pub(crate) frame_max: u64,
    /// The carriers on offer.
    #[allow(dead_code)] // stage 4: the side table routes by the carriers a session offers
    pub(crate) carriers: Vec<CarrierOffer>,
    /// The name ids bound so far.
    pub(crate) table: Vec<Bind>,
    /// The checkpoint period in milliseconds.
    #[allow(dead_code)] // stage 5: checkpoints are taken at the period the sender announced
    pub(crate) ckpt_ms: u64,
    /// `Window` mode: what is replayed.
    #[allow(dead_code)]
    // recorded from the signed session; a later stage's `Window` verbs read it
    pub(crate) window: Option<Window>,
    /// The next sequence the sender will use, when it answered.
    pub(crate) seq: u64,
    /// The audience epoch the sender judged this device by.
    #[allow(dead_code)] // recorded from the signed session; later stages judge by it
    pub(crate) audience: Option<EpochId>,
}

impl Terms {
    pub(crate) fn of(record: &SessionRecord) -> Terms {
        Terms {
            aead: record.aead,
            frame_max: record.frame_max,
            carriers: record.carriers.clone(),
            table: record.table.clone(),
            ckpt_ms: record.ckpt_ms,
            window: record.window,
            seq: record.seq,
            audience: record.audience_epoch.clone(),
        }
    }
}

struct State {
    current: Held,
    previous: Option<(Held, Instant)>,
    /// The low octet of the first key epoch seen that was not held, and when.
    first_seen: Option<(u8, Instant)>,
    installed: Instant,
    lifetime: Duration,
    terms: Terms,
    /// The key that signed the sender's last answer.
    sender_key: Name,
    /// When a failed renewal may be tried again.
    retry_at: Option<Instant>,
    ended: Option<EndReason>,
}

/// What a session shows its holder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelInfo {
    /// The channel id.
    pub channel: u64,
    /// The sender's device.
    pub sender: Name,
    /// The space.
    pub space: Name,
    /// The mode.
    pub mode: ChannelMode,
    /// How many times the sender re-keyed the channel (the session holds the latest it gave).
    pub key_epoch: u32,
    /// How long the session lasts from receipt.
    pub lifetime: Duration,
}

/// One sender's channel as this device holds it.
pub(crate) struct RecvSession {
    id: u64,
    sender: Name,
    space: Name,
    mode: ChannelMode,
    state: Mutex<State>,
    /// What the judges said when the sender was last judged.
    generation: AtomicU64,
    fold_version: AtomicU64,
    judge: Arc<Judge>,
    live_fold: Arc<AtomicU64>,
}

impl fmt::Debug for RecvSession {
    /// The channel and its sender: never a key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecvSession")
            .field("id", &self.id)
            .field("sender", &self.sender)
            .field("space", &self.space)
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}
fn newer(epoch: u32, than: u32) -> bool {
    epoch != than && epoch.wrapping_sub(than) < (1 << 31)
}

impl RecvSession {
    /// A session installed at `now` from the sender's answer `record`, whose key (already
    /// unwrapped) is `key`, judged by `judge` and the fold whose version is `live_fold` when
    /// `judged_at` was read.
    pub(crate) fn new(
        record: &SessionRecord,
        key: ChannelKey,
        sender_key: Name,
        judge: Arc<Judge>,
        live_fold: Arc<AtomicU64>,
        judged_at: (u64, u64),
        now: Instant,
    ) -> RecvSession {
        let frame = key.frame_key(record.id, record.key_epoch);
        RecvSession {
            id: record.id,
            sender: record.sender.clone(),
            space: record.space.clone(),
            mode: record.mode,
            state: Mutex::new(State {
                current: Held {
                    epoch: record.key_epoch,
                    _key: key,
                    frame,
                },
                previous: None,
                first_seen: None,
                installed: now,
                lifetime: Duration::from_secs(record.lifetime),
                terms: Terms::of(record),
                sender_key,
                retry_at: None,
                ended: None,
            }),
            generation: AtomicU64::new(judged_at.0),
            fold_version: AtomicU64::new(judged_at.1),
            judge,
            live_fold,
        }
    }

    /// The channel id.
    pub(crate) fn id(&self) -> u64 {
        self.id
    }

    /// The sender's device.
    pub(crate) fn sender(&self) -> &Name {
        &self.sender
    }

    /// The space.
    pub(crate) fn space(&self) -> &Name {
        &self.space
    }

    /// The mode.
    pub(crate) fn mode(&self) -> ChannelMode {
        self.mode
    }

    /// What the sender's last answer set.
    pub(crate) fn terms(&self) -> Terms {
        self.state.lock().terms.clone()
    }

    /// The key epoch of the key held now.
    #[cfg(test)]
    pub(crate) fn key_epoch(&self) -> u32 {
        self.state.lock().current.epoch
    }

    /// What the session shows its holder.
    pub(crate) fn info(&self) -> ChannelInfo {
        let state = self.state.lock();
        ChannelInfo {
            channel: self.id,
            sender: self.sender.clone(),
            space: self.space.clone(),
            mode: self.mode,
            key_epoch: state.current.epoch,
            lifetime: state.lifetime,
        }
    }

    /// Why the session ended, if it did.
    pub(crate) fn ended(&self) -> Option<EndReason> {
        self.state.lock().ended.clone()
    }

    pub(crate) fn end(&self, why: EndReason) {
        let mut state = self.state.lock();
        state.ended.get_or_insert(why);
    }

    /// Whether the session may be used at `now`: it has not ended, and its lifetime plus
    /// [`LIFETIME_GRACE`] has not passed since it was received.
    pub(crate) fn usable(&self, now: Instant) -> bool {
        let state = self.state.lock();
        state.ended.is_none()
            && now.saturating_duration_since(state.installed) < state.lifetime + LIFETIME_GRACE
    }

    /// Whether the session is due its renewal at `now`: 75 % of its lifetime has passed since it
    /// was received, and a renewal that failed is not waited on.
    pub(crate) fn renewal_due(&self, now: Instant) -> bool {
        let state = self.state.lock();
        state.ended.is_none()
            && now.saturating_duration_since(state.installed) >= state.lifetime * 3 / 4
            && state.retry_at.is_none_or(|at| now >= at)
    }

    /// A renewal at `now` failed: it is tried again after [`RENEW_RETRY`].
    pub(crate) fn renewal_failed(&self, now: Instant) {
        self.state.lock().retry_at = Some(now + RENEW_RETRY);
    }

    /// The key frames of this channel were sealed under at the key epoch whose low octet is
    /// `low`, at `now`: the key held now, or the one before it for [`REKEY_GRACE`] after the
    /// receiver first saw the next epoch. `None` when the session is not usable, or the epoch is
    /// not held.
    pub(crate) fn frame_key(&self, low: u8, now: Instant) -> Option<FrameKey> {
        let state = self.state.lock();
        if state.ended.is_some()
            || now.saturating_duration_since(state.installed) >= state.lifetime + LIFETIME_GRACE
        {
            return None;
        }
        if state.current.epoch as u8 == low {
            return Some(state.current.frame.clone());
        }
        match &state.previous {
            Some((held, until)) if held.epoch as u8 == low && now < *until => {
                Some(held.frame.clone())
            }
            _ => None,
        }
    }

    /// The session took a new answer of the same channel at `now`: a renewal, or a key pulled
    /// after a re-key. A key epoch not newer than the one held changes only the lifetime. The key
    /// before stays acceptable until [`REKEY_GRACE`] after the first time the new epoch was seen
    /// (in a frame, or here).
    pub(crate) fn renewed(
        &self,
        record: &SessionRecord,
        key: ChannelKey,
        sender_key: Name,
        judged_at: (u64, u64),
        now: Instant,
    ) {
        let mut state = self.state.lock();
        if newer(record.key_epoch, state.current.epoch) {
            let seen = match state.first_seen {
                Some((low, at)) if low == record.key_epoch as u8 => at,
                _ => now,
            };
            let frame = key.frame_key(record.id, record.key_epoch);
            let old = std::mem::replace(
                &mut state.current,
                Held {
                    epoch: record.key_epoch,
                    _key: key,
                    frame,
                },
            );
            state.previous = Some((old, seen + REKEY_GRACE));
            state.first_seen = None;
        }
        state.installed = now;
        state.lifetime = Duration::from_secs(record.lifetime);
        state.terms = Terms::of(record);
        state.sender_key = sender_key;
        state.retry_at = None;
        self.generation.store(judged_at.0, Ordering::SeqCst);
        self.fold_version.store(judged_at.1, Ordering::SeqCst);
    }

    /// Whether the verdict on the sender still stands as far as two counters say: neither the
    /// trust generation ([`Judge::generation`]) nor the space's fold version has moved since the
    /// sender was judged. The frame layer asks it per frame; when it is false, it calls
    /// [`Self::recheck`] before delivering that frame.
    pub(crate) fn is_current(&self) -> bool {
        self.generation.load(Ordering::SeqCst) == self.judge.generation()
            && self.fold_version.load(Ordering::SeqCst) == self.live_fold.load(Ordering::SeqCst)
    }

    /// Judge the sender again from what this node holds now (offline, synchronous), and take the
    /// verdict as the one both counters stand for. The sender must be a **writer** by the entries
    /// held and this device must still be a member; if not, the session ends with the reason and
    /// is dropped from the store: the frame that asked is not delivered.
    pub(crate) fn recheck(&self, node: &NodeInner) -> Result<(), EndReason> {
        if let Some(why) = self.ended() {
            return Err(why);
        }
        // Read before judging, so a move during the judgement is judged on the next call.
        let judged_at = (
            self.judge.generation(),
            self.live_fold.load(Ordering::SeqCst),
        );
        let verdict = match node.space_of(&self.space).filter(|s| !s.follower) {
            None => Err(EndReason::Left),
            Some(held) => {
                let log = held.log.lock();
                let sender_key = self.state.lock().sender_key.clone();
                standing(&log, &node.judge, &sender_key, Who::Writer)
                    .map_err(|_| EndReason::NotMember {
                        why: format!(
                            "{} is no writer of {} by the entries held now: ask the owner of \
                             the space whether it still lists that person as a writer",
                            self.sender, self.space
                        ),
                    })
                    .and_then(|_| {
                        gate(&log, &node.judge, Who::Listed, "channels")
                            .map_err(|e| EndReason::NotMember { why: e.to_string() })
                    })
            }
        };
        match verdict {
            Ok(()) => {
                self.generation.store(judged_at.0, Ordering::SeqCst);
                self.fold_version.store(judged_at.1, Ordering::SeqCst);
                Ok(())
            }
            Err(why) => {
                self.end(why.clone());
                node.chan.sessions.remove(self.id);
                Err(why)
            }
        }
    }
}

/// What a frame under an unknown key epoch makes of the receiver ([`RecvSessions::unknown_epoch`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Unknown {
    /// No session holds that channel id: the frame is not this device's.
    NoSession,
    /// The sender was asked again less than a second ago: the frame is dropped.
    Limited,
    /// Ask the sender again for this channel.
    Ask {
        /// The space.
        space: Name,
        /// The sender's device.
        sender: Name,
        /// The mode.
        mode: ChannelMode,
    },
}

#[derive(Default)]
struct Store {
    by_id: FastMap<u64, Arc<RecvSession>>,
    asked_for_epoch: FastMap<Name, Instant>,
}

/// The sessions this device holds as a receiver.
#[derive(Default)]
pub(crate) struct RecvSessions {
    store: Mutex<Store>,
}

impl RecvSessions {
    /// The session of channel `id`.
    pub(crate) fn get(&self, id: u64) -> Option<Arc<RecvSession>> {
        self.store.lock().by_id.get(&id).cloned()
    }

    /// The session of `sender` in `mode` over `space`, if one is held.
    pub(crate) fn find(
        &self,
        space: &Name,
        sender: &Name,
        mode: ChannelMode,
    ) -> Option<Arc<RecvSession>> {
        let store = self.store.lock();
        store
            .by_id
            .values()
            .find(|s| s.space == *space && s.sender == *sender && s.mode == mode)
            .cloned()
    }

    /// Every session held.
    pub(crate) fn all(&self) -> Vec<Arc<RecvSession>> {
        let store = self.store.lock();
        let mut all: Vec<_> = store.by_id.values().cloned().collect();
        all.sort_by_key(|s| s.id);
        all
    }

    /// Hold `session`, ending (as replaced) any other of the same space, sender and mode: the
    /// sender began a new channel.
    pub(crate) fn insert(&self, session: Arc<RecvSession>) {
        let mut store = self.store.lock();
        let replaced: Vec<u64> = store
            .by_id
            .values()
            .filter(|s| {
                s.id != session.id
                    && s.space == session.space
                    && s.sender == session.sender
                    && s.mode == session.mode
            })
            .map(|s| s.id)
            .collect();
        for id in replaced {
            if let Some(old) = store.by_id.remove(&id) {
                old.end(EndReason::Replaced);
            }
        }
        store.by_id.insert(session.id, session);
    }

    /// Drop the session of channel `id`.
    pub(crate) fn remove(&self, id: u64) {
        self.store.lock().by_id.remove(&id);
    }

    /// End and drop each session past its lifetime and grace at `now`; returns their ids.
    pub(crate) fn lapse(&self, now: Instant) -> Vec<u64> {
        let mut store = self.store.lock();
        let mut gone = Vec::new();
        store.by_id.retain(|id, s| {
            let keep = s.ended().is_none() && s.usable(now);
            if !keep {
                s.end(EndReason::Lapsed);
                gone.push(*id);
            }
            keep
        });
        gone
    }

    /// The sessions due their renewal at `now`.
    pub(crate) fn due(&self, now: Instant) -> Vec<Arc<RecvSession>> {
        self.all()
            .into_iter()
            .filter(|s| s.renewal_due(now))
            .collect()
    }

    /// A frame of channel `id` came under a key epoch (low octet `low`) this device does not
    /// hold, at `now`. The first time a new epoch is seen is noted (the grace of the key before it
    /// counts from there). The sender is to be asked again at most once a second.
    pub(crate) fn unknown_epoch(&self, id: u64, low: u8, now: Instant) -> Unknown {
        let mut store = self.store.lock();
        let Some(session) = store.by_id.get(&id).cloned() else {
            return Unknown::NoSession;
        };
        {
            let mut state = session.state.lock();
            if state.first_seen.is_none_or(|(l, _)| l != low) {
                state.first_seen = Some((low, now));
            }
        }
        if store
            .asked_for_epoch
            .get(&session.sender)
            .is_some_and(|at| now.saturating_duration_since(*at) < UNKNOWN_EPOCH_ASK_EVERY)
        {
            return Unknown::Limited;
        }
        store.asked_for_epoch.insert(session.sender.clone(), now);
        // What an old sender left is not kept for ever.
        if store.asked_for_epoch.len() > 1024 {
            store
                .asked_for_epoch
                .retain(|_, at| now.saturating_duration_since(*at) < Duration::from_secs(60));
        }
        Unknown::Ask {
            space: session.space.clone(),
            sender: session.sender.clone(),
            mode: session.mode,
        }
    }
}

#[cfg(test)]
#[path = "sessions_tests.rs"]
mod tests;
