//! The receiver's session store (docs/specs/channel.md, Receiver): one [`RecvSession`] per
//! (space, sender, mode), what a sender's signed answer gave this device.
//!
//! A session is **usable** until its lifetime plus a 5 s grace has passed on the monotonic clock,
//! counted from the receipt of the answer (no wall clock is read: a clock that steps changes
//! nothing). It holds the key of the epoch it was last given and, for [`REKEY_GRACE`] after the
//! answer that gave the next key epoch, the key before it, so frames in flight under the old key
//! are not lost. The frame layer asks, per frame, [`RecvSession::is_current`] (two atomic loads:
//! the trust generation and the space's fold version it was judged under) and, when either moved,
//! [`RecvSession::recheck`], which judges the sender again from what the node holds, offline, and
//! drops the session with its reason if the sender no longer stands.
//!
//! A frame under a key epoch the session does not hold calls [`RecvSessions::unknown_epoch`], which
//! says whether to ask the sender again: at most once a second per sender. Such a frame is not
//! authenticated, so it changes nothing of the session.

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

/// How long the key before the current one is accepted after the answer that gave the new one.
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
    /// A checkpoint of the channel did not verify under the sender's key: some holder of the
    /// channel key made it (the sender signs with a key no receiver holds), so the frames of this
    /// session are not to be trusted. The session was dropped, evidence kept
    /// ([`crate::host::NodeHandle::channel_evidence`]) and [`crate::Alert::ChannelCheckpoint`] raised.
    /// Ask the sender again for a new session once the face that carried it is dealt with.
    BadCheckpoint {
        /// What was wrong, and what to do.
        why: String,
    },
    /// Frames came and no checkpoint that verifies came for them within 3 s: this receiver cannot
    /// tell the sender's frames from a key holder's, so it ended the session instead of trusting
    /// them. Ask the sender again: the cause is a link that drops the sender's stream (where
    /// checkpoints ride), a sender that stopped signing, or a key holder racing the sender.
    Unverifiable {
        /// What was waited for, and what to do.
        why: String,
    },
}

impl fmt::Display for EndReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EndReason::NotMember { why } => write!(f, "not a member: {why}"),
            EndReason::Replaced => f.write_str("the sender began a new channel"),
            EndReason::Lapsed => f.write_str("its lifetime ran out and it was not renewed"),
            EndReason::Left => f.write_str("this device left the space"),
            EndReason::Closed => f.write_str("the sender ended the channel"),
            EndReason::BadCheckpoint { why } => {
                write!(f, "a checkpoint was not the sender's: {why}")
            }
            EndReason::Unverifiable { why } => write!(f, "frames could not be verified: {why}"),
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
    pub(crate) carriers: Vec<CarrierOffer>,
    /// The name ids bound so far.
    pub(crate) table: Vec<Bind>,
    /// The checkpoint period in milliseconds, 0 when the sender sends none.
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
    installed: Instant,
    lifetime: Duration,
    terms: Terms,
    /// The key that signed the sender's last answer.
    sender_key: Name,
    /// The 32 octets of that key's Ed25519 public key, as a certificate this device vouches for
    /// carries it: what a checkpoint's signature is verified under. `None` when no such
    /// certificate was found (checkpoints then cannot be verified, which is not forgery).
    signer_public: Option<[u8; 32]>,
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
    /// The checkpoint period the sender's last answer announced, or `None` when its channel sends
    /// no checkpoints (its carrier has no stream): such a channel cannot be
    /// [`crate::Trust::Verified`], and what it delivers is authenticated only as a holder of the
    /// channel key's. See [`ChannelInfo::detection_window`].
    pub checkpoint: Option<Duration>,
}

impl ChannelInfo {
    /// The stated detection window of this channel for a stream whose one-way delay is `delay`:
    /// `W = P + d + ε` with the sender's period `P` and ε of 1 ms (see
    /// [`crate::ChannelConfig`]). A frame a key holder forged is delivered to a
    /// [`crate::Trust::Prompt`] receiver for at most this long before a signed checkpoint exposes
    /// it. `None` for a channel that sends no checkpoints: nothing ever exposes a forgery there.
    pub fn detection_window(&self, delay: Duration) -> Option<Duration> {
        self.checkpoint
            .map(|period| period + delay + super::config::VERIFY_EPSILON)
    }
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
                installed: now,
                lifetime: Duration::from_secs(record.lifetime),
                terms: Terms::of(record),
                sender_key,
                signer_public: None,
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

    /// Whether the sender's last answer offers the stream carrier. A session that does not (the
    /// path from the sender has no stream) is given no `HELLO`, so none is waited for.
    pub(crate) fn offers_stream(&self) -> bool {
        self.state
            .lock()
            .terms
            .carriers
            .iter()
            .any(|c| c.kind == super::wire::carrier::STREAM)
    }

    /// The sequence the sender's last answer said its next message takes (`S_SEQ`): where this
    /// receiver's frames begin, and the floor a frame's `seq0` is measured from when the
    /// receiver has seen none above it (the receiver's `too_far` rule).
    pub(crate) fn seq(&self) -> u64 {
        self.state.lock().terms.seq
    }

    /// The frame key of the epoch this session holds now, and that whole epoch: what the
    /// `adversary` feature's holder seals under.
    #[cfg(feature = "adversary")]
    pub(crate) fn current_frame_key(&self) -> Option<(FrameKey, u32)> {
        let state = self.state.lock();
        state
            .ended
            .is_none()
            .then(|| (state.current.frame.clone(), state.current.epoch))
    }

    /// The 32 octets of the Ed25519 public key checkpoints of this channel are verified under
    /// (see [`Self::set_signer_public`]).
    pub(crate) fn signer_public(&self) -> Option<[u8; 32]> {
        self.state.lock().signer_public
    }

    /// The sender's key, as this device found it in a certificate it vouches for when the answer
    /// was taken (an answer's own key is the one that signed it: the digest the validator
    /// resolved to a certificate names exactly this key). Set at each install and renewal.
    pub(crate) fn set_signer_public(&self, public: Option<[u8; 32]>) {
        self.state.lock().signer_public = public;
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
            checkpoint: (state.terms.ckpt_ms > 0)
                .then(|| Duration::from_millis(state.terms.ckpt_ms.clamp(1, 2_000))),
        }
    }

    /// Why the session ended, if it did.
    pub(crate) fn ended(&self) -> Option<EndReason> {
        self.state.lock().ended.clone()
    }

    /// When the session was installed (the answer was taken, or the last renewal began).
    pub(crate) fn installed(&self) -> Instant {
        self.state.lock().installed
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
            && now.saturating_duration_since(state.installed)
                < state.lifetime.saturating_add(LIFETIME_GRACE)
    }

    /// Whether the session is due its renewal at `now`: 75 % of its lifetime has passed since it
    /// was received, and a renewal that failed is not waited on.
    pub(crate) fn renewal_due(&self, now: Instant) -> bool {
        let state = self.state.lock();
        state.ended.is_none()
            && now.saturating_duration_since(state.installed)
                >= state.lifetime.saturating_mul(3) / 4
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
    #[cfg(test)]
    pub(crate) fn frame_key(&self, low: u8, now: Instant) -> Option<FrameKey> {
        self.frame_key_epoch(low, now).map(|(key, _)| key)
    }

    /// [`Self::frame_key`] and the whole key epoch it was derived for (a frame's header carries
    /// only its low octet; a checkpoint's signature covers all 32 bits).
    pub(crate) fn frame_key_epoch(&self, low: u8, now: Instant) -> Option<(FrameKey, u32)> {
        let state = self.state.lock();
        if state.ended.is_some()
            || now.saturating_duration_since(state.installed)
                >= state.lifetime.saturating_add(LIFETIME_GRACE)
        {
            return None;
        }
        if state.current.epoch as u8 == low {
            return Some((state.current.frame.clone(), state.current.epoch));
        }
        match &state.previous {
            Some((held, until)) if held.epoch as u8 == low && now < *until => {
                Some((held.frame.clone(), held.epoch))
            }
            _ => None,
        }
    }

    /// The session took a new answer of the same channel at `now`: a renewal, or a key pulled
    /// after a re-key. A key epoch not newer than the one held changes only the lifetime. The key
    /// before stays acceptable until [`REKEY_GRACE`] after this answer.
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
            // Counted from this answer: a frame under a key this device does not hold is not
            // authenticated, so nothing it says is a time to count from.
            let frame = key.frame_key(record.id, record.key_epoch);
            let old = std::mem::replace(
                &mut state.current,
                Held {
                    epoch: record.key_epoch,
                    _key: key,
                    frame,
                },
            );
            state.previous = Some((old, now + REKEY_GRACE));
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

/// The channel another sender, space or mode holds: what a session that names an id already held
/// is refused for ([`RecvSessions::insert`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct IdHeld {
    /// The space of the channel that holds the id.
    pub(crate) space: Name,
    /// Its sender's device.
    pub(crate) sender: Name,
    /// Its mode.
    pub(crate) mode: ChannelMode,
}

/// Why an ask's session was not installed ([`RecvSessions::insert_asked`]).
pub(crate) enum NotInstalled {
    /// The channel was let go after the ask began.
    Stale,
    /// The id belongs to another channel.
    IdHeld(IdHeld),
}

/// What the asks of one `(space, mode)` in flight share.
#[derive(Default)]
struct Lane {
    /// The value of [`Store::releases`] at the last release of the channel while an ask was in
    /// flight.
    released: u64,
    /// Asks in flight.
    asking: u32,
}

/// An ask of `(space, mode)` in flight ([`RecvSessions::asking`]); its drop ends it.
///
/// **The invariant.** A session is installed from an answer only if the channel was not let go
/// (the last `Items` taking `(space, mode)` dropped: [`RecvSessions::released`]) since the ask
/// began. The ask's `new` flag, its Interest and so the route its answer lays at every forwarder
/// all come after `began`; a release after it gives up the route by an `Unsub` that the answer's
/// route may or may not have beaten, so the answer says nothing of what the receiver holds and
/// is discarded ([`ChanError::Superseded`](super::error::ChanError::Superseded)), whatever the
/// timing of the links. Which asks are stale is decided by one counter under the store's lock,
/// not by clocks.
pub(crate) struct Asking<'a> {
    sessions: &'a RecvSessions,
    key: (Name, ChannelMode),
    began: u64,
}

impl Asking<'_> {
    /// Whether no other ask of this `(space, mode)` is in flight.
    pub(crate) fn alone(&self) -> bool {
        self.sessions
            .store
            .lock()
            .lanes
            .get(&self.key)
            .is_none_or(|lane| lane.asking <= 1)
    }
}

impl Drop for Asking<'_> {
    fn drop(&mut self) {
        let mut store = self.sessions.store.lock();
        if let Some(lane) = store.lanes.get_mut(&self.key) {
            lane.asking -= 1;
            if lane.asking == 0 {
                store.lanes.remove(&self.key);
            }
        }
    }
}

#[derive(Default)]
struct Store {
    by_id: FastMap<u64, Arc<RecvSession>>,
    asked_for_epoch: FastMap<Name, Instant>,
    /// Releases so far (a counter, not a clock).
    releases: u64,
    /// The `(space, mode)` that have an ask in flight.
    lanes: FastMap<(Name, ChannelMode), Lane>,
}

/// The sessions this device holds as a receiver.
#[derive(Default)]
pub(crate) struct RecvSessions {
    store: Mutex<Store>,
    /// Moves whenever the set of sessions held does (one is inserted, removed or lapses): what a
    /// receiver cached of a lookup is good while this stands still.
    generation: AtomicU64,
    /// How many times the store was asked for a session by id (a test counts them).
    #[cfg(test)]
    lookups: AtomicU64,
}

impl RecvSessions {
    /// The session of channel `id`.
    pub(crate) fn get(&self, id: u64) -> Option<Arc<RecvSession>> {
        #[cfg(test)]
        self.lookups.fetch_add(1, Ordering::Relaxed);
        self.store.lock().by_id.get(&id).cloned()
    }

    /// The generation of the set of sessions held: read it before a lookup, and what the lookup
    /// found stands while it reads the same.
    pub(crate) fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// How many times [`Self::get`] ran (a test asks).
    #[cfg(test)]
    pub(crate) fn lookups(&self) -> u64 {
        self.lookups.load(Ordering::Relaxed)
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
    ///
    /// A channel id belongs to the (space, sender, mode) that holds it. It is in the clear in every
    /// frame header, so a session that names an id another channel holds is refused with
    /// [`IdHeld`] and nothing changes: otherwise a second writer could take the frames of the
    /// first.
    #[cfg(test)]
    pub(crate) fn insert(&self, session: Arc<RecvSession>) -> Result<(), IdHeld> {
        let mut store = self.store.lock();
        self.insert_in(&mut store, session)
    }

    /// [`Self::insert`] of the session an ask installs, refused as [`NotInstalled::Stale`] when
    /// the channel was let go ([`Self::released`]) after the ask began. The check and the
    /// insertion are one step under the store's lock, so a release either comes first (the
    /// session is refused) or after (the release finds the session and lets it go).
    pub(crate) fn insert_asked(
        &self,
        session: Arc<RecvSession>,
        asking: &Asking<'_>,
    ) -> Result<(), NotInstalled> {
        let mut store = self.store.lock();
        let stale = store
            .lanes
            .get(&asking.key)
            .is_some_and(|lane| lane.released > asking.began);
        if stale {
            return Err(NotInstalled::Stale);
        }
        self.insert_in(&mut store, session)
            .map_err(NotInstalled::IdHeld)
    }

    /// The last `Items` taking `(space, mode)` was dropped: every ask of it that began before is
    /// stale ([`Asking`]).
    pub(crate) fn released(&self, space: &Name, mode: ChannelMode) {
        let mut store = self.store.lock();
        store.releases += 1;
        let at = store.releases;
        if let Some(lane) = store.lanes.get_mut(&(space.clone(), mode)) {
            lane.released = at;
        }
    }

    /// An ask of `(space, mode)` is about to go out: read before the ask's `new` flag is decided
    /// and before its Interest leaves, and held until its answer was taken or refused.
    pub(crate) fn asking(&self, space: &Name, mode: ChannelMode) -> Asking<'_> {
        let mut store = self.store.lock();
        let began = store.releases;
        let key = (space.clone(), mode);
        store.lanes.entry(key.clone()).or_default().asking += 1;
        Asking {
            sessions: self,
            key,
            began,
        }
    }

    fn insert_in(&self, store: &mut Store, session: Arc<RecvSession>) -> Result<(), IdHeld> {
        if let Some(holder) = store.by_id.get(&session.id)
            && (holder.space != session.space
                || holder.sender != session.sender
                || holder.mode != session.mode)
        {
            return Err(IdHeld {
                space: holder.space.clone(),
                sender: holder.sender.clone(),
                mode: holder.mode,
            });
        }
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
        self.generation.fetch_add(1, Ordering::Release);
        Ok(())
    }

    /// Drop the session of channel `id`.
    pub(crate) fn remove(&self, id: u64) {
        self.store.lock().by_id.remove(&id);
        self.generation.fetch_add(1, Ordering::Release);
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
        if !gone.is_empty() {
            self.generation.fetch_add(1, Ordering::Release);
        }
        gone
    }

    /// The sessions due their renewal at `now`.
    pub(crate) fn due(&self, now: Instant) -> Vec<Arc<RecvSession>> {
        self.all()
            .into_iter()
            .filter(|s| s.renewal_due(now))
            .collect()
    }

    /// A frame of channel `id` came under a key epoch this device does not hold, at `now`. The
    /// frame is not authenticated (its key is not held), so it changes nothing of the session:
    /// all it can do is make the sender be asked again, at most once a second per sender.
    pub(crate) fn unknown_epoch(&self, id: u64, now: Instant) -> Unknown {
        let mut store = self.store.lock();
        let Some(session) = store.by_id.get(&id).cloned() else {
            return Unknown::NoSession;
        };
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
