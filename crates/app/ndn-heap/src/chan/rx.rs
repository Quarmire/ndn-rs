//! The receiver (docs/specs/channel.md, The receiver): what a node does with a channel frame the
//! host hands it ([`NodeHandle::deliver_frame`]), in the order the spec gives.
//!
//! **Before any cryptography**, each costs at most a length test, a header parse or one lookup:
//! a frame under 46 octets or over the largest any session may grant; a marker, version, kind or
//! class that is not assigned; a count or sequence the kind does not allow; a channel id this
//! device holds no session of (a **stream** frame is **held**, copied, and taken in when a session
//! of that id is installed: [`rx_hold`](super::rx_hold); a datagram is lost); a frame over the
//! limit that session grants for its class; a
//! `Reliable` or `Window` frame on a datagram; a session whose sender no longer stands (the
//! generation check: **the first frame after the node holds the removing record is refused**, the
//! session ends and the `Items` are told); a key epoch the session does not hold (no AEAD attempt:
//! the sender is asked again, at most once a second); a `seq0` the replay window has seen or
//! passed. Only then one AEAD attempt, and a sequence is marked seen **after** the tag verified:
//! a forged copy of a genuine `seq0` is an attempt and a refusal and burns nothing.
//!
//! **After** the tag: the messages parse (the whole frame or none of it), a `CONTROL` frame is read
//! (`BIND`, `UNBIND`, `HELLO`, `END`, the standing bracket), a gap in `Reliable` and `Window` is
//! told and, in `Window`, asked for again, a message with a name id the table does not know is held
//! 50 ms, and what is left is pushed to each [`Sink`] of the space whose path filter keeps it.
//!
//! Frames of one channel are processed one at a time, under one lock, in the order they were
//! handed in. No timer task runs: the hold is swept by frames, by `Items` polls and by the node's
//! maintenance pass.

use super::FastMap;
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_transport::side_header::HeaderError;
use ndn_transport::{FaceId, SideClass, SideKind};
use parking_lot::{Mutex, RwLock};

use super::aead::{Aead, FrameCipher};
use super::checkpoint::Record;
use super::control::Control;
use super::evidence::{ChannelEvidence, EvidenceKind};
use super::frame::{FrameError, Header, Opened, open};
use super::hub::Counter;
use super::items::{Out, Sink};
use super::key::FrameKey;
use super::latest::Pair;
use super::limits::{
    FRAME_OVERHEAD, MIN_FRAME_LEN, STREAM_FRAME_DEFAULT, STREAM_FRAME_MAX, message_limit_for,
};
use super::message::{Message, Origin};
use super::replay::{Replay, ReplayWindow};
use super::rx_hold::Hold;
use super::rx_names::{Held, Names, Seen};
use super::sessions::{EndReason, RecvSession, RecvSessions, Unknown};
use super::verbs::{Emitted, Got, Kind, LiveEnd, Trust};
use super::verify::{Accepted, Budget, Dup, Judged, Mismatch, Silence, Verify};
use super::wire::{Bind, ChannelMode};
use crate::error::Timestamp;
use crate::host::NodeHandle;
use crate::log::{Alert, Change};
use crate::node::NodeInner;
use crate::rt::Instant;

/// The shortest time between two re-asks of a `Window` sender made because of a gap.
pub(crate) const REASK_EVERY: Duration = Duration::from_secs(1);

/// What the receiver counted: the proof of what a frame cost and why it was not delivered.
#[derive(Default)]
pub(crate) struct RxStats {
    /// Frames handed to the receiver.
    pub(crate) frames: Counter,
    /// Frames under 46 octets: dropped before anything else.
    pub(crate) short: Counter,
    /// Frames whose first octet is not the side marker.
    pub(crate) marker: Counter,
    /// Frames of a version other than 1.
    pub(crate) version: Counter,
    /// Frames of a kind not assigned, on a class it never uses, or not sealed (an `UP`).
    pub(crate) kind: Counter,
    /// Frames shorter than their header.
    pub(crate) truncated: Counter,
    /// Frames whose message count the kind does not allow.
    pub(crate) count: Counter,
    /// Frames whose sequence reaches 2^63.
    pub(crate) sequence: Counter,
    /// Frames over the limit of their class.
    pub(crate) oversize: Counter,
    /// Frames of a channel id this device holds no session of.
    pub(crate) unknown_channel: Counter,
    /// `Reliable` or `Window` frames that came as datagrams.
    pub(crate) wrong_class: Counter,
    /// Frames of a session whose sender no longer stands (the session ended).
    pub(crate) not_member: Counter,
    /// Frames under a key epoch the session does not hold: dropped without an AEAD attempt.
    pub(crate) unknown_epoch: Counter,
    /// Of those, the ones that did not ask the sender again (one ask a second).
    pub(crate) epoch_limited: Counter,
    /// Asks made because of a frame under an unknown key epoch.
    pub(crate) epoch_asks: Counter,
    /// Frames whose `seq0` the replay window had seen: dropped before the AEAD.
    pub(crate) replayed: Counter,
    /// Frames whose `seq0` is below the replay window: dropped before the AEAD.
    pub(crate) too_old: Counter,
    /// Frames that authenticated and whose `seq0` is more than 2^24 above what the window has
    /// seen and the sender's last answer said: refused, and the sender is asked again (a
    /// genuine frame can only be that far after the receiver was cut off).
    pub(crate) too_far: Counter,
    /// AEAD attempts: the only cryptography a frame costs.
    pub(crate) aead_attempts: Counter,
    /// Attempts that failed: not this session's key, or altered.
    pub(crate) unauthentic: Counter,
    /// Frames that authenticated and were refused: a message or record that does not parse.
    pub(crate) malformed: Counter,
    /// Frames that authenticated and were taken.
    pub(crate) accepted: Counter,
    /// Messages read from accepted frames.
    pub(crate) messages: Counter,
    /// Messages dropped for a name id the table did not know within 50 ms, or because 64 were
    /// held already.
    pub(crate) unknown_name: Counter,
    /// Messages held for their bind.
    pub(crate) name_held: Counter,
    /// Messages dropped at once because the hold was full.
    pub(crate) hold_full: Counter,
    /// `BIND`s and `NAMED` messages whose id or name was refused.
    pub(crate) bad_bind: Counter,
    /// `STANDING` messages outside the standing bracket.
    pub(crate) standing_stray: Counter,
    /// `REPLAYED` messages whose original was delivered already.
    pub(crate) duplicates: Counter,
    /// Gaps told in `Reliable` and `Window`.
    pub(crate) gaps: Counter,
    /// Re-asks made because of a gap in `Window`.
    pub(crate) reasks: Counter,
    /// `CONTROL` frames taken.
    pub(crate) controls: Counter,
    /// `HELLO`s taken.
    pub(crate) hellos: Counter,
    /// `CHECKPOINT` frames taken (read, and judged when the sender's key verifies them).
    pub(crate) checkpoints: Counter,
    /// Checkpoints whose signature verified under the sender's key.
    pub(crate) checkpoints_verified: Counter,
    /// Checkpoints that could not be verified because this device holds no certificate of the
    /// sender's key (not a forgery: the silence rule applies).
    pub(crate) unverifiable_checkpoints: Counter,
    /// Checkpoints that opened under the channel key and did not verify under the sender's: the
    /// session was dropped.
    pub(crate) bad_checkpoints: Counter,
    /// Accepted frames a verified checkpoint contradicted (each is evidence).
    pub(crate) mismatches: Counter,
    /// Second authentic frames at an already accepted sequence (each is evidence; not delivered).
    pub(crate) conflicts: Counter,
    /// Frames no checkpoint judged: forgotten for the ring's bounds (4,096 frames, 2 MiB a
    /// channel, 8 MiB a node), or below a range that was verified without them.
    pub(crate) unchecked: Counter,
    /// Frames held for a lane that had to wait for a verified checkpoint.
    pub(crate) held: Counter,
    /// Held frames dropped, once for each lane that lost them: over the hold's bounds, or
    /// unlisted for good (a lost checkpoint), or 3 s old.
    pub(crate) held_dropped: Counter,
    /// Times the names a key holder wrote (a contradicted `CONTROL` frame) were taken back.
    pub(crate) resets: Counter,
    /// Sessions ended because no checkpoint verified in 3 s.
    pub(crate) unverifiable: Counter,
    /// Frames of a space no `Items` wants.
    pub(crate) no_sink: Counter,
    /// Sessions ended by the receiver (a removed sender, the sender's `END`).
    pub(crate) ended: Counter,
    /// Frames of a channel id this device holds no session of that were refused because the hold
    /// had no room for them: their own face held the most already, or the frame is larger than a
    /// face's share.
    pub(crate) held_unknown_full: Counter,
    /// Frames held for an unknown channel id that were pushed out, before they were claimed or
    /// expired, to make room for a frame of a face that held less.
    pub(crate) held_unknown_evicted: Counter,
    /// Frames of an unknown channel id that were held 2 s without a session coming: dropped.
    pub(crate) held_unknown_expired: Counter,
}

/// Why a frame was not delivered. Every reason is counted by the node (channel.md §12.8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Dropped {
    /// Under 46 octets.
    Short,
    /// The first octet is not the side marker `0x00`: not a channel frame.
    NotASideFrame,
    /// A version other than 1.
    Version,
    /// A kind that is not assigned, is on a class it never uses, or is not sealed.
    Kind,
    /// Shorter than the 20-octet header.
    Truncated,
    /// A message count the kind does not allow.
    Count,
    /// A sequence at or above 2^63.
    Sequence,
    /// Over the limit of its class.
    Oversize,
    /// No session of that channel is held (or it ended while the frame waited): a datagram is
    /// lost, and so is a stream frame the hold has no room for (a face's share, §12.1 row 4).
    UnknownChannel,
    /// A `Reliable` or `Window` data frame on a datagram.
    WrongClass,
    /// Under a key epoch the session does not hold; the sender is asked again, at most once a
    /// second.
    UnknownEpoch,
    /// A sequence seen already.
    Replayed,
    /// A sequence below the replay window.
    TooOld,
    /// Authenticated, and its sequence is more than 2^24 above the highest this receiver has
    /// seen and the sender's last answer said (a receiver cut off longer than that is told by
    /// the sender's next answer, which this frame makes the receiver ask for, at most once a
    /// second).
    TooFar,
    /// The tag did not verify.
    Unauthentic,
    /// Authenticated, and a message or record in it does not parse.
    Malformed,
}

/// What [`NodeHandle::deliver_frame`] did with a frame.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Delivery {
    /// A data frame: its messages were read and pushed to the `Items` that want them (a message
    /// held for an unknown name or dropped as a duplicate is among `messages`).
    Delivered {
        /// Messages the frame carried.
        messages: usize,
    },
    /// A `CONTROL` frame was read and applied.
    Control,
    /// A `CHECKPOINT` frame was read: its signature was checked, and the frames it covers were
    /// settled, exposed or released.
    Checkpoint,
    /// The frame was accepted and is **not delivered yet**: it waits for a checkpoint that lists
    /// it (a `Trust::Verified` receiver) or for a verified checkpoint to lift the hold (frames
    /// went unchecked for longer than `max(4 x period, 100 ms)`). It is delivered or dropped, and
    /// counted, when one arrives.
    Deferred,
    /// A second authentic frame at a sequence that already holds an accepted frame of other
    /// octets (a holder of the channel key made one of the two): **an event, not a delivery**.
    /// The first accepted stays the one delivered; evidence was made at once, and neither face is
    /// barred nor named in an alert until a checkpoint that covers the sequence says which of the
    /// two frames the sender did not send (a sequence a checkpoint already listed is decided at
    /// once, against the second frame's face).
    Conflict,
    /// Not delivered, and why. Nothing was changed but a counter.
    Dropped(Dropped),
    /// The session ended with this frame: the sender no longer stands, or said `END`. The frame is
    /// not delivered, and every `Items` of the space is told.
    Ended(EndReason),
    /// A **stream** frame of a channel id this device holds no session of: kept at most 2 s for
    /// the session to be installed (it is the session Data that tells the channel's key; the frame
    /// is not decrypted and decides nothing), then dropped.
    Held,
}

/// The octets of `name` as a Name TLV's value.
fn name_octets(name: &Name) -> Bytes {
    let tlv = name.encode_to_tlv();
    let skip = match tlv.get(1) {
        Some(253) => 4,
        Some(254) => 6,
        Some(255) => 10,
        _ => 2,
    };
    tlv.slice(skip..)
}

/// What a frame leaves to do after its lock is let go.
#[derive(Default)]
struct Post {
    /// Ask the `Window` sender again for the sequences from here.
    reask: Option<u64>,
    /// The session ends with this reason (the sender said `END` and a checkpoint listed it, a
    /// checkpoint was not the sender's, nothing verified in time).
    end: Option<EndReason>,
    /// An authentic frame was too far ahead of the sequences held: ask the sender again.
    far: bool,
    /// Faces to bar from channel frames, each once.
    bars: Vec<u64>,
    /// What the host is told: each becomes a `Change::Alert` and a `warn` log.
    alerts: Vec<Alert>,
    /// A holder of the key wrote the names this receiver reads by: ask the sender again.
    resync: bool,
}

/// The class of sinks a frame is applied for.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Lane {
    /// [`Trust::Prompt`] sinks: the frame is applied as it is accepted.
    Prompt,
    /// [`Trust::Verified`] sinks: the frame is applied when a checkpoint that lists it verified.
    Verified,
}

/// The bit of a held frame that says the `Prompt` lane has not been given it yet (the receiver
/// held it because no checkpoint verified in time).
const PROMPT: u8 = 1;
/// The bit that says the `Verified` lane has not been given it yet.
const VERIFIED: u8 = 2;

/// The most frames a channel holds for its lanes: the replay window's size.
const HELD_MAX: usize = super::verify::SLOTS_MAX;

/// The sinks of a channel's space and mode, by what they trust.
struct Lanes {
    prompt: Arc<[Arc<Sink>]>,
    verified: Arc<[Arc<Sink>]>,
}

/// What a frame is, parsed: the messages of a `DATA` frame or the record of a `CONTROL` frame.
#[derive(Clone)]
enum Body {
    Data(Vec<Message>),
    Control(Control),
}

/// A frame accepted and not yet applied to a lane.
struct Deferred {
    seq0: u64,
    header: Header,
    body: Body,
    at: Instant,
    /// The lanes that have not been given it ([`PROMPT`], [`VERIFIED`]).
    lanes: u8,
    /// Octets it is charged for.
    bytes: usize,
}

/// What one class of sinks has been given of a channel: the name table it reads by, the
/// sequences it expects, the standing bracket, and the messages on their way to it. A channel
/// has a prompt pipe always and a verified one while a `Trust::Verified` `Items` takes it, so a
/// frame a key holder forged cannot rename what the verified sinks read until a checkpoint lists it.
struct Pipe {
    names: Names<Message>,
    seen: Seen,
    /// The sequence the next frame of the stream should start at.
    expected: Option<u64>,
    standing_open: bool,
    /// The messages of the frame being taken, on their way to the sinks (a buffer kept between
    /// frames, so a frame costs no allocation for them).
    out: Vec<Out>,
    /// The first sequence a `Window` re-ask is still owed from.
    pending_since: Option<u64>,
    reask_at: Option<Instant>,
}

impl Pipe {
    fn new(table: &[Bind]) -> Pipe {
        Pipe {
            names: Self::names(table),
            seen: Seen::default(),
            expected: None,
            standing_open: false,
            out: Vec::new(),
            pending_since: None,
            reask_at: None,
        }
    }

    fn names(table: &[Bind]) -> Names<Message> {
        let mut names = Names::default();
        for bind in table {
            // A table the sender signed: an id or name that is not valid is skipped.
            let _ = names.bind(bind.id, &name_octets(&bind.name));
        }
        names
    }

    /// Forget what a key holder may have written: the names go back to the session's table and the
    /// standing bracket closes. Returns the messages that were held for an id (they are dropped).
    fn reset(&mut self, table: &[Bind]) -> usize {
        let held = self.names.held();
        self.names = Self::names(table);
        self.standing_open = false;
        self.out.clear();
        held
    }
}

struct RxState {
    replay: ReplayWindow,
    prompt: Pipe,
    verified: Option<Pipe>,
    /// The sequence the sender's last `HELLO` said its next message takes.
    hello: Option<u64>,
    /// Prepared ciphers by frame key: the key held and the one before it.
    ciphers: Vec<(FrameKey, FrameCipher)>,
    /// The messages of the frame being taken (a buffer kept between frames).
    parsed: Vec<Message>,
    /// The face the last accepted frame came over.
    last_ingress: u64,
    ended: bool,
    /// The frames accepted and the checkpoint clock: present when the sender checkpoints.
    verify: Option<Verify>,
    /// Frames waiting for a lane: held by silence (`Prompt`) or by `Trust::Verified`.
    held: VecDeque<Deferred>,
    held_bytes: usize,
    /// A frame waited past `unchecked_max` with no verified checkpoint: what follows is held for
    /// the `Prompt` lane until one verifies.
    hold_active: bool,
    /// The sender's `END` waits here, by its sequence, until a checkpoint lists it.
    pending_end: Option<u64>,
    /// The highest sequence an accepted `DATA` or `CONTROL` frame took.
    highest: u64,
    /// `Verified` sinks already told that this channel cannot be verified (by address).
    refused: Vec<usize>,
}

impl RxState {
    fn cipher_index(&mut self, key: &FrameKey, aead: Aead) -> usize {
        if let Some(at) = self
            .ciphers
            .iter()
            .position(|(held, _)| held.expose() == key.expose())
        {
            return at;
        }
        // The key held and the one before it: a third evicts the oldest.
        if self.ciphers.len() >= 2 {
            self.ciphers.remove(0);
        }
        self.ciphers
            .push((key.clone(), FrameCipher::new(key, aead)));
        self.ciphers.len() - 1
    }
}

/// One channel as this device receives it: the session, the replay window, the name table, and
/// what a gap and a `HELLO` need.
pub(crate) struct ChannelRx {
    session: Arc<RecvSession>,
    channel: u64,
    space: Name,
    mode: ChannelMode,
    /// The writer's device and person.
    writer: Name,
    by: Name,
    aead: Aead,
    datagram_limit: usize,
    stream_limit: usize,
    message_limit: usize,
    /// Where the sequences of this receiver begin, as the session said (`S_SEQ`).
    start: u64,
    /// The checkpoint period the sender announced, `None` when it sends none.
    period: Option<Duration>,
    sinks: RwLock<(u64, Arc<Lanes>)>,
    reasking: Arc<AtomicBool>,
    state: Mutex<RxState>,
}

impl ChannelRx {
    fn new(session: &Arc<RecvSession>, node: &NodeInner) -> ChannelRx {
        let terms = session.terms();
        let writer = session.sender().clone();
        let frame_max = usize::try_from(terms.frame_max).unwrap_or(usize::MAX);
        let period =
            (terms.ckpt_ms > 0).then(|| Duration::from_millis(terms.ckpt_ms.clamp(1, 2_000)));
        ChannelRx {
            channel: session.id(),
            space: session.space().clone(),
            mode: session.mode(),
            by: node.person_of(&writer),
            writer,
            aead: terms.aead,
            datagram_limit: frame_max.clamp(MIN_FRAME_LEN, STREAM_FRAME_MAX),
            stream_limit: frame_max.clamp(STREAM_FRAME_DEFAULT, STREAM_FRAME_MAX),
            message_limit: message_limit_for(
                frame_max.clamp(STREAM_FRAME_DEFAULT, STREAM_FRAME_MAX),
            ),
            start: terms.seq,
            period,
            sinks: RwLock::new((
                u64::MAX,
                Arc::new(Lanes {
                    prompt: Arc::from([]),
                    verified: Arc::from([]),
                }),
            )),
            reasking: Arc::new(AtomicBool::new(false)),
            state: Mutex::new(RxState {
                replay: ReplayWindow::new(),
                prompt: Pipe::new(&terms.table),
                verified: None,
                hello: None,
                ciphers: Vec::with_capacity(2),
                parsed: Vec::new(),
                last_ingress: 0,
                ended: false,
                verify: period.map(|p| Verify::new(p, Arc::clone(&node.chan.rx.budget))),
                held: VecDeque::new(),
                held_bytes: 0,
                hold_active: false,
                pending_end: None,
                highest: 0,
                refused: Vec::new(),
            }),
            session: Arc::clone(session),
        }
    }

    /// The sinks of this channel's space that take its mode, as of the registry's generation.
    fn lanes(&self, rx: &Receivers) -> Arc<Lanes> {
        let generation = rx.generation.load(Ordering::Acquire);
        {
            let cached = self.sinks.read();
            if cached.0 == generation {
                return Arc::clone(&cached.1);
            }
        }
        let mine: Vec<Arc<Sink>> = rx
            .sinks
            .lock()
            .iter()
            .filter(|s| s.takes(&self.space, self.mode))
            .cloned()
            .collect();
        let (verified, prompt): (Vec<_>, Vec<_>) =
            mine.into_iter().partition(|s| s.trust == Trust::Verified);
        let lanes = Arc::new(Lanes {
            prompt: prompt.into(),
            verified: verified.into(),
        });
        *self.sinks.write() = (generation, Arc::clone(&lanes));
        lanes
    }

    /// The sequence the sender said its next message takes, if a `HELLO` came.
    #[cfg(test)]
    pub(crate) fn hello(&self) -> Option<u64> {
        self.state.lock().hello
    }

    /// The face the last accepted frame came over.
    #[cfg(test)]
    pub(crate) fn last_ingress(&self) -> u64 {
        self.state.lock().last_ingress
    }

    /// Messages held now for an unbound id.
    #[cfg(test)]
    pub(crate) fn held(&self) -> usize {
        self.state.lock().prompt.names.held()
    }

    /// Frames held for a lane now, and the octets they are charged (a test asks).
    #[cfg(test)]
    pub(crate) fn deferred(&self) -> (usize, usize) {
        let st = self.state.lock();
        (st.held.len(), st.held_bytes)
    }

    /// Slots and octets the checkpoint ring holds (a test asks).
    #[cfg(test)]
    pub(crate) fn ring(&self) -> (usize, usize) {
        self.state
            .lock()
            .verify
            .as_ref()
            .map_or((0, 0), |v| (v.slots(), v.bytes()))
    }

    /// Whether this channel is holding frames for the `Prompt` lane for want of a verified
    /// checkpoint (a test asks).
    #[cfg(test)]
    pub(crate) fn holding(&self) -> bool {
        self.state.lock().hold_active
    }

    fn sweep(&self, rx: &Receivers, stats: &RxStats, now: Instant) {
        let mut st = self.state.lock();
        let mut dropped = st.prompt.names.sweep(now);
        if let Some(verified) = st.verified.as_mut() {
            dropped += verified.names.sweep(now);
        }
        drop(st);
        if dropped > 0 {
            rx.held.fetch_sub(dropped, Ordering::AcqRel);
            for _ in 0..dropped {
                stats.unknown_name.bump();
            }
        }
    }

    /// The checkpoint clocks of this channel at `now`, with nothing but time to go on: frames the
    /// `Verified` lane has held 3 s are dropped (counted, `Lagged`), and a channel whose accepted
    /// frames waited 3 s for a verified checkpoint ends. Called by the node's maintenance pass.
    fn sweep_checks(&self, rx: &Receivers, stats: &RxStats, now: Instant) -> Option<EndReason> {
        let lanes = self.lanes(rx);
        let mut st = self.state.lock();
        if st.ended {
            return None;
        }
        // A frame the `Verified` lane waited 3 s for is never going to be listed.
        let mut expired = Vec::new();
        for d in st.held.iter_mut() {
            if d.lanes & VERIFIED != 0
                && now.saturating_duration_since(d.at) > super::verify::UNVERIFIED_MAX
            {
                d.lanes &= !VERIFIED;
                expired.push((d.seq0, d.header.sequences()));
            }
        }
        for (seq0, sequences) in expired {
            self.lose_lane(&mut st, stats, &lanes, Lane::Verified, seq0, sequences);
        }
        self.drop_done(&mut st, rx);
        let (silence, period) = st.verify.as_ref().map(|v| (v.silence(now), v.period()))?;
        match silence {
            Silence::End => {
                // The session ends with frames still waiting: each lane that was to be given one
                // is told it missed it, before the end.
                self.lose_all_held(&mut st, rx, stats, &lanes);
                stats.unverifiable.bump();
                Some(unverifiable(period))
            }
            _ => None,
        }
    }

    async fn receive(
        &self,
        node: &NodeInner,
        header: Header,
        frame: Bytes,
        ingress: u64,
        now: Instant,
    ) -> Delivery {
        let stats = &node.chan.stats.rx;
        let limit = match header.class {
            SideClass::Datagram => self.datagram_limit,
            SideClass::Stream => self.stream_limit,
        };
        if frame.len() > limit {
            stats.oversize.bump();
            return Delivery::Dropped(Dropped::Oversize);
        }
        let fifo_mode = self.mode != ChannelMode::Latest;
        if fifo_mode && header.class == SideClass::Datagram {
            stats.wrong_class.bump();
            return Delivery::Dropped(Dropped::WrongClass);
        }
        let lanes = self.lanes(&node.chan.rx);
        // Back pressure: a stream frame is not taken while an `Items` that blocks has no room.
        if fifo_mode && header.class == SideClass::Stream && header.kind == SideKind::Data {
            for sink in lanes.prompt.iter().chain(lanes.verified.iter()) {
                sink.wait_room().await;
            }
        }
        // The generation check: the sender is judged again when the trust generation or the
        // space's record moved since, before this frame is taken.
        if !self.session.is_current()
            && let Err(why) = self.session.recheck(node)
        {
            stats.not_member.bump();
            node.chan.rx.end_channel(self.channel, &why);
            return Delivery::Ended(why);
        }
        let Some((key, epoch)) = self.session.frame_key_epoch(header.key_epoch, now) else {
            return self.unknown_epoch(node, now);
        };
        let mut post = Post::default();
        let delivery = {
            let mut st = self.state.lock();
            self.process(
                &mut st, node, &lanes, header, frame, limit, &key, epoch, ingress, now, &mut post,
            )
        };
        self.finish(node, post, now, delivery)
    }

    /// What a frame left to do once its lock was let go: tell the host, bar faces, end the
    /// session, ask again.
    fn finish(&self, node: &NodeInner, post: Post, now: Instant, delivery: Delivery) -> Delivery {
        let Post {
            reask,
            end,
            far,
            bars,
            alerts,
            resync,
        } = post;
        for alert in alerts {
            match &alert {
                Alert::ChannelForgery {
                    writer,
                    channel,
                    seq,
                    via,
                    ..
                } => tracing::warn!(
                    %writer, channel = format_args!("{channel:016x}"), seq, via = via.0,
                    "a frame of this channel is not the sender's: a key holder made it; the face it came over is barred"
                ),
                Alert::ChannelCheckpoint {
                    writer,
                    channel,
                    via,
                    ..
                } => tracing::warn!(
                    %writer, channel = format_args!("{channel:016x}"), via = via.0,
                    "a checkpoint of this channel is not the sender's: the session was dropped"
                ),
                _ => {}
            }
            if let Some(space) = node.space_of(&self.space) {
                space.tell(Change::Alert(alert));
            }
        }
        if !bars.is_empty()
            && let Some(bar) = node.chan.bar.get()
        {
            for ingress in bars {
                bar.bar(ingress);
            }
        }
        if let Some(why) = end {
            self.session.end(why.clone());
            node.chan.sessions.remove(self.channel);
            node.chan.rx.end_channel(self.channel, &why);
            return Delivery::Ended(why);
        }
        if let Some(since) = reask {
            self.reask(node, since);
        }
        if far {
            self.ask_again(node, now, "a frame came far ahead of the sequences held");
        }
        if resync {
            self.ask_again(
                node,
                now,
                "a key holder wrote the names this device reads by",
            );
        }
        delivery
    }

    /// A frame under a key epoch the session does not hold: no AEAD attempt. The sender is asked
    /// again, at most once a second per sender.
    fn unknown_epoch(&self, node: &NodeInner, now: Instant) -> Delivery {
        let stats = &node.chan.stats.rx;
        stats.unknown_epoch.bump();
        if !self.ask_again(node, now, "a frame came under a new key epoch") {
            stats.unknown_channel.bump();
            return Delivery::Dropped(Dropped::UnknownChannel);
        }
        Delivery::Dropped(Dropped::UnknownEpoch)
    }

    /// Ask the sender for the session again, at most once a second per sender (one limit for every
    /// cause: a frame under an unknown key epoch, and an authentic frame far ahead of the
    /// sequences held). The answer brings the key epoch it holds and the sequence it has reached.
    /// False when this node holds no session of the channel any more.
    fn ask_again(&self, node: &NodeInner, now: Instant, why: &'static str) -> bool {
        let stats = &node.chan.stats.rx;
        match node.chan.sessions.unknown_epoch(self.channel, now) {
            Unknown::Ask {
                space,
                sender,
                mode,
            } => {
                stats.epoch_asks.bump();
                let node = node.arc();
                let task = Arc::clone(&node);
                node.tasks.spawn(async move {
                    if let Err(error) = task.chan_ask(&space, &sender, mode).await {
                        tracing::debug!(%space, %sender, ?mode, "asking again ({why}) failed: {error}");
                    }
                });
                true
            }
            Unknown::Limited => {
                stats.epoch_limited.bump();
                true
            }
            Unknown::NoSession => false,
        }
    }

    /// Ask the `Window` sender again for the sequences from `since`.
    fn reask(&self, node: &NodeInner, since: u64) {
        if self.reasking.swap(true, Ordering::AcqRel) {
            return;
        }
        node.chan.stats.rx.reasks.bump();
        let (space, sender, mode) = (self.space.clone(), self.writer.clone(), self.mode);
        let flag = Arc::clone(&self.reasking);
        let task = node.arc();
        node.tasks.spawn(async move {
            if let Err(why) = task
                .chan_ask_since(&space, &sender, mode, Some(since))
                .await
            {
                tracing::debug!(%space, %sender, "asking again for a gap failed: {why}");
            }
            flag.store(false, Ordering::Release);
        });
    }

    #[allow(clippy::too_many_arguments)]
    fn process(
        &self,
        st: &mut RxState,
        node: &NodeInner,
        lanes: &Lanes,
        header: Header,
        frame: Bytes,
        limit: usize,
        key: &FrameKey,
        epoch: u32,
        ingress: u64,
        now: Instant,
        post: &mut Post,
    ) -> Delivery {
        let stats = &node.chan.stats.rx;
        if st.ended {
            stats.unknown_channel.bump();
            return Delivery::Dropped(Dropped::UnknownChannel);
        }
        // A frame of the channel sweeps what has been held 50 ms: no timer runs.
        let mut swept = st.prompt.names.sweep(now);
        if let Some(verified) = st.verified.as_mut() {
            swept += verified.names.sweep(now);
        }
        if swept > 0 {
            node.chan.rx.held.fetch_sub(swept, Ordering::AcqRel);
            for _ in 0..swept {
                stats.unknown_name.bump();
            }
        }
        // A frame at a sequence the window has seen is a copy; but a frame that differs from the
        // one accepted there gets one AEAD attempt (at most three a sequence), because a second
        // authentic frame at one sequence is a conflict a key holder made.
        let mut second = false;
        match st.replay.check(header.seq0) {
            Replay::Fresh => {}
            Replay::Replayed => match st.verify.as_mut().map(|v| v.seen(header.seq0, &frame)) {
                Some(Dup::Different) => second = true,
                _ => {
                    stats.replayed.bump();
                    return Delivery::Dropped(Dropped::Replayed);
                }
            },
            Replay::TooOld => {
                stats.too_old.bump();
                return Delivery::Dropped(Dropped::TooOld);
            }
        }
        let at = st.cipher_index(key, self.aead);
        stats.aead_attempts.bump();
        // The octets as they came are kept for the checkpoint that judges them (the AEAD opens
        // the frame in place, so a copy is made first: one allocation).
        let kept = st.verify.is_some().then(|| Bytes::copy_from_slice(&frame));
        let opened = match open(&st.ciphers[at].1, frame, limit) {
            Ok(opened) => opened,
            Err(FrameError::Authentication) => {
                stats.unauthentic.bump();
                return Delivery::Dropped(Dropped::Unauthentic);
            }
            Err(_) => {
                stats.malformed.bump();
                return Delivery::Dropped(Dropped::Malformed);
            }
        };
        if second {
            return self.second(
                st, node, lanes, &header, &opened, kept, ingress, epoch, now, post,
            );
        }
        // A frame far above everything this receiver has seen and the sender last said is refused
        // and marks nothing: a holder of the key can seal any `seq0`, and one such frame marked
        // would make every genuine frame after it too old. The sender's last answer moves the
        // floor (the receiver is asked again), so a receiver cut off for longer than the bound is
        // not stuck.
        if st.replay.beyond(self.start, header.seq0)
            && st
                .replay
                .beyond(self.start.max(self.session.seq()), header.seq0)
        {
            stats.too_far.bump();
            post.far = true;
            return Delivery::Dropped(Dropped::TooFar);
        }
        // Marked only now: a forged frame of a genuine `seq0` burned nothing.
        st.replay.mark(header.seq0);
        st.last_ingress = ingress;
        stats.accepted.bump();
        // A checkpoint takes a sequence too, but nothing is delivered under it: a retraction runs
        // to the highest sequence of a frame that carried something.
        if header.kind != SideKind::Checkpoint {
            st.highest = st
                .highest
                .max(header.seq0 + header.sequences().saturating_sub(1));
        }
        let body = match header.kind {
            SideKind::Data => {
                let messages = match opened.messages(self.message_limit) {
                    Ok(messages) => messages,
                    Err(_) => {
                        stats.malformed.bump();
                        return Delivery::Dropped(Dropped::Malformed);
                    }
                };
                st.parsed.clear();
                for message in messages {
                    match message {
                        Ok(message) => st.parsed.push(message),
                        Err(_) => {
                            st.parsed.clear();
                            stats.malformed.bump();
                            return Delivery::Dropped(Dropped::Malformed);
                        }
                    }
                }
                Body::Data(std::mem::take(&mut st.parsed))
            }
            SideKind::Control => match Control::decode(opened.plaintext()) {
                Ok(control) => {
                    stats.controls.bump();
                    Body::Control(control)
                }
                Err(_) => {
                    stats.malformed.bump();
                    return Delivery::Dropped(Dropped::Malformed);
                }
            },
            SideKind::Checkpoint => {
                let delivery = self.on_checkpoint(
                    st,
                    node,
                    lanes,
                    &header,
                    opened.plaintext(),
                    kept,
                    ingress,
                    epoch,
                    now,
                    true,
                    post,
                );
                return self.after(st, now, post, delivery);
            }
            _ => {
                stats.kind.bump();
                return Delivery::Dropped(Dropped::Kind);
            }
        };
        let plain = opened.plaintext().len() + FRAME_OVERHEAD;
        let delivery = self.dispatch(
            st, node, lanes, header, body, kept, plain, ingress, epoch, now, post,
        );
        self.after(st, now, post, delivery)
    }

    /// What follows every frame: a `Window` sender is asked again for a gap, at most once a second.
    fn after(
        &self,
        st: &mut RxState,
        now: Instant,
        post: &mut Post,
        delivery: Delivery,
    ) -> Delivery {
        if self.mode == ChannelMode::Window
            && st.prompt.pending_since.is_some()
            && st
                .prompt
                .reask_at
                .is_none_or(|at| now.saturating_duration_since(at) >= REASK_EVERY)
        {
            post.reask = st.prompt.pending_since.take();
            st.prompt.reask_at = Some(now);
        }
        delivery
    }

    /// An accepted `DATA` or `CONTROL` frame, parsed: record it for the checkpoint that will judge
    /// it, then give it to each lane that may have it now and hold it for the rest.
    #[allow(clippy::too_many_arguments)]
    fn dispatch(
        &self,
        st: &mut RxState,
        node: &NodeInner,
        lanes: &Lanes,
        header: Header,
        mut body: Body,
        kept: Option<Bytes>,
        plain: usize,
        ingress: u64,
        epoch: u32,
        now: Instant,
        post: &mut Post,
    ) -> Delivery {
        let stats = &node.chan.stats.rx;
        // `Verified` sinks of a channel whose sender sends no checkpoints are told, once each,
        // that nothing will be delivered to them.
        if st.verify.is_none() && !lanes.verified.is_empty() {
            self.refuse_verified(st, lanes);
        }
        let rebinds = match &body {
            Body::Data(messages) => messages.iter().any(|m| m.name.is_some()),
            Body::Control(control) => {
                matches!(control, Control::Bind { .. } | Control::Unbind { .. })
            }
        };
        if let (Some(v), Some(kept)) = (st.verify.as_mut(), kept) {
            v.note_accepted(now);
            let (forgot, ok) = v.offer(
                header.seq0,
                Accepted {
                    frame: kept,
                    ingress,
                    at: now,
                    sequences: header.sequences(),
                    kind: header.kind,
                    epoch,
                    rebinds,
                },
            );
            stats.unchecked.add(forgot + u64::from(!ok));
            let (silence, period) = (v.silence(now), v.period());
            match silence {
                Silence::End => {
                    let why = unverifiable(period);
                    self.lose_all_held(st, &node.chan.rx, stats, lanes);
                    post.end = Some(why.clone());
                    stats.unverifiable.bump();
                    return Delivery::Ended(why);
                }
                Silence::Hold => st.hold_active = true,
                Silence::Ok => {}
            }
        }
        let verified_wanted = st.verify.is_some() && !lanes.verified.is_empty();
        if verified_wanted && st.verified.is_none() {
            st.verified = Some(Pipe::new(&self.session.terms().table));
        } else if lanes.verified.is_empty() {
            st.verified = None;
        }
        let prompt_now = !st.hold_active;
        let waiting =
            (if prompt_now { 0 } else { PROMPT }) | (if verified_wanted { VERIFIED } else { 0 });
        let held_body = (waiting != 0).then(|| body.clone());
        let mut delivery = Delivery::Deferred;
        if prompt_now {
            delivery = self.apply(
                st,
                Lane::Prompt,
                node,
                &lanes.prompt,
                &header,
                &mut body,
                now,
                post,
            );
        }
        // The `Prompt` lane has no sink: nothing was delivered to anyone, and the frame waits for
        // the checkpoint that lists it.
        if lanes.prompt.is_empty()
            && verified_wanted
            && matches!(delivery, Delivery::Delivered { .. })
        {
            delivery = Delivery::Deferred;
        }
        // The buffer the messages were parsed into is kept for the next frame.
        if let Body::Data(buffer) = body {
            st.parsed = buffer;
        }
        if let Some(held_body) = held_body {
            stats.held.bump();
            let deferred = Deferred {
                seq0: header.seq0,
                header,
                body: held_body,
                at: now,
                lanes: waiting,
                bytes: plain,
            };
            self.defer(st, &node.chan.rx, stats, lanes, deferred);
        }
        delivery
    }

    /// Tell each `Verified` sink, once, that this channel cannot be verified: its sender sends no
    /// checkpoints (its path has no stream), so nothing is delivered to it.
    fn refuse_verified(&self, st: &mut RxState, lanes: &Lanes) {
        for sink in lanes.verified.iter() {
            let id = Arc::as_ptr(sink) as usize;
            if st.refused.contains(&id) {
                continue;
            }
            st.refused.push(id);
            sink.end(
                self.channel,
                LiveEnd::Ended {
                    writer: self.writer.clone(),
                    reason: EndReason::Unverifiable {
                        why: format!(
                            "{} sends no checkpoints on this channel (its path has no stream), so \
                             nothing it sends can be verified: ask for `Trust::Prompt`, or use a \
                             path with a stream",
                            self.writer
                        ),
                    },
                },
            );
        }
    }

    /// Put a frame the lanes wait for in the hold, within its bounds: at most 4,096 frames and 2
    /// MiB of the channel's, and the node's 8 MiB across channels. Past a bound the oldest is
    /// dropped, counted and told as a `Lagged` to the lanes that had not been given it.
    fn defer(&self, st: &mut RxState, rx: &Receivers, stats: &RxStats, lanes: &Lanes, d: Deferred) {
        while st.held.len() >= HELD_MAX
            || st.held_bytes + d.bytes > super::verify::CHANNEL_BYTES
            || !rx.budget.try_charge(d.bytes)
        {
            let Some(old) = st.held.pop_front() else {
                // Nothing of this channel's to give up: the frame itself cannot be held.
                self.lose(st, stats, lanes, &d);
                return;
            };
            st.held_bytes -= old.bytes;
            rx.budget.release(old.bytes);
            self.lose(st, stats, lanes, &old);
        }
        st.held_bytes += d.bytes;
        st.held.push_back(d);
    }

    /// A held frame is dropped: each lane that had not been given it says so.
    fn lose(&self, st: &mut RxState, stats: &RxStats, lanes: &Lanes, d: &Deferred) {
        let sequences = d.header.sequences();
        for (bit, lane) in [(PROMPT, Lane::Prompt), (VERIFIED, Lane::Verified)] {
            if d.lanes & bit != 0 {
                self.lose_lane(st, stats, lanes, lane, d.seq0, sequences);
            }
        }
    }

    /// `sequences` sequences from `seq0` will never reach `lane`: its sinks are told a gap, and the
    /// lane's own gap rule does not count them twice.
    fn lose_lane(
        &self,
        st: &mut RxState,
        stats: &RxStats,
        lanes: &Lanes,
        lane: Lane,
        seq0: u64,
        sequences: u64,
    ) {
        stats.held_dropped.bump();
        let (sinks, pipe) = match lane {
            Lane::Prompt => (&lanes.prompt, Some(&mut st.prompt)),
            Lane::Verified => (&lanes.verified, st.verified.as_mut()),
        };
        for sink in sinks.iter() {
            sink.gap(sequences);
        }
        if let Some(pipe) = pipe
            && self.mode != ChannelMode::Latest
        {
            let next = seq0.saturating_add(sequences);
            pipe.expected = Some(pipe.expected.map_or(next, |e| e.max(next)));
        }
    }

    /// The session ends with frames still held: every lane that had not been given one is told it
    /// missed it (counted), and the octets go back.
    fn lose_all_held(&self, st: &mut RxState, rx: &Receivers, stats: &RxStats, lanes: &Lanes) {
        for d in std::mem::take(&mut st.held) {
            self.lose(st, stats, lanes, &d);
            st.held_bytes -= d.bytes;
            rx.budget.release(d.bytes);
        }
    }

    /// Drop held frames no lane waits for any more, giving their octets back.
    fn drop_done(&self, st: &mut RxState, rx: &Receivers) {
        let mut freed = 0;
        st.held.retain(|d| {
            let keep = d.lanes != 0;
            if !keep {
                freed += d.bytes;
            }
            keep
        });
        st.held_bytes -= freed;
        rx.budget.release(freed);
    }

    /// A second frame opened under the key at a sequence that already holds one of other octets.
    /// A checkpoint is read (it is what shows which of the two is the sender's); any other frame
    /// is a conflict: **an event, not a delivery**. The frame accepted first stays the one
    /// delivered; the second is evidence at once and the next checkpoint that covers the sequence
    /// says which of them the sender did not send.
    #[allow(clippy::too_many_arguments)]
    fn second(
        &self,
        st: &mut RxState,
        node: &NodeInner,
        lanes: &Lanes,
        header: &Header,
        opened: &Opened,
        kept: Option<Bytes>,
        ingress: u64,
        epoch: u32,
        now: Instant,
        post: &mut Post,
    ) -> Delivery {
        let stats = &node.chan.stats.rx;
        if header.kind == SideKind::Checkpoint {
            let delivery = self.on_checkpoint(
                st,
                node,
                lanes,
                header,
                opened.plaintext(),
                kept,
                ingress,
                epoch,
                now,
                false,
                post,
            );
            return self.after(st, now, post, delivery);
        }
        stats.conflicts.bump();
        let (Some(v), Some(frame)) = (st.verify.as_mut(), kept) else {
            return Delivery::Dropped(Dropped::Replayed);
        };
        let conflict = v.conflict(
            header.seq0,
            Accepted {
                frame: frame.clone(),
                ingress,
                at: now,
                sequences: header.sequences(),
                kind: header.kind,
                epoch,
                // A second frame is never applied: it binds nothing.
                rebinds: false,
            },
        );
        // A frame at a sequence a verified checkpoint already listed is provably not the sender's
        // (a mismatch against that checkpoint: its face is barred and the host alerted). One set
        // against a frame nothing has vouched for yet is only a conflict, evidence and no more:
        // either of the two faces may be the honest one, so no link is barred and no alert names
        // one until the next checkpoint says which frame is the sender's.
        let (kind, proof) = match conflict.settled_by {
            Some(proof) => {
                stats.mismatches.bump();
                post.bars.push(ingress);
                post.alerts.push(Alert::ChannelForgery {
                    writer: self.writer.clone(),
                    channel: self.channel,
                    key_epoch: epoch,
                    seq: header.seq0,
                    via: FaceId(ingress),
                });
                (EvidenceKind::Mismatch, proof)
            }
            None => (EvidenceKind::Conflict, conflict.first.unwrap_or_default()),
        };
        self.record(node, kind, frame, proof, header.seq0, ingress, epoch);
        Delivery::Conflict
    }

    /// Keep evidence: the last 64 are readable ([`NodeHandle::channel_evidence`]).
    #[allow(clippy::too_many_arguments)]
    fn record(
        &self,
        node: &NodeInner,
        kind: EvidenceKind,
        frame: Bytes,
        proof: Bytes,
        seq0: u64,
        ingress: u64,
        epoch: u32,
    ) {
        node.chan.evidence.push(ChannelEvidence {
            kind,
            channel: self.channel,
            sender: self.writer.clone(),
            key_epoch: epoch,
            seq0,
            frame,
            ingress: FaceId(ingress),
            proof,
            when: Timestamp(node.now()),
        });
    }

    /// A `CHECKPOINT` frame that authenticated under the channel key (see
    /// [`Self::judge_checkpoint`]). The checkpoint takes its own sequence in each lane **after**
    /// the frames it released: frames held for the lane are applied first, so the lane does not
    /// count them as lost because the checkpoint that follows them in the stream came first.
    #[allow(clippy::too_many_arguments)]
    fn on_checkpoint(
        &self,
        st: &mut RxState,
        node: &NodeInner,
        lanes: &Lanes,
        header: &Header,
        plaintext: &Bytes,
        kept: Option<Bytes>,
        ingress: u64,
        epoch: u32,
        now: Instant,
        in_sequence: bool,
        post: &mut Post,
    ) -> Delivery {
        let delivery = self.judge_checkpoint(
            st, node, lanes, header, plaintext, kept, ingress, epoch, now, post,
        );
        if in_sequence {
            self.sequence(&mut st.prompt, node, &lanes.prompt, header, false);
            if let Some(verified) = st.verified.as_mut() {
                self.sequence(verified, node, &lanes.verified, header, false);
            }
        }
        delivery
    }

    /// A `CHECKPOINT` frame that authenticated under the channel key: its signature must verify
    /// under the sender's key, else the session is dropped. A verified checkpoint settles the
    /// frames it lists, exposes the accepted frames in its range that it does not list, and lets
    /// the lanes that waited for it have their frames.
    #[allow(clippy::too_many_arguments)]
    fn judge_checkpoint(
        &self,
        st: &mut RxState,
        node: &NodeInner,
        lanes: &Lanes,
        header: &Header,
        plaintext: &Bytes,
        kept: Option<Bytes>,
        ingress: u64,
        epoch: u32,
        now: Instant,
        post: &mut Post,
    ) -> Delivery {
        let stats = &node.chan.stats.rx;
        stats.checkpoints.bump();
        let (Some(_), Some(frame)) = (st.verify.as_ref(), kept) else {
            // The sender announced none: there is nothing to judge by, and nothing to refuse.
            return Delivery::Checkpoint;
        };
        let record = match Record::decode(plaintext) {
            Ok(record) => record,
            Err(error) => {
                stats.malformed.bump();
                tracing::debug!(
                    channel = self.channel,
                    "a checkpoint does not parse: {error}"
                );
                return Delivery::Dropped(Dropped::Malformed);
            }
        };
        let Some(public) = self.session.signer_public() else {
            // No certificate of the sender's key was found when its answer was taken: nothing can
            // be verified, which says nothing against the sender. The silence rule applies.
            stats.unverifiable_checkpoints.bump();
            return Delivery::Checkpoint;
        };
        if !record.verify(self.channel, epoch, &public) {
            return self.bad_checkpoint(node, header, frame, ingress, epoch, post);
        }
        stats.checkpoints_verified.bump();
        let Some(v) = st.verify.as_mut() else {
            return Delivery::Checkpoint;
        };
        let judged = v.judge(&record, &frame);
        stats.unchecked.add(judged.uncoverable);
        let Judged {
            settled,
            mismatches,
            ..
        } = judged;
        self.expose(st, node, lanes, mismatches, &frame, post);
        self.release(st, node, lanes, &record, &settled, now, post);
        if let Some(end) = st.pending_end
            && settled.binary_search(&end).is_ok()
        {
            // The `END` the sender said is listed by its own signature: now it ends the session.
            post.end.get_or_insert(EndReason::Closed);
        }
        Delivery::Checkpoint
    }

    /// A checkpoint opened under the channel key and was not signed by the sender: a holder of the
    /// key made it. The session is dropped, the face is barred, the host is alerted.
    fn bad_checkpoint(
        &self,
        node: &NodeInner,
        header: &Header,
        frame: Bytes,
        ingress: u64,
        epoch: u32,
        post: &mut Post,
    ) -> Delivery {
        node.chan.stats.rx.bad_checkpoints.bump();
        self.record(
            node,
            EvidenceKind::BadCheckpoint,
            frame,
            Bytes::new(),
            header.seq0,
            ingress,
            epoch,
        );
        post.bars.push(ingress);
        post.alerts.push(Alert::ChannelCheckpoint {
            writer: self.writer.clone(),
            channel: self.channel,
            key_epoch: epoch,
            via: FaceId(ingress),
        });
        let why = EndReason::BadCheckpoint {
            why: format!(
                "a checkpoint of {w}'s channel opened under the channel key and its signature does \
                 not verify under {w}'s key, so a holder of the channel key made it; the face it \
                 came over ({ingress}) is barred: ask {w} again once that link is dealt with",
                w = self.writer
            ),
        };
        post.end = Some(why.clone());
        Delivery::Ended(why)
    }

    /// Frames a verified checkpoint contradicts: evidence, a retraction for each `Prompt` sink, one
    /// bar and one alert for each face that carried them. A contradicted `CONTROL` frame (a
    /// `BIND`, `UNBIND`, `HELLO`, standing bracket) may have been read: everything accepted since
    /// is retracted, the names go back to the session's table, and the sender is asked again.
    fn expose(
        &self,
        st: &mut RxState,
        node: &NodeInner,
        lanes: &Lanes,
        mismatches: Vec<Mismatch>,
        proof: &Bytes,
        post: &mut Post,
    ) {
        let stats = &node.chan.stats.rx;
        let mut poisoned = false;
        for m in mismatches {
            stats.mismatches.bump();
            let Mismatch {
                seq0,
                first,
                accepted,
            } = m;
            self.record(
                node,
                EvidenceKind::Mismatch,
                accepted.frame.clone(),
                proof.clone(),
                seq0,
                accepted.ingress,
                accepted.epoch,
            );
            if first {
                // A frame that wrote the name table (a `BIND`, an `UNBIND`, a message carrying its
                // own name) may have changed how everything after it was read.
                let to = if accepted.kind == SideKind::Data && !accepted.rebinds {
                    seq0 + accepted.sequences.saturating_sub(1)
                } else {
                    poisoned = true;
                    st.highest.max(seq0)
                };
                for sink in lanes.prompt.iter() {
                    sink.retract(&self.writer, seq0, to);
                }
                if st.pending_end == Some(seq0) {
                    st.pending_end = None;
                }
            }
            if !post.bars.contains(&accepted.ingress) {
                post.bars.push(accepted.ingress);
                post.alerts.push(Alert::ChannelForgery {
                    writer: self.writer.clone(),
                    channel: self.channel,
                    key_epoch: accepted.epoch,
                    seq: seq0,
                    via: FaceId(accepted.ingress),
                });
            }
        }
        if poisoned {
            stats.resets.bump();
            let dropped = st.prompt.reset(&self.session.terms().table);
            node.chan.rx.held.fetch_sub(dropped, Ordering::AcqRel);
            post.resync = true;
        }
    }

    /// A checkpoint verified: the frames held for a lane are applied or dropped.
    ///
    /// * The `Prompt` lane's frames (held for want of a verified checkpoint) are applied, in the
    ///   order they were accepted, except any the checkpoint contradicts: the hold is over.
    /// * The `Verified` lane's frames are applied when this checkpoint lists them; one in its
    ///   range that it does not list is dropped (it is evidence); one below its range is dropped
    ///   and counted (**its checkpoint was lost**: ranges only rise, so none will cover it) and
    ///   told as a `Lagged`; one above its range waits for the next.
    #[allow(clippy::too_many_arguments)]
    fn release(
        &self,
        st: &mut RxState,
        node: &NodeInner,
        lanes: &Lanes,
        record: &Record,
        settled: &[u64],
        now: Instant,
        post: &mut Post,
    ) {
        let rx = &node.chan.rx;
        let stats = &node.chan.stats.rx;
        // The hold is over when nothing accepted waits past `unchecked_max` any more: a checkpoint
        // that covers none of what waits (an old one, sealed again by a holder of the key) lifts
        // nothing.
        let still_held = st
            .verify
            .as_ref()
            .is_some_and(|v| v.silence(now) == Silence::Hold);
        st.hold_active = still_held;
        let held = std::mem::take(&mut st.held);
        for mut d in held {
            let covered = d.seq0 >= record.lo && d.seq0 < record.hi;
            let listed = settled.binary_search(&d.seq0).is_ok();
            if covered && !listed {
                // The checkpoint contradicts it: nothing of it reaches a lane.
                d.lanes = 0;
            }
            if d.lanes & PROMPT != 0 && !still_held {
                if d.lanes & VERIFIED != 0 {
                    let mut copy = d.body.clone();
                    self.apply(
                        st,
                        Lane::Prompt,
                        node,
                        &lanes.prompt,
                        &d.header,
                        &mut copy,
                        now,
                        post,
                    );
                } else {
                    self.apply(
                        st,
                        Lane::Prompt,
                        node,
                        &lanes.prompt,
                        &d.header,
                        &mut d.body,
                        now,
                        post,
                    );
                }
                d.lanes &= !PROMPT;
            }
            if d.lanes & VERIFIED != 0 {
                if listed {
                    if st.verified.is_some() {
                        self.apply(
                            st,
                            Lane::Verified,
                            node,
                            &lanes.verified,
                            &d.header,
                            &mut d.body,
                            now,
                            post,
                        );
                    }
                    d.lanes &= !VERIFIED;
                } else if d.seq0 < record.lo
                    || now.saturating_duration_since(d.at) > super::verify::UNVERIFIED_MAX
                {
                    self.lose_lane(
                        st,
                        stats,
                        lanes,
                        Lane::Verified,
                        d.seq0,
                        d.header.sequences(),
                    );
                    d.lanes &= !VERIFIED;
                }
            }
            if d.lanes != 0 {
                st.held.push_back(d);
            } else {
                st.held_bytes -= d.bytes;
                rx.budget.release(d.bytes);
            }
        }
    }

    /// The gap rule: in `Reliable` and `Window` each stream frame must start where the last one
    /// ended; a frame that starts later says that many sequences are missing, which every sink is
    /// told in its place in the stream, and in `Window` is asked for again. `Latest` expects
    /// gaps and notices none.
    fn sequence(
        &self,
        pipe: &mut Pipe,
        node: &NodeInner,
        sinks: &[Arc<Sink>],
        header: &Header,
        hello: bool,
    ) {
        if self.mode == ChannelMode::Latest || header.class != SideClass::Stream {
            return;
        }
        let first = header.seq0;
        let next = first + header.sequences();
        // A `HELLO` is the sender saying where this receiver's stream begins; before one, the
        // session's own sequence is the start.
        let start = pipe
            .expected
            .unwrap_or(if hello { first } else { self.start.min(first) });
        pipe.expected = Some(start.max(next));
        if first > start {
            node.chan.stats.rx.gaps.bump();
            for sink in sinks {
                sink.gap(first - start);
            }
            if self.mode == ChannelMode::Window {
                pipe.pending_since = Some(pipe.pending_since.map_or(start, |p| p.min(start)));
            }
        }
    }

    /// Give a parsed frame to a lane: its messages go to the lane's sinks, its record is read.
    #[allow(clippy::too_many_arguments)]
    fn apply(
        &self,
        st: &mut RxState,
        lane: Lane,
        node: &NodeInner,
        sinks: &[Arc<Sink>],
        header: &Header,
        body: &mut Body,
        now: Instant,
        post: &mut Post,
    ) -> Delivery {
        let stats = &node.chan.stats.rx;
        let RxState {
            prompt,
            verified,
            hello,
            pending_end,
            ..
        } = st;
        let pipe = match lane {
            Lane::Prompt => prompt,
            Lane::Verified => match verified.as_mut() {
                Some(pipe) => pipe,
                None => return Delivery::Deferred,
            },
        };
        match body {
            Body::Data(messages) => {
                self.sequence(pipe, node, sinks, header, false);
                let count = messages.len();
                for message in messages.drain(..) {
                    self.accept(pipe, node, message, now);
                }
                self.flush(pipe, node, sinks);
                Delivery::Delivered { messages: count }
            }
            Body::Control(control) => {
                let control = control.clone();
                self.sequence(
                    pipe,
                    node,
                    sinks,
                    header,
                    matches!(control, Control::Hello { .. }),
                );
                match control {
                    Control::Bind { id, name } => {
                        if pipe.names.bind(id, &name).is_ok() {
                            self.release_id(pipe, node, id, now);
                            self.flush(pipe, node, sinks);
                        } else {
                            stats.bad_bind.bump();
                        }
                    }
                    Control::Unbind { id } => pipe.names.unbind(id),
                    Control::Hello { seq } => {
                        if lane == Lane::Prompt {
                            *hello = Some(seq);
                            stats.hellos.bump();
                        }
                        for sink in sinks {
                            sink.hello_seen();
                        }
                    }
                    Control::End => {
                        // With checkpoints an `END` is a claim until the sender's signature lists
                        // it: any receiver can seal one, so it ends nothing by itself.
                        if lane == Lane::Prompt && self.period.is_some() {
                            *pending_end = Some(header.seq0);
                        } else {
                            post.end.get_or_insert(EndReason::Closed);
                        }
                    }
                    Control::StandingBegin => pipe.standing_open = true,
                    Control::StandingEnd => pipe.standing_open = false,
                }
                Delivery::Control
            }
        }
    }

    /// Take one message: bind its name if it carries one, hold it if its bare id is unknown, and
    /// otherwise queue it for the sinks.
    fn accept(&self, pipe: &mut Pipe, node: &NodeInner, message: Message, now: Instant) {
        let stats = &node.chan.stats.rx;
        stats.messages.bump();
        let named = message.name.is_some();
        let id = message.name_id;
        let resolved = match &message.name {
            Some(octets) => match pipe.names.bind(id, octets) {
                Ok(binding) => Some((binding.name.clone(), binding.bound)),
                Err(_) => {
                    stats.bad_bind.bump();
                    return;
                }
            },
            None => pipe
                .names
                .get(id)
                .map(|binding| (binding.name.clone(), binding.bound)),
        };
        match resolved {
            Some((name, bound)) => {
                self.resolve(pipe, node, message, name, bound);
                if named {
                    self.release_id(pipe, node, id, now);
                }
            }
            None => match pipe.names.hold(id, message, now) {
                Held::Kept => {
                    stats.name_held.bump();
                    node.chan.rx.held.fetch_add(1, Ordering::AcqRel);
                }
                Held::Full => {
                    stats.hold_full.bump();
                    stats.unknown_name.bump();
                }
            },
        }
    }

    /// `id` was bound just now: the messages held for it that are within 50 ms are queued, the
    /// older ones are dropped and counted.
    fn release_id(&self, pipe: &mut Pipe, node: &NodeInner, id: u64, now: Instant) {
        let stats = &node.chan.stats.rx;
        let (ready, late) = pipe.names.release(id, now);
        if ready.is_empty() && late == 0 {
            return;
        }
        node.chan
            .rx
            .held
            .fetch_sub(ready.len() + late, Ordering::AcqRel);
        for _ in 0..late {
            stats.unknown_name.bump();
        }
        let Some((name, bound)) = pipe
            .names
            .get(id)
            .map(|binding| (binding.name.clone(), binding.bound))
        else {
            return;
        };
        for message in ready {
            self.resolve(pipe, node, message, name.clone(), bound);
        }
    }

    /// A message with its name: apply its origin and queue it.
    fn resolve(&self, pipe: &mut Pipe, node: &NodeInner, message: Message, name: Name, bound: u32) {
        let stats = &node.chan.stats.rx;
        let seq = match message.origin {
            Some(Origin::Standing(original)) => {
                if !pipe.standing_open {
                    stats.standing_stray.bump();
                    return;
                }
                original
            }
            Some(Origin::Replayed(original)) => {
                if pipe.seen.contains(original) {
                    stats.duplicates.bump();
                    return;
                }
                pipe.seen.insert(original);
                original
            }
            None => {
                if self.mode != ChannelMode::Latest {
                    pipe.seen.insert(message.seq);
                }
                message.seq
            }
        };
        let weight = message.pinned;
        pipe.out.push(Out {
            pair: Pair {
                channel: self.channel,
                id: message.name_id as u32,
                bound,
            },
            seq,
            weight,
            got: Got {
                path: name,
                bytes: message.payload,
                by: self.by.clone(),
                writer: self.writer.clone(),
                kind: Kind::Emitted(Emitted {
                    seq,
                    stands: message.stand_secs.map(Duration::from_secs),
                }),
            },
        });
    }

    /// Push what the frame queued to the sinks.
    fn flush(&self, pipe: &mut Pipe, node: &NodeInner, sinks: &[Arc<Sink>]) {
        if pipe.out.is_empty() {
            return;
        }
        if sinks.is_empty() {
            node.chan.stats.rx.no_sink.bump();
            pipe.out.clear();
            return;
        }
        let last = sinks.len() - 1;
        for (at, sink) in sinks.iter().enumerate() {
            sink.deliver(self.mode, &mut pipe.out, at == last);
        }
        pipe.out.clear();
    }
}

/// The reason a session ends when frames wait 3 s for a verified checkpoint.
fn unverifiable(period: Duration) -> EndReason {
    EndReason::Unverifiable {
        why: format!(
            "frames of this channel waited 3 s for a checkpoint that verifies (the sender's period \
             is {} ms) and none came, so they cannot be told from a key holder's: ask the sender \
             again; if it keeps happening the link drops the sender's stream (checkpoints ride it), \
             or the sender stopped signing",
            period.as_millis()
        ),
    }
}

/// What a node's receiver holds: the channels it takes frames of and the `Items` it pushes to.
#[derive(Default)]
pub(crate) struct Receivers {
    channels: Mutex<FastMap<u64, Arc<ChannelRx>>>,
    sinks: Mutex<Vec<Arc<Sink>>>,
    /// Moves whenever `sinks` does, so a channel knows its cached list is stale.
    generation: AtomicU64,
    /// Messages held for an unbound id across the channels: nothing to sweep while it is zero.
    held: AtomicUsize,
    /// Frames of channels with no session, held for one (see [`rx_hold`](super::rx_hold)).
    unknown: Mutex<UnknownHold>,
    /// How many frames `unknown` holds: nothing to sweep while it is zero.
    unknown_frames: AtomicUsize,
    /// How many channels have held frames being taken in: no frame is looked up against a
    /// session without this being read.
    replaying: AtomicUsize,
    /// The channel the last frame went through and the generation of the sessions held when it
    /// was found: the next frame of it needs no lookup while that generation stands.
    fast: RwLock<Option<(u64, Arc<ChannelRx>)>>,
    /// The octets of accepted frames and held messages all channels keep for checkpoints, against
    /// the node's 8 MiB.
    pub(crate) budget: Arc<Budget>,
}

impl Receivers {
    pub(crate) fn add_sink(&self, sink: Arc<Sink>) {
        self.sinks.lock().push(sink);
        self.generation.fetch_add(1, Ordering::AcqRel);
    }

    pub(crate) fn remove_sink(&self, sink: &Arc<Sink>) {
        self.sinks.lock().retain(|s| !Arc::ptr_eq(s, sink));
        self.generation.fetch_add(1, Ordering::AcqRel);
    }

    /// Whether any `Items` takes the channels of `space` in `mode`.
    pub(crate) fn wanted(&self, space: &Name, mode: ChannelMode) -> bool {
        self.sinks.lock().iter().any(|s| s.takes(space, mode))
    }

    /// Whether a `HELLO` came on channel `id`: the sender says the path works.
    pub(crate) fn path_seen(&self, id: u64) -> bool {
        self.channels
            .lock()
            .get(&id)
            .is_some_and(|ch| ch.state.lock().hello.is_some())
    }

    /// Tell every `Items` that takes `(space, mode)` that channel `id` has no path to its sender
    /// ([`LiveEnd::NoPath`]), after what it has queued.
    pub(crate) fn tell_no_path(&self, space: &Name, mode: ChannelMode, id: u64, why: String) {
        let sinks: Vec<Arc<Sink>> = self
            .sinks
            .lock()
            .iter()
            .filter(|s| s.takes(space, mode))
            .cloned()
            .collect();
        for sink in sinks {
            sink.end(id, LiveEnd::NoPath { why: why.clone() });
        }
    }

    /// The channel `session` is received through, made at its first frame.
    fn channel_for(&self, session: &Arc<RecvSession>, node: &NodeInner) -> Arc<ChannelRx> {
        let mut channels = self.channels.lock();
        if let Some(ch) = channels.get(&session.id())
            && Arc::ptr_eq(&ch.session, session)
        {
            return Arc::clone(ch);
        }
        let ch = Arc::new(ChannelRx::new(session, node));
        if let Some(old) = channels.insert(session.id(), Arc::clone(&ch)) {
            old.state.lock().ended = true;
            *self.fast.write() = None;
        }
        ch
    }

    /// The channel of `channel` that [`Self::remember`] kept, if the sessions held are still the
    /// ones it was found under (`generation`) and no channel has frames being taken in.
    fn fast_channel(&self, channel: u64, generation: u64) -> Option<Arc<ChannelRx>> {
        if self.replaying.load(Ordering::Acquire) > 0 {
            return None;
        }
        let fast = self.fast.read();
        let (found_at, ch) = fast.as_ref()?;
        (*found_at == generation && ch.channel == channel).then(|| Arc::clone(ch))
    }

    /// Keep `ch`, found while the sessions held stood at `generation`.
    fn remember(&self, generation: u64, ch: &Arc<ChannelRx>) {
        *self.fast.write() = Some((generation, Arc::clone(ch)));
    }

    /// The channel of `id`, if it has received a frame.
    #[cfg(test)]
    pub(crate) fn channel(&self, id: u64) -> Option<Arc<ChannelRx>> {
        self.channels.lock().get(&id).cloned()
    }

    /// The channel of `id` was let go because no `Items` takes it any more: its receiving state
    /// goes and nobody is told (a sink made later has not seen the session it would be told of).
    pub(crate) fn release_channel(&self, id: u64) {
        *self.fast.write() = None;
        if let Some(ch) = self.channels.lock().remove(&id) {
            ch.state.lock().ended = true;
        }
    }

    /// The channel of `id` ended with `why`: every sink of its space and mode is told, after what
    /// it has queued. A channel replaced by a newer one of the same sender and mode is not told:
    /// the sink goes on with the new one.
    pub(crate) fn end_channel(&self, id: u64, why: &EndReason) {
        *self.fast.write() = None;
        let Some(ch) = self.channels.lock().remove(&id) else {
            return;
        };
        ch.state.lock().ended = true;
        if *why == EndReason::Replaced {
            return;
        }
        let sinks: Vec<Arc<Sink>> = self
            .sinks
            .lock()
            .iter()
            .filter(|s| s.takes(&ch.space, ch.mode))
            .cloned()
            .collect();
        for sink in sinks {
            sink.end(
                id,
                LiveEnd::Ended {
                    writer: ch.writer.clone(),
                    reason: why.clone(),
                },
            );
        }
    }

    /// The maintenance pass: held messages past 50 ms are dropped, and a channel whose session
    /// ended or was replaced is ended here too (the receiver is told the moment a frame comes;
    /// this is for a session that ends without one).
    pub(crate) fn sweep(&self, node: &NodeInner, now: Instant) {
        self.sweep_unknown(&node.chan.stats.rx, now);
        let all: Vec<Arc<ChannelRx>> = self.channels.lock().values().cloned().collect();
        for ch in all {
            ch.sweep(self, &node.chan.stats.rx, now);
            match ch.session.ended() {
                Some(why) => {
                    node.chan.stats.rx.ended.bump();
                    self.end_channel(ch.channel, &why);
                }
                None => {
                    let held = node.chan.sessions.get(ch.channel);
                    if held.is_none_or(|s| !Arc::ptr_eq(&s, &ch.session)) {
                        self.end_channel(ch.channel, &EndReason::Replaced);
                    } else if let Some(why) = ch.sweep_checks(self, &node.chan.stats.rx, now) {
                        // Frames waited 3 s for a checkpoint that verifies: no frame came to say so.
                        ch.session.end(why.clone());
                        node.chan.sessions.remove(ch.channel);
                        node.chan.stats.rx.ended.bump();
                        self.end_channel(ch.channel, &why);
                    }
                }
            }
        }
    }

    /// Sweep the hold of every channel if anything is held: what an `Items` poll does. The clock is
    /// read only when something is held.
    pub(crate) fn sweep_held_if_any(&self, stats: &RxStats) {
        let held = self.held.load(Ordering::Acquire);
        if held == 0 && self.unknown_frames.load(Ordering::Acquire) == 0 {
            return;
        }
        let now = Instant::now();
        self.sweep_unknown(stats, now);
        if held == 0 {
            return;
        }
        let all: Vec<Arc<ChannelRx>> = self.channels.lock().values().cloned().collect();
        for ch in all {
            ch.sweep(self, stats, now);
        }
    }

    /// The node stops: every sink ends once its queues are read.
    pub(crate) fn close_all(&self) {
        for sink in self.sinks.lock().iter() {
            sink.close();
        }
    }

    /// A session of channel `id` is about to be installed: frames of the id queue behind the
    /// held ones until the returned guard is dropped (the replay is over).
    pub(crate) fn begin_replay(&self, id: u64) -> Draining<'_> {
        let mut unknown = self.unknown.lock();
        unknown.replaying.push(id);
        self.replaying
            .store(unknown.replaying.len(), Ordering::Release);
        Draining { rx: self, id }
    }

    /// Whether frames of `id` queue behind a replay now.
    fn replaying(&self, id: u64) -> bool {
        self.replaying.load(Ordering::Acquire) > 0 && self.unknown.lock().replaying.contains(&id)
    }

    /// Hold a stream frame of channel `channel`, which no session takes frames of now. `None`: a
    /// session of it was installed since (and no replay is under way), so the frame is taken
    /// the usual way. A frame the hold has no room for is dropped, and counted: its own face
    /// holds its share already or the most of a full hold (`held_unknown_full`); frames of other
    /// faces pushed out for it are counted too (`held_unknown_evicted`).
    fn hold_unknown(
        &self,
        sessions: &RecvSessions,
        channel: u64,
        frame: &Bytes,
        ingress: u64,
        stats: &RxStats,
        now: Instant,
    ) -> Option<Delivery> {
        let mut unknown = self.unknown.lock();
        if !unknown.replaying.contains(&channel) && sessions.get(channel).is_some() {
            return None;
        }
        let expired = unknown.hold.sweep(now);
        let kept = unknown.hold.hold(channel, frame, ingress, now);
        self.unknown_frames
            .store(unknown.hold.size().0, Ordering::Release);
        drop(unknown);
        for _ in 0..expired {
            stats.held_unknown_expired.bump();
        }
        Some(match kept {
            Ok(evicted) => {
                for _ in 0..evicted {
                    stats.held_unknown_evicted.bump();
                }
                Delivery::Held
            }
            Err(why) => {
                stats.held_unknown_full.bump();
                tracing::debug!(
                    "frame of channel {channel:016x} from face {ingress} not held: {}",
                    why.why()
                );
                Delivery::Dropped(Dropped::UnknownChannel)
            }
        })
    }

    /// The frames held for `id`, swept first; `None` when none is left, and then the replay of
    /// `id` is over (the channel takes frames directly).
    fn take_unknown(
        &self,
        id: u64,
        stats: &RxStats,
        now: Instant,
    ) -> Option<Vec<super::rx_hold::Held>> {
        let mut unknown = self.unknown.lock();
        let expired = unknown.hold.sweep(now);
        let batch = unknown.hold.take(id);
        if batch.is_empty() {
            unknown.replaying.retain(|&r| r != id);
            self.replaying
                .store(unknown.replaying.len(), Ordering::Release);
        }
        self.unknown_frames
            .store(unknown.hold.size().0, Ordering::Release);
        drop(unknown);
        for _ in 0..expired {
            stats.held_unknown_expired.bump();
        }
        (!batch.is_empty()).then_some(batch)
    }

    /// Drop the held frames past their time: counted.
    fn sweep_unknown(&self, stats: &RxStats, now: Instant) {
        if self.unknown_frames.load(Ordering::Acquire) == 0 {
            return;
        }
        let mut unknown = self.unknown.lock();
        let expired = unknown.hold.sweep(now);
        self.unknown_frames
            .store(unknown.hold.size().0, Ordering::Release);
        drop(unknown);
        for _ in 0..expired {
            stats.held_unknown_expired.bump();
        }
    }

    /// How many frames of unknown channels are held, and their octets (a test asks).
    #[cfg(test)]
    pub(crate) fn unknown_held(&self) -> (usize, usize) {
        self.unknown.lock().hold.size()
    }

    /// How many frames of unknown channels face `ingress` has held, and their octets (a test
    /// asks).
    #[cfg(test)]
    pub(crate) fn unknown_held_by(&self, ingress: u64) -> (usize, usize) {
        self.unknown.lock().hold.share_of(ingress)
    }
}

/// What frames of a channel queue behind while its held frames are taken in: dropping it ends
/// the replay.
pub(crate) struct Draining<'a> {
    rx: &'a Receivers,
    id: u64,
}

impl Drop for Draining<'_> {
    fn drop(&mut self) {
        let mut unknown = self.rx.unknown.lock();
        unknown.replaying.retain(|&r| r != self.id);
        self.rx
            .replaying
            .store(unknown.replaying.len(), Ordering::Release);
    }
}

/// What a node holds of frames of channels it has no session of: the hold, and the channels
/// whose held frames are being taken in.
#[derive(Default)]
struct UnknownHold {
    hold: Hold,
    replaying: Vec<u64>,
}

impl NodeInner {
    /// Take one channel frame the host read, at `now` (an injected clock for tests).
    pub(crate) async fn chan_deliver(&self, frame: Bytes, ingress: u64, now: Instant) -> Delivery {
        let stats = &self.chan.stats.rx;
        stats.frames.bump();
        if frame.len() < MIN_FRAME_LEN {
            stats.short.bump();
            return Delivery::Dropped(Dropped::Short);
        }
        if frame.len() > STREAM_FRAME_MAX {
            stats.oversize.bump();
            return Delivery::Dropped(Dropped::Oversize);
        }
        let header = match Header::decode(&frame) {
            Ok(header) => header,
            Err(error) => return self.refuse(error),
        };
        let rx = &self.chan.rx;
        // The steady state: the channel this frame's id went through last, while the sessions held
        // have not moved since, takes it with no lookup of the session or of the channel.
        let generation = self.chan.sessions.generation();
        if let Some(channel) = rx.fast_channel(header.channel, generation) {
            return channel.receive(self, header, frame, ingress, now).await;
        }
        loop {
            let known = self.chan.sessions.get(header.channel);
            // A session whose held frames are being taken in is not yet taking frames: a stream
            // frame that arrives meanwhile queues behind them, so the order of arrival is kept.
            if let Some(session) = known.filter(|_| !rx.replaying(header.channel)) {
                let channel = rx.channel_for(&session, self);
                rx.remember(generation, &channel);
                return channel.receive(self, header, frame, ingress, now).await;
            }
            let unknown = self.chan.sessions.get(header.channel).is_none();
            // A datagram is not held: it is lost, as a datagram may be, whether it is early or
            // arrives while the held frames are taken in (it would overtake them). A `Latest`
            // channel is told by its next emission, and what stands is replayed on the stream.
            if header.class == SideClass::Datagram {
                if unknown {
                    stats.unknown_channel.bump();
                }
                return Delivery::Dropped(Dropped::UnknownChannel);
            }
            if let Some(delivery) = rx.hold_unknown(
                &self.chan.sessions,
                header.channel,
                &frame,
                ingress,
                stats,
                now,
            ) {
                if unknown {
                    stats.unknown_channel.bump();
                }
                return delivery;
            }
        }
    }

    /// A session of channel `id` was installed (`replay` was begun before it was): the frames
    /// held for it are taken in, in the order they arrived, then later ones that queued behind
    /// them, until none is left; only then does the channel take frames directly.
    pub(crate) async fn chan_replay_held(&self, id: u64, replay: Draining<'_>) {
        let stats = &self.chan.stats.rx;
        loop {
            let now = Instant::now();
            let Some(batch) = self.chan.rx.take_unknown(id, stats, now) else {
                break;
            };
            for held in batch {
                let Some(session) = self.chan.sessions.get(id) else {
                    break;
                };
                if held.frame.len() < MIN_FRAME_LEN {
                    continue;
                }
                let Ok(header) = Header::decode(&held.frame) else {
                    continue;
                };
                let channel = self.chan.rx.channel_for(&session, self);
                channel
                    .receive(self, header, held.frame, held.ingress, now)
                    .await;
            }
        }
        drop(replay);
    }

    /// Count a frame whose header is refused.
    fn refuse(&self, error: FrameError) -> Delivery {
        let stats = &self.chan.stats.rx;
        let why = match error {
            FrameError::Header(HeaderError::NotASideFrame { .. }) => {
                stats.marker.bump();
                Dropped::NotASideFrame
            }
            FrameError::Header(HeaderError::Version { .. }) => {
                stats.version.bump();
                Dropped::Version
            }
            FrameError::Header(HeaderError::Truncated { .. }) | FrameError::Truncated { .. } => {
                stats.truncated.bump();
                Dropped::Truncated
            }
            FrameError::Count { .. } => {
                stats.count.bump();
                Dropped::Count
            }
            FrameError::SequenceExhausted { .. } => {
                stats.sequence.bump();
                Dropped::Sequence
            }
            _ => {
                stats.kind.bump();
                Dropped::Kind
            }
        };
        Delivery::Dropped(why)
    }
}

impl NodeHandle {
    /// Hand the node one channel frame the host read from a link: a datagram, or a frame of the
    /// stream (one whole frame; the host reads the stream's own framing). `ingress` is an opaque
    /// id of the face it came over: the hold of early frames is shared fairly between faces by it
    /// (a host that gives every frame of every face one id gives up that fairness), and it is kept
    /// for the evidence of checkpoints.
    ///
    /// The node does the peel-time work (docs/specs/channel.md, The receiver): a frame that is
    /// short, over its limit, malformed, a repeat, or under a key epoch it does not hold costs
    /// no cryptography; a stream frame of a channel it holds no session of is **held** (a copy,
    /// at most 16 frames and 2 MiB from one face, 64 frames and 4 MiB in all, 2 s each:
    /// [`Delivery::Held`]) and taken in, in order,
    /// when a session of that channel is installed; a frame of a session whose sender
    /// no longer stands is refused and the session ends; the first AEAD attempt is the first
    /// cryptography; messages go to the `Items` of the space.
    ///
    /// It **waits** only for a stream frame of a `Reliable` or `Window` channel while an `Items`
    /// that blocks has a full queue: awaiting it is the back pressure that stalls the sender.
    /// Every other frame is taken without waiting.
    pub async fn deliver_frame(&self, frame: Bytes, ingress: u64) -> Delivery {
        self.inner
            .chan_deliver(frame, ingress, Instant::now())
            .await
    }
}
