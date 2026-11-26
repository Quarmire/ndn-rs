//! The receiver (docs/specs/channel.md, The receiver): what a node does with a channel frame the
//! host hands it ([`NodeHandle::deliver_frame`]), in the order the spec gives.
//!
//! **Before any cryptography**, each costs at most a length test, a header parse or one lookup:
//! a frame under 46 octets or over the largest any session may grant; a marker, version, kind or
//! class that is not assigned; a count or sequence the kind does not allow; a channel id this
//! device holds no session of (the frame is **held**, copied, and taken in when a session of that
//! id is installed: [`rx_hold`](super::rx_hold)); a frame over the limit that session grants for its class; a
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
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_transport::side_header::HeaderError;
use ndn_transport::{SideClass, SideKind};
use parking_lot::{Mutex, RwLock};

use super::aead::{Aead, FrameCipher};
use super::control::Control;
use super::frame::{FrameError, Header, open};
use super::hub::Counter;
use super::items::{Out, Sink};
use super::key::FrameKey;
use super::latest::Pair;
use super::limits::{MIN_FRAME_LEN, STREAM_FRAME_DEFAULT, STREAM_FRAME_MAX, message_limit_for};
use super::message::{Message, Origin};
use super::replay::{Replay, ReplayWindow};
use super::rx_hold::{Full, Hold};
use super::rx_names::{Held, Names, Seen};
use super::sessions::{EndReason, RecvSession, RecvSessions, Unknown};
use super::verbs::{Emitted, Got, Kind, LiveEnd};
use super::wire::ChannelMode;
use crate::host::NodeHandle;
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
    /// `CHECKPOINT` frames taken and not read (checkpoints: stage 5).
    pub(crate) checkpoints: Counter,
    /// Frames of a space no `Items` wants.
    pub(crate) no_sink: Counter,
    /// Sessions ended by the receiver (a removed sender, the sender's `END`).
    pub(crate) ended: Counter,
    /// Frames of a channel id this device holds no session of that were dropped because the hold
    /// was full (64 frames or 512 KiB).
    pub(crate) held_unknown_full: Counter,
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
    /// No session of that channel is held (or it ended while the frame waited).
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
    /// A `CHECKPOINT` frame was opened and noted; checkpoints are read from stage 5.
    Checkpoint,
    /// Not delivered, and why. Nothing was changed but a counter.
    Dropped(Dropped),
    /// The session ended with this frame: the sender no longer stands, or said `END`. The frame is
    /// not delivered, and every `Items` of the space is told.
    Ended(EndReason),
    /// A frame of a channel id this device holds no session of: kept at most 2 s for the session
    /// to be installed (it is the session Data that tells the channel's key; the frame is not
    /// decrypted and decides nothing), then dropped.
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
    /// The sender said `END`.
    end: bool,
    /// An authentic frame was too far ahead of the sequences held: ask the sender again.
    far: bool,
}

struct RxState {
    replay: ReplayWindow,
    names: Names<Message>,
    seen: Seen,
    /// The sequence the next frame of the stream should start at.
    expected: Option<u64>,
    /// The sequence the sender's next message takes, as its last `HELLO` said.
    hello: Option<u64>,
    standing_open: bool,
    /// Prepared ciphers by frame key: the key held and the one before it.
    ciphers: Vec<(FrameKey, FrameCipher)>,
    /// The messages of the frame being taken, on their way to the sinks (a buffer kept between
    /// frames, so a frame costs no allocation for them).
    out: Vec<Out>,
    parsed: Vec<Message>,
    /// The first sequence a `Window` re-ask is still owed from.
    pending_since: Option<u64>,
    reask_at: Option<Instant>,
    /// The face the last accepted frame came over (evidence for checkpoints: stage 5).
    last_ingress: u64,
    ended: bool,
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
    sinks: RwLock<(u64, Arc<[Arc<Sink>]>)>,
    reasking: Arc<AtomicBool>,
    state: Mutex<RxState>,
}

impl ChannelRx {
    fn new(session: &Arc<RecvSession>, node: &NodeInner) -> ChannelRx {
        let terms = session.terms();
        let writer = session.sender().clone();
        let frame_max = usize::try_from(terms.frame_max).unwrap_or(usize::MAX);
        let mut names = Names::default();
        for bind in &terms.table {
            // A table the sender signed: an id or name that is not valid is skipped.
            let _ = names.bind(bind.id, &name_octets(&bind.name));
        }
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
            sinks: RwLock::new((u64::MAX, Arc::from([]))),
            reasking: Arc::new(AtomicBool::new(false)),
            state: Mutex::new(RxState {
                replay: ReplayWindow::new(),
                names,
                seen: Seen::default(),
                expected: None,
                hello: None,
                standing_open: false,
                ciphers: Vec::with_capacity(2),
                out: Vec::new(),
                parsed: Vec::new(),
                pending_since: None,
                reask_at: None,
                last_ingress: 0,
                ended: false,
            }),
            session: Arc::clone(session),
        }
    }

    /// The sinks of this channel's space that take its mode, as of the registry's generation.
    fn sinks(&self, rx: &Receivers) -> Arc<[Arc<Sink>]> {
        let generation = rx.generation.load(Ordering::Acquire);
        {
            let cached = self.sinks.read();
            if cached.0 == generation {
                return Arc::clone(&cached.1);
            }
        }
        let list: Arc<[Arc<Sink>]> = rx
            .sinks
            .lock()
            .iter()
            .filter(|s| s.takes(&self.space, self.mode))
            .cloned()
            .collect();
        *self.sinks.write() = (generation, Arc::clone(&list));
        list
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
        self.state.lock().names.held()
    }

    fn sweep(&self, rx: &Receivers, stats: &RxStats, now: Instant) {
        let dropped = self.state.lock().names.sweep(now);
        if dropped > 0 {
            rx.held.fetch_sub(dropped, Ordering::AcqRel);
            for _ in 0..dropped {
                stats.unknown_name.bump();
            }
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
        let sinks = self.sinks(&node.chan.rx);
        // Back pressure: a stream frame is not taken while an `Items` that blocks has no room.
        if fifo_mode && header.class == SideClass::Stream && header.kind == SideKind::Data {
            for sink in sinks.iter() {
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
        let Some(key) = self.session.frame_key(header.key_epoch, now) else {
            return self.unknown_epoch(node, now);
        };
        let mut post = Post::default();
        let delivery = {
            let mut st = self.state.lock();
            self.process(
                &mut st, node, &sinks, header, frame, limit, &key, ingress, now, &mut post,
            )
        };
        if post.end {
            self.session.end(EndReason::Closed);
            node.chan.sessions.remove(self.channel);
            node.chan.rx.end_channel(self.channel, &EndReason::Closed);
            return Delivery::Ended(EndReason::Closed);
        }
        if let Some(since) = post.reask {
            self.reask(node, since);
        }
        if post.far {
            self.ask_again(node, now, "a frame came far ahead of the sequences held");
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
        sinks: &[Arc<Sink>],
        header: Header,
        frame: Bytes,
        limit: usize,
        key: &FrameKey,
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
        let swept = st.names.sweep(now);
        if swept > 0 {
            node.chan.rx.held.fetch_sub(swept, Ordering::AcqRel);
            for _ in 0..swept {
                stats.unknown_name.bump();
            }
        }
        match st.replay.check(header.seq0) {
            Replay::Fresh => {}
            Replay::Replayed => {
                stats.replayed.bump();
                return Delivery::Dropped(Dropped::Replayed);
            }
            Replay::TooOld => {
                stats.too_old.bump();
                return Delivery::Dropped(Dropped::TooOld);
            }
        }
        let at = st.cipher_index(key, self.aead);
        stats.aead_attempts.bump();
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
        let delivery = match header.kind {
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
                self.sequence(st, node, sinks, &header, false);
                let mut parsed = std::mem::take(&mut st.parsed);
                let count = parsed.len();
                for message in parsed.drain(..) {
                    self.accept(st, node, message, now);
                }
                st.parsed = parsed;
                self.flush(st, node, sinks);
                Delivery::Delivered { messages: count }
            }
            SideKind::Control => {
                let control = match Control::decode(opened.plaintext()) {
                    Ok(control) => control,
                    Err(_) => {
                        stats.malformed.bump();
                        return Delivery::Dropped(Dropped::Malformed);
                    }
                };
                self.sequence(
                    st,
                    node,
                    sinks,
                    &header,
                    matches!(control, Control::Hello { .. }),
                );
                stats.controls.bump();
                match control {
                    Control::Bind { id, name } => {
                        if st.names.bind(id, &name).is_ok() {
                            self.release(st, node, id, now);
                            self.flush(st, node, sinks);
                        } else {
                            stats.bad_bind.bump();
                        }
                    }
                    Control::Unbind { id } => st.names.unbind(id),
                    Control::Hello { seq } => {
                        st.hello = Some(seq);
                        stats.hellos.bump();
                        for sink in sinks {
                            sink.hello_seen();
                        }
                    }
                    Control::End => post.end = true,
                    Control::StandingBegin => st.standing_open = true,
                    Control::StandingEnd => st.standing_open = false,
                }
                Delivery::Control
            }
            SideKind::Checkpoint => {
                self.sequence(st, node, sinks, &header, false);
                stats.checkpoints.bump();
                Delivery::Checkpoint
            }
            _ => {
                stats.kind.bump();
                return Delivery::Dropped(Dropped::Kind);
            }
        };
        if self.mode == ChannelMode::Window
            && st.pending_since.is_some()
            && st
                .reask_at
                .is_none_or(|at| now.saturating_duration_since(at) >= REASK_EVERY)
        {
            post.reask = st.pending_since.take();
            st.reask_at = Some(now);
        }
        delivery
    }

    /// The gap rule: in `Reliable` and `Window` each stream frame must start where the last one
    /// ended; a frame that starts later says that many sequences are missing, which every sink is
    /// told in its place in the stream, and in `Window` is asked for again. `Latest` expects
    /// gaps and notices none.
    fn sequence(
        &self,
        st: &mut RxState,
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
        let start = st
            .expected
            .unwrap_or(if hello { first } else { self.start.min(first) });
        st.expected = Some(start.max(next));
        if first > start {
            node.chan.stats.rx.gaps.bump();
            for sink in sinks {
                sink.gap(first - start);
            }
            if self.mode == ChannelMode::Window {
                st.pending_since = Some(st.pending_since.map_or(start, |p| p.min(start)));
            }
        }
    }

    /// Take one message: bind its name if it carries one, hold it if its bare id is unknown, and
    /// otherwise queue it for the sinks.
    fn accept(&self, st: &mut RxState, node: &NodeInner, message: Message, now: Instant) {
        let stats = &node.chan.stats.rx;
        stats.messages.bump();
        let named = message.name.is_some();
        let id = message.name_id;
        let resolved = match &message.name {
            Some(octets) => match st.names.bind(id, octets) {
                Ok(binding) => Some((binding.name.clone(), binding.bound)),
                Err(_) => {
                    stats.bad_bind.bump();
                    return;
                }
            },
            None => st
                .names
                .get(id)
                .map(|binding| (binding.name.clone(), binding.bound)),
        };
        match resolved {
            Some((name, bound)) => {
                self.resolve(st, node, message, name, bound);
                if named {
                    self.release(st, node, id, now);
                }
            }
            None => match st.names.hold(id, message, now) {
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
    fn release(&self, st: &mut RxState, node: &NodeInner, id: u64, now: Instant) {
        let stats = &node.chan.stats.rx;
        let (ready, late) = st.names.release(id, now);
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
        let Some((name, bound)) = st
            .names
            .get(id)
            .map(|binding| (binding.name.clone(), binding.bound))
        else {
            return;
        };
        for message in ready {
            self.resolve(st, node, message, name.clone(), bound);
        }
    }

    /// A message with its name: apply its origin and queue it.
    fn resolve(
        &self,
        st: &mut RxState,
        node: &NodeInner,
        message: Message,
        name: Name,
        bound: u32,
    ) {
        let stats = &node.chan.stats.rx;
        let seq = match message.origin {
            Some(Origin::Standing(original)) => {
                if !st.standing_open {
                    stats.standing_stray.bump();
                    return;
                }
                original
            }
            Some(Origin::Replayed(original)) => {
                if st.seen.contains(original) {
                    stats.duplicates.bump();
                    return;
                }
                st.seen.insert(original);
                original
            }
            None => {
                if self.mode != ChannelMode::Latest {
                    st.seen.insert(message.seq);
                }
                message.seq
            }
        };
        let weight = message.pinned;
        st.out.push(Out {
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
    fn flush(&self, st: &mut RxState, node: &NodeInner, sinks: &[Arc<Sink>]) {
        if st.out.is_empty() {
            return;
        }
        if sinks.is_empty() {
            node.chan.stats.rx.no_sink.bump();
            st.out.clear();
            return;
        }
        let last = sinks.len() - 1;
        for (at, sink) in sinks.iter().enumerate() {
            sink.deliver(self.mode, &mut st.out, at == last);
        }
        st.out.clear();
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

    /// Hold a frame of channel `channel`, which no session takes frames of now. `None`: a
    /// session of it was installed since (and no replay is under way), so the frame is taken
    /// the usual way.
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
            Ok(()) => Delivery::Held,
            Err(Full) => {
                stats.held_unknown_full.bump();
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
            // A session whose held frames are being taken in is not yet taking frames: a frame
            // that arrives meanwhile queues behind them, so the order of arrival is kept.
            if let Some(session) = known.filter(|_| !rx.replaying(header.channel)) {
                let channel = rx.channel_for(&session, self);
                rx.remember(generation, &channel);
                return channel.receive(self, header, frame, ingress, now).await;
            }
            let unknown = self.chan.sessions.get(header.channel).is_none();
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
    /// id of the face it came over, kept for the evidence of checkpoints.
    ///
    /// The node does the peel-time work (docs/specs/channel.md, The receiver): a frame that is
    /// short, over its limit, malformed, a repeat, or under a key epoch it does not hold costs
    /// no cryptography; a frame of a channel it holds no session of is **held** (a copy, at
    /// most 64 frames and 512 KiB in all, 2 s each: [`Delivery::Held`]) and taken in, in order,
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
