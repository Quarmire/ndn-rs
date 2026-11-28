//! The messages of a `DATA` frame: the plaintext the frame's AEAD seals.
//!
//! ```text
//! message = flags (1) | [original sequence (varint)]  if STANDING or REPLAYED
//!           | name id (varint) | [name length (varint) | name octets]  if NAMED
//!           | [stand seconds (varint)]  if STAND | length (varint) | payload
//! flags:  bit 0 NAMED     the full name rides here
//!         bit 1 STAND     the sender lets this emission stand
//!         bit 2 STANDING  a replay of a standing value after a session start
//!         bit 3 REPLAYED  a `Window` replay
//!         bits 4-6        reserved, zero
//!         bit 7 PAD       the octet 0x80, then zero octets to the end
//! ```
//!
//! [`MessageWriter`] appends messages into the frame's single buffer and
//! seals it in place; [`Messages`] walks an opened frame's plaintext and hands
//! each payload out as a slice of it, without copying. Both enforce the
//! limits of [`super::limits`], so a writer never builds what a reader
//! refuses.

use bytes::{BufMut, Bytes};

use super::aead::FrameCipher;
use super::frame::{FrameBuf, FrameError};
use super::limits::{MESSAGE_MAX, MESSAGES_PER_FRAME, NAME_MAX, NAMES_PER_CHANNEL};
use super::varint;
use super::verbs::STAND_MAX;
use ndn_transport::SideClass;

/// Flag: the message carries its name (a bind, or a datagram that may overtake
/// its bind).
pub(crate) const NAMED: u8 = 0x01;
/// Flag: the sender lets this emission stand.
pub(crate) const STAND: u8 = 0x02;
/// Flag: a replay of a standing value; an original sequence follows the flags.
pub(crate) const STANDING: u8 = 0x04;
/// Flag: a `Window` replay; an original sequence follows the flags.
pub(crate) const REPLAYED: u8 = 0x08;
/// The padding octet: a receiver stops parsing here and requires every octet
/// after it to be zero.
pub(crate) const PAD: u8 = 0x80;

const RESERVED: u8 = 0x70;

/// The most seconds a message may stand for: the sender's own limit (one hour). A reader refuses
/// more, since the value goes to consumers that add it to a clock.
const STAND_SECS_MAX: u64 = STAND_MAX.as_secs();

/// The largest frame whose messages are handed out as slices of it: 9,000 octets, the most a
/// datagram frame carries (`tx::FRAME_CAP`), so the datagram lane costs no allocation per
/// message. A payload of a larger frame (only the stream carries them) is **copied out** unless
/// it is at least half of the frame. So a queued message never pins more than the larger of
/// this and twice its own size, however the sender padded or packed its frame
/// (channel.md §12.6).
pub(crate) const SHARE_FRAME_MAX: usize = 9_000;

const _: () = assert!(SHARE_FRAME_MAX >= super::tx::FRAME_CAP);

/// Where a replayed message first went out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Origin {
    /// A standing value replayed after a session start; its original sequence.
    Standing(u64),
    /// A `Window` replay; its original sequence.
    Replayed(u64),
}

impl Origin {
    const fn flag(self) -> u8 {
        match self {
            Origin::Standing(_) => STANDING,
            Origin::Replayed(_) => REPLAYED,
        }
    }

    const fn sequence(self) -> u64 {
        match self {
            Origin::Standing(s) | Origin::Replayed(s) => s,
        }
    }
}

/// Why a message, or the plaintext around it, is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum MessageError {
    /// The plaintext ends inside a message.
    #[error("the frame ends inside a message (its {what}): drop the frame")]
    Truncated { what: &'static str },
    /// Reserved flag bits, STANDING and REPLAYED together, or PAD with other
    /// bits.
    #[error(
        "message flags {flags:#04x} are not valid (bits 4-6 are reserved, STANDING and REPLAYED exclude each other, PAD stands alone): drop the frame"
    )]
    Flags { flags: u8 },
    /// A name id outside 1 to 4,096.
    #[error("name id {id} is outside 1 to {NAMES_PER_CHANNEL}: drop the frame")]
    NameId { id: u64 },
    /// A name over 255 octets.
    #[error("a name of {len} octets is over the {NAME_MAX} octet limit: shorten the path")]
    NameTooLong { len: usize },
    /// A payload over the message limit.
    #[error(
        "a message of {len} octets is over the limit of {max}: split it or raise the session's message limit (at most {MESSAGE_MAX})"
    )]
    TooLarge { len: usize, max: usize },
    /// A number a varint cannot hold, or a sequence at or above 2^63.
    #[error("the {what} is too large to encode: re-key the channel")]
    Overflow { what: &'static str },
    /// The frame header says `expected` messages and the plaintext holds
    /// `found`.
    #[error("the frame counts {expected} messages and holds {found}: drop the frame")]
    Count { expected: usize, found: usize },
    /// After the messages, octets that are not padding.
    #[error("{octets} octets follow the last message and are not padding: drop the frame")]
    Trailing { octets: usize },
    /// An original sequence that is not below the message's own: a replay carries a sequence the
    /// message went out under before, so the message's own is later.
    #[error(
        "the original sequence {original} is not below the message's own sequence {seq}: drop the frame (a writer: replay only what was sent before)"
    )]
    OriginalSequence { original: u64, seq: u64 },
    /// Stand seconds over what a sender may stand an emission for.
    #[error(
        "a message stands for {secs} s, over the {max} s a sender may stand an emission for: drop the frame (a writer: stand for less)"
    )]
    StandSeconds { secs: u64, max: u64 },
    /// A PAD flag followed by a non-zero octet.
    #[error("padding has a non-zero octet at {at}: drop the frame")]
    Padding { at: usize },
}

/// A message to be written.
#[derive(Clone, Copy, Debug)]
pub(crate) struct OutMessage<'a> {
    /// The name id, 1 to 4,096.
    pub name_id: u64,
    /// The name's octets (the Name TLV's value) when the message is `NAMED`.
    pub name: Option<&'a [u8]>,
    /// Seconds the emission stands for, when it does.
    pub stand_secs: Option<u64>,
    /// Set when the message replays an earlier one.
    pub origin: Option<Origin>,
    /// The payload.
    pub payload: &'a [u8],
}

impl<'a> OutMessage<'a> {
    /// A bare message: an id and a payload.
    #[cfg(test)]
    pub(crate) fn new(name_id: u64, payload: &'a [u8]) -> Self {
        Self {
            name_id,
            name: None,
            stand_secs: None,
            origin: None,
            payload,
        }
    }

    /// Checks the message against the codec's limits and `max_message` and
    /// returns the octets it takes.
    pub(crate) fn encoded_len(&self, max_message: usize) -> Result<usize, MessageError> {
        if !(1..=NAMES_PER_CHANNEL).contains(&self.name_id) {
            return Err(MessageError::NameId { id: self.name_id });
        }
        let mut n = 1 + varint::len(self.name_id).expect("an id is at most 4,096");
        if let Some(origin) = self.origin {
            n += varint::len(origin.sequence()).ok_or(MessageError::Overflow {
                what: "original sequence",
            })?;
        }
        if let Some(name) = self.name {
            if name.len() > NAME_MAX {
                return Err(MessageError::NameTooLong { len: name.len() });
            }
            n += 1 + name.len() + usize::from(name.len() > 0x3f);
        }
        if let Some(secs) = self.stand_secs {
            n += varint::len(secs).ok_or(MessageError::Overflow {
                what: "stand seconds",
            })?;
            if secs > STAND_SECS_MAX {
                return Err(MessageError::StandSeconds {
                    secs,
                    max: STAND_SECS_MAX,
                });
            }
        }
        let max = max_message.min(MESSAGE_MAX);
        if self.payload.len() > max {
            return Err(MessageError::TooLarge {
                len: self.payload.len(),
                max,
            });
        }
        Ok(
            n + varint::len(self.payload.len() as u64).expect("a payload is at most 16 MiB")
                + self.payload.len(),
        )
    }

    fn flags(&self) -> u8 {
        let mut flags = 0;
        if self.name.is_some() {
            flags |= NAMED;
        }
        if self.stand_secs.is_some() {
            flags |= STAND;
        }
        if let Some(origin) = self.origin {
            flags |= origin.flag();
        }
        flags
    }

    /// Appends the message to `buf`. The caller has checked it with
    /// [`encoded_len`](Self::encoded_len) and that `buf` has room.
    fn write(&self, buf: &mut impl BufMut) -> Result<(), varint::Overflow> {
        buf.put_u8(self.flags());
        if let Some(origin) = self.origin {
            varint::write(buf, origin.sequence())?;
        }
        varint::write(buf, self.name_id)?;
        if let Some(name) = self.name {
            varint::write(buf, name.len() as u64)?;
            buf.put_slice(name);
        }
        if let Some(secs) = self.stand_secs {
            varint::write(buf, secs)?;
        }
        varint::write(buf, self.payload.len() as u64)?;
        buf.put_slice(self.payload);
        Ok(())
    }
}

/// Why a message was not appended to a frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum WriteError {
    /// The frame has no room for this message: seal it and start another (or,
    /// when the frame is empty, send the message on the stream). Nothing was
    /// written.
    #[error("the frame has {room} octets of room and the message needs {need}")]
    Full { need: usize, room: usize },
    /// The frame already holds 255 messages: seal it and start another.
    /// Nothing was written.
    #[error("the frame holds the most messages it can (255)")]
    CountFull,
    /// The message breaks a limit of the codec; it is never sendable as given.
    #[error(transparent)]
    Invalid(#[from] MessageError),
}

/// Builds one `DATA` frame: messages appended into the frame's one buffer,
/// then sealed in place.
#[derive(Debug)]
pub(crate) struct MessageWriter {
    frame: FrameBuf,
    count: usize,
    max_message: usize,
}

impl MessageWriter {
    /// A writer for a frame on `class` of `channel` at `key_epoch` (low octet)
    /// whose first message has sequence `seq0`.
    ///
    /// `limit` is the frame's whole size at most (the datagram room the
    /// carrier gave, or the stream frame limit), `capacity` the octets to
    /// allocate up front. A frame is **two allocations** whatever its size and
    /// message count (the buffer, and the shared header `Bytes` adds when the
    /// buffer is frozen) provided `capacity` is at least its final size and
    /// within a quarter (and 64 octets) above it, as it is when the writer is
    /// sized to the room; a frame that used less of its buffer than that is
    /// copied to an exact one (three allocations, [`FrameBuf::seal`]), so a
    /// frame never keeps much more than its own octets alive. `max_message`
    /// bounds a payload.
    pub(crate) fn new(
        class: SideClass,
        channel: u64,
        key_epoch: u8,
        seq0: u64,
        limit: usize,
        capacity: usize,
        max_message: usize,
    ) -> Result<Self, FrameError> {
        Ok(Self {
            frame: FrameBuf::new(
                class,
                ndn_transport::SideKind::Data,
                channel,
                key_epoch,
                seq0,
                limit,
                capacity,
            )?,
            count: 0,
            max_message,
        })
    }

    /// Octets of messages the frame can still take.
    #[cfg(test)]
    pub(crate) fn room(&self) -> usize {
        self.frame.room()
    }

    /// Messages written so far.
    pub(crate) fn len(&self) -> usize {
        self.count
    }

    /// Whether no message was written.
    pub(crate) fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// The sequence the next message takes.
    #[cfg(test)]
    pub(crate) fn next_seq(&self) -> u64 {
        self.frame.seq0() + self.count as u64
    }

    /// Appends `message`, or says why not and writes nothing.
    pub(crate) fn push(&mut self, message: &OutMessage<'_>) -> Result<(), WriteError> {
        let need = message.encoded_len(self.max_message)?;
        if self.count == MESSAGES_PER_FRAME {
            return Err(WriteError::CountFull);
        }
        let room = self.frame.room();
        if need > room {
            return Err(WriteError::Full { need, room });
        }
        if let Some(origin) = message.origin {
            let seq = self.frame.seq0() + self.count as u64;
            if origin.sequence() >= seq {
                return Err(MessageError::OriginalSequence {
                    original: origin.sequence(),
                    seq,
                }
                .into());
            }
        }
        message
            .write(self.frame.plaintext_mut())
            .map_err(|_| MessageError::Overflow { what: "message" })?;
        self.count += 1;
        Ok(())
    }

    /// Pads the frame to 46 octets if it is shorter, seals it in place under
    /// `cipher` and returns it. Fails when no message was written.
    pub(crate) fn seal(self, cipher: &FrameCipher) -> Result<Bytes, FrameError> {
        let count = u8::try_from(self.count).expect("push stops at 255 messages");
        self.frame.seal(cipher, count)
    }
}

/// A message read from an opened frame, as the receiver holds it: 64 octets, written once by
/// [`Messages::parse_into`] where it stays until the sinks have it. What does not fit a message
/// of its own is beside it: the names a frame carries are the frame's (`names`, in order), and a
/// message points at its name by index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Message {
    /// The payload: a slice of the opened frame when the frame is small or the payload is at
    /// least half of it, a copy otherwise ([`SHARE_FRAME_MAX`]).
    pub payload: Bytes,
    /// The message's sequence: the frame's `seq0` plus its index.
    pub seq: u64,
    /// The original sequence, when the message replays an earlier one (`flags` says which way);
    /// 0 otherwise.
    original: u64,
    /// The octets a queued message is charged for: its payload when copied; when it shares the
    /// frame, the larger of the payload and the frame's share per message (the frame's octets
    /// over its message count), so the messages of a frame together are charged what the frame
    /// is.
    pinned: u32,
    /// Seconds the emission stands for, when `flags` has `STAND` (at most an hour).
    stand: u32,
    /// The name id, 1 to 4,096.
    name_id: u16,
    /// `NAMED`, `STAND`, `STANDING` and `REPLAYED` as the message carried them.
    flags: u8,
    /// The place of this message's name among the frame's names, when `flags` has `NAMED`.
    name_ix: u8,
}

const _: () = assert!(std::mem::size_of::<Message>() == 64);
// A charge and a stand time fit the octets a message keeps them in.
const _: () = assert!((super::limits::STREAM_FRAME_MAX as u64) < u32::MAX as u64);
const _: () = assert!(STAND_SECS_MAX <= u32::MAX as u64);
const _: () = assert!(NAMES_PER_CHANNEL <= u16::MAX as u64);

impl Message {
    /// The name id.
    pub(crate) fn name_id(&self) -> u64 {
        u64::from(self.name_id)
    }

    /// The octets this message is charged for while it is queued.
    pub(crate) fn pinned(&self) -> usize {
        self.pinned as usize
    }

    /// Seconds the emission stands for, when it does.
    pub(crate) fn stand_secs(&self) -> Option<u64> {
        (self.flags & STAND != 0).then_some(u64::from(self.stand))
    }

    /// Where the message was first sent, when it replays an earlier one.
    pub(crate) fn origin(&self) -> Option<Origin> {
        if self.flags & STANDING != 0 {
            Some(Origin::Standing(self.original))
        } else if self.flags & REPLAYED != 0 {
            Some(Origin::Replayed(self.original))
        } else {
            None
        }
    }

    /// The place of the message's name among its frame's names, when it carries one.
    pub(crate) fn name_index(&self) -> Option<usize> {
        (self.flags & NAMED != 0).then_some(usize::from(self.name_ix))
    }
}

/// A message with everything it carries as its own value: what tests read a frame as (the
/// receiver reads [`Message`]).
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReadMessage {
    /// The message's sequence: the frame's `seq0` plus its index.
    pub seq: u64,
    /// The name id.
    pub name_id: u64,
    /// The name's octets, when the message was `NAMED`.
    pub name: Option<Bytes>,
    /// Seconds the emission stands for, when it does.
    pub stand_secs: Option<u64>,
    /// Set when the message replays an earlier one.
    pub origin: Option<Origin>,
    /// The payload.
    pub payload: Bytes,
    /// The octets a queued message is charged for.
    pub pinned: usize,
}

#[cfg(test)]
impl ReadMessage {
    /// `message` with its name taken from `names`, the names of its frame.
    pub(crate) fn of(message: &Message, names: &[Bytes]) -> Self {
        Self {
            seq: message.seq,
            name_id: message.name_id(),
            name: message.name_index().map(|at| names[at].clone()),
            stand_secs: message.stand_secs(),
            origin: message.origin(),
            payload: message.payload.clone(),
            pinned: message.pinned(),
        }
    }
}

/// The messages of an opened `DATA` frame, in order. [`parse_into`](Self::parse_into) writes
/// them where the receiver keeps them; after the last it checks that only padding remains. (Tests
/// read the frame through the iterator, which yields [`ReadMessage`]s and ends after one error.)
#[derive(Debug)]
pub(crate) struct Messages {
    data: Bytes,
    pos: usize,
    seq: u64,
    count: usize,
    seen: usize,
    max_message: usize,
    #[cfg(test)]
    done: bool,
}

impl Messages {
    /// The `count` messages of `plaintext`, the first with sequence `seq0`.
    pub(crate) fn new(plaintext: Bytes, seq0: u64, count: usize, max_message: usize) -> Self {
        Self {
            data: plaintext,
            pos: 0,
            seq: seq0,
            count,
            seen: 0,
            max_message: max_message.min(MESSAGE_MAX),
            #[cfg(test)]
            done: false,
        }
    }

    fn varint(&mut self, what: &'static str) -> Result<u64, MessageError> {
        let (value, n) =
            varint::read(&self.data[self.pos..]).ok_or(MessageError::Truncated { what })?;
        self.pos += n;
        Ok(value)
    }

    fn take(&mut self, len: usize, what: &'static str) -> Result<Bytes, MessageError> {
        let end = self
            .pos
            .checked_add(len)
            .filter(|&end| end <= self.data.len())
            .ok_or(MessageError::Truncated { what })?;
        let out = self.data.slice(self.pos..end);
        self.pos = end;
        Ok(out)
    }

    /// The payload of `len` octets at the cursor and what it is charged: shared with the frame
    /// when the frame is small or the payload is most of it, a copy of its own otherwise.
    fn take_payload(&mut self, len: usize) -> Result<(Bytes, u32), MessageError> {
        let whole = self.data.len();
        let shared = whole <= SHARE_FRAME_MAX || len.saturating_mul(2) >= whole;
        let slice = self.take(len, "payload")?;
        if shared {
            let share = whole.div_ceil(self.count.max(1));
            Ok((slice, charge(len.max(share))))
        } else {
            Ok((Bytes::copy_from_slice(&slice), charge(len)))
        }
    }

    /// The name of `len` octets at the cursor: a slice of the frame when the frame is small, a
    /// copy of its own otherwise, so a name held for a bind never keeps a large frame alive.
    fn take_name(&mut self, len: usize) -> Result<Bytes, MessageError> {
        let whole = self.data.len();
        let slice = self.take(len, "name")?;
        if whole <= SHARE_FRAME_MAX {
            Ok(slice)
        } else {
            Ok(Bytes::copy_from_slice(&slice))
        }
    }

    /// The next message; a name it carries is pushed to `names`.
    fn message(&mut self, names: &mut Vec<Bytes>) -> Result<Message, MessageError> {
        let flags = *self
            .data
            .get(self.pos)
            .ok_or(MessageError::Truncated { what: "flags" })?;
        if flags & PAD != 0 {
            if flags != PAD {
                return Err(MessageError::Flags { flags });
            }
            return Err(MessageError::Count {
                expected: self.count,
                found: self.seen,
            });
        }
        if flags & RESERVED != 0 || flags & (STANDING | REPLAYED) == (STANDING | REPLAYED) {
            return Err(MessageError::Flags { flags });
        }
        self.pos += 1;
        let original = if flags & (STANDING | REPLAYED) != 0 {
            let original = self.sequence()?;
            if original >= self.seq {
                return Err(MessageError::OriginalSequence {
                    original,
                    seq: self.seq,
                });
            }
            original
        } else {
            0
        };
        let name_id = self.varint("name id")?;
        if !(1..=NAMES_PER_CHANNEL).contains(&name_id) {
            return Err(MessageError::NameId { id: name_id });
        }
        let name_ix = if flags & NAMED != 0 {
            let len = self.varint("name length")?;
            if len > NAME_MAX as u64 {
                return Err(MessageError::NameTooLong { len: len as usize });
            }
            let name = self.take_name(len as usize)?;
            // A frame counts at most 255 messages, so this is at most 254.
            let at = names.len() as u8;
            names.push(name);
            at
        } else {
            0
        };
        let stand = if flags & STAND != 0 {
            let secs = self.varint("stand seconds")?;
            if secs > STAND_SECS_MAX {
                return Err(MessageError::StandSeconds {
                    secs,
                    max: STAND_SECS_MAX,
                });
            }
            secs as u32
        } else {
            0
        };
        let len = self.varint("payload length")?;
        if len > self.max_message as u64 {
            return Err(MessageError::TooLarge {
                len: usize::try_from(len).unwrap_or(usize::MAX),
                max: self.max_message,
            });
        }
        let (payload, pinned) = self.take_payload(len as usize)?;
        Ok(Message {
            payload,
            seq: self.seq,
            original,
            pinned,
            stand,
            name_id: name_id as u16,
            flags: flags & (NAMED | STAND | STANDING | REPLAYED),
            name_ix,
        })
    }

    fn sequence(&mut self) -> Result<u64, MessageError> {
        self.varint("original sequence")
    }

    /// Parse every message of the frame into the end of `out`, written where it stays (no
    /// message is returned and moved again), and the names the frame carries into the end of
    /// `names` (a message says which by its index, [`Message::name_index`], counted from the
    /// frame's first: pass `names` empty). On an error `out` holds the messages before it and
    /// the frame is refused as a whole by the caller. Each message is checked, then only padding
    /// may follow the last.
    #[inline]
    pub(crate) fn parse_into(
        &mut self,
        out: &mut Vec<Message>,
        names: &mut Vec<Bytes>,
    ) -> Result<(), MessageError> {
        while self.seen < self.count {
            let message = self.message(names)?;
            out.push(message);
            self.seen += 1;
            self.seq += 1;
        }
        check_padding(&self.data[self.pos..])
    }
}

/// The octets a message is charged, as the 32 bits a [`Message`] keeps them in (the plaintext of
/// a frame is at most `STREAM_FRAME_MAX`).
fn charge(octets: usize) -> u32 {
    u32::try_from(octets).unwrap_or(u32::MAX)
}

#[cfg(test)]
impl Iterator for Messages {
    type Item = Result<ReadMessage, MessageError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        if self.seen == self.count {
            self.done = true;
            return check_padding(&self.data[self.pos..]).err().map(Err);
        }
        let mut names = Vec::new();
        match self.message(&mut names) {
            Ok(m) => {
                self.seen += 1;
                self.seq += 1;
                Some(Ok(ReadMessage::of(&m, &names)))
            }
            Err(e) => {
                self.done = true;
                Some(Err(e))
            }
        }
    }
}

/// Checks the octets after a frame's content: none, or the PAD octet and
/// zeros. A sealed frame shorter than 46 octets is padded inside its
/// plaintext with exactly this, so the tag is at the end.
pub(crate) fn check_padding(rest: &[u8]) -> Result<(), MessageError> {
    match rest.split_first() {
        None => Ok(()),
        Some((&PAD, zeros)) => match zeros.iter().position(|&b| b != 0) {
            None => Ok(()),
            Some(at) => Err(MessageError::Padding { at: 1 + at }),
        },
        Some(_) => Err(MessageError::Trailing { octets: rest.len() }),
    }
}

#[cfg(test)]
#[path = "message_equivalence_tests.rs"]
mod equivalence_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chan::aead::Aead;
    use crate::chan::key::ChannelKey;
    use crate::chan::limits::{
        FRAME_OVERHEAD, MESSAGE_DEFAULT, SEQUENCE_LIMIT, STREAM_FRAME_DEFAULT,
    };
    use proptest::prelude::*;

    fn cipher() -> FrameCipher {
        FrameCipher::new(
            &ChannelKey::from_bytes([9; 32]).frame_key(77, 0),
            Aead::Aes256Gcm,
        )
    }

    fn plaintext_of(msgs: &[OutMessage<'_>]) -> Vec<u8> {
        let mut buf = Vec::new();
        for m in msgs {
            m.encoded_len(MESSAGE_DEFAULT).unwrap();
            m.write(&mut buf).unwrap();
        }
        buf
    }

    fn read_all(plain: Vec<u8>, seq0: u64, count: usize) -> Result<Vec<ReadMessage>, MessageError> {
        Messages::new(Bytes::from(plain), seq0, count, MESSAGE_DEFAULT).collect()
    }

    fn shares_the_frame(data: &Bytes, payload: &Bytes) -> bool {
        data.as_ptr_range().contains(&payload.as_ptr())
    }

    /// Every payload of a small frame is a slice of it (the 64 octet path allocates nothing per
    /// message), and what each is charged adds up to the frame; in a frame over
    /// [`SHARE_FRAME_MAX`] a payload that is less than half of it is a copy charged its own
    /// length, so it never keeps the frame alive; one that is most of the frame is shared.
    #[test]
    fn a_payload_shares_a_small_frame_and_is_copied_out_of_a_large_one_unless_it_is_most_of_it() {
        let small = [0x11u8; 64];
        let msgs: Vec<OutMessage<'_>> = (0..14).map(|_| OutMessage::new(1, &small)).collect();
        let plain = Bytes::from(plaintext_of(&msgs));
        assert!(plain.len() <= SHARE_FRAME_MAX);
        let got: Vec<ReadMessage> = Messages::new(plain.clone(), 0, 14, MESSAGE_DEFAULT)
            .collect::<Result<_, _>>()
            .unwrap();
        assert!(got.iter().all(|m| shares_the_frame(&plain, &m.payload)));
        let charged: usize = got.iter().map(|m| m.pinned).sum();
        assert!(
            (plain.len()..plain.len() + 14).contains(&charged),
            "{charged} charged for a frame of {}",
            plain.len()
        );

        // 120 messages of 100 octets: a frame of 12 KiB.
        let hundred = [0x22u8; 100];
        let msgs: Vec<OutMessage<'_>> = (0..120).map(|_| OutMessage::new(1, &hundred)).collect();
        let plain = Bytes::from(plaintext_of(&msgs));
        assert!(plain.len() > SHARE_FRAME_MAX);
        let got: Vec<ReadMessage> = Messages::new(plain.clone(), 0, 120, MESSAGE_DEFAULT)
            .collect::<Result<_, _>>()
            .unwrap();
        assert!(got.iter().all(|m| !shares_the_frame(&plain, &m.payload)));
        assert!(
            got.iter()
                .all(|m| m.pinned == 100 && m.payload[..] == hundred)
        );

        // One message of 20,000 octets and a small one: the big is most of the frame.
        let big = vec![0x33u8; 20_000];
        let msgs = [OutMessage::new(1, &big), OutMessage::new(2, &small)];
        let plain = Bytes::from(plaintext_of(&msgs));
        let got: Vec<ReadMessage> = Messages::new(plain.clone(), 0, 2, MESSAGE_DEFAULT)
            .collect::<Result<_, _>>()
            .unwrap();
        assert!(shares_the_frame(&plain, &got[0].payload));
        assert!(!shares_the_frame(&plain, &got[1].payload));
        assert_eq!(got[1].pinned, 64);

        // A tiny message in a frame padded to 1 MiB.
        let mut padded = plaintext_of(&[OutMessage::new(1, b"x")]);
        padded.push(PAD);
        padded.resize(1 << 20, 0);
        let plain = Bytes::from(padded);
        let got: Vec<ReadMessage> = Messages::new(plain.clone(), 0, 1, MESSAGE_DEFAULT)
            .collect::<Result<_, _>>()
            .unwrap();
        assert!(!shares_the_frame(&plain, &got[0].payload));
        assert_eq!(got[0].pinned, 1);
    }

    /// The bytes a 3-octet-overhead message has, written out.
    #[test]
    fn a_small_message_takes_three_octets_of_overhead() {
        let payload = [0xaa; 5];
        let m = OutMessage::new(1, &payload);
        assert_eq!(m.encoded_len(MESSAGE_DEFAULT), Ok(8));
        assert_eq!(
            plaintext_of(&[m]),
            [0x00, 0x01, 0x05, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa]
        );
        // Larger ids and payloads take four to five.
        let big = vec![0u8; 100];
        let m = OutMessage::new(100, &big);
        assert_eq!(m.encoded_len(MESSAGE_DEFAULT), Ok(1 + 2 + 2 + 100));
    }

    #[test]
    fn every_flag_and_field_reads_back_as_written() {
        let name = b"\x08\x01a\x08\x01b";
        let all = OutMessage {
            name_id: 4_096,
            name: Some(name),
            stand_secs: Some(300),
            origin: Some(Origin::Replayed(1 << 40)),
            payload: b"payload",
        };
        let standing = OutMessage {
            origin: Some(Origin::Standing(9)),
            name: None,
            stand_secs: None,
            ..all
        };
        let plain = plaintext_of(&[all, standing]);
        assert_eq!(plain[0], NAMED | STAND | REPLAYED);
        assert_eq!(
            all.encoded_len(MESSAGE_DEFAULT).unwrap()
                + standing.encoded_len(MESSAGE_DEFAULT).unwrap(),
            plain.len()
        );
        // The messages are at 2^41 and above: a replay's original sequence is below its own.
        let got = read_all(plain, 1 << 41, 2).unwrap();
        assert_eq!(got[0].seq, 1 << 41);
        assert_eq!(got[1].seq, (1 << 41) + 1);
        assert_eq!(got[0].name_id, 4_096);
        assert_eq!(got[0].name.as_deref(), Some(&name[..]));
        assert_eq!(got[0].stand_secs, Some(300));
        assert_eq!(got[0].origin, Some(Origin::Replayed(1 << 40)));
        assert_eq!(&got[0].payload[..], b"payload");
        assert_eq!(got[1].origin, Some(Origin::Standing(9)));
        assert_eq!(got[1].name, None);
        assert_eq!(got[1].stand_secs, None);
    }

    proptest! {
        #[test]
        fn a_message_round_trips(
            id in 1u64..=4_096,
            name in proptest::option::of(proptest::collection::vec(any::<u8>(), 0..=255)),
            stand in proptest::option::of(0u64..=STAND_SECS_MAX),
            origin in proptest::option::of((any::<bool>(), 0u64..=varint::MAX)),
            payload in proptest::collection::vec(any::<u8>(), 0..300),
            seq0 in 0u64..(SEQUENCE_LIMIT - 1),
        ) {
            // A replay's original sequence is below the message's own.
            let origin = origin.filter(|_| seq0 > 0).map(|(standing, s)| {
                let s = s % seq0;
                if standing { Origin::Standing(s) } else { Origin::Replayed(s) }
            });
            let m = OutMessage { name_id: id, name: name.as_deref(), stand_secs: stand, origin, payload: &payload };
            let plain = plaintext_of(&[m]);
            prop_assert_eq!(m.encoded_len(MESSAGE_DEFAULT).unwrap(), plain.len());
            let got = read_all(plain, seq0, 1).unwrap();
            prop_assert_eq!(got.len(), 1);
            prop_assert_eq!(got[0].seq, seq0);
            prop_assert_eq!(got[0].name_id, id);
            prop_assert_eq!(got[0].name.as_deref(), name.as_deref());
            prop_assert_eq!(got[0].stand_secs, stand);
            prop_assert_eq!(got[0].origin, origin);
            prop_assert_eq!(&got[0].payload[..], &payload[..]);
        }

        /// A frame of several messages, sealed and opened through the writer.
        #[test]
        fn a_frame_of_messages_round_trips_through_seal_and_open(
            payloads in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..200), 1..40),
            seq0 in 0u64..1_000_000,
        ) {
            let cipher = cipher();
            let mut w = MessageWriter::new(SideClass::Datagram, 77, 0, seq0, 9_000, 9_000, MESSAGE_DEFAULT).unwrap();
            for (i, p) in payloads.iter().enumerate() {
                w.push(&OutMessage::new(1 + (i as u64 % 64), p)).unwrap();
            }
            let frame = w.seal(&cipher).unwrap();
            let opened = crate::chan::frame::open(&cipher, frame, 9_000).unwrap();
            prop_assert_eq!(opened.header().count as usize, payloads.len());
            let got: Vec<ReadMessage> = opened.messages(MESSAGE_DEFAULT).unwrap().collect::<Result<_, _>>().unwrap();
            prop_assert_eq!(got.len(), payloads.len());
            for (i, (m, p)) in got.iter().zip(&payloads).enumerate() {
                prop_assert_eq!(m.seq, seq0 + i as u64);
                prop_assert_eq!(&m.payload[..], &p[..]);
            }
        }

        /// No plaintext, however mangled, panics the reader; it reads or errs.
        #[test]
        fn arbitrary_plaintext_never_panics_the_reader(
            plain in proptest::collection::vec(any::<u8>(), 0..400),
            count in 0usize..300,
        ) {
            let mut n = 0;
            for r in Messages::new(Bytes::from(plain), 5, count, 64) {
                if r.is_err() { break; }
                n += 1;
                prop_assert!(n <= count);
            }
        }
    }

    /// The plaintexts a reader refuses, with the count the frame header says and the refusal each
    /// has (the reader's limit is 64): the table the equivalence cases also run.
    pub(super) fn malformed_vectors() -> &'static [(&'static [u8], usize, MessageError)] {
        &[
            (&[], 1, MessageError::Truncated { what: "flags" }),
            (&[0x00], 1, MessageError::Truncated { what: "name id" }),
            (
                &[0x00, 0x01],
                1,
                MessageError::Truncated {
                    what: "payload length",
                },
            ),
            (
                &[0x00, 0x01, 0x03, 1, 2],
                1,
                MessageError::Truncated { what: "payload" },
            ),
            (&[0x00, 0x00, 0x00], 1, MessageError::NameId { id: 0 }),
            (
                &[0x00, 0x7f, 0xff, 0x00],
                1,
                MessageError::NameId { id: 16_383 },
            ),
            (&[0x10, 0x01, 0x00], 1, MessageError::Flags { flags: 0x10 }),
            (&[0x70, 0x01, 0x00], 1, MessageError::Flags { flags: 0x70 }),
            (
                &[0x0c, 0x00, 0x01, 0x00],
                1,
                MessageError::Flags { flags: 0x0c },
            ),
            (&[0x81, 0x01, 0x00], 1, MessageError::Flags { flags: 0x81 }),
            (
                &[0x01, 0x01, 0x40],
                1,
                MessageError::Truncated {
                    what: "name length",
                },
            ),
            // a name of 256 octets
            (
                &[0x01, 0x01, 0x41, 0x00],
                1,
                MessageError::NameTooLong { len: 256 },
            ),
            // a payload over the limit the reader was given (64)
            (
                &[0x00, 0x01, 0x41, 0x00],
                1,
                MessageError::TooLarge { len: 256, max: 64 },
            ),
            // padding where a message was owed
            (
                &[0x80, 0x00],
                1,
                MessageError::Count {
                    expected: 1,
                    found: 0,
                },
            ),
            // an original sequence a varint cannot hold is never read; a truncated one is
            (
                &[0x04, 0x40],
                1,
                MessageError::Truncated {
                    what: "original sequence",
                },
            ),
            // one message where two were counted
            (
                &[0x00, 0x01, 0x00],
                2,
                MessageError::Truncated { what: "flags" },
            ),
            // octets after the last message that are not padding
            (
                &[0x00, 0x01, 0x00, 0x00],
                1,
                MessageError::Trailing { octets: 1 },
            ),
            (
                &[0x00, 0x01, 0x00, 0x80, 0x00, 0x01],
                1,
                MessageError::Padding { at: 2 },
            ),
        ]
    }

    #[test]
    fn a_malformed_plaintext_is_refused_and_says_why() {
        for (plain, count, want) in malformed_vectors() {
            let got: Result<Vec<_>, _> =
                Messages::new(Bytes::copy_from_slice(plain), 0, *count, 64).collect();
            assert_eq!(got.as_ref().err(), Some(want), "{plain:02x?}");
            let (mut into, mut names) = (Vec::new(), Vec::new());
            let parsed = Messages::new(Bytes::copy_from_slice(plain), 0, *count, 64)
                .parse_into(&mut into, &mut names);
            assert_eq!(parsed.as_ref().err(), Some(want), "parse_into {plain:02x?}");
        }
    }

    /// `parse_into` gives the messages the iterator gives, in the same order, with the same
    /// sequences and payloads.
    #[test]
    fn parse_into_gives_what_the_iterator_gives() {
        let big = [0x33u8; 300];
        let msgs = [
            OutMessage::new(1, b"a"),
            OutMessage::new(2, &big),
            OutMessage::new(3, b""),
        ];
        for count in [1usize, 2, 3] {
            let plain = Bytes::from(plaintext_of(&msgs[..count]));
            let by_iter: Vec<ReadMessage> =
                Messages::new(plain.clone(), 40, count, MESSAGE_DEFAULT)
                    .collect::<Result<_, _>>()
                    .unwrap();
            let (mut into, mut names) = (vec![], vec![]);
            Messages::new(plain, 40, count, MESSAGE_DEFAULT)
                .parse_into(&mut into, &mut names)
                .unwrap();
            let read: Vec<ReadMessage> = into.iter().map(|m| ReadMessage::of(m, &names)).collect();
            assert_eq!(read, by_iter, "{count} messages");
            assert_eq!(into.last().map(|m| m.seq), Some(40 + count as u64 - 1));
        }
    }

    #[test]
    fn padding_is_the_pad_octet_then_zeros_and_nothing_else() {
        assert_eq!(check_padding(&[]), Ok(()));
        assert_eq!(check_padding(&[PAD]), Ok(()));
        assert_eq!(check_padding(&[PAD, 0, 0, 0]), Ok(()));
        assert_eq!(
            check_padding(&[PAD, 0, 1]),
            Err(MessageError::Padding { at: 2 })
        );
        assert_eq!(
            check_padding(&[0x00]),
            Err(MessageError::Trailing { octets: 1 })
        );
        assert_eq!(
            check_padding(&[0x81, 0]),
            Err(MessageError::Trailing { octets: 2 })
        );
    }

    #[test]
    fn the_limits_hold_in_the_writer() {
        let big = vec![0u8; 65];
        assert_eq!(
            OutMessage::new(1, &big).encoded_len(64),
            Err(MessageError::TooLarge { len: 65, max: 64 })
        );
        assert_eq!(
            OutMessage::new(0, b"").encoded_len(64),
            Err(MessageError::NameId { id: 0 })
        );
        assert_eq!(
            OutMessage::new(4_097, b"").encoded_len(64),
            Err(MessageError::NameId { id: 4_097 })
        );
        let name = [b'x'; 256];
        let mut m = OutMessage::new(1, b"");
        m.name = Some(&name);
        assert_eq!(
            m.encoded_len(64),
            Err(MessageError::NameTooLong { len: 256 })
        );
        m.name = Some(&name[..255]);
        assert!(m.encoded_len(64).is_ok());
        let mut m = OutMessage::new(1, b"");
        m.stand_secs = Some(varint::MAX + 1);
        assert_eq!(
            m.encoded_len(64),
            Err(MessageError::Overflow {
                what: "stand seconds"
            })
        );
        let mut m = OutMessage::new(1, b"");
        m.origin = Some(Origin::Standing(varint::MAX + 1));
        assert_eq!(
            m.encoded_len(64),
            Err(MessageError::Overflow {
                what: "original sequence"
            })
        );
        // The session's limit never exceeds 16 MiB.
        let huge = vec![0u8; MESSAGE_MAX + 1];
        assert!(matches!(
            OutMessage::new(1, &huge).encoded_len(usize::MAX),
            Err(MessageError::TooLarge {
                max: MESSAGE_MAX,
                ..
            })
        ));
    }

    /// A sender stands an emission for at most an hour; a reader refuses more instead of passing
    /// 2^62 seconds to a consumer that adds it to an `Instant` (security review L8).
    #[test]
    fn stand_seconds_over_the_senders_limit_are_refused_by_the_reader_and_the_writer() {
        let max = 3_600;
        for secs in [3_601u64, 1 << 40, varint::MAX] {
            let mut plain = vec![STAND, 1];
            varint::write(&mut plain, secs).unwrap();
            plain.push(0);
            assert_eq!(
                read_all(plain, 0, 1).err(),
                Some(MessageError::StandSeconds { secs, max }),
                "reading {secs} s"
            );
            let mut m = OutMessage::new(1, b"");
            m.stand_secs = Some(secs);
            assert_eq!(
                m.encoded_len(MESSAGE_DEFAULT),
                Err(MessageError::StandSeconds { secs, max }),
                "writing {secs} s"
            );
        }
        // The limit itself is read and written.
        let mut m = OutMessage::new(1, b"");
        m.stand_secs = Some(max);
        let got = read_all(plaintext_of(&[m]), 0, 1).unwrap();
        assert_eq!(got[0].stand_secs, Some(max));
    }

    /// A replay carries the sequence its message went out under before, so that is below the
    /// message's own. A reader that took any original would let a key holder mute a name in
    /// `Latest` by replaying it under a sequence no genuine message reaches (security review M7).
    #[test]
    fn an_original_sequence_not_below_the_messages_own_is_refused_by_the_reader_and_the_writer() {
        for (own, original) in [(10u64, 10u64), (10, 11), (10, 1 << 60), (5, varint::MAX)] {
            for standing in [true, false] {
                let origin = if standing {
                    Origin::Standing(original)
                } else {
                    Origin::Replayed(original)
                };
                let mut m = OutMessage::new(1, b"x");
                m.origin = Some(origin);
                let mut plain = Vec::new();
                m.write(&mut plain).unwrap();
                let want = MessageError::OriginalSequence { original, seq: own };
                assert_eq!(
                    read_all(plain, own, 1).err(),
                    Some(want),
                    "reading {origin:?} at {own}"
                );
                let mut w = MessageWriter::new(
                    SideClass::Datagram,
                    77,
                    0,
                    own,
                    1_200,
                    1_200,
                    MESSAGE_DEFAULT,
                )
                .unwrap();
                assert_eq!(
                    w.push(&m),
                    Err(WriteError::Invalid(want)),
                    "writing {origin:?} at {own}"
                );
                assert!(w.is_empty(), "nothing was written");
            }
        }
        // Below is read: the second message of a frame is at seq0 + 1.
        let mut m = OutMessage::new(1, b"x");
        m.origin = Some(Origin::Replayed(10));
        let plain = plaintext_of(&[OutMessage::new(1, b"y"), m]);
        let got = read_all(plain, 10, 2).unwrap();
        assert_eq!(got[1].seq, 11);
        assert_eq!(got[1].origin, Some(Origin::Replayed(10)));
    }

    #[test]
    fn a_writer_stops_at_its_room_and_at_255_messages_and_writes_nothing_when_it_refuses() {
        let mut w = MessageWriter::new(SideClass::Datagram, 1, 0, 0, 100, 100, 64).unwrap();
        let p = [1u8; 40];
        assert_eq!(w.room(), 100 - FRAME_OVERHEAD);
        w.push(&OutMessage::new(1, &p)).unwrap(); // 43 octets
        let room = w.room();
        assert_eq!(room, 100 - FRAME_OVERHEAD - 43);
        assert_eq!(
            w.push(&OutMessage::new(1, &p)),
            Err(WriteError::Full { need: 43, room })
        );
        assert_eq!(w.room(), room);
        assert_eq!(w.len(), 1);
        assert_eq!(w.next_seq(), 1);

        let mut w = MessageWriter::new(
            SideClass::Stream,
            1,
            0,
            10,
            STREAM_FRAME_DEFAULT,
            4_096,
            MESSAGE_DEFAULT,
        )
        .unwrap();
        for _ in 0..MESSAGES_PER_FRAME {
            w.push(&OutMessage::new(1, b"")).unwrap();
        }
        assert_eq!(w.push(&OutMessage::new(1, b"")), Err(WriteError::CountFull));
        assert_eq!(w.next_seq(), 10 + 255);
        let frame = w.seal(&cipher()).unwrap();
        assert_eq!(frame[19], 255);
        assert!(matches!(
            MessageWriter::new(SideClass::Datagram, 1, 0, 0, 100, 100, 64)
                .unwrap()
                .seal(&cipher()),
            Err(FrameError::Count { .. })
        ));
    }

    /// The 64 B path: building and sealing a frame allocates a fixed number of
    /// times (the frame buffer, and the shared header `Bytes` adds when the
    /// buffer is frozen) whatever the number of messages; reading it allocates
    /// at most once. Nothing is allocated per message.
    #[test]
    fn a_frame_allocates_a_fixed_number_of_times_whatever_the_number_of_64_octet_messages() {
        use crate::chan::alloc_probe::count_allocations;
        let cipher = cipher();
        let payload = [0x5a; 64];
        let build = |messages: usize| {
            count_allocations(|| {
                let mut w = MessageWriter::new(
                    SideClass::Datagram,
                    77,
                    0,
                    0,
                    1_200,
                    1_200,
                    MESSAGE_DEFAULT,
                )
                .unwrap();
                for _ in 0..messages {
                    w.push(&OutMessage::new(1, &payload)).unwrap();
                }
                w.seal(&cipher).unwrap()
            })
        };
        let (_, one) = build(1);
        let (frame, fourteen) = build(14);
        assert_eq!(
            one, fourteen,
            "allocations of a frame of 1 and of 14 messages"
        );
        assert_eq!(
            fourteen, 2,
            "the buffer and the frozen buffer's shared header"
        );
        let (n, read) = count_allocations(|| {
            let opened = crate::chan::frame::open(&cipher, frame, 1_200).unwrap();
            let mut n = 0;
            for m in opened.messages(MESSAGE_DEFAULT).unwrap() {
                assert_eq!(m.unwrap().payload.len(), 64);
                n += 1;
            }
            n
        });
        assert_eq!(n, 14);
        assert!(
            read <= 1,
            "opening and reading 14 messages allocated {read} times"
        );
    }
}
