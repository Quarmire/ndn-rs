//! The channel frame: a 20-octet header, an AEAD ciphertext and a 16-octet tag
//! (channel.md, Frame).
//!
//! ```text
//! offset size field
//!      0    1 0x00, the side marker
//!      1    1 ver:3 | class:1 | kind:4   (ver 1; 0x20 DATA datagram, 0x30 DATA stream,
//!                                         0x31 CHECKPOINT, 0x32 CONTROL)
//!      2    8 channel id, big-endian
//!     10    1 key epoch, low 8 bits
//!     11    8 seq0, big-endian: the sequence of the frame's first message
//!     19    1 count: messages in a DATA frame (1-255); 0 for CHECKPOINT and CONTROL
//!     20    … the ciphertext, then the 16-octet tag
//! ```
//!
//! The first ten octets are the routing header a relay reads
//! ([`ndn_transport::SideHeader`]); the rest is authenticated, not
//! readable by a relay. The tag covers all 20 header octets as additional
//! data and every octet of the body as ciphertext, so an octet changed
//! anywhere, a changed channel id, or a frame moved to another channel fails
//! the AEAD.
//!
//! **Nonce.** 12 octets: the key epoch's low octet, three zero octets, `seq0`
//! big-endian. The key is `HKDF-SHA256(K, "ndn-channel/frame/1" ‖ channel id ‖
//! key epoch as u32)` ([`ChannelKey::frame_key`](super::key::ChannelKey::frame_key)),
//! a key per channel and per full epoch, so epochs 256 apart share a nonce
//! layout but never a key. `seq0` rises for the life of the channel (every
//! frame takes at least one sequence), so under one key a nonce is never
//! reused, with no durable counter. **A frame is sealed once**: a caller that
//! re-packs messages takes new sequences.
//!
//! **No frame is shorter than 46 octets** (an Ethernet NIC pads a payload under
//! 46 octets and the padding would be read as part of the frame): a frame whose
//! header, plaintext and tag come to fewer is padded **inside** the plaintext
//! with [`PAD`](super::message::PAD) and zero octets, the shortest padding
//! that reaches 46, so the tag stays at the end.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use ndn_transport::side_header::{self, HeaderError, SideHeader};
use ndn_transport::{SideClass, SideKind};

use super::aead::{FrameCipher, NONCE_LEN, OpenFailed};
use super::limits::{
    FRAME_OVERHEAD, HEADER_LEN, MESSAGE_MAX, MIN_FRAME_LEN, SEQUENCE_LIMIT, STREAM_FRAME_MAX,
    TAG_LEN,
};
use super::message::{MessageError, Messages, PAD};

/// Why a frame was not built, or was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum FrameError {
    /// The routing header is not valid.
    #[error(transparent)]
    Header(#[from] HeaderError),
    /// Fewer octets than the 20-octet header.
    #[error("a frame of {have} octets is shorter than its 20-octet header: drop the frame")]
    Truncated { have: usize },
    /// A frame under 46 octets: senders never build one.
    #[error(
        "a frame of {len} octets is under the 46-octet minimum no sender builds: drop the frame"
    )]
    TooShort { len: usize },
    /// A frame longer than the receiver allows.
    #[error(
        "a frame of {len} octets is over the limit of {max}: drop the frame (a stream peer that exceeds its grant is closed)"
    )]
    TooLarge { len: usize, max: usize },
    /// A frame limit outside 46 octets to 16 MiB plus slack.
    #[error(
        "a frame limit of {limit} octets is outside 46 to {STREAM_FRAME_MAX}: the carrier's room is too small for channel frames or the session grants too much"
    )]
    Limit { limit: usize },
    /// An `UP` record where a sealed frame was expected.
    #[error("a {kind:?} frame is not sealed: it has no AEAD to open")]
    NotSealed { kind: SideKind },
    /// A `count` the kind does not allow.
    #[error(
        "a {kind:?} frame counts {count} messages: DATA carries 1 to 255, CHECKPOINT and CONTROL 0"
    )]
    Count { kind: SideKind, count: u8 },
    /// A sequence at or above 2^63.
    #[error("sequence {seq0} (+{count}) reaches 2^63: re-key the channel before sending more")]
    SequenceExhausted { seq0: u64, count: u8 },
    /// The tag did not verify: a wrong key, key epoch or channel, or an octet
    /// changed on the way.
    #[error(
        "the frame did not authenticate: it is not from this session's key (wrong key epoch or channel) or was altered; drop it, and ask for the session again if the key epoch is new"
    )]
    Authentication,
    /// `messages` on a frame that is not `DATA`.
    #[error("a {kind:?} frame carries no messages")]
    NotData { kind: SideKind },
    /// A message, or the padding after the messages, is malformed.
    #[error(transparent)]
    Message(#[from] MessageError),
}

/// The 20-octet header of a sealed frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Header {
    /// The carrier class the frame travels on.
    pub class: SideClass,
    /// `DATA`, `CHECKPOINT` or `CONTROL`.
    pub kind: SideKind,
    /// The channel the frame belongs to.
    pub channel: u64,
    /// The key epoch's low 8 bits.
    pub key_epoch: u8,
    /// The sequence of the frame's first message (the frame's only sequence for
    /// `CHECKPOINT` and `CONTROL`).
    pub seq0: u64,
    /// Messages in a `DATA` frame (1 to 255); 0 for `CHECKPOINT` and `CONTROL`.
    pub count: u8,
}

impl Header {
    /// A header, or why no frame has it.
    pub(crate) fn new(
        class: SideClass,
        kind: SideKind,
        channel: u64,
        key_epoch: u8,
        seq0: u64,
        count: u8,
    ) -> Result<Self, FrameError> {
        if kind == SideKind::Up {
            return Err(FrameError::NotSealed { kind });
        }
        SideHeader::new(class, kind, channel)?;
        let counted = kind == SideKind::Data;
        if counted != (count != 0) {
            return Err(FrameError::Count { kind, count });
        }
        if seq0 >= SEQUENCE_LIMIT || seq0 + u64::from(count.max(1)) > SEQUENCE_LIMIT {
            return Err(FrameError::SequenceExhausted { seq0, count });
        }
        Ok(Self {
            class,
            kind,
            channel,
            key_epoch,
            seq0,
            count,
        })
    }

    /// The 20 octets, which are the AEAD's additional data.
    pub(crate) fn encode(&self) -> [u8; HEADER_LEN] {
        let routing = SideHeader::new(self.class, self.kind, self.channel)
            .expect("a Header is built by Header::new, which checks this");
        let mut out = [0u8; HEADER_LEN];
        out[..side_header::HEADER_LEN].copy_from_slice(&routing.encode());
        out[10] = self.key_epoch;
        out[11..19].copy_from_slice(&self.seq0.to_be_bytes());
        out[19] = self.count;
        out
    }

    /// Reads the header at the start of `frame` (20 or more octets).
    pub(crate) fn decode(frame: &[u8]) -> Result<Self, FrameError> {
        let routing = SideHeader::parse(frame)?;
        let Some(head) = frame.first_chunk::<HEADER_LEN>() else {
            return Err(FrameError::Truncated { have: frame.len() });
        };
        let mut seq0 = [0u8; 8];
        seq0.copy_from_slice(&head[11..19]);
        Self::new(
            routing.class(),
            routing.kind(),
            routing.id(),
            head[10],
            u64::from_be_bytes(seq0),
            head[19],
        )
    }

    /// The AEAD nonce: the key epoch's low octet, three zero octets, `seq0`
    /// big-endian.
    pub(crate) fn nonce(&self) -> [u8; NONCE_LEN] {
        let mut nonce = [0u8; NONCE_LEN];
        nonce[0] = self.key_epoch;
        nonce[4..].copy_from_slice(&self.seq0.to_be_bytes());
        nonce
    }

    /// The sequences the frame takes: its message count for `DATA`, one
    /// otherwise.
    pub(crate) fn sequences(&self) -> u64 {
        u64::from(self.count.max(1))
    }
}

/// A frame being built: its 20 header octets reserved, then plaintext
/// appended, then padded, tagged and sealed in place. One buffer.
#[derive(Debug)]
pub(crate) struct FrameBuf {
    buf: BytesMut,
    class: SideClass,
    kind: SideKind,
    channel: u64,
    key_epoch: u8,
    seq0: u64,
    limit: usize,
}

impl FrameBuf {
    /// A frame of `kind` on `class` for `channel`, at most `limit` octets in
    /// all (46 up to [`STREAM_FRAME_MAX`]), with `capacity` octets allocated
    /// (clamped to 46 up to `limit`).
    pub(crate) fn new(
        class: SideClass,
        kind: SideKind,
        channel: u64,
        key_epoch: u8,
        seq0: u64,
        limit: usize,
        capacity: usize,
    ) -> Result<Self, FrameError> {
        if !(MIN_FRAME_LEN..=STREAM_FRAME_MAX).contains(&limit) {
            return Err(FrameError::Limit { limit });
        }
        // Checks the kind on its class and the sequence; the count is set when
        // the frame is sealed.
        Header::new(
            class,
            kind,
            channel,
            key_epoch,
            seq0,
            u8::from(kind == SideKind::Data),
        )?;
        let mut buf = BytesMut::with_capacity(capacity.clamp(MIN_FRAME_LEN, limit));
        buf.put_bytes(0, HEADER_LEN);
        Ok(Self {
            buf,
            class,
            kind,
            channel,
            key_epoch,
            seq0,
            limit,
        })
    }

    /// The sequence of the frame's first message.
    #[cfg(test)]
    pub(crate) fn seq0(&self) -> u64 {
        self.seq0
    }

    /// Octets of plaintext the frame can still take.
    pub(crate) fn room(&self) -> usize {
        self.limit
            .saturating_sub(FRAME_OVERHEAD + self.plaintext_len())
    }

    /// Octets of plaintext so far.
    pub(crate) fn plaintext_len(&self) -> usize {
        self.buf.len() - HEADER_LEN
    }

    /// The plaintext buffer, for appending. The caller keeps within
    /// [`room`](Self::room).
    pub(super) fn plaintext_mut(&mut self) -> &mut BytesMut {
        &mut self.buf
    }

    /// Appends `octets` to the plaintext, or refuses when they do not fit.
    pub(crate) fn put(&mut self, octets: &[u8]) -> Result<(), FrameError> {
        if octets.len() > self.room() {
            return Err(FrameError::TooLarge {
                len: FRAME_OVERHEAD + self.plaintext_len() + octets.len(),
                max: self.limit,
            });
        }
        self.buf.put_slice(octets);
        Ok(())
    }

    /// Pads to 46 octets if shorter, writes the header (`count` messages),
    /// reserves the tag and seals the plaintext in place. The frame is an allocation of its own
    /// size: when the buffer it was built in has more than a quarter (and 64 octets) to spare,
    /// the frame is copied to an exact one.
    pub(crate) fn seal(mut self, cipher: &FrameCipher, count: u8) -> Result<Bytes, FrameError> {
        let header = Header::new(
            self.class,
            self.kind,
            self.channel,
            self.key_epoch,
            self.seq0,
            count,
        )?;
        let unpadded = self.buf.len() + TAG_LEN;
        if unpadded < MIN_FRAME_LEN {
            self.buf.put_u8(PAD);
            self.buf.put_bytes(0, MIN_FRAME_LEN - unpadded - 1);
        }
        let body_end = self.buf.len();
        self.buf.put_bytes(0, TAG_LEN);
        self.buf[..HEADER_LEN].copy_from_slice(&header.encode());

        let (head, rest) = self.buf.split_at_mut(HEADER_LEN);
        let (body, tag) = rest.split_at_mut(body_end - HEADER_LEN);
        tag.copy_from_slice(&cipher.seal_detached(header.nonce(), head, body));
        // The buffer was sized for everything that was pending, and the run that fit may be a
        // fraction of it. The ring (and a carrier that queues the frame) keeps the whole
        // allocation alive, so a frame that uses well under its buffer moves to an exact one.
        let wasted = self.buf.capacity() - self.buf.len();
        if wasted > self.buf.len() / 4 + 64 {
            return Ok(Bytes::copy_from_slice(&self.buf));
        }
        Ok(self.buf.freeze())
    }
}

/// Seals `plaintext` as one frame under `cipher`: the one-call form for
/// `CHECKPOINT` and `CONTROL` frames, whose plaintext is not a list of
/// messages. The frame is padded to 46 octets if shorter. Nothing is
/// allocated but the frame.
pub(crate) fn seal(
    cipher: &FrameCipher,
    header: &Header,
    plaintext: &[u8],
) -> Result<Bytes, FrameError> {
    let header = Header::new(
        header.class,
        header.kind,
        header.channel,
        header.key_epoch,
        header.seq0,
        header.count,
    )?;
    let mut frame = FrameBuf::new(
        header.class,
        header.kind,
        header.channel,
        header.key_epoch,
        header.seq0,
        STREAM_FRAME_MAX,
        (FRAME_OVERHEAD + plaintext.len()).max(MIN_FRAME_LEN),
    )?;
    frame.put(plaintext)?;
    frame.seal(cipher, header.count)
}

/// An opened frame: its header and its plaintext, authenticated.
#[derive(Debug)]
pub(crate) struct Opened {
    header: Header,
    plaintext: Bytes,
}

impl Opened {
    /// The frame's header.
    #[cfg(test)]
    pub(crate) fn header(&self) -> &Header {
        &self.header
    }

    /// The plaintext, with any padding still on its end.
    pub(crate) fn plaintext(&self) -> &Bytes {
        &self.plaintext
    }

    /// The messages of a `DATA` frame, each payload a slice of this frame's
    /// plaintext. `max_message` is the session's payload limit.
    pub(crate) fn messages(&self, max_message: usize) -> Result<Messages, FrameError> {
        if self.header.kind != SideKind::Data {
            return Err(FrameError::NotData {
                kind: self.header.kind,
            });
        }
        Ok(Messages::new(
            self.plaintext.clone(),
            self.header.seq0,
            usize::from(self.header.count),
            max_message.min(MESSAGE_MAX),
        ))
    }
}

/// Opens `frame` under `cipher`: checks its length against `limit` (the
/// carrier's room or the stream frame limit granted) and the 46-octet minimum,
/// reads the header, verifies the tag over all of it and decrypts in place. The
/// buffer is reused when `frame` is the only handle to it, and copied once when
/// it is shared.
///
/// The key epoch in the header is its low octet only: the caller picks the
/// [`FrameCipher`] for the full epoch before it opens.
pub(crate) fn open(cipher: &FrameCipher, frame: Bytes, limit: usize) -> Result<Opened, FrameError> {
    let len = frame.len();
    let header = Header::decode(&frame)?;
    if len < MIN_FRAME_LEN {
        return Err(FrameError::TooShort { len });
    }
    let max = limit.min(STREAM_FRAME_MAX);
    if len > max {
        return Err(FrameError::TooLarge { len, max });
    }
    let mut buf = match frame.try_into_mut() {
        Ok(buf) => buf,
        Err(shared) => BytesMut::from(&shared[..]),
    };
    let (head, body) = buf.split_at_mut(HEADER_LEN);
    cipher
        .open_in_place(header.nonce(), head, body)
        .map_err(|OpenFailed| FrameError::Authentication)?;
    buf.truncate(len - TAG_LEN);
    let mut plaintext = buf.freeze();
    plaintext.advance(HEADER_LEN);
    Ok(Opened { header, plaintext })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chan::aead::Aead;
    use crate::chan::key::{ChannelKey, FrameKey};
    use crate::chan::limits::MESSAGE_DEFAULT;
    use crate::chan::message::{Message, MessageWriter, OutMessage};
    use proptest::prelude::*;

    const BOTH: [Aead; 2] = [Aead::Aes256Gcm, Aead::ChaCha20Poly1305];
    const CHANNEL: u64 = 0x0102_0304_0506_0708;
    /// The full epoch; the header carries its low octet, 0x02.
    const EPOCH: u32 = 0x0102;
    const SEQ0: u64 = 0x1122_3344_5566_7788;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// `K` = octets 0x00 to 0x1f.
    fn channel_key() -> ChannelKey {
        ChannelKey::from_bytes(std::array::from_fn(|i| i as u8))
    }

    fn frame_key(channel: u64, epoch: u32) -> FrameKey {
        channel_key().frame_key(channel, epoch)
    }

    fn cipher(aead: Aead) -> FrameCipher {
        FrameCipher::new(&frame_key(CHANNEL, EPOCH), aead)
    }

    /// A DATA frame of two messages: a bare one and a NAMED one.
    fn data_frame(aead: Aead, class: SideClass) -> Bytes {
        let mut w = MessageWriter::new(
            class,
            CHANNEL,
            EPOCH as u8,
            SEQ0,
            1_200,
            1_200,
            MESSAGE_DEFAULT,
        )
        .unwrap();
        w.push(&OutMessage::new(1, b"hello")).unwrap();
        let mut named = OutMessage::new(2, b"world!");
        named.name = Some(b"\x08\x01a");
        w.push(&named).unwrap();
        w.seal(&cipher(aead)).unwrap()
    }

    /// One message with an empty payload: 3 octets of plaintext, so the frame
    /// is padded to 46.
    fn padded_frame(aead: Aead) -> Bytes {
        let mut w = MessageWriter::new(
            SideClass::Stream,
            CHANNEL,
            EPOCH as u8,
            SEQ0,
            1_200,
            1_200,
            MESSAGE_DEFAULT,
        )
        .unwrap();
        w.push(&OutMessage::new(1, b"")).unwrap();
        w.seal(&cipher(aead)).unwrap()
    }

    fn checkpoint_frame(aead: Aead) -> Bytes {
        let header = Header::new(
            SideClass::Stream,
            SideKind::Checkpoint,
            CHANNEL,
            EPOCH as u8,
            SEQ0,
            0,
        )
        .unwrap();
        let plaintext: Vec<u8> = (1..=30).collect();
        seal(&cipher(aead), &header, &plaintext).unwrap()
    }

    /// HELLO: op 3, then the sender's current sequence as a varint.
    fn control_frame(aead: Aead) -> Bytes {
        let header = Header::new(
            SideClass::Stream,
            SideKind::Control,
            CHANNEL,
            EPOCH as u8,
            SEQ0,
            0,
        )
        .unwrap();
        let plaintext = [0x03, 0xd1, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        seal(&cipher(aead), &header, &plaintext).unwrap()
    }

    /// Golden frames. The frame key was computed independently with
    /// `openssl kdf HKDF` (so a wrong label, a missing field or a wrong byte
    /// order in the schedule fails here), and the frames are the octets `ring`
    /// and RustCrypto both produce (see `aead.rs`). They are the vectors of
    /// channel.md.
    #[test]
    fn the_golden_frames_are_these_octets() {
        assert_eq!(
            hex(frame_key(CHANNEL, EPOCH).expose()),
            "91de2d89433d466f77cb1018f68c9fdbba620980522e4ee557c168bbf1a8d196"
        );
        assert_eq!(hex(&channel_key().id()), "62939e166fa5dba1");
        assert_eq!(
            hex(&data_frame(Aead::Aes256Gcm, SideClass::Datagram)),
            "00200102030405060708021122334455667788027a717a4fb0a19e51de28cca72d34bb909c205895e5d097a1937e7ce5f579f4fd1c32a18e7f"
        );
        assert_eq!(
            hex(&data_frame(Aead::ChaCha20Poly1305, SideClass::Datagram)),
            "002001020304050607080211223344556677880219081b0319ad28f01191a9adb047d8cf9edab2e3b08a19ea53d2b9e33b47704bf5da4b2cf6"
        );
        assert_eq!(
            hex(&padded_frame(Aead::ChaCha20Poly1305)),
            "003001020304050607080211223344556677880119081eeb7cc1449f10937cd4a971a420bf82233f87e8846faf36"
        );
        assert_eq!(
            hex(&checkpoint_frame(Aead::Aes256Gcm)),
            "00310102030405060708021122334455667788007b727c23d0cbf536d620c4a3215bb2f7e24027e5d13ac14f1f042a165ae413a2371eb6c94c4f120297429b26ee95"
        );
        assert_eq!(
            hex(&control_frame(Aead::ChaCha20Poly1305)),
            "00320102030405060708021122334455667788001ad83c58389422e898139cdf1fd88c4f66931d9a5f646184dfc6"
        );
    }

    #[test]
    fn the_golden_frames_open_to_their_messages() {
        for aead in BOTH {
            let frame = data_frame(aead, SideClass::Datagram);
            assert_eq!(frame[..2], [0x00, 0x20]);
            assert_eq!(frame[2..10], CHANNEL.to_be_bytes());
            assert_eq!(frame[10], 0x02);
            assert_eq!(frame[11..19], SEQ0.to_be_bytes());
            assert_eq!(frame[19], 2);
            let opened = open(&cipher(aead), frame, 1_200).unwrap();
            assert_eq!(
                hex(opened.plaintext()),
                "00010568656c6c6f01020308016106776f726c6421"
            );
            let got: Vec<Message> = opened
                .messages(MESSAGE_DEFAULT)
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            assert_eq!(got.len(), 2);
            assert_eq!(
                (got[0].seq, got[0].name_id, &got[0].payload[..]),
                (SEQ0, 1, &b"hello"[..])
            );
            assert_eq!(
                (got[1].seq, got[1].name_id, &got[1].payload[..]),
                (SEQ0 + 1, 2, &b"world!"[..])
            );
            assert_eq!(got[1].name.as_deref(), Some(&b"\x08\x01a"[..]));

            let frame = padded_frame(aead);
            assert_eq!(frame.len(), MIN_FRAME_LEN);
            assert_eq!(frame[..2], [0x00, 0x30]);
            let opened = open(&cipher(aead), frame, 1_200).unwrap();
            assert_eq!(opened.plaintext()[..], [0, 1, 0, PAD, 0, 0, 0, 0, 0, 0]);
            assert_eq!(opened.messages(MESSAGE_DEFAULT).unwrap().count(), 1);

            let opened = open(&cipher(aead), checkpoint_frame(aead), 1_200).unwrap();
            assert_eq!(opened.header().kind, SideKind::Checkpoint);
            assert_eq!(opened.header().count, 0);
            assert_eq!(opened.plaintext()[..], (1..=30).collect::<Vec<u8>>()[..]);
            assert!(matches!(
                opened.messages(1),
                Err(FrameError::NotData { .. })
            ));

            let frame = control_frame(aead);
            assert_eq!(frame.len(), MIN_FRAME_LEN);
            assert_eq!(frame[..2], [0x00, 0x32]);
            let opened = open(&cipher(aead), frame, 1_200).unwrap();
            assert_eq!(
                opened.plaintext()[..9],
                [0x03, 0xd1, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]
            );
            assert_eq!(
                crate::chan::message::check_padding(&opened.plaintext()[9..]),
                Ok(())
            );
        }
    }

    /// Every octet of every frame kind, flipped one at a time in three ways,
    /// both AEADs: nothing opens. Where the header still parses (channel, epoch,
    /// sequence, count) it is the AEAD that refuses.
    #[test]
    fn a_flipped_octet_in_any_header_field_or_the_body_fails_the_aead() {
        for aead in BOTH {
            let frames = [
                data_frame(aead, SideClass::Datagram),
                data_frame(aead, SideClass::Stream),
                padded_frame(aead),
                checkpoint_frame(aead),
                control_frame(aead),
            ];
            for frame in frames {
                assert!(open(&cipher(aead), frame.clone(), 1_200).is_ok());
                for i in 0..frame.len() {
                    for mask in [0x01u8, 0x80, 0xff] {
                        let mut bad = frame.to_vec();
                        bad[i] ^= mask;
                        let err = open(&cipher(aead), Bytes::from(bad.clone()), 1_200).unwrap_err();
                        if Header::decode(&bad).is_ok() {
                            assert_eq!(
                                err,
                                FrameError::Authentication,
                                "{aead:?} octet {i} ^ {mask:#x}"
                            );
                        }
                    }
                }
            }
        }
    }

    /// A frame whose header octets 2..=19 are changed is refused by the tag
    /// (AAD) even though the key is right; the marker, version, class and kind
    /// are refused by the parser before that.
    #[test]
    fn every_header_octet_is_covered_by_the_tag() {
        for aead in BOTH {
            let frame = data_frame(aead, SideClass::Stream);
            for i in 2..HEADER_LEN {
                let mut bad = frame.to_vec();
                bad[i] = bad[i].wrapping_add(1);
                if i == 19 {
                    bad[i] = 3; // a count that still parses
                }
                assert_eq!(
                    open(&cipher(aead), Bytes::from(bad), 1_200).unwrap_err(),
                    FrameError::Authentication,
                    "{aead:?} octet {i}"
                );
            }
        }
    }

    #[test]
    fn a_frame_moved_to_another_channel_id_fails() {
        for aead in BOTH {
            let frame = data_frame(aead, SideClass::Datagram);
            // The id rewritten in the header, under the right key: the AAD no longer matches.
            let mut moved = frame.to_vec();
            moved[2..10].copy_from_slice(&(CHANNEL + 1).to_be_bytes());
            assert_eq!(
                open(&cipher(aead), Bytes::from(moved.clone()), 1_200).unwrap_err(),
                FrameError::Authentication
            );
            // And under the other channel's own key (the receiver of that
            // channel, same K): the key differs.
            let other = FrameCipher::new(&frame_key(CHANNEL + 1, EPOCH), aead);
            assert_eq!(
                open(&other, Bytes::from(moved), 1_200).unwrap_err(),
                FrameError::Authentication
            );
            assert_eq!(
                open(&other, frame, 1_200).unwrap_err(),
                FrameError::Authentication
            );
        }
    }

    /// The key epoch's low octet is in the header, but the key is derived from
    /// the whole epoch: a frame sealed at epoch 2 does not open at epoch 258.
    #[test]
    fn a_frame_does_not_open_under_an_epoch_256_apart() {
        for aead in BOTH {
            let frame = data_frame(aead, SideClass::Datagram);
            let later = FrameCipher::new(&frame_key(CHANNEL, EPOCH + 256), aead);
            assert_eq!(
                open(&later, frame, 1_200).unwrap_err(),
                FrameError::Authentication
            );
        }
    }

    #[test]
    fn the_same_plaintext_under_the_other_aead_does_not_open() {
        let frame = data_frame(Aead::Aes256Gcm, SideClass::Datagram);
        assert_eq!(
            open(&cipher(Aead::ChaCha20Poly1305), frame, 1_200).unwrap_err(),
            FrameError::Authentication
        );
    }

    proptest! {
        /// Under one frame key a nonce is unique per sequence; across epochs the
        /// nonce layout repeats every 256 epochs but the key never does, so no
        /// (key, nonce) pair recurs for two different (epoch, seq0).
        #[test]
        fn a_nonce_is_never_reused_across_a_rekey(
            e1 in 0u32..2_000, s1 in 0u64..SEQUENCE_LIMIT,
            e2 in 0u32..2_000, s2 in 0u64..SEQUENCE_LIMIT,
            nudge in 0u64..4,
        ) {
            // Bias towards the collisions that matter: same sequence, epochs 256 apart.
            let (e2, s2) = if nudge == 0 { (e1 + 256 * (1 + e2 % 7), s1) } else { (e2, s2) };
            prop_assume!((e1, s1) != (e2, s2));
            let h = |e: u32, s: u64| Header::new(SideClass::Datagram, SideKind::Data, CHANNEL, e as u8, s, 1).unwrap();
            let pair = |e: u32, s: u64| (frame_key(CHANNEL, e).expose().to_vec(), h(e, s).nonce());
            // `SideKind::Data` with count 1 needs seq0 + 1 <= 2^63.
            prop_assume!(s1 < SEQUENCE_LIMIT - 1 && s2 < SEQUENCE_LIMIT - 1);
            prop_assert_ne!(pair(e1, s1), pair(e2, s2));
        }

        /// The nonce is the epoch's low octet, three zeros, the sequence.
        #[test]
        fn the_nonce_layout(epoch in any::<u8>(), seq0 in 0u64..SEQUENCE_LIMIT - 1) {
            let nonce = Header::new(SideClass::Stream, SideKind::Data, 1, epoch, seq0, 1).unwrap().nonce();
            prop_assert_eq!(nonce[0], epoch);
            prop_assert_eq!(&nonce[1..4], &[0, 0, 0]);
            prop_assert_eq!(&nonce[4..], &seq0.to_be_bytes());
        }

        /// Bytes that are not a frame, or a frame cut or grown, never panic the
        /// codec: they are refused.
        #[test]
        fn arbitrary_octets_never_panic_open(
            octets in proptest::collection::vec(any::<u8>(), 0..300),
            limit in 0usize..400,
            lead in any::<bool>(),
        ) {
            let mut octets = octets;
            if lead && octets.len() >= 2 {
                octets[0] = 0;
                octets[1] = 0x20;
            }
            for aead in BOTH {
                let r = open(&cipher(aead), Bytes::from(octets.clone()), limit);
                prop_assert!(r.is_err());
            }
            let _ = Header::decode(&octets);
        }
    }

    #[test]
    fn a_truncated_or_extended_frame_is_refused_at_every_length() {
        for aead in BOTH {
            let frame = data_frame(aead, SideClass::Datagram);
            for n in 0..frame.len() {
                assert!(
                    open(&cipher(aead), frame.slice(..n), 1_200).is_err(),
                    "{aead:?} cut to {n}"
                );
            }
            for extra in 1..=40 {
                let mut longer = frame.to_vec();
                longer.extend(std::iter::repeat_n(0u8, extra));
                assert_eq!(
                    open(&cipher(aead), Bytes::from(longer), 1_200).unwrap_err(),
                    FrameError::Authentication,
                    "{aead:?} +{extra} zero octets"
                );
            }
        }
    }

    #[test]
    fn the_frame_limit_and_the_46_octet_minimum_are_enforced_on_open() {
        let frame = data_frame(Aead::Aes256Gcm, SideClass::Datagram);
        let len = frame.len();
        assert!(open(&cipher(Aead::Aes256Gcm), frame.clone(), len).is_ok());
        assert_eq!(
            open(&cipher(Aead::Aes256Gcm), frame.clone(), len - 1).unwrap_err(),
            FrameError::TooLarge { len, max: len - 1 }
        );
        // A well-formed header over fewer than 46 octets.
        let short = frame.slice(..MIN_FRAME_LEN - 1);
        assert_eq!(
            open(&cipher(Aead::Aes256Gcm), short, 1_200).unwrap_err(),
            FrameError::TooShort {
                len: MIN_FRAME_LEN - 1
            }
        );
        // Under 20 octets: no header.
        assert_eq!(
            open(&cipher(Aead::Aes256Gcm), frame.slice(..12), 1_200).unwrap_err(),
            FrameError::Truncated { have: 12 }
        );
        // The limit cannot be raised past 16 MiB plus slack.
        let mut huge_header = data_frame(Aead::Aes256Gcm, SideClass::Datagram).to_vec();
        huge_header.resize(STREAM_FRAME_MAX + 1, 0);
        assert_eq!(
            open(
                &cipher(Aead::Aes256Gcm),
                Bytes::from(huge_header),
                usize::MAX
            )
            .unwrap_err(),
            FrameError::TooLarge {
                len: STREAM_FRAME_MAX + 1,
                max: STREAM_FRAME_MAX
            }
        );
    }

    #[test]
    fn a_frame_builder_refuses_a_limit_outside_46_to_the_stream_maximum() {
        for limit in [0, MIN_FRAME_LEN - 1, STREAM_FRAME_MAX + 1] {
            assert_eq!(
                FrameBuf::new(SideClass::Datagram, SideKind::Data, 1, 0, 0, limit, 0).unwrap_err(),
                FrameError::Limit { limit }
            );
        }
        for limit in [MIN_FRAME_LEN, STREAM_FRAME_MAX] {
            assert!(FrameBuf::new(SideClass::Datagram, SideKind::Data, 1, 0, 0, limit, 0).is_ok());
        }
        assert!(
            matches!(
                FrameBuf::new(SideClass::Datagram, SideKind::Control, 1, 0, 0, 60, 60),
                Err(FrameError::Header(_))
            ),
            "CONTROL is never a datagram"
        );
        assert!(matches!(
            FrameBuf::new(SideClass::Datagram, SideKind::Up, 1, 0, 0, 60, 60),
            Err(FrameError::NotSealed { kind: SideKind::Up })
        ));
        let mut f = FrameBuf::new(SideClass::Stream, SideKind::Control, 1, 0, 0, 60, 60).unwrap();
        assert_eq!(f.room(), 24);
        f.put(&[0; 24]).unwrap();
        assert_eq!(f.put(&[0]), Err(FrameError::TooLarge { len: 61, max: 60 }));
    }

    #[test]
    fn a_header_refuses_the_counts_and_sequences_no_frame_has() {
        let d = SideClass::Datagram;
        let s = SideClass::Stream;
        assert!(matches!(
            Header::new(d, SideKind::Data, 1, 0, 0, 0),
            Err(FrameError::Count { .. })
        ));
        assert!(Header::new(d, SideKind::Data, 1, 0, 0, 255).is_ok());
        assert!(matches!(
            Header::new(s, SideKind::Checkpoint, 1, 0, 0, 1),
            Err(FrameError::Count { .. })
        ));
        assert!(matches!(
            Header::new(s, SideKind::Control, 1, 0, 0, 1),
            Err(FrameError::Count { .. })
        ));
        assert!(Header::new(s, SideKind::Control, 1, 0, SEQUENCE_LIMIT - 1, 0).is_ok());
        // Below 2^63, and the last message's sequence too.
        assert!(Header::new(d, SideKind::Data, 1, 0, SEQUENCE_LIMIT - 1, 1).is_ok());
        assert_eq!(
            Header::new(d, SideKind::Data, 1, 0, SEQUENCE_LIMIT - 1, 2),
            Err(FrameError::SequenceExhausted {
                seq0: SEQUENCE_LIMIT - 1,
                count: 2
            })
        );
        assert_eq!(
            Header::new(s, SideKind::Control, 1, 0, SEQUENCE_LIMIT, 0),
            Err(FrameError::SequenceExhausted {
                seq0: SEQUENCE_LIMIT,
                count: 0
            })
        );
        assert!(matches!(
            Header::new(d, SideKind::Up, 1, 0, 0, 0),
            Err(FrameError::NotSealed { .. })
        ));
        // The decoder applies the same rules to what arrives.
        let mut wire = Header::new(d, SideKind::Data, 1, 0, 5, 3).unwrap().encode();
        assert_eq!(Header::decode(&wire).unwrap().count, 3);
        wire[19] = 0;
        assert!(matches!(
            Header::decode(&wire),
            Err(FrameError::Count { .. })
        ));
        wire[19] = 1;
        wire[11] = 0x80;
        assert!(matches!(
            Header::decode(&wire),
            Err(FrameError::SequenceExhausted { .. })
        ));
    }

    #[test]
    fn the_header_encodes_in_the_documented_octets_and_decodes_back() {
        let h = Header::new(SideClass::Stream, SideKind::Data, CHANNEL, 0xab, SEQ0, 7).unwrap();
        let wire = h.encode();
        assert_eq!(hex(&wire), "00300102030405060708ab112233445566778807");
        assert_eq!(Header::decode(&wire).unwrap(), h);
        assert_eq!(h.sequences(), 7);
        assert_eq!(
            Header::new(SideClass::Stream, SideKind::Control, 1, 0, 0, 0)
                .unwrap()
                .sequences(),
            1
        );
    }

    /// A frame of every sealed kind with a payload of 0 to 64 octets is at
    /// least 46 octets, whichever AEAD and class; the padding is the
    /// shortest that gets there.
    #[test]
    fn a_frame_of_every_kind_and_size_is_at_least_46_octets_and_padded_only_as_far_as_needed() {
        for aead in BOTH {
            for len in 0..=64usize {
                let payload = vec![0xa5u8; len];
                for class in [SideClass::Datagram, SideClass::Stream] {
                    let mut w =
                        MessageWriter::new(class, CHANNEL, 2, 9, 1_200, 1_200, MESSAGE_DEFAULT)
                            .unwrap();
                    w.push(&OutMessage::new(1, &payload)).unwrap();
                    let frame = w.seal(&cipher(aead)).unwrap();
                    let message = 1 + 1 + usize::from(len > 0x3f) + 1 + len;
                    assert_eq!(
                        frame.len(),
                        (FRAME_OVERHEAD + message).max(MIN_FRAME_LEN),
                        "DATA {aead:?} {len}"
                    );
                    let opened = open(&cipher(aead), frame, 1_200).unwrap();
                    let got: Vec<_> = opened
                        .messages(MESSAGE_DEFAULT)
                        .unwrap()
                        .collect::<Result<_, _>>()
                        .unwrap();
                    assert_eq!(got.len(), 1);
                    assert_eq!(&got[0].payload[..], &payload[..]);
                }
                for kind in [SideKind::Checkpoint, SideKind::Control] {
                    let header = Header::new(SideClass::Stream, kind, CHANNEL, 2, 9, 0).unwrap();
                    let frame = seal(&cipher(aead), &header, &payload).unwrap();
                    assert_eq!(
                        frame.len(),
                        (FRAME_OVERHEAD + len).max(MIN_FRAME_LEN),
                        "{kind:?} {aead:?} {len}"
                    );
                    let opened = open(&cipher(aead), frame, 1_200).unwrap();
                    assert_eq!(&opened.plaintext()[..len], &payload[..]);
                    assert_eq!(
                        crate::chan::message::check_padding(&opened.plaintext()[len..]),
                        Ok(())
                    );
                }
            }
        }
    }

    /// The padding is inside the AEAD: zero octets appended to a sealed frame
    /// (what a NIC does) move the tag, and the frame no longer opens.
    #[test]
    fn zero_octets_appended_to_a_sealed_frame_fail_the_aead() {
        for aead in BOTH {
            let frame = padded_frame(aead);
            for extra in [1usize, 2, 17, 100] {
                let mut grown = frame.to_vec();
                grown.resize(frame.len() + extra, 0);
                assert_eq!(
                    open(&cipher(aead), Bytes::from(grown), 1_200).unwrap_err(),
                    FrameError::Authentication
                );
            }
        }
    }

    /// A sender that pads with anything but PAD and zeros is refused by the
    /// reader, after the AEAD passed.
    #[test]
    fn padding_with_a_non_zero_octet_or_not_the_pad_flag_is_malformed() {
        let aead = Aead::Aes256Gcm;
        let header = Header::new(SideClass::Datagram, SideKind::Data, CHANNEL, 2, 9, 1).unwrap();
        for (plaintext, want) in [
            (
                &[0x00, 0x01, 0x00, PAD, 0, 0, 0, 0, 0, 1][..],
                Some(MessageError::Padding { at: 6 }),
            ),
            (
                &[0x00, 0x01, 0x00, 0x00, 0, 0, 0, 0, 0, 0][..],
                Some(MessageError::Trailing { octets: 7 }),
            ),
            (&[0x00, 0x01, 0x00, PAD, 0, 0, 0, 0, 0, 0][..], None),
        ] {
            let frame = seal(&cipher(aead), &header, plaintext).unwrap();
            let opened = open(&cipher(aead), frame, 1_200).unwrap();
            let got: Result<Vec<_>, _> = opened.messages(MESSAGE_DEFAULT).unwrap().collect();
            assert_eq!(got.err(), want);
        }
    }

    /// An owned, unshared frame is decrypted where it lies; a shared one is
    /// copied once and the other handle is left as it was.
    #[test]
    fn open_decrypts_in_place_when_it_owns_the_buffer_and_copies_when_shared() {
        let aead = Aead::Aes256Gcm;
        let frame = data_frame(aead, SideClass::Datagram);
        let start = frame.as_ptr();
        let opened = open(&cipher(aead), frame, 1_200).unwrap();
        assert_eq!(
            opened.plaintext().as_ptr(),
            start.wrapping_add(HEADER_LEN),
            "in place"
        );

        let frame = data_frame(aead, SideClass::Datagram);
        let keep = frame.clone();
        let before = keep.to_vec();
        let opened = open(&cipher(aead), frame, 1_200).unwrap();
        assert_ne!(
            opened.plaintext().as_ptr(),
            keep.as_ptr().wrapping_add(HEADER_LEN),
            "copied"
        );
        assert_eq!(
            keep[..],
            before[..],
            "the other handle still holds the sealed frame"
        );
        assert_eq!(opened.messages(MESSAGE_DEFAULT).unwrap().count(), 2);
    }

    #[test]
    fn only_a_sealed_kind_has_a_frame_and_an_up_record_is_not_one() {
        let up = ndn_transport::UpRecord {
            id: CHANNEL,
            op: ndn_transport::UpOp::Keep,
        }
        .encode();
        assert_eq!(
            open(&cipher(Aead::Aes256Gcm), Bytes::copy_from_slice(&up), 1_200).unwrap_err(),
            FrameError::NotSealed { kind: SideKind::Up }
        );
    }
}
