//! The routing header of a channel frame: the first ten octets a relay reads.
//!
//! A channel frame is a [side frame](crate::side) whose first ten octets are
//!
//! | Offset | Size | Field |
//! |---|---|---|
//! | 0 | 1 | `0x00`, the marker ([`SIDE_MARKER`]) |
//! | 1 | 1 | `ver:3 \| class:1 \| kind:4`, high bit first |
//! | 2 | 8 | channel id (or, for `UP`, the route id), big-endian |
//!
//! `ver` is [`VERSION`] (1); `class` is 0 for a datagram and 1 for a stream, so
//! a relay forwards a frame on the class it arrived on without reading
//! further; `kind` is 0 `DATA`, 1 `CHECKPOINT`, 2 `CONTROL`, 4 `UP`. A relay
//! routes on [`SideHeader`] alone: it never opens, re-packs or re-seals a
//! frame, so it needs nothing of the frame's body. The first octets that
//! occur are [`DATA_DATAGRAM`] (0x20), [`DATA_STREAM`] (0x30), [`CHECKPOINT`]
//! (0x31), [`CONTROL`] (0x32) and [`UP`] (0x24), and nothing else parses.
//!
//! The rest of a sealed frame (key epoch, sequence, count, body, tag) is the
//! channel codec's, in `ndn-heap`; a relay has no use for it and none of it
//! is read here.
//!
//! # The `UP` record, and the short-frame rule
//!
//! `UP` is the one unsealed frame: 11 octets of meaning, `0x00 | 0x24 | id (8)
//! | op (1)`, `op` 1 [`Keep`](UpOp::Keep) or 2 [`Unsub`](UpOp::Unsub), sent
//! upstream by a face that wants a route kept or ended. A NIC pads an
//! Ethernet payload under 46 octets with zero octets and a receiver cannot
//! tell padding from content, so **no frame is shorter than
//! [`MIN_FRAME_LEN`] (46) octets on any carrier**: [`UpRecord::encode`] pads
//! the record with zero octets to 46, and [`UpRecord::parse`] accepts 11 or
//! more octets whose octets after the 11th are all zero, and refuses
//! anything else. (The sealed kinds carry their padding inside the AEAD, where
//! a padded frame still has its tag at the end; see the channel codec.)

use crate::side::{SIDE_MARKER, SideClass};

/// The version in the high three bits of octet 1.
pub const VERSION: u8 = 1;

/// Octets of the routing header: marker, `ver|class|kind`, id.
pub const HEADER_LEN: usize = 10;

/// First octets of the five frames that exist: `DATA` on a datagram.
pub const DATA_DATAGRAM: u8 = 0x20;
/// `DATA` on a stream.
pub const DATA_STREAM: u8 = 0x30;
/// `CHECKPOINT` (always a stream).
pub const CHECKPOINT: u8 = 0x31;
/// `CONTROL` (always a stream).
pub const CONTROL: u8 = 0x32;
/// `UP` (always a datagram).
pub const UP: u8 = 0x24;

/// The shortest frame on any carrier: an Ethernet payload under 46 octets is
/// padded by the NIC, so no frame is allowed to be shorter.
pub const MIN_FRAME_LEN: usize = 46;

/// The longest frame a face grants its peer on a side stream by default: 1 MiB.
/// A carrier that grants this much names it in its `stream_frame_max`, and a
/// protocol that rides the stream (the channel, docs/specs/channel.md) derives
/// its default stream frame limit and message limit from it, so a message at
/// the protocol's limit is never refused by the face.
pub const STREAM_FRAME_GRANT: usize = 1024 * 1024;

/// Octets of an `UP` record that mean something (the rest, to
/// [`MIN_FRAME_LEN`], is zero).
pub const UP_LEN: usize = HEADER_LEN + 1;

/// What a frame is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SideKind {
    /// Messages, sealed.
    Data,
    /// A signed checkpoint of the frames sent, sealed.
    Checkpoint,
    /// Binds, hello, end: sealed.
    Control,
    /// An unsealed route-keeping record sent upstream.
    Up,
}

impl SideKind {
    /// The kind's four-bit code.
    pub const fn code(self) -> u8 {
        match self {
            SideKind::Data => 0,
            SideKind::Checkpoint => 1,
            SideKind::Control => 2,
            SideKind::Up => 4,
        }
    }

    /// The kind with `code`, if one is assigned.
    pub const fn from_code(code: u8) -> Option<SideKind> {
        match code {
            0 => Some(SideKind::Data),
            1 => Some(SideKind::Checkpoint),
            2 => Some(SideKind::Control),
            4 => Some(SideKind::Up),
            _ => None,
        }
    }

    /// Whether a frame of this kind may travel on `class`: `CHECKPOINT` and
    /// `CONTROL` are always streams, `UP` is always a datagram, `DATA` is
    /// either.
    pub const fn allows(self, class: SideClass) -> bool {
        matches!(
            (self, class),
            (SideKind::Data, _)
                | (SideKind::Checkpoint | SideKind::Control, SideClass::Stream)
                | (SideKind::Up, SideClass::Datagram)
        )
    }
}

/// Why a routing header or an `UP` record was refused. Every refusal is final
/// for that frame; the carrier is unaffected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HeaderError {
    /// Fewer octets than the header (or the `UP` record) needs.
    #[error("a frame of {have} octets is too short: {need} are needed")]
    Truncated { have: usize, need: usize },
    /// The first octet is not the side marker `0x00`: this is not a channel
    /// frame (an NDN packet starts with 0x05, 0x06 or 0x64).
    #[error("the first octet is {first:#04x}, not the side marker 0x00: not a channel frame")]
    NotASideFrame { first: u8 },
    /// A version this implementation does not speak.
    #[error("frame version {ver} is not the supported version 1: upgrade the older side")]
    Version { ver: u8 },
    /// A kind with no assignment.
    #[error("frame kind {kind} is not assigned (0 DATA, 1 CHECKPOINT, 2 CONTROL, 4 UP)")]
    UnknownKind { kind: u8 },
    /// A kind on a class it never uses.
    #[error(
        "a {kind:?} frame is never sent as a {class:?}: CHECKPOINT and CONTROL are streams, UP is a datagram"
    )]
    WrongClass { kind: SideKind, class: SideClass },
    /// An `UP` operation that is not 1 (keep) or 2 (unsubscribe).
    #[error("UP operation {op} is not assigned (1 keep, 2 unsub)")]
    UnknownOp { op: u8 },
    /// An `UP` record whose octets after the 11th are not all zero.
    #[error("the octets of an UP record after the 11th must be zero padding; octet {at} is not")]
    NonZeroPadding { at: usize },
    /// A frame that is not an `UP` where an `UP` record was expected.
    #[error("expected an UP record, found a {kind:?} frame")]
    NotUp { kind: SideKind },
}

/// The ten octets a relay routes on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SideHeader {
    class: SideClass,
    kind: SideKind,
    id: u64,
}

impl SideHeader {
    /// A header for a frame of `kind` on `class` with `id`, or the refusal a
    /// receiver would give it: a kind on a class it never uses.
    pub fn new(class: SideClass, kind: SideKind, id: u64) -> Result<Self, HeaderError> {
        if kind.allows(class) {
            Ok(Self { class, kind, id })
        } else {
            Err(HeaderError::WrongClass { kind, class })
        }
    }

    /// The carrier class this frame travels on.
    pub fn class(&self) -> SideClass {
        self.class
    }

    /// What the frame is.
    pub fn kind(&self) -> SideKind {
        self.kind
    }

    /// The channel id (the route id for an `UP`).
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Octet 1: `ver:3 | class:1 | kind:4`.
    pub const fn first_octet(&self) -> u8 {
        (VERSION << 5)
            | (match self.class {
                SideClass::Datagram => 0,
                SideClass::Stream => 1,
            } << 4)
            | self.kind.code()
    }

    /// The ten octets of the header.
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0] = SIDE_MARKER;
        out[1] = self.first_octet();
        out[2..].copy_from_slice(&self.id.to_be_bytes());
        out
    }

    /// Reads the header of `frame` (its first ten octets; the rest is not
    /// looked at). Never allocates.
    pub fn parse(frame: &[u8]) -> Result<Self, HeaderError> {
        let Some(head) = frame.first_chunk::<HEADER_LEN>() else {
            return Err(HeaderError::Truncated {
                have: frame.len(),
                need: HEADER_LEN,
            });
        };
        if head[0] != SIDE_MARKER {
            return Err(HeaderError::NotASideFrame { first: head[0] });
        }
        let ver = head[1] >> 5;
        if ver != VERSION {
            return Err(HeaderError::Version { ver });
        }
        let class = if head[1] & 0x10 == 0 {
            SideClass::Datagram
        } else {
            SideClass::Stream
        };
        let code = head[1] & 0x0f;
        let Some(kind) = SideKind::from_code(code) else {
            return Err(HeaderError::UnknownKind { kind: code });
        };
        let mut id = [0u8; 8];
        id.copy_from_slice(&head[2..]);
        Self::new(class, kind, u64::from_be_bytes(id))
    }
}

/// What an `UP` record asks of the face it reaches.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum UpOp {
    /// Keep this face's entry in the route alive.
    Keep,
    /// Remove this face's entry from the route.
    Unsub,
}

impl UpOp {
    /// The octet on the wire.
    pub const fn code(self) -> u8 {
        match self {
            UpOp::Keep => 1,
            UpOp::Unsub => 2,
        }
    }

    /// The operation with `code`, if assigned.
    pub const fn from_code(code: u8) -> Option<UpOp> {
        match code {
            1 => Some(UpOp::Keep),
            2 => Some(UpOp::Unsub),
            _ => None,
        }
    }
}

/// The unsealed `UP` record: `0x00 | 0x24 | id (8) | op (1)`, padded with zero
/// octets to [`MIN_FRAME_LEN`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct UpRecord {
    /// The route the record is about.
    pub id: u64,
    /// What it asks.
    pub op: UpOp,
}

impl UpRecord {
    /// The record as it is sent: its 11 octets, then zero octets to
    /// [`MIN_FRAME_LEN`], so no NIC pads it.
    pub fn encode(&self) -> [u8; MIN_FRAME_LEN] {
        let mut out = [0u8; MIN_FRAME_LEN];
        out[1] = UP;
        out[2..HEADER_LEN].copy_from_slice(&self.id.to_be_bytes());
        out[HEADER_LEN] = self.op.code();
        out
    }

    /// Reads an `UP` record from a whole frame: 11 or more octets, the first
    /// ten a valid `UP` header, the 11th an assigned operation, every octet
    /// after it zero.
    pub fn parse(frame: &[u8]) -> Result<Self, HeaderError> {
        let header = SideHeader::parse(frame)?;
        if header.kind() != SideKind::Up {
            return Err(HeaderError::NotUp {
                kind: header.kind(),
            });
        }
        let Some(&op) = frame.get(HEADER_LEN) else {
            return Err(HeaderError::Truncated {
                have: frame.len(),
                need: UP_LEN,
            });
        };
        let Some(op) = UpOp::from_code(op) else {
            return Err(HeaderError::UnknownOp { op });
        };
        if let Some(at) = frame[UP_LEN..].iter().position(|&b| b != 0) {
            return Err(HeaderError::NonZeroPadding { at: UP_LEN + at });
        }
        Ok(Self {
            id: header.id(),
            op,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(first: u8, id: u64) -> Vec<u8> {
        let mut v = vec![SIDE_MARKER, first];
        v.extend_from_slice(&id.to_be_bytes());
        v
    }

    #[test]
    fn the_first_octets_are_the_five_the_design_names() {
        let id = 0x0102_0304_0506_0708;
        for (class, kind, first) in [
            (SideClass::Datagram, SideKind::Data, DATA_DATAGRAM),
            (SideClass::Stream, SideKind::Data, DATA_STREAM),
            (SideClass::Stream, SideKind::Checkpoint, CHECKPOINT),
            (SideClass::Stream, SideKind::Control, CONTROL),
            (SideClass::Datagram, SideKind::Up, UP),
        ] {
            let h = SideHeader::new(class, kind, id).unwrap();
            assert_eq!(h.first_octet(), first);
            assert_eq!(h.encode().to_vec(), header(first, id));
            assert_eq!(SideHeader::parse(&h.encode()), Ok(h));
        }
        assert_eq!(
            [DATA_DATAGRAM, DATA_STREAM, CHECKPOINT, CONTROL, UP],
            [0x20, 0x30, 0x31, 0x32, 0x24]
        );
    }

    #[test]
    fn the_id_is_big_endian_and_the_body_is_not_read() {
        let mut frame = header(DATA_DATAGRAM, 0x0102_0304_0506_0708);
        frame.extend_from_slice(&[0xff; 40]);
        let h = SideHeader::parse(&frame).unwrap();
        assert_eq!(h.id(), 0x0102_0304_0506_0708);
        assert_eq!(h.class(), SideClass::Datagram);
        assert_eq!(h.kind(), SideKind::Data);
    }

    #[test]
    fn a_short_frame_a_foreign_marker_and_another_version_are_refused() {
        for n in 0..HEADER_LEN {
            let frame = header(DATA_DATAGRAM, 1);
            assert_eq!(
                SideHeader::parse(&frame[..n]),
                Err(HeaderError::Truncated {
                    have: n,
                    need: HEADER_LEN
                })
            );
        }
        for marker in 1..=255u8 {
            let mut frame = header(DATA_DATAGRAM, 1);
            frame[0] = marker;
            assert_eq!(
                SideHeader::parse(&frame),
                Err(HeaderError::NotASideFrame { first: marker })
            );
        }
        for ver in [0u8, 2, 3, 4, 5, 6, 7] {
            let frame = header((ver << 5) | 0x10, 1);
            assert_eq!(SideHeader::parse(&frame), Err(HeaderError::Version { ver }));
        }
    }

    #[test]
    fn only_the_assigned_kinds_on_the_classes_they_use_parse() {
        let mut ok = Vec::new();
        for class_bit in [0u8, 1] {
            for code in 0..16u8 {
                let first = (VERSION << 5) | (class_bit << 4) | code;
                if SideHeader::parse(&header(first, 7)).is_ok() {
                    ok.push(first);
                }
            }
        }
        assert_eq!(ok, [0x20, 0x24, 0x30, 0x31, 0x32]);
        assert_eq!(
            SideHeader::parse(&header(0x23, 7)),
            Err(HeaderError::UnknownKind { kind: 3 })
        );
        assert_eq!(
            SideHeader::parse(&header(0x21, 7)),
            Err(HeaderError::WrongClass {
                kind: SideKind::Checkpoint,
                class: SideClass::Datagram
            })
        );
        assert_eq!(
            SideHeader::parse(&header(0x34, 7)),
            Err(HeaderError::WrongClass {
                kind: SideKind::Up,
                class: SideClass::Stream
            })
        );
        assert!(SideHeader::new(SideClass::Datagram, SideKind::Control, 1).is_err());
    }

    /// Every pattern of the first two octets (and a spread of id octets)
    /// parses or is refused; none panics, and nothing parses that does not
    /// re-encode to the same ten octets.
    #[test]
    fn every_byte_pattern_parses_or_is_refused_and_never_panics() {
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                for fill in [0x00u8, 0x5a, 0xff] {
                    let mut frame = [fill; 24];
                    frame[0] = a;
                    frame[1] = b;
                    for len in [0usize, 1, 2, 9, 10, 11, 24] {
                        if let Ok(h) = SideHeader::parse(&frame[..len]) {
                            assert_eq!(a, 0);
                            assert_eq!(b >> 5, VERSION);
                            assert_eq!(h.encode()[..], frame[..HEADER_LEN]);
                        }
                        let _ = UpRecord::parse(&frame[..len]);
                    }
                }
            }
        }
    }

    /// The vectors of channel.md: a routing header and the `UP` record.
    #[test]
    fn the_golden_routing_header_and_up_records() {
        fn hex(b: &[u8]) -> String {
            b.iter().map(|x| format!("{x:02x}")).collect()
        }
        let id = 0x0102_0304_0506_0708;
        let h = SideHeader::new(SideClass::Datagram, SideKind::Data, id).unwrap();
        assert_eq!(hex(&h.encode()), "00200102030405060708");
        let h = SideHeader::new(SideClass::Stream, SideKind::Control, id).unwrap();
        assert_eq!(hex(&h.encode()), "00320102030405060708");
        let keep = UpRecord { id, op: UpOp::Keep }.encode();
        assert_eq!(
            hex(&keep),
            "00240102030405060708010000000000000000000000000000000000000000000000000000000000000000000000"
        );
        let unsub = UpRecord {
            id,
            op: UpOp::Unsub,
        }
        .encode();
        assert_eq!(
            hex(&unsub),
            "00240102030405060708020000000000000000000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn an_up_record_is_46_octets_and_round_trips() {
        for (op, code) in [(UpOp::Keep, 1u8), (UpOp::Unsub, 2)] {
            let rec = UpRecord {
                id: 0xdead_beef_0000_0001,
                op,
            };
            let wire = rec.encode();
            assert_eq!(wire.len(), MIN_FRAME_LEN);
            assert_eq!(wire[..2], [0x00, UP]);
            assert_eq!(wire[2..10], 0xdead_beef_0000_0001u64.to_be_bytes());
            assert_eq!(wire[10], code);
            assert!(wire[UP_LEN..].iter().all(|&b| b == 0));
            assert_eq!(UpRecord::parse(&wire), Ok(rec));
            // The 11 meaningful octets alone, and any zero tail, are accepted.
            assert_eq!(UpRecord::parse(&wire[..UP_LEN]), Ok(rec));
            let mut long = wire.to_vec();
            long.extend_from_slice(&[0; 1500]);
            assert_eq!(UpRecord::parse(&long), Ok(rec));
        }
    }

    #[test]
    fn an_up_record_with_a_non_zero_tail_or_a_bad_op_or_the_wrong_kind_is_refused() {
        let wire = UpRecord {
            id: 9,
            op: UpOp::Keep,
        }
        .encode();
        for at in UP_LEN..MIN_FRAME_LEN {
            let mut bad = wire;
            bad[at] = 1;
            assert_eq!(
                UpRecord::parse(&bad),
                Err(HeaderError::NonZeroPadding { at })
            );
        }
        let mut long = wire.to_vec();
        long.extend_from_slice(&[0; 100]);
        long.push(0x80);
        assert_eq!(
            UpRecord::parse(&long),
            Err(HeaderError::NonZeroPadding { at: long.len() - 1 })
        );
        for n in 0..UP_LEN {
            assert!(matches!(
                UpRecord::parse(&wire[..n]),
                Err(HeaderError::Truncated { .. })
            ));
        }
        for op in [0u8, 3, 0xff] {
            let mut bad = wire;
            bad[10] = op;
            assert_eq!(UpRecord::parse(&bad), Err(HeaderError::UnknownOp { op }));
        }
        let data = header(DATA_DATAGRAM, 9);
        assert_eq!(
            UpRecord::parse(&data),
            Err(HeaderError::NotUp {
                kind: SideKind::Data
            })
        );
    }
}
