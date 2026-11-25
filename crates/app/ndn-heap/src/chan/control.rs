//! The bodies of `CONTROL` frames (docs/specs/channel.md, Kinds): what a sender says on the stream
//! besides data. A `CONTROL` frame takes one sequence, always travels on the stream, and carries
//! `op (1) | …`; the codec reads the record and then requires nothing but padding to the end
//! of the plaintext ([`check_padding`]).

use bytes::{BufMut, Bytes, BytesMut};

use super::limits::{NAME_MAX, NAMES_PER_CHANNEL};
use super::message::{MessageError, check_padding};
use super::varint;

/// `BIND`: a name id and its name.
pub(crate) const OP_BIND: u8 = 1;
/// `UNBIND`: a name id is free again.
pub(crate) const OP_UNBIND: u8 = 2;
/// `HELLO`: the first frame on the stream after a session starts.
pub(crate) const OP_HELLO: u8 = 3;
/// `END`: the sender ends the channel.
pub(crate) const OP_END: u8 = 4;
/// `STANDING_BEGIN`: standing values follow.
pub(crate) const OP_STANDING_BEGIN: u8 = 5;
/// `STANDING_END`: the standing values are over.
pub(crate) const OP_STANDING_END: u8 = 6;

/// Why a `CONTROL` body is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ControlError {
    /// No octet at all.
    #[error("the control frame is empty: drop the frame")]
    Empty,
    /// An operation that is not assigned.
    #[error("control operation {op} is not assigned: drop the frame")]
    Unknown { op: u8 },
    /// The record ends inside a field.
    #[error("the control record ends inside its {what}: drop the frame")]
    Truncated { what: &'static str },
    /// A name id outside 1 to 4,096.
    #[error("name id {id} is outside 1 to {NAMES_PER_CHANNEL}: drop the frame")]
    NameId { id: u64 },
    /// A name over 255 octets.
    #[error("a name of {len} octets is over the {NAME_MAX} octet limit: drop the frame")]
    NameTooLong { len: usize },
    /// A value no varint holds.
    #[error("the {what} is too large to encode")]
    Overflow { what: &'static str },
    /// What follows the record is not padding.
    #[error(transparent)]
    Padding(#[from] MessageError),
}

/// One `CONTROL` record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Control {
    /// Name id `id` stands for the name whose octets (the Name TLV's value) are `name`.
    Bind {
        /// The id, 1 to 4,096.
        id: u64,
        /// The name's octets, at most 255.
        name: Bytes,
    },
    /// Name id `id` is free; a bare message under it is no longer meaningful.
    Unbind {
        /// The id.
        id: u64,
    },
    /// The sequence the sender's next message takes, as the sender stood when it sealed this.
    Hello {
        /// The next sequence.
        seq: u64,
    },
    /// The sender ends the channel.
    End,
    /// Standing values follow, up to [`Control::StandingEnd`].
    StandingBegin,
    /// The standing values are over.
    StandingEnd,
}

fn checked_id(id: u64) -> Result<(), ControlError> {
    if (1..=NAMES_PER_CHANNEL).contains(&id) {
        Ok(())
    } else {
        Err(ControlError::NameId { id })
    }
}

impl Control {
    /// The record's octets (no padding: sealing pads a short frame).
    pub(crate) fn encode(&self) -> Result<Bytes, ControlError> {
        let mut out = BytesMut::with_capacity(16);
        let overflow = |what| move |_| ControlError::Overflow { what };
        match self {
            Control::Bind { id, name } => {
                checked_id(*id)?;
                if name.len() > NAME_MAX {
                    return Err(ControlError::NameTooLong { len: name.len() });
                }
                out.reserve(name.len());
                out.put_u8(OP_BIND);
                varint::write(&mut out, *id).map_err(overflow("name id"))?;
                varint::write(&mut out, name.len() as u64).map_err(overflow("name length"))?;
                out.put_slice(name);
            }
            Control::Unbind { id } => {
                checked_id(*id)?;
                out.put_u8(OP_UNBIND);
                varint::write(&mut out, *id).map_err(overflow("name id"))?;
            }
            Control::Hello { seq } => {
                out.put_u8(OP_HELLO);
                varint::write(&mut out, *seq).map_err(overflow("sequence"))?;
            }
            Control::End => out.put_u8(OP_END),
            Control::StandingBegin => out.put_u8(OP_STANDING_BEGIN),
            Control::StandingEnd => out.put_u8(OP_STANDING_END),
        }
        Ok(out.freeze())
    }

    /// Reads one record from an opened `CONTROL` frame's plaintext, then requires nothing but
    /// padding to its end.
    pub(crate) fn decode(plaintext: &Bytes) -> Result<Control, ControlError> {
        let mut at = 0usize;
        let op = *plaintext.first().ok_or(ControlError::Empty)?;
        at += 1;
        let read = |what: &'static str, at: &mut usize| -> Result<u64, ControlError> {
            let (value, n) =
                varint::read(&plaintext[*at..]).ok_or(ControlError::Truncated { what })?;
            *at += n;
            Ok(value)
        };
        let control = match op {
            OP_BIND => {
                let id = read("name id", &mut at)?;
                checked_id(id)?;
                let len = read("name length", &mut at)?;
                let len = usize::try_from(len).unwrap_or(usize::MAX);
                if len > NAME_MAX {
                    return Err(ControlError::NameTooLong { len });
                }
                let end = at
                    .checked_add(len)
                    .filter(|end| *end <= plaintext.len())
                    .ok_or(ControlError::Truncated { what: "name" })?;
                let name = plaintext.slice(at..end);
                at = end;
                Control::Bind { id, name }
            }
            OP_UNBIND => {
                let id = read("name id", &mut at)?;
                checked_id(id)?;
                Control::Unbind { id }
            }
            OP_HELLO => Control::Hello {
                seq: read("sequence", &mut at)?,
            },
            OP_END => Control::End,
            OP_STANDING_BEGIN => Control::StandingBegin,
            OP_STANDING_END => Control::StandingEnd,
            op => return Err(ControlError::Unknown { op }),
        };
        check_padding(&plaintext[at..])?;
        Ok(control)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn all() -> Vec<Control> {
        vec![
            Control::Bind {
                id: 1,
                name: Bytes::from_static(b"\x08\x01a"),
            },
            Control::Bind {
                id: 4096,
                name: Bytes::new(),
            },
            Control::Unbind { id: 7 },
            Control::Hello {
                seq: 0x1122_3344_5566_7788,
            },
            Control::Hello { seq: 1 },
            Control::End,
            Control::StandingBegin,
            Control::StandingEnd,
        ]
    }

    #[test]
    fn every_record_reads_back_what_was_written_with_or_without_padding() {
        for control in all() {
            let body = control.encode().unwrap();
            assert_eq!(Control::decode(&body).unwrap(), control);
            let mut padded = body.to_vec();
            padded.push(super::super::message::PAD);
            padded.extend_from_slice(&[0; 5]);
            assert_eq!(Control::decode(&Bytes::from(padded)).unwrap(), control);
        }
    }

    #[test]
    fn the_octets_are_op_then_varints() {
        let hello = Control::Hello {
            seq: 0x1122_3344_5566_7788,
        }
        .encode()
        .unwrap();
        assert_eq!(
            hex(&hello),
            "03d122334455667788",
            "the vector channel.md prints"
        );
        let bind = Control::Bind {
            id: 2,
            name: Bytes::from_static(b"\x08\x01a"),
        }
        .encode()
        .unwrap();
        assert_eq!(hex(&bind), "0102030801".to_owned() + "61");
        assert_eq!(hex(&Control::Unbind { id: 2 }.encode().unwrap()), "0202");
        assert_eq!(hex(&Control::End.encode().unwrap()), "04");
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn a_record_is_refused_when_it_is_empty_unknown_cut_or_followed_by_more() {
        let b = |v: &[u8]| Bytes::copy_from_slice(v);
        assert_eq!(Control::decode(&b(&[])), Err(ControlError::Empty));
        assert_eq!(
            Control::decode(&b(&[0])),
            Err(ControlError::Unknown { op: 0 })
        );
        assert_eq!(
            Control::decode(&b(&[7])),
            Err(ControlError::Unknown { op: 7 })
        );
        assert!(matches!(
            Control::decode(&b(&[OP_BIND, 1, 3, 1, 2])),
            Err(ControlError::Truncated { what: "name" })
        ));
        assert!(matches!(
            Control::decode(&b(&[OP_HELLO])),
            Err(ControlError::Truncated { what: "sequence" })
        ));
        assert_eq!(
            Control::decode(&b(&[OP_UNBIND, 0])),
            Err(ControlError::NameId { id: 0 })
        );
        assert_eq!(
            Control::decode(&b(&[OP_UNBIND, 0x50, 0x01])),
            Err(ControlError::NameId { id: 4097 })
        );
        // Something after the record that is not padding.
        assert!(matches!(
            Control::decode(&b(&[OP_END, 1])),
            Err(ControlError::Padding(_))
        ));
        // Padding with a non-zero octet.
        assert!(matches!(
            Control::decode(&b(&[OP_END, 0x80, 0, 1])),
            Err(ControlError::Padding(_))
        ));
        // A name over 255 octets cannot be written or read.
        let long = Control::Bind {
            id: 1,
            name: Bytes::from(vec![0; 256]),
        };
        assert_eq!(long.encode(), Err(ControlError::NameTooLong { len: 256 }));
        let mut wire = vec![OP_BIND, 1, 0x41, 0x00];
        wire.extend_from_slice(&[0; 256]);
        assert_eq!(
            Control::decode(&Bytes::from(wire)),
            Err(ControlError::NameTooLong { len: 256 })
        );
        // HELLO's sequence is a varint: 2^62 does not fit.
        assert_eq!(
            Control::Hello { seq: 1 << 62 }.encode(),
            Err(ControlError::Overflow { what: "sequence" })
        );
    }

    proptest! {
        #[test]
        fn arbitrary_octets_are_read_or_refused_and_never_panic(octets in proptest::collection::vec(any::<u8>(), 0..300)) {
            let _ = Control::decode(&Bytes::from(octets));
        }
    }
}
