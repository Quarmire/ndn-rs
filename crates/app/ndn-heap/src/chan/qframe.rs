//! The two frames of the channel path, `QUERY` (kind 5, up) and `ANSWER` (kind 6, down), and the
//! plaintexts they seal (docs/specs/channel.md §11.5, docs/specs/query.md §15).
//!
//! Neither frame has the layout of a `DATA` frame: [`super::frame::Header`] refuses both
//! (`QueryLayer`), and the query layer decodes them here. A relay reads only the first 19 octets
//! of a `QUERY` and the first 18 of an `ANSWER` (the routing header and the token, and for a
//! `QUERY` the ttl: `ndn_transport::side_header`); everything after is the sender's and sealed.
//!
//! ```text
//! QUERY  0 0x00 | 1 0x25 | 2..9 route id | 10..17 token | 18 ttl | 19..26 pair id | 27..34 qseq | 35 key epoch low | 36.. AEAD(plaintext) | tag (16)
//! ANSWER 0 0x00 | 1 0x26 or 0x36 | 2..9 route id | 10..17 token | 18 key epoch low | 19.. AEAD(plaintext) | tag (16)
//! ```
//!
//! The additional data of the seal is the header (36 octets of a `QUERY`, 19 of an `ANSWER`).

use bytes::{BufMut, Bytes};
use ndn_foundation_types::Name;
use ndn_tlv::TlvWriter;
use ndn_transport::SideClass;
use ndn_transport::side_header::{
    ANSWER_PREFIX_LEN, AnswerPrefix, HeaderError, MIN_FRAME_LEN, QUERY_PREFIX_LEN, QueryPrefix,
};

use super::limits::TAG_LEN;
use super::varint;
use crate::wire::{DEADLINE_MAX_MS, QUERY_PATH_MAX};

/// The octets of a `QUERY` before its sealed body: the relay's prefix (19), the pair id (8), the
/// query sequence (8) and the key epoch's low octet (1).
pub(crate) const QUERY_HEADER_LEN: usize = QUERY_PREFIX_LEN + 8 + 8 + 1;

/// The octets of an `ANSWER` before its sealed body: the relay's prefix (18) and the key epoch's
/// low octet.
pub(crate) const ANSWER_HEADER_LEN: usize = ANSWER_PREFIX_LEN + 1;

/// What a sealed `QUERY` adds to its plaintext: 52.
pub(crate) const QUERY_OVERHEAD: usize = QUERY_HEADER_LEN + TAG_LEN;

/// What a sealed `ANSWER` adds to its plaintext: 35.
pub(crate) const ANSWER_OVERHEAD: usize = ANSWER_HEADER_LEN + TAG_LEN;

/// The plaintext an `ANSWER` has at least, so that no frame is under 46 octets on any carrier:
/// the shorter ones are padded inside the seal (channel.md §11.3).
const ANSWER_PLAIN_MIN: usize = MIN_FRAME_LEN - ANSWER_OVERHEAD;

/// The padding flag of a sealed plaintext: `0x80`, then zero octets.
const PAD: u8 = 0x80;

/// The most octets of a refusal text.
pub(crate) const REFUSAL_TEXT_MAX: usize = 256;

/// The most octets of a query's bytes on the channel path: one datagram on the smallest floor.
pub(crate) const QUERY_BYTES_MAX: usize = 1_024;

/// Why a frame is not a `QUERY` or an `ANSWER` of the layout above.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum FrameFault {
    /// The routing header or its prefix is refused.
    #[error("{0}")]
    Header(#[from] HeaderError),
    /// The header after the relay's prefix is cut.
    #[error("a {kind} frame of {have} octets is cut: its header is {need} octets")]
    Truncated {
        kind: &'static str,
        have: usize,
        need: usize,
    },
}

/// The cleartext header of a `QUERY` (authenticated as the seal's additional data).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct QueryHeader {
    /// The route the query goes up: the channel id.
    pub(crate) route: u64,
    /// The asker's token: random, per query per server.
    pub(crate) token: u64,
    /// How long a relay keeps the breadcrumb, in 100 ms.
    pub(crate) ttl_ticks: u8,
    /// The pair the query is sealed under.
    pub(crate) pair: [u8; 8],
    /// The asker's counter under that pair: the nonce, and the replay window's key.
    pub(crate) qseq: u64,
    /// The low octet of the key epoch the pair was given at.
    pub(crate) epoch: u8,
}

impl QueryHeader {
    /// The 36 octets.
    pub(crate) fn encode(&self) -> [u8; QUERY_HEADER_LEN] {
        let mut out = [0u8; QUERY_HEADER_LEN];
        out[..QUERY_PREFIX_LEN].copy_from_slice(
            &QueryPrefix {
                id: self.route,
                token: self.token,
                ttl_ticks: self.ttl_ticks,
            }
            .encode(),
        );
        out[QUERY_PREFIX_LEN..QUERY_PREFIX_LEN + 8].copy_from_slice(&self.pair);
        out[QUERY_PREFIX_LEN + 8..QUERY_HEADER_LEN - 1].copy_from_slice(&self.qseq.to_be_bytes());
        out[QUERY_HEADER_LEN - 1] = self.epoch;
        out
    }

    /// The header of `frame` and what follows it (the sealed body), or why it is no `QUERY`.
    /// Never allocates and opens nothing.
    pub(crate) fn parse(frame: &[u8]) -> Result<(QueryHeader, &[u8]), FrameFault> {
        let prefix = QueryPrefix::parse(frame)?;
        let Some(head) = frame.get(..QUERY_HEADER_LEN) else {
            return Err(FrameFault::Truncated {
                kind: "QUERY",
                have: frame.len(),
                need: QUERY_HEADER_LEN,
            });
        };
        let mut pair = [0u8; 8];
        pair.copy_from_slice(&head[QUERY_PREFIX_LEN..QUERY_PREFIX_LEN + 8]);
        let mut qseq = [0u8; 8];
        qseq.copy_from_slice(&head[QUERY_PREFIX_LEN + 8..QUERY_HEADER_LEN - 1]);
        Ok((
            QueryHeader {
                route: prefix.id,
                token: prefix.token,
                ttl_ticks: prefix.ttl_ticks,
                pair,
                qseq: u64::from_be_bytes(qseq),
                epoch: head[QUERY_HEADER_LEN - 1],
            },
            &frame[QUERY_HEADER_LEN..],
        ))
    }
}

/// The cleartext header of an `ANSWER`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AnswerHeader {
    /// The class it travels on: a datagram, or a stream for an answer too large for one.
    pub(crate) class: SideClass,
    /// The route it comes down: the channel id.
    pub(crate) route: u64,
    /// The token of the `QUERY` it answers.
    pub(crate) token: u64,
    /// The low octet of the key epoch of the pair it is sealed under.
    pub(crate) epoch: u8,
}

impl AnswerHeader {
    /// The 19 octets.
    pub(crate) fn encode(&self) -> [u8; ANSWER_HEADER_LEN] {
        let mut out = [0u8; ANSWER_HEADER_LEN];
        out[..ANSWER_PREFIX_LEN].copy_from_slice(
            &AnswerPrefix {
                class: self.class,
                id: self.route,
                token: self.token,
            }
            .encode(),
        );
        out[ANSWER_HEADER_LEN - 1] = self.epoch;
        out
    }

    /// The header of `frame` and what follows it, or why it is no `ANSWER`.
    pub(crate) fn parse(frame: &[u8]) -> Result<(AnswerHeader, &[u8]), FrameFault> {
        let prefix = AnswerPrefix::parse(frame)?;
        let Some(&epoch) = frame.get(ANSWER_PREFIX_LEN) else {
            return Err(FrameFault::Truncated {
                kind: "ANSWER",
                have: frame.len(),
                need: ANSWER_HEADER_LEN,
            });
        };
        Ok((
            AnswerHeader {
                class: prefix.class,
                route: prefix.id,
                token: prefix.token,
                epoch,
            },
            &frame[ANSWER_HEADER_LEN..],
        ))
    }
}

/// Why a plaintext is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum PlainFault {
    /// A deadline of 0 ms or over 10 s.
    #[error("a deadline of {0} ms: a query lives for 1 ms to 10 s")]
    Deadline(u64),
    /// A path over 255 octets of value, or that is no run of name components.
    #[error("the path {0}")]
    Path(&'static str),
    /// The plaintext ends inside a field.
    #[error("the plaintext is cut")]
    Truncated,
    /// A status no assignment names, a pad that is not `0x80` and zeros, or text that is no UTF-8.
    #[error("{0}")]
    Malformed(&'static str),
}

/// The octets of the value of `path` (its components, each as a TLV).
pub(crate) fn path_value(path: &Name) -> Bytes {
    let mut w = TlvWriter::new();
    for c in path.components() {
        w.write_tlv(c.typ, &c.value);
    }
    w.finish()
}

/// What a `QUERY` seals: the asker's query id, the deadline, the asked path and the query bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct QueryPlain {
    /// The asker's query id (`Query::id`): eight octets, the same to every server of one `get`.
    /// It is inside the seal because a relay needs only the token.
    pub(crate) id: u64,
    /// Milliseconds the asker still waits, 1 to 10,000.
    pub(crate) deadline_ms: u32,
    /// The asked path, relative to the space (at most 255 octets of value).
    pub(crate) path: Name,
    /// The query octets.
    pub(crate) bytes: Bytes,
}

impl QueryPlain {
    /// The id (8 octets), `deadline_ms` (varint), the path's length (varint), the path's value,
    /// then the query octets.
    pub(crate) fn encode(&self) -> Result<Vec<u8>, PlainFault> {
        if self.deadline_ms == 0 || self.deadline_ms > DEADLINE_MAX_MS {
            return Err(PlainFault::Deadline(u64::from(self.deadline_ms)));
        }
        let path = path_value(&self.path);
        if path.len() > QUERY_PATH_MAX {
            return Err(PlainFault::Path("is over 255 octets"));
        }
        let mut out = Vec::with_capacity(16 + path.len() + self.bytes.len());
        out.put_slice(&self.id.to_be_bytes());
        varint::write(&mut out, u64::from(self.deadline_ms)).expect("a deadline fits a varint");
        varint::write(&mut out, path.len() as u64).expect("a length fits a varint");
        out.put_slice(&path);
        out.put_slice(&self.bytes);
        Ok(out)
    }

    /// The plaintext of a `QUERY`: what [`Self::encode`] writes, and nothing else.
    pub(crate) fn decode(plain: &[u8]) -> Result<QueryPlain, PlainFault> {
        let (id, plain) = plain
            .split_first_chunk::<8>()
            .ok_or(PlainFault::Truncated)?;
        let id = u64::from_be_bytes(*id);
        let (deadline, n) = varint::read(plain).ok_or(PlainFault::Truncated)?;
        if deadline == 0 || deadline > u64::from(DEADLINE_MAX_MS) {
            return Err(PlainFault::Deadline(deadline));
        }
        let rest = &plain[n..];
        let (len, n) = varint::read(rest).ok_or(PlainFault::Truncated)?;
        let rest = &rest[n..];
        let len = usize::try_from(len).map_err(|_| PlainFault::Path("is over 255 octets"))?;
        if len > QUERY_PATH_MAX {
            return Err(PlainFault::Path("is over 255 octets"));
        }
        let Some(value) = rest.get(..len) else {
            return Err(PlainFault::Truncated);
        };
        let path = Name::decode(Bytes::copy_from_slice(value))
            .map_err(|_| PlainFault::Path("is no run of name components"))?;
        Ok(QueryPlain {
            id,
            deadline_ms: deadline as u32,
            path,
            bytes: Bytes::copy_from_slice(&rest[len..]),
        })
    }
}

/// What an `ANSWER` seals: the server's word on one query.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ChanStatus {
    /// The handler's answer.
    Answered(Bytes),
    /// The handler's own refusal: the application's word, not a failure.
    Refused { code: u16, text: String },
    /// The server cannot take the query now (a limit of its own): try again after `retry_ms`.
    Busy { retry_ms: u64 },
    /// The server serves no prefix of the path.
    NotServed,
    /// The answer does not fit what the path carries: at most `max` octets.
    TooLarge { max: u64 },
}

impl ChanStatus {
    /// A refusal of the handler's, its text cut at 256 octets (on a character boundary).
    pub(crate) fn refused(code: u16, text: &str) -> ChanStatus {
        let mut end = text.len().min(REFUSAL_TEXT_MAX);
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        ChanStatus::Refused {
            code,
            text: text[..end].to_owned(),
        }
    }

    /// The plaintext: the status octet and its fields, padded (`0x80`, zeros) to the 11 octets
    /// that make a frame of 46.
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            ChanStatus::Answered(bytes) => {
                out.push(0);
                put_varint(&mut out, bytes.len() as u64);
                out.put_slice(bytes);
            }
            ChanStatus::Refused { code, text } => {
                out.push(1);
                out.put_u16(*code);
                put_varint(&mut out, text.len() as u64);
                out.put_slice(text.as_bytes());
            }
            ChanStatus::Busy { retry_ms } => {
                out.push(2);
                put_varint(&mut out, *retry_ms);
            }
            ChanStatus::NotServed => out.push(3),
            ChanStatus::TooLarge { max } => {
                out.push(4);
                put_varint(&mut out, *max);
            }
        }
        if out.len() < ANSWER_PLAIN_MIN {
            out.push(PAD);
            out.resize(ANSWER_PLAIN_MIN, 0);
        }
        out
    }

    /// The status a plaintext holds: its fields, then nothing or a pad of `0x80` and zeros.
    pub(crate) fn decode(plain: &[u8]) -> Result<ChanStatus, PlainFault> {
        let (&status, mut rest) = plain.split_first().ok_or(PlainFault::Truncated)?;
        let status = match status {
            0 => {
                let len = take_varint(&mut rest)?;
                let len = usize::try_from(len).map_err(|_| PlainFault::Truncated)?;
                let (bytes, after) = split(rest, len)?;
                rest = after;
                ChanStatus::Answered(Bytes::copy_from_slice(bytes))
            }
            1 => {
                let (code, after) = split(rest, 2)?;
                let code = u16::from_be_bytes([code[0], code[1]]);
                rest = after;
                let len = take_varint(&mut rest)?;
                let len = usize::try_from(len).map_err(|_| PlainFault::Truncated)?;
                if len > REFUSAL_TEXT_MAX {
                    return Err(PlainFault::Malformed(
                        "a refusal text is at most 256 octets",
                    ));
                }
                let (text, after) = split(rest, len)?;
                rest = after;
                let text = std::str::from_utf8(text)
                    .map_err(|_| PlainFault::Malformed("a refusal text is UTF-8"))?;
                ChanStatus::Refused {
                    code,
                    text: text.to_owned(),
                }
            }
            2 => ChanStatus::Busy {
                retry_ms: take_varint(&mut rest)?,
            },
            3 => ChanStatus::NotServed,
            4 => ChanStatus::TooLarge {
                max: take_varint(&mut rest)?,
            },
            _ => {
                return Err(PlainFault::Malformed(
                    "an answer's status is 0 to 4 (answered, refused, busy, not served, too large)",
                ));
            }
        };
        match rest.split_first() {
            None => Ok(status),
            Some((&PAD, zeros)) if zeros.iter().all(|&b| b == 0) => Ok(status),
            Some(_) => Err(PlainFault::Malformed(
                "octets follow an answer's fields that are no pad (0x80, then zeros)",
            )),
        }
    }
}

fn put_varint(out: &mut Vec<u8>, value: u64) {
    // A value over 2^62 - 1 is not a length or a time this layer makes: cap it, never panic.
    varint::write(out, value.min(varint::MAX)).expect("capped to what a varint holds");
}

fn take_varint(rest: &mut &[u8]) -> Result<u64, PlainFault> {
    let (value, n) = varint::read(rest).ok_or(PlainFault::Truncated)?;
    *rest = &rest[n..];
    Ok(value)
}

fn split(rest: &[u8], len: usize) -> Result<(&[u8], &[u8]), PlainFault> {
    if rest.len() < len {
        return Err(PlainFault::Truncated);
    }
    Ok(rest.split_at(len))
}

#[cfg(test)]
#[path = "qframe_tests.rs"]
mod tests;
