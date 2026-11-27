//! The records of a signed query (`docs/specs/query.md`): the ask an Interest carries in its
//! ApplicationParameters and the answer the Data carries as its Content.
//!
//! TLV-TYPEs are the block 0x06C0–0x06FF. Odd is critical: a decoder refuses a type it does not
//! know. Even is skippable and reserved for additive fields, as in heap.md §3.4. Numbers are
//! NonNegativeIntegers. 0x06D9 is reserved for a later `Busy` answer and is not written or read.
//!
//! A query is **plain** (`Q_PATH` and the query octets in the clear) or **sealed** (`Q_SEAL`,
//! `Q_EPOCH` and `Q_SEQ` present, `Q_PATH` absent, the path and the query octets sealed together
//! under the pair key: [`QueryAsk::seal_inner`]). Anything between is refused. An answer is plain
//! (a [`Status`] as TLVs in the Content) or sealed (the same TLVs, [`Status::encode_inner`],
//! sealed under the pair key: `Q_SEQ` and `A_SEALED`).

use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_tlv::TlvWriter;

use super::{
    EpochId, WireError, each, once, only, read_array, read_epoch_id, read_name, read_nni, tlv,
    write_nni,
};
use crate::chan::wire::{S_CERT, need, take_cert, write_epoch_as, write_name_as};

/// `{ Q_SPACE, Q_PATH?, Q_ID, Q_DEADLINE, Q_BYTES, Q_SEAL?, Q_EPOCH?, Q_SEQ?, ASKER_CERT* }`: the
/// ApplicationParameters of a query.
pub(crate) const QUERY_ASK: u64 = 0x06C1;
/// Name: the space.
pub(crate) const Q_SPACE: u64 = 0x06C3;
/// Name: the asked path, relative to the space (a plain ask only).
pub(crate) const Q_PATH: u64 = 0x06C5;
/// 8 octets: the asker's query id, echoed by the answer.
pub(crate) const Q_ID: u64 = 0x06C7;
/// NonNegativeInteger: milliseconds, 1 to [`DEADLINE_MAX_MS`].
pub(crate) const Q_DEADLINE: u64 = 0x06C9;
/// The query octets (the ciphertext in a sealed ask).
pub(crate) const Q_BYTES: u64 = 0x06CB;
/// 32 octets: the asker's ephemeral X25519 key (a sealed ask only).
pub(crate) const Q_SEAL: u64 = 0x06CD;
/// The Content of the answering Data: `{ Q_ID, status fields | Q_SEQ + A_SEALED, S_CERT* }`.
pub(crate) const QUERY_ANSWER: u64 = 0x06CF;
/// NonNegativeInteger: 1 `Answered`, 2 `Refused`, 3 `NotServed`, 4 `TooLarge`.
pub(crate) const A_STATUS: u64 = 0x06D1;
/// The answer octets (`Answered`).
pub(crate) const A_BYTES: u64 = 0x06D3;
/// NonNegativeInteger: the application's code (`Refused`, at most 65,535) or the limit
/// (`TooLarge`).
pub(crate) const A_CODE: u64 = 0x06D5;
/// UTF-8, at most [`ANSWER_TEXT_MAX`] octets (`Refused`).
pub(crate) const A_TEXT: u64 = 0x06D7;
/// An EPOCH_ID value: the epoch of the pair key (a sealed ask only).
pub(crate) const Q_EPOCH: u64 = 0x06DB;
/// NonNegativeInteger: the sealing counter of the sender of the packet (the asker's in an ask,
/// the server's in an answer).
pub(crate) const Q_SEQ: u64 = 0x06DD;
/// The ciphertext of the status fields (a sealed answer only).
pub(crate) const A_SEALED: u64 = 0x06DF;

/// The most octets of a query's ApplicationParameters.
pub(crate) const QUERY_ASK_MAX: usize = 8 * 1024;
/// The most octets of the query a plain ask carries (and of the query inside a sealed one).
pub(crate) const QUERY_BYTES_MAX: usize = 2048;
/// The most octets of a path (the value of its `Name`).
pub(crate) const QUERY_PATH_MAX: usize = 255;
/// The most octets of the ciphertext of a sealed ask: the query, the path and the tag.
pub(crate) const QUERY_SEALED_MAX: usize = QUERY_BYTES_MAX + QUERY_PATH_MAX + 64;
/// The most octets of the answer a handler gives.
pub(crate) const ANSWER_BYTES_MAX: usize = 4096;
/// The most octets of a refusal's text.
pub(crate) const ANSWER_TEXT_MAX: usize = 256;
/// The most octets of the ciphertext of a sealed answer.
pub(crate) const ANSWER_SEALED_MAX: usize = ANSWER_BYTES_MAX + ANSWER_TEXT_MAX + 64;
/// The most octets of an answer's Content.
pub(crate) const ANSWER_CONTENT_MAX: usize = 8000;
/// The most milliseconds a query may be given.
pub(crate) const DEADLINE_MAX_MS: u32 = 10_000;
/// The octets of an AEAD tag: no ciphertext is shorter.
const TAG_LEN: usize = 16;

/// The octets of the value of `name`.
pub(crate) fn name_value_len(name: &Name) -> usize {
    let mut w = TlvWriter::new();
    for c in name.components() {
        w.write_tlv(c.typ, &c.value);
    }
    w.finish().len()
}

fn check_path(path: &Name, what: &'static str) -> Result<(), WireError> {
    let size = name_value_len(path);
    if size > QUERY_PATH_MAX {
        return Err(WireError::TooLarge {
            what,
            size,
            max: QUERY_PATH_MAX,
        });
    }
    Ok(())
}

fn check_chain(chain: &[Bytes], what: &'static str) -> Result<(), WireError> {
    let (mut taken, mut octets) = (Vec::new(), 0);
    for cert in chain {
        take_cert(&mut taken, &mut octets, cert.clone(), what)?;
    }
    Ok(())
}

// -- The ask -------------------------------------------------------------------------------------

/// What a sealed ask carries beside the query: the asker's ephemeral key, the epoch of the pair
/// key and the asker's counter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AskSeal {
    /// The asker's ephemeral X25519 key.
    pub ephemeral: [u8; 32],
    /// The epoch the pair key is bound to.
    pub epoch: EpochId,
    /// The asker's sealing counter: the nonce of the query, and of the answer under the other key.
    pub seq: u64,
}

/// What an asker asks a server: the ApplicationParameters of `<server>/32=query/<digest>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct QueryAsk {
    /// The space.
    pub space: Name,
    /// The asked path, relative to the space: present iff the ask is not sealed.
    pub path: Option<Name>,
    /// The asker's query id.
    pub id: [u8; 8],
    /// Milliseconds the asker waits, 1 to [`DEADLINE_MAX_MS`].
    pub deadline_ms: u32,
    /// The query octets; the ciphertext of [`QueryAsk::seal_inner`] when sealed.
    pub bytes: Bytes,
    /// Present iff the ask is sealed.
    pub seal: Option<AskSeal>,
    /// The certificates of the asker's signer chain, leaf first, each a whole Data.
    pub chain: Vec<Bytes>,
}

impl QueryAsk {
    /// The limits and the plain-or-sealed shape of an ask: what both ends of the wire refuse.
    fn check(&self) -> Result<(), WireError> {
        if !(1..=DEADLINE_MAX_MS).contains(&self.deadline_ms) {
            return Err(WireError::Malformed(
                "a query's deadline is 1 to 10,000 milliseconds; ask again with one in that range",
            ));
        }
        match (&self.seal, &self.path) {
            (Some(_), Some(_)) => {
                return Err(WireError::Malformed(
                    "a sealed query carries its path inside the sealed bytes: it has no Q_PATH",
                ));
            }
            (None, None) => return Err(WireError::Missing("a plain query's path")),
            (Some(_), None) => {
                let max = QUERY_SEALED_MAX;
                if self.bytes.len() > max || self.bytes.len() < TAG_LEN {
                    return Err(WireError::TooLarge {
                        what: "a sealed query's ciphertext",
                        size: self.bytes.len(),
                        max,
                    });
                }
            }
            (None, Some(path)) => {
                check_path(path, "a query's path")?;
                if self.bytes.len() > QUERY_BYTES_MAX {
                    return Err(WireError::TooLarge {
                        what: "a query's octets",
                        size: self.bytes.len(),
                        max: QUERY_BYTES_MAX,
                    });
                }
            }
        }
        check_chain(&self.chain, "the certificates a query carries")
    }

    /// The `QUERY_ASK` TLV; refused if the ask breaks a limit or is neither plain nor sealed.
    pub(crate) fn encode(&self) -> Result<Bytes, WireError> {
        self.check()?;
        let mut w = TlvWriter::new();
        w.write_nested(QUERY_ASK, |w| {
            write_name_as(w, Q_SPACE, &self.space);
            if let Some(path) = &self.path {
                write_name_as(w, Q_PATH, path);
            }
            w.write_tlv(Q_ID, &self.id);
            write_nni(w, Q_DEADLINE, u64::from(self.deadline_ms));
            w.write_tlv(Q_BYTES, &self.bytes);
            if let Some(seal) = &self.seal {
                w.write_tlv(Q_SEAL, &seal.ephemeral);
                write_epoch_as(w, Q_EPOCH, &seal.epoch);
                write_nni(w, Q_SEQ, seal.seq);
            }
            for cert in &self.chain {
                w.write_tlv(tlv::ASKER_CERT, cert);
            }
        });
        let wire = w.finish();
        if wire.len() > QUERY_ASK_MAX {
            return Err(WireError::TooLarge {
                what: "a query",
                size: wire.len(),
                max: QUERY_ASK_MAX,
            });
        }
        Ok(wire)
    }

    /// Decode a `QUERY_ASK` TLV of at most [`QUERY_ASK_MAX`] octets.
    pub(crate) fn decode(content: Bytes) -> Result<QueryAsk, WireError> {
        if content.len() > QUERY_ASK_MAX {
            return Err(WireError::TooLarge {
                what: "a query",
                size: content.len(),
                max: QUERY_ASK_MAX,
            });
        }
        let value = only(content, QUERY_ASK, "a query is one QUERY_ASK TLV")?;
        let (mut space, mut path, mut id, mut deadline) = (None, None, None, None);
        let (mut bytes, mut ephemeral, mut epoch, mut seq) = (None, None, None, None);
        let (mut chain, mut octets) = (Vec::new(), 0);
        each(value, |t, v| {
            match t {
                Q_SPACE => once(&mut space, read_name(v)?, "a query's space")?,
                Q_PATH => once(&mut path, read_name(v)?, "a query's path")?,
                Q_ID => once(
                    &mut id,
                    read_array::<8>(&v, "a query id is 8 octets")?,
                    "a query's id",
                )?,
                Q_DEADLINE => once(
                    &mut deadline,
                    u32::try_from(read_nni(&v)?).unwrap_or(0),
                    "a query's deadline",
                )?,
                Q_BYTES => once(&mut bytes, v, "a query's octets")?,
                Q_SEAL => once(
                    &mut ephemeral,
                    read_array::<32>(&v, "a query's ephemeral key is 32 octets")?,
                    "a query's ephemeral key",
                )?,
                Q_EPOCH => once(&mut epoch, read_epoch_id(v)?, "a query's epoch")?,
                Q_SEQ => once(&mut seq, read_nni(&v)?, "a query's counter")?,
                tlv::ASKER_CERT => take_cert(
                    &mut chain,
                    &mut octets,
                    v,
                    "the certificates a query carries",
                )?,
                _ => return Ok(false),
            }
            Ok(true)
        })?;
        let seal = match (ephemeral, epoch, seq) {
            (None, None, None) => None,
            (Some(ephemeral), Some(epoch), Some(seq)) => Some(AskSeal {
                ephemeral,
                epoch,
                seq,
            }),
            _ => {
                return Err(WireError::Malformed(
                    "a sealed query carries Q_SEAL, Q_EPOCH and Q_SEQ together; a plain one none",
                ));
            }
        };
        let ask = QueryAsk {
            space: need(space, "a query's space")?,
            path,
            id: need(id, "a query's id")?,
            deadline_ms: need(deadline, "a query's deadline")?,
            bytes: need(bytes, "a query's octets")?,
            seal,
            chain,
        };
        ask.check()?;
        Ok(ask)
    }

    /// The plaintext a sealed ask seals: `Q_PATH` and `Q_BYTES`. The caller keeps `path` to
    /// [`QUERY_PATH_MAX`] octets of name value and `bytes` to [`QUERY_BYTES_MAX`]:
    /// [`QueryAsk::open_inner`] refuses more.
    pub(crate) fn seal_inner(path: &Name, bytes: &[u8]) -> Bytes {
        debug_assert!(name_value_len(path) <= QUERY_PATH_MAX && bytes.len() <= QUERY_BYTES_MAX);
        let mut w = TlvWriter::new();
        write_name_as(&mut w, Q_PATH, path);
        w.write_tlv(Q_BYTES, bytes);
        w.finish()
    }

    /// The path and the query octets of an opened sealed ask ([`QueryAsk::seal_inner`]).
    pub(crate) fn open_inner(plaintext: Bytes) -> Result<(Name, Bytes), WireError> {
        let (mut path, mut bytes) = (None, None);
        each(plaintext, |t, v| {
            match t {
                Q_PATH => {
                    let path_name = read_name(v)?;
                    check_path(&path_name, "a query's path")?;
                    once(&mut path, path_name, "a query's path")?
                }
                Q_BYTES => {
                    if v.len() > QUERY_BYTES_MAX {
                        return Err(WireError::TooLarge {
                            what: "a query's octets",
                            size: v.len(),
                            max: QUERY_BYTES_MAX,
                        });
                    }
                    once(&mut bytes, v, "a query's octets")?
                }
                _ => return Ok(false),
            }
            Ok(true)
        })?;
        Ok((
            need(path, "a sealed query's path")?,
            need(bytes, "a sealed query's octets")?,
        ))
    }
}

// -- The answer ------------------------------------------------------------------------------------

/// What a server says to a query: the answer's status and what goes with it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Status {
    /// The handler answered (`A_STATUS` 1).
    Answered(Bytes),
    /// The handler refused, in the application's words (`A_STATUS` 2).
    Refused {
        /// The application's code.
        code: u16,
        /// Why, at most [`ANSWER_TEXT_MAX`] octets.
        text: String,
    },
    /// No prefix of the path is served here (`A_STATUS` 3).
    NotServed,
    /// The answer is over what fits; `max` is the limit (`A_STATUS` 4).
    TooLarge {
        /// The most octets an answer may carry.
        max: u64,
    },
}

/// The fields of a [`Status`], read as they come.
#[derive(Default)]
struct StatusParts {
    status: Option<u64>,
    bytes: Option<Bytes>,
    code: Option<u64>,
    text: Option<String>,
}

impl StatusParts {
    /// Take one TLV if it is a status field; `Ok(false)` for any other type.
    fn take(&mut self, typ: u64, v: Bytes) -> Result<bool, WireError> {
        match typ {
            A_STATUS => once(&mut self.status, read_nni(&v)?, "an answer's status")?,
            A_BYTES => {
                if v.len() > ANSWER_BYTES_MAX {
                    return Err(WireError::TooLarge {
                        what: "an answer's octets",
                        size: v.len(),
                        max: ANSWER_BYTES_MAX,
                    });
                }
                once(&mut self.bytes, v, "an answer's octets")?
            }
            A_CODE => once(&mut self.code, read_nni(&v)?, "an answer's code")?,
            A_TEXT => {
                if v.len() > ANSWER_TEXT_MAX {
                    return Err(WireError::TooLarge {
                        what: "an answer's text",
                        size: v.len(),
                        max: ANSWER_TEXT_MAX,
                    });
                }
                let text = String::from_utf8(v.to_vec())
                    .map_err(|_| WireError::Malformed("an answer's text is UTF-8"))?;
                once(&mut self.text, text, "an answer's text")?
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn none(&self) -> bool {
        self.status.is_none() && self.bytes.is_none() && self.code.is_none() && self.text.is_none()
    }

    /// The status the fields say: each status has its own fields and no others.
    fn finish(self) -> Result<Status, WireError> {
        const STRAY: WireError = WireError::Malformed(
            "an answer carries the fields of its status and no others (1 octets, 2 code and \
             text, 3 none, 4 the limit as code)",
        );
        let status = need(self.status, "an answer's status")?;
        match (status, self.bytes, self.code, self.text) {
            (1, Some(bytes), None, None) => Ok(Status::Answered(bytes)),
            (1, None, _, _) => Err(WireError::Missing("an answered status's octets")),
            (2, None, Some(code), Some(text)) => Ok(Status::Refused {
                code: u16::try_from(code)
                    .map_err(|_| WireError::Malformed("a refusal's code is a 16-bit number"))?,
                text,
            }),
            (2, None, None, _) => Err(WireError::Missing("a refusal's code")),
            (2, None, _, None) => Err(WireError::Missing("a refusal's text")),
            (3, None, None, None) => Ok(Status::NotServed),
            (4, None, Some(max), None) => Ok(Status::TooLarge { max }),
            (4, None, None, None) => Err(WireError::Missing("a too-large status's limit")),
            (1..=4, ..) => Err(STRAY),
            _ => Err(WireError::Malformed(
                "an answer's status is 1 (Answered), 2 (Refused), 3 (NotServed) or 4 (TooLarge)",
            )),
        }
    }
}

impl Status {
    /// A refusal of the application's: `text` is cut to [`ANSWER_TEXT_MAX`] octets at a character
    /// boundary.
    pub(crate) fn refused(code: u16, text: &str) -> Status {
        let mut end = text.len().min(ANSWER_TEXT_MAX);
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        Status::Refused {
            code,
            text: text[..end].to_owned(),
        }
    }

    /// Whether the status is one the wire carries: `Answered` octets within
    /// [`ANSWER_BYTES_MAX`] and a refusal's text within [`ANSWER_TEXT_MAX`]. A server turns what
    /// fails this into `TooLarge` or a cut text before it seals or encodes.
    pub(crate) fn check(&self) -> Result<(), WireError> {
        match self {
            Status::Answered(bytes) if bytes.len() > ANSWER_BYTES_MAX => Err(WireError::TooLarge {
                what: "an answer's octets",
                size: bytes.len(),
                max: ANSWER_BYTES_MAX,
            }),
            Status::Refused { text, .. } if text.len() > ANSWER_TEXT_MAX => {
                Err(WireError::TooLarge {
                    what: "an answer's text",
                    size: text.len(),
                    max: ANSWER_TEXT_MAX,
                })
            }
            _ => Ok(()),
        }
    }

    fn write(&self, w: &mut TlvWriter) {
        match self {
            Status::Answered(bytes) => {
                write_nni(w, A_STATUS, 1);
                w.write_tlv(A_BYTES, bytes);
            }
            Status::Refused { code, text } => {
                write_nni(w, A_STATUS, 2);
                write_nni(w, A_CODE, u64::from(*code));
                w.write_tlv(A_TEXT, text.as_bytes());
            }
            Status::NotServed => write_nni(w, A_STATUS, 3),
            Status::TooLarge { max } => {
                write_nni(w, A_STATUS, 4);
                write_nni(w, A_CODE, *max);
            }
        }
    }

    /// The status as a run of TLVs: what a plain answer carries beside `Q_ID`, and the plaintext
    /// of a sealed one. The caller keeps to [`Status::check`]; a decoder refuses more.
    pub(crate) fn encode_inner(&self) -> Bytes {
        debug_assert!(self.check().is_ok());
        let mut w = TlvWriter::new();
        self.write(&mut w);
        w.finish()
    }

    /// The status of a run of TLVs ([`Status::encode_inner`]).
    pub(crate) fn decode_inner(inner: Bytes) -> Result<Status, WireError> {
        let mut parts = StatusParts::default();
        each(inner, |t, v| parts.take(t, v))?;
        parts.finish()
    }
}

/// The body of an answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AnswerBody {
    /// The status in the clear.
    Plain(Status),
    /// The status sealed under the pair key.
    Sealed {
        /// The server's sealing counter: the nonce of this answer.
        seq: u64,
        /// The ciphertext of [`Status::encode_inner`].
        cipher: Bytes,
    },
}

/// What a server answers a query with: the Content of the Data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct QueryAnswer {
    /// The query's id, echoed.
    pub id: [u8; 8],
    /// The status, in the clear or sealed.
    pub body: AnswerBody,
    /// The certificates of the server's signer chain, leaf first, each a whole Data.
    pub certs: Vec<Bytes>,
}

impl QueryAnswer {
    /// The `QUERY_ANSWER` TLV; refused if it is over [`ANSWER_CONTENT_MAX`] octets or breaks a
    /// limit.
    pub(crate) fn encode(&self) -> Result<Bytes, WireError> {
        check_chain(&self.certs, "the certificates an answer carries")?;
        match &self.body {
            AnswerBody::Plain(status) => status.check()?,
            AnswerBody::Sealed { cipher, .. } => {
                if cipher.len() > ANSWER_SEALED_MAX || cipher.len() < TAG_LEN {
                    return Err(WireError::TooLarge {
                        what: "a sealed answer's ciphertext",
                        size: cipher.len(),
                        max: ANSWER_SEALED_MAX,
                    });
                }
            }
        }
        let mut w = TlvWriter::new();
        w.write_nested(QUERY_ANSWER, |w| {
            w.write_tlv(Q_ID, &self.id);
            match &self.body {
                AnswerBody::Plain(status) => status.write(w),
                AnswerBody::Sealed { seq, cipher } => {
                    write_nni(w, Q_SEQ, *seq);
                    w.write_tlv(A_SEALED, cipher);
                }
            }
            for cert in &self.certs {
                w.write_tlv(S_CERT, cert);
            }
        });
        let wire = w.finish();
        if wire.len() > ANSWER_CONTENT_MAX {
            return Err(WireError::TooLarge {
                what: "a query answer",
                size: wire.len(),
                max: ANSWER_CONTENT_MAX,
            });
        }
        Ok(wire)
    }

    /// Decode a `QUERY_ANSWER` TLV of at most [`ANSWER_CONTENT_MAX`] octets.
    pub(crate) fn decode(content: Bytes) -> Result<QueryAnswer, WireError> {
        if content.len() > ANSWER_CONTENT_MAX {
            return Err(WireError::TooLarge {
                what: "a query answer",
                size: content.len(),
                max: ANSWER_CONTENT_MAX,
            });
        }
        let value = only(content, QUERY_ANSWER, "an answer is one QUERY_ANSWER TLV")?;
        let (mut id, mut seq, mut sealed) = (None, None, None);
        let mut parts = StatusParts::default();
        let (mut certs, mut octets) = (Vec::new(), 0);
        each(value, |t, v| {
            match t {
                Q_ID => once(
                    &mut id,
                    read_array::<8>(&v, "a query id is 8 octets")?,
                    "an answer's id",
                )?,
                Q_SEQ => once(&mut seq, read_nni(&v)?, "an answer's counter")?,
                A_SEALED => {
                    if v.len() > ANSWER_SEALED_MAX || v.len() < TAG_LEN {
                        return Err(WireError::TooLarge {
                            what: "a sealed answer's ciphertext",
                            size: v.len(),
                            max: ANSWER_SEALED_MAX,
                        });
                    }
                    once(&mut sealed, v, "an answer's sealed part")?
                }
                S_CERT => take_cert(
                    &mut certs,
                    &mut octets,
                    v,
                    "the certificates an answer carries",
                )?,
                _ => return parts.take(t, v),
            }
            Ok(true)
        })?;
        let body = match (seq, sealed) {
            (None, None) => AnswerBody::Plain(parts.finish()?),
            (Some(seq), Some(cipher)) => {
                if !parts.none() {
                    return Err(WireError::Malformed(
                        "a sealed answer carries its status inside the sealed part, not beside it",
                    ));
                }
                AnswerBody::Sealed { seq, cipher }
            }
            _ => {
                return Err(WireError::Malformed(
                    "a sealed answer carries Q_SEQ and A_SEALED together; a plain one neither",
                ));
            }
        };
        Ok(QueryAnswer {
            id: need(id, "an answer's id")?,
            body,
            certs,
        })
    }
}

#[cfg(test)]
#[path = "query_tests.rs"]
mod tests;
