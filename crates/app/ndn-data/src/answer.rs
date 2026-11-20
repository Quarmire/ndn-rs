//! Answers: named, checkable readings over signed data (`docs/specs/answers.md`).
//!
//! An **answer** is the result of a definition or a function read over exact, signed versions,
//! published as one immutable packet `<D>/32=answer/<id>` signed by one device and sealed to the
//! readers of everything it read. This module holds its types and its bytes: the read set and
//! its digest ([`ReadSet`]), the binding ([`AnswerBinding`]), the question a reader asks
//! ([`AnswerAsk`]), the typed result of a `get` ([`Answered`], [`Provenance`]), the evaluators a
//! program brings ([`Evaluator`], [`Evaluators`]) and the host's policy ([`AnswerConfig`]). The
//! verbs and the checks are the [`Device`](crate::Device)'s.
//!
//! Every TLV of an answer is odd (critical): a decoder refuses an unknown TLV, a non-minimal
//! length, an unsorted or repeated read, so equal content has equal bytes and equal digests.

use std::collections::{BTreeSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_foundation_types::{Hash, Name, NameComponent, tlv_type};
use ndn_tlv::{TlvReader, TlvWriter};
use sha2::{Digest, Sha256};

use crate::collection::Epoch;
use crate::error::{AnswerRefusal, DataError, NextStep};
use crate::layer::{Age, Got};
use crate::version::{Parents, Writer};
use crate::wire::{
    self, INLINE_MAX, PAYLOAD_MAX, WireError, bad, parse_log_name, read_digest, read_name,
    read_nni, write_name, write_nni,
};

/// The most reads in one read set (answers.md §3.1).
pub const READS_MAX: usize = 65_536;
/// The most distinct epochs in one read set (answers.md §5.1).
pub const SEAL_EPOCHS_MAX: usize = 256;
/// The most octets of an [`AnswerAsk`] (answers.md §7.1).
pub const QUESTION_MAX: usize = 65_536;

/// TLV-TYPE numbers of answers (0x05C0–0x05DF, all odd but the two of the ask exchange: every
/// field changes what an answer means). Registered in `docs/specs/README.md`.
pub mod tlv {
    /// An answer's Content: `AnswerKind`, then one of `AnswerBody`; `AnswerSealed` with a
    /// `Ciphertext`; `Chunks`; `AnswerSealed` without a `Ciphertext`, then `Chunks`.
    pub const ANSWER_RECORD: u64 = 0x05C1;
    /// 0 pure, 1 provider (NonNegativeInteger).
    pub const ANSWER_KIND: u64 = 0x05C3;
    /// The plaintext: `AnswerBinding`, `ReadSet`, `Result`.
    pub const ANSWER_BODY: u64 = 0x05C5;
    /// `AnswerKind`, the definition (`ReadVersion` or `ReadState`, pure only), `AnswerBy`,
    /// `Digest` (the read-set digest).
    pub const ANSWER_BINDING: u64 = 0x05C7;
    /// A `Name`: the evaluator (pure) or the function (provider), full and versioned.
    pub const ANSWER_BY: u64 = 0x05C9;
    /// `(ReadVersion | ReadState)*`, in canonical order.
    pub const READ_SET: u64 = 0x05CB;
    /// `Name` (the version's log entry name), `Digest` (the implicit digest of its packet).
    pub const READ_VERSION: u64 = 0x05CD;
    /// `Name` (the merge collection), `Rule`, `Frontier` (every tip with its `Digest`), `Digest`
    /// (the applied-set digest).
    pub const READ_STATE: u64 = 0x05CF;
    /// The evaluator's or function's octets.
    pub const RESULT: u64 = 0x05D1;
    /// `SealEpoch+` in ascending order, then a `Ciphertext`: the `AnswerBody` and its
    /// `AnswerPadding`, sealed.
    pub const ANSWER_SEALED: u64 = 0x05D3;
    /// A question: `AnswerKind`, the definition (pure), `AnswerBy`, a `ReadSet` the asker
    /// states, if any. In a question's name only, never on a packet.
    pub const ANSWER_ASK: u64 = 0x05D5;
    /// A record of the device's own event store: the answer's name, the signer's key, the id,
    /// the read-set digest, an `AnswerFault`. Never on a packet.
    pub const ANSWER_EVIDENCE: u64 = 0x05D7;
    /// `FaultKind`, then by kind the digests and names of its evidence.
    pub const ANSWER_FAULT: u64 = 0x05D9;
    /// 0–8 (NonNegativeInteger).
    pub const FAULT_KIND: u64 = 0x05DB;
    /// Zero octets after the `AnswerBody`, inside a sealed answer's plaintext only: they make the
    /// plaintext the size of its bucket (answers.md §5.3).
    pub const ANSWER_PADDING: u64 = 0x05DD;
    /// An ask for an answer, the Interest's ApplicationParameters: the ephemeral key, the wrapped
    /// content key and the sealed body, as an introduction's ask carries them
    /// ([`AnswerAskEnvelope`](super::AnswerAskEnvelope)).
    pub const ANSWER_ASK_ENVELOPE: u64 = 0x05DE;
    /// A signer's refusal of an ask, the reply's Content: a reason code, a number and an
    /// explanation ([`AnswerAskRefusal`](super::AnswerAskRefusal)).
    pub const ANSWER_ASK_REFUSAL: u64 = 0x05DF;
}

/// The label of the read-set digest.
pub(crate) const LABEL_READSET: &[u8] = b"ndn-answer/1 readset\0";
/// The label of the applied-set digest.
pub(crate) const LABEL_APPLIED: &[u8] = b"ndn-answer/1 applied\0";
/// The label of an answer id.
pub(crate) const LABEL_ID: &[u8] = b"ndn-answer/1 id\0";
/// The label of a result digest.
pub(crate) const LABEL_RESULT: &[u8] = b"ndn-answer/1 result\0";
/// The label of the seal key.
pub(crate) const LABEL_SEAL: &[u8] = b"ndn-answer/1 seal\0";
/// The label of the name key.
pub(crate) const LABEL_NAME: &[u8] = b"ndn-answer/1 name\0";
/// The label of the AEAD's associated data.
pub(crate) const LABEL_AAD: &[u8] = b"ndn-answer/1 aad\0";

/// Which kind of answer: judged by recomputation (pure) or by the provider's authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AnswerKind {
    /// An evaluator and a definition are named: any holder of the definition and the inputs
    /// recomputes it.
    Pure,
    /// A function is named, no evaluator: only its provider computes it.
    Provider,
}

impl AnswerKind {
    pub(crate) fn code(self) -> u64 {
        match self {
            AnswerKind::Pure => 0,
            AnswerKind::Provider => 1,
        }
    }

    pub(crate) fn of_code(c: u64) -> Result<Self, WireError> {
        match c {
            0 => Ok(AnswerKind::Pure),
            1 => Ok(AnswerKind::Provider),
            _ => Err(bad("an answer is of kind 0 (pure) or 1 (provider)")),
        }
    }
}

// ---- strict TLV reading -------------------------------------------------------------------------

/// The TLVs of `value`, in order, none left out or skipped: an answer's records have no
/// non-critical TLVs.
struct Parts(VecDeque<(u64, Bytes)>);

impl Parts {
    fn of(value: Bytes) -> Result<Self, WireError> {
        let mut r = TlvReader::new(value);
        let mut all = VecDeque::new();
        while !r.is_empty() {
            all.push_back(r.read_tlv().map_err(|e| bad(format!("bad TLV: {e:?}")))?);
        }
        Ok(Parts(all))
    }

    /// The next TLV's value if it is of `typ`.
    fn next_if(&mut self, typ: u64) -> Option<Bytes> {
        if self.0.front().is_some_and(|(t, _)| *t == typ) {
            return self.0.pop_front().map(|(_, v)| v);
        }
        None
    }

    fn expect(&mut self, typ: u64, what: &str) -> Result<Bytes, WireError> {
        self.next_if(typ)
            .ok_or_else(|| bad(format!("expected {what}")))
    }

    fn end(&self) -> Result<(), WireError> {
        match self.0.front() {
            None => Ok(()),
            Some((t, _)) => Err(bad(format!(
                "an unexpected or misplaced TLV-TYPE {t:#x}: a decoder refuses an unknown TLV \
                 in an answer"
            ))),
        }
    }
}

/// The value of `tlv`, one TLV of type `typ` and nothing else.
fn unwrap_tlv(tlv: Bytes, typ: u64, what: &str) -> Result<Bytes, WireError> {
    let mut p = Parts::of(tlv)?;
    let v = p.expect(typ, what)?;
    p.end()?;
    Ok(v)
}

fn tlv_of(typ: u64, value: &[u8]) -> Bytes {
    let mut w = TlvWriter::new();
    w.write_tlv(typ, value);
    w.finish()
}

fn read_by(value: Bytes) -> Result<Name, WireError> {
    let mut p = Parts::of(value)?;
    let name = read_name(p.expect(tlv_type::NAME, "the evaluator's or function's name")?)?;
    p.end()?;
    Ok(name)
}

// ---- reads --------------------------------------------------------------------------------------

/// One read: one version, or one merge collection's state (answers.md §3.1).
///
/// The order is that of the octets of the read's TLV encoding, the canonical order of a
/// [`ReadSet`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ReadRef {
    /// One version: its log entry name `<D>/32=log/<C>/seq=<n>` and the implicit digest of its
    /// packet.
    Version {
        /// The version's name.
        name: Name,
        /// SHA-256 of the version's whole Data packet.
        digest: Hash,
    },
    /// A merge collection's state: the rule it was computed under (full name), the frontier
    /// with every tip's digest (never empty), and the applied-set digest (SHA-256 over
    /// `"ndn-answer/1 applied\0"` and the versions the state is computed from,
    /// [`applied_digest`]).
    State {
        /// The merge collection.
        collection: Name,
        /// The merge rule's full name.
        rule: Name,
        /// The frontier, each tip bound to its packet's digest.
        at: Parents,
        /// The applied-set digest.
        applied: Hash,
    },
}

impl ReadRef {
    /// The collection this read is of: a version's, parsed from its name.
    pub fn collection(&self) -> Result<Name, DataError> {
        match self {
            ReadRef::State { collection, .. } => Ok(collection.clone()),
            ReadRef::Version { name, .. } => parse_log_name(name)
                .and_then(|l| l.subject)
                .ok_or_else(|| DataError::BadName {
                    name: name.clone(),
                    why: "a read of a version names a log entry of a collection, \
                          <device>/32=log/<collection>/seq=<n>"
                        .into(),
                }),
        }
    }

    /// Its TLV: `ReadVersion` (0x05CD) or `ReadState` (0x05CF).
    pub fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        match self {
            ReadRef::Version { name, digest } => w.write_nested(tlv::READ_VERSION, |w| {
                write_name(w, name);
                w.write_tlv(wire::tlv::DIGEST, &digest.0);
            }),
            ReadRef::State {
                collection,
                rule,
                at,
                applied,
            } => w.write_nested(tlv::READ_STATE, |w| {
                write_name(w, collection);
                w.write_nested(wire::tlv::RULE, |w| {
                    write_nni(w, wire::tlv::RULE_KIND, 2);
                    write_name(w, rule);
                });
                wire::write_parents(w, at);
                w.write_tlv(wire::tlv::DIGEST, &applied.0);
            }),
        }
        w.finish()
    }

    /// Decode one read, exactly: minimal lengths, no unknown TLV, the bytes it encodes again.
    pub fn decode(tlv: Bytes) -> Result<Self, WireError> {
        let mut p = Parts::of(tlv.clone())?;
        let (typ, value) = p.0.pop_front().ok_or_else(|| bad("expected a read"))?;
        p.end()?;
        let read = Self::of_value(typ, value)?;
        if read.encode() != tlv {
            return Err(bad("a read is not in its minimal encoding"));
        }
        Ok(read)
    }

    fn of_value(typ: u64, value: Bytes) -> Result<Self, WireError> {
        let mut p = Parts::of(value)?;
        match typ {
            tlv::READ_VERSION => {
                let name = read_name(p.expect(tlv_type::NAME, "the version's name")?)?;
                let digest = Hash(read_digest(&p.expect(wire::tlv::DIGEST, "its digest")?)?);
                p.end()?;
                if parse_log_name(&name).is_none_or(|l| l.subject.is_none()) {
                    return Err(bad(
                        "a read of a version names a log entry of a collection, \
                         <device>/32=log/<collection>/seq=<n>",
                    ));
                }
                Ok(ReadRef::Version { name, digest })
            }
            tlv::READ_STATE => {
                let collection = read_name(p.expect(tlv_type::NAME, "the collection")?)?;
                let rule = {
                    let mut r = Parts::of(p.expect(wire::tlv::RULE, "the rule")?)?;
                    let kind = read_nni(&r.expect(wire::tlv::RULE_KIND, "the rule's kind")?)?;
                    let name = read_name(r.expect(tlv_type::NAME, "the rule's name")?)?;
                    r.end()?;
                    if kind != 2 {
                        return Err(bad("a state is read under a merge rule (kind 2)"));
                    }
                    name
                };
                let at = wire::read_parents(p.expect(wire::tlv::FRONTIER, "the frontier")?)?;
                let applied = Hash(read_digest(
                    &p.expect(wire::tlv::DIGEST, "the applied-set digest")?,
                )?);
                p.end()?;
                if at.is_empty() {
                    return Err(bad(
                        "a read of a collection whose frontier is empty is not a read",
                    ));
                }
                if at.tips().any(|(_, _, d)| d.is_none()) {
                    return Err(bad("every tip of a state read carries its digest"));
                }
                if !wire::is_collection_name(&collection) {
                    return Err(bad("a state read names a collection"));
                }
                Ok(ReadRef::State {
                    collection,
                    rule,
                    at,
                    applied,
                })
            }
            t => Err(bad(format!("expected a read, found TLV-TYPE {t:#x}"))),
        }
    }
}

impl PartialOrd for ReadRef {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ReadRef {
    /// The order of the octets of the TLV encodings.
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.encode().cmp(&other.encode())
    }
}

/// A read set: reads in canonical order, no repeats, at most one version per name and one state
/// per collection, at most [`READS_MAX`] reads (answers.md §3.1).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ReadSet(Vec<ReadRef>);

impl ReadSet {
    /// A read set of `reads`: sorted canonically, exact repeats made one. Refused: two reads of
    /// one version name with other digests, two states of one collection, more than
    /// [`READS_MAX`] reads or an encoding over `PAYLOAD_MAX` octets.
    pub fn new(reads: impl IntoIterator<Item = ReadRef>) -> Result<Self, AnswerRefusal> {
        let mut keyed: Vec<(Bytes, ReadRef)> = reads.into_iter().map(|r| (r.encode(), r)).collect();
        keyed.sort_by(|a, b| a.0.cmp(&b.0));
        keyed.dedup_by(|a, b| a.0 == b.0);
        let set = ReadSet(keyed.into_iter().map(|(_, r)| r).collect());
        set.check_shape()?;
        Ok(set)
    }

    fn check_shape(&self) -> Result<(), AnswerRefusal> {
        if self.0.len() > READS_MAX {
            return Err(AnswerRefusal::TooLarge {
                what: "the reads of one answer".into(),
                size: self.0.len() as u64,
                limit: READS_MAX as u64,
            });
        }
        let mut versions: BTreeSet<&Name> = BTreeSet::new();
        let mut states: BTreeSet<&Name> = BTreeSet::new();
        for r in &self.0 {
            let fresh = match r {
                ReadRef::Version { name, .. } => versions.insert(name),
                ReadRef::State { collection, .. } => states.insert(collection),
            };
            if !fresh {
                return Err(AnswerRefusal::ReadSet(match r {
                    ReadRef::Version { name, .. } => {
                        format!("two reads of the version {name} with different digests")
                    }
                    ReadRef::State { collection, .. } => {
                        format!("two reads of the state of {collection}")
                    }
                }));
            }
        }
        let size: usize = self.0.iter().map(|r| r.encode().len()).sum();
        if size as u64 > PAYLOAD_MAX {
            return Err(AnswerRefusal::TooLarge {
                what: "the read set's encoding".into(),
                size: size as u64,
                limit: PAYLOAD_MAX,
            });
        }
        Ok(())
    }

    /// The reads, in canonical order.
    pub fn reads(&self) -> &[ReadRef] {
        &self.0
    }

    /// Whether `r` is one of the reads.
    pub fn contains(&self, r: &ReadRef) -> bool {
        self.0.contains(r)
    }

    /// The one read of `collection`; `None` when there is none or several.
    pub fn current(&self, collection: &Name) -> Option<&ReadRef> {
        let mut of = self
            .0
            .iter()
            .filter(|r| r.collection().is_ok_and(|c| c == *collection));
        let one = of.next()?;
        of.next().is_none().then_some(one)
    }

    /// The `ReadSet` TLV (0x05CB): the reads' TLVs in canonical order.
    pub fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(tlv::READ_SET, |w| {
            for r in &self.0 {
                w.write_raw(&r.encode());
            }
        });
        w.finish()
    }

    /// Decode a `ReadSet` TLV, refusing what is not canonical: an unknown TLV, a non-minimal
    /// length, an unsorted or repeated read, two reads of one version or state, too many reads.
    pub fn decode(tlv: Bytes) -> Result<Self, AnswerRefusal> {
        let malformed = |e: WireError| AnswerRefusal::Malformed(e.0);
        let body = unwrap_tlv(tlv.clone(), tlv::READ_SET, "a ReadSet").map_err(malformed)?;
        let mut reads: Vec<ReadRef> = Vec::new();
        let mut p = Parts::of(body).map_err(malformed)?;
        while let Some((typ, value)) = p.0.pop_front() {
            if reads.len() >= READS_MAX {
                return Err(AnswerRefusal::TooLarge {
                    what: "the reads of one answer".into(),
                    size: reads.len() as u64 + 1,
                    limit: READS_MAX as u64,
                });
            }
            reads.push(ReadRef::of_value(typ, value).map_err(malformed)?);
        }
        let set = ReadSet(reads);
        for pair in set.0.windows(2) {
            let (a, b) = (pair[0].encode(), pair[1].encode());
            if a >= b {
                return Err(AnswerRefusal::ReadSet(
                    "not canonical: the reads are not in strictly ascending order of their \
                     encodings (unsorted or repeated)"
                        .into(),
                ));
            }
        }
        set.check_shape()?;
        if set.encode() != tlv {
            return Err(AnswerRefusal::ReadSet(
                "not canonical: a length or a read is not in its minimal encoding".into(),
            ));
        }
        Ok(set)
    }

    /// SHA-256 over `"ndn-answer/1 readset\0"` and the `ReadSet` TLV as it is on the wire.
    pub fn digest(&self) -> Hash {
        let mut h = Sha256::new();
        h.update(LABEL_READSET);
        h.update(self.encode());
        Hash(h.finalize().into())
    }
}

/// The applied-set digest of a state (answers.md §3.1): SHA-256 over `"ndn-answer/1 applied\0"`
/// and, for every version the state is computed from, in ascending order of the octets of the
/// writer's key Name TLV and then of seq, the writer's Name TLV, the seq as 8 octets big-endian
/// and the version's implicit digest.
pub fn applied_digest(versions: impl IntoIterator<Item = (Writer, u64, [u8; 32])>) -> Hash {
    let mut all: Vec<(Bytes, u64, [u8; 32])> = versions
        .into_iter()
        .map(|(w, s, d)| (w.key().encode_to_tlv(), s, d))
        .collect();
    all.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    let mut h = Sha256::new();
    h.update(LABEL_APPLIED);
    for (writer, seq, digest) in &all {
        h.update(writer);
        h.update(seq.to_be_bytes());
        h.update(digest);
    }
    Hash(h.finalize().into())
}

// ---- the binding, the question, the result -----------------------------------------------------

/// What an answer is an answer to (answers.md §3.2): its kind, its definition (pure), its
/// evaluator or function, and the digest of its read set.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AnswerBinding {
    /// Pure or provider.
    pub kind: AnswerKind,
    /// Pure only: the definition's exact read; MUST be one of the read set's reads.
    pub definition: Option<ReadRef>,
    /// The evaluator (pure) or the function (provider): full, versioned, matched exactly.
    pub by: Name,
    /// [`ReadSet::digest`].
    pub reads: Hash,
}

impl AnswerBinding {
    /// The `AnswerBinding` TLV (0x05C7).
    pub fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(tlv::ANSWER_BINDING, |w| {
            write_nni(w, tlv::ANSWER_KIND, self.kind.code());
            if let Some(d) = &self.definition {
                w.write_raw(&d.encode());
            }
            w.write_nested(tlv::ANSWER_BY, |w| write_name(w, &self.by));
            w.write_tlv(wire::tlv::DIGEST, &self.reads.0);
        });
        w.finish()
    }

    /// Decode an `AnswerBinding` TLV exactly.
    pub fn decode(tlv: Bytes) -> Result<Self, WireError> {
        let value = unwrap_tlv(tlv.clone(), tlv::ANSWER_BINDING, "an AnswerBinding")?;
        let mut p = Parts::of(value)?;
        let kind = AnswerKind::of_code(read_nni(&p.expect(tlv::ANSWER_KIND, "the kind")?)?)?;
        let definition = match p.0.front().map(|(t, _)| *t) {
            Some(t @ (tlv::READ_VERSION | tlv::READ_STATE)) => {
                let (_, v) = p.0.pop_front().expect("just seen");
                Some(ReadRef::of_value(t, v)?)
            }
            _ => None,
        };
        let by = read_by(p.expect(tlv::ANSWER_BY, "the evaluator or function")?)?;
        let reads = Hash(read_digest(
            &p.expect(wire::tlv::DIGEST, "the read-set digest")?,
        )?);
        p.end()?;
        if definition.is_some() != (kind == AnswerKind::Pure) {
            return Err(bad(
                "a pure answer's binding names its definition and a provider answer's does not",
            ));
        }
        let b = AnswerBinding {
            kind,
            definition,
            by,
            reads,
        };
        if b.encode() != tlv {
            return Err(bad("a binding is not in its minimal encoding"));
        }
        Ok(b)
    }
}

/// What is asked: the value of a question name `<X>/32=question/<AnswerAsk>` (answers.md §7.1).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AnswerAsk {
    /// Pure or provider.
    pub kind: AnswerKind,
    /// Pure only: the exact definition the asker means.
    pub definition: Option<ReadRef>,
    /// The evaluator (pure) or function (provider).
    pub by: Name,
    /// Provider: required, the inputs. Pure: `Some` when the asker states the reads, `None` to
    /// have them planned.
    pub reads: Option<ReadSet>,
}

impl AnswerAsk {
    /// A pure question: the answer of `definition` under `evaluator`, its reads planned from
    /// what this device holds.
    pub fn pure(definition: ReadRef, evaluator: Name) -> Self {
        AnswerAsk {
            kind: AnswerKind::Pure,
            definition: Some(definition),
            by: evaluator,
            reads: None,
        }
    }

    /// A provider question: the answer of `function` over exactly `inputs`.
    pub fn provider(function: Name, inputs: ReadSet) -> Self {
        AnswerAsk {
            kind: AnswerKind::Provider,
            definition: None,
            by: function,
            reads: Some(inputs),
        }
    }

    /// This question, stating the reads: it names an answer without evaluating.
    pub fn stating(mut self, reads: ReadSet) -> Self {
        self.reads = Some(reads);
        self
    }

    /// The `AnswerAsk` TLV (0x05D5).
    pub fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(tlv::ANSWER_ASK, |w| {
            write_nni(w, tlv::ANSWER_KIND, self.kind.code());
            if let Some(d) = &self.definition {
                w.write_raw(&d.encode());
            }
            w.write_nested(tlv::ANSWER_BY, |w| write_name(w, &self.by));
            if let Some(r) = &self.reads {
                w.write_raw(&r.encode());
            }
        });
        w.finish()
    }

    /// Decode one `AnswerAsk` TLV, exactly.
    pub fn decode(tlv: Bytes) -> Result<Self, WireError> {
        let value = unwrap_tlv(tlv.clone(), tlv::ANSWER_ASK, "an AnswerAsk")?;
        let mut p = Parts::of(value)?;
        let kind = AnswerKind::of_code(read_nni(&p.expect(tlv::ANSWER_KIND, "the kind")?)?)?;
        let definition = match p.0.front().map(|(t, _)| *t) {
            Some(t @ (tlv::READ_VERSION | tlv::READ_STATE)) => {
                let (_, v) = p.0.pop_front().expect("just seen");
                Some(ReadRef::of_value(t, v)?)
            }
            _ => None,
        };
        let by = read_by(p.expect(tlv::ANSWER_BY, "the evaluator or function")?)?;
        let reads = match p.next_if(tlv::READ_SET) {
            Some(v) => {
                let whole = tlv_of(tlv::READ_SET, &v);
                Some(ReadSet::decode(whole).map_err(|e| bad(e.to_string()))?)
            }
            None => None,
        };
        p.end()?;
        if definition.is_some() != (kind == AnswerKind::Pure) {
            return Err(bad(
                "a pure question names its definition and a provider question does not",
            ));
        }
        if kind == AnswerKind::Provider && reads.is_none() {
            return Err(bad("a provider question states the inputs it asks about"));
        }
        let ask = AnswerAsk {
            kind,
            definition,
            by,
            reads,
        };
        if ask.encode() != tlv {
            return Err(bad("a question is not in its minimal encoding"));
        }
        Ok(ask)
    }

    /// The question's name, `<X>/32=question/<AnswerAsk TLV>`: `X` is the definition's
    /// collection (pure) or `provider`, the provider device asked (required for a provider
    /// question, refused for a pure one).
    pub fn name(&self, provider: Option<&Name>) -> Result<Name, DataError> {
        let bad_request = |why: String| DataError::BadRequest {
            name: self.by.clone(),
            why,
        };
        let x = match (self.kind, provider) {
            (AnswerKind::Pure, None) => self
                .definition
                .as_ref()
                .ok_or_else(|| bad_request("a pure question names its definition".into()))?
                .collection()?,
            (AnswerKind::Pure, Some(_)) => {
                return Err(bad_request(
                    "a pure question is asked of the definition's collection, never of a \
                     provider device: give no provider"
                        .into(),
                ));
            }
            (AnswerKind::Provider, Some(p)) => {
                if !wire::is_device_name(p) {
                    return Err(bad_request(format!(
                        "{p} is not a device name; a provider question is asked of the \
                         provider device, <namespace>/<device>"
                    )));
                }
                p.clone()
            }
            (AnswerKind::Provider, None) => {
                return Err(bad_request(
                    "a provider question names the provider device it asks of: give it".into(),
                ));
            }
        };
        let name = wire::question_name(&x, self);
        let size = self.encode().len();
        if size > QUESTION_MAX {
            return Err(DataError::Answer {
                name,
                why: AnswerRefusal::TooLarge {
                    what: "the question".into(),
                    size: size as u64,
                    limit: QUESTION_MAX as u64,
                },
            });
        }
        Ok(name)
    }

    /// Parse a question name; `BadName` says how a question is formed.
    pub fn parse(name: &Name) -> Result<Self, DataError> {
        Self::parse_with_x(name).map(|(_, ask)| ask)
    }

    /// [`Self::parse`], and `X`: the definition's collection, or the provider device.
    pub(crate) fn parse_with_x(name: &Name) -> Result<(Name, Self), DataError> {
        let bad_name = |why: String| DataError::BadName {
            name: name.clone(),
            why: format!(
                "{why}; a question is <X>/32=question/<AnswerAsk>, one generic component holding \
                 one AnswerAsk, X the definition's collection (pure) or the provider device \
                 (provider); build it with AnswerAsk::name"
            ),
        };
        let (x, ask) = match wire::parse_question_name(name) {
            None => return Err(bad_name("it has no 32=question component".into())),
            Some(Err(e)) => return Err(bad_name(e.0)),
            Some(Ok(parsed)) => parsed,
        };
        match ask.kind {
            AnswerKind::Pure => {
                if !wire::is_collection_name(&x) {
                    return Err(bad_name(format!(
                        "{x} is not a collection, and a pure question is asked of its \
                         definition's collection"
                    )));
                }
                let of = ask
                    .definition
                    .as_ref()
                    .expect("a decoded pure question has its definition")
                    .collection()?;
                if of != x {
                    return Err(bad_name(format!("its definition is of {of}, not of {x}")));
                }
            }
            AnswerKind::Provider => {
                if !wire::is_device_name(&x) {
                    return Err(bad_name(format!(
                        "{x} is not a device, and a provider question is asked of the provider \
                         device"
                    )));
                }
            }
        }
        Ok((x, ask))
    }
}

// ---- the record ----------------------------------------------------------------------------------

/// The plaintext of an answer (answers.md §3.4): the binding, the read set and the result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Body {
    pub(crate) binding: AnswerBinding,
    pub(crate) reads: ReadSet,
    pub(crate) result: Bytes,
}

impl Body {
    /// The `AnswerBody` TLV (0x05C5).
    pub(crate) fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(tlv::ANSWER_BODY, |w| {
            w.write_raw(&self.binding.encode());
            w.write_raw(&self.reads.encode());
            w.write_tlv(tlv::RESULT, &self.result);
        });
        w.finish()
    }

    pub(crate) fn decode(tlv: Bytes) -> Result<Self, AnswerRefusal> {
        let malformed = |e: WireError| AnswerRefusal::Malformed(e.0);
        let value =
            unwrap_tlv(tlv.clone(), tlv::ANSWER_BODY, "an AnswerBody").map_err(malformed)?;
        let mut p = Parts::of(value).map_err(malformed)?;
        let binding = p
            .expect(tlv::ANSWER_BINDING, "the binding")
            .map_err(malformed)?;
        let binding =
            AnswerBinding::decode(tlv_of(tlv::ANSWER_BINDING, &binding)).map_err(malformed)?;
        let reads = p.expect(tlv::READ_SET, "the read set").map_err(malformed)?;
        let reads = ReadSet::decode(tlv_of(tlv::READ_SET, &reads))?;
        let result = p.expect(tlv::RESULT, "the result").map_err(malformed)?;
        p.end().map_err(malformed)?;
        let body = Body {
            binding,
            reads,
            result,
        };
        if body.encode() != tlv {
            return Err(AnswerRefusal::Malformed(
                "an answer body is not in its minimal encoding".into(),
            ));
        }
        Ok(body)
    }
}

// ---- padding a sealed body -----------------------------------------------------------------------

/// A sealed answer's plaintext grows in steps of this many octets up to [`PAD_LINEAR_MAX`].
const PAD_STEP: usize = 128;
/// Above this many octets the steps are an eighth of the plaintext's power of two (answers.md
/// §13.3), so the padding is at most 12.5% of the body.
const PAD_LINEAR_MAX: usize = 1024;

/// The octets of `x` as a TLV-TYPE or TLV-LENGTH number.
fn number_len(x: usize) -> usize {
    match x {
        0..=252 => 1,
        253..=0xFFFF => 3,
        0x1_0000..=0xFFFF_FFFF => 5,
        _ => 9,
    }
}

/// The octets of the `AnswerPadding` TLV with exactly `total` octets, as its value's length; none
/// when there is no such element: the length number takes 1, 3 or 5 octets, so no element is of
/// 1 to 3 octets, of 257 or 258 or of 65,542 or 65,543.
fn padding_value_len(total: usize) -> Option<usize> {
    [1, 3, 5, 9].into_iter().find_map(|length| {
        let value = total.checked_sub(number_len(tlv::ANSWER_PADDING as usize) + length)?;
        (number_len(value) == length).then_some(value)
    })
}

/// The least size of a bucket that holds `n` octets (answers.md §13.3).
fn bucket_at_least(n: usize) -> usize {
    let step = match n <= PAD_LINEAR_MAX {
        true => PAD_STEP,
        false => 1 << (n.ilog2() - 3),
    };
    n.div_ceil(step).max(1) * step
}

/// The size a sealed answer's plaintext has when its `AnswerBody` is `n` octets: the least bucket
/// that is `n` itself or leaves room for an `AnswerPadding` element (answers.md §13.3). Buckets are
/// the multiples of 128 octets up to 1,024 and above that the multiples of an eighth of the
/// plaintext's power of two. A bucket that would leave a gap no element fills (1 to 3 octets, 257
/// or 258, 65,542 or 65,543) is passed over for the next.
pub(crate) fn padded_len(n: usize) -> usize {
    let mut size = bucket_at_least(n);
    while size != n && padding_value_len(size - n).is_none() {
        size = bucket_at_least(size + 1);
    }
    size
}

/// `body` (an `AnswerBody` TLV) followed by the `AnswerPadding` that makes it [`padded_len`]
/// octets: zeros, none when the body is that size already.
pub(crate) fn pad_body(body: &Bytes) -> Vec<u8> {
    let size = padded_len(body.len());
    let mut out = Vec::with_capacity(size);
    out.extend_from_slice(body);
    if size > body.len() {
        let zeros = padding_value_len(size - body.len()).expect("padded_len leaves room");
        let mut w = TlvWriter::new();
        w.write_varu64(tlv::ANSWER_PADDING);
        w.write_varu64(zeros as u64);
        out.extend_from_slice(&w.finish());
        out.resize(size, 0);
    }
    out
}

/// The `AnswerBody` of a sealed answer's decrypted plaintext, which MUST be that body and the one
/// `AnswerPadding` of zeros [`pad_body`] makes of it: padding that is missing, not last, repeated,
/// not of the length it is due, not minimally encoded or not zero is refused.
pub(crate) fn unpad_body(plain: Bytes) -> Result<Bytes, AnswerRefusal> {
    let refuse = |why: String| {
        AnswerRefusal::Malformed(format!(
            "{why}; a signer pads a sealed answer as answers.md §13.3 says, so this packet is \
             not a conforming answer: ask another holder of it"
        ))
    };
    let mut r = TlvReader::new(plain.clone());
    let (typ, _) = r
        .read_tlv()
        .map_err(|e| refuse(format!("its sealed body does not start with a TLV: {e:?}")))?;
    if typ == tlv::ANSWER_PADDING {
        return Err(refuse(
            "its AnswerPadding comes before its AnswerBody; the padding is last".into(),
        ));
    }
    if typ != tlv::ANSWER_BODY {
        return Err(refuse(format!(
            "its sealed body starts with TLV-TYPE {typ:#x}, not an AnswerBody"
        )));
    }
    let end = r.position();
    let body = plain.slice(..end);
    let due = padded_len(end);
    if r.is_empty() {
        return match due == end {
            true => Ok(body),
            false => Err(refuse(format!(
                "its AnswerBody of {end} octets has no AnswerPadding, and is due one up to {due} \
                 octets"
            ))),
        };
    }
    let (typ, zeros) = r
        .read_tlv()
        .map_err(|e| refuse(format!("its AnswerPadding is not a well-formed TLV: {e:?}")))?;
    if typ != tlv::ANSWER_PADDING {
        return Err(refuse(format!(
            "TLV-TYPE {typ:#x} follows its AnswerBody; only one AnswerPadding does"
        )));
    }
    if !r.is_empty() {
        return Err(refuse(
            "more follows its AnswerPadding; the padding is one TLV, the last".into(),
        ));
    }
    if due == end {
        return Err(refuse(format!(
            "its AnswerBody of {end} octets is a bucket already, and no AnswerPadding is due"
        )));
    }
    if plain.len() != due || Some(zeros.len()) != padding_value_len(due - end) {
        return Err(refuse(format!(
            "its AnswerBody of {end} octets has an AnswerPadding that makes it {} octets, not the \
             {due} octets of its bucket, or does not encode it minimally",
            plain.len()
        )));
    }
    if zeros.iter().any(|b| *b != 0) {
        return Err(refuse(
            "its AnswerPadding carries non-zero octets; padding is zeros and carries nothing"
                .into(),
        ));
    }
    Ok(body)
}

/// What an answer's content carries after its kind (answers.md §3.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Content {
    /// No sealed read, one packet: the `AnswerBody` TLV.
    Plain(Bytes),
    /// Sealed, one packet: the epochs and the ciphertext of the body.
    Sealed {
        epochs: Vec<Epoch>,
        ciphertext: Bytes,
    },
    /// In pieces: the size of the body (or its ciphertext) and the digest of the root node;
    /// `epochs` when sealed.
    Pieces {
        epochs: Option<Vec<Epoch>>,
        size: u64,
        root: [u8; 32],
    },
}

/// The Content of an answer packet, an `AnswerRecord` (0x05C1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Record {
    pub(crate) kind: AnswerKind,
    pub(crate) content: Content,
}

/// Epochs in the order of §5.1: the octets of the creator's Name TLV, then seq.
pub(crate) fn epoch_order(a: &Epoch, b: &Epoch) -> std::cmp::Ordering {
    a.creator
        .encode_to_tlv()
        .cmp(&b.creator.encode_to_tlv())
        .then(a.seq.cmp(&b.seq))
}

fn check_epochs(epochs: &[Epoch]) -> Result<(), WireError> {
    if epochs.is_empty() {
        return Err(bad("a sealed answer names the epochs it reads in"));
    }
    if epochs.len() > SEAL_EPOCHS_MAX {
        return Err(bad(format!(
            "an answer reads in at most {SEAL_EPOCHS_MAX} epochs, this one in {}",
            epochs.len()
        )));
    }
    if epochs
        .windows(2)
        .any(|w| epoch_order(&w[0], &w[1]) != std::cmp::Ordering::Less)
    {
        return Err(bad("the epochs of an answer are strictly ascending"));
    }
    Ok(())
}

impl Record {
    pub(crate) fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(tlv::ANSWER_RECORD, |w| {
            write_nni(w, tlv::ANSWER_KIND, self.kind.code());
            match &self.content {
                Content::Plain(body) => w.write_raw(body),
                Content::Sealed { epochs, ciphertext } => w.write_nested(tlv::ANSWER_SEALED, |w| {
                    for e in epochs {
                        wire::write_epoch(w, e);
                    }
                    w.write_tlv(wire::tlv::CIPHERTEXT, ciphertext);
                }),
                Content::Pieces { epochs, size, root } => {
                    if let Some(epochs) = epochs {
                        w.write_nested(tlv::ANSWER_SEALED, |w| {
                            for e in epochs {
                                wire::write_epoch(w, e);
                            }
                        });
                    }
                    w.write_nested(wire::tlv::CHUNKS, |w| {
                        write_nni(w, wire::tlv::SIZE, *size);
                        w.write_tlv(wire::tlv::DIGEST, root);
                    });
                }
            }
        });
        w.finish()
    }

    pub(crate) fn decode(tlv: Bytes) -> Result<Self, WireError> {
        let value = unwrap_tlv(tlv.clone(), tlv::ANSWER_RECORD, "an AnswerRecord")?;
        let mut p = Parts::of(value)?;
        let kind = AnswerKind::of_code(read_nni(&p.expect(tlv::ANSWER_KIND, "the kind")?)?)?;
        let epochs_of = |v: Bytes| -> Result<(Vec<Epoch>, Option<Bytes>), WireError> {
            let mut q = Parts::of(v)?;
            let mut epochs = Vec::new();
            while let Some(e) = q.next_if(wire::tlv::SEAL_EPOCH) {
                epochs.push(wire::read_epoch(e)?);
            }
            let ct = q.next_if(wire::tlv::CIPHERTEXT);
            q.end()?;
            check_epochs(&epochs)?;
            Ok((epochs, ct))
        };
        let chunks_of = |v: Bytes| -> Result<(u64, [u8; 32]), WireError> {
            let mut q = Parts::of(v)?;
            let size = read_nni(&q.expect(wire::tlv::SIZE, "its size")?)?;
            let root = read_digest(&q.expect(wire::tlv::DIGEST, "its root digest")?)?;
            q.end()?;
            if size <= INLINE_MAX as u64 {
                return Err(bad(format!(
                    "a body of {size} octets travels in its packet, not in pieces"
                )));
            }
            if size > PAYLOAD_MAX {
                return Err(bad(format!(
                    "a body of {size} octets is larger than the {PAYLOAD_MAX} an answer carries"
                )));
            }
            Ok((size, root))
        };
        let content = match p.0.front().map(|(t, _)| *t) {
            Some(tlv::ANSWER_BODY) => {
                let (_, v) = p.0.pop_front().expect("just seen");
                Content::Plain(tlv_of(tlv::ANSWER_BODY, &v))
            }
            Some(tlv::ANSWER_SEALED) => {
                let (_, v) = p.0.pop_front().expect("just seen");
                let (epochs, ct) = epochs_of(v)?;
                match (ct, p.next_if(wire::tlv::CHUNKS)) {
                    (Some(ciphertext), None) => Content::Sealed { epochs, ciphertext },
                    (None, Some(c)) => {
                        let (size, root) = chunks_of(c)?;
                        Content::Pieces {
                            epochs: Some(epochs),
                            size,
                            root,
                        }
                    }
                    _ => {
                        return Err(bad(
                            "a sealed answer carries its ciphertext, or, with none, its pieces",
                        ));
                    }
                }
            }
            Some(wire::tlv::CHUNKS) => {
                let (_, v) = p.0.pop_front().expect("just seen");
                let (size, root) = chunks_of(v)?;
                Content::Pieces {
                    epochs: None,
                    size,
                    root,
                }
            }
            _ => return Err(bad("an answer carries a body, a sealed body or pieces")),
        };
        p.end()?;
        let rec = Record { kind, content };
        if rec.encode() != tlv {
            return Err(bad("an answer record is not in its minimal encoding"));
        }
        Ok(rec)
    }
}

// ---- what a get returns --------------------------------------------------------------------------

/// The result of a `get` of a question or an exact answer name (answers.md §7.4). The same type
/// whether the answer was recomputed here, found in this device's store or fetched: [`how`]
/// tells how, and is information, never a different shape.
///
/// [`how`]: Answered::how
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Answered {
    /// The exact answer name used: `<D>/32=answer/<id>`, the signed answer's or, when computed
    /// here, the one this device's own signature gives or would give.
    pub name: Name,
    /// The answer id (answers.md §3.2).
    pub id: Hash,
    /// Pure or provider.
    pub kind: AnswerKind,
    /// What it answers.
    pub binding: AnswerBinding,
    /// What it read: always present, the answer is opened.
    pub reads: ReadSet,
    /// The evaluator's or function's octets, canonical.
    pub result: Bytes,
    /// Its digest (answers.md §3.4), keyed when anything read is sealed.
    pub result_digest: Hash,
    /// How it was obtained.
    pub how: Provenance,
}

/// How an answer was obtained (answers.md §7.3).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Provenance {
    /// This device ran the evaluator over exactly the read set. `confirmed_by`: signers of
    /// verified answers whose result digest equals the recomputed one; `disagreed_with`: signers
    /// of those that differ, each of them evidence. Both empty: nobody had answered.
    Recomputed {
        /// Signers whose answers equal this device's.
        confirmed_by: Vec<Writer>,
        /// Signers whose answers differ: evidence.
        disagreed_with: Vec<Writer>,
    },
    /// A signed answer taken on trust: the evaluator is unknown here, or the policy lists it in
    /// `trust`, and `signer` is trusted for pure answers. `unverified_reads`: the reads this
    /// device did not hold, so did not check.
    Trusted {
        /// Who signed it.
        signer: Writer,
        /// How many reads were not held here.
        unverified_reads: u32,
    },
    /// A provider answer from a signer the policy names for the function.
    Provider {
        /// Who signed it.
        signer: Writer,
        /// How many reads were not held here.
        unverified_reads: u32,
    },
}

// ---- evaluators ---------------------------------------------------------------------------------

/// The definition an evaluator is given: its exact read and what it opened to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Definition {
    /// The read of the definition, one of the read set's reads.
    pub reference: ReadRef,
    /// What it opened to: [`Got::Version`] or [`Got::State`].
    pub got: Got,
}

/// Why an evaluation fails.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum EvalError {
    /// The definition or an input is not one this evaluator takes: a pure function of them,
    /// the same on every device. The text is shown to an asker the signer refused, as the
    /// evaluator's own words ([`AskRefusal::EvaluatorRefused`], answers.md §15.6): say what is
    /// wrong with the definition and how to fix it, in at most 512 characters, and never put the
    /// contents of an input in it (the reply is not sealed, and a plan's inputs are judged against
    /// the asker's audience after the plan).
    #[error("{0}")]
    Refused(String),
    /// A read outside the read set, or a read of the set that is never used (a recompute only).
    #[error("the reads are not this evaluator's reading of its definition: {0}")]
    NotItsReads(String),
}

/// Why a plan fails: a read the layer refuses, or the evaluator.
#[derive(Debug, thiserror::Error)]
pub enum PlanError {
    /// A read the layer refuses: the error `get` of it answers.
    #[error(transparent)]
    Data(#[from] DataError),
    /// The evaluator refuses its definition or its inputs.
    #[error(transparent)]
    Eval(#[from] EvalError),
}

/// The planning phase's reads (answers.md §4.1). Every read is of a version or state this
/// device holds verified (fetching, asking for keys and opening sealed versions as `get` does),
/// so an unsigned input cannot be named. In a recompute it serves exactly the read set.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait Reads: Send {
    /// The newest this device holds of `collection`, as an exact read (a merge collection: its
    /// state; a log or one-key collection: its newest version), and how old it may be. Records
    /// nothing. In a recompute: the set's one read of the collection
    /// ([`EvalError::NotItsReads`] as a [`DataError::BadRequest`] if none or many).
    async fn current(&mut self, collection: &Name) -> Result<(ReadRef, Age), DataError>;

    /// Read exactly `r` and record it. The error is the one `get` of it answers (`Sealed`,
    /// `NotReady`, `Unavailable`, `Refused`, `Pruned`, `Expired`, `RuleUnknown`).
    async fn read(&mut self, r: &ReadRef) -> Result<Got, DataError>;
}

/// The evaluation phase's reads: fully fetched, in memory, no I/O.
pub trait ReadView {
    /// The read set's one read of `collection`.
    fn current(&self, collection: &Name) -> Result<&ReadRef, EvalError>;
    /// What `r` opened to; `r` MUST be a read of the set.
    fn read(&self, r: &ReadRef) -> Result<&Got, EvalError>;
    /// Whether this evaluation is over its time ([`Budget::time`]): it is abandoned and its
    /// result will not be used, so an evaluator that runs long checks this between its steps
    /// and returns early (with any error).
    fn cancelled(&self) -> bool {
        false
    }
}

/// A named, versioned pure function of a definition and the contents of a read set
/// (answers.md §4.1). Brought by the program, like a merge rule.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait Evaluator: Send + Sync {
    /// Its full, versioned name, e.g. `/ndf/eval/v=3`; matched exactly, never by prefix. A
    /// change of meaning is a new name.
    fn evaluator(&self) -> &Name;

    /// Make exactly the reads `evaluate` will make: `reads.current(..)`, `reads.read(..)`;
    /// compute nothing else. MUST be a function of the definition and what the reads return.
    async fn plan(&self, definition: &Definition, reads: &mut dyn Reads) -> Result<(), PlanError>;

    /// A pure function of the definition and the contents of the reads: the same bytes on every
    /// device that registers this name. No clock, randomness, environment, file, network, other
    /// local or unsigned state; iteration order by contents only; canonical result octets.
    fn evaluate(&self, definition: &Definition, view: &dyn ReadView) -> Result<Bytes, EvalError>;
}

/// The evaluators a device knows, by exact name (as [`MergeRules`](crate::MergeRules)).
#[derive(Clone, Default)]
pub struct Evaluators(Vec<Arc<dyn Evaluator>>);

impl Evaluators {
    /// No evaluator.
    pub fn none() -> Self {
        Self::default()
    }

    /// With `e`, replacing one of the same name.
    #[must_use]
    pub fn with(mut self, e: Arc<dyn Evaluator>) -> Self {
        self.0.retain(|x| x.evaluator() != e.evaluator());
        self.0.push(e);
        self
    }

    /// The evaluator named exactly `name`.
    pub fn get(&self, name: &Name) -> Option<&Arc<dyn Evaluator>> {
        self.0.iter().find(|e| e.evaluator() == name)
    }
}

impl std::fmt::Debug for Evaluators {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.0.iter().map(|e| e.evaluator()))
            .finish()
    }
}

// ---- policy, limits, config ---------------------------------------------------------------------

/// Whom to trust (answers.md §9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Signers {
    /// Nobody: recompute, or [`DataError::CannotCheck`].
    None,
    /// Devices of this device's own namespace.
    Own,
    /// Own, or a writer of EVERY collection the answer read, by the records held, no context
    /// held revoking its key (a device that only reads a collection is not trusted: it could
    /// not have changed what the answer read; list it in [`Signers::Devices`] to trust it).
    OwnAndMembers,
    /// These device names; a name also matches the devices under it.
    Devices(Vec<Name>),
}

impl Signers {
    /// Whether the list names `device`: itself, or a prefix of it. `Own` and `OwnAndMembers` are
    /// decided against the device's own namespace and records, not here.
    pub fn names(&self, device: &Name) -> bool {
        match self {
            Signers::Devices(names) => names.iter().any(|n| device.has_prefix(n)),
            Signers::None | Signers::Own | Signers::OwnAndMembers => false,
        }
    }
}

/// The host's policy for answers, a value it holds and passes (answers.md §9): which signers a
/// reader trusts without recomputing, and which devices provide which function.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnswerPolicy {
    /// Whom to trust for pure answers. Default [`Signers::OwnAndMembers`].
    pub pure: Signers,
    /// Function name (exact) to who provides it. Default none: a provider answer is refused
    /// unless an entry names its function and its signer.
    pub providers: Vec<(Name, Signers)>,
    /// Evaluators for which this host takes a trusted signer's answer without recomputing.
    /// Default none: a known evaluator is recomputed.
    pub trust: BTreeSet<Name>,
}

impl Default for AnswerPolicy {
    fn default() -> Self {
        AnswerPolicy {
            pure: Signers::OwnAndMembers,
            providers: Vec::new(),
            trust: BTreeSet::new(),
        }
    }
}

/// Whether `get` signs what it computed (answers.md §6.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Publish {
    /// `get` never signs; [`Device::publish_answer`](crate::Device::publish_answer) and
    /// [`Device::provide`](crate::Device::provide) do.
    Never,
    /// A pure answer this device computed in a `get` is also signed, stored and served.
    Computed,
}

/// What one evaluation may spend (answers.md §10): exceeded is
/// [`AnswerRefusal::OverBudget`], never a different result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Budget {
    /// Reads of distinct versions and states, and calls of [`Reads::current`] (each is a
    /// lookup of what this device holds, and a plan that calls it again and again spends it).
    pub reads: usize,
    /// Octets read.
    pub read_bytes: u64,
    /// Octets of the result.
    pub result_bytes: u64,
    /// Wall-clock time to evaluate, and to check the reads of a signed answer against what
    /// this device holds. Over it the work is abandoned and refused as
    /// [`AnswerRefusal::OverBudget`]: the clock only ever makes a refusal, never a result or a
    /// trust decision.
    pub time: Duration,
}

/// What a device keeps of others' answers (answers.md §10).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnswerStore {
    /// Answers kept per signer.
    pub per_signer_answers: usize,
    /// Octets kept per signer.
    pub per_signer_bytes: u64,
    /// Octets kept in all.
    pub total_bytes: u64,
}

/// A device's settings for answers (`Config::answers`).
#[derive(Clone, Debug)]
pub struct AnswerConfig {
    /// Whom to trust. Default [`AnswerPolicy::default`].
    pub policy: AnswerPolicy,
    /// Whether `get` signs what it computed. Default [`Publish::Never`].
    pub publish: Publish,
    /// What one evaluation may spend. Default: 65,536 reads and `current` calls,
    /// `PAYLOAD_MAX` octets read and returned, 10 s.
    pub budget: Budget,
    /// What is kept of others' answers. Default: 1,024 answers and 64 MiB per signer, 1 GiB in
    /// all.
    pub store: AnswerStore,
    /// The most answers this device signs per second for itself (a `get` that publishes,
    /// `publish_answer`, `provide`). The asks of other devices have a rate of their own, half of
    /// this (rounded up), counted apart, so asks never use up the device's own: past it an ask
    /// is refused [`AskRefusal::Busy`]. Default 16.
    pub sign_per_second: u32,
    /// Whose asks for an answer this device answers (answers.md §15). Default
    /// [`AskServing::Own`].
    pub serve_asks: AskServing,
    /// The most asks for an answer this device works on at once, for all askers together; one
    /// more is refused [`AskRefusal::Busy`] (each asker also has one in progress at most). The
    /// signer's own namespace may use all of them. Devices of other namespaces together may use
    /// half of them (rounded down) and one other namespace half of that (rounded up, at least
    /// 1), so a collaborator who enrols many devices cannot keep the person's own devices
    /// waiting. Default 4.
    pub asks_at_once: usize,
    /// The most asks for an answer this device holds while it opens them and verifies their
    /// proofs, which a stranger can seal as well as anyone: one more is dropped without a
    /// reply, as an unauthenticated ask is. The asker asks again. Default 32.
    pub asks_queued: usize,
    /// The device roles ([`AskServing::Own`] and the own part of [`AskServing::OwnAndMembers`])
    /// that are served: the role is the name component after the namespace
    /// (`/<ns>/<role>/<device>`), and a device of another role (a guest's short-lived key; a
    /// node, which is a relay) is refused [`AskRefusal::NotServed`]. Add `node` to serve a relay
    /// of the person's. A device whose name carries no role is served only where the namespace
    /// does not use the role layout (its trust context lists no role in `DataRequiresCut`, so
    /// there is no role to refuse); in a namespace that does, a role-less name is no device its
    /// CA issued and is refused [`AskRefusal::NotServed`] too. Default `admin` and `member`.
    pub ask_roles: Vec<String>,
    /// Run the checks of an ask's reads and the evaluations, which are CPU-bound and bounded by
    /// [`Budget::time`] of wall-clock time, on the executor's own thread instead of the runtime's
    /// blocking pool. For a simulation on a paused clock that must replay exactly: a pool
    /// thread's finishing is an event of real time that lands among the tasks ready meanwhile,
    /// wherever the machine's load puts it, so two runs can order two packets differently. A
    /// host that serves traffic leaves it off: inline, the executor waits out each check and
    /// evaluation (a check of the reads of one ask, an evaluation at most [`Budget::time`]).
    /// Default `false`.
    pub inline_work: bool,
}

impl Default for AnswerConfig {
    fn default() -> Self {
        AnswerConfig {
            policy: AnswerPolicy::default(),
            publish: Publish::Never,
            budget: Budget {
                reads: READS_MAX,
                read_bytes: PAYLOAD_MAX,
                result_bytes: PAYLOAD_MAX,
                time: Duration::from_secs(10),
            },
            store: AnswerStore {
                per_signer_answers: 1_024,
                per_signer_bytes: 64 << 20,
                total_bytes: 1 << 30,
            },
            sign_per_second: 16,
            serve_asks: AskServing::Own,
            asks_at_once: 4,
            asks_queued: 32,
            ask_roles: vec!["admin".into(), "member".into()],
            inline_work: false,
        }
    }
}

// ---- the ask exchange (answers.md §15) ---------------------------------------------------------

/// TLV-TYPE of a Data packet: the asker's proof rides in an ask's plaintext as one.
const DATA_TLV: u64 = 0x06;

/// Whose asks for an answer a device answers ([`AnswerConfig::serve_asks`], answers.md §15).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AskServing {
    /// None: no ask is answered, and no reply is sent at all.
    Off,
    /// Asks of devices of this device's own namespace (in a role of
    /// [`AnswerConfig::ask_roles`]); a device of another namespace gets no reply.
    Own,
    /// Own, and a device that is a listed writer or reader of every collection the ask reads
    /// (a device of a namespace this device holds no trust context for gets no reply).
    OwnAndMembers,
}

/// Why a signer does not answer an ask with an answer (answers.md §15): the reason code of an
/// [`AnswerAskRefusal`]. An ask that does not authenticate gets no reply at all, so none of
/// these is ever told to a stranger.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AskRefusal {
    /// 1: a read of the question is sealed to an audience the asker is not in. `index` is the
    /// position, in the read set, of the first such read.
    NotAudience {
        /// The first read the asker may not read.
        index: u64,
    },
    /// 2: the signer works on as many asks as it may, on one of the asker's already, or on as
    /// many as the asker's namespace may; or the rate at which it signs for asks is spent.
    Busy {
        /// How long to wait before asking again.
        retry_after: Duration,
    },
    /// 3: the answer is being computed and was not ready within the ask's lifetime; asking the
    /// same question again gets it once it is.
    Pending {
        /// How long to wait before asking again.
        retry_after: Duration,
    },
    /// 4: the signer does not know the evaluator the question names.
    CannotCheck,
    /// 5: the signer does not provide the function, or its host delivered no result in time.
    NotProvided,
    /// 6: computing the answer would exceed the signer's budget, or the ask lists more reads of
    /// merge states than the signer checks. Never a rate: that is `Busy`.
    OverBudget,
    /// 7: the signer serves no asks from this asker: its role is not one of
    /// [`AnswerConfig::ask_roles`], or it is of another namespace and no listed writer or reader
    /// of every collection read ([`AskServing`]).
    NotServed,
    /// 8: the signer's evaluator refused the definition (or the reads the question states): it
    /// is no reading the evaluator takes. Unlike `CannotCheck`, the signer knows the evaluator;
    /// the definition is what is wrong, so the next step is to fix it. The evaluator's reason
    /// travels in the explanation ([`AnswerAskRefusal::evaluator_refused`]), and is shown to the
    /// asker for this reason only ([`AnswerAskRefusal::said`]).
    EvaluatorRefused,
}

impl AskRefusal {
    /// The reason code on the wire, 1 to 8.
    pub fn code(&self) -> u64 {
        match self {
            AskRefusal::NotAudience { .. } => 1,
            AskRefusal::Busy { .. } => 2,
            AskRefusal::Pending { .. } => 3,
            AskRefusal::CannotCheck => 4,
            AskRefusal::NotProvided => 5,
            AskRefusal::OverBudget => 6,
            AskRefusal::NotServed => 7,
            AskRefusal::EvaluatorRefused => 8,
        }
    }

    /// The one number a reason carries: the read's index, or the wait in milliseconds; 0 for the
    /// others.
    fn param(&self) -> u64 {
        match self {
            AskRefusal::NotAudience { index } => *index,
            AskRefusal::Busy { retry_after } | AskRefusal::Pending { retry_after } => {
                u64::try_from(retry_after.as_millis()).unwrap_or(u64::MAX)
            }
            _ => 0,
        }
    }

    fn of(code: u64, param: u64) -> Result<Self, WireError> {
        let wait = Duration::from_millis(param);
        let none = |r: AskRefusal| match param {
            0 => Ok(r),
            _ => Err(bad("this reason of an ask's refusal carries no number")),
        };
        match code {
            1 => Ok(AskRefusal::NotAudience { index: param }),
            2 => Ok(AskRefusal::Busy { retry_after: wait }),
            3 => Ok(AskRefusal::Pending { retry_after: wait }),
            4 => none(AskRefusal::CannotCheck),
            5 => none(AskRefusal::NotProvided),
            6 => none(AskRefusal::OverBudget),
            7 => none(AskRefusal::NotServed),
            8 => none(AskRefusal::EvaluatorRefused),
            _ => Err(bad("an ask's refusal has a reason code from 1 to 8")),
        }
    }

    /// How long to wait before asking again, if asking again can help.
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            AskRefusal::Busy { retry_after } | AskRefusal::Pending { retry_after } => {
                Some(*retry_after)
            }
            _ => None,
        }
    }

    /// What to do about it, by class.
    pub fn next(&self) -> NextStep {
        match self {
            AskRefusal::NotAudience { .. } => NextStep::AskOwner,
            AskRefusal::Busy { .. } | AskRefusal::Pending { .. } => NextStep::RetryLater,
            AskRefusal::CannotCheck | AskRefusal::NotProvided | AskRefusal::NotServed => {
                NextStep::SetPolicy
            }
            AskRefusal::OverBudget | AskRefusal::EvaluatorRefused => NextStep::FixRequest,
        }
    }

    /// Why, and what to do: what a signer says with the reason code.
    pub fn explain(&self) -> String {
        match self {
            AskRefusal::NotAudience { index } => format!(
                "read {index} of the question is sealed to an audience the asker is not in, so \
                 the signer neither computes nor tells it; ask the owner of that collection to \
                 add the asker's device to its readers"
            ),
            AskRefusal::Busy { retry_after } => format!(
                "the signer works on as many asks as it may, on one of this asker's already, on \
                 as many as this asker's namespace may, or signs for asks as fast as it may; \
                 ask again after {} ms",
                retry_after.as_millis()
            ),
            AskRefusal::Pending { retry_after } => format!(
                "the answer is being computed and was not ready within the ask's lifetime; ask \
                 the same question again after {} ms: the signer keeps the answer once it has \
                 it",
                retry_after.as_millis()
            ),
            AskRefusal::CannotCheck => "the signer does not know the evaluator the question \
                 names, so it cannot compute the answer; name a signer that knows it in the \
                 policy, or run a program that knows it"
                .into(),
            AskRefusal::NotProvided => "the signer does not provide this function, or its host \
                 delivered no result for it in time; name a device that provides it in \
                 AnswerPolicy::providers"
                .into(),
            AskRefusal::OverBudget => "computing the answer would exceed the signer's budget; \
                 state a smaller read set, or raise Config::answers.budget on the signer"
                .into(),
            AskRefusal::NotServed => "the signer serves no asks from this device (its role, or \
                 its namespace, is not one Config::answers.serve_asks and ask_roles name there); \
                 name another signer in the policy, or set serve_asks or ask_roles on the signer \
                 to include this device"
                .into(),
            AskRefusal::EvaluatorRefused => "the signer's evaluator refused the definition; fix \
                 the definition and ask again"
                .into(),
        }
    }
}

/// The most characters of an evaluator's reason that are shown ([`AskRefusal::EvaluatorRefused`]).
pub const EVALUATOR_REASON_MAX: usize = 512;

/// What precedes, and what follows, the evaluator's reason in the explanation of
/// [`AskRefusal::EvaluatorRefused`]: the reason is always inside these quotes.
const REASON_HEAD: &str = "the signer's evaluator refused the definition, in its words: \"";
const REASON_TAIL: &str = "\"; fix the definition and ask again";

/// `raw` as the words of a signer's evaluator that may be shown (answers.md §15.9): no control
/// character (every `char::is_control`: newlines, tabs, the escape of an ANSI sequence), no
/// character that reorders the text around it (the bidirectional embeddings, overrides and
/// isolates, which a signer could use to carry the closing quote elsewhere), no double quote
/// (each is a single quote, so the words can never close the quotes they are shown in), and at
/// most [`EVALUATOR_REASON_MAX`] characters: past that, the first `EVALUATOR_REASON_MAX - 1`
/// and an ellipsis (the ellipsis is within the cap). Idempotent.
fn evaluator_words(raw: &str) -> String {
    // The marks and embeddings of bidirectional text, which reorder what surrounds them.
    let reorders = |c: &char| matches!(c, '\u{200e}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}');
    let mut kept = raw
        .chars()
        .filter(|c| !c.is_control() && !reorders(c))
        .map(|c| if c == '"' { '\'' } else { c })
        .take(EVALUATOR_REASON_MAX + 1)
        .collect::<Vec<char>>();
    if kept.len() > EVALUATOR_REASON_MAX {
        kept.truncate(EVALUATOR_REASON_MAX - 1);
        kept.push('…');
    }
    kept.into_iter().collect()
}

/// `words` in the frame of an [`AskRefusal::EvaluatorRefused`] explanation.
fn quoted(words: &str) -> String {
    format!("{REASON_HEAD}{words}{REASON_TAIL}")
}

/// A signer's refusal of an ask, the Content of the reply Data (TLV 0x05DF, answers.md §15).
/// Its value is the reason code as a one-octet NonNegativeInteger, the one number the reason
/// carries ([`AskRefusal`]) as an eight-octet NonNegativeInteger, and, to the end, the
/// explanation in UTF-8: why, and what to do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnswerAskRefusal {
    /// The reason.
    pub why: AskRefusal,
    /// Why, and what to do, in words.
    pub explanation: String,
}

impl From<AskRefusal> for AnswerAskRefusal {
    fn from(why: AskRefusal) -> Self {
        AnswerAskRefusal::new(why)
    }
}

impl AnswerAskRefusal {
    /// The refusal for `why`, with the explanation of [`AskRefusal::explain`].
    pub fn new(why: AskRefusal) -> Self {
        AnswerAskRefusal {
            explanation: why.explain(),
            why,
        }
    }

    /// The refusal [`AskRefusal::EvaluatorRefused`] with the evaluator's `reason` in its
    /// explanation, as the signer's quoted words: sanitised as [`Self::said`] does (no control
    /// character, at most [`EVALUATOR_REASON_MAX`] characters), so that what the signer puts
    /// on the wire is already what is shown.
    pub fn evaluator_refused(reason: &str) -> Self {
        AnswerAskRefusal {
            why: AskRefusal::EvaluatorRefused,
            explanation: quoted(&evaluator_words(reason)),
        }
    }

    /// What the asker shows of this refusal (answers.md §15.9). For every reason but
    /// [`AskRefusal::EvaluatorRefused`], the reason's own text ([`AskRefusal::explain`]): what
    /// the signer wrote is a hostile or compromised signer's own words and is never shown. For
    /// `EvaluatorRefused`, the evaluator's words as the signer gave them, cleaned again here
    /// (control characters removed, at most [`EVALUATOR_REASON_MAX`] characters, double quotes
    /// made single), and always inside this device's own frame, `the signer's evaluator refused
    /// the definition, in its words: "…"; fix the definition and ask again`, so that nothing the
    /// signer sent reads as this device's words. A refusal that gave no words is the reason's
    /// own text.
    pub fn said(&self) -> String {
        if self.why != AskRefusal::EvaluatorRefused {
            return self.why.explain();
        }
        let given = self
            .explanation
            .strip_prefix(REASON_HEAD)
            .and_then(|e| e.strip_suffix(REASON_TAIL))
            .unwrap_or(&self.explanation);
        let words = evaluator_words(given);
        if words.is_empty() || self.explanation == self.why.explain() {
            self.why.explain()
        } else {
            quoted(&words)
        }
    }

    /// The `AnswerAskRefusal` TLV (0x05DF).
    pub fn encode(&self) -> Bytes {
        let mut v = Vec::with_capacity(9 + self.explanation.len());
        v.push(self.why.code() as u8);
        v.extend_from_slice(&self.why.param().to_be_bytes());
        v.extend_from_slice(self.explanation.as_bytes());
        tlv_of(tlv::ANSWER_ASK_REFUSAL, &v)
    }

    /// Decode one `AnswerAskRefusal` TLV, exactly.
    pub fn decode(tlv: Bytes) -> Result<Self, WireError> {
        let value = unwrap_tlv(tlv, tlv::ANSWER_ASK_REFUSAL, "an AnswerAskRefusal")?;
        let (Some(code), Some(param)) = (
            value.first().copied(),
            value.get(1..9).and_then(|p| <[u8; 8]>::try_from(p).ok()),
        ) else {
            return Err(bad(
                "an ask's refusal is a reason code, a number and an explanation",
            ));
        };
        let explanation = std::str::from_utf8(&value[9..])
            .map_err(|_| bad("an ask's refusal explains itself in UTF-8"))?
            .to_owned();
        Ok(AnswerAskRefusal {
            why: AskRefusal::of(u64::from(code), u64::from_be_bytes(param))?,
            explanation,
        })
    }
}

/// An ask for an answer as it travels (TLV 0x05DE, answers.md §15): sealed to the signer's seal
/// key like an introduction's ask, with the same fields: the asker's ephemeral X25519 public
/// key, a fresh content key wrapped to the signer's key, and the [`AnswerAskBody`] sealed under
/// it. The Interest's ApplicationParameters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnswerAskEnvelope {
    /// The asker's ephemeral X25519 public key.
    pub ephemeral: [u8; 32],
    /// A fresh content key, wrapped to the signer's seal key.
    pub key: Bytes,
    /// The [`AnswerAskBody`], sealed under that content key.
    pub sealed: Bytes,
}

impl AnswerAskEnvelope {
    /// Its `AnswerAskEnvelope` TLV: an ask Interest's ApplicationParameters.
    pub fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(tlv::ANSWER_ASK_ENVELOPE, |w| {
            w.write_tlv(wire::tlv::EPHEMERAL_KEY, &self.ephemeral);
            w.write_tlv(wire::tlv::CIPHERTEXT, &self.key);
            w.write_tlv(wire::tlv::CIPHERTEXT, &self.sealed);
        });
        w.finish()
    }

    /// Read an ask Interest's ApplicationParameters: one `AnswerAskEnvelope`.
    pub fn decode(params: Bytes) -> Result<Self, WireError> {
        let value = unwrap_tlv(params, tlv::ANSWER_ASK_ENVELOPE, "an AnswerAskEnvelope")?;
        let mut p = Parts::of(value)?;
        let ephemeral = read_digest(&p.expect(wire::tlv::EPHEMERAL_KEY, "the ephemeral key")?)?;
        let key = p.expect(wire::tlv::CIPHERTEXT, "the wrapped content key")?;
        let sealed = p.expect(wire::tlv::CIPHERTEXT, "the sealed body")?;
        p.end()?;
        Ok(AnswerAskEnvelope {
            ephemeral,
            key,
            sealed,
        })
    }
}

/// What an ask for an answer holds once opened: the question, the asking device and its proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnswerAskBody {
    /// The question: what is asked.
    pub ask: AnswerAsk,
    /// The asking device.
    pub asker: Name,
    /// The asker's proof packet `<asker>/32=ask/<binding>`, signed by its device key, a whole
    /// Data packet. `binding` is [`AnswerAskBody::binding`].
    pub proof: Bytes,
}

impl AnswerAskBody {
    /// What the asker's proof packet names: the label of this protocol, the signer's Name TLV,
    /// the `AnswerAsk` TLV and the ephemeral public key the ask is sealed with
    /// ([`wire::ask_binding`]).
    pub fn binding(signer: &Name, ask: &AnswerAsk, ephemeral: &[u8; 32]) -> [u8; 32] {
        wire::ask_binding(
            wire::AskProtocol::AnswerAsk,
            &[&signer.encode_to_tlv(), &ask.encode(), ephemeral],
        )
    }

    /// Its plaintext: the `AnswerAsk` TLV, the asker's Name TLV, the proof Data packet.
    pub fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_raw(&self.ask.encode());
        write_name(&mut w, &self.asker);
        w.write_raw(&self.proof);
        w.finish()
    }

    /// Read a plaintext, exactly.
    pub fn decode(plain: Bytes) -> Result<Self, WireError> {
        let mut p = Parts::of(plain)?;
        let ask = AnswerAsk::decode(tlv_of(
            tlv::ANSWER_ASK,
            &p.expect(tlv::ANSWER_ASK, "the question")?,
        ))?;
        let asker = read_name(p.expect(tlv_type::NAME, "the asker's name")?)?;
        let proof = tlv_of(DATA_TLV, &p.expect(DATA_TLV, "the asker's proof packet")?);
        p.end()?;
        Ok(AnswerAskBody { ask, asker, proof })
    }
}

/// `<signer>/32=ask-answer`: an ask for an answer's name before its parameters digest, and what
/// its sealing binds as associated data.
pub fn answer_ask_prefix(signer: &Name) -> Name {
    signer.clone().append_component(wire::kw(b"ask-answer"))
}

/// An ask's name: `<signer>/32=ask-answer/<ParametersSha256Digest>`, the digest over the
/// ApplicationParameters TLV that carries `params` (an [`AnswerAskEnvelope`] TLV), as the
/// Interest carries it and the reply is named.
pub fn answer_ask_name(signer: &Name, params: &[u8]) -> Name {
    let mut w = TlvWriter::new();
    w.write_tlv(ndn_packet::tlv_type::APP_PARAMETERS, params);
    let digest = Sha256::digest(w.finish());
    answer_ask_prefix(signer).append_component(NameComponent::new(
        tlv_type::PARAMETERS_SHA256,
        Bytes::copy_from_slice(&digest),
    ))
}

/// The signer `<signer>/32=ask-answer/<ParametersSha256Digest>` asks.
pub fn parse_answer_ask_name(name: &Name) -> Option<Name> {
    let comps = name.components();
    let at = comps.iter().position(|c| wire::is_kw(c, b"ask-answer"))?;
    (wire::is_device_comps(&comps[..at])
        && at + 2 == comps.len()
        && comps[at + 1].typ == tlv_type::PARAMETERS_SHA256
        && comps[at + 1].value.len() == 32)
        .then(|| wire::name_of(&comps[..at]))
}

/// A function's call a host is asked to compute (answers.md §15): delivered on
/// [`Device::provider_asks`](crate::Device::provider_asks) when an authenticated device in the
/// audience of every input asks this device for a provider answer it does not hold. The host
/// computes the result and calls [`Device::provide`](crate::Device::provide) with `function`,
/// `inputs` and it; the asker's next ask finds the answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderAsk {
    /// The function, full and versioned.
    pub function: Name,
    /// The inputs: signed reads the asker may read.
    pub inputs: ReadSet,
    /// The asking device.
    pub asker: Name,
}
