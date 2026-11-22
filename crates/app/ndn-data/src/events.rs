//! Device-wide events (spec `docs/specs/data-layer.md` §21): what no folder owns.
//!
//! A device tells its host, on one stream, about equivocation of a key (any two different entries
//! at one seq, a members record against a version included), entries withdrawn, cuts that took
//! effect, and revocations adopted. **An event reports; it never decides.** Everything it says was
//! already done fail-closed before it existed (both entries kept, an entry refused, a key's later
//! entries refused), and no verb answers differently for an event delivered, acknowledged,
//! coalesced or dropped. It carries only what this device verified — names, digests, kinds, key
//! names and counts, never content — and is never published: it lives under
//! `/localhost/ndn-data/events/` in the device's own store.
//!
//! Delivery is at least once ([`Device::events`](crate::Device::events)): an event stays until the
//! host [`acknowledge`](crate::Device::acknowledge)s it, across restarts. Flooding is bounded
//! without losing the first of each kind per subject (§21.5): per `(kind, subject)` the first
//! event is kept and later ones are coalesced into a count and the last evidence; the number kept
//! is capped ([`Config::events_unacked`](crate::Config::events_unacked)), and a single
//! [`EventDetail::Overflow`] event counts what was not kept.

use std::fmt;
use std::pin::Pin;

use bytes::Bytes;
use futures_core::Stream;
use ndn_foundation_types::{Name, tlv_type};
use ndn_tlv::TlvWriter;
use sha2::{Digest, Sha256};

use crate::error::{NextStep, Refusal};
use crate::version::Timestamp;
use crate::wire::{
    self, WireError, bad, each, read_digest, read_name, read_nni, write_name, write_nni,
};

/// TLV-TYPE numbers of an event as the store keeps it (0x05E0–0x05FF, all even; local to the
/// store, never on the wire). Registered in `docs/specs/README.md`.
pub mod tlv {
    /// A stored event: `EventId`, `Dated` (first seen), `Count`, one detail, `Last`?.
    pub const EVENT_RECORD: u64 = 0x05E0;
    /// An event's id: 16 octets.
    pub const EVENT_ID: u64 = 0x05E2;
    /// How many occurrences the event stands for, in an event; how many versions a cut keeps,
    /// in a cut; how many events of a kind were not kept, in a `Dropped` (NonNegativeInteger).
    pub const EVENT_COUNT: u64 = 0x05E4;
    /// The last coalesced occurrence: one detail.
    pub const EVENT_LAST: u64 = 0x05E6;
    /// Detail: equivocation. `Name` (the key), `Seq`, two `EntryRef`.
    pub const EQUIVOCATION: u64 = 0x05E8;
    /// Detail: withdrawal. `Name` (the key), `Name`? (the collection), `EntryRef`, one of
    /// `ByCut`, `ByChain`, `ByGroup`.
    pub const WITHDRAWAL: u64 = 0x05EA;
    /// Detail: cut. `Folder`, `Revision`, `Count` (versions kept), then four `Name`: subject,
    /// of, signer, record.
    pub const CUT_EVENT: u64 = 0x05EC;
    /// Detail: revocation. `Seq` (the context's version), two `Name`: namespace, revoked.
    pub const REVOCATION_EVENT: u64 = 0x05EE;
    /// Detail: overflow. `Dropped*`.
    pub const OVERFLOW: u64 = 0x05F0;
    /// A log entry by name: `Name`, `Kind`?, `Digest`?.
    pub const ENTRY_REF: u64 = 0x05F2;
    /// An entry's kind, or an event kind in a `Dropped` (NonNegativeInteger).
    pub const KIND: u64 = 0x05F4;
    /// Withdrawn by a cut: two `Name`: the key cut, the signer.
    pub const BY_CUT: u64 = 0x05F6;
    /// Withdrawn for its chain: the validator's verdict, UTF-8.
    pub const BY_CHAIN: u64 = 0x05F8;
    /// Withdrawn with its group: the member refused, `Name`.
    pub const BY_GROUP: u64 = 0x05FA;
    /// Whether a cut's subject is a folder (NonNegativeInteger, 0 or 1).
    pub const FOLDER: u64 = 0x05FC;
    /// Events not kept: `Kind` + `Count`.
    pub const DROPPED: u64 = 0x05FE;
}

/// An event's identity: the first 16 octets of SHA-256 over `"ndn-data/event/1"` and the event's
/// first detail as stored (an [`EventDetail::Overflow`]: over its creation cursor). Stable across
/// restarts, and equal on devices that derive the same evidence, so a host deduplicates by it.
/// Display: 32 hex digits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EventId(pub [u8; 16]);

impl fmt::Display for EventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

impl EventId {
    const DOMAIN: &'static [u8] = b"ndn-data/event/1";

    fn digest(parts: &[&[u8]]) -> EventId {
        let mut h = Sha256::new();
        h.update(Self::DOMAIN);
        for p in parts {
            h.update(p);
        }
        let d = h.finalize();
        let mut id = [0u8; 16];
        id.copy_from_slice(&d[..16]);
        EventId(id)
    }

    /// The id of an event whose first detail is `detail`, created at `cursor`.
    pub fn of(detail: &EventDetail, cursor: Cursor) -> EventId {
        match detail {
            EventDetail::Overflow { .. } => Self::digest(&[b"overflow", &cursor.0.to_be_bytes()]),
            _ => Self::digest(&[&encode_detail(detail)]),
        }
    }
}

/// Where an event stands in delivery on one device: strictly increasing, never reused (a durable
/// counter). [`Device::events`](crate::Device::events) delivers events above a cursor.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Cursor(pub u64);

/// The kind of an event.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EventKind {
    /// Two different entries of one key at one seq.
    Equivocation,
    /// A held entry refused again.
    Withdrawal,
    /// A members record took a cut into force.
    Cut,
    /// A trust context adopted revokes a name.
    Revocation,
    /// Events not kept for want of room.
    Overflow,
}

impl EventKind {
    /// The kinds events are kept for: every kind but [`EventKind::Overflow`], the notice of what
    /// was not kept. A kind's share of the cap is one of these.
    pub(crate) const KEPT: [EventKind; 4] = [
        EventKind::Equivocation,
        EventKind::Withdrawal,
        EventKind::Cut,
        EventKind::Revocation,
    ];

    fn code(self) -> u64 {
        match self {
            EventKind::Equivocation => 0,
            EventKind::Withdrawal => 1,
            EventKind::Cut => 2,
            EventKind::Revocation => 3,
            EventKind::Overflow => 4,
        }
    }

    fn of_code(c: u64) -> Result<Self, WireError> {
        Ok(match c {
            0 => EventKind::Equivocation,
            1 => EventKind::Withdrawal,
            2 => EventKind::Cut,
            3 => EventKind::Revocation,
            4 => EventKind::Overflow,
            _ => return Err(bad("an unknown event kind")),
        })
    }
}

impl fmt::Display for EventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            EventKind::Equivocation => "equivocation",
            EventKind::Withdrawal => "withdrawal",
            EventKind::Cut => "cut",
            EventKind::Revocation => "revocation",
            EventKind::Overflow => "overflow",
        })
    }
}

/// Who an event is about. With the kind it is the key events coalesce by.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EventSubject {
    /// A writer's key (`<device>/KEY/<k>`): equivocation and withdrawal; for a cut, the key
    /// prefix the record cut, as it lists it.
    Writer(Name),
    /// A key or prefix a trust context revokes.
    Revoked(Name),
    /// This device: the overflow notice.
    Device,
}

/// What an entry of a log is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EntryKind {
    /// A version.
    Version,
    /// A members record.
    Members,
    /// A snapshot.
    Snapshot,
    /// A hold record.
    Hold,
    /// A lease.
    Lease,
    /// A prune record.
    Prune,
    /// An introduction's offer or use mark.
    Intro,
}

impl EntryKind {
    fn code(self) -> u64 {
        match self {
            EntryKind::Version => 0,
            EntryKind::Members => 1,
            EntryKind::Snapshot => 2,
            EntryKind::Hold => 3,
            EntryKind::Lease => 4,
            EntryKind::Prune => 5,
            EntryKind::Intro => 6,
        }
    }

    fn of_code(c: u64) -> Result<Self, WireError> {
        Ok(match c {
            0 => EntryKind::Version,
            1 => EntryKind::Members,
            2 => EntryKind::Snapshot,
            3 => EntryKind::Hold,
            4 => EntryKind::Lease,
            5 => EntryKind::Prune,
            6 => EntryKind::Intro,
            _ => return Err(bad("an unknown entry kind")),
        })
    }

    /// The kind of the entry that carries `record`.
    pub(crate) fn of(record: &wire::Record) -> Self {
        match record {
            wire::Record::Version(_) => EntryKind::Version,
            wire::Record::Members(_) => EntryKind::Members,
            wire::Record::Snapshot(_) => EntryKind::Snapshot,
            wire::Record::Hold(_) => EntryKind::Hold,
            wire::Record::Lease(_) => EntryKind::Lease,
            wire::Record::Prune(_) => EntryKind::Prune,
            wire::Record::Intro(_) => EntryKind::Intro,
        }
    }
}

impl fmt::Display for EntryKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            EntryKind::Version => "version",
            EntryKind::Members => "members record",
            EntryKind::Snapshot => "snapshot",
            EntryKind::Hold => "hold record",
            EntryKind::Lease => "lease",
            EntryKind::Prune => "prune record",
            EntryKind::Intro => "introduction record",
        })
    }
}

/// A log entry by name, never by content: evidence a receiver can check against the writer's
/// packets without this device saying anything it cannot read.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EntryRef {
    /// Its name, `<device>/32=log/<collection>/seq=<n>` (a snapshot's has no collection).
    pub name: Name,
    /// What it is, when this device held it whole; `None` when it never did.
    pub kind: Option<EntryKind>,
    /// The implicit digest of the packet this device verified, when it has it.
    pub digest: Option<[u8; 32]>,
}

impl fmt::Display for EntryRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            Some(k) => write!(f, "{} ({k})", self.name),
            None => write!(f, "{}", self.name),
        }
    }
}

/// Why a held entry was withdrawn, as a `get` of it answers now.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum WithdrawnBy {
    /// Its key was cut and the cut does not list it ([`Refusal::OutsideCut`]).
    Cut {
        /// The key, or prefix of keys, cut.
        of: Name,
        /// The key that signed the cut.
        signer: Name,
    },
    /// A key above its signer is revoked or no longer authorised
    /// ([`Refusal::Untrusted`]): no cut excuses it.
    Chain {
        /// The validator's verdict.
        why: String,
    },
    /// A member of its group is refused ([`Refusal::Group`]).
    Group {
        /// The member refused.
        member: Name,
    },
}

impl WithdrawnBy {
    /// What `why` withdrew an entry by; `None` for a refusal that does not withdraw
    /// (an entry refused as it arrives is never told).
    pub fn of(why: &Refusal) -> Option<Self> {
        Some(match why {
            Refusal::OutsideCut(cut) => WithdrawnBy::Cut {
                of: cut.of.clone(),
                signer: cut.signer.key().clone(),
            },
            Refusal::Untrusted { why } => WithdrawnBy::Chain { why: why.clone() },
            Refusal::Group { member, .. } => WithdrawnBy::Group {
                member: member.clone(),
            },
            _ => return None,
        })
    }
}

/// What an event says: the evidence of one occurrence.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum EventDetail {
    /// Two different entries of one key at one seq, in any collections, of any kinds.
    Equivocation {
        /// The key that signed both.
        writer: Name,
        /// The seq.
        seq: u64,
        /// The entry taken first here.
        first: EntryRef,
        /// The other.
        second: EntryRef,
    },
    /// A held entry is refused now, whether or not anyone watches.
    Withdrawal {
        /// The key that signed it.
        writer: Name,
        /// The collection it is about; `None` for a snapshot.
        collection: Option<Name>,
        /// The entry.
        entry: EntryRef,
        /// Why.
        by: WithdrawnBy,
    },
    /// A members record not signed by this device took a cut into force: a writer prefix
    /// removed from `subject`.
    Cut {
        /// The collection or folder whose record it is.
        subject: Name,
        /// Whether `subject` is a folder.
        folder: bool,
        /// The key prefix removed.
        of: Name,
        /// The key that signed the record.
        signer: Name,
        /// The record's log entry, which the signer serves.
        record: Name,
        /// The record's revision.
        revision: u64,
        /// How many versions the cut keeps.
        kept: u64,
    },
    /// A trust context adopted revokes a name the context before it did not.
    Revocation {
        /// The namespace.
        namespace: Name,
        /// The key or key prefix revoked.
        revoked: Name,
        /// The adopted context's version.
        version: u64,
    },
    /// Events not kept, by kind: the retained ones are full or the kind is.
    Overflow {
        /// How many occurrences of each kind were not kept, in kind order.
        dropped: Vec<(EventKind, u64)>,
    },
}

/// What this device already did about an event's cause (spec §21): the event reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Meaning {
    /// Both entries are kept as evidence; neither is preferred.
    BothKept,
    /// The entry no longer counts here; its packet stays held.
    Withdrawn,
    /// The key's new entries are refused outside the cut; what the cut keeps stays.
    WriterCut,
    /// Entries of the revoked name outside its cut, and chains through it, are refused.
    KeyRefused,
    /// Events were not kept; the evidence is still held.
    ReportsDropped,
}

impl EventDetail {
    /// The kind of event.
    pub fn kind(&self) -> EventKind {
        match self {
            EventDetail::Equivocation { .. } => EventKind::Equivocation,
            EventDetail::Withdrawal { .. } => EventKind::Withdrawal,
            EventDetail::Cut { .. } => EventKind::Cut,
            EventDetail::Revocation { .. } => EventKind::Revocation,
            EventDetail::Overflow { .. } => EventKind::Overflow,
        }
    }

    /// The key or name whose namespace the event is counted under (spec §21.5): the writer, the
    /// signer of a cut, the namespace of a revocation; none for the overflow
    /// notice.
    pub(crate) fn about(&self) -> Option<&Name> {
        match self {
            EventDetail::Equivocation { writer, .. } | EventDetail::Withdrawal { writer, .. } => {
                Some(writer)
            }
            EventDetail::Cut { signer, .. } => Some(signer),
            EventDetail::Revocation { namespace, .. } => Some(namespace),
            EventDetail::Overflow { .. } => None,
        }
    }

    /// Who it is about.
    pub fn subject(&self) -> EventSubject {
        match self {
            EventDetail::Equivocation { writer, .. } | EventDetail::Withdrawal { writer, .. } => {
                EventSubject::Writer(writer.clone())
            }
            EventDetail::Cut { of, .. } => EventSubject::Writer(of.clone()),
            EventDetail::Revocation { revoked, .. } => EventSubject::Revoked(revoked.clone()),
            EventDetail::Overflow { .. } => EventSubject::Device,
        }
    }

    /// What this device already did.
    pub fn meaning(&self) -> Meaning {
        match self {
            EventDetail::Equivocation { .. } => Meaning::BothKept,
            EventDetail::Withdrawal { .. } => Meaning::Withdrawn,
            EventDetail::Cut { .. } => Meaning::WriterCut,
            EventDetail::Revocation { .. } => Meaning::KeyRefused,
            EventDetail::Overflow { .. } => Meaning::ReportsDropped,
        }
    }

    /// The next step, by class ([`NextStep`]); [`what_to_do`](Self::what_to_do) says it in words.
    pub fn next_step(&self) -> NextStep {
        match self {
            EventDetail::Equivocation { .. } => NextStep::UseOwnerDevice,
            EventDetail::Withdrawal { by, .. } => match by {
                WithdrawnBy::Cut { .. } | WithdrawnBy::Chain { .. } => NextStep::AskOwner,
                WithdrawnBy::Group { .. } => NextStep::None,
            },
            EventDetail::Cut { .. } | EventDetail::Revocation { .. } => NextStep::None,
            EventDetail::Overflow { .. } => NextStep::None,
        }
    }

    /// What the host does, in words.
    pub fn what_to_do(&self) -> String {
        match self {
            EventDetail::Equivocation { writer, .. } => format!(
                "on a device that holds the owner's authority, mark {writer} suspected \
                 (Device::suspect), and revoke it once the copy or fault is confirmed; nothing \
                 is lost meanwhile, both entries are kept"
            ),
            EventDetail::Withdrawal { by, entry, .. } => match by {
                WithdrawnBy::Cut { .. } => format!(
                    "nothing if the cut was meant; otherwise ask the owner to re-admit {} \
                     exactly, by its name and digest",
                    entry.name
                ),
                WithdrawnBy::Chain { .. } => format!(
                    "nothing if the revocation was meant; otherwise ask the owner of the \
                     namespace to certify the key again, which takes {} back",
                    entry.name
                ),
                WithdrawnBy::Group { member } => format!(
                    "nothing: a member of its group, {member}, is refused, so no version of the \
                     group counts"
                ),
            },
            EventDetail::Cut { subject, of, .. } => format!(
                "nothing if removing {of} from {subject} was meant; members({subject}) shows the \
                 record in force, and the owner can add the writer again"
            ),
            EventDetail::Revocation { revoked, .. } => format!(
                "nothing: entries of {revoked} outside its cut are refused here already; see \
                 the withdrawals that follow for what they were"
            ),
            EventDetail::Overflow { .. } => {
                "acknowledge the events handled, which makes room; what was not kept is still \
                 held and can be read again (watch lists equivocation, members the records in \
                 force)"
                    .to_owned()
            }
        }
    }

    /// What happened, and why it matters, in words.
    pub fn why(&self) -> String {
        match self {
            EventDetail::Equivocation {
                writer,
                seq,
                first,
                second,
            } => format!(
                "{writer} signed two different entries at seq {seq}: {first} and {second}. A \
                 key's log is one sequence, so a copy of the key is writing, or the device \
                 faulted; both entries are kept as evidence and neither is preferred"
            ),
            EventDetail::Withdrawal {
                entry, by, writer, ..
            } => match by {
                WithdrawnBy::Cut { of, signer } => format!(
                    "{} of {writer} no longer counts: {of} was cut by {signer} and the cut does \
                     not list it",
                    entry.name
                ),
                WithdrawnBy::Chain { why } => format!(
                    "{} of {writer} no longer counts: a trust context adopted later refuses its \
                     key's chain ({why})",
                    entry.name
                ),
                WithdrawnBy::Group { member } => format!(
                    "{} of {writer} no longer counts: its group member {member} is refused",
                    entry.name
                ),
            },
            EventDetail::Cut {
                subject,
                folder,
                of,
                signer,
                revision,
                kept,
                ..
            } => format!(
                "{signer} removed {of} from {} {subject} (record revision {revision}), keeping {kept} \
                 of its versions; its later entries there are refused",
                if *folder { "folder" } else { "collection" }
            ),
            EventDetail::Revocation {
                namespace,
                revoked,
                version,
            } => format!(
                "the trust context of {namespace} (version {version}) revokes {revoked}; its \
                 entries outside the revocation's cut are refused"
            ),
            EventDetail::Overflow { dropped } => {
                let total: u64 = dropped.iter().map(|(_, n)| n).sum();
                let by = dropped
                    .iter()
                    .map(|(k, n)| format!("{n} {k}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!(
                    "{total} events were not kept ({by}): too many were waiting for \
                     acknowledgement"
                )
            }
        }
    }
}

/// One event: the first occurrence of its `(kind, subject)` since the last acknowledgement, and
/// how many later ones were coalesced into it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceEvent {
    /// Its identity.
    pub id: EventId,
    /// Its place in delivery.
    pub cursor: Cursor,
    /// When this device first saw it, by its own clock; display only.
    pub first_seen: Timestamp,
    /// The first occurrence's evidence.
    pub detail: EventDetail,
    /// How many occurrences it stands for, the first included.
    pub count: u64,
    /// The newest coalesced occurrence, when `count` is above 1.
    pub last: Option<EventDetail>,
}

impl DeviceEvent {
    /// The kind.
    pub fn kind(&self) -> EventKind {
        self.detail.kind()
    }

    /// Who it is about.
    pub fn subject(&self) -> EventSubject {
        self.detail.subject()
    }

    /// What this device already did.
    pub fn meaning(&self) -> Meaning {
        self.detail.meaning()
    }

    /// The next step, by class.
    pub fn next_step(&self) -> NextStep {
        self.detail.next_step()
    }

    /// What the host does, in words.
    pub fn what_to_do(&self) -> String {
        self.detail.what_to_do()
    }

    /// What happened, in words.
    pub fn why(&self) -> String {
        self.detail.why()
    }
}

/// The stream [`Device::events`](crate::Device::events) returns. It ends when the device stops.
pub type DeviceEvents = Pin<Box<dyn Stream<Item = DeviceEvent> + Send>>;

// ---- the store's encoding -----------------------------------------------------------------------

fn write_entry(w: &mut TlvWriter, e: &EntryRef) {
    w.write_nested(tlv::ENTRY_REF, |w| {
        write_name(w, &e.name);
        if let Some(k) = e.kind {
            write_nni(w, tlv::KIND, k.code());
        }
        if let Some(d) = &e.digest {
            w.write_tlv(wire::tlv::DIGEST, d);
        }
    });
}

fn read_entry(value: Bytes) -> Result<EntryRef, WireError> {
    let (mut name, mut kind, mut digest) = (None, None, None);
    each(value, |t, v| {
        match t {
            tlv_type::NAME => name = Some(read_name(v)?),
            tlv::KIND => kind = Some(EntryKind::of_code(read_nni(&v)?)?),
            wire::tlv::DIGEST => digest = Some(read_digest(&v)?),
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    Ok(EntryRef {
        name: name.ok_or_else(|| bad("an entry reference names the entry"))?,
        kind,
        digest,
    })
}

fn write_detail(w: &mut TlvWriter, d: &EventDetail) {
    match d {
        EventDetail::Equivocation {
            writer,
            seq,
            first,
            second,
        } => w.write_nested(tlv::EQUIVOCATION, |w| {
            write_name(w, writer);
            write_nni(w, wire::tlv::SEQ, *seq);
            write_entry(w, first);
            write_entry(w, second);
        }),
        EventDetail::Withdrawal {
            writer,
            collection,
            entry,
            by,
        } => w.write_nested(tlv::WITHDRAWAL, |w| {
            write_name(w, writer);
            if let Some(c) = collection {
                write_name(w, c);
            }
            write_entry(w, entry);
            match by {
                WithdrawnBy::Cut { of, signer } => w.write_nested(tlv::BY_CUT, |w| {
                    write_name(w, of);
                    write_name(w, signer);
                }),
                WithdrawnBy::Chain { why } => w.write_tlv(tlv::BY_CHAIN, why.as_bytes()),
                WithdrawnBy::Group { member } => {
                    w.write_nested(tlv::BY_GROUP, |w| write_name(w, member))
                }
            }
        }),
        EventDetail::Cut {
            subject,
            folder,
            of,
            signer,
            record,
            revision,
            kept,
        } => w.write_nested(tlv::CUT_EVENT, |w| {
            write_nni(w, tlv::FOLDER, u64::from(*folder));
            write_nni(w, wire::tlv::REVISION, *revision);
            write_nni(w, tlv::EVENT_COUNT, *kept);
            for n in [subject, of, signer, record] {
                write_name(w, n);
            }
        }),
        EventDetail::Revocation {
            namespace,
            revoked,
            version,
        } => w.write_nested(tlv::REVOCATION_EVENT, |w| {
            write_nni(w, wire::tlv::SEQ, *version);
            write_name(w, namespace);
            write_name(w, revoked);
        }),
        EventDetail::Overflow { dropped } => w.write_nested(tlv::OVERFLOW, |w| {
            for (k, n) in dropped {
                w.write_nested(tlv::DROPPED, |w| {
                    write_nni(w, tlv::KIND, k.code());
                    write_nni(w, tlv::EVENT_COUNT, *n);
                });
            }
        }),
    }
}

/// An event detail's encoding: one of its TLVs.
pub(crate) fn encode_detail(d: &EventDetail) -> Bytes {
    let mut w = TlvWriter::new();
    write_detail(&mut w, d);
    w.finish()
}

fn is_detail(t: u64) -> bool {
    matches!(
        t,
        tlv::EQUIVOCATION
            | tlv::WITHDRAWAL
            | tlv::CUT_EVENT
            | tlv::REVOCATION_EVENT
            | tlv::OVERFLOW
    )
}

fn read_detail(typ: u64, value: Bytes) -> Result<EventDetail, WireError> {
    match typ {
        tlv::EQUIVOCATION => {
            let (mut names, mut seq, mut entries) = (Vec::new(), None, Vec::new());
            each(value, |t, v| {
                match t {
                    tlv_type::NAME => names.push(read_name(v)?),
                    wire::tlv::SEQ => seq = Some(read_nni(&v)?),
                    tlv::ENTRY_REF => entries.push(read_entry(v)?),
                    _ => return Ok(false),
                }
                Ok(true)
            })?;
            match (names.as_slice(), seq, entries.as_slice()) {
                ([writer], Some(seq), [first, second]) => Ok(EventDetail::Equivocation {
                    writer: writer.clone(),
                    seq,
                    first: first.clone(),
                    second: second.clone(),
                }),
                _ => Err(bad("an equivocation names a key, a seq and two entries")),
            }
        }
        tlv::WITHDRAWAL => {
            let (mut names, mut entry, mut by) = (Vec::new(), None, None);
            each(value, |t, v| {
                match t {
                    tlv_type::NAME => names.push(read_name(v)?),
                    tlv::ENTRY_REF => entry = Some(read_entry(v)?),
                    tlv::BY_CUT => {
                        let mut ns = Vec::new();
                        each(v, |t, v| {
                            if t != tlv_type::NAME {
                                return Ok(false);
                            }
                            ns.push(read_name(v)?);
                            Ok(true)
                        })?;
                        let [of, signer] = <[Name; 2]>::try_from(ns)
                            .map_err(|_| bad("a cut names the key cut and its signer"))?;
                        by = Some(WithdrawnBy::Cut { of, signer });
                    }
                    tlv::BY_CHAIN => {
                        by = Some(WithdrawnBy::Chain {
                            why: String::from_utf8_lossy(&v).into_owned(),
                        })
                    }
                    tlv::BY_GROUP => {
                        let mut ns = Vec::new();
                        each(v, |t, v| {
                            if t != tlv_type::NAME {
                                return Ok(false);
                            }
                            ns.push(read_name(v)?);
                            Ok(true)
                        })?;
                        let [member] = <[Name; 1]>::try_from(ns)
                            .map_err(|_| bad("a group refusal names one member"))?;
                        by = Some(WithdrawnBy::Group { member });
                    }
                    _ => return Ok(false),
                }
                Ok(true)
            })?;
            let (writer, collection) = match names.as_slice() {
                [w] => (w.clone(), None),
                [w, c] => (w.clone(), Some(c.clone())),
                _ => return Err(bad("a withdrawal names a key and maybe a collection")),
            };
            Ok(EventDetail::Withdrawal {
                writer,
                collection,
                entry: entry.ok_or_else(|| bad("a withdrawal names an entry"))?,
                by: by.ok_or_else(|| bad("a withdrawal says by what"))?,
            })
        }
        tlv::CUT_EVENT => {
            let (mut names, mut folder, mut revision, mut kept) = (Vec::new(), None, None, None);
            each(value, |t, v| {
                match t {
                    tlv_type::NAME => names.push(read_name(v)?),
                    tlv::FOLDER => folder = Some(read_nni(&v)? != 0),
                    wire::tlv::REVISION => revision = Some(read_nni(&v)?),
                    tlv::EVENT_COUNT => kept = Some(read_nni(&v)?),
                    _ => return Ok(false),
                }
                Ok(true)
            })?;
            let [subject, of, signer, record] = <[Name; 4]>::try_from(names).map_err(|_| {
                bad("a cut event names the subject, the key cut, the signer and the record")
            })?;
            match (folder, revision, kept) {
                (Some(folder), Some(revision), Some(kept)) => Ok(EventDetail::Cut {
                    subject,
                    folder,
                    of,
                    signer,
                    record,
                    revision,
                    kept,
                }),
                _ => Err(bad("a cut event has a folder flag, a revision and a count")),
            }
        }
        tlv::REVOCATION_EVENT => {
            let (mut names, mut version) = (Vec::new(), None);
            each(value, |t, v| {
                match t {
                    tlv_type::NAME => names.push(read_name(v)?),
                    wire::tlv::SEQ => version = Some(read_nni(&v)?),
                    _ => return Ok(false),
                }
                Ok(true)
            })?;
            let [namespace, revoked] = <[Name; 2]>::try_from(names)
                .map_err(|_| bad("a revocation event names a namespace and what is revoked"))?;
            Ok(EventDetail::Revocation {
                namespace,
                revoked,
                version: version.ok_or_else(|| bad("a revocation event has a version"))?,
            })
        }
        tlv::OVERFLOW => {
            let mut dropped = Vec::new();
            each(value, |t, v| {
                if t != tlv::DROPPED {
                    return Ok(false);
                }
                let (mut kind, mut n) = (None, None);
                each(v, |t, v| {
                    match t {
                        tlv::KIND => kind = Some(EventKind::of_code(read_nni(&v)?)?),
                        tlv::EVENT_COUNT => n = Some(read_nni(&v)?),
                        _ => return Ok(false),
                    }
                    Ok(true)
                })?;
                dropped.push((
                    kind.ok_or_else(|| bad("a dropped count names a kind"))?,
                    n.ok_or_else(|| bad("a dropped count has a count"))?,
                ));
                Ok(true)
            })?;
            Ok(EventDetail::Overflow { dropped })
        }
        _ => Err(bad("not an event detail")),
    }
}

/// An event as the store keeps it, without its cursor (its name carries it).
pub(crate) fn encode_event(e: &DeviceEvent) -> Bytes {
    let mut w = TlvWriter::new();
    w.write_nested(tlv::EVENT_RECORD, |w| {
        w.write_tlv(tlv::EVENT_ID, &e.id.0);
        write_nni(w, wire::tlv::DATED, e.first_seen.0);
        write_nni(w, tlv::EVENT_COUNT, e.count);
        write_detail(w, &e.detail);
        if let Some(last) = &e.last {
            w.write_nested(tlv::EVENT_LAST, |w| write_detail(w, last));
        }
    });
    w.finish()
}

/// Read back a stored event at `cursor`.
pub(crate) fn decode_event(cursor: Cursor, value: Bytes) -> Result<DeviceEvent, WireError> {
    let mut r = ndn_tlv::TlvReader::new(value);
    let (typ, body) = r.read_tlv().map_err(|e| bad(format!("bad TLV: {e:?}")))?;
    if typ != tlv::EVENT_RECORD || !r.is_empty() {
        return Err(bad("a stored event is one EventRecord"));
    }
    let (mut id, mut first_seen, mut count, mut detail, mut last) = (None, None, None, None, None);
    each(body, |t, v| {
        match t {
            tlv::EVENT_ID => {
                id = Some(EventId(
                    <[u8; 16]>::try_from(&v[..]).map_err(|_| bad("an event id is 16 octets"))?,
                ))
            }
            wire::tlv::DATED => first_seen = Some(Timestamp(read_nni(&v)?)),
            tlv::EVENT_COUNT => count = Some(read_nni(&v)?),
            tlv::EVENT_LAST => {
                let mut r = ndn_tlv::TlvReader::new(v);
                let (t, v) = r.read_tlv().map_err(|e| bad(format!("bad TLV: {e:?}")))?;
                last = Some(read_detail(t, v)?);
            }
            t if is_detail(t) => detail = Some(read_detail(t, v)?),
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    Ok(DeviceEvent {
        id: id.ok_or_else(|| bad("a stored event has an id"))?,
        cursor,
        first_seen: first_seen.ok_or_else(|| bad("a stored event has a date"))?,
        detail: detail.ok_or_else(|| bad("a stored event has a detail"))?,
        count: count.ok_or_else(|| bad("a stored event has a count"))?,
        last,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_kinds_events_are_kept_for_are_every_kind_but_the_overflow_notice() {
        let kept: Vec<EventKind> = (0..64)
            .filter_map(|c| EventKind::of_code(c).ok())
            .filter(|k| *k != EventKind::Overflow)
            .collect();
        assert_eq!(
            kept,
            EventKind::KEPT,
            "a kind was added: list it in EventKind::KEPT, which a kind's share of the cap counts"
        );
    }
}
