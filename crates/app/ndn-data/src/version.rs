//! The immutable unit: a [`Version`], identified by `(writer, seq)`, and the
//! values it carries (parents, type, seal, keep, payload).

use std::collections::BTreeMap;

use bytes::Bytes;
use ndn_foundation_types::Name;

/// A writer is **one signing key**, named by its key name — never a person.
///
/// A person's laptop and phone are two writers (model change M1). Each writer
/// numbers its own versions; two writers can never collide.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Writer(Name);

impl Writer {
    /// The writer whose key is named `key`.
    pub fn new(key: Name) -> Self {
        Self(key)
    }

    /// The key name.
    pub fn key(&self) -> &Name {
        &self.0
    }
}

/// A writer's sequence number. It increases with every version of that
/// writer and never goes back (model invariant 3, "monotonic").
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Seq(pub u64);

/// The identity of a version: `(writer, seq)`.
///
/// One `(writer, seq)` has one set of bytes (model invariant 2). Two
/// different versions with the same id are proof of misbehaviour by that key,
/// reported as [`Change::Equivocation`](crate::Change::Equivocation).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VersionId {
    /// The signing key.
    pub writer: Writer,
    /// Its sequence number for this version.
    pub seq: Seq,
}

/// A causal point: for each writer, the highest sequence number included.
///
/// Because a writer's versions form one numbered log, `writer ≤ seq` names
/// all of that writer's versions up to `seq`. A frontier is used as a
/// version's parents (what its writer had seen) and as a collection's state
/// (what a summary or a merged value covers). It never refers to a clock.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Frontier(BTreeMap<Writer, Seq>);

impl Frontier {
    /// The empty frontier: nothing seen.
    pub fn new() -> Self {
        Self::default()
    }

    /// The highest sequence number of `writer` this frontier includes.
    pub fn get(&self, writer: &Writer) -> Option<Seq> {
        self.0.get(writer).copied()
    }

    /// Include `id` and every earlier version of its writer. Never lowers an
    /// entry.
    pub fn include(&mut self, id: &VersionId) {
        let entry = self.0.entry(id.writer.clone()).or_insert(id.seq);
        if *entry < id.seq {
            *entry = id.seq;
        }
    }

    /// Whether `id` lies inside this frontier.
    pub fn contains(&self, id: &VersionId) -> bool {
        self.get(&id.writer).is_some_and(|s| id.seq <= s)
    }

    /// Whether this frontier includes everything `other` does.
    pub fn covers(&self, other: &Frontier) -> bool {
        other
            .0
            .iter()
            .all(|(w, s)| self.get(w).is_some_and(|mine| *s <= mine))
    }

    /// The writers and their highest included sequence numbers, by writer.
    pub fn iter(&self) -> impl Iterator<Item = (&Writer, Seq)> {
        self.0.iter().map(|(w, s)| (w, *s))
    }

    /// Whether nothing is included.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl FromIterator<VersionId> for Frontier {
    fn from_iter<I: IntoIterator<Item = VersionId>>(iter: I) -> Self {
        let mut f = Frontier::new();
        for id in iter {
            f.include(&id);
        }
        f
    }
}

/// A named, versioned content schema, e.g. `/types/note` revision 2.
///
/// Types grow; readers name the type they understand; writers keep the
/// fields they do not understand, and a type says how such fields merge
/// (model change M7). Filled by slice 1.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TypeId {
    /// The type's name, without the revision.
    pub name: Name,
    /// The revision; a higher revision only adds fields.
    pub revision: u64,
}

/// A date: milliseconds since the Unix epoch, as some device's clock read it.
///
/// Dates are for display and retention only. No validity decision ever reads
/// one (model invariant 1); a version's date is whatever its signer's clock
/// said, and a stolen key can write any date.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(pub u64);

/// Retention chosen at write (model invariant 7). Custody never extends it;
/// prune only narrows it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Keep {
    /// Keep until this date, by the holder's clock.
    Until(Timestamp),
    /// Keep this writer's last `n` versions in the collection.
    LastN(u32),
    /// Keep until pruned.
    Forever,
}

/// Who a seal admits: a person, a device or a group — never an app.
///
/// Lenses hold no keys; the host opens exactly what the person pointed at
/// and hands that to the lens (model change M4). There is deliberately no
/// app variant.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Audience {
    /// A person, by their namespace (e.g. `/alice`).
    Person(Name),
    /// One device, by its name.
    Device(Name),
    /// A group, by its name (e.g. `/alice/groups/family`).
    Group(Name),
}

/// A read policy: anyone in `any_of` may read.
///
/// Sealed data is stored and forwarded by holders that cannot read it;
/// erasing it means destroying its key. Revocation and removal move reading to
/// a new epoch: they stop future reads and recall no copy already made (model
/// invariant 9). Filled by slice 2.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Seal {
    /// The readers, as a disjunction.
    pub any_of: Vec<Audience>,
}

/// Typed content: named fields with opaque values.
///
/// A writer that edits content of a type it understands only in part keeps
/// every field it does not know (model invariant 8). The field names and
/// encodings belong to the [`TypeId`]; their wire form is slice 1's.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Content(BTreeMap<String, Bytes>);

impl Content {
    /// Empty content.
    pub fn new() -> Self {
        Self::default()
    }

    /// This content with `field` set to `value`.
    pub fn with(mut self, field: impl Into<String>, value: impl Into<Bytes>) -> Self {
        self.0.insert(field.into(), value.into());
        self
    }

    /// The value of `field`, if present.
    pub fn get(&self, field: &str) -> Option<&Bytes> {
        self.0.get(field)
    }

    /// Every field, by name.
    pub fn fields(&self) -> impl Iterator<Item = (&str, &Bytes)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v))
    }
}

/// What a version carries: one entry, or a block of many small entries under
/// one signature.
///
/// A block carries a digest per entry so each entry verifies on its own; the
/// producer states the delay it accepts to fill one (model change M6). Blocks
/// are filled by slice 4.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Payload {
    /// A single entry.
    Entry(Content),
    /// Several entries under one signature, in order.
    Block(Vec<Content>),
}

/// An immutable record signed by one key (model primitive "Version").
///
/// It verifies from its bytes, its name, the trust context and the cuts —
/// never from a server or a clock (model invariant 1). Filled by slice 1.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Version {
    /// `(writer, seq)`.
    pub id: VersionId,
    /// The version's own name, under its writer's prefix.
    pub name: Name,
    /// The collection the version belongs to.
    pub collection: Name,
    /// What the writer had seen when it wrote this version.
    pub parents: Frontier,
    /// The content's type.
    pub type_id: TypeId,
    /// Who may read it.
    pub seal: Seal,
    /// How long it is kept.
    pub keep: Keep,
    /// The date its writer's clock showed; display only.
    pub dated: Timestamp,
    /// The content.
    pub payload: Payload,
}
