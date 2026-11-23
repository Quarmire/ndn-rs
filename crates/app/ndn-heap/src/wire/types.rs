//! The shapes of what a log entry says (spec §3). Pure data: the TLV codec
//! is `wire::codec`, the names are `wire::names`.

use bytes::Bytes;
use ndn_foundation_types::Name;

/// What an entry is, as the `KIND` TLV says it (spec §3.2). Derived from the
/// entry's body; a decoder refuses an entry whose `KIND` and body disagree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    /// A write at a path (plain or sealed).
    Put = 0,
    /// Membership operations: the space's creation, additions, removals.
    Members = 1,
    /// A new epoch: who may open what is sealed from here on.
    Epoch = 2,
}

/// The Content of every log packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Entry {
    /// The link to the writer's previous entry in this space. Absent only at
    /// seq 1.
    pub prev: Option<Prev>,
    /// Put only: the heads of the entry's path this write supersedes
    /// (at most [`AFTER_MAX`](super::AFTER_MAX)).
    pub after: Vec<EntryRef>,
    /// What the entry says.
    pub body: Body,
}

impl Entry {
    /// The entry's [`Kind`], from its body.
    pub(crate) fn kind(&self) -> Kind {
        match self.body {
            Body::Put(_) | Body::Sealed(_) => Kind::Put,
            Body::Members(_) => Kind::Members,
            Body::Epoch(_) => Kind::Epoch,
        }
    }
}

/// `PREV` (+ `PREV_SEQ`): the chain link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Prev {
    /// The signed-region digest of the entry at `seq` (or of `seq - 1` when
    /// `seq` is `None`); 32 zero octets with `seq == Some(0)` say "this
    /// device lost everything before" (the signed gap statement, spec §4).
    pub digest: [u8; 32],
    /// Present iff the previous entry's seq is not this entry's `seq - 1`.
    pub seq: Option<u64>,
}

/// A reference to one entry: who wrote it, at which seq, and the
/// signed-region digest of its bytes.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct EntryRef {
    /// The writing device.
    pub device: Name,
    /// Its seq in the (device, space) log.
    pub seq: u64,
    /// The signed-region digest of the entry's Data.
    pub digest: [u8; 32],
}

/// What an entry says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Body {
    /// A plain write.
    Put(PutBody),
    /// A write sealed in an epoch (path and payload are inside).
    Sealed(SealedBody),
    /// Membership operations.
    Members(MembersBody),
    /// A new epoch.
    Epoch(EpochBody),
}

/// A plain write: one path, one payload. An empty inline payload is a
/// removal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PutBody {
    /// Relative to the space: 1 to 8 generic components, at most 200 octets.
    pub path: Name,
    /// The value.
    pub payload: Payload,
}

/// A payload: in the entry, or in pieces under it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Payload {
    /// At most `INLINE_MAX` octets, empty for a removal.
    Inline(Bytes),
    /// Larger: `size` octets in pieces under the entry's name, the manifest
    /// tree's root digest `root`.
    Blob {
        /// Octets of the (sealed, if sealed) payload.
        size: u64,
        /// The manifest tree's root digest.
        root: [u8; 32],
    },
}

/// A write sealed in an epoch. The plaintext sealed is the TLV bytes of
/// `PATH` + payload; the AAD is the entry's `Name` TLV.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SealedBody {
    /// The epoch whose key sealed it.
    pub epoch: EpochId,
    /// `nonce ‖ tag ‖ ciphertext` (`Sealed::to_bytes`).
    pub sealed: Bytes,
}

/// An epoch: the Epoch entry that made it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct EpochId {
    /// The owner device that signed the Epoch entry.
    pub creator: Name,
    /// Its seq.
    pub seq: u64,
}

/// A Members entry: at most 32 operations.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub(crate) struct MembersBody {
    /// The space's creation (once): `Some(anyone)` says whether readers are
    /// everybody.
    pub create: Option<bool>,
    /// Additions and removals.
    pub ops: Vec<Op>,
}

/// One membership operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Op {
    /// Admit `who` (a person's namespace, matched exactly) in `role`.
    Add {
        /// Names this addition; a removal names the ids it removes.
        id: [u8; 16],
        /// The person.
        who: Name,
        /// Writer or reader.
        role: Role,
        /// Reader additions: the epoch whose history the reader reads.
        epoch: Option<EpochId>,
    },
    /// Remove every addition under `id`; `tips` bind what the owner held of
    /// the removed person's devices (at most 64).
    Remove {
        /// The addition ids removed.
        id: [u8; 16],
        /// Chain tips of the removed person's devices.
        tips: Vec<EntryRef>,
    },
}

/// A member's role.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Role {
    /// May write.
    Writer = 0,
    /// May read.
    Reader = 1,
}

/// An Epoch entry's body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EpochBody {
    /// `key_check` of the epoch key (HKDF, spec §6): tells a reader the key
    /// it was granted is the epoch's.
    pub key_check: [u8; 32],
    /// The persons the epoch is for (at most 256).
    pub audience: Vec<Name>,
}
