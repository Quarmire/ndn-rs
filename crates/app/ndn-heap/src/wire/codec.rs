//! The entry codec (`docs/specs/heap.md`, §3): the Content of every log
//! packet, the grant answer, the seal-key packet and the manifest node.
//!
//! One set of limits holds on both sides: a decoder validates what it built
//! exactly as the encoder validates what it is given, so nothing that encodes
//! fails to decode and nothing that decodes fails to encode. An unknown even
//! TLV inside a record is skipped (a later revision's additive field, kept in
//! the signed packet because a served packet is never re-encoded); an unknown
//! odd one refuses.

use bytes::Bytes;
use ndn_foundation_types::{Name, NameComponent, tlv_type};
use ndn_security::confidentiality::{NONCE_LEN, TAG_LEN};
use ndn_tlv::TlvWriter;

use super::names::{is_device_name, is_namespace};
use super::pieces::{FANOUT, PAYLOAD_MAX};
use super::prim::{
    WireError, each, fields, once, only, read_array, read_digest, read_epoch_id, read_name,
    read_nni, write_epoch_id, write_name, write_nni,
};
use super::tlv;
use super::types::{
    Body, Entry, EntryRef, EpochBody, Kind, MembersBody, Op, Payload, Prev, PutBody, Role,
    SealedBody,
};

/// The most payload octets an entry carries in its own packet; a larger
/// payload travels in pieces.
pub(crate) const INLINE_MAX: usize = 6144;

/// The most heads of its path a Put entry supersedes.
pub(crate) const AFTER_MAX: usize = 8;

/// The most generic components of a path.
pub(crate) const PATH_COMPONENTS_MAX: usize = 8;

/// The most octets of a path's components in all.
pub(crate) const PATH_OCTETS_MAX: usize = 200;

/// The most operations of one Members entry.
pub(crate) const OPS_MAX: usize = 32;

/// The most chain tips one removal binds.
pub(crate) const TIPS_MAX: usize = 64;

/// The most persons an Epoch entry's audience lists.
pub(crate) const AUDIENCE_MAX: usize = 256;

/// The largest single NDN packet (ndn-cxx `MAX_NDN_PACKET_SIZE`); a Data over
/// it cannot cross a bare face.
pub(crate) const MAX_NDN_PACKET_SIZE: usize = ndn_sync::MAX_NDN_PACKET_SIZE;

/// What the packet around an entry may take: its name, MetaInfo, signature
/// info (with key locator) and signature value.
pub(crate) const ENVELOPE_RESERVE: usize = 800;

/// The most octets of an entry's own encoding: what is left of
/// [`MAX_NDN_PACKET_SIZE`] for the packet's content.
pub(crate) const ENTRY_MAX: usize = MAX_NDN_PACKET_SIZE - ENVELOPE_RESERVE;

/// The most octets of a sealed payload: the plaintext (`PATH` and the
/// largest inline payload, with their headers) plus nonce and tag.
pub(crate) const SEALED_MAX: usize = INLINE_MAX + 256;

const ZERO_DIGEST: [u8; 32] = [0; 32];

impl Entry {
    /// The entry's encoding: one `ENTRY` TLV, the Content of its packet.
    /// Refuses an entry the format cannot carry, or one over [`ENTRY_MAX`].
    pub(crate) fn encode(&self) -> Result<Bytes, WireError> {
        self.validate()?;
        let mut w = TlvWriter::new();
        w.write_nested(tlv::ENTRY, |w| {
            write_nni(w, tlv::KIND, self.kind() as u64);
            if let Some(prev) = &self.prev {
                w.write_tlv(tlv::PREV, &prev.digest);
                if let Some(seq) = prev.seq {
                    write_nni(w, tlv::PREV_SEQ, seq);
                }
            }
            for r in &self.after {
                write_ref(w, r);
            }
            match &self.body {
                Body::Put(put) => write_put(w, put),
                Body::Sealed(sealed) => w.write_nested(tlv::SEALED, |w| {
                    write_epoch_id(w, &sealed.epoch);
                    w.write_tlv(tlv::CIPHERTEXT, &sealed.sealed);
                }),
                Body::Members(members) => w.write_nested(tlv::MEMBERS, |w| {
                    if let Some(anyone) = members.create {
                        w.write_nested(tlv::CREATE, |w| {
                            write_nni(w, tlv::ANYONE, u64::from(anyone));
                        });
                    }
                    for op in &members.ops {
                        write_op(w, op);
                    }
                }),
                Body::Epoch(epoch) => w.write_nested(tlv::EPOCH_BODY, |w| {
                    w.write_tlv(tlv::KEY_CHECK, &epoch.key_check);
                    w.write_nested(tlv::AUDIENCE, |w| {
                        for person in &epoch.audience {
                            write_name(w, person);
                        }
                    });
                }),
            }
        });
        let out = w.finish();
        too_large(out.len(), ENTRY_MAX, "the entry")?;
        Ok(out)
    }

    /// Decode the Content of a log packet. Refuses what [`Entry::encode`]
    /// would, an unknown critical TLV, a `KIND` that disagrees with the body,
    /// and anything not well-formed.
    pub(crate) fn decode(content: &[u8]) -> Result<Entry, WireError> {
        too_large(content.len(), ENTRY_MAX, "the entry")?;
        let value = only(
            Bytes::copy_from_slice(content),
            tlv::ENTRY,
            "the Content of a log packet is one ENTRY TLV",
        )?;
        let mut kind = None;
        let mut prev = None;
        let mut prev_seq = None;
        let mut after = Vec::new();
        let (mut path, mut inline, mut blob) = (None, None, None);
        let (mut sealed, mut members, mut epoch) = (None, None, None);
        fields!(value, |v| {
            tlv::KIND => once(&mut kind, read_nni(&v)?, "KIND")?,
            tlv::PREV => once(&mut prev, read_digest(&v)?, "PREV")?,
            tlv::PREV_SEQ => once(&mut prev_seq, read_nni(&v)?, "PREV_SEQ")?,
            tlv::ENTRY_REF => after.push(read_ref(v)?),
            tlv::PATH => once(&mut path, read_name(v)?, "PATH")?,
            tlv::INLINE => once(&mut inline, v, "INLINE")?,
            tlv::BLOB => once(&mut blob, read_blob(v)?, "BLOB")?,
            tlv::SEALED => once(&mut sealed, read_sealed(v)?, "SEALED")?,
            tlv::MEMBERS => once(&mut members, read_members(v)?, "MEMBERS")?,
            tlv::EPOCH_BODY => once(&mut epoch, read_epoch_body(v)?, "EPOCH_BODY")?,
        });

        let plain = path.is_some() || inline.is_some() || blob.is_some();
        let named = [plain, sealed.is_some(), members.is_some(), epoch.is_some()];
        if named.iter().filter(|b| **b).count() > 1 {
            return Err(WireError::Malformed(
                "an entry carries one body (a write, a sealed write, members or an epoch) and \
                 this one carries several; discard it",
            ));
        }
        let (body, body_kind, body_what) = if plain {
            (Body::Put(put_of(path, inline, blob)?), Kind::Put, "a write")
        } else if let Some(s) = sealed {
            (Body::Sealed(s), Kind::Put, "a sealed write")
        } else if let Some(m) = members {
            (Body::Members(m), Kind::Members, "members operations")
        } else if let Some(e) = epoch {
            (Body::Epoch(e), Kind::Epoch, "an epoch")
        } else {
            return Err(WireError::Missing("the entry's body"));
        };

        let kind = kind.ok_or(WireError::Missing("KIND"))?;
        if kind > Kind::Epoch as u64 {
            return Err(WireError::UnknownKind(kind));
        }
        if kind != body_kind as u64 {
            return Err(WireError::KindMismatch {
                kind,
                body: body_what,
            });
        }
        let entry = Entry {
            prev: link(prev, prev_seq)?,
            after,
            body,
        };
        entry.validate()?;
        Ok(entry)
    }

    /// The chain link the Content of a log packet states, read without its
    /// body: what a packet that verifies and does not [`decode`](Self::decode)
    /// still says of the entry before it. `None` when the `ENTRY` itself or
    /// its link cannot be read (PREV that is no digest, a repeated PREV, a
    /// PREV_SEQ without PREV, zero digest and `PREV_SEQ` that disagree);
    /// `Some(None)` when it states none.
    pub(crate) fn decode_prev(content: &[u8]) -> Option<Option<Prev>> {
        let value = only(Bytes::copy_from_slice(content), tlv::ENTRY, "an entry").ok()?;
        let (mut prev, mut prev_seq) = (None, None);
        each(value, |t, v| {
            match t {
                tlv::PREV => once(&mut prev, read_digest(&v)?, "PREV")?,
                tlv::PREV_SEQ => once(&mut prev_seq, read_nni(&v)?, "PREV_SEQ")?,
                _ => {}
            }
            Ok(true)
        })
        .ok()?;
        let prev = link(prev, prev_seq).ok()?;
        prev.as_ref().is_none_or(Prev::consistent).then_some(prev)
    }

    /// The limits of the format, held when writing and when reading.
    fn validate(&self) -> Result<(), WireError> {
        require(
            self.prev.as_ref().is_none_or(Prev::consistent),
            "PREV is 32 zero octets exactly when PREV_SEQ is 0 (the signed statement that \
             the device lost everything before); anything else is no chain link",
        )?;
        too_many(
            self.after.len(),
            AFTER_MAX,
            "the superseded heads of an entry, or the epochs an epoch replaces",
        )?;
        require(
            self.after.is_empty() || self.kind() != Kind::Members,
            "only a write names the heads it supersedes and only an epoch the epochs it \
             replaces; a members entry carries none",
        )?;
        self.after
            .iter()
            .try_for_each(|r| check_device(&r.device))?;
        match &self.body {
            Body::Put(put) => check_put(put)?,
            Body::Sealed(sealed) => {
                check_device(&sealed.epoch.creator)?;
                too_large(sealed.sealed.len(), SEALED_MAX, "a sealed payload")?;
                require(
                    sealed.sealed.len() >= NONCE_LEN + TAG_LEN,
                    "a sealed payload is at least a nonce and a tag",
                )?;
            }
            Body::Members(members) => {
                too_many(members.ops.len(), OPS_MAX, "a members entry")?;
                members.ops.iter().try_for_each(check_op)?;
            }
            Body::Epoch(epoch) => {
                too_many(epoch.audience.len(), AUDIENCE_MAX, "an epoch's audience")?;
                epoch.audience.iter().try_for_each(check_person)?;
            }
        }
        Ok(())
    }
}

/// The chain link `PREV` and `PREV_SEQ` state together.
fn link(digest: Option<[u8; 32]>, seq: Option<u64>) -> Result<Option<Prev>, WireError> {
    match (digest, seq) {
        (Some(digest), seq) => Ok(Some(Prev { digest, seq })),
        (None, None) => Ok(None),
        (None, Some(_)) => Err(WireError::Malformed(
            "PREV_SEQ without PREV states a gap from nothing; discard the entry",
        )),
    }
}

impl Prev {
    /// `PREV` is 32 zero octets exactly when `PREV_SEQ` is 0.
    fn consistent(&self) -> bool {
        (self.digest == ZERO_DIGEST) == (self.seq == Some(0))
    }
}

/// Refuse with `why` unless `ok`.
fn require(ok: bool, why: &'static str) -> Result<(), WireError> {
    ok.then_some(()).ok_or(WireError::Malformed(why))
}

fn too_large(size: usize, max: usize, what: &'static str) -> Result<(), WireError> {
    (size <= max)
        .then_some(())
        .ok_or(WireError::TooLarge { what, size, max })
}

fn too_many(count: usize, max: usize, what: &'static str) -> Result<(), WireError> {
    (count <= max)
        .then_some(())
        .ok_or(WireError::TooMany { what, count, max })
}

fn check_device(device: &Name) -> Result<(), WireError> {
    require(
        is_device_name(device),
        "a device name has at least one component and no keyword or digest component",
    )
}

fn check_person(person: &Name) -> Result<(), WireError> {
    require(
        is_namespace(person),
        "a person is a namespace: at least one component, none a keyword, digest or \
         sequence number",
    )
}

fn check_op(op: &Op) -> Result<(), WireError> {
    match op {
        Op::Add { who, epoch, .. } => {
            check_person(who)?;
            epoch.as_ref().map_or(Ok(()), |e| check_device(&e.creator))
        }
        Op::Remove { tips, .. } => {
            too_many(tips.len(), TIPS_MAX, "a removal's tips")?;
            tips.iter().try_for_each(|r| check_device(&r.device))
        }
    }
}

/// The octets one generic component takes on the wire.
fn component_octets(c: &NameComponent) -> usize {
    let len = c.value.len();
    let header = match len {
        0..=252 => 2,
        253..=0xFFFF => 4,
        _ => 6,
    };
    header + len
}

pub(crate) fn check_path(path: &Name) -> Result<(), WireError> {
    let comps = path.components();
    require(
        !comps.is_empty()
            && comps.len() <= PATH_COMPONENTS_MAX
            && comps
                .iter()
                .all(|c| c.typ == tlv_type::GENERIC_NAME_COMPONENT),
        "a path is 1 to 8 generic components (no keyword, digest or typed component)",
    )?;
    too_large(
        comps.iter().map(component_octets).sum(),
        PATH_OCTETS_MAX,
        "a path",
    )
}

pub(crate) fn write_path(w: &mut TlvWriter, path: &Name) {
    w.write_nested(tlv::PATH, |w| {
        for c in path.components() {
            w.write_tlv(c.typ, &c.value);
        }
    });
}

/// A write's `PATH` and payload TLVs: what an `ENTRY` carries for a plain
/// Put, and what a sealed Put seals.
fn write_put(w: &mut TlvWriter, put: &PutBody) {
    write_path(w, &put.path);
    match &put.payload {
        Payload::Inline(bytes) => w.write_tlv(tlv::INLINE, bytes),
        Payload::Blob { size, root } => w.write_nested(tlv::BLOB, |w| {
            write_nni(w, tlv::SIZE, *size);
            w.write_tlv(tlv::ROOT, root);
        }),
    }
}

/// The limits of a write: the path and the payload.
fn check_put(put: &PutBody) -> Result<(), WireError> {
    check_path(&put.path)?;
    match &put.payload {
        Payload::Inline(bytes) => too_large(bytes.len(), INLINE_MAX, "an inline payload"),
        Payload::Blob { size, .. } if *size > PAYLOAD_MAX => Err(WireError::TooLarge {
            what: "a blob",
            size: usize::try_from(*size).unwrap_or(usize::MAX),
            max: PAYLOAD_MAX as usize,
        }),
        Payload::Blob { .. } => Ok(()),
    }
}

/// A write from the fields a decoder found: a path and exactly one payload.
fn put_of(
    path: Option<Name>,
    inline: Option<Bytes>,
    blob: Option<(u64, [u8; 32])>,
) -> Result<PutBody, WireError> {
    let path = path.ok_or(WireError::Missing("PATH"))?;
    let payload = match (inline, blob) {
        (Some(bytes), None) => Payload::Inline(bytes),
        (None, Some((size, root))) => Payload::Blob { size, root },
        (None, None) => return Err(WireError::Missing("INLINE or BLOB")),
        (Some(_), Some(_)) => {
            return Err(WireError::Malformed(
                "a write carries INLINE or BLOB, not both; discard the entry",
            ));
        }
    };
    Ok(PutBody { path, payload })
}

/// The plaintext a sealed Put seals: the TLVs of `PATH` and the payload
/// (`INLINE` or `BLOB`), with no `ENTRY` around them. Held to the limits of
/// a plain Put.
pub(crate) fn encode_sealed_plain(put: &PutBody) -> Result<Bytes, WireError> {
    check_put(put)?;
    let mut w = TlvWriter::new();
    write_put(&mut w, put);
    Ok(w.finish())
}

/// Decode what [`encode_sealed_plain`] wrote: a `PATH` and exactly one of
/// `INLINE` or `BLOB`. An unknown even TLV is skipped, an unknown odd one
/// refuses.
pub(crate) fn decode_sealed_plain(plain: &[u8]) -> Result<PutBody, WireError> {
    too_large(plain.len(), ENTRY_MAX, "a sealed plaintext")?;
    let (mut path, mut inline, mut blob) = (None, None, None);
    fields!(Bytes::copy_from_slice(plain), |v| {
        tlv::PATH => once(&mut path, read_name(v)?, "PATH")?,
        tlv::INLINE => once(&mut inline, v, "INLINE")?,
        tlv::BLOB => once(&mut blob, read_blob(v)?, "BLOB")?,
    });
    let put = put_of(path, inline, blob)?;
    check_put(&put)?;
    Ok(put)
}

pub(crate) fn write_ref(w: &mut TlvWriter, r: &EntryRef) {
    w.write_nested(tlv::ENTRY_REF, |w| {
        write_name(w, &r.device);
        write_nni(w, tlv::SEQ, r.seq);
        w.write_tlv(tlv::DIGEST, &r.digest);
    });
}

pub(crate) fn read_ref(value: Bytes) -> Result<EntryRef, WireError> {
    let (mut device, mut seq, mut digest) = (None, None, None);
    fields!(value, |v| {
        tlv_type::NAME => once(&mut device, read_name(v)?, "an entry reference's device")?,
        tlv::SEQ => once(&mut seq, read_nni(&v)?, "an entry reference's seq")?,
        tlv::DIGEST => once(&mut digest, read_digest(&v)?, "an entry reference's digest")?,
    });
    let (Some(device), Some(seq), Some(digest)) = (device, seq, digest) else {
        return Err(WireError::Missing(
            "a device, a seq or a digest of an entry reference",
        ));
    };
    Ok(EntryRef {
        device,
        seq,
        digest,
    })
}

fn write_op(w: &mut TlvWriter, op: &Op) {
    match op {
        Op::Add {
            id,
            who,
            role,
            epoch,
        } => w.write_nested(tlv::ADD, |w| {
            w.write_tlv(tlv::ID, id);
            write_name(w, who);
            write_nni(w, tlv::ROLE, *role as u64);
            if let Some(epoch) = epoch {
                write_epoch_id(w, epoch);
            }
        }),
        Op::Remove { id, tips } => w.write_nested(tlv::REMOVE, |w| {
            w.write_tlv(tlv::ID, id);
            for tip in tips {
                write_ref(w, tip);
            }
        }),
    }
}

fn read_add(value: Bytes) -> Result<Op, WireError> {
    let (mut id, mut who, mut role, mut epoch) = (None, None, None, None);
    fields!(value, |v| {
        tlv::ID => once(&mut id, read_array::<16>(&v, "an id is 16 octets")?, "ID")?,
        tlv_type::NAME => once(&mut who, read_name(v)?, "an addition's person")?,
        tlv::ROLE => once(&mut role, read_role(&v)?, "ROLE")?,
        tlv::EPOCH_ID => once(&mut epoch, read_epoch_id(v)?, "an addition's epoch")?,
    });
    let (Some(id), Some(who), Some(role)) = (id, who, role) else {
        return Err(WireError::Missing(
            "an ID, a person or a ROLE of an addition",
        ));
    };
    Ok(Op::Add {
        id,
        who,
        role,
        epoch,
    })
}

fn read_role(v: &[u8]) -> Result<Role, WireError> {
    match read_nni(v)? {
        0 => Ok(Role::Writer),
        1 => Ok(Role::Reader),
        _ => Err(WireError::Malformed("ROLE is 0 (writer) or 1 (reader)")),
    }
}

fn read_flag(v: &[u8]) -> Result<bool, WireError> {
    match read_nni(v)? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(WireError::Malformed("ANYONE is 0 or 1")),
    }
}

fn read_remove(value: Bytes) -> Result<Op, WireError> {
    let mut id = None;
    let mut tips = Vec::new();
    fields!(value, |v| {
        tlv::ID => once(&mut id, read_array::<16>(&v, "an id is 16 octets")?, "ID")?,
        tlv::ENTRY_REF => tips.push(read_ref(v)?),
    });
    Ok(Op::Remove {
        id: id.ok_or(WireError::Missing("the ID of a removal"))?,
        tips,
    })
}

fn read_members(value: Bytes) -> Result<MembersBody, WireError> {
    let mut create = None;
    let mut ops = Vec::new();
    fields!(value, |v| {
        tlv::CREATE => once(&mut create, read_create(v)?, "CREATE")?,
        tlv::ADD => ops.push(read_add(v)?),
        tlv::REMOVE => ops.push(read_remove(v)?),
    });
    Ok(MembersBody { create, ops })
}

fn read_create(value: Bytes) -> Result<bool, WireError> {
    let mut anyone = None;
    fields!(value, |v| {
        tlv::ANYONE => once(&mut anyone, read_flag(&v)?, "ANYONE")?,
    });
    anyone.ok_or(WireError::Missing("ANYONE of CREATE"))
}

fn read_blob(value: Bytes) -> Result<(u64, [u8; 32]), WireError> {
    let (mut size, mut root) = (None, None);
    fields!(value, |v| {
        tlv::SIZE => once(&mut size, read_nni(&v)?, "SIZE")?,
        tlv::ROOT => once(&mut root, read_digest(&v)?, "ROOT")?,
    });
    let (Some(size), Some(root)) = (size, root) else {
        return Err(WireError::Missing("the SIZE or the ROOT of a blob"));
    };
    Ok((size, root))
}

fn read_sealed(value: Bytes) -> Result<SealedBody, WireError> {
    let (mut epoch, mut sealed) = (None, None);
    fields!(value, |v| {
        tlv::EPOCH_ID => once(&mut epoch, read_epoch_id(v)?, "a sealed body's epoch")?,
        tlv::CIPHERTEXT => once(&mut sealed, v, "CIPHERTEXT")?,
    });
    let (Some(epoch), Some(sealed)) = (epoch, sealed) else {
        return Err(WireError::Missing(
            "the EPOCH_ID or the CIPHERTEXT of a sealed body",
        ));
    };
    Ok(SealedBody { epoch, sealed })
}

fn read_epoch_body(value: Bytes) -> Result<EpochBody, WireError> {
    let (mut key_check, mut audience) = (None, None);
    fields!(value, |v| {
        tlv::KEY_CHECK => once(&mut key_check, read_digest(&v)?, "KEY_CHECK")?,
        tlv::AUDIENCE => once(&mut audience, read_audience(v)?, "AUDIENCE")?,
    });
    let (Some(key_check), Some(audience)) = (key_check, audience) else {
        return Err(WireError::Missing(
            "the KEY_CHECK or the AUDIENCE of an epoch",
        ));
    };
    Ok(EpochBody {
        key_check,
        audience,
    })
}

fn read_audience(value: Bytes) -> Result<Vec<Name>, WireError> {
    let mut persons = Vec::new();
    fields!(value, |v| { tlv_type::NAME => persons.push(read_name(v)?) });
    Ok(persons)
}

/// A grant's answer: the granter's ephemeral public key and the epoch key
/// wrapped to the asker's seal key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Grant {
    /// The granter's ephemeral X25519 public key.
    pub ephemeral: [u8; 32],
    /// `nonce ‖ tag ‖ ciphertext` of the wrapped key.
    pub ciphertext: Bytes,
}

impl Grant {
    /// The Content of a grant packet: one `GRANT` TLV.
    pub(crate) fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(tlv::GRANT, |w| {
            w.write_tlv(tlv::EPHEMERAL_KEY, &self.ephemeral);
            w.write_tlv(tlv::CIPHERTEXT, &self.ciphertext);
        });
        w.finish()
    }

    /// Decode the Content of a grant packet.
    pub(crate) fn decode(content: Bytes) -> Result<Grant, WireError> {
        let value = only(content, tlv::GRANT, "a grant packet carries one GRANT")?;
        let (mut ephemeral, mut ciphertext) = (None, None);
        fields!(value, |v| {
            tlv::EPHEMERAL_KEY => {
                once(&mut ephemeral, read_array(&v, "an ephemeral key is 32 octets")?, "EPHEMERAL_KEY")?
            },
            tlv::CIPHERTEXT => once(&mut ciphertext, v, "CIPHERTEXT")?,
        });
        let (Some(ephemeral), Some(ciphertext)) = (ephemeral, ciphertext) else {
            return Err(WireError::Missing(
                "the EPHEMERAL_KEY or the CIPHERTEXT of a grant",
            ));
        };
        Ok(Grant {
            ephemeral,
            ciphertext,
        })
    }
}

/// A seal key packet's Content: the X25519 public key.
pub(crate) fn encode_seal_key(public: &[u8; 32]) -> Bytes {
    let mut w = TlvWriter::new();
    w.write_tlv(tlv::SEAL_KEY, public);
    w.finish()
}

/// Decode a seal key packet's Content.
pub(crate) fn decode_seal_key(content: Bytes) -> Result<[u8; 32], WireError> {
    let value = only(
        content,
        tlv::SEAL_KEY,
        "a seal key packet carries one SEAL_KEY",
    )?;
    read_array(&value, "a seal key is 32 octets")
}

/// A manifest node's Content: the digests it lists, in order.
pub(crate) fn encode_manifest(digests: &[[u8; 32]]) -> Bytes {
    let mut w = TlvWriter::new();
    for d in digests {
        w.write_tlv(tlv::DIGEST, d);
    }
    w.finish()
}

/// Decode a manifest node's Content: 1 to [`FANOUT`] digests.
pub(crate) fn decode_manifest(content: Bytes) -> Result<Vec<[u8; 32]>, WireError> {
    let mut out = Vec::new();
    fields!(content, |v| { tlv::DIGEST => out.push(read_digest(&v)?) });
    if out.is_empty() {
        return Err(WireError::Missing("a digest of a manifest node"));
    }
    too_many(out.len(), FANOUT, "a manifest node")?;
    Ok(out)
}
