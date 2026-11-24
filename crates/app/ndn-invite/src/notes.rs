//! The grant note and the mirror note (spec §10 rule 3, 11, 14; §11 rule 17): what an
//! inviter keeps of a grant under `grant/<id>` and what a joiner keeps of the grant it
//! was given under `mirror/<space>/<key>` (`store.rs`).
//!
//! Notes are the device's own and local, never served, never on the wire. Their value
//! is a fixed-width local form, not a TLV: **no TLV-TYPE number is registered or used
//! for them**. A note ends in a MAC under a key derived from the device's recipient
//! secret, which lives in the key store, not the data store, with labels of its own for
//! each kind of note (so one kind is never read as the other): a note changed in the
//! store (the `ended` flag cleared, a date extended, a role flipped, a departure mark
//! added, cleared or moved) fails its check and is ignored.

use bytes::Bytes;
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use ndn_foundation_types::Name;
use ndn_heap::Timestamp;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::host::{Departure, Grant, Role};

/// The note's version octet. Version 2 notes (no departure mark) are still read.
pub(crate) const NOTE_VERSION: u8 = 3;

/// The version of a note written before departure marks.
pub(crate) const NOTE_VERSION_2: u8 = 2;

/// Flag bits of a note.
pub(crate) const ENDED: u8 = 1;
pub(crate) const DATED: u8 = 2;
/// The note carries a departure mark (version 3, and only on an ended note).
pub(crate) const MARKED: u8 = 4;

/// The fixed head of a note: version, flags, role, `until` (8, big-endian; zero when
/// the note has no date), the key's digest.
pub(crate) const HEAD: usize = 1 + 1 + 1 + 8 + 32;

/// The octets of a note's MAC (HMAC-SHA256), which end it.
pub(crate) const MAC_LEN: usize = 32;

/// The domain label of the grant note's MAC key's derivation from the recipient secret.
pub(crate) const MAC_KEY_LABEL: &[u8] = b"ndn-invite/grant-note/mac-key/1";

/// The domain label of the grant note's MAC itself.
pub(crate) const MAC_LABEL: &[u8] = b"ndn-invite/grant-note/mac/1";

/// The domain label of the mirror note's MAC key: not the inviter note's, so a MAC made
/// for one kind of note never checks for the other.
pub(crate) const MIRROR_MAC_KEY_LABEL: &[u8] = b"ndn-invite/mirror-note/mac-key/1";

/// The domain label of the mirror note's MAC itself.
pub(crate) const MIRROR_MAC_LABEL: &[u8] = b"ndn-invite/mirror-note/mac/1";

/// The mirror note's version octet.
pub(crate) const MIRROR_VERSION: u8 = 1;

/// The fixed head of a mirror note: version, flags (only [`ENDED`]), role, the
/// inviter key's digest.
pub(crate) const MIRROR_HEAD: usize = 1 + 1 + 1 + 32;

/// A key derived (HKDF-SHA256, the domain label `label`) from the device's recipient
/// secret. That secret is kept by the key store, never in the data store the notes live
/// in, so whoever can only write the data store cannot make a note that passes.
pub(crate) fn derived_key(secret: &[u8; 32], label: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, secret)
        .expand(label, &mut *key)
        .expect("32 octets is a valid HKDF-SHA256 output length");
    key
}

fn mac_under(key: &[u8; 32], label: &[u8], body: &[u8]) -> Hmac<Sha256> {
    let mut m =
        <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC accepts a key of any length");
    m.update(label);
    m.update(body);
    m
}

/// The MAC of a grant note's `body`.
pub(crate) fn mac_of(key: &[u8; 32], body: &[u8]) -> Hmac<Sha256> {
    mac_under(key, MAC_LABEL, body)
}

/// The MAC of a mirror note's `body`.
pub(crate) fn mirror_mac_of(key: &[u8; 32], body: &[u8]) -> Hmac<Sha256> {
    mac_under(key, MIRROR_MAC_LABEL, body)
}

/// Why a stored value is not a note this device reads.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Unread {
    /// A form or version this program does not read.
    Form,
    /// It is a note, but its MAC does not check under this device's key: it was
    /// changed, or written under another secret.
    Check,
}

/// A departure mark a note keeps (spec §11 rule 14): the held Members entry that let
/// the person go, and by when this device stops showing it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Mark {
    /// The entry's log name, `<signer device>/32=log/<space>/seq=<n>`.
    pub(crate) record: Name,
    /// By this device's clock: no longer served after it.
    pub(crate) until: Timestamp,
}

/// What the store keeps of a grant (spec §10).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GrantNote {
    /// The own offer whose admission made it, `<D>/32=intro/offer/<id>`.
    pub(crate) offer: Name,
    /// The asker key's public-key digest.
    pub(crate) key: [u8; 32],
    /// The asker's namespace (its person), as the join adopted it.
    pub(crate) namespace: Name,
    /// The space the offer admitted it to.
    pub(crate) space: Name,
    /// The role last told to the host: the offer's, then whatever the space's members
    /// make of it.
    pub(crate) role: Role,
    /// By this device's clock; `None`: no date, the note follows the members.
    pub(crate) until: Option<Timestamp>,
    /// The members left the person out, or the host ended it (`Invites::end_grant`).
    pub(crate) ended: bool,
    /// The entry that let the person go, when the members' change ended the grant and
    /// the policy keeps a mark. Never on a note the host ended, nor one in force.
    pub(crate) departure: Option<Mark>,
}

fn push_name(out: &mut Vec<u8>, name: &Name) {
    let tlv = name.encode_to_tlv();
    out.extend_from_slice(&(tlv.len() as u16).to_be_bytes());
    out.extend_from_slice(&tlv);
}

/// The name a length-prefixed Name TLV at `at` of `body` holds, and where it ends.
fn read_name_at(bytes: &Bytes, body: &[u8], at: usize) -> Result<(Name, usize), Unread> {
    let len = u16::from_be_bytes(
        body.get(at..at + 2)
            .ok_or(Unread::Form)?
            .try_into()
            .map_err(|_| Unread::Form)?,
    ) as usize;
    let start = at + 2;
    let tlv = body
        .get(start..start.checked_add(len).ok_or(Unread::Form)?)
        .ok_or(Unread::Form)?;
    let name = Name::decode_from_tlv(bytes.slice_ref(tlv)).map_err(|_| Unread::Form)?;
    Ok((name, start + len))
}

fn role_octet(role: Role) -> u8 {
    match role {
        Role::Reader => 0,
        Role::Writer => 1,
    }
}

fn role_of(octet: u8) -> Result<Role, Unread> {
    match octet {
        0 => Ok(Role::Reader),
        1 => Ok(Role::Writer),
        _ => Err(Unread::Form),
    }
}

impl GrantNote {
    /// The note's octets, MAC'd under `mac_key`.
    pub(crate) fn encode(&self, mac_key: &[u8; 32]) -> Bytes {
        let mut out = Vec::with_capacity(HEAD + 64 + MAC_LEN);
        out.push(NOTE_VERSION);
        out.push(
            if self.ended { ENDED } else { 0 }
                | if self.until.is_some() { DATED } else { 0 }
                | if self.departure.is_some() { MARKED } else { 0 },
        );
        out.push(role_octet(self.role));
        out.extend_from_slice(&self.until.map_or(0, |t| t.0).to_be_bytes());
        out.extend_from_slice(&self.key);
        for name in [&self.offer, &self.space, &self.namespace] {
            push_name(&mut out, name);
        }
        if let Some(mark) = &self.departure {
            out.extend_from_slice(&mark.until.0.to_be_bytes());
            push_name(&mut out, &mark.record);
        }
        let check = mac_of(mac_key, &out).finalize().into_bytes();
        out.extend_from_slice(&check);
        Bytes::from(out)
    }

    /// The note `bytes` hold, if they are one of a version this device reads (3, or 2:
    /// no departure mark) whose MAC checks under `mac_key`.
    pub(crate) fn decode(bytes: &Bytes, mac_key: &[u8; 32]) -> Result<Self, Unread> {
        let body_len = bytes.len().checked_sub(MAC_LEN).ok_or(Unread::Form)?;
        let (body, check) = bytes.split_at(body_len);
        if body.len() < HEAD || !matches!(body[0], NOTE_VERSION | NOTE_VERSION_2) {
            return Err(Unread::Form);
        }
        if mac_of(mac_key, body).verify_slice(check).is_err() {
            return Err(Unread::Check);
        }
        let flags = body[1];
        let known = if body[0] == NOTE_VERSION {
            ENDED | DATED | MARKED
        } else {
            ENDED | DATED
        };
        if flags & !known != 0 || (flags & MARKED != 0 && flags & ENDED == 0) {
            return Err(Unread::Form);
        }
        let role = role_of(body[2])?;
        let dated = u64::from_be_bytes(body[3..11].try_into().map_err(|_| Unread::Form)?);
        let until = (flags & DATED != 0).then_some(Timestamp(dated));
        let key = <[u8; 32]>::try_from(&body[11..HEAD]).map_err(|_| Unread::Form)?;
        let (offer, at) = read_name_at(bytes, body, HEAD)?;
        let (space, at) = read_name_at(bytes, body, at)?;
        let (namespace, mut at) = read_name_at(bytes, body, at)?;
        let departure = if flags & MARKED != 0 {
            let until = body.get(at..at + 8).ok_or(Unread::Form)?;
            let until = Timestamp(u64::from_be_bytes(
                until.try_into().map_err(|_| Unread::Form)?,
            ));
            let (record, end) = read_name_at(bytes, body, at + 8)?;
            at = end;
            Some(Mark { record, until })
        } else {
            None
        };
        if at != body.len() {
            return Err(Unread::Form);
        }
        Ok(Self {
            offer,
            key,
            namespace,
            space,
            role,
            until,
            ended: flags & ENDED != 0,
            departure,
        })
    }

    /// What the host is told, in the role the note holds.
    pub(crate) fn grant(&self) -> Grant {
        Grant {
            key: self.key,
            namespaces: vec![self.namespace.clone()],
            folder: self.space.clone(),
            role: self.role,
            until: self.until,
        }
    }

    /// The departure the note's mark makes, if it has one.
    pub(crate) fn departure(&self) -> Option<Departure> {
        self.departure.as_ref().map(|mark| Departure {
            key: self.key,
            namespaces: vec![self.namespace.clone()],
            folder: self.space.clone(),
            record: mark.record.clone(),
            until: mark.until,
        })
    }

    /// Whether the note's own date, if it has one, is past `now`.
    pub(crate) fn dated_out(&self, now: Timestamp) -> bool {
        self.until.is_some_and(|t| t <= now)
    }
}

/// What the joiner's device keeps of a grant it was given (spec §11 rule 17): the
/// mirror of the inviter's [`GrantNote`], kept the same way (under the same kind of
/// MAC, with labels of its own).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MirrorNote {
    /// The inviter's key's digest: the key of the device that signed the answer the
    /// join verified.
    pub(crate) key: [u8; 32],
    /// The inviter's namespace, which owns the space.
    pub(crate) owner: Name,
    /// The space the offer admitted this device to.
    pub(crate) space: Name,
    /// The inviter's role, last told to the host: re-derived from the members at every
    /// judgement.
    pub(crate) role: Role,
    /// The members left this device out, or the host ended the entry.
    pub(crate) ended: bool,
}

impl MirrorNote {
    /// The note's octets: version, flags, role, key, then the space and owner names
    /// (each a 2-octet length and its Name TLV), then the MAC under `mac_key`.
    pub(crate) fn encode(&self, mac_key: &[u8; 32]) -> Bytes {
        let mut out = Vec::with_capacity(MIRROR_HEAD + 64 + MAC_LEN);
        out.push(MIRROR_VERSION);
        out.push(if self.ended { ENDED } else { 0 });
        out.push(role_octet(self.role));
        out.extend_from_slice(&self.key);
        for name in [&self.space, &self.owner] {
            push_name(&mut out, name);
        }
        let check = mirror_mac_of(mac_key, &out).finalize().into_bytes();
        out.extend_from_slice(&check);
        Bytes::from(out)
    }

    /// The mirror note `bytes` hold, if they are one of the version this device reads
    /// whose MAC checks under `mac_key`.
    pub(crate) fn decode(bytes: &Bytes, mac_key: &[u8; 32]) -> Result<Self, Unread> {
        let body_len = bytes.len().checked_sub(MAC_LEN).ok_or(Unread::Form)?;
        let (body, check) = bytes.split_at(body_len);
        if body.len() < MIRROR_HEAD || body[0] != MIRROR_VERSION {
            return Err(Unread::Form);
        }
        if mirror_mac_of(mac_key, body).verify_slice(check).is_err() {
            return Err(Unread::Check);
        }
        if body[1] & !ENDED != 0 {
            return Err(Unread::Form);
        }
        let role = role_of(body[2])?;
        let key = <[u8; 32]>::try_from(&body[3..MIRROR_HEAD]).map_err(|_| Unread::Form)?;
        let (space, at) = read_name_at(bytes, body, MIRROR_HEAD)?;
        let (owner, at) = read_name_at(bytes, body, at)?;
        if at != body.len() {
            return Err(Unread::Form);
        }
        Ok(Self {
            key,
            owner,
            space,
            role,
            ended: body[1] & ENDED != 0,
        })
    }

    /// What the host is told: the inviter's key, the inviter's namespace as the
    /// space's owner, no date (the entry follows the members).
    pub(crate) fn grant(&self) -> Grant {
        Grant {
            key: self.key,
            namespaces: vec![self.owner.clone()],
            folder: self.space.clone(),
            role: self.role,
            until: None,
        }
    }
}
