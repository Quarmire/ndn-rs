//! The grants an offer's admission makes (spec §19.8): the durable note kept
//! with the use mark, the grants in force ([`Device::grants`]), the judgement
//! of them against the members record in force **for each note's folder** (a
//! person left out of one folder loses that folder's grant alone, a person
//! whose role changed has the grant re-told), the departure mark a held record
//! that lets a person go leaves in the note ([`Device::departures`],
//! [`Device::take_departure`]), and the host's own durable ends and renewals
//! ([`Device::end_grant`], [`Device::end_grant_in`], [`Device::renew_grant`]).
//!
//! A grant is built at **both ends**. The inviter's end is the note above. The
//! joiner's end is the **mirror note** a successful [`Device::join`] keeps
//! (spec §19.8, ndn-link §8.7): the inviter's key (the digest of the key that
//! signed the answer, which the join verified belongs to the offering device
//! under the anchor the code named), the folder, and the inviter's namespace as
//! its owner. It is judged like the inviter's note against the folder's members
//! record in force, with two differences the rule requires: it stands only while
//! that record **lists this device** (by the predicates a join waits on), and
//! its role is **the inviter's** standing in the record (a writer when its
//! namespace is listed as a writer, else a reader: never wider than the record
//! says). It joins [`Device::grants`], is told to the host the same way
//! ([`Introducer::grant`](crate::intro::Introducer::grant) at the join and when
//! a record changes the role, [`Introducer::revoke_grant`](crate::intro::Introducer::revoke_grant)
//! when the record leaves this device out), and **never makes a departure
//! mark**: the person who is let go is told by the inviter, and a mirror grant
//! only admits the inviter's own link. The same notes drive
//! [`Device::joined_folders`] and [`Device::joined_changes`]: what the link to
//! each inviter must route.
//!
//! Notes are the device's own and local: under `/localhost/ndn-data/intro/grant/`
//! (the inviter's) and `/localhost/ndn-data/intro/mirror/` (the joiner's), never
//! served, never on the wire. Their value is the module's fixed-width local
//! form (as the `joined` note's), not a TLV: **no TLV-TYPE number is registered or
//! used for them**. A note ends in a MAC under a key derived from the device's
//! recipient secret, which lives in the key store, not the data store, with
//! labels of its own for each kind of note (so one kind is never read as the
//! other): a note changed in the store (the `ended` flag cleared, a date
//! extended, a role flipped, a departure mark added, cleared or moved) fails its
//! check and is ignored.

use std::sync::Arc;

use bytes::Bytes;
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use ndn_packet::{Name, NameComponent};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::intro::{local_name, local_name_base};
use super::{Device, Inner, St, local};
use crate::collection::Members;
use crate::error::DataError;
use crate::intro::{Departure, Grant, Introducer, JOINED_WRITERS_MAX, JoinedFolder, Role};
use crate::version::{Audience, Timestamp};
use crate::wire::{self, device_of, log_name, parse_log_name};

/// Where the store keeps the grant the own offer `offer`'s admission made:
/// a [`GrantNote`]. Written under the same store barrier as the kept
/// acceptance and the use mark.
fn grant_name(offer: &Name) -> Name {
    local_name("grant", offer)
}

/// The note's version octet. Version 2 notes (no departure mark) are still read.
const NOTE_VERSION: u8 = 3;

/// The version of a note written before departure marks.
const NOTE_VERSION_2: u8 = 2;

/// Flag bits of a note.
const ENDED: u8 = 1;
const DATED: u8 = 2;
/// The note carries a departure mark (version 3, and only on an ended note).
const MARKED: u8 = 4;

/// The fixed head of a note: version, flags, role, `until` (8, big-endian;
/// zero when the note has no date), the key's digest.
const HEAD: usize = 1 + 1 + 1 + 8 + 32;

/// Departure marks one device lets be taken ([`Device::take_departure`]) in a
/// minute: a hostile inviter's stream of `Departure` messages costs this many
/// fetches a minute, no more.
const DEPARTURES_PER_MINUTE: usize = 6;

/// The minute those are counted in, in milliseconds of the device's clock.
const DEPARTURE_WINDOW_MS: u64 = 60_000;

/// The octets of a note's MAC (HMAC-SHA256), which end it.
const MAC_LEN: usize = 32;

/// The domain label of the MAC key's derivation from the recipient secret.
const MAC_KEY_LABEL: &[u8] = b"ndn-data/grant-note/mac-key/1";

/// The domain label of the MAC itself.
const MAC_LABEL: &[u8] = b"ndn-data/grant-note/mac/1";

/// The domain label of the mirror note's MAC key: not the inviter note's, so a
/// MAC made for one kind of note never checks for the other.
const MIRROR_MAC_KEY_LABEL: &[u8] = b"ndn-data/mirror-note/mac-key/1";

/// The domain label of the mirror note's MAC itself.
const MIRROR_MAC_LABEL: &[u8] = b"ndn-data/mirror-note/mac/1";

/// A key derived (HKDF-SHA256, the domain label `label`) from the device's
/// recipient secret. That secret is kept by the key store, never in the data
/// store the notes live in, so whoever can only write the data store cannot
/// make a note that passes.
fn derived_key(st: &St, label: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, st.keys.recipient.expose())
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

/// The key the inviter notes' MAC is made under.
fn mac_key(st: &St) -> Zeroizing<[u8; 32]> {
    derived_key(st, MAC_KEY_LABEL)
}

fn mac_of(key: &[u8; 32], body: &[u8]) -> Hmac<Sha256> {
    mac_under(key, MAC_LABEL, body)
}

/// The key the mirror notes' MAC is made under.
fn mirror_mac_key(st: &St) -> Zeroizing<[u8; 32]> {
    derived_key(st, MIRROR_MAC_KEY_LABEL)
}

fn mirror_mac_of(key: &[u8; 32], body: &[u8]) -> Hmac<Sha256> {
    mac_under(key, MIRROR_MAC_LABEL, body)
}

/// Why a stored value is not a note this device reads.
#[derive(Debug, PartialEq, Eq)]
enum Unread {
    /// A form or version this program does not read.
    Form,
    /// It is a note, but its MAC does not check under this device's key: it
    /// was changed, or written under another secret.
    Check,
}

/// A departure mark a note keeps (spec §19.8): the held members record that
/// let the person go, and by when this device stops showing it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Mark {
    /// The record's log entry name, `<signer device>/32=log/<folder>/seq=<n>`.
    pub(super) record: Name,
    /// By this device's clock: no longer served after it.
    pub(super) until: Timestamp,
}

/// What the store keeps of a grant (spec §19.8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct GrantNote {
    /// The own offer whose admission made it.
    pub(super) offer: Name,
    /// The asker key's public-key digest.
    pub(super) key: [u8; 32],
    /// The asker's namespace, as the join adopted it.
    pub(super) namespace: Name,
    /// The folder the offer admitted it to.
    pub(super) folder: Name,
    /// The role last told to the host: the offer's, then whatever the members
    /// record in force made of it ([`Standing`]).
    pub(super) role: Role,
    /// By this device's clock; `None`: no date, the note follows the members
    /// record.
    pub(super) until: Option<Timestamp>,
    /// A held members record left the person out, or the host ended it
    /// ([`Device::end_grant`]).
    pub(super) ended: bool,
    /// The record that let the person go, when a held record ended the grant
    /// and the policy keeps a mark ([`IntroPolicy::departure_for`]
    /// (crate::intro::IntroPolicy::departure_for)). Never on a note the host
    /// ended, nor on one still in force.
    pub(super) departure: Option<Mark>,
}

/// What the members record held in force for a grant's folder makes of the
/// person.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Standing {
    /// None is held: nothing to judge by.
    Unknown,
    /// A record is held and lists the namespace neither as a writer nor as a
    /// reader.
    Out,
    /// A record is held and admits the namespace in this role (a writer
    /// wins over a reader).
    In(Role),
}

/// What the record `m` makes of the namespace `ns`: a writer, or a reader
/// (prefix match, as device admission does), or out. Only its own writers and
/// readers count: a cut keeps versions, it does not admit.
fn standing_in(m: &crate::collection::Members, ns: &Name) -> Standing {
    if m.writers.iter().any(|p| ns.has_prefix(p)) {
        Standing::In(Role::Writer)
    } else if m
        .readers
        .iter()
        .any(|a| matches!(a, Audience::Person(p) if ns.has_prefix(p)))
    {
        Standing::In(Role::Reader)
    } else {
        Standing::Out
    }
}

impl GrantNote {
    fn encode(&self, mac_key: &[u8; 32]) -> Bytes {
        let mut out = Vec::with_capacity(HEAD + 64 + MAC_LEN);
        out.push(NOTE_VERSION);
        out.push(
            if self.ended { ENDED } else { 0 }
                | if self.until.is_some() { DATED } else { 0 }
                | if self.departure.is_some() { MARKED } else { 0 },
        );
        out.push(match self.role {
            Role::Reader => 0,
            Role::Writer => 1,
        });
        out.extend_from_slice(&self.until.map_or(0, |t| t.0).to_be_bytes());
        out.extend_from_slice(&self.key);
        for name in [&self.offer, &self.folder, &self.namespace] {
            let tlv = name.encode_to_tlv();
            out.extend_from_slice(&(tlv.len() as u16).to_be_bytes());
            out.extend_from_slice(&tlv);
        }
        if let Some(mark) = &self.departure {
            out.extend_from_slice(&mark.until.0.to_be_bytes());
            let tlv = mark.record.encode_to_tlv();
            out.extend_from_slice(&(tlv.len() as u16).to_be_bytes());
            out.extend_from_slice(&tlv);
        }
        let check = mac_of(mac_key, &out).finalize().into_bytes();
        out.extend_from_slice(&check);
        Bytes::from(out)
    }

    /// The note `bytes` hold, if they are one of a version this device reads
    /// (3, or 2: no departure mark) whose MAC checks under `mac_key`.
    fn decode(bytes: &Bytes, mac_key: &[u8; 32]) -> Result<Self, Unread> {
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
        let role = match body[2] {
            0 => Role::Reader,
            1 => Role::Writer,
            _ => return Err(Unread::Form),
        };
        let dated = u64::from_be_bytes(body[3..11].try_into().map_err(|_| Unread::Form)?);
        let until = (flags & DATED != 0).then_some(Timestamp(dated));
        let key = <[u8; 32]>::try_from(&body[11..HEAD]).map_err(|_| Unread::Form)?;
        let mut at = HEAD;
        let mut names = Vec::with_capacity(4);
        let mut mark_until = None;
        let wanted = if flags & MARKED != 0 { 4 } else { 3 };
        for i in 0..wanted {
            if i == 3 {
                let t = body.get(at..at + 8).ok_or(Unread::Form)?;
                mark_until = Some(Timestamp(u64::from_be_bytes(
                    t.try_into().map_err(|_| Unread::Form)?,
                )));
                at += 8;
            }
            let len = u16::from_be_bytes(
                body.get(at..at + 2)
                    .ok_or(Unread::Form)?
                    .try_into()
                    .map_err(|_| Unread::Form)?,
            ) as usize;
            at += 2;
            let tlv = body
                .get(at..at.checked_add(len).ok_or(Unread::Form)?)
                .ok_or(Unread::Form)?;
            names.push(Name::decode_from_tlv(bytes.slice_ref(tlv)).map_err(|_| Unread::Form)?);
            at += len;
        }
        if at != body.len() {
            return Err(Unread::Form);
        }
        let departure = match (names.len() == 4, mark_until) {
            (true, Some(until)) => Some(Mark {
                record: names.pop().ok_or(Unread::Form)?,
                until,
            }),
            _ => None,
        };
        let namespace = names.pop().ok_or(Unread::Form)?;
        let folder = names.pop().ok_or(Unread::Form)?;
        let offer = names.pop().ok_or(Unread::Form)?;
        Ok(Self {
            offer,
            key,
            namespace,
            folder,
            role,
            until,
            ended: flags & ENDED != 0,
            departure,
        })
    }

    /// What the host is told, in the role the note holds.
    pub(super) fn grant(&self) -> Grant {
        Grant {
            key: self.key,
            namespaces: vec![self.namespace.clone()],
            folder: self.folder.clone(),
            role: self.role,
            until: self.until,
        }
    }

    /// The departure the note's mark makes, if it has one.
    fn departure(&self) -> Option<Departure> {
        self.departure.as_ref().map(|mark| Departure {
            key: self.key,
            namespaces: vec![self.namespace.clone()],
            folder: self.folder.clone(),
            record: mark.record.clone(),
            until: mark.until,
        })
    }

    /// Whether the note's own date, if it has one, is past `now`.
    fn dated_out(&self, now: Timestamp) -> bool {
        self.until.is_some_and(|t| t <= now)
    }

    /// What the members record `st` holds in force for the folder makes of the
    /// namespace: a writer, or a reader (prefix match, as device admission
    /// does), or out.
    fn standing(&self, st: &St) -> Standing {
        match st
            .folders
            .get(&self.folder)
            .and_then(|f| f.members.as_ref())
        {
            Some(m) => standing_in(m, &self.namespace),
            None => Standing::Unknown,
        }
    }

    /// The held members record of the folder's line that lets the person go
    /// (spec §19.8), by its log entry name: the record that **first** left the
    /// namespace out of the run that stands. Reading the revisions held from the
    /// highest down, while a revision holds a record whose own writers and
    /// readers leave the namespace out (lowest signer key first), that record is
    /// the candidate; the run ends at the first revision below whose records all
    /// list the namespace, which is where the person was last a member. The
    /// lowest revision of the run is the record: a later record of the run that
    /// leaves them out as well may list the others' later admissions (a
    /// membership the person must not be handed), and one that readmits them ends
    /// the run and is never named. Failing a record that leaves them out by its
    /// own lists (a merge removed the person through a cut), the same over the
    /// records with a cut of a prefix of the namespace, from the highest revision
    /// that has one. `None` when no held record does either: no mark is made then.
    fn letting_go_record(&self, st: &St) -> Option<Name> {
        use std::collections::BTreeMap;

        use crate::collection::Members;
        use crate::version::Writer;

        type Signers = BTreeMap<Writer, super::LineRecord>;
        // The lowest revision of the run `groups` (highest first) begins with, of
        // the records `leaves` picks, lowest signer first in a revision.
        fn first_of_run<'a>(
            groups: impl Iterator<Item = &'a Signers>,
            leaves: impl Fn(&Members) -> bool,
        ) -> Option<(&'a Writer, u64)> {
            let mut found = None;
            for signers in groups {
                let Some((writer, held)) = signers.iter().find(|(_, h)| leaves(&h.record)) else {
                    break;
                };
                found = Some((writer, held.seq));
            }
            found
        }
        let line = &st.folders.get(&self.folder)?.line;
        let ns = &self.namespace;
        let by_lists = |m: &Members| standing_in(m, ns) == Standing::Out;
        let by_cut = |m: &Members| m.cuts.iter().any(|c| ns.has_prefix(&c.of));
        let (writer, seq) = first_of_run(line.records.values().rev(), by_lists).or_else(|| {
            first_of_run(
                line.records
                    .values()
                    .rev()
                    .skip_while(|signers| !signers.values().any(|h| by_cut(&h.record))),
                by_cut,
            )
        })?;
        device_of(writer.key()).map(|d| log_name(&d, Some(&self.folder), seq))
    }
}

/// The mirror note's version octet.
const MIRROR_VERSION: u8 = 1;

/// The fixed head of a mirror note: version, flags (only [`ENDED`]), role, the
/// inviter key's digest.
const MIRROR_HEAD: usize = 1 + 1 + 1 + 32;

/// Where the store keeps the mirror note of the folder `folder` for the inviter
/// key `key`: `/localhost/ndn-data/intro/mirror/<folder's Name TLV><key>`. One
/// note for each `(inviter key, folder)`; a second join of the same folder by
/// the same key writes the same name, another key another one.
fn mirror_name(folder: &Name, key: &[u8; 32]) -> Name {
    local_name("mirror", folder)
        .append_component(NameComponent::generic(Bytes::copy_from_slice(key)))
}

/// What the joiner's device keeps of a grant it was given (spec §19.8): the
/// mirror of the inviter's [`GrantNote`], kept the same way (under the same
/// kind of MAC, with labels of its own).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct MirrorNote {
    /// The inviter's key's digest: the key of the device that signed the answer
    /// the join verified.
    pub(super) key: [u8; 32],
    /// The inviter's namespace, which owns the folder.
    pub(super) owner: Name,
    /// The folder the offer admitted this device to.
    pub(super) folder: Name,
    /// The inviter's role, last told to the host: re-derived from the record in
    /// force at every judgement ([`Inner::mirror_standing`]).
    pub(super) role: Role,
    /// A held record left this device out, or the host ended the entry
    /// ([`Device::end_grant`]).
    pub(super) ended: bool,
}

impl MirrorNote {
    /// The note's octets: version, flags, role, key, then the folder and owner
    /// names (each a 2-octet length and its Name TLV), then the MAC under
    /// `mac_key`.
    pub(super) fn encode(&self, mac_key: &[u8; 32]) -> Bytes {
        let mut out = Vec::with_capacity(MIRROR_HEAD + 64 + MAC_LEN);
        out.push(MIRROR_VERSION);
        out.push(if self.ended { ENDED } else { 0 });
        out.push(match self.role {
            Role::Reader => 0,
            Role::Writer => 1,
        });
        out.extend_from_slice(&self.key);
        for name in [&self.folder, &self.owner] {
            let tlv = name.encode_to_tlv();
            out.extend_from_slice(&(tlv.len() as u16).to_be_bytes());
            out.extend_from_slice(&tlv);
        }
        let check = mirror_mac_of(mac_key, &out).finalize().into_bytes();
        out.extend_from_slice(&check);
        Bytes::from(out)
    }

    /// The mirror note `bytes` hold, if they are one of the version this device
    /// reads whose MAC checks under `mac_key`.
    fn decode(bytes: &Bytes, mac_key: &[u8; 32]) -> Result<Self, Unread> {
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
        let role = match body[2] {
            0 => Role::Reader,
            1 => Role::Writer,
            _ => return Err(Unread::Form),
        };
        let key = <[u8; 32]>::try_from(&body[3..MIRROR_HEAD]).map_err(|_| Unread::Form)?;
        let mut at = MIRROR_HEAD;
        let mut names = Vec::with_capacity(2);
        for _ in 0..2 {
            let len = u16::from_be_bytes(
                body.get(at..at + 2)
                    .ok_or(Unread::Form)?
                    .try_into()
                    .map_err(|_| Unread::Form)?,
            ) as usize;
            at += 2;
            let tlv = body
                .get(at..at.checked_add(len).ok_or(Unread::Form)?)
                .ok_or(Unread::Form)?;
            names.push(Name::decode_from_tlv(bytes.slice_ref(tlv)).map_err(|_| Unread::Form)?);
            at += len;
        }
        if at != body.len() {
            return Err(Unread::Form);
        }
        let owner = names.pop().ok_or(Unread::Form)?;
        let folder = names.pop().ok_or(Unread::Form)?;
        Ok(Self {
            key,
            owner,
            folder,
            role,
            ended: body[1] & ENDED != 0,
        })
    }

    /// What the host is told: the inviter's key, the inviter's namespace as the
    /// folder's owner, no date (the entry follows the record).
    fn grant(&self) -> Grant {
        Grant {
            key: self.key,
            namespaces: vec![self.owner.clone()],
            folder: self.folder.clone(),
            role: self.role,
            until: None,
        }
    }
}

/// What the members record held in force for a mirror note's folder makes of
/// the note and of this device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MirrorStanding {
    /// No record of the folder is held: nothing to judge by, so nothing is
    /// granted.
    Unknown,
    /// A record is held and does not list this device (as a writer, or as a
    /// reader where the folder is sealed).
    Out,
    /// A record is held and lists this device: `entry` is the inviter's role in
    /// it (the mirror grant's), `device` this device's (the joined folder's).
    In { entry: Role, device: Role },
}

/// A take of a folder's departure record under way
/// ([`Intros::departing`](super::intro::Intros)), let go as it is dropped.
struct Departing<'a> {
    inner: &'a Inner,
    folder: Name,
}

impl Drop for Departing<'_> {
    fn drop(&mut self) {
        self.inner.st.lock().intro.departing.remove(&self.folder);
    }
}

impl Inner {
    /// The note of a grant for the own offer `offer`'s admission of `key`, as
    /// [`IntroPolicy::grant_for`](crate::intro::IntroPolicy::grant_for) bounds
    /// it from now; `None` when that is `Some(ZERO)`. Not yet kept.
    pub(super) fn grant_note(
        &self,
        offer: &Name,
        key: [u8; 32],
        namespace: &Name,
        folder: &Name,
        role: Role,
    ) -> Option<GrantNote> {
        let until = match self.config.intro.grant_for {
            Some(d) if d.is_zero() => return None,
            Some(d) => {
                let ms = u64::try_from(d.as_millis()).unwrap_or(u64::MAX);
                Some(Timestamp((self.config.clock)().0.saturating_add(ms)))
            }
            None => None,
        };
        Some(GrantNote {
            offer: offer.clone(),
            key,
            namespace: namespace.clone(),
            folder: folder.clone(),
            role,
            until,
            ended: false,
            departure: None,
        })
    }

    /// Put `note` into the store; durable at the next barrier (the one under
    /// the use mark, or [`Inner::barrier`]).
    pub(super) fn keep_grant(&self, note: &GrantNote) {
        let value = note.encode(&mac_key(&self.st.lock()));
        self.store.insert(grant_name(&note.offer), value);
    }

    /// Every grant note kept that this device reads, held here or not. One
    /// that fails its MAC, or that this version does not read, is ignored —
    /// and said so, with why.
    fn grant_notes(&self, st: &St) -> Vec<GrantNote> {
        let base = local_name_base("grant");
        let key = mac_key(st);
        self.store
            .scan_under(&base, 0)
            .into_iter()
            .filter_map(|(name, value)| match GrantNote::decode(&value, &key) {
                Ok(note) if grant_name(&note.offer) == name => Some(note),
                Ok(_) => {
                    tracing::warn!(%name, "a grant note is kept under a name that is not its offer's: ignored");
                    None
                }
                Err(Unread::Check) => {
                    tracing::warn!(%name, "a grant note fails its integrity check (it was changed in the store, or written under another device secret): ignored, so the person it names has no grant from it; to link with them again, offer the folder to them again");
                    None
                }
                Err(Unread::Form) => {
                    tracing::warn!(%name, "a grant note this version does not read: ignored, so the person it names has no grant from it; to link with them again, offer the folder to them again");
                    None
                }
            })
            .collect()
    }

    /// The notes of grants the use marks held bear out: the offer is used by
    /// the very key the note names.
    fn used_grants(&self, st: &St) -> Vec<GrantNote> {
        if st.intro.used.is_empty() {
            return Vec::new();
        }
        self.grant_notes(st)
            .into_iter()
            .filter(|n| {
                st.intro
                    .used
                    .get(&n.offer)
                    .is_some_and(|(_, digest)| *digest == n.key)
            })
            .collect()
    }

    /// The grants in force ([`Device::grants`]): each in the role the members
    /// record in force makes of the person now, then the mirror entries (the
    /// grants this device was given by joining) in the role the record in force
    /// makes of the inviter.
    fn live_grants(&self) -> Vec<Grant> {
        let now = (self.config.clock)();
        let st = self.st.lock();
        let mut grants: Vec<Grant> = self
            .used_grants(&st)
            .into_iter()
            .filter(|n| !n.ended && !n.dated_out(now))
            .filter_map(|n| match n.standing(&st) {
                Standing::In(role) => Some(GrantNote { role, ..n }.grant()),
                Standing::Out | Standing::Unknown => None,
            })
            .collect();
        grants.extend(
            self.live_mirrors(&st)
                .into_iter()
                .map(|(note, _)| note.grant()),
        );
        grants
    }

    /// Take the one place grant notes are changed from: a change reads the
    /// notes as the one before left them.
    async fn hold_grants(&self) -> tokio::sync::OwnedMutexGuard<()> {
        let one = Arc::clone(&self.st.lock().intro.notes);
        one.lock_owned().await
    }

    /// Judge the grants against the members records held (spec §19.8), each
    /// note against the record in force **for its own folder**. An inviter's
    /// note is judged as [`Self::judge_inviter_notes`] says, a mirror note as
    /// [`Self::judge_mirrors`] says; then the joined folders are published
    /// ([`Self::publish_joined`]), whether or not this device has a host or an
    /// offer used: a joiner's routes follow the record on its own.
    ///
    /// Run after every record taken, from any device of the namespace, and at a
    /// start. A failure to make a note durable leaves the next run to judge
    /// again.
    pub(super) async fn judge_grants(self: &Arc<Self>) {
        let host = self.config.introducer.clone();
        let _one = self.hold_grants().await;
        if let Some(host) = &host
            && !self.st.lock().intro.used.is_empty()
        {
            self.judge_inviter_notes(host).await;
        }
        self.judge_mirrors(host.as_ref()).await;
        self.publish_joined();
    }

    /// The inviter's notes judged against the record in force for each note's
    /// folder: it is held and
    ///
    /// - lists the namespace neither as a writer nor as a reader: the host is
    ///   told, in memory, first — of the departure
    ///   ([`Introducer::departure`](crate::intro::Introducer::departure)) when
    ///   [`IntroPolicy::departure_for`](crate::intro::IntroPolicy::departure_for)
    ///   keeps a mark and a held record that lets the person go is found, then
    ///   of the end of this folder's grant alone
    ///   ([`Introducer::revoke_grant`](crate::intro::Introducer::revoke_grant),
    ///   with the key and the folder) —, then the note is marked ended (with the
    ///   departure mark, under the same MAC) durably;
    /// - lists it in another role than the grant bears: the note takes the
    ///   role, the host is told again ([`Introducer::grant`](crate::intro::Introducer::grant),
    ///   in memory, first) and the note is made durable.
    ///
    /// The person's grants of other folders are not touched. Called with the
    /// notes held ([`Self::hold_grants`]).
    async fn judge_inviter_notes(&self, host: &Arc<dyn Introducer>) {
        let now = (self.config.clock)();
        let (ending, retold): (Vec<GrantNote>, Vec<GrantNote>) = {
            let st = self.st.lock();
            let mut ending = Vec::new();
            let mut retold = Vec::new();
            for n in self.used_grants(&st).into_iter().filter(|n| !n.ended) {
                match n.standing(&st) {
                    Standing::Out => {
                        let departure = self.departure_mark(&st, &n, now);
                        ending.push(GrantNote { departure, ..n });
                    }
                    Standing::In(role) if role != n.role => retold.push(GrantNote { role, ..n }),
                    Standing::In(_) | Standing::Unknown => {}
                }
            }
            (ending, retold)
        };
        for mut note in ending {
            // The host first: in memory, and the safe direction. A slow or
            // failing flush must not delay the link layer's end. The departure
            // goes before the end, so a link layer that narrows its link at its
            // last entry's end already holds the mark.
            if let Some(departure) = note.departure() {
                host.departure(&departure);
            }
            host.revoke_grant(&note.key, &note.folder);
            note.ended = true;
            self.keep_grant(&note);
            if !self.barrier().await {
                tracing::debug!(offer = %note.offer, "the device stopped before the end of a grant was durable; the next start judges it again");
                continue;
            }
            tracing::info!(offer = %note.offer, folder = %note.folder, namespace = %note.namespace, record = ?note.departure.as_ref().map(|m| m.record.to_string()), "a members record held leaves the person out: its grant to link ended");
        }
        for note in retold {
            host.grant(&note.grant());
            self.keep_grant(&note);
            if !self.barrier().await {
                tracing::debug!(offer = %note.offer, "the device stopped before a grant's new role was durable; the next start judges it again");
                continue;
            }
            tracing::info!(offer = %note.offer, folder = %note.folder, namespace = %note.namespace, role = ?note.role, "a members record held changes the person's role: its grant to link now bears it");
        }
    }

    /// Put the mirror note `note` into the store; durable at the next barrier.
    fn keep_mirror_note(&self, note: &MirrorNote) {
        let value = note.encode(&mirror_mac_key(&self.st.lock()));
        self.store
            .insert(mirror_name(&note.folder, &note.key), value);
    }

    /// Every mirror note kept that this device reads, ended or not, held here
    /// or not. One that fails its MAC, or that this version does not read, is
    /// ignored — and said so, with why.
    fn mirror_notes(&self, st: &St) -> Vec<MirrorNote> {
        let base = local_name_base("mirror");
        let key = mirror_mac_key(st);
        self.store
            .scan_under(&base, 0)
            .into_iter()
            .filter_map(|(name, value)| match MirrorNote::decode(&value, &key) {
                Ok(note) if mirror_name(&note.folder, &note.key) == name => Some(note),
                Ok(_) => {
                    tracing::warn!(%name, "a mirror note is kept under a name that is not its folder's and key's: ignored");
                    None
                }
                Err(Unread::Check) => {
                    tracing::warn!(%name, "a mirror note fails its integrity check (it was changed in the store, or written under another device secret): ignored, so the inviter it names is granted no link on its account; to link with them again, join again with a new offer");
                    None
                }
                Err(Unread::Form) => {
                    tracing::warn!(%name, "a mirror note this version does not read: ignored, so the inviter it names is granted no link on its account; to link with them again, join again with a new offer");
                    None
                }
            })
            .collect()
    }

    /// This device's role in the members record `m` of a folder, if `m` lists
    /// it: by the predicates a join waits on ([`Inner::admission_missing`]) —
    /// a writer when a writer entry is a prefix of its key, else a reader —,
    /// and, when the folder is sealed (the record starts an epoch), only while
    /// the record's audience admits it ([`Inner::admits_record`]). `None`: the
    /// record leaves this device out.
    fn device_role_in(&self, st: &St, m: &Members) -> Option<Role> {
        if m.epoch.is_some() && !self.admits_record(st, m, &self.device, &self.ns) {
            return None;
        }
        Some(if m.lists_writer(self.writer.key()) {
            Role::Writer
        } else {
            Role::Reader
        })
    }

    /// What the record in force for `note`'s folder makes of the note and of
    /// this device: the entry stands only while the record lists this device;
    /// its role is the inviter's (a writer when the owner's namespace lies
    /// under a listed writer, else a reader — never wider than the record
    /// says).
    fn mirror_standing(&self, st: &St, note: &MirrorNote) -> MirrorStanding {
        let Some(m) = st
            .folders
            .get(&note.folder)
            .and_then(|f| f.members.as_ref())
        else {
            return MirrorStanding::Unknown;
        };
        match self.device_role_in(st, m) {
            None => MirrorStanding::Out,
            Some(device) => MirrorStanding::In {
                entry: if m.writers.iter().any(|p| note.owner.has_prefix(p)) {
                    Role::Writer
                } else {
                    Role::Reader
                },
                device,
            },
        }
    }

    /// The mirror entries in force: each note not ended whose folder's record in
    /// force lists this device, in the inviter's role the record gives now, with
    /// this device's own role.
    fn live_mirrors(&self, st: &St) -> Vec<(MirrorNote, Role)> {
        self.mirror_notes(st)
            .into_iter()
            .filter(|n| !n.ended)
            .filter_map(|n| match self.mirror_standing(st, &n) {
                MirrorStanding::In { entry, device } => {
                    Some((MirrorNote { role: entry, ..n }, device))
                }
                MirrorStanding::Out | MirrorStanding::Unknown => None,
            })
            .collect()
    }

    /// The mirror notes judged against the record in force for each note's
    /// folder, and the host told **in memory, first**, as for the inviter's:
    ///
    /// - the record leaves this device out: [`Introducer::revoke_grant`] with the
    ///   inviter's key and the folder, then the note is marked ended durably.
    ///   **Never [`Introducer::departure`]**: the person who is let go is told by
    ///   the inviter, not by the one let in;
    /// - the record gives the inviter another role than the note bears: the note
    ///   takes it, [`Introducer::grant`] tells the host again and the note is
    ///   made durable.
    ///
    /// No record held for the folder: nothing is done (nothing to judge by).
    /// Without a host the notes are still kept right; only the telling is
    /// skipped. Called with the notes held ([`Self::hold_grants`]).
    async fn judge_mirrors(&self, host: Option<&Arc<dyn Introducer>>) {
        let (ending, retold): (Vec<MirrorNote>, Vec<MirrorNote>) = {
            let st = self.st.lock();
            let mut ending = Vec::new();
            let mut retold = Vec::new();
            for n in self.mirror_notes(&st).into_iter().filter(|n| !n.ended) {
                match self.mirror_standing(&st, &n) {
                    MirrorStanding::Out => ending.push(n),
                    MirrorStanding::In { entry, .. } if entry != n.role => {
                        retold.push(MirrorNote { role: entry, ..n });
                    }
                    MirrorStanding::In { .. } | MirrorStanding::Unknown => {}
                }
            }
            (ending, retold)
        };
        for mut note in ending {
            if let Some(host) = host {
                host.revoke_grant(&note.key, &note.folder);
            }
            note.ended = true;
            self.keep_mirror_note(&note);
            // Published before the flush: the routes follow the memory.
            self.publish_joined();
            if !self.barrier().await {
                tracing::debug!(folder = %note.folder, "the device stopped before the end of a mirror grant was durable; the next start judges it again");
                continue;
            }
            tracing::info!(folder = %note.folder, owner = %note.owner, "a members record held leaves this device out: the inviter's mirror grant to link ended");
        }
        for note in retold {
            if let Some(host) = host {
                host.grant(&note.grant());
            }
            self.keep_mirror_note(&note);
            if !self.barrier().await {
                tracing::debug!(folder = %note.folder, "the device stopped before a mirror grant's new role was durable; the next start judges it again");
                continue;
            }
            tracing::info!(folder = %note.folder, owner = %note.owner, role = ?note.role, "a members record held changes the inviter's role: its mirror grant to link now bears it");
        }
    }

    /// The folders this device joined, derived now ([`Device::joined_folders`]):
    /// for each live mirror entry, the inviter, owner, folder, this device's role
    /// in the record in force and the other writers' namespaces — sorted by
    /// folder, then inviter.
    pub(super) fn joined_list(&self, st: &St) -> Vec<JoinedFolder> {
        let mut out: Vec<JoinedFolder> = self
            .live_mirrors(st)
            .into_iter()
            .map(|(note, role)| JoinedFolder {
                inviter: note.key,
                writers: self.joined_writers(st, &note.owner, &note.folder),
                owner: note.owner,
                folder: note.folder,
                role,
            })
            .collect();
        out.sort_by(|a, b| (&a.folder, &a.inviter).cmp(&(&b.folder, &b.inviter)));
        out
    }

    /// The namespaces of the other writers of `folder` a link to its inviter
    /// routes: [`Inner::writer_namespaces_of`] minus the owner's, this device's
    /// own namespace and every namespace above or below it (a record cannot
    /// divert this device's own names, nor `/` or a broad parent of them), only
    /// namespaces, at most [`JOINED_WRITERS_MAX`], in order.
    fn joined_writers(&self, st: &St, owner: &Name, folder: &Name) -> Vec<Name> {
        self.writer_namespaces_of(st, folder)
            .into_iter()
            .filter(|w| {
                wire::is_namespace(w)
                    && w != owner
                    && !w.has_prefix(&self.ns)
                    && !self.ns.has_prefix(w)
            })
            .take(JOINED_WRITERS_MAX)
            .collect()
    }

    /// Tell the watchers of [`Device::joined_changes`] the list changed: derive
    /// it now and, only when it differs from the one the generation stands for,
    /// raise the generation (never repeating a value). Called where grants are
    /// judged, at a join and at a host end, with the notes held.
    pub(super) fn publish_joined(&self) {
        let mut st = self.st.lock();
        let list = self.joined_list(&st);
        let super::intro::Intros {
            joined_changes,
            joined_seen,
            ..
        } = &mut st.intro;
        joined_changes.send_if_modified(|generation| {
            if *joined_seen == list {
                return false;
            }
            *joined_seen = list;
            *generation += 1;
            true
        });
    }

    /// Keep the mirror note of a join that succeeded (spec §19.8): the inviter's
    /// `key` (the digest of the key that signed its answer, verified to belong to
    /// the offering device under the anchor the code named), `owner` (its
    /// namespace) and `folder`, once the record that admits this device is held
    /// ([`Inner::await_admission`]). The role is the inviter's in that record.
    /// Durable first, then the host is told ([`Introducer::grant`]) and the
    /// joined folders are published. A second join of the same folder by the same
    /// key replaces the note (un-ends it); another key is another entry.
    ///
    /// No note is kept, and why is said, when `folder` is not under the inviter's
    /// own namespace (the folder's owner is the inviter's namespace, or the
    /// inviter would be granted a link into a folder it does not own), or when
    /// the record in force no longer lists this device (the record already left
    /// it out: nothing is granted).
    ///
    /// # Errors
    /// [`DataError::Local`] when the device stopped before the note was durable.
    pub(super) async fn keep_mirror(
        &self,
        key: [u8; 32],
        owner: &Name,
        folder: &Name,
    ) -> Result<(), DataError> {
        if wire::namespace_of(folder).as_ref() != Some(owner) {
            tracing::warn!(%folder, %owner, "the offer's folder is not under the inviter's own namespace: no mirror grant is kept, so the inviter is not admitted to link back on its account; join a folder of the inviter's namespace");
            return Ok(());
        }
        let _one = self.hold_grants().await;
        let note = {
            let st = self.st.lock();
            let probe = MirrorNote {
                key,
                owner: owner.clone(),
                folder: folder.clone(),
                role: Role::Reader,
                ended: false,
            };
            match self.mirror_standing(&st, &probe) {
                MirrorStanding::In { entry, .. } => MirrorNote {
                    role: entry,
                    ..probe
                },
                MirrorStanding::Out | MirrorStanding::Unknown => {
                    tracing::warn!(%folder, "the members record in force no longer lists this device: no mirror grant is kept; ask the inviter for a new offer");
                    return Ok(());
                }
            }
        };
        self.keep_mirror_note(&note);
        if !self.barrier().await {
            return Err(local(
                "the device stopped before the join's mirror grant was durable: join again with \
                 the same code once the device runs (the offer answers the device it admitted)",
            ));
        }
        if let Some(host) = &self.config.introducer {
            host.grant(&note.grant());
        }
        self.publish_joined();
        tracing::info!(%folder, %owner, role = ?note.role, "joined: the inviter may link back for this folder");
        Ok(())
    }

    /// The departure mark the end of `note` by a held record makes (spec
    /// §19.8): the record that lets the person go and the date by this device's
    /// clock; `None` when the policy keeps no mark
    /// ([`IntroPolicy::departure_for`](crate::intro::IntroPolicy::departure_for)
    /// is zero) or no held record of the folder's line leaves the person out.
    fn departure_mark(&self, st: &St, note: &GrantNote, now: Timestamp) -> Option<Mark> {
        let keep = self.config.intro.departure_for;
        if keep.is_zero() {
            return None;
        }
        let record = note.letting_go_record(st)?;
        let ms = u64::try_from(keep.as_millis()).unwrap_or(u64::MAX);
        Some(Mark {
            record,
            until: Timestamp(now.0.saturating_add(ms)),
        })
    }

    /// The departure marks in force ([`Device::departures`]): of ended notes
    /// whose MAC checks, not past their date, and not superseded by a live
    /// grant of the same key for the same folder (the person was invited again).
    fn live_departures(&self) -> Vec<Departure> {
        let now = (self.config.clock)();
        let st = self.st.lock();
        let notes = self.used_grants(&st);
        let mut marks: Vec<Departure> = notes
            .iter()
            .filter(|n| n.ended)
            .filter_map(GrantNote::departure)
            .filter(|d| d.until > now)
            .filter(|d| {
                !notes.iter().any(|n| {
                    !n.ended && !n.dated_out(now) && n.key == d.key && n.folder == d.folder
                })
            })
            .collect();
        marks.sort_by(|a, b| (&a.key, &a.folder, &a.record).cmp(&(&b.key, &b.folder, &b.record)));
        marks
    }

    /// The host ends the grants of `key` ([`Device::end_grant`]), all of them,
    /// or only those for `folder` ([`Device::end_grant_in`]): the inviter's notes
    /// **and** the mirror notes of that key (and folder). The host ended them
    /// itself: no departure mark is made, and the host is not told.
    async fn end_grant(
        self: &Arc<Self>,
        key: &[u8; 32],
        folder: Option<&Name>,
    ) -> Result<bool, DataError> {
        let _one = self.hold_grants().await;
        let (live, mirrors): (Vec<GrantNote>, Vec<MirrorNote>) = {
            let st = self.st.lock();
            (
                self.used_grants(&st)
                    .into_iter()
                    .filter(|n| n.key == *key && !n.ended && folder.is_none_or(|f| n.folder == *f))
                    .collect(),
                self.mirror_notes(&st)
                    .into_iter()
                    .filter(|n| n.key == *key && !n.ended && folder.is_none_or(|f| n.folder == *f))
                    .collect(),
            )
        };
        if live.is_empty() && mirrors.is_empty() {
            return Ok(false);
        }
        for mut note in live {
            note.ended = true;
            note.departure = None;
            self.keep_grant(&note);
            tracing::info!(offer = %note.offer, folder = %note.folder, namespace = %note.namespace, "the host ended a grant to link");
        }
        for mut note in mirrors {
            note.ended = true;
            self.keep_mirror_note(&note);
            tracing::info!(folder = %note.folder, owner = %note.owner, "the host ended a mirror grant to link");
        }
        // The routes follow the memory; the flush below makes the end durable.
        self.publish_joined();
        if !self.barrier().await {
            return Err(local(
                "the device stopped before the end of the grant was durable: end it again once \
                 the device runs, or the grant stands at the next start",
            ));
        }
        Ok(true)
    }

    /// The departed person's side ([`Device::take_departure`]): fetch `record`,
    /// a members record of `folder`, and take it as any held record.
    ///
    /// Only when the device that told it (`from`) lies under the namespace of
    /// `folder`, this device holds a members record line for `folder` (it is,
    /// or was, a member), `record` is a log entry name whose subject is
    /// `folder` and whose device lies under a namespace this device holds a
    /// trust context of, no other take for `folder` is in flight, and fewer
    /// than [`DEPARTURES_PER_MINUTE`] were begun in the last minute. What is
    /// fetched is validated, merged and judged as every record is; the name is
    /// a hint only, so an inviter that names another record gets nothing taken
    /// that the member could not have fetched by any other path.
    pub(super) async fn take_departure(
        self: &Arc<Self>,
        from: &Name,
        folder: &Name,
        record: &Name,
    ) -> Result<(), DataError> {
        let refuse = |why: String| DataError::BadRequest {
            name: record.clone(),
            why,
        };
        let Some(owner) = crate::wire::namespace_of(folder) else {
            return Err(refuse(format!(
                "{folder} is no folder name (<namespace>/32=data[/<path>]); a departure names the \
                 folder the members record governs: ignore a hint with another name"
            )));
        };
        if !from.has_prefix(&owner) {
            return Err(refuse(format!(
                "the hint came from {from}, which lies under no namespace of {folder} ({owner}): \
                 only a device of the folder's own namespace lets a member go of it, so this \
                 device ignores a hint from another; ask the person who invited you (a device of \
                 {owner}) to invite you again if you were let go"
            )));
        }
        let Some(log) = parse_log_name(record).filter(|l| l.subject.as_ref() == Some(folder))
        else {
            return Err(refuse(format!(
                "{record} is no log entry of {folder} (<device>/32=log/<folder>/seq=<n>), so it \
                 is no members record of that folder: ignore a hint that names anything else"
            )));
        };
        // Whether `record` is a members record of `folder`'s line held here.
        let holds_record = |st: &St| {
            st.folders.get(folder).is_some_and(|f| {
                f.line.records.values().any(|signers| {
                    signers.iter().any(|(w, h)| {
                        h.seq == log.seq && device_of(w.key()).as_ref() == Some(&log.device)
                    })
                })
            })
        };
        let guard = {
            let mut st = self.st.lock();
            if !st
                .folders
                .get(folder)
                .is_some_and(|f| f.members.is_some() || f.line.own.is_some())
            {
                return Err(refuse(format!(
                    "no members record of {folder} is held here, so this device is no member of \
                     it and has nothing to be let go of: join the folder first, or ignore the \
                     hint"
                )));
            }
            let held = log.device.has_prefix(&self.ns)
                || self
                    .validator
                    .keyring()
                    .contexts()
                    .iter()
                    .any(|c| log.device.has_prefix(c.namespace()));
            if !held {
                return Err(refuse(format!(
                    "the record's device {} lies under no namespace this device holds a trust \
                     context of, so a record it signed cannot be checked here: ignore the hint",
                    log.device
                )));
            }
            if holds_record(&st) {
                return Ok(());
            }
            if st.intro.departing.contains(folder) {
                return Err(DataError::NotReady {
                    name: record.clone(),
                    why: format!(
                        "a departure record of {folder} is being fetched already: wait for it, \
                         then ask again if the folder's members still list this device"
                    ),
                });
            }
            let now = (self.config.clock)();
            let window = &mut st.intro.departures_begun;
            while window
                .front()
                .is_some_and(|t| now.0.saturating_sub(t.0) >= DEPARTURE_WINDOW_MS)
            {
                window.pop_front();
            }
            if window.len() >= DEPARTURES_PER_MINUTE {
                return Err(DataError::NotReady {
                    name: record.clone(),
                    why: format!(
                        "this device began {DEPARTURES_PER_MINUTE} departure fetches in the last \
                         minute, the most it takes: ask again in a minute"
                    ),
                });
            }
            window.push_back(now);
            st.intro.departing.insert(folder.clone());
            Departing {
                inner: self,
                folder: folder.clone(),
            }
        };
        let got = self.take_fetched(record.clone(), None).await;
        drop(guard);
        let held = holds_record(&self.st.lock());
        match (got, held) {
            (true, true) => Ok(()),
            (true, false) => Err(refuse(format!(
                "{record} was fetched and is held, but it is no members record of {folder}: \
                 ignore a hint that names anything else"
            ))),
            (false, _) => Err(DataError::NotReady {
                name: record.clone(),
                why: format!(
                    "{record} could not be fetched and verified from the link this hint came \
                     over, or from the devices of its namespace: ask again once the link is up"
                ),
            }),
        }
    }

    /// The host sets the date of the grants of `key` ([`Device::renew_grant`]).
    async fn renew_grant(
        self: &Arc<Self>,
        key: &[u8; 32],
        until: Option<Timestamp>,
    ) -> Result<Option<Grant>, DataError> {
        let _one = self.hold_grants().await;
        let now = (self.config.clock)();
        let renewed: Vec<GrantNote> = {
            let st = self.st.lock();
            self.used_grants(&st)
                .into_iter()
                .filter(|n| n.key == *key && !n.ended)
                .filter_map(|n| match n.standing(&st) {
                    Standing::In(role) => Some(GrantNote { role, until, ..n }),
                    Standing::Out | Standing::Unknown => None,
                })
                .collect()
        };
        let Some(first) = renewed.first() else {
            return Ok(None);
        };
        if until.is_some_and(|t| t <= now) {
            return Err(DataError::BadRequest {
                name: first.folder.clone(),
                why: format!(
                    "the date {} is not after this device's clock ({}): give a later date, or \
                     None for a grant that follows the members record, or end the grant with \
                     Device::end_grant",
                    until.map_or(0, |t| t.0),
                    now.0
                ),
            });
        }
        let grant = first.grant();
        for note in &renewed {
            self.keep_grant(note);
        }
        if !self.barrier().await {
            return Err(local(
                "the device stopped before the grant's new date was durable: renew it again \
                 once the device runs",
            ));
        }
        Ok(Some(grant))
    }
}

impl Device {
    /// The grants in force now (spec §19.8): for each used offer of this
    /// device whose admission made one, that has not been ended (by a held
    /// members record that leaves the person out, or by the host,
    /// [`end_grant`](Self::end_grant)), is not past its date if it has one
    /// ([`renew_grant`](Self::renew_grant)), and that the members record in
    /// force for its folder still admits (the namespace is a writer or a
    /// reader of it), **in the role that record gives it**; then the **mirror
    /// entries**, the grants this device was given by joining a folder (key =
    /// the inviter's, `namespaces` = `[owner]`, the folder, the role the record
    /// in force gives the inviter — a writer when its namespace is listed as a
    /// writer, else a reader —, `until` = `None`: it follows the record), each
    /// only while the record in force for its folder lists this device and the
    /// entry has not been ended. Derived from the grant notes kept with the use
    /// marks, the mirror notes kept at joins and the records held, so it is the
    /// same after a restart, less what ended. A note whose MAC does not check
    /// (it was changed in the store) is ignored.
    ///
    /// A host that links installs these at start
    /// ([`Introducer::grant`] for each).
    pub fn grants(&self) -> Vec<Grant> {
        self.inner.live_grants()
    }

    /// The folders this device joined, for the link layer's routes (spec §19.8):
    /// for each live mirror entry — kept by [`join`](Self::join) once the record
    /// admitting this device was held, not ended by the host
    /// ([`end_grant`](Self::end_grant)), and whose folder's members record in
    /// force still lists this device — its [`JoinedFolder`]: the inviter's key,
    /// the folder and its owner, this device's role in the record in force and
    /// the other writers' namespaces (this device's own namespace and every
    /// namespace above or below it left out, at most
    /// [`JOINED_WRITERS_MAX`]). Sorted by folder, then inviter (the order of
    /// `Name` and of the key's octets).
    ///
    /// Derived on every call from signed durable data and the device's MAC'd
    /// mirror notes: nothing is cached, so a record that adds a writer or ends
    /// the entry shows at the next call. A watcher calls it again after each
    /// change of [`joined_changes`](Self::joined_changes).
    pub fn joined_folders(&self) -> Vec<JoinedFolder> {
        self.inner.joined_list(&self.inner.st.lock())
    }

    /// The generation of [`joined_folders`](Self::joined_folders): the value
    /// changes (never repeating within a run) whenever the list changed — a
    /// join, a record that changed a role or a writer, an entry that ended or
    /// began. It is signalled where grants are judged (after every record taken
    /// and at a start), at a join and at a host end, and only when the list
    /// really changed. A watcher reads [`joined_folders`](Self::joined_folders)
    /// after each change (and once when it starts: the generation says nothing
    /// of what came before it).
    pub fn joined_changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.inner.st.lock().intro.joined_changes.subscribe()
    }

    /// End the grants of `key` for good, durably: every grant note of that
    /// key not yet ended (for every folder), the inviter's notes and the
    /// mirror notes (the grants this device was given by joining) alike, is
    /// marked ended, behind the store barrier, so a restart does not bring it
    /// back ([`grants`](Self::grants) no longer lists it, nor does
    /// [`joined_folders`](Self::joined_folders)). `true` if there was a grant
    /// of the key not yet ended (past its date or not), `false` if none. Tells
    /// the host nothing:
    /// the host that calls this ends its link layer's grant itself
    /// ([`Introducer::revoke_grant`]
    /// is for ends the device makes). The person stays a member of the
    /// folder: removing them is a members record, not this, and the host's end
    /// makes no departure mark (nor ever one for a mirror).
    ///
    /// # Errors
    /// [`DataError::Local`] when the device stopped before the end was
    /// durable: call it again once the device runs.
    pub async fn end_grant(&self, key: &[u8; 32]) -> Result<bool, DataError> {
        self.inner.end_grant(key, None).await
    }

    /// [`end_grant`](Self::end_grant) for the grants of `key` of `folder`
    /// alone, inviter's notes and mirror notes: the person's grants of other
    /// folders stand.
    ///
    /// # Errors
    /// [`DataError::Local`] when the device stopped before the end was
    /// durable: call it again once the device runs.
    pub async fn end_grant_in(&self, key: &[u8; 32], folder: &Name) -> Result<bool, DataError> {
        self.inner.end_grant(key, Some(folder)).await
    }

    /// The departure marks in force (spec §19.8): for each grant a held
    /// members record ended by leaving the person out
    /// ([`IntroPolicy::departure_for`](crate::intro::IntroPolicy::departure_for)
    /// keeps a mark), the record's name and the date by this device's clock
    /// after which it is no longer shown. Derived from the grant notes, whose
    /// MAC keeps the mark: a note changed in the store is ignored, mark and all.
    /// A mark a later grant of the same key for the same folder supersedes
    /// (the person was invited again) is not listed. Sorted by key, then folder.
    ///
    /// A host that links installs these at start
    /// ([`Introducer::departure`] for each).
    pub fn departures(&self) -> Vec<Departure> {
        self.inner.live_departures()
    }

    /// The departed person's side (spec §19.8): this device was told — by the
    /// link layer of the person that invited it, which names the folder and
    /// the record — that the members record `record` of `folder` leaves it out.
    /// Fetch the record, over the link or from the devices of its namespace, and
    /// take it as any held record: validated by its signatures, merged, judged
    /// as ever, so this device's own folder then no longer lists it and it
    /// withdraws what it wrote after the cut. The name carries no authority.
    ///
    /// `from` is the **authenticated device** of the peer that told it (its
    /// certificate validated in a namespace this device holds, on a full link:
    /// never an enrollment or introduction link). Only a device under the
    /// folder's own namespace (`<namespace>/32=data[/<path>]`) can let this
    /// device go of the folder, so a hint from any other is refused before it
    /// can hold the folder's fetch or spend the minute's bound.
    ///
    /// Taken only when this device holds a members record line of `folder`,
    /// `record` is a log entry of `folder` (`<device>/32=log/<folder>/seq=<n>`)
    /// whose device lies under a namespace this device holds a trust context of,
    /// and what is fetched is a members record of `folder`; at most one take of
    /// `folder` is in flight, and a bounded number begin in a minute.
    ///
    /// # Errors
    /// [`DataError::BadRequest`] for a hint that is none of those, or told by a
    /// device outside the folder's namespace (ignore it);
    /// [`DataError::NotReady`] while another take of `folder` is under way, when
    /// the minute's bound is used up, or when the record could not be fetched:
    /// ask again.
    pub async fn take_departure(
        &self,
        from: &Name,
        folder: &Name,
        record: &Name,
    ) -> Result<(), DataError> {
        self.inner.take_departure(from, folder, record).await
    }

    /// Set the date of the grants of `key`, durably: `Some(t)` makes it
    /// the date after which they are over, `None` gives them no date (they
    /// follow the members record). Only a grant a held members record still
    /// admits the person for, and not ended, is renewed — one past its old
    /// date is renewable, one ended is not: offer the folder again. Returns
    /// the grant as it now stands (the first, by offer, when several offers
    /// admitted the key), or `None` when there is none to renew. Tells the
    /// host nothing: the host that calls this installs the returned grant
    /// ([`Introducer::grant`]).
    ///
    /// A **mirror** entry (the grant this device was given by joining) is never
    /// dated and is left untouched here: it has no date, it follows the members
    /// record, and only the record or [`end_grant`](Self::end_grant) ends it.
    ///
    /// # Errors
    /// [`DataError::BadRequest`] for a date not after this device's clock
    /// (give a later one, `None`, or [`end_grant`](Self::end_grant));
    /// [`DataError::Local`] when the device stopped before the change was
    /// durable.
    pub async fn renew_grant(
        &self,
        key: &[u8; 32],
        until: Option<Timestamp>,
    ) -> Result<Option<Grant>, DataError> {
        self.inner.renew_grant(key, until).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7; 32];

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    fn note(ended: bool, departure: Option<Mark>) -> GrantNote {
        GrantNote {
            offer: n("/alice/laptop/32=log/alice/32=data/notebook/seq=3"),
            key: [9; 32],
            namespace: n("/bob"),
            folder: n("/alice/32=data/notebook"),
            role: Role::Writer,
            until: Some(Timestamp(1234)),
            ended,
            departure,
        }
    }

    fn mark() -> Mark {
        Mark {
            record: n("/alice/phone/32=log/alice/32=data/notebook/seq=1"),
            until: Timestamp(99_000),
        }
    }

    /// `body` with the MAC a note of this device carries.
    fn sealed(mut body: Vec<u8>) -> Bytes {
        let check = mac_of(&KEY, &body).finalize().into_bytes();
        body.extend_from_slice(&check);
        Bytes::from(body)
    }

    #[test]
    fn a_note_with_a_mark_and_one_without_read_back_as_written() {
        for note in [
            note(false, None),
            note(true, None),
            note(true, Some(mark())),
        ] {
            let bytes = note.encode(&KEY);
            assert_eq!(GrantNote::decode(&bytes, &KEY), Ok(note));
        }
    }

    #[test]
    fn a_version_2_note_reads_as_no_mark() {
        // The octets a build before departure marks wrote: version 2, no mark field.
        let n3 = note(true, None).encode(&KEY);
        let mut body = n3[..n3.len() - MAC_LEN].to_vec();
        body[0] = NOTE_VERSION_2;
        let v2 = sealed(body);
        assert_eq!(GrantNote::decode(&v2, &KEY), Ok(note(true, None)));

        // A version 2 note cannot carry a mark: its flag is not one it knows.
        let marked = note(true, Some(mark())).encode(&KEY);
        let mut body = marked[..marked.len() - MAC_LEN].to_vec();
        body[0] = NOTE_VERSION_2;
        assert_eq!(
            GrantNote::decode(&sealed(body), &KEY),
            Err(Unread::Form),
            "a version 2 note with the mark flag was read"
        );
    }

    #[test]
    fn a_mark_on_a_note_not_ended_is_no_note() {
        let marked = note(true, Some(mark())).encode(&KEY);
        let mut body = marked[..marked.len() - MAC_LEN].to_vec();
        body[1] &= !ENDED;
        assert_eq!(GrantNote::decode(&sealed(body), &KEY), Err(Unread::Form));
    }

    #[test]
    fn a_note_changed_after_its_mac_fails_it_whatever_the_change() {
        let bytes = note(true, Some(mark())).encode(&KEY);
        for at in [1, 3, 11, HEAD + 5, bytes.len() - MAC_LEN - 3] {
            let mut b = bytes.to_vec();
            b[at] ^= 1;
            assert_eq!(
                GrantNote::decode(&Bytes::from(b), &KEY),
                Err(Unread::Check),
                "a change at {at} passed"
            );
        }
        // Another device's key does not read it either.
        assert_eq!(GrantNote::decode(&bytes, &[8; 32]), Err(Unread::Check));
        // The mark's flag cleared, the check left as it was.
        let mut cleared = bytes.to_vec();
        cleared[1] &= !MARKED;
        assert_eq!(
            GrantNote::decode(&Bytes::from(cleared), &KEY),
            Err(Unread::Check)
        );
    }

    fn mirror(role: Role, ended: bool) -> MirrorNote {
        MirrorNote {
            key: [5; 32],
            owner: n("/alice"),
            folder: n("/alice/32=data/notebook"),
            role,
            ended,
        }
    }

    #[test]
    fn a_mirror_note_reads_back_as_written() {
        for role in [Role::Reader, Role::Writer] {
            for ended in [false, true] {
                let note = mirror(role, ended);
                assert_eq!(
                    MirrorNote::decode(&note.encode(&KEY), &KEY),
                    Ok(note),
                    "a {role:?} mirror note (ended: {ended}) did not read back"
                );
            }
        }
    }

    #[test]
    fn a_mirror_note_changed_or_under_another_key_does_not_read() {
        let bytes = mirror(Role::Reader, false).encode(&KEY);
        // The flags, the role, the key and a name each changed after the MAC.
        for at in [1, 2, 3, MIRROR_HEAD + 5, bytes.len() - MAC_LEN - 3] {
            let mut b = bytes.to_vec();
            b[at] ^= 1;
            assert_eq!(
                MirrorNote::decode(&Bytes::from(b), &KEY),
                Err(Unread::Check),
                "a change at {at} passed"
            );
        }
        assert_eq!(MirrorNote::decode(&bytes, &[8; 32]), Err(Unread::Check));
    }

    #[test]
    fn an_inviters_note_does_not_read_as_a_mirror_nor_the_reverse() {
        let granted = note(false, None).encode(&KEY);
        let mirrored = mirror(Role::Writer, false).encode(&KEY);
        assert_eq!(MirrorNote::decode(&granted, &KEY), Err(Unread::Form));
        assert_eq!(GrantNote::decode(&mirrored, &KEY), Err(Unread::Form));

        // Whatever the version octet says, the MAC is of its own kind: a mirror
        // note's body sealed as an inviter's note does not check as a mirror, nor
        // an inviter's body sealed as a mirror's as an inviter's.
        let mut body = mirrored[..mirrored.len() - MAC_LEN].to_vec();
        let as_grant = {
            let check = mac_of(&KEY, &body).finalize().into_bytes();
            body.extend_from_slice(&check);
            Bytes::from(body)
        };
        assert_eq!(
            MirrorNote::decode(&as_grant, &KEY),
            Err(Unread::Check),
            "a mirror body under the inviter note's MAC read as a mirror"
        );
        let mut body = granted[..granted.len() - MAC_LEN].to_vec();
        let as_mirror = {
            let check = mirror_mac_of(&KEY, &body).finalize().into_bytes();
            body.extend_from_slice(&check);
            Bytes::from(body)
        };
        assert_eq!(
            GrantNote::decode(&as_mirror, &KEY),
            Err(Unread::Check),
            "an inviter's body under the mirror note's MAC read as an inviter's note"
        );
    }
}
