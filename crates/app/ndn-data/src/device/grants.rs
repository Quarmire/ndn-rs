//! The grants an offer's admission makes (spec §19.8): the durable note kept
//! with the use mark, the grants in force ([`Device::grants`]), the judgement
//! of them against the members record in force **for each note's folder** (a
//! person left out of one folder loses that folder's grant alone, a person
//! whose role changed has the grant re-told), the departure mark a held record
//! that lets a person go leaves in the note ([`Device::departures`],
//! [`Device::take_departure`]), and the host's own durable ends and renewals
//! ([`Device::end_grant`], [`Device::end_grant_in`], [`Device::renew_grant`]).
//!
//! Notes are the device's own and local: under `/localhost/ndn-data/intro/grant/`,
//! never served, never on the wire. Their value is the module's fixed-width local
//! form (as the `joined` note's), not a TLV: **no TLV-TYPE number is registered or
//! used for them**. A note ends in a MAC under a key derived from the device's
//! recipient secret, which lives in the key store, not the data store: a note
//! changed in the store (the `ended` flag cleared, a date extended, a role
//! flipped, a departure mark added, cleared or moved) fails its check and is
//! ignored.

use std::sync::Arc;

use bytes::Bytes;
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use ndn_packet::Name;
use sha2::Sha256;
use zeroize::Zeroizing;

use super::intro::{local_name, local_name_base};
use super::{Device, Inner, St, local};
use crate::error::DataError;
use crate::intro::{Departure, Grant, Role};
use crate::version::{Audience, Timestamp};
use crate::wire::{device_of, log_name, parse_log_name};

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

/// The key the notes' MAC is made under: derived (HKDF-SHA256, a domain label)
/// from the device's recipient secret. That secret is kept by the key store,
/// never in the data store the notes live in, so whoever can only write the
/// data store cannot make a note that passes.
fn mac_key(st: &St) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, st.keys.recipient.expose())
        .expand(MAC_KEY_LABEL, &mut *key)
        .expect("32 octets is a valid HKDF-SHA256 output length");
    key
}

fn mac_of(key: &[u8; 32], body: &[u8]) -> Hmac<Sha256> {
    let mut m =
        <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC accepts a key of any length");
    m.update(MAC_LABEL);
    m.update(body);
    m
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
    /// record in force makes of the person now.
    fn live_grants(&self) -> Vec<Grant> {
        let now = (self.config.clock)();
        let st = self.st.lock();
        self.used_grants(&st)
            .into_iter()
            .filter(|n| !n.ended && !n.dated_out(now))
            .filter_map(|n| match n.standing(&st) {
                Standing::In(role) => Some(GrantNote { role, ..n }.grant()),
                Standing::Out | Standing::Unknown => None,
            })
            .collect()
    }

    /// Take the one place grant notes are changed from: a change reads the
    /// notes as the one before left them.
    async fn hold_grants(&self) -> tokio::sync::OwnedMutexGuard<()> {
        let one = Arc::clone(&self.st.lock().intro.notes);
        one.lock_owned().await
    }

    /// Judge the grants against the members records held (spec §19.8), each
    /// note against the record in force **for its own folder**: it is held and
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
    /// The person's grants of other folders are not touched. Run after every
    /// record taken, from any device of the namespace, and at a start. A failure
    /// to make a note durable leaves the next run to judge again.
    pub(super) async fn judge_grants(self: &Arc<Self>) {
        let Some(host) = self.config.introducer.clone() else {
            return;
        };
        if self.st.lock().intro.used.is_empty() {
            return;
        }
        let _one = self.hold_grants().await;
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
    /// or only those for `folder` ([`Device::end_grant_in`]). The host ended
    /// them itself: no departure mark is made.
    async fn end_grant(
        self: &Arc<Self>,
        key: &[u8; 32],
        folder: Option<&Name>,
    ) -> Result<bool, DataError> {
        let _one = self.hold_grants().await;
        let live: Vec<GrantNote> = {
            let st = self.st.lock();
            self.used_grants(&st)
                .into_iter()
                .filter(|n| n.key == *key && !n.ended && folder.is_none_or(|f| n.folder == *f))
                .collect()
        };
        if live.is_empty() {
            return Ok(false);
        }
        for mut note in live {
            note.ended = true;
            note.departure = None;
            self.keep_grant(&note);
            tracing::info!(offer = %note.offer, folder = %note.folder, namespace = %note.namespace, "the host ended a grant to link");
        }
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
    /// reader of it), **in the role that record gives it**. Derived from the
    /// grant notes kept with the use marks and the records held, so it is the
    /// same after a restart, less what ended. A note whose MAC does not
    /// check (it was changed in the store) is ignored.
    ///
    /// A host that links installs these at start
    /// ([`Introducer::grant`](crate::intro::Introducer::grant) for each).
    pub fn grants(&self) -> Vec<Grant> {
        self.inner.live_grants()
    }

    /// End the grants of `key` for good, durably: every grant note of that
    /// key not yet ended (for every folder) is marked ended, behind the store
    /// barrier, so a restart does not bring it back ([`grants`](Self::grants)
    /// no longer lists it). `true` if there was a grant of the key not yet
    /// ended (past its date or not), `false` if none. Tells the host nothing:
    /// the host that calls this ends its link layer's grant itself
    /// ([`Introducer::revoke_grant`](crate::intro::Introducer::revoke_grant)
    /// is for ends the device makes). The person stays a member of the
    /// folder: removing them is a members record, not this, and the host's end
    /// makes no departure mark.
    ///
    /// # Errors
    /// [`DataError::Local`] when the device stopped before the end was
    /// durable: call it again once the device runs.
    pub async fn end_grant(&self, key: &[u8; 32]) -> Result<bool, DataError> {
        self.inner.end_grant(key, None).await
    }

    /// [`end_grant`](Self::end_grant) for the grants of `key` of `folder`
    /// alone: the person's grants of other folders stand.
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
    /// ([`Introducer::departure`](crate::intro::Introducer::departure) for each).
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
    /// ([`Introducer::grant`](crate::intro::Introducer::grant)).
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
}
