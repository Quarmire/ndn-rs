//! The grants an offer's admission makes (spec §19.8): the durable note kept
//! with the use mark, the grants in force ([`Device::grants`]), the judgement
//! of them against the members record in force (a person left out loses the
//! grant, a person whose role changed has the grant re-told), and the host's
//! own durable ends and renewals ([`Device::end_grant`],
//! [`Device::renew_grant`]).
//!
//! Notes are the device's own and local: under `/localhost/ndn-data/intro/grant/`,
//! never served, never on the wire. Their value is the module's fixed-width local
//! form (as the `joined` note's), not a TLV: **no TLV-TYPE number is registered or
//! used for them**. A note ends in a MAC under a key derived from the device's
//! recipient secret, which lives in the key store, not the data store: a note
//! changed in the store (the `ended` flag cleared, a date extended, a role
//! flipped) fails its check and is ignored.

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
use crate::intro::{Grant, Role};
use crate::version::{Audience, Timestamp};

/// Where the store keeps the grant the own offer `offer`'s admission made:
/// a [`GrantNote`]. Written under the same store barrier as the kept
/// acceptance and the use mark.
fn grant_name(offer: &Name) -> Name {
    local_name("grant", offer)
}

/// The note's version octet.
const NOTE_VERSION: u8 = 2;

/// Flag bits of a note.
const ENDED: u8 = 1;
const DATED: u8 = 2;

/// The fixed head of a note: version, flags, role, `until` (8, big-endian;
/// zero when the note has no date), the key's digest.
const HEAD: usize = 1 + 1 + 1 + 8 + 32;

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

impl GrantNote {
    fn encode(&self, mac_key: &[u8; 32]) -> Bytes {
        let mut out = Vec::with_capacity(HEAD + 64 + MAC_LEN);
        out.push(NOTE_VERSION);
        out.push(if self.ended { ENDED } else { 0 } | if self.until.is_some() { DATED } else { 0 });
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
        let check = mac_of(mac_key, &out).finalize().into_bytes();
        out.extend_from_slice(&check);
        Bytes::from(out)
    }

    /// The note `bytes` hold, if they are one of this version whose MAC checks
    /// under `mac_key`.
    fn decode(bytes: &Bytes, mac_key: &[u8; 32]) -> Result<Self, Unread> {
        let body_len = bytes.len().checked_sub(MAC_LEN).ok_or(Unread::Form)?;
        let (body, check) = bytes.split_at(body_len);
        if body.len() < HEAD || body[0] != NOTE_VERSION {
            return Err(Unread::Form);
        }
        if mac_of(mac_key, body).verify_slice(check).is_err() {
            return Err(Unread::Check);
        }
        let flags = body[1];
        if flags & !(ENDED | DATED) != 0 {
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
        let mut names = Vec::with_capacity(3);
        for _ in 0..3 {
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

    /// Whether the note's own date, if it has one, is past `now`.
    fn dated_out(&self, now: Timestamp) -> bool {
        self.until.is_some_and(|t| t <= now)
    }

    /// What the members record `st` holds in force for the folder makes of the
    /// namespace: a writer, or a reader (prefix match, as device admission
    /// does), or out.
    fn standing(&self, st: &St) -> Standing {
        let Some(m) = st
            .folders
            .get(&self.folder)
            .and_then(|f| f.members.as_ref())
        else {
            return Standing::Unknown;
        };
        let ns = &self.namespace;
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

    /// Judge the grants against the members records held (spec §19.8): the
    /// record in force for a grant's folder is held and
    ///
    /// - lists the namespace neither as a writer nor as a reader: the host is
    ///   told ([`Introducer::revoke_grant`](crate::intro::Introducer::revoke_grant),
    ///   in memory, first), then the note is marked ended durably;
    /// - lists it in another role than the grant bears: the note takes the
    ///   role, the host is told again ([`Introducer::grant`](crate::intro::Introducer::grant),
    ///   in memory, first) and the note is made durable.
    ///
    /// Run after every record taken, from any device of the namespace, and at
    /// a start. A failure to make a note durable leaves the next run to judge
    /// again.
    pub(super) async fn judge_grants(self: &Arc<Self>) {
        let Some(host) = self.config.introducer.clone() else {
            return;
        };
        if self.st.lock().intro.used.is_empty() {
            return;
        }
        let _one = self.hold_grants().await;
        let (ending, retold): (Vec<GrantNote>, Vec<GrantNote>) = {
            let st = self.st.lock();
            let mut ending = Vec::new();
            let mut retold = Vec::new();
            for n in self.used_grants(&st).into_iter().filter(|n| !n.ended) {
                match n.standing(&st) {
                    Standing::Out => ending.push(n),
                    Standing::In(role) if role != n.role => retold.push(GrantNote { role, ..n }),
                    Standing::In(_) | Standing::Unknown => {}
                }
            }
            (ending, retold)
        };
        for mut note in ending {
            // The host first: in memory, and the safe direction. A slow or
            // failing flush must not delay the link layer's end.
            host.revoke_grant(&note.key);
            note.ended = true;
            self.keep_grant(&note);
            if !self.barrier().await {
                tracing::debug!(offer = %note.offer, "the device stopped before the end of a grant was durable; the next start judges it again");
                continue;
            }
            tracing::info!(offer = %note.offer, folder = %note.folder, namespace = %note.namespace, "a members record held leaves the person out: its grant to link ended");
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

    /// The host ends the grants of `key` ([`Device::end_grant`]).
    async fn end_grant(self: &Arc<Self>, key: &[u8; 32]) -> Result<bool, DataError> {
        let _one = self.hold_grants().await;
        let live: Vec<GrantNote> = {
            let st = self.st.lock();
            self.used_grants(&st)
                .into_iter()
                .filter(|n| n.key == *key && !n.ended)
                .collect()
        };
        if live.is_empty() {
            return Ok(false);
        }
        for mut note in live {
            note.ended = true;
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
    /// key not yet ended is marked ended, behind the store barrier, so a
    /// restart does not bring it back ([`grants`](Self::grants) no longer
    /// lists it). `true` if there was a grant of the key not yet ended (past
    /// its date or not), `false` if none. Tells the host nothing: the host
    /// that calls this ends its link layer's grant itself
    /// ([`Introducer::revoke_grant`](crate::intro::Introducer::revoke_grant)
    /// is for ends the device makes). The person stays a member of the
    /// folder: removing them is a members record, not this.
    ///
    /// # Errors
    /// [`DataError::Local`] when the device stopped before the end was
    /// durable: call it again once the device runs.
    pub async fn end_grant(&self, key: &[u8; 32]) -> Result<bool, DataError> {
        self.inner.end_grant(key).await
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
