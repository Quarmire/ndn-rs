//! The grants an offer's admission makes (spec §19.8): the durable note kept
//! with the use mark, the grants in force ([`Device::grants`]) and the check
//! that ends them when a held members record leaves the person out.
//!
//! Notes are the device's own and local: under `/localhost/ndn-data/intro/grant/`,
//! never served, never on the wire. Their value is the module's fixed-width local
//! form (as the `joined` note's), not a TLV: **no TLV-TYPE number is registered or
//! used for them**.

use std::sync::Arc;

use bytes::Bytes;
use ndn_packet::Name;

use super::intro::{local_name, local_name_base};
use super::{Device, Inner, St};
use crate::intro::{Grant, Role};
use crate::version::{Audience, Timestamp};

/// Where the store keeps the grant the own offer `offer`'s admission made:
/// a [`GrantNote`]. Written under the same store barrier as the kept
/// acceptance and the use mark.
fn grant_name(offer: &Name) -> Name {
    local_name("grant", offer)
}

/// The note's version octet.
const NOTE_VERSION: u8 = 1;

/// The fixed head of a note: version, flags, role, `until` (8, big-endian),
/// the key's digest.
const HEAD: usize = 1 + 1 + 1 + 8 + 32;

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
    pub(super) role: Role,
    /// By this device's clock.
    pub(super) until: Timestamp,
    /// A held members record left the person out, and the host was told
    /// ([`Introducer::revoke_grant`](crate::intro::Introducer::revoke_grant)).
    pub(super) ended: bool,
}

impl GrantNote {
    fn encode(&self) -> Bytes {
        let mut out = Vec::with_capacity(HEAD + 64);
        out.push(NOTE_VERSION);
        out.push(u8::from(self.ended));
        out.push(match self.role {
            Role::Reader => 0,
            Role::Writer => 1,
        });
        out.extend_from_slice(&self.until.0.to_be_bytes());
        out.extend_from_slice(&self.key);
        for name in [&self.offer, &self.folder, &self.namespace] {
            let tlv = name.encode_to_tlv();
            out.extend_from_slice(&(tlv.len() as u16).to_be_bytes());
            out.extend_from_slice(&tlv);
        }
        Bytes::from(out)
    }

    /// The note `bytes` hold; `None` for what is not a note of this version.
    fn decode(bytes: &Bytes) -> Option<Self> {
        let head = bytes.get(..HEAD)?;
        if head[0] != NOTE_VERSION {
            return None;
        }
        let ended = match head[1] {
            0 => false,
            1 => true,
            _ => return None,
        };
        let role = match head[2] {
            0 => Role::Reader,
            1 => Role::Writer,
            _ => return None,
        };
        let until = Timestamp(u64::from_be_bytes(head[3..11].try_into().ok()?));
        let key = <[u8; 32]>::try_from(&head[11..]).ok()?;
        let mut at = HEAD;
        let mut names = Vec::with_capacity(3);
        for _ in 0..3 {
            let len = u16::from_be_bytes(bytes.get(at..at + 2)?.try_into().ok()?) as usize;
            at += 2;
            let tlv = bytes.get(at..at.checked_add(len)?)?;
            names.push(Name::decode_from_tlv(bytes.slice_ref(tlv)).ok()?);
            at += len;
        }
        if at != bytes.len() {
            return None;
        }
        let namespace = names.pop()?;
        let folder = names.pop()?;
        let offer = names.pop()?;
        Some(Self {
            offer,
            key,
            namespace,
            folder,
            role,
            until,
            ended,
        })
    }

    /// What the host is told.
    pub(super) fn grant(&self) -> Grant {
        Grant {
            key: self.key,
            namespaces: vec![self.namespace.clone()],
            folder: self.folder.clone(),
            role: self.role,
            until: self.until,
        }
    }

    /// Whether the members record `st` holds in force for the folder admits the
    /// namespace — as a writer, or as a reader: `Some(false)` when a record is
    /// held and does not, `None` when none is held (nothing to judge by).
    fn admitted(&self, st: &St) -> Option<bool> {
        let m = st.folders.get(&self.folder)?.members.as_ref()?;
        let ns = &self.namespace;
        Some(
            m.writers.iter().any(|p| ns.has_prefix(p))
                || m.readers
                    .iter()
                    .any(|a| matches!(a, Audience::Person(p) if ns.has_prefix(p))),
        )
    }
}

impl Inner {
    /// The note of a grant for the own offer `offer`'s admission of `key`, as
    /// [`IntroPolicy::grant_for`](crate::intro::IntroPolicy::grant_for) lasts
    /// from now; `None` when it is zero. Not yet kept.
    pub(super) fn grant_note(
        &self,
        offer: &Name,
        key: [u8; 32],
        namespace: &Name,
        folder: &Name,
        role: Role,
    ) -> Option<GrantNote> {
        let lasts = self.config.intro.grant_for;
        if lasts.is_zero() {
            return None;
        }
        let ms = u64::try_from(lasts.as_millis()).unwrap_or(u64::MAX);
        Some(GrantNote {
            offer: offer.clone(),
            key,
            namespace: namespace.clone(),
            folder: folder.clone(),
            role,
            until: Timestamp((self.config.clock)().0.saturating_add(ms)),
            ended: false,
        })
    }

    /// Put `note` into the store; durable at the next barrier (the one under
    /// the use mark).
    pub(super) fn keep_grant(&self, note: &GrantNote) {
        self.store.insert(grant_name(&note.offer), note.encode());
    }

    /// Every grant note kept, held here or not.
    fn grant_notes(&self) -> Vec<GrantNote> {
        let base = local_name_base("grant");
        self.store
            .scan_under(&base, 0)
            .into_iter()
            .filter_map(|(name, value)| match GrantNote::decode(&value) {
                Some(note) if grant_name(&note.offer) == name => Some(note),
                _ => {
                    tracing::debug!(%name, "a grant note this version does not read; ignored");
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
        self.grant_notes()
            .into_iter()
            .filter(|n| {
                st.intro
                    .used
                    .get(&n.offer)
                    .is_some_and(|(_, digest)| *digest == n.key)
            })
            .collect()
    }

    /// The grants in force ([`Device::grants`]).
    fn live_grants(&self) -> Vec<Grant> {
        let now = (self.config.clock)();
        let st = self.st.lock();
        self.used_grants(&st)
            .into_iter()
            .filter(|n| !n.ended && n.until > now && n.admitted(&st) == Some(true))
            .map(|n| n.grant())
            .collect()
    }

    /// End the grants a members record held leaves out (spec §19.8): the record
    /// in force for a grant's folder is held and lists the namespace neither as
    /// a writer nor as a reader. Each is marked ended durably, then the host is
    /// told once. Run after every record taken, from any device of the
    /// namespace, and at a start.
    pub(super) async fn end_grants(self: &Arc<Self>) {
        let Some(host) = self.config.introducer.clone() else {
            return;
        };
        let ending: Vec<GrantNote> = {
            let mut st = self.st.lock();
            let left_out: Vec<GrantNote> = self
                .used_grants(&st)
                .into_iter()
                .filter(|n| !n.ended && n.admitted(&st) == Some(false))
                .collect();
            // One settle ends a grant: another that runs meanwhile sees it taken.
            left_out
                .into_iter()
                .filter(|n| st.intro.ending.insert(n.offer.clone()))
                .collect()
        };
        for mut note in ending {
            note.ended = true;
            self.keep_grant(&note);
            let durable = self.barrier().await;
            self.st.lock().intro.ending.remove(&note.offer);
            if !durable {
                tracing::debug!(offer = %note.offer, "the device stopped before the end of a grant was durable");
                continue;
            }
            tracing::info!(offer = %note.offer, folder = %note.folder, namespace = %note.namespace, "a members record held leaves the person out: its grant to link ended");
            host.revoke_grant(&note.key);
        }
    }
}

impl Device {
    /// The grants in force now (spec §19.8): for each used offer of this
    /// device whose admission made one, that has not expired by this device's
    /// clock or been ended, and that the members record in force for its folder
    /// still admits (the namespace is a writer or a reader of it). Derived from
    /// the grant notes kept with the use marks and the records held, so it is
    /// the same after a restart, less what ended.
    ///
    /// A host that links installs these at start
    /// ([`Introducer::grant`](crate::intro::Introducer::grant) for each).
    pub fn grants(&self) -> Vec<Grant> {
        self.inner.live_grants()
    }
}
