//! Reads of what the log holds: markers, statuses, packets and what an
//! applied entry wrote. Borrows the log's parts rather than the log, so the
//! register can be changed while a closure reads through it.

use std::collections::BTreeMap;

use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_sync::DataStore;

use super::chain::{Dev, Status};
use super::{Log, decode_wire};
use crate::error::Refusal;
use crate::register::{Write, decode_refs};
use crate::seal::{self, Keys};
use crate::store::{Kind, Marker, supers_key};
use crate::wire::{self, Body, Entry, EntryRef, Payload, PutBody, log_name, signed_digest};

pub(super) struct View<'a> {
    pub store: &'a dyn DataStore,
    pub space: &'a Name,
    pub keys: &'a Keys,
    pub devices: &'a BTreeMap<Name, Dev>,
}

impl<'a> View<'a> {
    pub(super) fn of(log: &'a Log) -> View<'a> {
        View {
            store: &log.store,
            space: &log.space,
            keys: &log.keys,
            devices: &log.devices,
        }
    }

    pub(super) fn marker(&self, device: &Name, seq: u64) -> Option<Marker> {
        Marker::read(self.store, device, self.space, seq)
    }

    pub(super) fn status(&self, device: &Name, seq: u64) -> Option<Status> {
        Status::decode(
            &self.store.get(&Kind::STATUS.seq(self.space, device, seq))?,
            device,
        )
    }

    /// The packet at the entry's name: the first one taken.
    pub(super) fn wire_at(&self, device: &Name, seq: u64) -> Option<Bytes> {
        self.store.get(&log_name(device, self.space, seq))
    }

    /// Every packet kept at the entry's name: the first, and the second one
    /// a device signed there (evidence).
    pub(super) fn wires_at(&self, device: &Name, seq: u64) -> Vec<Bytes> {
        let name = log_name(device, self.space, seq);
        self.store
            .get(&name)
            .into_iter()
            .chain(self.store.get(&Kind::EQUIVOCAL.of(&name)))
            .collect()
    }

    /// The entries that name `x`, digest included, in their `after` (applied
    /// ones): a ref to other bytes at `x`'s name is another record.
    pub(super) fn namers(&self, x: &EntryRef) -> Vec<EntryRef> {
        self.store
            .get(&supers_key(self.space, &x.device, x.seq, &x.digest))
            .and_then(|record| decode_refs(&record))
            .unwrap_or_default()
    }

    /// The path and payload an entry writes, a sealed one opened under the key
    /// held; `None` if it is not a write or cannot be opened.
    pub(super) fn opened_put(&self, entry: &Entry, name: &Name) -> Option<PutBody> {
        match &entry.body {
            Body::Put(put) => Some(put.clone()),
            Body::Sealed(sealed) => {
                let key = self.keys.key(self.space, &sealed.epoch)?;
                let plain = seal::open_payload(key, name, &sealed.sealed)?;
                wire::decode_sealed_plain(&plain).ok()
            }
            Body::Members(_) | Body::Epoch(_) => None,
        }
    }

    /// The write the entry `r` carries, opened if sealed and under the key
    /// held; `None` when its packet is not held as those bytes, or is no
    /// write, or cannot be opened.
    fn put_of(&self, r: &EntryRef) -> Option<PutBody> {
        let (entry, digest) = decode_wire(&self.wire_at(&r.device, r.seq)?)?;
        if digest != r.digest {
            return None;
        }
        self.opened_put(&entry, &log_name(&r.device, self.space, r.seq))
    }

    /// What the applied entry `r` wrote; `None` when it is not held, not
    /// applied, or not a write. The register asks for it when an entry it
    /// superseded returns.
    pub(super) fn write_of(&self, r: &EntryRef) -> Option<Write> {
        if self.status(&r.device, r.seq).is_some() {
            return None;
        }
        let put = self.put_of(r)?;
        let person = self.devices.get(&r.device)?.person.clone();
        Some(write_for(&put, person))
    }

    /// The payload the applied entry `r` wrote.
    pub(super) fn payload_of(&self, r: &EntryRef) -> Option<Payload> {
        Some(self.put_of(r)?.payload)
    }
}

/// What the register needs of a write by `person`.
pub(super) fn write_for(put: &PutBody, person: Name) -> Write {
    let (removal, size) = match &put.payload {
        Payload::Inline(bytes) => (bytes.is_empty(), bytes.len() as u64),
        Payload::Blob { size, .. } => (false, *size),
    };
    Write {
        path: put.path.clone(),
        person,
        removal,
        size,
    }
}

// -- What a revocation cut reads ---------------------------------------------------

/// Where one held entry stands, as a revocation cut sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Standing {
    /// Applied, or held closed: a cut may keep it.
    Live,
    /// Verified and does not decode: a cut leaves it out and lists it.
    Unreadable,
    /// Refused as outside a cut while its writer's person still writes: only
    /// the revocation of its key does that.
    Revoked,
    /// Any other refusal, or waiting on a removal cut: not the key's work a
    /// cut vouches for.
    Gone,
}

/// One entry held of a device: what a cut reads of it.
#[derive(Clone, Debug)]
pub(crate) struct HeldEntry {
    /// Its seq.
    pub seq: u64,
    /// Where it stands.
    pub standing: Standing,
    /// What was kept when it was verified; `None` if the record is gone or
    /// cannot be read.
    pub marker: Option<Marker>,
    /// The packet at its name, only if it is the one the marker verified.
    pub wire: Option<Bytes>,
}

impl Log {
    /// Call `f` for every entry held of `device` in this space, by seq, one
    /// at a time (a packet is read only for the entry at hand).
    pub(crate) fn each_held(&self, device: &Name, mut f: impl FnMut(HeldEntry)) {
        let Some(dev) = self.devices.get(device) else {
            return;
        };
        let view = self.view();
        let writes = self.fold.is_writer(&dev.person);
        for seq in dev.held.seqs() {
            let standing = match view.status(device, seq) {
                None | Some(Status::Closed) => Standing::Live,
                Some(Status::Unreadable) => Standing::Unreadable,
                Some(Status::Refused(Refusal::OutsideCut(_))) if writes => Standing::Revoked,
                Some(_) => Standing::Gone,
            };
            let marker = view.marker(device, seq);
            let wire = view
                .wire_at(device, seq)
                .filter(|w| marker.is_some_and(|m| signed_digest(w) == m.signed_digest));
            f(HeldEntry {
                seq,
                standing,
                marker,
                wire,
            });
        }
    }
}

// -- What the signal gate reads ----------------------------------------------------

impl Log {
    /// This device's key name, `<device>/KEY/<id>`.
    pub(crate) fn key(&self) -> &Name {
        &self.key
    }

    /// This device's person: the namespace of the context that vouches for
    /// its key.
    pub(crate) fn person(&self) -> &Name {
        &self.person
    }
}
