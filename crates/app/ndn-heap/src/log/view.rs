//! Reads of what the log holds: markers, statuses, packets and what an
//! applied entry wrote. Borrows the log's parts rather than the log, so the
//! register can be changed while a closure reads through it.

use std::collections::BTreeMap;

use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_packet::Data;
use ndn_sync::DataStore;

use super::chain::{Dev, Status};
use super::{Log, decode_wire};
use crate::fold::Fold;
use crate::register::{Write, decode_refs};
use crate::seal::{self, Keys};
use crate::store::{Marker, equivocal_key, status_key, supers_key, verified_key};
use crate::wire::{self, Body, Entry, EntryRef, Payload, PutBody, log_name, signed_digest};

pub(super) struct View<'a> {
    pub store: &'a dyn DataStore,
    pub space: &'a Name,
    pub fold: &'a Fold,
    pub keys: &'a Keys,
    pub devices: &'a BTreeMap<Name, Dev>,
}

impl<'a> View<'a> {
    pub(super) fn of(log: &'a Log) -> View<'a> {
        View {
            store: &*log.store,
            space: &log.space,
            fold: &log.fold,
            keys: &log.keys,
            devices: &log.devices,
        }
    }

    pub(super) fn marker(&self, device: &Name, seq: u64) -> Option<Marker> {
        Marker::decode(
            &self
                .store
                .get(&verified_key(&log_name(device, self.space, seq)))?,
        )
    }

    pub(super) fn status(&self, device: &Name, seq: u64) -> Option<Status> {
        Status::decode(
            &self.store.get(&status_key(self.space, device, seq))?,
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
            .chain(self.store.get(&equivocal_key(&name)))
            .collect()
    }

    /// The entries that name `x` in their `after` (applied ones).
    pub(super) fn namers(&self, x: &EntryRef) -> Vec<EntryRef> {
        self.store
            .get(&supers_key(self.space, &x.device, x.seq))
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

    /// What the applied entry `r` wrote; `None` when it is not held, not
    /// applied, or not a write. The register asks for it when an entry it
    /// superseded returns.
    pub(super) fn write_of(&self, r: &EntryRef) -> Option<Write> {
        let wire = self.wire_at(&r.device, r.seq)?;
        if signed_digest(&wire) != r.digest || self.status(&r.device, r.seq).is_some() {
            return None;
        }
        let (entry, _) = decode_wire(&wire)?;
        let put = self.opened_put(&entry, &log_name(&r.device, self.space, r.seq))?;
        let person = self.devices.get(&r.device)?.person.clone();
        Some(write_for(&put, person))
    }

    /// The payload the applied entry `r` wrote.
    pub(super) fn payload_of(&self, r: &EntryRef) -> Option<Payload> {
        let wire = self.wire_at(&r.device, r.seq)?;
        if signed_digest(&wire) != r.digest {
            return None;
        }
        let (entry, _) = decode_wire(&wire)?;
        let put = self.opened_put(&entry, &log_name(&r.device, self.space, r.seq))?;
        Some(put.payload)
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
