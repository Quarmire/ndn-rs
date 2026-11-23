//! The store's key layout, its typed records and its batches (spec §4).
//!
//! One [`DataStore`] per node holds everything. A log entry sits at its own
//! name (`<D>/32=log/<S>/seq=<n>`); everything else sits under
//! `/localhost/ndn-heap/`, a prefix no device serves, one key kind per
//! function below. Every write of one entry is one [`DataStore::apply`]
//! through a [`Stage`] batch, so a kill leaves all of an entry's records or
//! none.
//!
//! Where a space name is followed by more components in a key (`structural`,
//! `heads`, `supers`, `epoch`: the keys a scan lists), the space (and the
//! device after it) is one component holding its `Name` TLV. A space name is
//! a prefix of the names of spaces that extend it, so spelled as components
//! a scan of one space's keys would list another's. Keys that are only ever
//! read by their whole name spell the name out.

use std::collections::BTreeMap;
use std::sync::{Arc, LazyLock};
use std::thread::ThreadId;

use bytes::Bytes;
use ndn_foundation_types::{Name, NameComponent};
use ndn_sync::{DataStore, StoreOp};
use parking_lot::Mutex;
use sha2::{Digest, Sha256};

use crate::wire::log_name;

#[cfg(test)]
mod tests;

// -- Keys ------------------------------------------------------------------------

/// `/localhost/ndn-heap`: the prefix of every key that is not an entry.
fn root() -> &'static Name {
    static ROOT: LazyLock<Name> =
        LazyLock::new(|| "/localhost/ndn-heap".parse().expect("a valid name"));
    &ROOT
}

/// `/localhost/ndn-heap/<kind>`.
fn kind(kind: &str) -> Name {
    root().clone().append(kind)
}

/// `prefix` followed by the components of `name`.
fn under(prefix: Name, name: &Name) -> Name {
    Name::from_components(prefix.components().iter().chain(name.components()).cloned())
}

/// `name` as one component: its `Name` TLV.
fn tlv_component(name: &Name) -> NameComponent {
    NameComponent::generic(name.encode_to_tlv())
}

/// A sequence number as one component of 8 octets, big-endian: names order
/// by length and then bytes, so these order numerically.
fn seq_component(seq: u64) -> NameComponent {
    NameComponent::generic(Bytes::copy_from_slice(&seq.to_be_bytes()))
}

/// Where the record that an own entry's signature was verified sits:
/// `verified/<entry name>` ([`Marker`]).
pub(crate) fn verified_key(entry: &Name) -> Name {
    under(kind("verified"), entry)
}

/// That every piece of an entry's value in pieces is held and proved:
/// `assembled/<entry name>` (one octet), written after the last piece, and
/// in the batch of the entry for a value this device wrote.
pub(crate) fn assembled_key(entry: &Name) -> Name {
    under(kind("assembled"), entry)
}

/// The device's own head in a space: `head/<S>` ([`Head`]).
pub(crate) fn head_key(space: &Name) -> Name {
    under(kind("head"), space)
}

/// The sequence reserved in a space: `reserve/<S>` ([`ReserveRecord`]).
pub(crate) fn reserve_key(space: &Name) -> Name {
    under(kind("reserve"), space)
}

/// That the device created or opened a space: `space/<S>` (one octet).
pub(crate) fn space_key(space: &Name) -> Name {
    under(kind("space"), space)
}

/// The revocations of the readers' devices the last epoch this device signed
/// accounted for: `revoked/<S>` (a 32-octet digest, spec §6.6).
pub(crate) fn revoked_key(space: &Name) -> Name {
    under(kind("revoked"), space)
}

/// `<kind>/<S>/<device>/<seq 8>`: a record per entry of a device, listed by
/// [`seq_prefix`].
fn seq_key(label: &str, space: &Name, device: &Name, seq: u64) -> Name {
    seq_prefix(label, space)
        .append_component(tlv_component(device))
        .append_component(seq_component(seq))
}

fn seq_prefix(label: &str, space: &Name) -> Name {
    kind(label).append_component(tlv_component(space))
}

/// The device and seq a [`seq_key`] of `space` names.
fn parse_seq_key(label: &str, space: &Name, key: &Name) -> Option<(Name, u64)> {
    let prefix = seq_prefix(label, space);
    if !key.has_prefix(&prefix) || key.len() != prefix.len() + 2 {
        return None;
    }
    let comps = key.components();
    let device = Name::decode_from_tlv(comps[prefix.len()].value.clone()).ok()?;
    let seq = u64::from_be_bytes(comps[prefix.len() + 1].value.as_ref().try_into().ok()?);
    Some((device, seq))
}

/// A Members or Epoch entry: `structural/<S>/<device>/<seq 8>`, empty.
/// Start replays only these.
pub(crate) fn structural_key(space: &Name, device: &Name, seq: u64) -> Name {
    seq_key("structural", space, device, seq)
}

/// Every [`structural_key`] of `space` has this prefix, and no other
/// space's has.
pub(crate) fn structural_prefix(space: &Name) -> Name {
    seq_prefix("structural", space)
}

/// The device and seq of a [`structural_key`] of `space`.
pub(crate) fn parse_structural_key(space: &Name, key: &Name) -> Option<(Name, u64)> {
    parse_seq_key("structural", space, key)
}

/// The entries that name the entry `<device>/<seq>` with signed-region digest
/// `digest` in their `after`: `supers/<S>/<device>/<seq 8>/<digest>`
/// (`ENTRY_REF*`). The digest is in the key so that a ref naming another
/// packet at the same name hides nothing.
pub(crate) fn supers_key(space: &Name, device: &Name, seq: u64, digest: &[u8; 32]) -> Name {
    seq_key("supers", space, device, seq)
        .append_component(NameComponent::generic(Bytes::copy_from_slice(digest)))
}

/// The epoch key this device made, wrapped to its seal key:
/// `epoch/<S>/<creator>/<seq 8>`.
pub(crate) fn epoch_key(space: &Name, creator: &Name, seq: u64) -> Name {
    seq_key("epoch", space, creator, seq)
}

/// Every [`epoch_key`] of `space` has this prefix.
pub(crate) fn epoch_prefix(space: &Name) -> Name {
    seq_prefix("epoch", space)
}

/// The creator and seq of an [`epoch_key`] of `space`.
pub(crate) fn parse_epoch_key(space: &Name, key: &Name) -> Option<(Name, u64)> {
    parse_seq_key("epoch", space, key)
}

/// The heads of one path: `heads/<S>/<sha256 of the path TLV>` (the path
/// TLV, then `ENTRY_REF*`).
pub(crate) fn heads_key(space: &Name, path_tlv: &[u8]) -> Name {
    heads_prefix(space).append_component(NameComponent::generic(Bytes::copy_from_slice(
        &Sha256::digest(path_tlv),
    )))
}

/// Every [`heads_key`] of `space` has this prefix.
pub(crate) fn heads_prefix(space: &Name) -> Name {
    seq_prefix("heads", space)
}

/// The second packet a device signed under an entry name it already signed
/// another under: `equivocal/<entry name>`.
pub(crate) fn equivocal_key(entry: &Name) -> Name {
    under(kind("equivocal"), entry)
}

/// Since when a key is suspected here: `suspected/<key name>` (ms, 8 octets
/// big-endian).
pub(crate) fn suspected_key(key: &Name) -> Name {
    under(kind("suspected"), key)
}

/// The scoped trust context kept for a person: `scoped/<person>`.
pub(crate) fn scoped_key(person: &Name) -> Name {
    under(kind("scoped"), person)
}

/// `<kind>/<S>/<device>`: a record per device of a space, listed by
/// [`seq_prefix`] and read back by [`parse_device_key`].
fn device_key(label: &str, space: &Name, device: &Name) -> Name {
    seq_prefix(label, space).append_component(tlv_component(device))
}

/// The device a [`device_key`] of `space` names.
fn parse_device_key(label: &str, space: &Name, key: &Name) -> Option<Name> {
    let prefix = seq_prefix(label, space);
    if !key.has_prefix(&prefix) || key.len() != prefix.len() + 1 {
        return None;
    }
    Name::decode_from_tlv(key.components()[prefix.len()].value.clone()).ok()
}

/// What the log knows of one device of a space: its person, the seqs it
/// holds as ranges and the gaps its entries declared: `ledger/<S>/<device>`.
/// Read at open in place of every `verified/` marker.
pub(crate) fn ledger_key(space: &Name, device: &Name) -> Name {
    device_key("ledger", space, device)
}

/// Every [`ledger_key`] of `space` has this prefix.
pub(crate) fn ledger_prefix(space: &Name) -> Name {
    seq_prefix("ledger", space)
}

/// The device a [`ledger_key`] of `space` names.
pub(crate) fn parse_ledger_key(space: &Name, key: &Name) -> Option<Name> {
    parse_device_key("ledger", space, key)
}

/// The seqs a removal cut keeps of one device (chain ancestry of its tips):
/// `kept/<S>/<device>`.
pub(crate) fn kept_key(space: &Name, device: &Name) -> Name {
    device_key("kept", space, device)
}

/// Every [`kept_key`] of `space` has this prefix.
pub(crate) fn kept_prefix(space: &Name) -> Name {
    seq_prefix("kept", space)
}

/// The device a [`kept_key`] of `space` names.
pub(crate) fn parse_kept_key(space: &Name, key: &Name) -> Option<Name> {
    parse_device_key("kept", space, key)
}

/// Why a held entry is not applied: `status/<S>/<device>/<seq 8>`. Absent
/// for an applied entry.
pub(crate) fn status_key(space: &Name, device: &Name, seq: u64) -> Name {
    seq_key("status", space, device, seq)
}

/// Every [`status_key`] of `space` has this prefix.
pub(crate) fn status_prefix(space: &Name) -> Name {
    seq_prefix("status", space)
}

/// The device and seq of a [`status_key`] of `space`.
pub(crate) fn parse_status_key(space: &Name, key: &Name) -> Option<(Name, u64)> {
    parse_seq_key("status", space, key)
}

/// Every [`suspected_key`] has this prefix.
pub(crate) fn suspected_prefix() -> Name {
    kind("suspected")
}

/// The key a [`suspected_key`] names.
pub(crate) fn parse_suspected_key(key: &Name) -> Option<Name> {
    let prefix = suspected_prefix();
    key.has_prefix(&prefix)
        .then(|| Name::from_components(key.components()[prefix.len()..].iter().cloned()))
}

// -- Records ---------------------------------------------------------------------

/// A record the store holds that cannot be read. Never taken for an absent
/// one: a node that cannot tell what it reserved could sign a seq a peer saw.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Corrupt {
    /// The key of the record.
    pub key: Name,
    /// What the record is.
    pub what: &'static str,
}

impl std::fmt::Display for Corrupt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the store holds a {} at {} that cannot be read (damaged, or written by another \
             version); restore the store from a copy, or remove it and let the node recover \
             from its peers",
            self.what, self.key
        )
    }
}

impl std::error::Error for Corrupt {}

fn array<const N: usize>(bytes: &[u8]) -> Option<[u8; N]> {
    bytes.try_into().ok()
}

fn be(bytes: &[u8]) -> Option<u64> {
    Some(u64::from_be_bytes(array(bytes)?))
}

/// What the store keeps of a verified entry (`verified/<entry name>`): enough
/// to walk a chain without reading an entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Marker {
    /// The signed-region digest of the entry.
    pub signed_digest: [u8; 32],
    /// The digest of the public key that verified it.
    pub key_digest: [u8; 32],
    /// The signed-region digest of the previous entry (zero when there is
    /// none, or the device declared it lost everything before).
    pub prev: [u8; 32],
    /// The previous entry's seq, always absolute (the entry's own `seq - 1`
    /// when the log is dense; zero with a zero `prev`).
    pub prev_seq: u64,
    /// When this node first saw the entry, `Config.clock` in milliseconds:
    /// display and cut bounds only.
    pub at: u64,
}

impl Marker {
    /// Octets of an encoded marker.
    pub(crate) const LEN: usize = 112;

    pub(crate) fn encode(&self) -> Bytes {
        let mut out = Vec::with_capacity(Self::LEN);
        out.extend_from_slice(&self.signed_digest);
        out.extend_from_slice(&self.key_digest);
        out.extend_from_slice(&self.prev);
        out.extend_from_slice(&self.prev_seq.to_be_bytes());
        out.extend_from_slice(&self.at.to_be_bytes());
        Bytes::from(out)
    }

    /// `None` for anything but exactly [`Self::LEN`] octets.
    pub(crate) fn decode(bytes: &[u8]) -> Option<Marker> {
        if bytes.len() != Self::LEN {
            return None;
        }
        Some(Marker {
            signed_digest: array(&bytes[..32])?,
            key_digest: array(&bytes[32..64])?,
            prev: array(&bytes[64..96])?,
            prev_seq: be(&bytes[96..104])?,
            at: be(&bytes[104..112])?,
        })
    }
}

/// The device's own head in a space (`head/<S>`), written with every own
/// entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Head {
    /// The seq of the newest own entry.
    pub seq: u64,
    /// Its signed-region digest.
    pub digest: [u8; 32],
}

impl Head {
    pub(crate) fn encode(&self) -> Bytes {
        let mut out = Vec::with_capacity(40);
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.digest);
        Bytes::from(out)
    }

    /// `None` for anything but exactly 40 octets.
    pub(crate) fn decode(bytes: &[u8]) -> Option<Head> {
        if bytes.len() != 40 {
            return None;
        }
        Some(Head {
            seq: be(&bytes[..8])?,
            digest: array(&bytes[8..])?,
        })
    }
}

/// The sequence reserved in a space (`reserve/<S>`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReserveRecord {
    /// The device signs no seq above it once it is durable.
    pub r: u64,
    /// That the last run closed cleanly with `r` equal to its head.
    pub clean: bool,
}

impl ReserveRecord {
    pub(crate) fn encode(&self) -> Bytes {
        let mut out = Vec::with_capacity(9);
        out.extend_from_slice(&self.r.to_be_bytes());
        out.push(u8::from(self.clean));
        Bytes::from(out)
    }

    /// `None` for anything but 9 octets with a clean flag of 0 or 1.
    pub(crate) fn decode(bytes: &[u8]) -> Option<ReserveRecord> {
        if bytes.len() != 9 {
            return None;
        }
        let clean = match bytes[8] {
            0 => false,
            1 => true,
            _ => return None,
        };
        Some(ReserveRecord {
            r: be(&bytes[..8])?,
            clean,
        })
    }
}

/// The write of a [`Head`], to put in a batch.
pub(crate) fn head_op(space: &Name, head: Head) -> StoreOp {
    StoreOp::Insert(head_key(space), head.encode())
}

/// The write of a [`Marker`] for `entry`, to put in a batch.
pub(crate) fn verified_op(entry: &Name, marker: &Marker) -> StoreOp {
    StoreOp::Insert(verified_key(entry), marker.encode())
}

/// The reservation record of `space`; `Ok(None)` when there is none.
pub(crate) fn read_reserve(
    store: &dyn DataStore,
    space: &Name,
) -> Result<Option<ReserveRecord>, Corrupt> {
    let key = reserve_key(space);
    match store.get(&key) {
        None => Ok(None),
        Some(wire) => ReserveRecord::decode(&wire).map(Some).ok_or(Corrupt {
            key,
            what: "reservation record",
        }),
    }
}

/// The head record of `space`; `Ok(None)` when there is none.
pub(crate) fn read_head(store: &dyn DataStore, space: &Name) -> Result<Option<Head>, Corrupt> {
    let key = head_key(space);
    match store.get(&key) {
        None => Ok(None),
        Some(wire) => Head::decode(&wire).map(Some).ok_or(Corrupt {
            key,
            what: "head record",
        }),
    }
}

/// Write the reservation record of `space` straight to the store.
#[cfg(test)]
pub(crate) fn write_reserve(store: &dyn DataStore, space: &Name, record: ReserveRecord) {
    store.insert(reserve_key(space), record.encode());
}

/// Write the head record of `space` straight to the store.
#[cfg(test)]
pub(crate) fn write_head(store: &dyn DataStore, space: &Name, head: Head) {
    store.insert(head_key(space), head.encode());
}

// -- Own head and chains ---------------------------------------------------------

/// One entry of a chain: its seq and signed-region digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Link {
    /// The entry's seq.
    pub seq: u64,
    /// Its signed-region digest.
    pub digest: [u8; 32],
}

/// Where a chain walk stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ChainEnd {
    /// At an entry whose `PREV` says there is none before it.
    Genesis,
    /// The marker of the entry at `seq` is not held: fetch it.
    Missing {
        /// The seq to fetch.
        seq: u64,
    },
    /// The marker at `seq` records another packet than the one the chain
    /// names there.
    Diverges {
        /// The seq.
        seq: u64,
        /// The digest the chain names.
        expected: [u8; 32],
        /// The digest the marker records.
        found: [u8; 32],
    },
    /// The marker at `seq` cannot be read, or links to a seq that is not
    /// below its own.
    Corrupt {
        /// The seq.
        seq: u64,
    },
}

/// The links of a chain walked from a tip, newest first, and where the walk
/// stopped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ChainWalk {
    /// The entries reached, the tip first: each is the one the marker above
    /// it names and has a marker of its own that records its digest.
    pub links: Vec<Link>,
    /// Why it stopped.
    pub end: ChainEnd,
}

#[cfg(test)]
impl ChainWalk {
    /// Whether the chain reaches its first entry.
    pub(crate) fn is_complete(&self) -> bool {
        self.end == ChainEnd::Genesis
    }
}

/// Walk the chain of `device` in `space` from `tip` down through `PREV` and
/// `PREV_SEQ`, reading the `verified/` markers only: no entry is read, so
/// nothing is decoded, and a walk costs one small read per link.
pub(crate) fn walk_chain(
    store: &dyn DataStore,
    device: &Name,
    space: &Name,
    tip: Link,
) -> ChainWalk {
    let mut links = Vec::new();
    let mut at = tip;
    let end = loop {
        let Some(wire) = store.get(&verified_key(&log_name(device, space, at.seq))) else {
            break ChainEnd::Missing { seq: at.seq };
        };
        let Some(marker) = Marker::decode(&wire) else {
            break ChainEnd::Corrupt { seq: at.seq };
        };
        if marker.signed_digest != at.digest {
            break ChainEnd::Diverges {
                seq: at.seq,
                expected: at.digest,
                found: marker.signed_digest,
            };
        }
        if marker.prev == [0; 32] && marker.prev_seq == 0 {
            links.push(at);
            break ChainEnd::Genesis;
        }
        if marker.prev_seq == 0 || marker.prev_seq >= at.seq {
            break ChainEnd::Corrupt { seq: at.seq };
        }
        links.push(at);
        at = Link {
            seq: marker.prev_seq,
            digest: marker.prev,
        };
    };
    ChainWalk { links, end }
}

// -- Batches ---------------------------------------------------------------------

/// The batch open on one thread: what it has written so far.
struct Open {
    owner: ThreadId,
    /// Batches of the owner nested in this one (inner ones join the outer).
    depth: usize,
    ops: Vec<StoreOp>,
}

/// The node's store, with batches ([`Self::batch`]).
///
/// An entry's write is several records: the entry, its marker, the head. Made
/// one by one each is a call into the engine, and a kill between two leaves a
/// state no write leaves. The node wraps the store it is given in a `Stage`
/// and opens a [`Batch`] around the stretch of a write that stores: every
/// write the thread makes through the stage meanwhile is kept, and handed to
/// the store as ONE [`DataStore::apply`] when the batch ends.
///
/// A batch is opened by a thread holding the space's state lock, in a stretch
/// with no `await`, and ends before that lock is released: no other thread
/// publishes what a batch of this thread still holds. Writes of any thread
/// with no batch open go straight through, in the order made. A read by
/// prefix ([`DataStore::scan_under`], [`DataStore::find_under`]) inside a
/// batch answers as the store would with the batch applied, and does not
/// apply it: no part of a write reaches the store before all of it does.
pub(crate) struct Stage {
    store: Arc<dyn DataStore>,
    open: Mutex<Option<Open>>,
}

/// Writes made by the thread that opened it, kept until it is dropped
/// ([`Stage::batch`]).
#[must_use = "a batch ends, and writes what it kept, when it is dropped"]
pub(crate) struct Batch<'a> {
    /// The stage whose batch this thread opened or joined; `None` when
    /// another thread's batch was open (this thread then writes straight
    /// through).
    stage: Option<&'a Stage>,
}

impl Stage {
    pub(crate) fn new(store: Arc<dyn DataStore>) -> Arc<Stage> {
        Arc::new(Stage {
            store,
            open: Mutex::new(None),
        })
    }

    /// Open a batch on this thread, or join the one it has open. Writes this
    /// thread makes through the stage are kept until the outermost guard
    /// drops, and then reach the store as one [`DataStore::apply`], in the
    /// order made.
    pub(crate) fn batch(&self) -> Batch<'_> {
        let me = std::thread::current().id();
        let mut open = self.open.lock();
        match open.as_mut() {
            Some(o) if o.owner == me => {
                o.depth += 1;
                Batch { stage: Some(self) }
            }
            // Another thread's batch is open: this one writes through.
            Some(_) => Batch { stage: None },
            None => {
                *open = Some(Open {
                    owner: me,
                    depth: 1,
                    ops: Vec::new(),
                });
                Batch { stage: Some(self) }
            }
        }
    }

    /// Keep `op` in this thread's open batch; give it back when this thread
    /// has none.
    fn keep(&self, op: StoreOp) -> Option<StoreOp> {
        let mut open = self.open.lock();
        match open.as_mut() {
            Some(o) if o.owner == std::thread::current().id() => {
                o.ops.push(op);
                None
            }
            _ => Some(op),
        }
    }

    /// What this thread's open batch says of `name`: `Some(Some(wire))` it
    /// stores it, `Some(None)` it removes it, `None` nothing (read the
    /// store).
    fn staged(&self, name: &Name) -> Option<Option<Bytes>> {
        let open = self.open.lock();
        let o = open
            .as_ref()
            .filter(|o| o.owner == std::thread::current().id())?;
        o.ops.iter().rev().find_map(|op| match op {
            StoreOp::Insert(n, wire) if n == name => Some(Some(wire.clone())),
            StoreOp::Remove(n) if n == name => Some(None),
            _ => None,
        })
    }

    /// What this thread's open batch says of each name under `prefix`, the
    /// last write of a name standing: `Some` it stores it, `None` it removes
    /// it. Empty when this thread has no batch open, or its batch says
    /// nothing under `prefix` (read the store).
    fn staged_under(&self, prefix: &Name) -> BTreeMap<Name, Option<Bytes>> {
        let open = self.open.lock();
        let Some(o) = open
            .as_ref()
            .filter(|o| o.owner == std::thread::current().id())
        else {
            return BTreeMap::new();
        };
        let mut staged = BTreeMap::new();
        for op in &o.ops {
            match op {
                StoreOp::Insert(n, wire) if n.has_prefix(prefix) => {
                    staged.insert(n.clone(), Some(wire.clone()));
                }
                StoreOp::Remove(n) if n.has_prefix(prefix) => {
                    staged.insert(n.clone(), None);
                }
                _ => {}
            }
        }
        staged
    }

    /// The first `limit` (`0` = all) `(name, wire)` pairs under `prefix` in
    /// ascending name order, as the store would answer once the open batch
    /// was applied: what it stores appears (over the store's own at that
    /// name), what it removes does not. The batch is not applied: a read is
    /// not a point to hand a part of a write to the store, which a kill would
    /// leave half done.
    fn merged(
        &self,
        prefix: &Name,
        limit: usize,
        staged: BTreeMap<Name, Option<Bytes>>,
    ) -> Vec<(Name, Bytes)> {
        // Each staged name hides at most one of the store's, so asking for
        // that many more leaves `limit` of the store's that stand.
        let ask = if limit == 0 { 0 } else { limit + staged.len() };
        let mut found: BTreeMap<Name, Bytes> = self
            .store
            .scan_under(prefix, ask)
            .into_iter()
            .filter(|(name, _)| !staged.contains_key(name))
            .collect();
        found.extend(
            staged
                .into_iter()
                .filter_map(|(name, wire)| Some((name, wire?))),
        );
        let found = found.into_iter();
        match limit {
            0 => found.collect(),
            limit => found.take(limit).collect(),
        }
    }
}

impl Drop for Batch<'_> {
    fn drop(&mut self) {
        let Some(stage) = self.stage else { return };
        let ops = {
            let mut open = stage.open.lock();
            let o = open
                .as_mut()
                .expect("a batch's stage holds the batch it opened until the batch drops");
            o.depth -= 1;
            if o.depth > 0 {
                return;
            }
            open.take().map(|o| o.ops).unwrap_or_default()
        };
        if !ops.is_empty() {
            stage.store.apply(ops);
        }
    }
}

impl DataStore for Stage {
    fn insert(&self, name: Name, wire: Bytes) {
        if let Some(StoreOp::Insert(name, wire)) = self.keep(StoreOp::Insert(name, wire)) {
            self.store.insert(name, wire);
        }
    }

    fn get(&self, name: &Name) -> Option<Bytes> {
        match self.staged(name) {
            Some(own) => own,
            None => self.store.get(name),
        }
    }

    fn contains(&self, name: &Name) -> bool {
        match self.staged(name) {
            Some(own) => own.is_some(),
            None => self.store.contains(name),
        }
    }

    fn find_under(&self, prefix: &Name) -> Option<Bytes> {
        let staged = self.staged_under(prefix);
        if staged.is_empty() {
            return self.store.find_under(prefix);
        }
        self.merged(prefix, 1, staged)
            .into_iter()
            .next()
            .map(|(_, wire)| wire)
    }

    fn scan_under(&self, prefix: &Name, limit: usize) -> Vec<(Name, Bytes)> {
        let staged = self.staged_under(prefix);
        if staged.is_empty() {
            return self.store.scan_under(prefix, limit);
        }
        self.merged(prefix, limit, staged)
    }

    fn remove(&self, name: &Name) {
        if let Some(StoreOp::Remove(name)) = self.keep(StoreOp::Remove(name.clone())) {
            self.store.remove(&name);
        }
    }

    fn apply(&self, ops: Vec<StoreOp>) {
        let mut open = self.open.lock();
        match open.as_mut() {
            Some(o) if o.owner == std::thread::current().id() => o.ops.extend(ops),
            _ => {
                drop(open);
                self.store.apply(ops);
            }
        }
    }

    fn sync(&self) -> std::io::Result<()> {
        self.store.sync()
    }

    fn sync_is_immediate(&self) -> bool {
        self.store.sync_is_immediate()
    }
}
