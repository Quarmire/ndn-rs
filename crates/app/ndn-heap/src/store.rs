//! The store's key layout, its typed records and its batches (spec §4).
//!
//! One [`DataStore`] per node holds everything. A log entry sits at its own
//! name (`<D>/32=log/<S>/seq=<n>`); everything else sits under
//! `/localhost/ndn-heap/`, a prefix no device serves, one key kind per
//! function below. Every write of one entry is one [`DataStore::apply`]
//! through a [`Batch`], so a kill leaves all of an entry's records or none.
//!
//! Where a space name is followed by more components in a key (`structural`,
//! `heads`, `supers`, `epoch`: the keys a scan lists), the space (and the
//! device after it) is one component holding its `Name` TLV. A space name is
//! a prefix of the names of spaces that extend it, so spelled as components
//! a scan of one space's keys would list another's. Keys that are only ever
//! read by their whole name spell the name out.

use std::collections::BTreeMap;
use std::sync::{Arc, LazyLock};

use bytes::Bytes;
use ndn_foundation_types::{Name, NameComponent};
use ndn_sync::{DataStore, StoreOp};
use parking_lot::Mutex;
use sha2::{Digest, Sha256};

use crate::error::HeapError;
use crate::wire::log_name;

#[cfg(test)]
mod tests;

// -- Keys ------------------------------------------------------------------------

/// A kind of key: the component after `/localhost/ndn-heap` (a prefix no
/// device serves). Every key is built and read back here, so a kind's keys
/// and the prefix a scan of them lists cannot disagree.
///
/// The kinds in three shapes: [`Self::of`] (`<kind>/<name>`, one record per
/// name), and with a space, [`Self::device`] (`<kind>/<S>/<device>`) and
/// [`Self::seq`] (`<kind>/<S>/<device>/<seq 8>`), listed by [`Self::listing`]
/// and read back by [`Self::parse_device`] and [`Self::parse_seq`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Kind(&'static str);

/// The version of the owner rule (spec §9.9): 2 is "only an `admin` or `member` device of the
/// owner holds the owner's powers, only an `admin` or `member` device of a reader is granted
/// an epoch key, and an owner device tracks the devices it grants keys to" (stage 7; a space
/// stored under 1 may hold keys given to a reader's guest or node device and to devices no
/// owner device tracks, so it gets a fresh epoch at start); 1 is the first half alone; 0
/// (no record) judged every device of the owner's namespace as an owner device.
pub(crate) const OWNER_RULE: u8 = 2;

impl Kind {
    /// `verified/<entry name>`: that an entry's signature was verified
    /// ([`Marker`]).
    pub(crate) const VERIFIED: Kind = Kind("verified");
    /// `assembled/<entry name>`: that every piece of an entry's value in
    /// pieces is held and proved (one octet), written after the last piece,
    /// and in the batch of the entry for a value this device wrote.
    pub(crate) const ASSEMBLED: Kind = Kind("assembled");
    /// `equivocal/<entry name>`: the second packet a device signed under an
    /// entry name it already signed another under.
    pub(crate) const EQUIVOCAL: Kind = Kind("equivocal");
    /// `suspected/<key name>`: since when a key is suspected here (ms, 8
    /// octets big-endian).
    pub(crate) const SUSPECTED: Kind = Kind("suspected");
    /// `scoped/<person>`: the scoped trust context kept for a person.
    pub(crate) const SCOPED: Kind = Kind("scoped");
    /// `head/<S>`: the device's own head in a space ([`Link`]).
    pub(crate) const HEAD: Kind = Kind("head");
    /// `reserve/<S>`: the sequence reserved in a space ([`ReserveRecord`]).
    pub(crate) const RESERVE: Kind = Kind("reserve");
    /// `space/<S>`: that the device created or opened a space (one octet).
    pub(crate) const SPACE: Kind = Kind("space");
    /// `revoked/<S>`: the revocations of the readers' devices the last epoch
    /// this device signed accounted for (a 32-octet digest, spec §6.6).
    pub(crate) const REVOKED: Kind = Kind("revoked");
    /// `rule/<S>`: the version of the owner rule (spec §9.9) the space's
    /// entries were last judged by here (one octet, [`OWNER_RULE`]). A space
    /// with entries and no such record, or an older one, is judged once at
    /// start, and the owner devices sign a fresh epoch.
    pub(crate) const RULE: Kind = Kind("rule");
    /// `structural/<S>/<device>/<seq 8>`, empty: a Members or Epoch entry.
    /// Start replays only these.
    pub(crate) const STRUCTURAL: Kind = Kind("structural");
    /// `epoch/<S>/<creator>/<seq 8>`: the epoch key this device made, wrapped
    /// to its seal key.
    pub(crate) const EPOCH: Kind = Kind("epoch");
    /// `status/<S>/<device>/<seq 8>`: why a held entry is not applied. Absent
    /// for an applied entry.
    pub(crate) const STATUS: Kind = Kind("status");
    /// `ledger/<S>/<device>`: what the log knows of one device of a space: its
    /// person, the seqs it holds as ranges and the gaps its entries declared.
    /// Read at open in place of every `verified/` marker.
    pub(crate) const LEDGER: Kind = Kind("ledger");
    /// `heads/<S>/<sha256 of the path TLV>` ([`heads_key`]): the heads of one
    /// path.
    pub(crate) const HEADS: Kind = Kind("heads");
    /// `supers/<S>/<device>/<seq 8>/<digest>` ([`supers_key`]): the entries
    /// that name an entry in their `after`.
    pub(crate) const SUPERS: Kind = Kind("supers");
    /// `joined/<S>`: that an offer's answer admitted this device to the space
    /// `S` and the space's members do not list its person yet
    /// ([`crate::Node::note_joined`]): one octet, 1, then the 32-octet
    /// signed-region digest of each members entry held that removes her. While
    /// it stands, a put the fold refuses for want of a listing is a wait; it is
    /// removed when the fold lists the person, and when a removal of her
    /// arrives that it does not name.
    pub(crate) const JOINED: Kind = Kind("joined");
    /// `granted/<S>/<person>/<key>`: the grant ask (`GrantAsk`: the asker's seal key packet and
    /// the certificate chain it carried) of a device of `<person>` this owner device granted an
    /// epoch key of the sealed space `S` to, by the key that signed the packet. What a lapse
    /// is judged by, restart or not ([`crate::space::SpaceInner::sweep_lapsed`]); removed
    /// once the epoch signed for the lapse is, when the person no longer reads, and when the
    /// key is revoked. Per person, so that her records are counted and dropped by one prefix.
    pub(crate) const GRANTED: Kind = Kind("granted");

    /// `/localhost/ndn-heap/<kind>`: the prefix of every key of the kind.
    fn root(self) -> Name {
        static ROOT: LazyLock<Name> =
            LazyLock::new(|| "/localhost/ndn-heap".parse().expect("a valid name"));
        ROOT.clone().append(self.0)
    }

    /// `<kind>/<name>`: the components of `name` follow the kind.
    pub(crate) fn of(self, name: &Name) -> Name {
        let root = self.root();
        Name::from_components(root.components().iter().chain(name.components()).cloned())
    }

    /// Every `<kind>/<name>` the store holds, with the name and the value, in
    /// name order.
    pub(crate) fn named(self, store: &dyn DataStore) -> Vec<(Name, Bytes)> {
        let prefix = self.root();
        let skip = prefix.len();
        let held = store.scan_under(&prefix, 0);
        held.into_iter()
            .map(|(key, value)| {
                (
                    Name::from_components(key.components()[skip..].iter().cloned()),
                    value,
                )
            })
            .collect()
    }

    /// `<kind>/<S>`, `S` one component holding its `Name` TLV: every key of
    /// the kind in `space` has this prefix, and no other space's has. A space
    /// name is a prefix of the names of spaces that extend it, so spelled as
    /// components a scan of one space's keys would list another's.
    pub(crate) fn listing(self, space: &Name) -> Name {
        self.root().append_component(tlv_component(space))
    }

    /// `<kind>/<S>/<device>`, the device as one component too.
    pub(crate) fn device(self, space: &Name, device: &Name) -> Name {
        self.listing(space).append_component(tlv_component(device))
    }

    /// `<kind>/<S>/<device>/<seq 8>`: the seq one component of 8 octets,
    /// big-endian, so names, which order by length and then bytes, order
    /// numerically.
    pub(crate) fn seq(self, space: &Name, device: &Name, seq: u64) -> Name {
        let seq = NameComponent::generic(Bytes::copy_from_slice(&seq.to_be_bytes()));
        self.device(space, device).append_component(seq)
    }

    /// What follows [`Self::listing`] in `key` (nothing when `key` is not one
    /// of the listing's).
    fn tail<'k>(self, space: &Name, key: &'k Name) -> &'k [NameComponent] {
        let prefix = self.listing(space);
        if key.has_prefix(&prefix) {
            &key.components()[prefix.len()..]
        } else {
            &[]
        }
    }

    /// The device a [`Self::device`] key of `space` names.
    pub(crate) fn parse_device(self, space: &Name, key: &Name) -> Option<Name> {
        let [device] = self.tail(space, key) else {
            return None;
        };
        Name::decode_from_tlv(device.value.clone()).ok()
    }

    /// The device and seq a [`Self::seq`] key of `space` names.
    pub(crate) fn parse_seq(self, space: &Name, key: &Name) -> Option<(Name, u64)> {
        let [device, seq] = self.tail(space, key) else {
            return None;
        };
        let device = Name::decode_from_tlv(device.value.clone()).ok()?;
        Some((
            device,
            u64::from_be_bytes(seq.value.as_ref().try_into().ok()?),
        ))
    }

    /// `<kind>/<S>/<person>`: the prefix of every [`Self::pair`] key of one person.
    pub(crate) fn person(self, space: &Name, person: &Name) -> Name {
        self.listing(space).append_component(tlv_component(person))
    }

    /// `<kind>/<S>/<person>/<key>`, each as one component.
    pub(crate) fn pair(self, space: &Name, person: &Name, key: &Name) -> Name {
        self.person(space, person)
            .append_component(tlv_component(key))
    }

    /// The person and key a [`Self::pair`] key of `space` names.
    pub(crate) fn parse_pair(self, space: &Name, key: &Name) -> Option<(Name, Name)> {
        let [person, device] = self.tail(space, key) else {
            return None;
        };
        Some((
            Name::decode_from_tlv(person.value.clone()).ok()?,
            Name::decode_from_tlv(device.value.clone()).ok()?,
        ))
    }
}

/// `name` as one component: its `Name` TLV.
fn tlv_component(name: &Name) -> NameComponent {
    NameComponent::generic(name.encode_to_tlv())
}

/// The entries that name the entry `<device>/<seq>` with signed-region digest
/// `digest` in their `after` (`ENTRY_REF*`). The digest is in the key so that
/// a ref naming another packet at the same name hides nothing.
pub(crate) fn supers_key(space: &Name, device: &Name, seq: u64, digest: &[u8; 32]) -> Name {
    Kind::SUPERS
        .seq(space, device, seq)
        .append_component(NameComponent::generic(Bytes::copy_from_slice(digest)))
}

/// The heads of one path: `heads/<S>/<sha256 of the path TLV>` (the path
/// TLV, then `ENTRY_REF*`).
pub(crate) fn heads_key(space: &Name, path_tlv: &[u8]) -> Name {
    Kind::HEADS
        .listing(space)
        .append_component(NameComponent::generic(Bytes::copy_from_slice(
            &Sha256::digest(path_tlv),
        )))
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

impl From<Corrupt> for HeapError {
    fn from(why: Corrupt) -> HeapError {
        HeapError::local(why)
    }
}

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
    pub(crate) fn encode(&self) -> Bytes {
        [
            &self.signed_digest[..],
            &self.key_digest,
            &self.prev,
            &self.prev_seq.to_be_bytes(),
            &self.at.to_be_bytes(),
        ]
        .concat()
        .into()
    }

    /// `None` for anything but exactly 112 octets.
    pub(crate) fn decode(bytes: &[u8]) -> Option<Marker> {
        let bytes: &[u8; 112] = bytes.try_into().ok()?;
        Some(Marker {
            signed_digest: array(&bytes[..32])?,
            key_digest: array(&bytes[32..64])?,
            prev: array(&bytes[64..96])?,
            prev_seq: be(&bytes[96..104])?,
            at: be(&bytes[104..112])?,
        })
    }

    /// The marker of the entry `<device>/<seq>` of `space`; `None` when there
    /// is none, or it cannot be read.
    pub(crate) fn read(
        store: &dyn DataStore,
        device: &Name,
        space: &Name,
        seq: u64,
    ) -> Option<Marker> {
        Marker::decode(&store.get(&Kind::VERIFIED.of(&log_name(device, space, seq)))?)
    }
}

impl Link {
    /// The `head/<S>` record: the device's own head in a space, the link of
    /// its newest own entry, written with every own entry.
    pub(crate) fn encode(&self) -> Bytes {
        [&self.seq.to_be_bytes()[..], &self.digest].concat().into()
    }

    /// `None` for anything but exactly 40 octets.
    pub(crate) fn decode(bytes: &[u8]) -> Option<Link> {
        let bytes: &[u8; 40] = bytes.try_into().ok()?;
        Some(Link {
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
        [&self.r.to_be_bytes()[..], &[u8::from(self.clean)]]
            .concat()
            .into()
    }

    /// `None` for anything but 9 octets with a clean flag of 0 or 1.
    pub(crate) fn decode(bytes: &[u8]) -> Option<ReserveRecord> {
        let bytes: &[u8; 9] = bytes.try_into().ok()?;
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

/// The record at `key` decoded by `decode`; `Ok(None)` when there is none,
/// and an error naming the key (`what` it is) when it cannot be read.
pub(crate) fn read<T>(
    store: &dyn DataStore,
    key: Name,
    what: &'static str,
    decode: impl FnOnce(&Bytes) -> Option<T>,
) -> Result<Option<T>, Corrupt> {
    let Some(wire) = store.get(&key) else {
        return Ok(None);
    };
    decode(&wire).map(Some).ok_or(Corrupt { key, what })
}

/// The reservation record of `space`; `Ok(None)` when there is none.
pub(crate) fn read_reserve(
    store: &dyn DataStore,
    space: &Name,
) -> Result<Option<ReserveRecord>, Corrupt> {
    let key = Kind::RESERVE.of(space);
    read(store, key, "reservation record", |w| {
        ReserveRecord::decode(w)
    })
}

/// The head record of `space`; `Ok(None)` when there is none.
pub(crate) fn read_head(store: &dyn DataStore, space: &Name) -> Result<Option<Link>, Corrupt> {
    read(store, Kind::HEAD.of(space), "head record", |w| {
        Link::decode(w)
    })
}

/// Write the reservation record of `space` straight to the store.
#[cfg(test)]
pub(crate) fn write_reserve(store: &dyn DataStore, space: &Name, record: ReserveRecord) {
    store.insert(Kind::RESERVE.of(space), record.encode());
}

/// Write the head record of `space` straight to the store.
#[cfg(test)]
pub(crate) fn write_head(store: &dyn DataStore, space: &Name, head: Link) {
    store.insert(Kind::HEAD.of(space), head.encode());
}

// -- Own head and chains ---------------------------------------------------------

/// One entry of a chain: its seq and signed-region digest.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Link {
    /// The entry's seq.
    pub seq: u64,
    /// Its signed-region digest.
    pub digest: [u8; 32],
}

// -- Batches ---------------------------------------------------------------------

/// The writes of one entry, kept until [`Batch::commit`] hands them to the
/// store as ONE [`DataStore::apply`], in the order made.
///
/// An entry's write is several records: the entry, its marker, the head. Made
/// one by one each is a call into the engine, and a kill between two leaves a
/// state no write leaves. A `Log` owns one `Batch` over the node's store and
/// writes through it; its entry points (all under the space's lock) end with
/// `commit`. Every read through the batch answers as the store would with the
/// batch applied, and does not apply it: no part of a write reaches the store
/// before all of it does. A read of the store itself never sees a batch.
pub(crate) struct Batch {
    store: Arc<dyn DataStore>,
    ops: Mutex<Vec<StoreOp>>,
}

impl Batch {
    pub(crate) fn new(store: Arc<dyn DataStore>) -> Batch {
        Batch {
            store,
            ops: Mutex::new(Vec::new()),
        }
    }

    /// Hand what was written to the store as one batch.
    pub(crate) fn commit(&self) {
        let ops = std::mem::take(&mut *self.ops.lock());
        if !ops.is_empty() {
            self.store.apply(ops);
        }
    }
}

impl DataStore for Batch {
    fn insert(&self, name: Name, wire: Bytes) {
        self.ops.lock().push(StoreOp::Insert(name, wire));
    }

    fn remove(&self, name: &Name) {
        self.ops.lock().push(StoreOp::Remove(name.clone()));
    }

    fn get(&self, name: &Name) -> Option<Bytes> {
        let staged = self.ops.lock().iter().rev().find_map(|op| match op {
            StoreOp::Insert(n, wire) if n == name => Some(Some(wire.clone())),
            StoreOp::Remove(n) if n == name => Some(None),
            _ => None,
        });
        staged.unwrap_or_else(|| self.store.get(name))
    }

    fn find_under(&self, prefix: &Name) -> Option<Bytes> {
        self.scan_under(prefix, 1).pop().map(|(_, wire)| wire)
    }

    /// The first `limit` (`0` = all) pairs under `prefix` in ascending name
    /// order: what the batch stores appears (over the store's own at that
    /// name), what it removes does not.
    fn scan_under(&self, prefix: &Name, limit: usize) -> Vec<(Name, Bytes)> {
        let mut staged: BTreeMap<Name, Option<Bytes>> = BTreeMap::new();
        for op in self.ops.lock().iter() {
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
        if staged.is_empty() {
            return self.store.scan_under(prefix, limit);
        }
        // Each staged name hides at most one of the store's, so asking for
        // that many more leaves `limit` of the store's that stand.
        let ask = if limit == 0 { 0 } else { limit + staged.len() };
        let mut found: BTreeMap<Name, Bytes> = self
            .store
            .scan_under(prefix, ask)
            .into_iter()
            .filter(|(name, _)| !staged.contains_key(name))
            .collect();
        found.extend(staged.into_iter().filter_map(|(n, wire)| Some((n, wire?))));
        let limit = if limit == 0 { usize::MAX } else { limit };
        found.into_iter().take(limit).collect()
    }

    fn sync(&self) -> std::io::Result<()> {
        self.store.sync()
    }
}
