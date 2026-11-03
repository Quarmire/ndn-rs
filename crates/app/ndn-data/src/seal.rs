//! Seals (spec §9): the keys a sealed collection is read and written with.
//!
//! A sealed collection is read in an [`Epoch`]: named by the members record
//! that started it, its content key derived by the device that signed that
//! record from its **master secret**. A device's master secret is derived
//! from its X25519 recipient secret, which never leaves it. Readers get keys
//! as grants, each wrapped to the asker's published recipient key
//! ([`ndn_security::confidentiality::wrap_ck_to`]): a device of the
//! collection's own namespace gets a creator's master secret (one grant per
//! pair of devices, whatever the number of collections), anyone else of the
//! current audience the one epoch key of one collection. Payloads are sealed
//! with ChaCha20-Poly1305 ([`ContentKey`]), their AAD the version's name.

use std::collections::HashMap;

use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_security::confidentiality::{ContentKey, RecipientKey, Sealed};
use sha2::{Digest, Sha256};

use crate::collection::Epoch;
use crate::version::Content;
use crate::wire;

const MASTER: &[u8] = b"ndn-data/seal/master/1";
const EPOCH_KEY: &[u8] = b"ndn-data/seal/epoch/1";

/// The master secret of the device whose recipient key is `recipient`.
fn master_of(recipient: &RecipientKey) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(MASTER);
    h.update(recipient.expose());
    h.finalize().into()
}

/// The content key of `epoch` of collection `c`, from the epoch creator's
/// master secret.
fn epoch_key(master: &[u8; 32], c: &Name, epoch: &Epoch) -> ContentKey {
    let mut h = Sha256::new();
    h.update(EPOCH_KEY);
    h.update(master);
    h.update(c.encode_to_tlv());
    h.update(epoch.creator.encode_to_tlv());
    h.update(epoch.seq.0.to_be_bytes());
    ContentKey::from_bytes(h.finalize().into())
}

/// The keys one device holds.
pub(crate) struct Keys {
    /// This device's recipient key: grants are wrapped to its public half.
    pub(crate) recipient: RecipientKey,
    /// Master secrets by device: this device's own, and those granted by
    /// other devices of its namespace.
    masters: HashMap<Name, [u8; 32]>,
    /// Epoch keys granted, by collection and epoch.
    granted: HashMap<(Name, Epoch), ContentKey>,
}

impl Keys {
    /// The keys of `device`, whose recipient key is `recipient`.
    pub(crate) fn new(device: &Name, recipient: RecipientKey) -> Self {
        let mut masters = HashMap::new();
        masters.insert(device.clone(), master_of(&recipient));
        Self {
            recipient,
            masters,
            granted: HashMap::new(),
        }
    }

    /// The content key of `epoch` of `c`, if this device holds it or the
    /// master it derives from.
    pub(crate) fn key(&self, c: &Name, epoch: &Epoch) -> Option<ContentKey> {
        if let Some(k) = self.granted.get(&(c.clone(), epoch.clone())) {
            return Some(k.clone());
        }
        self.masters
            .get(&epoch.creator)
            .map(|m| epoch_key(m, c, epoch))
    }

    /// The master secret of `device`, if held.
    pub(crate) fn master(&self, device: &Name) -> Option<ContentKey> {
        self.masters.get(device).map(|m| ContentKey::from_bytes(*m))
    }

    /// Whether `device`'s master secret is held.
    pub(crate) fn has_master(&self, device: &Name) -> bool {
        self.masters.contains_key(device)
    }

    /// Take a granted master secret of `device`.
    pub(crate) fn add_master(&mut self, device: Name, master: &ContentKey) {
        self.masters.insert(device, *master.expose());
    }

    /// Take a granted epoch key.
    pub(crate) fn add_epoch(&mut self, c: Name, epoch: Epoch, key: ContentKey) {
        self.granted.insert((c, epoch), key);
    }
}

/// Seal a version's fields and operation under `key`, bound to its name.
pub(crate) fn seal_payload(key: &ContentKey, name: &Name, fields: &Content, op: &[u8]) -> Bytes {
    key.seal(&wire::encode_payload(fields, op), &name.encode_to_tlv())
        .to_bytes()
}

/// Open a version's sealed payload; `None` if it is not `key`'s, or not
/// this name's.
pub(crate) fn open_payload(
    key: &ContentKey,
    name: &Name,
    ciphertext: &[u8],
) -> Option<(Content, Bytes)> {
    let sealed = Sealed::from_bytes(ciphertext).ok()?;
    let plain = key.open(&sealed, &name.encode_to_tlv()).ok()?;
    wire::decode_payload(Bytes::from(plain)).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::version::Seq;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    #[test]
    fn epoch_keys_derive_alike_from_a_granted_master_and_differ_per_collection_and_epoch() {
        let laptop = n("/alice/laptop");
        let owner = Keys::new(&laptop, RecipientKey::generate());
        let mut phone = Keys::new(&n("/alice/phone"), RecipientKey::generate());
        let (c, e) = (
            n("/alice/32=data/notes"),
            Epoch {
                creator: laptop.clone(),
                seq: Seq(4),
            },
        );
        assert!(phone.key(&c, &e).is_none());
        phone.add_master(laptop.clone(), &owner.master(&laptop).unwrap());
        let k = owner.key(&c, &e).unwrap();
        assert_eq!(phone.key(&c, &e).unwrap().expose(), k.expose());
        let next = Epoch {
            creator: laptop,
            seq: Seq(9),
        };
        assert_ne!(owner.key(&c, &next).unwrap().expose(), k.expose());
        assert_ne!(
            owner.key(&n("/alice/32=data/other"), &e).unwrap().expose(),
            k.expose()
        );
        let name = n("/alice/laptop/32=log/alice/32=data/notes/seq=5");
        let fields = Content::new().with("text", Bytes::from_static(b"secret"));
        let sealed = seal_payload(&k, &name, &fields, b"op");
        assert_eq!(
            open_payload(&k, &name, &sealed),
            Some((fields, Bytes::from_static(b"op")))
        );
        let other = n("/alice/laptop/32=log/alice/32=data/notes/seq=6");
        assert_eq!(open_payload(&k, &other, &sealed), None, "bound to its name");
    }
}
