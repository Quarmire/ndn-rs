//! Seals (spec §9): the keys a sealed collection is read and written with.
//!
//! A sealed collection is read in an [`Epoch`], named by the members record
//! that started it. Its content key is 32 random octets made by the device
//! that signed that record; the record carries the key's **check**
//! ([`key_check`]), so any key a device is given can be checked against the
//! owner-signed record before it is used. Readers get keys as grants, each
//! wrapped to the asker's published recipient key
//! ([`ndn_security::confidentiality::wrap_ck_to`]), one per epoch of one
//! collection. Payloads are sealed with ChaCha20-Poly1305 ([`ContentKey`]),
//! their AAD the version's name.

use std::collections::HashMap;

use bytes::Bytes;
use hkdf::Hkdf;
use ndn_foundation_types::Name;
use ndn_security::confidentiality::{ContentKey, RecipientKey, Sealed};
use sha2::Sha256;

use crate::collection::Epoch;
use crate::version::Content;
use crate::wire;

/// The domain label of an epoch key's check.
const KEY_CHECK: &[u8] = b"ndn-data/seal/check/1";

/// The check of `key` as the content key of `epoch` of collection `c`:
/// HKDF-SHA256 with the key as input key material, no salt, and `info` the
/// label, the TLVs of `c` and of the epoch's creator and the epoch's seq as
/// 8 octets, big-endian. The record starting the epoch carries it.
pub(crate) fn key_check(key: &ContentKey, c: &Name, epoch: &Epoch) -> [u8; 32] {
    let mut check = [0u8; 32];
    Hkdf::<Sha256>::new(None, key.expose())
        .expand_multi_info(
            &[
                KEY_CHECK,
                &c.encode_to_tlv(),
                &epoch.creator.encode_to_tlv(),
                &epoch.seq.0.to_be_bytes(),
            ],
            &mut check,
        )
        .expect("32 octets is a valid HKDF-SHA256 output length");
    check
}

/// The keys one device holds.
pub(crate) struct Keys {
    /// This device's recipient key: grants are wrapped to its public half.
    pub(crate) recipient: RecipientKey,
    /// Epoch keys this device made or was granted, each checked against the
    /// record naming its epoch, by collection and epoch.
    held: HashMap<(Name, Epoch), ContentKey>,
}

impl Keys {
    /// The keys of a device whose recipient key is `recipient`.
    pub(crate) fn new(recipient: RecipientKey) -> Self {
        Self {
            recipient,
            held: HashMap::new(),
        }
    }

    /// The content key of `epoch` of `c`, if held.
    pub(crate) fn key(&self, c: &Name, epoch: &Epoch) -> Option<ContentKey> {
        self.held.get(&(c.clone(), epoch.clone())).cloned()
    }

    /// Hold `key` as the content key of `epoch` of `c` (checked by the
    /// caller).
    pub(crate) fn hold(&mut self, c: Name, epoch: Epoch, key: ContentKey) {
        self.held.insert((c, epoch), key);
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
    fn a_key_check_binds_the_key_to_its_collection_and_epoch() {
        let (c, e) = (
            n("/alice/32=data/notes"),
            Epoch {
                creator: n("/alice/laptop"),
                seq: Seq(4),
            },
        );
        let k = ContentKey::generate();
        let check = key_check(&k, &c, &e);
        assert_eq!(check, key_check(&k, &c, &e));
        assert_ne!(
            check,
            key_check(&ContentKey::generate(), &c, &e),
            "another key"
        );
        assert_ne!(
            check,
            key_check(&k, &n("/alice/32=data/other"), &e),
            "another collection"
        );
        let next = Epoch {
            creator: n("/alice/laptop"),
            seq: Seq(9),
        };
        assert_ne!(check, key_check(&k, &c, &next), "another epoch");
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
