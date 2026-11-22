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
use ndn_security::confidentiality::{
    ConfidentialityError, ContentKey, RecipientKey, Sealed, wrap_ck_to,
};
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
    /// record naming its epoch, by epoch and the collection or folder whose
    /// record names it.
    held: HashMap<Epoch, Vec<(Name, ContentKey)>>,
}

impl Keys {
    /// The keys of a device whose recipient key is `recipient`.
    pub(crate) fn new(recipient: RecipientKey) -> Self {
        Self {
            recipient,
            held: HashMap::new(),
        }
    }

    /// The content key of `epoch` of `c`, if held: `c`'s own, or that of a
    /// folder above `c` whose epoch it is (spec §6: one key per folder
    /// epoch opens every collection under the folder that reads in it).
    pub(crate) fn key(&self, c: &Name, epoch: &Epoch) -> Option<ContentKey> {
        self.held
            .get(epoch)?
            .iter()
            .filter(|(at, _)| c.has_prefix(at))
            .max_by_key(|(at, _)| at.len())
            .map(|(_, k)| k.clone())
    }

    /// Hold `key` as the content key of `epoch` of `c` (checked by the
    /// caller).
    pub(crate) fn hold(&mut self, c: Name, epoch: Epoch, key: ContentKey) {
        let held = self.held.entry(epoch).or_default();
        match held.iter_mut().find(|(at, _)| *at == c) {
            Some((_, k)) => *k = key,
            None => held.push((c, key)),
        }
    }
}

/// Seal a version's fields and operation under `key`, bound to its name.
pub(crate) fn seal_payload(key: &ContentKey, name: &Name, fields: &Content, op: &[u8]) -> Bytes {
    key.seal(&wire::encode_payload(fields, op), &name.encode_to_tlv())
        .to_bytes()
}

/// Open a version's sealed payload: its fields and operation; `None` if it
/// is not `key`'s, or not this name's.
pub(crate) fn open_payload(
    key: &ContentKey,
    name: &Name,
    ciphertext: &[u8],
) -> Option<(Content, Bytes)> {
    let sealed = Sealed::from_bytes(ciphertext).ok()?;
    let plain = key.open(&sealed, &name.encode_to_tlv()).ok()?;
    wire::decode_payload(Bytes::from(plain)).ok()
}

// ---- asks (spec §19.4) ---------------------------------------------------------------------------

/// An ask sealed to a device's seal key: a fresh content key wrapped to that key with a fresh
/// ephemeral X25519 key, and the ask's plaintext sealed under the content key, both bound to
/// `aad`, the Interest's name without its parameters digest.
pub(crate) struct SealedAsk {
    /// The asker's ephemeral X25519 public key.
    pub(crate) ephemeral: [u8; 32],
    /// The content key, wrapped to the seal key.
    pub(crate) key: Bytes,
    /// The plaintext, sealed under the content key.
    pub(crate) sealed: Bytes,
}

/// A content key wrapped to a seal key, before the plaintext is sealed under it: an ask whose
/// proof binds the ephemeral key needs the key to make its plaintext.
pub(crate) struct AskKey {
    ck: ContentKey,
    /// The asker's ephemeral X25519 public key.
    pub(crate) ephemeral: [u8; 32],
    key: Bytes,
}

impl AskKey {
    /// Make a content key and wrap it to `seal_key`, bound to `aad`.
    pub(crate) fn to(seal_key: &[u8; 32], aad: &[u8]) -> Result<Self, ConfidentialityError> {
        let ck = ContentKey::generate();
        let (ephemeral, wrapped) = wrap_ck_to(seal_key, &ck, aad)?;
        Ok(AskKey {
            ck,
            ephemeral,
            key: wrapped.to_bytes(),
        })
    }

    /// Seal `plain` under the content key, bound to `aad`.
    pub(crate) fn seal(self, plain: &[u8], aad: &[u8]) -> SealedAsk {
        SealedAsk {
            ephemeral: self.ephemeral,
            key: self.key,
            sealed: self.ck.seal(plain, aad).to_bytes(),
        }
    }
}

/// Seal an ask's `plain` to the seal key `to`, bound to `aad`.
pub(crate) fn seal_ask(
    to: &[u8; 32],
    aad: &[u8],
    plain: &[u8],
) -> Result<SealedAsk, ConfidentialityError> {
    Ok(AskKey::to(to, aad)?.seal(plain, aad))
}

/// Open an ask sealed to `recipient`: the plaintext, or `None` if the key does not unwrap, the
/// ciphertext does not open, or either is not bound to `aad`.
pub(crate) fn open_ask(
    recipient: &RecipientKey,
    aad: &[u8],
    ephemeral: &[u8; 32],
    key: &[u8],
    sealed: &[u8],
) -> Option<Vec<u8>> {
    let ck = recipient
        .unwrap_ck(ephemeral, &Sealed::from_bytes(key).ok()?, aad)
        .ok()?;
    ck.open(&Sealed::from_bytes(sealed).ok()?, aad).ok()
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
