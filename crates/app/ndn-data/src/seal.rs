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

use hmac::{Hmac, KeyInit, Mac};
use zeroize::Zeroizing;

use bytes::Bytes;
use hkdf::Hkdf;
use ndn_foundation_types::Name;
use ndn_security::confidentiality::{
    ConfidentialityError, ContentKey, RecipientKey, Sealed, wrap_ck_to,
};
use sha2::Sha256;

use crate::answer::{
    AnswerBinding, AnswerKind, LABEL_AAD, LABEL_ID, LABEL_NAME, LABEL_RESULT, LABEL_SEAL,
};
use crate::collection::Epoch;
use crate::version::Content;
use crate::wire::{self, Inline};

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

    /// The content key of `epoch`, whichever collection or folder's record names it: an
    /// epoch is one record's, and so has one key. What an answer, which names no collection in
    /// the clear, opens with (answers.md §5.2).
    pub(crate) fn key_of_epoch(&self, epoch: &Epoch) -> Option<ContentKey> {
        self.held.get(epoch)?.first().map(|(_, k)| k.clone())
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

    /// Destroy the content key of `epoch` of `c`: the held copy is dropped
    /// (and zeroed, [`ContentKey`] is `ZeroizeOnDrop`). Whether one was held.
    pub(crate) fn forget(&mut self, c: &Name, epoch: &Epoch) -> bool {
        let Some(held) = self.held.get_mut(epoch) else {
            return false;
        };
        let before = held.len();
        held.retain(|(at, _)| at != c);
        let forgot = held.len() < before;
        if held.is_empty() {
            self.held.remove(epoch);
        }
        forgot
    }
}

/// Seal a version's fields and operation under `key`, bound to its name.
pub(crate) fn seal_payload(key: &ContentKey, name: &Name, fields: &Content, op: &[u8]) -> Bytes {
    seal_bytes(key, name, &wire::encode_payload(fields, op))
}

/// Seal `plain` (a version's `Fields` and `MergeOp`, or its `Block`) under
/// `key`, bound to the version's name.
pub(crate) fn seal_bytes(key: &ContentKey, name: &Name, plain: &[u8]) -> Bytes {
    key.seal(plain, &name.encode_to_tlv()).to_bytes()
}

/// Open a version's sealed payload: its fields and operation, or its
/// block; `None` if it is not `key`'s, or not this name's.
pub(crate) fn open_payload(key: &ContentKey, name: &Name, ciphertext: &[u8]) -> Option<Inline> {
    let sealed = Sealed::from_bytes(ciphertext).ok()?;
    let plain = key.open(&sealed, &name.encode_to_tlv()).ok()?;
    wire::decode_inline(Bytes::from(plain)).ok()
}

// ---- asks (spec §19.4, answers.md §15) ----------------------------------------------------------

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
/// proof binds the ephemeral key needs the key to make its plaintext
/// (`answers.md` §15).
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

    /// The content key, which the signer's reply seals its words under ([`seal_words`]).
    pub(crate) fn reply_key(&self) -> ContentKey {
        self.ck.clone()
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
    open_ask_keyed(recipient, aad, ephemeral, key, sealed).map(|(plain, _)| plain)
}

/// [`open_ask`], with the ask's content key besides, which the signer seals its reply's words
/// under ([`seal_words`]).
pub(crate) fn open_ask_keyed(
    recipient: &RecipientKey,
    aad: &[u8],
    ephemeral: &[u8; 32],
    key: &[u8],
    sealed: &[u8],
) -> Option<(Vec<u8>, ContentKey)> {
    let ck = recipient
        .unwrap_ck(ephemeral, &Sealed::from_bytes(key).ok()?, aad)
        .ok()?;
    let plain = ck.open(&Sealed::from_bytes(sealed).ok()?, aad).ok()?;
    Some((plain, ck))
}

/// Seal the words of a refusal under the ask's content key `ck`, bound to the name of the reply
/// that carries them (answers.md §15.6): `nonce ‖ tag ‖ ciphertext`, ChaCha20-Poly1305.
pub(crate) fn seal_words(ck: &ContentKey, reply: &Name, words: &str) -> Bytes {
    ck.seal(words.as_bytes(), &reply.encode_to_tlv()).to_bytes()
}

/// The words [`seal_words`] sealed under `ck` for the reply `reply`; `None` if `sealed` is not
/// `ck`'s, not this reply's, or not UTF-8.
pub(crate) fn open_words(ck: &ContentKey, reply: &Name, sealed: &[u8]) -> Option<String> {
    let plain = ck
        .open(&Sealed::from_bytes(sealed).ok()?, &reply.encode_to_tlv())
        .ok()?;
    String::from_utf8(plain).ok()
}

// ---- answers (answers.md §5) --------------------------------------------------------------------

/// The keys an answer is sealed and named under: derived from the content keys of every epoch of
/// its read set, so only a device that holds all of them has them (answers.md §5.2).
pub(crate) struct AudienceKeys {
    /// Encrypts the answer's body (ChaCha20-Poly1305).
    pub(crate) seal: ContentKey,
    /// Keys the answer id and the result digest (HMAC-SHA256).
    pub(crate) name: [u8; 32],
}

/// The `SealEpoch*` list `E` of an answer: the TLV of each epoch, in the order given (ascending,
/// answers.md §5.1).
pub(crate) fn epochs_tlv(epochs: &[Epoch]) -> Bytes {
    let mut w = ndn_tlv::TlvWriter::new();
    for e in epochs {
        wire::write_epoch(&mut w, e);
    }
    w.finish()
}

/// `PRK = HKDF-Extract(salt none, IKM = k1 ‖ … ‖ kn)`, then `seal_key` and `name_key`
/// `= HKDF-Expand(PRK, label ‖ E, 32)`: `keys` are the content keys of `epochs`, which are
/// ascending, one key each (answers.md §5.2).
pub(crate) fn audience_keys(keys: &[ContentKey], epochs: &[Epoch]) -> AudienceKeys {
    let mut ikm = Zeroizing::new(Vec::with_capacity(keys.len() * 32));
    for k in keys {
        ikm.extend_from_slice(k.expose());
    }
    let e = epochs_tlv(epochs);
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut seal_key = Zeroizing::new([0u8; 32]);
    let mut name = [0u8; 32];
    hk.expand_multi_info(&[LABEL_SEAL, &e], &mut *seal_key)
        .expect("32 octets is a valid HKDF-SHA256 output length");
    hk.expand_multi_info(&[LABEL_NAME, &e], &mut name)
        .expect("32 octets is a valid HKDF-SHA256 output length");
    AudienceKeys {
        seal: ContentKey::from_bytes(*seal_key),
        name,
    }
}

fn keyed(key: &[u8; 32], label: &[u8], octets: &[u8]) -> [u8; 32] {
    let mut m =
        <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC accepts a key of any length");
    m.update(label);
    m.update(octets);
    m.finalize().into_bytes().into()
}

fn plain(label: &[u8], octets: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut h = Sha256::new();
    h.update(label);
    h.update(octets);
    h.finalize().into()
}

/// The answer id: `SHA-256("ndn-answer/1 id\0" ‖ AnswerBinding)` when nothing read is sealed, the
/// keyed `HMAC-SHA256(name_key, …)` otherwise (answers.md §3.2).
pub(crate) fn answer_id(binding: &AnswerBinding, keys: Option<&AudienceKeys>) -> [u8; 32] {
    let octets = binding.encode();
    match keys {
        None => plain(LABEL_ID, &octets),
        Some(k) => keyed(&k.name, LABEL_ID, &octets),
    }
}

/// The result digest (answers.md §3.4): keyed when anything read is sealed, so a device outside
/// the audience cannot confirm a guess of a result from a digest that reaches it.
pub(crate) fn result_digest(result: &[u8], keys: Option<&AudienceKeys>) -> [u8; 32] {
    match keys {
        None => plain(LABEL_RESULT, result),
        Some(k) => keyed(&k.name, LABEL_RESULT, result),
    }
}

/// The associated data of a sealed answer: the label, its name as a Name TLV, its kind and its
/// `SealEpoch*` list, so none can be changed or moved by a holder (answers.md §5.3).
fn answer_aad(name: &Name, kind: AnswerKind, epochs: &[Epoch]) -> Vec<u8> {
    let mut aad = LABEL_AAD.to_vec();
    aad.extend_from_slice(&name.encode_to_tlv());
    aad.push(kind.code() as u8);
    aad.extend_from_slice(&epochs_tlv(epochs));
    aad
}

/// Seal an answer's `AnswerBody` TLV: `nonce ‖ tag ‖ ciphertext` under the audience seal key.
pub(crate) fn seal_answer(
    k: &AudienceKeys,
    name: &Name,
    kind: AnswerKind,
    epochs: &[Epoch],
    body: &[u8],
) -> Bytes {
    k.seal
        .seal(body, &answer_aad(name, kind, epochs))
        .to_bytes()
}

/// Open a sealed answer's ciphertext; `None` if it is not this audience's, or not this name's,
/// kind's and epochs'.
pub(crate) fn open_answer(
    k: &AudienceKeys,
    name: &Name,
    kind: AnswerKind,
    epochs: &[Epoch],
    ciphertext: &[u8],
) -> Option<Bytes> {
    let sealed = Sealed::from_bytes(ciphertext).ok()?;
    k.seal
        .open(&sealed, &answer_aad(name, kind, epochs))
        .ok()
        .map(Bytes::from)
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
            Some(Inline::Fields(fields, Bytes::from_static(b"op")))
        );
        let other = n("/alice/laptop/32=log/alice/32=data/notes/seq=6");
        assert_eq!(open_payload(&k, &other, &sealed), None, "bound to its name");
    }
}
