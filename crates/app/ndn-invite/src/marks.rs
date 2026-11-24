//! The notes an offer's judgement stands on, authenticated (spec §15, §18): the proof
//! key, the hint token, the use under way, the use mark and the wrong tries each end in
//! a MAC under a key derived from the device's recipient secret, which lives in the key
//! store, not in the data store the notes are kept in. Whoever can only write the data
//! store — and the recipient *public* key is public — cannot make a note that reads; a
//! note that does not read is judged **closed**: a use mark that does not read is a used
//! offer, tries that do not read are the cap.
//!
//! The MAC covers the note's key name, so a note copied to another key (another offer,
//! another asker, another kind) does not read. What a MAC cannot defend is a note's
//! **deletion**, or its replacement by an older note that did read: a writer of the data
//! store can reopen a use or give wrong tries back (spec §18).
//!
//! `closed/<id>` and `accepted/<id>` carry no MAC: a forged closing mark only closes (the
//! fail-closed side), and a forged acceptance is never given, since an answer is signed
//! afresh when the kept one does not read and carries a proof only the offer's secret
//! makes.

use bytes::Bytes;
use hmac::{Hmac, KeyInit, Mac};
use ndn_foundation_types::Name;
use ndn_security::confidentiality::RecipientKey;
use ndn_sync::DataStore;
use sha2::Sha256;

use crate::notes::derived_key;
use crate::store;
use crate::wire::{IntroRecord, OfferId, UsedBody};

/// The domain label of the offer notes' MAC key's derivation from the recipient secret.
const MAC_KEY_LABEL: &[u8] = b"ndn-invite/offer-note/mac-key/1";

/// The domain label of the offer notes' MAC itself.
const MAC_LABEL: &[u8] = b"ndn-invite/offer-note/mac/1";

/// The octets of a note's MAC (HMAC-SHA256), which end it.
const MAC_LEN: usize = 32;

fn mac(recipient: &RecipientKey, key: &Name, value: &[u8]) -> Hmac<Sha256> {
    let mac_key = derived_key(recipient.expose(), MAC_KEY_LABEL);
    let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(&*mac_key)
        .expect("HMAC accepts a key of any length");
    m.update(MAC_LABEL);
    m.update(&key.encode_to_tlv());
    m.update(value);
    m
}

/// `value` followed by its MAC, for the note kept at `key`.
pub(crate) fn seal(recipient: &RecipientKey, key: &Name, value: &[u8]) -> Bytes {
    let mut note = value.to_vec();
    note.extend_from_slice(&mac(recipient, key, value).finalize().into_bytes());
    Bytes::from(note)
}

/// The value of the note `note` kept at `key`, if its MAC checks under this device's key
/// (compared in constant time); `None` for anything else.
pub(crate) fn open(recipient: &RecipientKey, key: &Name, note: &[u8]) -> Option<Bytes> {
    let split = note.len().checked_sub(MAC_LEN)?;
    let (value, tag) = note.split_at(split);
    mac(recipient, key, value).verify_slice(tag).ok()?;
    Some(Bytes::copy_from_slice(value))
}

/// The asker key's digest the use mark `used/<id>` names, if the mark is there, reads and
/// names a key; `None` when there is none or it does not read.
pub(crate) fn used_digest(
    store: &dyn DataStore,
    recipient: &RecipientKey,
    id: &OfferId,
) -> Option<[u8; 32]> {
    match used_by(store, recipient, id) {
        Use::By(_, digest) => Some(digest),
        Use::Not | Use::Unreadable => None,
    }
}

/// What a use note says of the key an offer is used by (or is being used by).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Use {
    /// No such note.
    Not,
    /// A note that reads: the key and its public key's digest.
    By(Name, [u8; 32]),
    /// A note that is there and does not read: judged as a use by a key nobody knows.
    Unreadable,
}

/// The use mark of the offer `id`.
pub(crate) fn used_by(store: &dyn DataStore, recipient: &RecipientKey, id: &OfferId) -> Use {
    let key = store::used_key(id);
    let Some(note) = store.get(&key) else {
        return Use::Not;
    };
    let by = open(recipient, &key, &note)
        .and_then(|value| IntroRecord::decode(value).ok())
        .and_then(|record| match record {
            IntroRecord::Used(UsedBody { by, .. }) => by,
            IntroRecord::Offer(_) => None,
        });
    match by {
        Some((key, digest)) => Use::By(key, digest),
        None => Use::Unreadable,
    }
}

/// The note of a use under way, `using/<id>`: the key's Name TLV, then its digest.
pub(crate) fn using_by(store: &dyn DataStore, recipient: &RecipientKey, id: &OfferId) -> Use {
    let key = store::using_key(id);
    let Some(note) = store.get(&key) else {
        return Use::Not;
    };
    let by = open(recipient, &key, &note).and_then(|value| {
        let split = value.len().checked_sub(32)?;
        let name = Name::decode_from_tlv(value.slice(..split)).ok()?;
        Some((name, <[u8; 32]>::try_from(&value[split..]).ok()?))
    });
    match by {
        Some((key, digest)) => Use::By(key, digest),
        None => Use::Unreadable,
    }
}
