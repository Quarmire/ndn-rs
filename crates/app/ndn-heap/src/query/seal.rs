//! Sealing a query and its answer in a sealed space (`docs/specs/query.md`).
//!
//! The asker and the server share one [`PairKeys`] per (asker device, server device, epoch),
//! derived from one X25519 agreement ([`ndn_security::pair_keys_to`]) with the HKDF context
//! [`pair_context`]. A query is sealed under `Kq` and an answer under `Ka`, each with AES-256-GCM
//! (`S_AEAD` 1; both ends name it, none negotiates): the nonce is four zero octets then the
//! counter big-endian, the output the ciphertext then the 16-octet tag. The additional data
//! ([`query_aad`], [`answer_aad`]) names the server, the asker, the space, the epoch, the
//! asker's ephemeral key, the counter and the query id, and a direction octet, so a ciphertext
//! opens only as what it was sealed as, between whom it was sealed, in the exchange it was sealed
//! for. The answer uses the **query's** counter under the other key, so a nonce is never used
//! twice under one key as long as the asker never repeats a counter under one pair.

use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_security::PairKeys;
use ndn_tlv::TlvWriter;

use crate::chan::aead::{Aead, FrameCipher, NONCE_LEN};
use crate::chan::limits::TAG_LEN;
use crate::wire::{EpochId, write_epoch_id, write_name};

/// The direction octet of a query's additional data.
const DIR_QUERY: u8 = 1;
/// The direction octet of an answer's additional data.
const DIR_ANSWER: u8 = 2;

/// `Name` TLVs of `space`, `asker` and `server`, then the `EPOCH_ID` TLV of `epoch`: what the
/// pair keys are bound to, so that the asker and the server agree on it and no other pair or
/// epoch derives the same keys. Canonical: one encoding per quadruple.
pub(crate) fn pair_context(space: &Name, asker: &Name, server: &Name, epoch: &EpochId) -> Vec<u8> {
    let mut w = TlvWriter::new();
    write_name(&mut w, space);
    write_name(&mut w, asker);
    write_name(&mut w, server);
    write_epoch_id(&mut w, epoch);
    w.finish().to_vec()
}

/// A direction octet, then the server, the asker and the space (`Name` TLVs), the epoch
/// (`EPOCH_ID` TLV), the asker's ephemeral key (32 octets), the counter (8 octets big-endian) and
/// the query id (8 octets).
#[allow(clippy::too_many_arguments)] // the fields of the exchange, each one bound
fn exchange_aad(
    direction: u8,
    server: &Name,
    asker: &Name,
    space: &Name,
    epoch: &EpochId,
    ephemeral: &[u8; 32],
    seq: u64,
    id: &[u8; 8],
) -> Vec<u8> {
    let mut w = TlvWriter::new();
    w.write_raw(&[direction]);
    write_name(&mut w, server);
    write_name(&mut w, asker);
    write_name(&mut w, space);
    write_epoch_id(&mut w, epoch);
    w.write_raw(ephemeral);
    w.write_raw(&seq.to_be_bytes());
    w.write_raw(id);
    w.finish().to_vec()
}

/// The additional data of a query: [`exchange_aad`] with the query direction.
#[allow(clippy::too_many_arguments)] // the fields of the exchange, each one bound
pub(crate) fn query_aad(
    server: &Name,
    asker: &Name,
    space: &Name,
    epoch: &EpochId,
    ephemeral: &[u8; 32],
    seq: u64,
    id: &[u8; 8],
) -> Vec<u8> {
    exchange_aad(DIR_QUERY, server, asker, space, epoch, ephemeral, seq, id)
}

/// The additional data of an answer: [`query_aad`]'s fields with the answer direction.
#[allow(clippy::too_many_arguments)] // the fields of the exchange, each one bound
pub(crate) fn answer_aad(
    server: &Name,
    asker: &Name,
    space: &Name,
    epoch: &EpochId,
    ephemeral: &[u8; 32],
    seq: u64,
    id: &[u8; 8],
) -> Vec<u8> {
    exchange_aad(DIR_ANSWER, server, asker, space, epoch, ephemeral, seq, id)
}

/// Four zero octets, then `seq` big-endian.
fn nonce(seq: u64) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[4..].copy_from_slice(&seq.to_be_bytes());
    nonce
}

fn seal(key: &[u8; 32], seq: u64, aad: &[u8], plaintext: &[u8]) -> Bytes {
    let cipher = FrameCipher::from_key_octets(key, Aead::Aes256Gcm);
    let mut out = Vec::with_capacity(plaintext.len() + TAG_LEN);
    out.extend_from_slice(plaintext);
    let tag = cipher.seal_detached(nonce(seq), aad, &mut out);
    out.extend_from_slice(&tag);
    Bytes::from(out)
}

fn open(key: &[u8; 32], seq: u64, aad: &[u8], sealed: &[u8]) -> Option<Vec<u8>> {
    let cipher = FrameCipher::from_key_octets(key, Aead::Aes256Gcm);
    let mut buf = sealed.to_vec();
    cipher.open_in_place(nonce(seq), aad, &mut buf).ok()?;
    buf.truncate(sealed.len() - TAG_LEN);
    Some(buf)
}

/// Seal a query under `Kq`: the ciphertext, then the tag. `seq` is the asker's counter and is
/// never used twice under one pair.
pub(crate) fn seal_query(keys: &PairKeys, seq: u64, aad: &[u8], plaintext: &[u8]) -> Bytes {
    seal(&keys.query, seq, aad, plaintext)
}

/// Open a query sealed by [`seal_query`]; `None` if it does not open (wrong key, counter or
/// additional data, or a changed octet).
pub(crate) fn open_query(keys: &PairKeys, seq: u64, aad: &[u8], cipher: &[u8]) -> Option<Vec<u8>> {
    open(&keys.query, seq, aad, cipher)
}

/// Seal an answer under `Ka`; `seq` is the counter of the query it answers.
pub(crate) fn seal_answer(keys: &PairKeys, seq: u64, aad: &[u8], plaintext: &[u8]) -> Bytes {
    seal(&keys.answer, seq, aad, plaintext)
}

/// Open an answer sealed by [`seal_answer`]; `None` if it does not open.
pub(crate) fn open_answer(keys: &PairKeys, seq: u64, aad: &[u8], cipher: &[u8]) -> Option<Vec<u8>> {
    open(&keys.answer, seq, aad, cipher)
}

#[cfg(test)]
mod tests {
    use ndn_security::{RecipientKey, pair_keys_to};

    use super::*;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    fn epoch() -> EpochId {
        EpochId {
            creator: n("/alice/laptop"),
            seq: 3,
        }
    }

    /// The keys of an asker `/bob/phone` and a server `/alice/laptop`, from both ends.
    fn keys() -> ([u8; 32], PairKeys, PairKeys) {
        let (space, asker, server) = (n("/alice/32=data/w"), n("/bob/phone"), n("/alice/laptop"));
        let context = pair_context(&space, &asker, &server, &epoch());
        let recipient = RecipientKey::generate();
        let (ephemeral, at_asker) = pair_keys_to(&recipient.public(), &context).unwrap();
        let at_server = recipient.pair_keys_from(&ephemeral, &context).unwrap();
        (ephemeral, at_asker, at_server)
    }

    fn aads(ephemeral: &[u8; 32], seq: u64) -> (Vec<u8>, Vec<u8>) {
        let args = (
            &n("/alice/laptop"),
            &n("/bob/phone"),
            &n("/alice/32=data/w"),
            &epoch(),
            ephemeral,
            seq,
            &[7u8; 8],
        );
        (
            query_aad(args.0, args.1, args.2, args.3, args.4, args.5, args.6),
            answer_aad(args.0, args.1, args.2, args.3, args.4, args.5, args.6),
        )
    }

    #[test]
    fn a_query_and_an_answer_open_at_the_other_end() {
        let (ephemeral, asker, server) = keys();
        let (q_aad, a_aad) = aads(&ephemeral, 4);
        let query = seal_query(&asker, 4, &q_aad, b"where is the key?");
        assert_eq!(query.len(), 17 + TAG_LEN);
        assert_eq!(
            open_query(&server, 4, &q_aad, &query).as_deref(),
            Some(&b"where is the key?"[..])
        );
        let answer = seal_answer(&server, 4, &a_aad, b"under the mat");
        assert_eq!(
            open_answer(&asker, 4, &a_aad, &answer).as_deref(),
            Some(&b"under the mat"[..])
        );
        // An empty plaintext is a tag alone.
        let empty = seal_query(&asker, 0, &q_aad, b"");
        assert_eq!(empty.len(), TAG_LEN);
        assert_eq!(open_query(&server, 0, &q_aad, &empty), Some(vec![]));
        // Shorter than a tag opens to nothing, and does not panic.
        assert_eq!(open_query(&server, 4, &q_aad, &query[..TAG_LEN - 1]), None);
        assert_eq!(open_query(&server, 4, &q_aad, &[]), None);
    }

    #[test]
    fn the_nonce_and_suite_are_aes_256_gcm_with_four_zero_octets_and_the_counter() {
        use aes_gcm::aead::{Aead as _, KeyInit, Payload};
        let (ephemeral, asker, _) = keys();
        let (q_aad, a_aad) = aads(&ephemeral, 0x0102_0304_0506_0708);
        let sealed = seal_query(&asker, 0x0102_0304_0506_0708, &q_aad, b"pt");
        let reference = aes_gcm::Aes256Gcm::new_from_slice(&asker.query).unwrap();
        let nonce = [0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8];
        let expected = reference
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: b"pt",
                    aad: &q_aad,
                },
            )
            .unwrap();
        assert_eq!(sealed.as_ref(), expected.as_slice());
        let sealed = seal_answer(&asker, 0x0102_0304_0506_0708, &a_aad, b"pt");
        let reference = aes_gcm::Aes256Gcm::new_from_slice(&asker.answer).unwrap();
        let expected = reference
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: b"pt",
                    aad: &a_aad,
                },
            )
            .unwrap();
        assert_eq!(sealed.as_ref(), expected.as_slice());
    }

    #[test]
    fn the_query_key_cannot_open_an_answer_nor_the_answer_key_a_query() {
        let (ephemeral, asker, server) = keys();
        let (q_aad, a_aad) = aads(&ephemeral, 1);
        let answer = seal_answer(&server, 1, &a_aad, b"x");
        assert_eq!(open_query(&asker, 1, &a_aad, &answer), None);
        assert_eq!(open_query(&server, 1, &a_aad, &answer), None);
        let query = seal_query(&asker, 1, &q_aad, b"x");
        assert_eq!(open_answer(&server, 1, &q_aad, &query), None);
        assert_eq!(open_answer(&asker, 1, &q_aad, &query), None);
        // The direction octet alone: the same key and counter, the other direction's data.
        let swapped = seal_query(&asker, 1, &a_aad, b"x");
        assert_eq!(open_query(&server, 1, &q_aad, &swapped), None);
        assert!(open_query(&server, 1, &a_aad, &swapped).is_some());
        assert_ne!(q_aad[0], a_aad[0]);
        assert_eq!(q_aad[1..], a_aad[1..], "the fields are the same");
    }

    #[test]
    fn a_changed_octet_of_the_data_or_the_ciphertext_does_not_open() {
        let (ephemeral, asker, server) = keys();
        let (q_aad, _) = aads(&ephemeral, 9);
        let sealed = seal_query(&asker, 9, &q_aad, b"a query of some length");
        assert!(open_query(&server, 9, &q_aad, &sealed).is_some());
        for i in 0..sealed.len() {
            let mut bad = sealed.to_vec();
            bad[i] ^= 1;
            assert_eq!(
                open_query(&server, 9, &q_aad, &bad),
                None,
                "octet {i} of the ciphertext"
            );
        }
        for i in 0..q_aad.len() {
            let mut bad = q_aad.clone();
            bad[i] ^= 1;
            assert_eq!(
                open_query(&server, 9, &bad, &sealed),
                None,
                "octet {i} of the data"
            );
        }
        // Longer or shorter data, a truncated or extended ciphertext.
        assert_eq!(open_query(&server, 9, &q_aad[1..], &sealed), None);
        let mut longer = sealed.to_vec();
        longer.push(0);
        assert_eq!(open_query(&server, 9, &q_aad, &longer), None);
        assert_eq!(
            open_query(&server, 9, &q_aad, &sealed[..sealed.len() - 1]),
            None
        );
    }

    #[test]
    fn two_counters_give_different_ciphertexts_and_only_the_right_one_opens() {
        let (ephemeral, asker, server) = keys();
        let (q_aad, _) = aads(&ephemeral, 1);
        let one = seal_query(&asker, 1, &q_aad, b"same");
        let two = seal_query(&asker, 2, &q_aad, b"same");
        assert_ne!(one, two);
        assert_ne!(
            one[..4],
            two[..4],
            "the keystream differs from the first octet"
        );
        assert_eq!(open_query(&server, 2, &q_aad, &one), None);
        assert_eq!(open_query(&server, 1, &q_aad, &two), None);
        // The same counter and data repeat the ciphertext: a counter is never reused, and this is
        // why the asker's counter is strictly increasing.
        assert_eq!(one, seal_query(&asker, 1, &q_aad, b"same"));
    }

    #[test]
    fn every_field_of_the_exchange_is_in_the_data_and_the_context() {
        let e = [5u8; 32];
        let id = [7u8; 8];
        let (space, asker, server) = (n("/alice/32=data/w"), n("/bob/phone"), n("/alice/laptop"));
        let base = query_aad(&server, &asker, &space, &epoch(), &e, 1, &id);
        let other_epoch = EpochId { seq: 4, ..epoch() };
        let variants = [
            query_aad(&n("/alice/tablet"), &asker, &space, &epoch(), &e, 1, &id),
            query_aad(&server, &n("/bob/tablet"), &space, &epoch(), &e, 1, &id),
            query_aad(
                &server,
                &asker,
                &n("/alice/32=data/x"),
                &epoch(),
                &e,
                1,
                &id,
            ),
            query_aad(&server, &asker, &space, &other_epoch, &e, 1, &id),
            query_aad(&server, &asker, &space, &epoch(), &[6u8; 32], 1, &id),
            query_aad(&server, &asker, &space, &epoch(), &e, 2, &id),
            query_aad(&server, &asker, &space, &epoch(), &e, 1, &[8u8; 8]),
            // The asker and the server swapped.
            query_aad(&asker, &server, &space, &epoch(), &e, 1, &id),
            answer_aad(&server, &asker, &space, &epoch(), &e, 1, &id),
        ];
        for (i, v) in variants.iter().enumerate() {
            assert_ne!(*v, base, "variant {i}");
        }
        let context = pair_context(&space, &asker, &server, &epoch());
        let contexts = [
            pair_context(&n("/alice/32=data/x"), &asker, &server, &epoch()),
            pair_context(&space, &n("/bob/tablet"), &server, &epoch()),
            pair_context(&space, &asker, &n("/alice/tablet"), &epoch()),
            pair_context(&space, &asker, &server, &other_epoch),
            pair_context(&space, &server, &asker, &epoch()),
        ];
        for (i, c) in contexts.iter().enumerate() {
            assert_ne!(*c, context, "context {i}");
        }
        // Two names that concatenate alike are not the same context: a name is a TLV.
        assert_ne!(
            pair_context(&n("/a/b"), &n("/c"), &server, &epoch()),
            pair_context(&n("/a"), &n("/b/c"), &server, &epoch())
        );
    }

    #[test]
    fn keys_of_another_context_do_not_open() {
        let (space, asker, server) = (n("/alice/32=data/w"), n("/bob/phone"), n("/alice/laptop"));
        let recipient = RecipientKey::generate();
        let at = |who: &Name| pair_context(&space, who, &server, &epoch());
        let (ephemeral, at_asker) = pair_keys_to(&recipient.public(), &at(&asker)).unwrap();
        // The server derives the keys of the asker it believes it is talking to.
        let at_server = recipient
            .pair_keys_from(&ephemeral, &at(&n("/bob/tablet")))
            .unwrap();
        let (q_aad, _) = aads(&ephemeral, 1);
        let sealed = seal_query(&at_asker, 1, &q_aad, b"x");
        assert_eq!(open_query(&at_server, 1, &q_aad, &sealed), None);
    }
}
