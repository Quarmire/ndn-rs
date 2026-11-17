//! Answers (answers.md): the canonical bytes of a read set and its digest, the binding and the
//! answer id, the audience key and the keyed id, the seal, the record and the names — each as the
//! spec states it, computed again here from the spec's own formulas.

use bytes::Bytes;
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use ndn_foundation_types::{Hash, Name};
use ndn_security::confidentiality::ContentKey;
use ndn_tlv::TlvWriter;
use sha2::{Digest, Sha256};

use crate::answer::{
    AnswerAsk, AnswerBinding, AnswerKind, Body, Content as RecordContent, Evaluator, Evaluators,
    QUESTION_MAX, READS_MAX, ReadRef, ReadSet, Record, SEAL_EPOCHS_MAX, Signers, applied_digest,
    tlv,
};
use crate::collection::Epoch;
use crate::error::AnswerRefusal;
use crate::events::{
    AnswerFault, Cursor, DeviceEvent, EventDetail, EventId, EventKind, EventSubject, Meaning,
    ReadSetFault,
};
use crate::seal::{self, AudienceKeys};
use crate::version::{Parents, Seq, Timestamp, VersionId, Writer};
use crate::wire::{self, PieceKind};

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

fn hash(b: u8) -> Hash {
    Hash([b; 32])
}

fn version_read(path: &str, seq: u64, d: u8) -> ReadRef {
    ReadRef::Version {
        name: wire::log_name(&n("/alice/laptop"), Some(&n(path)), seq),
        digest: hash(d),
    }
}

fn state_read(path: &str) -> ReadRef {
    let mut at = Parents::new();
    for (w, s, d) in [("/alice/laptop", 7, 1u8), ("/alice/phone", 3, 2)] {
        at.insert(
            &VersionId {
                writer: Writer::new(n(w).append("KEY").append("1")),
                seq: Seq(s),
            },
            Some([d; 32]),
        );
    }
    ReadRef::State {
        collection: n(path),
        rule: n("/merge/yrs"),
        at,
        applied: hash(9),
    }
}

fn epoch(device: &str, seq: u64) -> Epoch {
    Epoch {
        creator: n(device),
        seq: Seq(seq),
    }
}

fn key(b: u8) -> ContentKey {
    ContentKey::from_bytes([b; 32])
}

fn reads() -> Vec<ReadRef> {
    vec![
        version_read("/alice/32=data/trip/plan", 4, 1),
        state_read("/alice/32=data/trip/notes"),
        version_read("/alice/32=data/trip/budget", 2, 3),
        version_read("/alice/32=data/trip/budget", 1, 4),
    ]
}

#[test]
fn a_read_set_is_a_set_its_bytes_do_not_show_the_order_the_reads_were_made_in() {
    let one = ReadSet::new(reads()).unwrap();
    let mut backwards = reads();
    backwards.reverse();
    let two = ReadSet::new(backwards).unwrap();
    assert_eq!(one.encode(), two.encode());
    assert_eq!(one.digest(), two.digest());
    // A read made twice is one read.
    let mut doubled = reads();
    doubled.extend(reads());
    assert_eq!(ReadSet::new(doubled).unwrap().encode(), one.encode());
    // Canonical order: ascending by the octets of each read's complete TLV.
    let octets: Vec<Bytes> = one.reads().iter().map(ReadRef::encode).collect();
    let mut sorted = octets.clone();
    sorted.sort();
    assert_eq!(octets, sorted, "the reads are in canonical order");
    // And it round-trips.
    assert_eq!(ReadSet::decode(one.encode()).unwrap(), one);
}

#[test]
fn the_read_set_digest_is_sha256_of_its_label_and_its_tlv() {
    let set = ReadSet::new(reads()).unwrap();
    let mut h = Sha256::new();
    h.update(b"ndn-answer/1 readset\0");
    h.update(set.encode());
    let expect: [u8; 32] = h.finalize().into();
    assert_eq!(set.digest(), Hash(expect));
    // The TLV is 0x05CB and its length is minimal.
    let tlv = set.encode();
    assert_eq!(&tlv[..3], &[0xFD, 0x05, 0xCB], "TLV-TYPE 0x05CB");
    let reads: Vec<u8> = set
        .reads()
        .iter()
        .flat_map(|r| r.encode().to_vec())
        .collect();
    let mut w = TlvWriter::new();
    w.write_tlv(0x05CB, &reads);
    assert_eq!(tlv, w.finish(), "ReadSet is 0x05CB over the reads in order");
}

#[test]
fn a_read_version_and_a_read_state_have_the_bytes_the_spec_gives() {
    let v = version_read("/alice/32=data/trip/plan", 4, 7);
    let ReadRef::Version { name, digest } = &v else {
        unreachable!()
    };
    let mut inner = TlvWriter::new();
    inner.write_tlv(0x07, &name_value(name));
    inner.write_tlv(0x055E, &digest.0);
    let mut w = TlvWriter::new();
    w.write_tlv(0x05CD, &inner.finish());
    assert_eq!(v.encode(), w.finish());
    // The state's four fields are in the order of the table: Name, Rule, Frontier, Digest.
    let s = state_read("/alice/32=data/trip/notes");
    let bytes = s.encode();
    assert_eq!(&bytes[..3], &[0xFD, 0x05, 0xCF], "TLV-TYPE 0x05CF");
    assert_eq!(ReadRef::decode(bytes).unwrap(), s);
}

fn name_value(name: &Name) -> Vec<u8> {
    let mut w = TlvWriter::new();
    for c in name.components() {
        w.write_tlv(c.typ, &c.value);
    }
    w.finish().to_vec()
}

/// The value of a TLV: what follows its type and length.
fn value_of(tlv: &[u8]) -> Vec<u8> {
    let mut r = ndn_tlv::TlvReader::new(Bytes::copy_from_slice(tlv));
    r.read_tlv().unwrap().1.to_vec()
}

#[test]
fn a_decoder_refuses_an_unknown_tlv_a_non_minimal_length_and_an_unsorted_or_repeated_read() {
    let set = ReadSet::new(reads()).unwrap();
    let wire = set.encode().to_vec();
    // An unknown TLV, even or odd, among the reads.
    for typ in [0x05DEu64, 0x05DF, 0x0600, 0x0601] {
        let mut inner = value_of(&wire);
        let mut w = TlvWriter::new();
        w.write_tlv(typ, b"x");
        inner.extend_from_slice(&w.finish());
        let mut w = TlvWriter::new();
        w.write_tlv(0x05CB, &inner);
        assert!(
            ReadSet::decode(w.finish()).is_err(),
            "an unknown TLV {typ:#x} is refused"
        );
    }
    // A non-minimal TLV-LENGTH: the first read with its length in the three-octet form.
    let one = version_read("/alice/32=data/trip/plan", 4, 1)
        .encode()
        .to_vec();
    assert!(one[3] < 253, "a short read: its length is one octet");
    let mut longer = one[..3].to_vec();
    longer.extend_from_slice(&[0xFD, 0x00, one[3]]);
    longer.extend_from_slice(&one[4..]);
    let mut w = TlvWriter::new();
    w.write_tlv(0x05CB, &longer);
    assert!(
        ReadSet::decode(w.finish()).is_err(),
        "a read whose length is not minimal is refused"
    );
    // The set's own length in the three-octet form.
    let mut loose = vec![0xFD, 0x05, 0xCB, 0xFD, 0x00, one.len() as u8];
    loose.extend_from_slice(&one);
    assert!(
        ReadSet::decode(Bytes::from(loose)).is_err(),
        "a set whose length is not minimal is refused"
    );
    // Unsorted and repeated reads.
    let a = version_read("/alice/32=data/trip/a", 1, 1)
        .encode()
        .to_vec();
    let b = version_read("/alice/32=data/trip/b", 1, 1)
        .encode()
        .to_vec();
    let (lo, hi) = if a < b { (&a, &b) } else { (&b, &a) };
    let with = |parts: &[&Vec<u8>]| {
        let mut w = TlvWriter::new();
        w.write_tlv(
            0x05CB,
            &parts.iter().flat_map(|p| p.to_vec()).collect::<Vec<u8>>(),
        );
        w.finish()
    };
    assert!(ReadSet::decode(with(&[lo, hi])).is_ok());
    assert!(
        matches!(
            ReadSet::decode(with(&[hi, lo])),
            Err(AnswerRefusal::ReadSet(_))
        ),
        "an unsorted read set is refused"
    );
    assert!(
        matches!(
            ReadSet::decode(with(&[lo, lo])),
            Err(AnswerRefusal::ReadSet(_))
        ),
        "a repeated read is refused"
    );
    // Two versions of one name, or two states of one collection, are refused.
    let c = version_read("/alice/32=data/trip/a", 1, 2);
    assert!(matches!(
        ReadSet::new([version_read("/alice/32=data/trip/a", 1, 1), c]),
        Err(AnswerRefusal::ReadSet(_))
    ));
    let mut s2 = state_read("/alice/32=data/trip/notes");
    if let ReadRef::State { applied, .. } = &mut s2 {
        *applied = hash(8);
    }
    assert!(matches!(
        ReadSet::new([state_read("/alice/32=data/trip/notes"), s2]),
        Err(AnswerRefusal::ReadSet(_))
    ));
}

#[test]
fn a_read_set_has_at_most_reads_max_reads() {
    let many = (0..=READS_MAX as u64).map(|i| version_read("/alice/32=data/trip/plan", i + 1, 1));
    assert!(matches!(
        ReadSet::new(many),
        Err(AnswerRefusal::TooLarge { limit, .. }) if limit == READS_MAX as u64
    ));
    const {
        assert!(
            crate::wire::PAYLOAD_MAX == 64 << 20
                && QUESTION_MAX == 65_536
                && SEAL_EPOCHS_MAX == 256
        );
    }
}

#[test]
fn the_current_read_of_a_collection_is_its_one_read() {
    let set = ReadSet::new(reads()).unwrap();
    assert!(matches!(
        set.current(&n("/alice/32=data/trip/plan")),
        Some(ReadRef::Version { .. })
    ));
    assert!(matches!(
        set.current(&n("/alice/32=data/trip/notes")),
        Some(ReadRef::State { .. })
    ));
    assert!(
        set.current(&n("/alice/32=data/trip/budget")).is_none(),
        "two reads of one collection: ambiguous"
    );
    assert!(set.current(&n("/alice/32=data/trip/other")).is_none());
}

#[test]
fn the_labels_are_distinct_and_none_is_a_prefix_of_another() {
    let labels: [&[u8]; 7] = [
        b"ndn-answer/1 readset\0",
        b"ndn-answer/1 applied\0",
        b"ndn-answer/1 id\0",
        b"ndn-answer/1 result\0",
        b"ndn-answer/1 seal\0",
        b"ndn-answer/1 name\0",
        b"ndn-answer/1 aad\0",
    ];
    for (i, a) in labels.iter().enumerate() {
        assert_eq!(a.last(), Some(&0));
        for (j, b) in labels.iter().enumerate() {
            assert!(i == j || !b.starts_with(a), "{a:?} is a prefix of {b:?}");
        }
    }
    // The same octets under two labels never agree.
    let set = ReadSet::new(reads()).unwrap();
    let binding = AnswerBinding {
        kind: AnswerKind::Provider,
        definition: None,
        by: n("/ndf/fn/v=1"),
        reads: set.digest(),
    };
    assert_ne!(
        seal::answer_id(&binding, None),
        seal::result_digest(&binding.encode(), None)
    );
}

#[test]
fn the_applied_set_digest_is_sha256_of_its_label_and_the_versions_in_order() {
    let a = Writer::new(n("/alice/laptop/KEY/1"));
    let b = Writer::new(n("/alice/phone/KEY/1"));
    let versions = [(&b, 2u64, [2u8; 32]), (&a, 9, [9; 32]), (&a, 3, [3; 32])];
    let mut h = Sha256::new();
    h.update(b"ndn-answer/1 applied\0");
    // The Name TLV of /alice/phone/… is shorter than /alice/laptop/…'s, so its octets sort
    // first: the order is of the encoded octets (length included), not of the names.
    assert!(b.key().encode_to_tlv() < a.key().encode_to_tlv());
    for (w, s, d) in [(&b, 2u64, [2u8; 32]), (&a, 3, [3; 32]), (&a, 9, [9; 32])] {
        h.update(w.key().encode_to_tlv());
        h.update(s.to_be_bytes());
        h.update(d);
    }
    let expect: [u8; 32] = h.finalize().into();
    assert_eq!(
        applied_digest(versions.iter().map(|(w, s, d)| ((*w).clone(), *s, *d))),
        Hash(expect),
        "ascending by the writer's Name TLV, then seq; seq 8 octets big-endian"
    );
}

#[test]
fn an_answer_id_is_a_plain_digest_when_nothing_is_sealed_and_a_keyed_one_otherwise() {
    let set = ReadSet::new(reads()).unwrap();
    let binding = AnswerBinding {
        kind: AnswerKind::Pure,
        definition: Some(reads()[0].clone()),
        by: n("/conformance/eval/sum/v=1"),
        reads: set.digest(),
    };
    let mut h = Sha256::new();
    h.update(b"ndn-answer/1 id\0");
    h.update(binding.encode());
    let plain: [u8; 32] = h.finalize().into();
    assert_eq!(seal::answer_id(&binding, None), plain);
    // The binding is 0x05C7: kind, definition, evaluator, read-set digest.
    assert_eq!(&binding.encode()[..3], &[0xFD, 0x05, 0xC7]);
    assert_eq!(AnswerBinding::decode(binding.encode()).unwrap(), binding);

    let epochs = [epoch("/alice/laptop", 1), epoch("/alice/laptop", 5)];
    let alice = audience_of(&[key(1), key(2)], &epochs);
    let bob = audience_of(&[key(1), key(3)], &epochs);
    let alice_phone = audience_of(&[key(1), key(2)], &epochs);
    let keyed = seal::answer_id(&binding, Some(&alice));
    assert_ne!(keyed, plain);
    assert_eq!(
        keyed,
        seal::answer_id(&binding, Some(&alice_phone)),
        "two members agree"
    );
    assert_ne!(
        keyed,
        seal::answer_id(&binding, Some(&bob)),
        "another audience has another id"
    );
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&alice.name).unwrap();
    mac.update(b"ndn-answer/1 id\0");
    mac.update(&binding.encode());
    assert_eq!(keyed.as_slice(), mac.finalize().into_bytes().as_slice());
    // The result digest is keyed the same way, under its own label.
    let rd = seal::result_digest(b"42", Some(&alice));
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&alice.name).unwrap();
    mac.update(b"ndn-answer/1 result\0");
    mac.update(b"42");
    assert_eq!(rd.as_slice(), mac.finalize().into_bytes().as_slice());
    let mut h = Sha256::new();
    h.update(b"ndn-answer/1 result\0");
    h.update(b"42");
    assert_eq!(
        seal::result_digest(b"42", None).as_slice(),
        h.finalize().as_slice()
    );
}

fn audience_of(keys: &[ContentKey], epochs: &[Epoch]) -> AudienceKeys {
    seal::audience_keys(keys, epochs)
}

#[test]
fn the_audience_keys_are_hkdf_of_the_epoch_keys_in_order_and_give_the_same_bytes_on_two_devices() {
    let epochs = [epoch("/alice/laptop", 1), epoch("/bob/laptop", 2)];
    let (k1, k2) = (key(1), key(2));
    let ours = audience_of(&[k1.clone(), k2.clone()], &epochs);
    let theirs = audience_of(&[k1.clone(), k2.clone()], &epochs);
    assert_eq!(ours.seal.expose(), theirs.seal.expose());
    assert_eq!(ours.name, theirs.name);
    // The formula of §5.2, again: PRK = HKDF-Extract(none, k1 ‖ k2), then two expansions.
    let mut e = Vec::new();
    for ep in &epochs {
        let mut w = TlvWriter::new();
        wire::write_epoch(&mut w, ep);
        e.extend_from_slice(&w.finish());
    }
    let mut ikm = k1.expose().to_vec();
    ikm.extend_from_slice(k2.expose());
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut seal_key = [0u8; 32];
    let mut name_key = [0u8; 32];
    hk.expand_multi_info(&[b"ndn-answer/1 seal\0", &e], &mut seal_key)
        .unwrap();
    hk.expand_multi_info(&[b"ndn-answer/1 name\0", &e], &mut name_key)
        .unwrap();
    assert_eq!(ours.seal.expose(), &seal_key);
    assert_eq!(ours.name, name_key);
    assert_ne!(seal_key, name_key, "two different keys come from one PRK");
    // The order of the keys is fixed by the epochs' order: swapped keys give other keys.
    let swapped = audience_of(&[k2, k1], &epochs);
    assert_ne!(swapped.seal.expose(), &seal_key);
}

#[test]
fn a_sealed_answer_opens_only_under_its_audience_key_and_is_bound_to_its_name_kind_and_epochs() {
    let epochs = [epoch("/alice/laptop", 1)];
    let aud = audience_of(&[key(1)], &epochs);
    let other = audience_of(&[key(2)], &epochs);
    let name = wire::answer_name(&n("/alice/laptop"), &[5; 32]);
    let ct = seal::seal_answer(&aud, &name, AnswerKind::Pure, &epochs, b"the body");
    assert_eq!(
        seal::open_answer(&aud, &name, AnswerKind::Pure, &epochs, &ct).as_deref(),
        Some(&b"the body"[..])
    );
    assert!(seal::open_answer(&other, &name, AnswerKind::Pure, &epochs, &ct).is_none());
    let moved = wire::answer_name(&n("/alice/phone"), &[5; 32]);
    assert!(
        seal::open_answer(&aud, &moved, AnswerKind::Pure, &epochs, &ct).is_none(),
        "not replayable under another signer's name"
    );
    assert!(seal::open_answer(&aud, &name, AnswerKind::Provider, &epochs, &ct).is_none());
    assert!(
        seal::open_answer(
            &aud,
            &name,
            AnswerKind::Pure,
            &[epoch("/alice/laptop", 2)],
            &ct
        )
        .is_none()
    );
    // A second sealing of one body is another ciphertext (a fresh nonce), not another answer.
    let again = seal::seal_answer(&aud, &name, AnswerKind::Pure, &epochs, b"the body");
    assert_ne!(ct, again);
}

#[test]
fn an_answer_record_round_trips_in_each_of_its_forms_and_refuses_an_unknown_tlv() {
    let set = ReadSet::new(reads()).unwrap();
    let binding = AnswerBinding {
        kind: AnswerKind::Pure,
        definition: Some(reads()[0].clone()),
        by: n("/conformance/eval/sum/v=1"),
        reads: set.digest(),
    };
    let body = Body {
        binding,
        reads: set,
        result: Bytes::from_static(b"17"),
    };
    let encoded = body.encode();
    assert_eq!(&encoded[..3], &[0xFD, 0x05, 0xC5]);
    assert_eq!(Body::decode(encoded.clone()).unwrap(), body);
    for content in [
        RecordContent::Plain(encoded.clone()),
        RecordContent::Sealed {
            epochs: vec![epoch("/alice/laptop", 1), epoch("/alice/laptop", 3)],
            ciphertext: Bytes::from_static(&[1; 40]),
        },
        RecordContent::Pieces {
            epochs: None,
            size: 7000,
            root: [4; 32],
        },
        RecordContent::Pieces {
            epochs: Some(vec![epoch("/alice/laptop", 1)]),
            size: 7000,
            root: [4; 32],
        },
    ] {
        let rec = Record {
            kind: AnswerKind::Pure,
            content,
        };
        let bytes = rec.encode();
        assert_eq!(&bytes[..3], &[0xFD, 0x05, 0xC1]);
        assert_eq!(Record::decode(bytes.clone()).unwrap(), rec);
        // An unknown TLV at the end of the record is refused, odd or even.
        for typ in [0x05DEu64, 0x0600] {
            let mut inner = value_of(&bytes);
            let mut w = TlvWriter::new();
            w.write_tlv(typ, b"x");
            inner.extend_from_slice(&w.finish());
            let mut w = TlvWriter::new();
            w.write_tlv(tlv::ANSWER_RECORD, &inner);
            assert!(Record::decode(w.finish()).is_err());
        }
    }
    // Pieces: not above INLINE_MAX, or above PAYLOAD_MAX, is refused.
    for size in [100u64, 6144, (64 << 20) + 1] {
        let rec = Record {
            kind: AnswerKind::Provider,
            content: RecordContent::Pieces {
                epochs: None,
                size,
                root: [1; 32],
            },
        };
        assert!(
            Record::decode(rec.encode()).is_err(),
            "pieces of {size} octets"
        );
    }
}

#[test]
fn answer_and_question_names_round_trip_and_every_other_form_is_refused() {
    let id = [7u8; 32];
    let name = wire::answer_name(&n("/alice/laptop"), &id);
    let comps = name.components();
    assert_eq!(
        comps.len(),
        4,
        "the device, 32=answer and one component for the id"
    );
    assert_eq!(
        comps[3].value.as_ref(),
        &id[..],
        "the id's 32 octets, as one component"
    );
    assert_eq!(
        wire::parse_answer_name(&name),
        Some((n("/alice/laptop"), id))
    );
    // Not: an id of another length, a name that goes on, a keyword before it, two ids.
    assert!(wire::parse_answer_name(&n("/alice/laptop/32=answer/x")).is_none());
    assert!(wire::parse_answer_name(&name.clone().append("more")).is_none());
    assert!(wire::parse_answer_name(&n("/alice/32=log/32=answer/x")).is_none());
    assert!(wire::parse_answer_name(&n("/alice/laptop/32=answer")).is_none());
    // Pieces.
    let chunk = name.clone().append_segment(3);
    assert_eq!(
        wire::parse_answer_piece_name(&chunk),
        Some((name.clone(), PieceKind::Chunk(3)))
    );
    let node = name
        .clone()
        .append_component(ndn_foundation_types::NameComponent::keyword(
            Bytes::from_static(b"manifest"),
        ))
        .append_segment(2);
    assert_eq!(
        wire::parse_answer_piece_name(&node),
        Some((name.clone(), PieceKind::Manifest(2)))
    );
    assert!(wire::parse_answer_piece_name(&name).is_none());
    assert!(
        wire::parse_piece_name(&chunk).is_none(),
        "an answer is no log entry"
    );

    let ask = AnswerAsk::pure(reads()[0].clone(), n("/conformance/eval/sum/v=1"));
    let q = ask.name(None).unwrap();
    assert_eq!(
        q.components()[..q.len() - 2],
        n("/alice/32=data/trip/plan").components()[..]
    );
    assert_eq!(AnswerAsk::parse(&q).unwrap(), ask);
    let stated = ask.clone().stating(ReadSet::new(reads()).unwrap());
    assert_eq!(
        AnswerAsk::parse(&stated.name(None).unwrap()).unwrap(),
        stated
    );
    let provider = AnswerAsk::provider(n("/ndf/summarize/v=1"), ReadSet::new(reads()).unwrap());
    let pq = provider.name(Some(&n("/alice/laptop"))).unwrap();
    assert_eq!(AnswerAsk::parse(&pq).unwrap(), provider);
    assert!(
        provider.name(None).is_err(),
        "a provider question names its provider"
    );
    assert!(ask.name(Some(&n("/alice/laptop"))).is_err());
    for bad in [
        q.clone().append("more"),
        n("/alice/32=data/trip/other/32=question").append_component(
            ndn_foundation_types::NameComponent::generic(Bytes::from_static(b"nope")),
        ),
        pq.clone()
            .append_component(ndn_foundation_types::NameComponent::generic(Bytes::new())),
    ] {
        assert!(
            matches!(
                AnswerAsk::parse(&bad),
                Err(crate::DataError::BadName { .. })
            ),
            "{bad}"
        );
    }
    // Kind and X disagreeing: a pure question under a device, a provider under a collection.
    let wrong = wire::question_name(&n("/alice/laptop"), &ask);
    assert!(matches!(
        AnswerAsk::parse(&wrong),
        Err(crate::DataError::BadName { .. })
    ));
    let wrong = wire::question_name(&n("/alice/32=data/trip/plan"), &provider);
    assert!(matches!(
        AnswerAsk::parse(&wrong),
        Err(crate::DataError::BadName { .. })
    ));
    // A definition outside X.
    let wrong = wire::question_name(&n("/alice/32=data/trip/budget"), &ask);
    assert!(matches!(
        AnswerAsk::parse(&wrong),
        Err(crate::DataError::BadName { .. })
    ));
}

#[test]
fn evaluators_are_matched_by_exact_name() {
    struct E(Name);
    #[async_trait::async_trait]
    impl Evaluator for E {
        fn evaluator(&self) -> &Name {
            &self.0
        }
        async fn plan(
            &self,
            _: &crate::answer::Definition,
            _: &mut dyn crate::answer::Reads,
        ) -> Result<(), crate::answer::PlanError> {
            Ok(())
        }
        fn evaluate(
            &self,
            _: &crate::answer::Definition,
            _: &dyn crate::answer::ReadView,
        ) -> Result<Bytes, crate::answer::EvalError> {
            Ok(Bytes::new())
        }
    }
    let v2 = n("/ndf/eval/v=2");
    let set = Evaluators::none().with(std::sync::Arc::new(E(v2.clone())));
    assert!(set.get(&v2).is_some());
    assert!(set.get(&n("/ndf/eval/v=1")).is_none());
    assert!(set.get(&n("/ndf/eval/v=3")).is_none());
    assert!(set.get(&n("/ndf/eval")).is_none(), "never by prefix");
    assert!(set.get(&n("/ndf/eval/v=2/more")).is_none());
    // `with` replaces one of the same name.
    let again = set.with(std::sync::Arc::new(E(v2.clone())));
    assert!(again.get(&v2).is_some());
}

#[test]
fn signers_match_a_device_by_name_and_by_prefix() {
    let s = Signers::Devices(vec![n("/alice/laptop"), n("/bob")]);
    assert!(s.names(&n("/alice/laptop")));
    assert!(
        s.names(&n("/bob/phone")),
        "a name also matches the devices under it"
    );
    assert!(!s.names(&n("/alice/phone")));
    assert!(!s.names(&n("/carol/laptop")));
    assert!(!Signers::None.names(&n("/alice/laptop")));
}

#[test]
fn an_answer_evidence_event_has_its_helpers_and_a_codec_that_round_trips() {
    let signer = n("/alice/phone/KEY/1");
    let answer = wire::answer_name(&n("/alice/phone"), &[1; 32]);
    let faults = [
        AnswerFault::Mismatch {
            signed: [1; 32],
            recomputed: [2; 32],
            evaluator: n("/conformance/eval/sum/v=1"),
        },
        AnswerFault::Equivocation {
            other_result: [3; 32],
        },
        AnswerFault::Conflict {
            other: wire::answer_name(&n("/alice/laptop"), &[1; 32]),
            other_signer: n("/alice/laptop/KEY/1"),
            other_result: [4; 32],
        },
        AnswerFault::Binding,
        AnswerFault::ReadSet(ReadSetFault::NotCanonical),
        AnswerFault::ReadSet(ReadSetFault::Digest),
        AnswerFault::ReadSet(ReadSetFault::Epochs),
        AnswerFault::ReadSet(ReadSetFault::HeldConflict),
        AnswerFault::ReadSet(ReadSetFault::NotItsReads),
    ];
    for fault in faults {
        let detail = EventDetail::Answer {
            answer: answer.clone(),
            signer: signer.clone(),
            id: [1; 32],
            readset: [9; 32],
            fault,
        };
        assert_eq!(detail.kind(), EventKind::AnswerEvidence);
        assert_eq!(detail.subject(), EventSubject::Writer(signer.clone()));
        assert_eq!(detail.meaning(), Meaning::AnswerKept);
        assert_eq!(detail.next_step(), crate::NextStep::UseOwnerDevice);
        assert!(detail.what_to_do().contains(&signer.to_string()));
        assert!(
            detail.why().contains(&answer.to_string()),
            "{}",
            detail.why()
        );
        let event = DeviceEvent {
            id: EventId::of(&detail, Cursor(1)),
            cursor: Cursor(1),
            first_seen: Timestamp(5),
            detail: detail.clone(),
            count: 1,
            last: None,
        };
        let bytes = crate::events::encode_event(&event);
        assert_eq!(
            crate::events::decode_event(Cursor(1), bytes).unwrap(),
            event,
            "{detail:?}"
        );
    }
}

// ---- the padding of a sealed body (answers.md §13.3) --------------------------------------------

/// Whether `t` is a size bucket: a multiple of 128 up to 1,024, then of an eighth of its power of
/// two.
fn is_bucket(t: usize) -> bool {
    match t <= 1024 {
        true => t.is_multiple_of(128),
        false => t.is_multiple_of(1 << (t.ilog2() - 3)),
    }
}

/// Whether an `AnswerPadding` element (a three-octet type, a one-, three- or five-octet length) is
/// of exactly `e` octets.
fn element_of(e: usize) -> bool {
    (4..=256).contains(&e) || (259..=65_541).contains(&e) || e >= 65_544
}

/// An `AnswerBody` TLV of exactly `total` octets, if one is.
fn body_of(total: usize) -> Option<Bytes> {
    for (header, lo, hi) in [(4, 0, 252), (6, 253, 65_535), (8, 65_536, usize::MAX)] {
        if let Some(v) = total.checked_sub(header)
            && (lo..=hi).contains(&v)
        {
            let mut w = TlvWriter::new();
            w.write_tlv(tlv::ANSWER_BODY, &vec![7u8; v]);
            return Some(w.finish());
        }
    }
    None
}

#[test]
fn a_sealed_body_pads_to_the_buckets_the_spec_lists_and_skips_the_sizes_no_element_fills() {
    use crate::answer::padded_len;
    // 128-octet steps to 1,024.
    for (n, t) in [
        (4, 128),
        (124, 128),
        (128, 128),
        (129, 256),
        (256, 256),
        (257, 384),
        (1000, 1024),
        (1024, 1024),
    ] {
        assert_eq!(padded_len(n), t, "a body of {n} octets");
    }
    // 125 to 127 octets leave 3 to 1 octets to 128, no element: the next bucket.
    for n in [125, 126, 127] {
        assert_eq!(padded_len(n), 256, "a body of {n} octets");
    }
    // Then steps of 2^(floor(log2 n) - 3).
    for (n, t) in [
        (1025, 1152),
        (2044, 2048),
        (2047, 2560),
        (2048, 2048),
        (2049, 2304),
        (4097, 4608),
        (65_535, 73_728),
        (65_537, 73_728),
    ] {
        assert_eq!(padded_len(n), t, "a body of {n} octets");
    }
    // 1,021 to 1,023 leave 3 to 1 octets to 1,024: the next bucket, 1,152.
    for n in [1021, 1022, 1023] {
        assert_eq!(padded_len(n), 1152, "a body of {n} octets");
    }
    // No element is of 257 or 258 octets: a body that would leave that many to its bucket goes up
    // one bucket. 4,608 is a bucket of 512-octet steps.
    for (n, t) in [
        (4349, 4608),
        (4350, 5120),
        (4351, 5120),
        (4352, 4608),
        (4353, 4608),
        (252, 256),
        (253, 384),
        (255, 384),
    ] {
        assert_eq!(padded_len(n), t, "a body of {n} octets");
    }
    // No element is of 65,542 or 65,543 octets: the bucket 1,179,648 is passed over for the next
    // (steps of 131,072) by a body of 65,542 or 65,543 octets less, and not by one of 65,541.
    let bucket = 1_179_648;
    for (gap, t) in [
        (65_541, bucket),
        (65_542, bucket + 131_072),
        (65_543, bucket + 131_072),
        (65_544, bucket),
    ] {
        let n = bucket - gap;
        assert_eq!(
            padded_len(n),
            t,
            "a body of {n} octets, {gap} below a bucket"
        );
        let body = body_of(n).unwrap();
        let padded = crate::answer::pad_body(&body);
        assert_eq!(padded.len(), t);
        assert_eq!(
            crate::answer::unpad_body(Bytes::from(padded)).unwrap(),
            body
        );
    }
}

#[test]
fn every_body_length_pads_to_the_least_bucket_with_room_and_decodes_and_nothing_else_does() {
    use crate::answer::{pad_body, padded_len, unpad_body};
    for n in 4..=70_000usize {
        let t = padded_len(n);
        assert!(is_bucket(t), "{n} octets pad to {t}, not a bucket");
        assert!(
            t == n || element_of(t - n),
            "{n} octets pad to {t}: no element fills it"
        );
        for b in n..t {
            assert!(
                !(is_bucket(b) && (b == n || element_of(b - n))),
                "{n} octets pad to {t}, but the bucket {b} holds them"
            );
        }
        let over = t - n;
        match n <= 1024 {
            true => assert!(over <= 131, "{n} octets pad by {over}"),
            false => assert!(over * 100 <= n * 26, "{n} octets pad by {over}"),
        }
        // The sizes of an AnswerBody TLV are not all there are; those that are, round trip.
        let Some(body) = body_of(n) else { continue };
        let padded = pad_body(&body);
        assert_eq!(padded.len(), t, "a body of {n} octets");
        let padded = Bytes::from(padded);
        assert_eq!(
            unpad_body(padded.clone()).unwrap(),
            body,
            "a body of {n} octets"
        );
        // The padding is due: one octet more or less is refused, and so is none.
        if t > n {
            assert!(unpad_body(padded.slice(..t - 1)).is_err(), "{n}");
            assert!(unpad_body(body.clone()).is_err(), "{n}");
        }
    }
    // The sizes above 70,000, where the steps grow: bucket, and an element that fills it.
    for e in 17..=26u32 {
        for d in [
            0usize, 1, 2, 3, 255, 256, 257, 258, 259, 65_541, 65_542, 65_543, 65_544,
        ] {
            let n = (1usize << e) - d;
            let t = padded_len(n);
            assert!(t >= n && is_bucket(t), "{n} octets pad to {t}");
            assert!(t == n || element_of(t - n), "{n} octets pad to {t}");
            assert!(t * 100 <= n * 126, "{n} octets pad to {t}");
        }
    }
}
