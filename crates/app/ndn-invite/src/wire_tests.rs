//! The introduction's bytes and names (`wire.rs`): the offer record, the ask,
//! the answer, the names a stranger's link carries.

use bytes::Bytes;
use ndn_foundation_types::{Name, NameComponent};
use ndn_heap::{EntryId, Timestamp};
use ndn_tlv::TlvWriter;

use crate::host::Role;
use crate::policy::IntroRefusal;
use crate::proofs::{SECRET_LEN, answer_proof, answer_proves, commitment, proof_key};
use crate::wire::{
    AnswerBody, AskBody, AskProtocol, IntroAsk, IntroRecord, NONCE_LEN, OFFER_ID_LEN, OfferBody,
    OfferId, Outcome, UsedBody, ask_binding, ask_name, hint_prefix, intro_name, intro_prefix,
    introduction_prefixes, offer_name, offer_prefix, parse_ask_name, parse_intro_name,
    parse_offer_name, tlv, write_name,
};

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

/// An offer id with octets no UTF-8 text holds: names carry it as bytes.
fn id() -> OfferId {
    core::array::from_fn(|i| 0x80 + i as u8)
}

fn offer() -> Name {
    offer_name(&n("/alice/laptop"), &id())
}

/// A small Data packet's wire, distinct per `tag`.
fn data_packet(tag: u8) -> Bytes {
    ndn_packet::encode::DataBuilder::new(n("/x").append(vec![tag]), &[tag]).sign_digest_sha256()
}

fn admitted() -> EntryId {
    EntryId {
        device: n("/alice/laptop"),
        seq: 7,
        digest: [0xAD; 32],
    }
}

/// An offer is not a log entry: its name is `<device>/32=intro/offer/<id>`, the
/// id one generic component of 16 octets, and it parses back to exactly the
/// device and the id; no other name does.
#[test]
fn an_offer_name_is_device_intro_offer_id_and_parses_back() {
    let device = n("/alice/laptop");
    let name = offer_name(&device, &id());
    assert_eq!(name.len(), device.len() + 3);
    assert!(name.has_prefix(&intro_prefix(&device)));
    assert!(name.has_prefix(&offer_prefix(&device)));
    let comps = name.components();
    assert_eq!((comps[2].typ, &comps[2].value[..]), (32, &b"intro"[..]));
    assert_eq!((comps[3].typ, &comps[3].value[..]), (32, &b"offer"[..]));
    assert_eq!(comps[4].typ, 8, "a generic component");
    assert_eq!(comps[4].value.len(), OFFER_ID_LEN);
    assert_eq!(OFFER_ID_LEN, 16);
    assert_eq!(parse_offer_name(&name), Some((device.clone(), id())));

    // Not an offer name: the prefix, a longer name, another keyword, an id of
    // another length or type, an ask's name, a device that holds a keyword.
    assert_eq!(parse_offer_name(&device), None);
    assert_eq!(parse_offer_name(&intro_prefix(&device)), None);
    assert_eq!(parse_offer_name(&offer_prefix(&device)), None);
    assert_eq!(parse_offer_name(&name.clone().append("more")), None);
    let other = intro_prefix(&device)
        .append_component(NameComponent::keyword(Bytes::from_static(b"other")))
        .append(id());
    assert_eq!(parse_offer_name(&other), None);
    assert_eq!(
        parse_offer_name(&offer_prefix(&device).append([1u8; 15])),
        None
    );
    assert_eq!(
        parse_offer_name(&offer_prefix(&device).append([1u8; 17])),
        None
    );
    let typed = offer_prefix(&device).append_component(NameComponent::sequence_num(9));
    assert_eq!(parse_offer_name(&typed), None);
    let ask = intro_name(
        &device,
        &IntroAsk {
            ephemeral: [1; 32],
            key: Bytes::from_static(&[2; 4]),
            sealed: Bytes::from_static(&[3; 4]),
        }
        .encode(),
    );
    assert_eq!(parse_offer_name(&ask), None);
    assert_eq!(parse_intro_name(&name), None, "an offer is not an ask");
    let keyworded = intro_prefix(&device).append("x");
    assert_eq!(
        parse_offer_name(
            &keyworded.append_component(NameComponent::keyword(Bytes::from_static(b"offer")))
        ),
        None
    );
    assert_eq!(parse_offer_name(&n("/offer").append(id())), None);
}

/// The names a stranger's link to a device carries: the ask's keyword and the
/// hint's, and nothing else of the device (the offer sits under the first).
#[test]
fn a_dialled_introduction_link_routes_two_prefixes() {
    let device = n("/alice/member/laptop");
    let [intro, hint] = introduction_prefixes(&device);
    assert_eq!(intro, intro_prefix(&device));
    assert_eq!(hint, hint_prefix(&device));
    assert!(offer_name(&device, &id()).has_prefix(&intro));
}

/// Both records round-trip through their TLV; a use mark naming a key without
/// its digest, one naming no offer, an offer allowing no wrong try and an offer
/// of what is no space are refused.
#[test]
fn intro_records_round_trip_and_malformed_ones_are_refused() {
    let offer_body = OfferBody {
        space: n("/alice/32=data/notes"),
        role: Role::Writer,
        until: Timestamp(1_800_000_000_000),
        tries: 3,
        commitment: commitment(&[9; SECRET_LEN]),
        seal_key: [4; 32],
    };
    let offer_record = IntroRecord::Offer(offer_body.clone());
    let used = IntroRecord::Used(UsedBody {
        offer: offer(),
        by: Some((n("/bob/phone/KEY/k1"), [5; 32])),
    });
    let closed = IntroRecord::Used(UsedBody {
        offer: offer(),
        by: None,
    });
    for r in [offer_record.clone(), used, closed] {
        assert_eq!(IntroRecord::decode(r.encode()).unwrap(), r);
    }

    let refuses = |build: &dyn Fn(&mut TlvWriter)| {
        let mut w = TlvWriter::new();
        build(&mut w);
        IntroRecord::decode(w.finish()).unwrap_err()
    };
    refuses(&|w| {
        w.write_nested(tlv::INTRO_USED, |w| {
            write_name(w, &offer());
            w.write_nested(tlv::WRITER, |w| write_name(w, &n("/bob/phone/KEY/k1")));
        });
    });
    refuses(&|w| {
        w.write_nested(tlv::INTRO_USED, |w| {
            w.write_tlv(tlv::DIGEST, &[5; 32]);
        });
    });
    // A use mark names an offer, not a log entry or any other name.
    refuses(&|w| {
        w.write_nested(tlv::INTRO_USED, |w| {
            write_name(w, &n("/alice/laptop/32=log/alice/32=data/notes/seq=7"));
        });
    });
    let tries = |tries: u32| {
        IntroRecord::Offer(OfferBody {
            tries,
            ..offer_body.clone()
        })
    };
    assert!(IntroRecord::decode(tries(0).encode()).is_err());
    assert!(IntroRecord::decode(tries(1).encode()).is_ok());
    let not_a_space = IntroRecord::Offer(OfferBody {
        space: n("/alice/notes"),
        ..offer_body.clone()
    });
    assert!(IntroRecord::decode(not_a_space.encode()).is_err());
    // Neither TLV, nor two records.
    assert!(IntroRecord::decode(Bytes::from_static(&[0x05, 0x00])).is_err());
    let mut two = offer_record.encode().to_vec();
    two.extend_from_slice(&offer_record.encode());
    assert!(IntroRecord::decode(Bytes::from(two)).is_err());
}

/// An ask round-trips through an Interest's parameters, and the name
/// `intro_name` computes is the one the Interest carries (its answer is
/// named so); its body round-trips, and the asker's binding changes with every
/// field it covers.
#[test]
fn an_ask_round_trips_and_its_binding_covers_its_fields() {
    let ask = IntroAsk {
        ephemeral: [1; 32],
        key: Bytes::from_static(&[2; 60]),
        sealed: Bytes::from_static(&[3; 90]),
    };
    let device = n("/alice/laptop");
    let params = ask.encode();
    let wire = ndn_packet::encode::InterestBuilder::new(intro_prefix(&device))
        .app_parameters(params.to_vec())
        .build();
    let interest = ndn_packet::Interest::decode(wire).unwrap();
    assert_eq!(*interest.name, intro_name(&device, &params));
    assert_eq!(parse_intro_name(&interest.name), Some(device.clone()));
    assert_eq!(
        IntroAsk::decode(interest.app_parameters().unwrap().clone()).unwrap(),
        ask
    );
    assert_eq!(parse_intro_name(&intro_prefix(&device)), None);
    let body = AskBody {
        offer: offer(),
        nonce: [6; NONCE_LEN],
        proof: [7; 32],
        credentials: vec![data_packet(1), data_packet(2)],
        asker: data_packet(3),
    };
    assert_eq!(AskBody::decode(body.encode()).unwrap(), body);
    let d = n("/alice/laptop");
    let other_nonce = AskBody {
        nonce: [8; NONCE_LEN],
        ..body.clone()
    };
    let other_creds = AskBody {
        credentials: vec![data_packet(1)],
        ..body.clone()
    };
    assert_ne!(body.binding(&d), other_nonce.binding(&d));
    assert_ne!(body.binding(&d), other_creds.binding(&d));
    assert_ne!(body.binding(&d), body.binding(&n("/alice/phone")));
}

/// A proof made for one protocol never verifies as another's, and the labels
/// are the invite crate's.
#[test]
fn bindings_are_labelled_by_protocol() {
    assert_eq!(AskProtocol::IntroAsk.label(), b"ndn-invite intro ask\0");
    assert_eq!(
        AskProtocol::IntroAnswer.label(),
        b"ndn-invite intro answer\0"
    );
    for (i, a) in AskProtocol::ALL.iter().enumerate() {
        assert_eq!(a.label().last(), Some(&0), "ends in a zero octet");
        for b in &AskProtocol::ALL[i + 1..] {
            assert!(!a.label().starts_with(b.label()));
            assert!(!b.label().starts_with(a.label()));
            assert_ne!(ask_binding(*a, &[b"x"]), ask_binding(*b, &[b"x"]));
        }
    }
    let binding = ask_binding(AskProtocol::IntroAsk, &[b"a", b"b"]);
    let name = ask_name(&n("/bob/phone"), &binding);
    assert_eq!(parse_ask_name(&name), Some((n("/bob/phone"), binding)));
    assert_eq!(parse_ask_name(&n("/bob/phone")), None);
    assert_eq!(parse_ask_name(&name.append("more")), None);
}

/// Answers round-trip, accepted and refused; the proof covers the asker, and a
/// different key or a changed field does not verify; the entry that admitted
/// the asker is covered too; an acceptance without a proof, or a refusal with
/// one, is malformed.
#[test]
fn answers_round_trip_and_their_proof_binds_the_asker_and_every_field() {
    let secret = [0x5A; SECRET_LEN];
    let key = proof_key(&secret, &offer());
    let mut accepted = AnswerBody {
        offer: offer(),
        asker: n("/bob/phone/KEY/k1"),
        digest: [5; 32],
        outcome: Outcome::Accepted {
            space: n("/alice/32=data/notes"),
            role: Role::Reader,
            credentials: vec![data_packet(1)],
            inviter: data_packet(4),
            admitted: Some(admitted()),
        },
        proof: None,
    };
    accepted.proof = Some(answer_proof(&key, &accepted));
    assert_eq!(AnswerBody::decode(accepted.encode()).unwrap(), accepted);
    assert!(answer_proves(&key, &accepted));
    let other_key = proof_key(&[0x5B; SECRET_LEN], &offer());
    assert!(!answer_proves(&other_key, &accepted));
    let carol = AnswerBody {
        asker: n("/carol/phone/KEY/k1"),
        ..accepted.clone()
    };
    assert!(!answer_proves(&key, &carol));
    // The entry that admitted the asker is covered (each of its three fields),
    // and an answer without one reads as one.
    let at = |admitted: Option<EntryId>| {
        let Outcome::Accepted {
            space,
            role,
            credentials,
            inviter,
            ..
        } = accepted.outcome.clone()
        else {
            unreachable!("an acceptance")
        };
        AnswerBody {
            outcome: Outcome::Accepted {
                space,
                role,
                credentials,
                inviter,
                admitted,
            },
            ..accepted.clone()
        }
    };
    for changed in [
        EntryId {
            seq: 8,
            ..admitted()
        },
        EntryId {
            digest: [0xAE; 32],
            ..admitted()
        },
        EntryId {
            device: n("/alice/phone"),
            ..admitted()
        },
    ] {
        assert!(
            !answer_proves(&key, &at(Some(changed))),
            "the admitting entry is not proven"
        );
    }
    assert!(!answer_proves(&key, &at(None)));
    let mut kept = at(None);
    kept.proof = Some(answer_proof(&key, &kept));
    assert_eq!(AnswerBody::decode(kept.encode()).unwrap(), kept);
    let unproven = AnswerBody {
        proof: None,
        ..accepted.clone()
    };
    assert!(AnswerBody::decode(unproven.encode()).is_err());
    for why in [
        IntroRefusal::Unknown,
        IntroRefusal::Used,
        IntroRefusal::Expired,
        IntroRefusal::Closed,
        IntroRefusal::WrongProof { left: 2 },
        IntroRefusal::Conflict,
    ] {
        let mut refused = AnswerBody {
            outcome: Outcome::Refused(why),
            proof: None,
            ..accepted.clone()
        };
        assert_eq!(AnswerBody::decode(refused.encode()).unwrap(), refused);
        refused.proof = Some(answer_proof(&key, &refused));
        assert!(AnswerBody::decode(refused.encode()).is_err());
    }
}

/// The admitting entry is one nested TLV (device, seq, digest), each once: a
/// half-written one, a twice-written field and a digest of another size are
/// refused.
#[test]
fn the_admitted_field_names_one_entry_whole() {
    let with = |admitted: &dyn Fn(&mut TlvWriter)| {
        let mut w = TlvWriter::new();
        w.write_nested(tlv::INTRO_ANSWER, |w| {
            write_name(w, &offer());
            w.write_nested(tlv::WRITER, |w| write_name(w, &n("/bob/phone/KEY/k1")));
            w.write_tlv(tlv::DIGEST, &[5; 32]);
            write_name(w, &n("/alice/32=data/notes"));
            crate::wire::write_nni(w, tlv::ROLE, 0);
            w.write_nested(tlv::ADMITTED, |w| admitted(w));
            w.write_tlv(tlv::CREDENTIALS, &data_packet(1));
            w.write_tlv(tlv::ASKER, &data_packet(4));
            w.write_tlv(tlv::PROOF, &[9; 32]);
        });
        AnswerBody::decode(w.finish())
    };
    let whole = |w: &mut TlvWriter| {
        write_name(w, &n("/alice/laptop"));
        crate::wire::write_nni(w, tlv::SEQ, 7);
        w.write_tlv(tlv::DIGEST, &[1; 32]);
    };
    let got = with(&whole).unwrap();
    assert!(matches!(
        got.outcome,
        Outcome::Accepted {
            admitted: Some(EntryId { seq: 7, .. }),
            ..
        }
    ));
    assert!(
        with(&|w| {
            write_name(w, &n("/alice/laptop"));
            crate::wire::write_nni(w, tlv::SEQ, 7);
        })
        .is_err()
    );
    assert!(
        with(&|w| {
            whole(w);
            crate::wire::write_nni(w, tlv::SEQ, 8);
        })
        .is_err()
    );
    assert!(
        with(&|w| {
            write_name(w, &n("/alice/laptop"));
            crate::wire::write_nni(w, tlv::SEQ, 7);
            w.write_tlv(tlv::DIGEST, &[1; 31]);
        })
        .is_err()
    );
}

/// Credentials are Data packets, whole, and at least one.
#[test]
fn credentials_are_data_packets_and_not_empty() {
    let ask = |credentials: Vec<Bytes>| AskBody {
        offer: offer(),
        nonce: [6; NONCE_LEN],
        proof: [7; 32],
        credentials,
        asker: data_packet(3),
    };
    assert!(AskBody::decode(ask(vec![]).encode()).is_err(), "none");
    let body = ask(vec![Bytes::from_static(&[0x05, 0x01, 0x00])]);
    assert!(AskBody::decode(body.encode()).is_err(), "not Data");
}
