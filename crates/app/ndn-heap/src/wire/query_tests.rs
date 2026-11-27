//! The records of a signed query: golden vectors written by hand from the TLV rules (the same
//! octets are in `docs/specs/query.md`), the limits, and every refusal.

use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_tlv::TlvWriter;

use super::*;
use crate::wire::{EpochId, WireError};

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Bytes {
    Bytes::from(
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect::<Vec<u8>>(),
    )
}

fn epoch() -> EpochId {
    EpochId {
        creator: n("/a/d"),
        seq: 3,
    }
}

const ID: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

fn plain() -> QueryAsk {
    QueryAsk {
        space: n("/a/32=data/w"),
        path: Some(n("/get")),
        id: ID,
        deadline_ms: 3000,
        bytes: Bytes::from_static(b"hi"),
        seal: None,
        chain: vec![Bytes::from_static(&[0xC0, 0xDE, 0x01])],
    }
}

fn sealed() -> QueryAsk {
    QueryAsk {
        space: n("/a/32=data/w"),
        path: None,
        id: ID,
        deadline_ms: 3000,
        bytes: Bytes::from(vec![0xCC; 20]),
        seal: Some(AskSeal {
            ephemeral: [0x11; 32],
            epoch: epoch(),
            seq: 5,
        }),
        chain: Vec::new(),
    }
}

fn answer(body: AnswerBody) -> QueryAnswer {
    QueryAnswer {
        id: ID,
        body,
        certs: Vec::new(),
    }
}

const SPACE: &str = "fd06c30c080161200464617461080177";
const QID: &str = "fd06c7080102030405060708";

fn golden_plain_ask() -> String {
    format!("fd06c138{SPACE}fd06c5050803676574{QID}fd06c9020bb8fd06cb026869fd063d03c0de01")
}

fn golden_sealed_ask() -> String {
    format!(
        "fd06c174{SPACE}{QID}fd06c9020bb8fd06cb14{}fd06cd20{}fd06db0d0706080161080164fd060b0103fd06dd0105",
        "cc".repeat(20),
        "11".repeat(32)
    )
}

#[test]
fn the_golden_vectors_are_the_octets_of_each_record_and_decode_back() {
    let wire = plain().encode().unwrap();
    assert_eq!(hex(&wire), golden_plain_ask(), "a plain ask");
    assert_eq!(
        QueryAsk::decode(unhex(&golden_plain_ask())).unwrap(),
        plain()
    );

    let wire = sealed().encode().unwrap();
    assert_eq!(hex(&wire), golden_sealed_ask(), "a sealed ask");
    assert_eq!(
        QueryAsk::decode(unhex(&golden_sealed_ask())).unwrap(),
        sealed()
    );

    let cases = [
        (
            "answered",
            Status::Answered(Bytes::from_static(b"ok")),
            format!("fd06cf17{QID}fd06d10101fd06d3026f6b"),
        ),
        (
            "refused",
            Status::Refused {
                code: 7,
                text: "no".into(),
            },
            format!("fd06cf1c{QID}fd06d10102fd06d50107fd06d7026e6f"),
        ),
        (
            "not served",
            Status::NotServed,
            format!("fd06cf11{QID}fd06d10103"),
        ),
        (
            "too large",
            Status::TooLarge { max: 4096 },
            format!("fd06cf17{QID}fd06d10104fd06d5021000"),
        ),
    ];
    for (what, status, golden) in cases {
        let a = answer(AnswerBody::Plain(status));
        assert_eq!(hex(&a.encode().unwrap()), golden, "{what}");
        assert_eq!(QueryAnswer::decode(unhex(&golden)).unwrap(), a, "{what}");
    }

    let sealed_answer = QueryAnswer {
        id: ID,
        body: AnswerBody::Sealed {
            seq: 9,
            cipher: Bytes::from(vec![0xDD; 18]),
        },
        certs: vec![Bytes::from_static(&[0xC0, 0xDE, 0x02])],
    };
    let golden = format!(
        "fd06cf2e{QID}fd06dd0109fd06df12{}fd069703c0de02",
        "dd".repeat(18)
    );
    assert_eq!(hex(&sealed_answer.encode().unwrap()), golden, "sealed");
    assert_eq!(QueryAnswer::decode(unhex(&golden)).unwrap(), sealed_answer);

    // The inner run of a status is the same fields without the record around them.
    let inner = Status::Answered(Bytes::from_static(b"ok")).encode_inner();
    assert_eq!(hex(&inner), "fd06d10101fd06d3026f6b");
    assert_eq!(
        Status::decode_inner(inner).unwrap(),
        Status::Answered(Bytes::from_static(b"ok"))
    );
    // The sealed part of a query: the path, then the octets.
    let inner = QueryAsk::seal_inner(&n("/get"), b"hi");
    assert_eq!(hex(&inner), "fd06c5050803676574fd06cb026869");
    assert_eq!(
        QueryAsk::open_inner(inner).unwrap(),
        (n("/get"), Bytes::from_static(b"hi"))
    );
}

/// `typ` with `value`, as a TLV.
fn tlv_of(typ: u64, value: &[u8]) -> Vec<u8> {
    let mut w = TlvWriter::new();
    w.write_tlv(typ, value);
    w.finish().to_vec()
}

/// `QUERY_ASK` (or `QUERY_ANSWER`, by `outer`) around hand-made fields.
fn record(outer: u64, fields: &[Vec<u8>]) -> Bytes {
    let mut w = TlvWriter::new();
    w.write_nested(outer, |w| {
        for f in fields {
            w.write_raw(f);
        }
    });
    w.finish()
}

fn name_value(name: &Name) -> Vec<u8> {
    let mut w = TlvWriter::new();
    for c in name.components() {
        w.write_tlv(c.typ, &c.value);
    }
    w.finish().to_vec()
}

fn nni(typ: u64, v: u64) -> Vec<u8> {
    let mut w = TlvWriter::new();
    write_nni(&mut w, typ, v);
    w.finish().to_vec()
}

/// The fields of a plain ask, each as the octets of its TLV, in the order of the wire.
fn plain_fields() -> Vec<Vec<u8>> {
    vec![
        tlv_of(Q_SPACE, &name_value(&n("/a/32=data/w"))),
        tlv_of(Q_PATH, &name_value(&n("/get"))),
        tlv_of(Q_ID, &ID),
        nni(Q_DEADLINE, 3000),
        tlv_of(Q_BYTES, b"hi"),
    ]
}

fn sealed_fields() -> Vec<Vec<u8>> {
    let mut epoch_value = TlvWriter::new();
    write_epoch_id_value(&mut epoch_value);
    vec![
        tlv_of(Q_SPACE, &name_value(&n("/a/32=data/w"))),
        tlv_of(Q_ID, &ID),
        nni(Q_DEADLINE, 3000),
        tlv_of(Q_BYTES, &[0xCC; 20]),
        tlv_of(Q_SEAL, &[0x11; 32]),
        tlv_of(Q_EPOCH, &epoch_value.finish()),
        nni(Q_SEQ, 5),
    ]
}

/// The value of an `EPOCH_ID` of `/a/d` seq 3, by hand: a name and a seq.
fn write_epoch_id_value(w: &mut TlvWriter) {
    w.write_nested(0x07, |w| {
        w.write_tlv(0x08, b"a");
        w.write_tlv(0x08, b"d");
    });
    w.write_tlv(0x060B, &[3]);
}

fn without(fields: &[Vec<u8>], typ: u64) -> Vec<Vec<u8>> {
    fields
        .iter()
        .filter(|f| {
            let mut r = ndn_tlv::TlvReader::new(Bytes::from(f.to_vec()));
            r.read_tlv().unwrap().0 != typ
        })
        .cloned()
        .collect()
}

#[test]
fn the_hand_made_fields_decode_to_the_asks_the_refusal_cases_start_from() {
    // Each refusal below changes one field of these, so a refusal is of that field alone.
    assert!(
        QueryAsk::decode(record(QUERY_ASK, &plain_fields()))
            .unwrap()
            .chain
            .is_empty()
    );
    let sealed = QueryAsk::decode(record(QUERY_ASK, &sealed_fields())).unwrap();
    assert_eq!(sealed.seal.unwrap().seq, 5);
}

/// A name of exactly `octets` octets of value: two generic components.
fn long_name(octets: usize) -> Name {
    Name::root()
        .append(vec![b'p'; 200 - 2])
        .append(vec![b'q'; octets - 200 - 2])
}
#[test]
fn an_unknown_even_type_is_skipped_and_an_unknown_odd_one_is_refused_in_every_record() {
    let skip = tlv_of(0x06E0, b"future");
    let crit = tlv_of(0x06FF, b"future");
    let with = |mut fields: Vec<Vec<u8>>, extra: &[u8]| {
        fields.push(extra.to_vec());
        fields
    };
    for fields in [plain_fields(), sealed_fields()] {
        assert!(QueryAsk::decode(record(QUERY_ASK, &with(fields.clone(), &skip))).is_ok());
        assert_eq!(
            QueryAsk::decode(record(QUERY_ASK, &with(fields, &crit))),
            Err(WireError::UnknownCritical(0x06FF))
        );
    }
    let body = vec![tlv_of(Q_ID, &ID), nni(A_STATUS, 3)];
    assert_eq!(
        QueryAnswer::decode(record(QUERY_ANSWER, &with(body.clone(), &skip)))
            .unwrap()
            .body,
        AnswerBody::Plain(Status::NotServed)
    );
    assert_eq!(
        QueryAnswer::decode(record(QUERY_ANSWER, &with(body, &crit))),
        Err(WireError::UnknownCritical(0x06FF))
    );
    // Inside the sealed part, too.
    let inner = [nni(A_STATUS, 3), skip].concat();
    assert_eq!(
        Status::decode_inner(Bytes::from(inner)),
        Ok(Status::NotServed)
    );
    let inner = [nni(A_STATUS, 3), crit.clone()].concat();
    assert_eq!(
        Status::decode_inner(Bytes::from(inner)),
        Err(WireError::UnknownCritical(0x06FF))
    );
    let inner = [tlv_of(Q_BYTES, b"x"), crit].concat();
    assert_eq!(
        QueryAsk::open_inner(Bytes::from(inner)),
        Err(WireError::UnknownCritical(0x06FF))
    );
    // 0x06D9 is reserved for a later `Busy` and is, until then, an unknown odd type.
    assert_eq!(
        QueryAnswer::decode(record(
            QUERY_ANSWER,
            &[tlv_of(Q_ID, &ID), nni(A_STATUS, 3), nni(0x06D9, 5)]
        )),
        Err(WireError::UnknownCritical(0x06D9))
    );
}

#[test]
fn a_plain_ask_needs_its_path_and_a_sealed_one_has_none() {
    assert!(matches!(
        QueryAsk::decode(record(QUERY_ASK, &without(&plain_fields(), Q_PATH))),
        Err(WireError::Missing(_))
    ));
    let mut no_path = plain();
    no_path.path = None;
    assert!(matches!(no_path.encode(), Err(WireError::Missing(_))));
    // A path beside a seal.
    let mut both = sealed_fields();
    both.push(tlv_of(Q_PATH, &name_value(&n("/get"))));
    assert!(matches!(
        QueryAsk::decode(record(QUERY_ASK, &both)),
        Err(WireError::Malformed(_))
    ));
    let mut both = sealed();
    both.path = Some(n("/get"));
    assert!(matches!(both.encode(), Err(WireError::Malformed(_))));
    // Any of the three seal fields alone, or two of them.
    for gone in [Q_SEAL, Q_EPOCH, Q_SEQ] {
        assert!(
            matches!(
                QueryAsk::decode(record(QUERY_ASK, &without(&sealed_fields(), gone))),
                Err(WireError::Malformed(_))
            ),
            "a seal without {gone:#x}"
        );
    }
    for keep in [Q_SEAL, Q_EPOCH, Q_SEQ] {
        let mut mixed = plain_fields();
        mixed.extend(
            sealed_fields()
                .into_iter()
                .filter(|f| f.starts_with(&tlv_of(keep, &[])[..3])),
        );
        assert!(
            matches!(
                QueryAsk::decode(record(QUERY_ASK, &mixed)),
                Err(WireError::Malformed(_))
            ),
            "a plain ask with only {keep:#x}"
        );
    }
}

#[test]
fn an_ask_is_refused_for_each_missing_duplicate_or_malformed_field() {
    for (drop, what) in [
        (Q_SPACE, "space"),
        (Q_ID, "id"),
        (Q_DEADLINE, "deadline"),
        (Q_BYTES, "bytes"),
    ] {
        assert!(
            matches!(
                QueryAsk::decode(record(QUERY_ASK, &without(&plain_fields(), drop))),
                Err(WireError::Missing(_))
            ),
            "no {what}"
        );
    }
    for (typ, value) in [
        (Q_SPACE, name_value(&n("/a"))),
        (Q_PATH, name_value(&n("/b"))),
        (Q_ID, ID.to_vec()),
        (Q_DEADLINE, vec![5]),
        (Q_BYTES, vec![]),
    ] {
        let mut twice = plain_fields();
        twice.push(tlv_of(typ, &value));
        assert!(
            matches!(
                QueryAsk::decode(record(QUERY_ASK, &twice)),
                Err(WireError::Duplicate(_))
            ),
            "{typ:#x} twice"
        );
    }
    // An id of 7 or 9 octets, a seal key of 31.
    for id in [&ID[..7], &[1u8; 9][..]] {
        let mut f = plain_fields();
        f[2] = tlv_of(Q_ID, id);
        assert!(matches!(
            QueryAsk::decode(record(QUERY_ASK, &f)),
            Err(WireError::Malformed(_))
        ));
    }
    let mut f = sealed_fields();
    f[4] = tlv_of(Q_SEAL, &[1u8; 31]);
    assert!(matches!(
        QueryAsk::decode(record(QUERY_ASK, &f)),
        Err(WireError::Malformed(_))
    ));
    // A record that is no ask, or an ask and more.
    assert!(QueryAsk::decode(record(QUERY_ANSWER, &plain_fields())).is_err());
    let mut two = plain().encode().unwrap().to_vec();
    two.extend_from_slice(&plain().encode().unwrap());
    assert!(QueryAsk::decode(Bytes::from(two)).is_err());
}

#[test]
fn the_deadline_is_1_to_10_000_milliseconds() {
    for ok in [1, 3000, 10_000] {
        let ask = QueryAsk {
            deadline_ms: ok,
            ..plain()
        };
        assert_eq!(QueryAsk::decode(ask.encode().unwrap()).unwrap(), ask);
    }
    for bad in [0u32, 10_001, u32::MAX] {
        let ask = QueryAsk {
            deadline_ms: bad,
            ..plain()
        };
        assert!(
            matches!(ask.encode(), Err(WireError::Malformed(_))),
            "{bad}"
        );
        let mut f = plain_fields();
        f[3] = nni(Q_DEADLINE, u64::from(bad));
        assert!(
            matches!(
                QueryAsk::decode(record(QUERY_ASK, &f)),
                Err(WireError::Malformed(_))
            ),
            "{bad} on the wire"
        );
    }
    // A deadline that does not fit 32 bits is no deadline.
    let mut f = plain_fields();
    f[3] = nni(Q_DEADLINE, 1 << 40);
    assert!(matches!(
        QueryAsk::decode(record(QUERY_ASK, &f)),
        Err(WireError::Malformed(_))
    ));
}

#[test]
fn the_limits_of_an_ask_hold() {
    // Query octets: 2,048 plain.
    let at = QueryAsk {
        bytes: Bytes::from(vec![1; QUERY_BYTES_MAX]),
        ..plain()
    };
    assert_eq!(QueryAsk::decode(at.encode().unwrap()).unwrap(), at);
    let over = QueryAsk {
        bytes: Bytes::from(vec![1; QUERY_BYTES_MAX + 1]),
        ..plain()
    };
    assert!(matches!(over.encode(), Err(WireError::TooLarge { .. })));
    let mut f = plain_fields();
    f[4] = tlv_of(Q_BYTES, &vec![1; QUERY_BYTES_MAX + 1]);
    assert!(matches!(
        QueryAsk::decode(record(QUERY_ASK, &f)),
        Err(WireError::TooLarge { .. })
    ));
    // The ciphertext of a sealed one: 2,048 + 255 + 64.
    assert_eq!(QUERY_SEALED_MAX, 2367);
    let at = QueryAsk {
        bytes: Bytes::from(vec![1; 2367]),
        ..sealed()
    };
    assert_eq!(QueryAsk::decode(at.encode().unwrap()).unwrap(), at);
    let over = QueryAsk {
        bytes: Bytes::from(vec![1; 2368]),
        ..sealed()
    };
    assert!(matches!(over.encode(), Err(WireError::TooLarge { .. })));
    let mut f = sealed_fields();
    f[3] = tlv_of(Q_BYTES, &vec![1; 2368]);
    assert!(matches!(
        QueryAsk::decode(record(QUERY_ASK, &f)),
        Err(WireError::TooLarge { .. })
    ));
    // Shorter than a tag, a ciphertext opens to nothing.
    let short = QueryAsk {
        bytes: Bytes::from(vec![1; 15]),
        ..sealed()
    };
    assert!(matches!(short.encode(), Err(WireError::TooLarge { .. })));
    // A path of 255 octets of name value, not 256.
    let path = long_name;
    assert_eq!(name_value_len(&path(255)), 255);
    let at = QueryAsk {
        path: Some(path(255)),
        ..plain()
    };
    assert_eq!(QueryAsk::decode(at.encode().unwrap()).unwrap(), at);
    let over = QueryAsk {
        path: Some(path(256)),
        ..plain()
    };
    assert!(matches!(over.encode(), Err(WireError::TooLarge { .. })));
    let mut f = plain_fields();
    f[1] = tlv_of(Q_PATH, &name_value(&path(256)));
    assert!(matches!(
        QueryAsk::decode(record(QUERY_ASK, &f)),
        Err(WireError::TooLarge { .. })
    ));
    // The whole parameters: 8 KiB.
    let mut f = plain_fields();
    f[0] = tlv_of(
        Q_SPACE,
        &name_value(&Name::root().append(vec![b's'; 8 * 1024])),
    );
    let big = record(QUERY_ASK, &f);
    assert!(big.len() > QUERY_ASK_MAX);
    assert!(matches!(
        QueryAsk::decode(big),
        Err(WireError::TooLarge {
            max: QUERY_ASK_MAX,
            ..
        })
    ));
    let huge = QueryAsk {
        space: Name::root().append(vec![b's'; 8 * 1024]),
        ..plain()
    };
    assert!(matches!(
        huge.encode(),
        Err(WireError::TooLarge {
            max: QUERY_ASK_MAX,
            ..
        })
    ));
}

#[test]
fn the_certificates_are_at_most_four_of_4096_and_6144_octets_in_all() {
    let certs = |sizes: &[usize]| {
        sizes
            .iter()
            .map(|s| Bytes::from(vec![7; *s]))
            .collect::<Vec<_>>()
    };
    for (what, sizes, ok) in [
        ("four small", vec![10; 4], true),
        ("five", vec![1; 5], false),
        ("one of 4096", vec![4096], true),
        ("one of 4097", vec![4097], false),
        ("6144 in all", vec![4096, 2048], true),
        ("6145 in all", vec![4096, 2049], false),
    ] {
        let ask = QueryAsk {
            chain: certs(&sizes),
            ..plain()
        };
        assert_eq!(ask.encode().is_ok(), ok, "an ask with {what}");
        let mut f = plain_fields();
        f.extend(sizes.iter().map(|s| tlv_of(tlv::ASKER_CERT, &vec![7; *s])));
        assert_eq!(
            QueryAsk::decode(record(QUERY_ASK, &f)).is_ok(),
            ok,
            "an ask with {what} on the wire"
        );
        let a = QueryAnswer {
            certs: certs(&sizes),
            ..answer(AnswerBody::Plain(Status::NotServed))
        };
        assert_eq!(a.encode().is_ok(), ok, "an answer with {what}");
        let mut f = vec![tlv_of(Q_ID, &ID), nni(A_STATUS, 3)];
        f.extend(sizes.iter().map(|s| tlv_of(S_CERT, &vec![7; *s])));
        assert_eq!(
            QueryAnswer::decode(record(QUERY_ANSWER, &f)).is_ok(),
            ok,
            "an answer with {what} on the wire"
        );
    }
}

#[test]
fn the_limits_of_an_answer_hold() {
    // 4,096 octets of answer, not 4,097.
    let at = answer(AnswerBody::Plain(Status::Answered(Bytes::from(vec![
        1;
        ANSWER_BYTES_MAX
    ]))));
    assert_eq!(QueryAnswer::decode(at.encode().unwrap()).unwrap(), at);
    let over = answer(AnswerBody::Plain(Status::Answered(Bytes::from(vec![
        1;
        ANSWER_BYTES_MAX + 1
    ]))));
    assert!(matches!(over.encode(), Err(WireError::TooLarge { .. })));
    let f = [
        tlv_of(Q_ID, &ID),
        nni(A_STATUS, 1),
        tlv_of(A_BYTES, &vec![1; ANSWER_BYTES_MAX + 1]),
    ];
    assert!(matches!(
        QueryAnswer::decode(record(QUERY_ANSWER, &f)),
        Err(WireError::TooLarge { .. })
    ));
    // A refusal's text: 256 octets, not 257.
    let text = |n: usize| Status::Refused {
        code: 1,
        text: "a".repeat(n),
    };
    let at = answer(AnswerBody::Plain(text(256)));
    assert_eq!(QueryAnswer::decode(at.encode().unwrap()).unwrap(), at);
    assert!(matches!(
        answer(AnswerBody::Plain(text(257))).encode(),
        Err(WireError::TooLarge { .. })
    ));
    let f = [
        tlv_of(Q_ID, &ID),
        nni(A_STATUS, 2),
        nni(A_CODE, 1),
        tlv_of(A_TEXT, &[b'a'; 257]),
    ];
    assert!(matches!(
        QueryAnswer::decode(record(QUERY_ANSWER, &f)),
        Err(WireError::TooLarge {
            max: ANSWER_TEXT_MAX,
            ..
        })
    ));
    // A text built by `refused` is cut at a character boundary.
    let cut = Status::refused(2, &"é".repeat(200));
    let Status::Refused { text, .. } = &cut else {
        panic!("{cut:?}")
    };
    assert_eq!(text.len(), 256);
    assert!(cut.check().is_ok());
    // A sealed answer's ciphertext: 4,096 + 256 + 64, not more; and at least a tag.
    let sealed = |len: usize| {
        answer(AnswerBody::Sealed {
            seq: 1,
            cipher: Bytes::from(vec![1; len]),
        })
    };
    let at = sealed(ANSWER_SEALED_MAX);
    assert_eq!(QueryAnswer::decode(at.encode().unwrap()).unwrap(), at);
    assert!(sealed(ANSWER_SEALED_MAX + 1).encode().is_err());
    assert!(sealed(15).encode().is_err());
    let f = [
        tlv_of(Q_ID, &ID),
        nni(Q_SEQ, 1),
        tlv_of(A_SEALED, &vec![1; ANSWER_SEALED_MAX + 1]),
    ];
    assert!(matches!(
        QueryAnswer::decode(record(QUERY_ANSWER, &f)),
        Err(WireError::TooLarge { .. })
    ));
    // The Content: 8,000 octets in all, with the certificates that fit beside a full answer.
    let full = QueryAnswer {
        certs: vec![Bytes::from(vec![9; 3500])],
        ..answer(AnswerBody::Plain(Status::Answered(Bytes::from(vec![
            1;
            ANSWER_BYTES_MAX
        ]))))
    };
    let wire = full.encode().unwrap();
    assert!(wire.len() <= ANSWER_CONTENT_MAX);
    let crowded = QueryAnswer {
        certs: vec![Bytes::from(vec![9; 3900])],
        ..full
    };
    assert!(
        matches!(
            crowded.encode(),
            Err(WireError::TooLarge {
                max: ANSWER_CONTENT_MAX,
                ..
            })
        ),
        "4,096 octets and a 3,900-octet certificate do not fit 8,000"
    );
    let mut f = vec![
        tlv_of(Q_ID, &ID),
        nni(A_STATUS, 1),
        tlv_of(A_BYTES, &vec![1; ANSWER_BYTES_MAX]),
    ];
    f.push(tlv_of(S_CERT, &vec![9; 3900]));
    let over = record(QUERY_ANSWER, &f);
    assert!(over.len() > ANSWER_CONTENT_MAX);
    assert!(matches!(
        QueryAnswer::decode(over),
        Err(WireError::TooLarge {
            max: ANSWER_CONTENT_MAX,
            ..
        })
    ));
}

#[test]
fn an_answer_is_refused_for_each_missing_duplicate_or_malformed_field() {
    let rec = |f: &[Vec<u8>]| QueryAnswer::decode(record(QUERY_ANSWER, f));
    // No id, no status.
    assert!(matches!(
        rec(&[nni(A_STATUS, 3)]),
        Err(WireError::Missing(_))
    ));
    assert!(matches!(
        rec(&[tlv_of(Q_ID, &ID)]),
        Err(WireError::Missing(_))
    ));
    // An id of 7 octets.
    assert!(matches!(
        rec(&[tlv_of(Q_ID, &ID[..7]), nni(A_STATUS, 3)]),
        Err(WireError::Malformed(_))
    ));
    // Twice.
    assert!(matches!(
        rec(&[tlv_of(Q_ID, &ID), tlv_of(Q_ID, &ID), nni(A_STATUS, 3)]),
        Err(WireError::Duplicate(_))
    ));
    assert!(matches!(
        rec(&[tlv_of(Q_ID, &ID), nni(A_STATUS, 3), nni(A_STATUS, 3)]),
        Err(WireError::Duplicate(_))
    ));
    // Each status wants its fields, and only its own.
    let id = || tlv_of(Q_ID, &ID);
    for (what, f, missing) in [
        (
            "answered without octets",
            vec![id(), nni(A_STATUS, 1)],
            true,
        ),
        (
            "refused without a code",
            vec![id(), nni(A_STATUS, 2), tlv_of(A_TEXT, b"x")],
            true,
        ),
        (
            "refused without a text",
            vec![id(), nni(A_STATUS, 2), nni(A_CODE, 1)],
            true,
        ),
        (
            "too large without a limit",
            vec![id(), nni(A_STATUS, 4)],
            true,
        ),
        (
            "not served with octets",
            vec![id(), nni(A_STATUS, 3), tlv_of(A_BYTES, b"x")],
            false,
        ),
        (
            "answered with a code",
            vec![
                id(),
                nni(A_STATUS, 1),
                tlv_of(A_BYTES, b"x"),
                nni(A_CODE, 1),
            ],
            false,
        ),
        (
            "refused with octets",
            vec![
                id(),
                nni(A_STATUS, 2),
                nni(A_CODE, 1),
                tlv_of(A_TEXT, b"x"),
                tlv_of(A_BYTES, b"x"),
            ],
            false,
        ),
        (
            "too large with a text",
            vec![id(), nni(A_STATUS, 4), nni(A_CODE, 1), tlv_of(A_TEXT, b"x")],
            false,
        ),
        ("status 0", vec![id(), nni(A_STATUS, 0)], false),
        ("status 5", vec![id(), nni(A_STATUS, 5)], false),
        (
            "refused with a code over 16 bits",
            vec![
                id(),
                nni(A_STATUS, 2),
                nni(A_CODE, 65_536),
                tlv_of(A_TEXT, b"x"),
            ],
            false,
        ),
    ] {
        let refused = rec(&f);
        assert!(
            if missing {
                matches!(refused, Err(WireError::Missing(_)))
            } else {
                matches!(refused, Err(WireError::Malformed(_)))
            },
            "{what}: {refused:?}"
        );
    }
    // Bad UTF-8 in a text.
    assert!(matches!(
        rec(&[
            id(),
            nni(A_STATUS, 2),
            nni(A_CODE, 1),
            tlv_of(A_TEXT, &[0xFF, 0xFE])
        ]),
        Err(WireError::Malformed(_))
    ));
    assert!(matches!(
        Status::decode_inner(Bytes::from(
            [
                nni(A_STATUS, 2),
                nni(A_CODE, 1),
                tlv_of(A_TEXT, &[0xC3, 0x28])
            ]
            .concat()
        )),
        Err(WireError::Malformed(_))
    ));
}

#[test]
fn a_sealed_answer_is_sealed_whole_or_not_at_all() {
    let id = || tlv_of(Q_ID, &ID);
    let rec = |f: &[Vec<u8>]| QueryAnswer::decode(record(QUERY_ANSWER, f));
    let cipher = || tlv_of(A_SEALED, &[1; 20]);
    // A counter without a sealed part, a sealed part without a counter.
    assert!(matches!(
        rec(&[id(), nni(Q_SEQ, 1), nni(A_STATUS, 3)]),
        Err(WireError::Malformed(_))
    ));
    assert!(matches!(
        rec(&[id(), cipher()]),
        Err(WireError::Malformed(_))
    ));
    // The status beside the sealed part would be a status the seal does not cover.
    assert!(matches!(
        rec(&[id(), nni(Q_SEQ, 1), cipher(), nni(A_STATUS, 3)]),
        Err(WireError::Malformed(_))
    ));
    // Twice.
    assert!(matches!(
        rec(&[id(), nni(Q_SEQ, 1), cipher(), cipher()]),
        Err(WireError::Duplicate(_))
    ));
    assert!(matches!(
        rec(&[id(), nni(Q_SEQ, 1), nni(Q_SEQ, 1), cipher()]),
        Err(WireError::Duplicate(_))
    ));
}

#[test]
fn the_sealed_part_of_a_query_is_a_path_and_octets_within_their_limits() {
    let path = long_name(255);
    assert_eq!(name_value_len(&path), 255);
    let inner = QueryAsk::seal_inner(&path, &[1; QUERY_BYTES_MAX]);
    assert_eq!(
        QueryAsk::open_inner(inner).unwrap(),
        (path, Bytes::from(vec![1; QUERY_BYTES_MAX]))
    );
    // Empty octets are a query (a ping).
    assert_eq!(
        QueryAsk::open_inner(QueryAsk::seal_inner(&Name::root(), b"")).unwrap(),
        (Name::root(), Bytes::new())
    );
    let too_long = long_name(256);
    let f = [
        tlv_of(Q_PATH, &name_value(&too_long)),
        tlv_of(Q_BYTES, b"x"),
    ]
    .concat();
    assert!(matches!(
        QueryAsk::open_inner(Bytes::from(f)),
        Err(WireError::TooLarge { .. })
    ));
    let f = [
        tlv_of(Q_PATH, &name_value(&n("/a"))),
        tlv_of(Q_BYTES, &[1; QUERY_BYTES_MAX + 1]),
    ]
    .concat();
    assert!(matches!(
        QueryAsk::open_inner(Bytes::from(f)),
        Err(WireError::TooLarge { .. })
    ));
    // Missing and doubled.
    assert!(matches!(
        QueryAsk::open_inner(Bytes::from(tlv_of(Q_BYTES, b"x"))),
        Err(WireError::Missing(_))
    ));
    assert!(matches!(
        QueryAsk::open_inner(Bytes::from(tlv_of(Q_PATH, &name_value(&n("/a"))))),
        Err(WireError::Missing(_))
    ));
    let f = [
        tlv_of(Q_PATH, &name_value(&n("/a"))),
        tlv_of(Q_PATH, &name_value(&n("/a"))),
        tlv_of(Q_BYTES, b"x"),
    ]
    .concat();
    assert!(matches!(
        QueryAsk::open_inner(Bytes::from(f)),
        Err(WireError::Duplicate(_))
    ));
}
