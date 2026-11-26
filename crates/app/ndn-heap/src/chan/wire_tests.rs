//! The records of the channel setup: golden vectors (the same octets are in
//! `docs/specs/channel.md`), the critical/skippable rule and the size limits.

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
        creator: n("/alice/laptop"),
        seq: 3,
    }
}

fn ask() -> ChanAsk {
    ChanAsk {
        space: n("/alice/32=data/notes"),
        prefix: n("/cursors"),
        mode: ChannelMode::Latest,
        recipient: [0x11; 32],
        carriers: vec![carrier::DATAGRAM, carrier::STREAM],
        lifetime: 3600,
        epoch: Some(epoch()),
        since: Some(9),
        chain: vec![Bytes::from_static(&[0xC0, 0xDE, 0x01])],
    }
}

fn session() -> SessionRecord {
    SessionRecord {
        id: 0x0102_0304_0506_0708,
        sender: n("/bob/phone"),
        space: n("/alice/32=data/notes"),
        mode: ChannelMode::Window,
        key_epoch: 2,
        key_id: [0xAA; 8],
        wrap: Bytes::from(vec![0xBB; 40]),
        aead: Aead::Aes256Gcm,
        carriers: vec![
            CarrierOffer {
                kind: carrier::DATAGRAM,
                params: Bytes::new(),
            },
            CarrierOffer {
                kind: carrier::STREAM,
                params: Bytes::new(),
            },
        ],
        table: vec![Bind {
            id: 1,
            name: n("/cursor/x"),
        }],
        ckpt_ms: 20,
        window: Some(Window {
            messages: 256,
            bytes: 1_048_576,
            ms: 10_000,
        }),
        lifetime: 3600,
        audience_epoch: Some(epoch()),
        frame_max: 1200,
        seq: 7,
        certs: vec![Bytes::from_static(&[0xC0, 0xDE, 0x02])],
    }
}

fn refusal() -> RefusalRecord {
    RefusalRecord {
        code: RefusalCode::NotAudience,
        text: "ask the owner to add you as a reader".into(),
        retry_ms: 0,
    }
}

fn announce() -> Announce {
    Announce {
        sender: n("/bob/phone"),
        modes: vec![ChannelMode::Latest, ChannelMode::Window],
    }
}

const GOLDEN_ASK: &str = "fd066180fd0663140805616c69636520046461746108056e6f746573fd0665090807637572736f7273fd06670101fd0669201111111111111111111111111111111111111111111111111111111111111111fd066b020102fd066d020e10fd066f16070f0805616c69636508066c6170746f70fd060b0103fd06710109fd063d03c0de01";
const GOLDEN_SESSION: &str = "fd0673f0fd0675080102030405060708fd06770c0803626f62080570686f6e65fd0679140805616c69636520046461746108056e6f746573fd067b0103fd067d0102fd067f08aaaaaaaaaaaaaaaafd068128bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbfd06830101fd06850101fd06850102fd068718fd068914fd06a30101fd06a50b0806637572736f72080178fd068b0114fd068d14fd06a7020100fd06a90400100000fd06ab022710fd068f020e10fd069116070f0805616c69636508066c6170746f70fd060b0103fd06930204b0fd06950107fd069703c0de02";
const GOLDEN_REFUSAL: &str = "fd069932fd069b0101fd069d2461736b20746865206f776e657220746f2061646420796f75206173206120726561646572fd069f0100";
const GOLDEN_ANNOUNCE: &str = "fd06a11afd06770c0803626f62080570686f6e65fd06670101fd06670103";

/// A record `typ` whose value is `value`, then `extra` TLVs inside it.
fn with_extra(wire: &Bytes, extra: &[(u64, &[u8])]) -> Bytes {
    let mut r = ndn_tlv::TlvReader::new(wire.clone());
    let (typ, value) = r.read_tlv().unwrap();
    let mut w = TlvWriter::new();
    w.write_nested(typ, |w| {
        w.write_raw(&value);
        for (t, v) in extra {
            w.write_tlv(*t, v);
        }
    });
    w.finish()
}

#[test]
fn the_golden_vectors_are_the_octets_of_each_record_and_decode_back() {
    let wire = ask().encode().unwrap();
    assert_eq!(hex(&wire), GOLDEN_ASK, "CHAN_ASK");
    assert_eq!(ChanAsk::decode(unhex(GOLDEN_ASK)).unwrap(), ask());

    let wire = session().encode().unwrap();
    assert_eq!(hex(&wire), GOLDEN_SESSION, "CHAN_SESSION");
    assert_eq!(
        SessionRecord::decode(unhex(GOLDEN_SESSION)).unwrap(),
        session()
    );

    let wire = refusal().encode();
    assert_eq!(hex(&wire), GOLDEN_REFUSAL, "CHAN_REFUSAL");
    assert_eq!(
        RefusalRecord::decode(unhex(GOLDEN_REFUSAL)).unwrap(),
        refusal()
    );

    let wire = announce().encode();
    assert_eq!(hex(&wire), GOLDEN_ANNOUNCE, "CHAN_ANNOUNCE");
    assert_eq!(
        Announce::decode(unhex(GOLDEN_ANNOUNCE)).unwrap(),
        announce()
    );

    // An answer is told by the type of its one TLV.
    assert_eq!(
        Answer::decode(unhex(GOLDEN_SESSION)).unwrap(),
        Answer::Session(Box::new(session()))
    );
    assert_eq!(
        Answer::decode(unhex(GOLDEN_REFUSAL)).unwrap(),
        Answer::Refusal(refusal())
    );
    assert!(
        Answer::decode(unhex(GOLDEN_ASK)).is_err(),
        "an ask is no answer"
    );
}

#[test]
#[allow(clippy::type_complexity)]
fn an_unknown_even_type_is_skipped_and_an_unknown_odd_one_is_refused_in_every_record() {
    let cases: [(&str, Bytes, fn(Bytes) -> Result<(), WireError>); 4] = [
        ("ask", ask().encode().unwrap(), |b| {
            ChanAsk::decode(b).map(drop)
        }),
        ("session", session().encode().unwrap(), |b| {
            SessionRecord::decode(b).map(drop)
        }),
        ("refusal", refusal().encode(), |b| {
            RefusalRecord::decode(b).map(drop)
        }),
        ("announce", announce().encode(), |b| {
            Announce::decode(b).map(drop)
        }),
    ];
    for (what, wire, decode) in cases {
        // 0x06BE is even (skippable), 0x06BF odd (critical): both in the block, neither assigned.
        let skippable = with_extra(&wire, &[(0x06BE, b"future")]);
        assert_eq!(
            decode(skippable),
            Ok(()),
            "{what}: an unknown even type is skipped"
        );
        let critical = with_extra(&wire, &[(0x06BF, b"future")]);
        assert_eq!(
            decode(critical),
            Err(WireError::UnknownCritical(0x06BF)),
            "{what}: an unknown odd type is a malformed record"
        );
    }
}

#[test]
fn the_limits_hold_an_ask_of_8_kib_a_session_of_8000_octets_and_four_certificates() {
    let mut big = ask();
    big.prefix = n("/x").append(vec![b'p'; 8 * 1024]);
    assert!(
        matches!(big.encode(), Err(WireError::TooLarge { max: ASK_MAX, .. })),
        "an ask over 8 KiB is not written"
    );
    let over = Bytes::from(vec![0u8; ASK_MAX + 1]);
    assert!(matches!(
        ChanAsk::decode(over),
        Err(WireError::TooLarge { .. })
    ));

    let mut many = ask();
    many.chain = vec![Bytes::from_static(&[1]); 5];
    assert!(
        matches!(many.encode(), Err(WireError::TooLarge { .. })),
        "five certificates"
    );
    let mut fat = ask();
    fat.chain = vec![Bytes::from(vec![1; 4097])];
    assert!(
        matches!(fat.encode(), Err(WireError::TooLarge { .. })),
        "a certificate over 4,096"
    );
    let mut total = ask();
    total.chain = vec![Bytes::from(vec![1; 3500]), Bytes::from(vec![2; 3500])];
    assert!(
        matches!(total.encode(), Err(WireError::TooLarge { .. })),
        "over 6,144 in all"
    );

    let mut s = session();
    s.certs = vec![Bytes::from(vec![9; 4096]), Bytes::from(vec![9; 2048])];
    s.sender = n("/bob").append(vec![b'd'; 2000]);
    assert!(
        matches!(
            s.encode(),
            Err(WireError::TooLarge {
                max: SESSION_MAX,
                ..
            })
        ),
        "a session over 8,000 octets is not written"
    );
    let mut table = session();
    table.table = (0..65).map(|id| Bind { id, name: n("/a") }).collect();
    assert!(matches!(
        table.encode(),
        Err(WireError::TooMany { max: 64, .. })
    ));
}

#[test]
fn a_refusal_text_is_cut_to_256_octets_and_a_longer_one_is_refused() {
    let mut r = refusal();
    r.text = "é".repeat(200);
    let wire = r.encode();
    let back = RefusalRecord::decode(wire).unwrap();
    assert!(back.text.len() <= TEXT_MAX && back.text.chars().all(|c| c == 'é'));
    assert_eq!(
        back.text.len(),
        256,
        "cut at a character boundary, 256 octets of 2-octet letters"
    );

    let mut w = TlvWriter::new();
    w.write_nested(CHAN_REFUSAL, |w| {
        write_nni(w, R_CODE, 1);
        w.write_tlv(R_TEXT, &[b'a'; 257]);
        write_nni(w, R_RETRY, 0);
    });
    assert!(matches!(
        RefusalRecord::decode(w.finish()),
        Err(WireError::TooLarge { max: TEXT_MAX, .. })
    ));
}

#[test]
fn a_record_missing_a_field_or_naming_an_unknown_code_is_refused() {
    let mut w = TlvWriter::new();
    w.write_nested(CHAN_REFUSAL, |w| write_nni(w, R_CODE, 7));
    assert!(matches!(
        RefusalRecord::decode(w.finish()),
        Err(WireError::Malformed(_))
    ));
    let mut w = TlvWriter::new();
    w.write_nested(CHAN_ASK, |w| write_nni(w, ASK_MODE, 4));
    assert!(matches!(
        ChanAsk::decode(w.finish()),
        Err(WireError::Malformed(_))
    ));
    let mut w = TlvWriter::new();
    w.write_nested(CHAN_ASK, |w| write_nni(w, ASK_MODE, 1));
    assert!(matches!(
        ChanAsk::decode(w.finish()),
        Err(WireError::Missing(_))
    ));
    // The same field twice is ambiguous.
    let twice = with_extra(&ask().encode().unwrap(), &[(ASK_LIFETIME, &[1])]);
    assert!(matches!(
        ChanAsk::decode(twice),
        Err(WireError::Duplicate(_))
    ));
}

/// A session's lifetime is what a receiver counts on its clock: a hostile writer's `2^63` must not
/// reach the arithmetic of the session store. The sender gives its asker's lifetime clamped to
/// a minute and a day, so the receiver refuses what the sender would never write.
#[test]
fn a_session_with_a_lifetime_over_a_day_is_refused() {
    let with = |lifetime: u64| {
        SessionRecord {
            lifetime,
            ..session()
        }
        .encode()
        .unwrap()
    };
    for ok in [LIFETIME_MIN, 3600, LIFETIME_MAX] {
        assert_eq!(SessionRecord::decode(with(ok)).unwrap().lifetime, ok);
    }
    for refused in [
        LIFETIME_MAX + 1,
        1 << 40,
        1 << 63,
        u64::MAX,
        LIFETIME_MIN - 1,
        0,
    ] {
        assert!(
            matches!(
                SessionRecord::decode(with(refused)),
                Err(WireError::Malformed(_))
            ),
            "a lifetime of {refused} s is refused"
        );
    }
}
