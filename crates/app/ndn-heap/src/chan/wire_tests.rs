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
        new: false,
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
        serves: Vec::new(),
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
    w.write_nested(CHAN_ASK, |w| write_nni(w, ASK_MODE, 5));
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

/// The `Ask` mode is code 4 in an ask and in a session (golden octets: the mode field is
/// `fd0667 01 04`), and an announce lists none: decoding one is refused, with the reason.
#[test]
fn the_ask_mode_is_code_4_in_an_ask_and_a_session_and_no_announce_lists_it() {
    assert_eq!(ChannelMode::Ask.code(), 4);
    assert_eq!(ChannelMode::ALL.len(), 4);
    assert!(!ChannelMode::Ask.needs_stream());
    let ask = ChanAsk {
        mode: ChannelMode::Ask,
        ..ask()
    };
    let wire = ask.encode().unwrap();
    assert!(
        hex(&wire).contains("fd06670104"),
        "ASK_MODE 4: {}",
        hex(&wire)
    );
    assert_eq!(ChanAsk::decode(wire).unwrap(), ask);
    let session = SessionRecord {
        mode: ChannelMode::Ask,
        ckpt_ms: 0,
        ..session()
    };
    let wire = session.encode().unwrap();
    assert!(
        hex(&wire).contains("fd067b0104"),
        "the session names mode 4: {}",
        hex(&wire)
    );
    let Answer::Session(back) = Answer::decode(wire).unwrap() else {
        panic!("a session");
    };
    assert_eq!(back.mode, ChannelMode::Ask);
    assert_eq!(back.ckpt_ms, 0);

    let mut w = TlvWriter::new();
    w.write_nested(CHAN_ANNOUNCE, |w| {
        write_name_as(w, S_SENDER, &n("/bob/phone"));
        write_nni(w, ASK_MODE, 1);
        write_nni(w, ASK_MODE, 4);
    });
    let why = Announce::decode(w.finish()).unwrap_err();
    assert!(
        why.to_string().contains("no Ask mode"),
        "an announce that lists Ask says so: {why}"
    );
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

#[test]
fn an_ask_that_holds_no_session_says_so_in_one_empty_even_field() {
    // The golden ask names none: it is the ask of a receiver that holds its session (a renewal).
    assert!(!ChanAsk::decode(unhex(GOLDEN_ASK)).unwrap().new);
    let mut said = ask();
    said.new = true;
    let wire = said.encode().unwrap();
    assert_eq!(ChanAsk::decode(wire.clone()).unwrap(), said);
    // Even, so a reader that predates it skips it and reads a renewal.
    assert_eq!(ASK_NEW % 2, 0);
    // It has no value.
    let valued = with_extra(&ask().encode().unwrap(), &[(ASK_NEW, &[1])]);
    assert!(matches!(
        ChanAsk::decode(valued),
        Err(WireError::Malformed(_))
    ));
    // Twice is ambiguous, as any field.
    let twice = with_extra(&wire, &[(ASK_NEW, &[])]);
    assert!(matches!(
        ChanAsk::decode(twice),
        Err(WireError::Duplicate(_))
    ));
}

/// The octets of a name's components: the value of a `Name` TLV or of an `ANN_SERVES`.
fn name_value(name: &Name) -> Vec<u8> {
    let mut w = TlvWriter::new();
    for c in name.components() {
        w.write_tlv(c.typ, &c.value);
    }
    w.finish().to_vec()
}

/// An announce of `/bob/phone` with these modes, plus raw `ANN_SERVES` values.
fn announce_with_serves(modes: &[ChannelMode], serves: &[Vec<u8>]) -> Bytes {
    let base = Announce {
        sender: n("/bob/phone"),
        modes: modes.to_vec(),
        serves: Vec::new(),
    }
    .encode();
    let extra: Vec<(u64, &[u8])> = serves.iter().map(|s| (ANN_SERVES, s.as_slice())).collect();
    with_extra(&base, &extra)
}

const GOLDEN_ANNOUNCE_SERVES: &str =
    "fd06a120fd06770c0803626f62080570686f6e65fd06670101fd06ac070805776f726c64";
const GOLDEN_ANNOUNCE_SERVES_ONLY: &str =
    "fd06a11bfd06770c0803626f62080570686f6e65fd06ac070805776f726c64";

#[test]
fn an_announce_carries_the_prefixes_it_serves_and_may_hold_no_channel() {
    let with = Announce {
        modes: vec![ChannelMode::Latest],
        serves: vec![n("/world")],
        ..announce()
    };
    assert_eq!(hex(&with.encode()), GOLDEN_ANNOUNCE_SERVES);
    assert_eq!(
        Announce::decode(unhex(GOLDEN_ANNOUNCE_SERVES)).unwrap(),
        with
    );
    // A device that serves and holds no channel.
    let only = Announce {
        modes: Vec::new(),
        serves: vec![n("/world")],
        ..announce()
    };
    assert_eq!(hex(&only.encode()), GOLDEN_ANNOUNCE_SERVES_ONLY);
    assert_eq!(
        Announce::decode(unhex(GOLDEN_ANNOUNCE_SERVES_ONLY)).unwrap(),
        only
    );
    // Without serves it is the old format, byte for byte, and an old reader's announce decodes.
    assert_eq!(announce().encode(), unhex(GOLDEN_ANNOUNCE));
    assert!(
        Announce::decode(unhex(GOLDEN_ANNOUNCE))
            .unwrap()
            .serves
            .is_empty()
    );
    // Several names keep their order; even, so a reader that predates it skips it.
    let several = Announce {
        serves: vec![n("/a"), n("/b/c"), Name::root()],
        ..announce()
    };
    assert_eq!(Announce::decode(several.encode()).unwrap(), several);
    assert_eq!(ANN_SERVES % 2, 0);
}

#[test]
fn an_announce_names_at_most_16_prefixes_and_512_octets_and_something_to_do() {
    let short = name_value(&n("/a"));
    let ok = announce_with_serves(&[ChannelMode::Latest], &vec![short.clone(); 16]);
    assert_eq!(Announce::decode(ok).unwrap().serves.len(), 16);
    let seventeen = announce_with_serves(&[ChannelMode::Latest], &vec![short; 17]);
    assert!(
        matches!(
            Announce::decode(seventeen),
            Err(WireError::TooMany { max: 16, .. })
        ),
        "17 names"
    );

    // Four names of 128 octets are exactly 512; four of 129 are over it.
    let sized = |component: usize| name_value(&Name::root().append(vec![b'x'; component]));
    assert_eq!(sized(126).len(), 128);
    let at = announce_with_serves(&[ChannelMode::Latest], &vec![sized(126); 4]);
    assert_eq!(Announce::decode(at).unwrap().serves.len(), 4);
    let over = announce_with_serves(&[ChannelMode::Latest], &vec![sized(127); 4]);
    assert!(
        matches!(
            Announce::decode(over),
            Err(WireError::TooLarge {
                max: SERVES_OCTETS_MAX,
                ..
            })
        ),
        "over 512 octets of names"
    );

    // Neither a mode nor a prefix: nothing the announce says, so it is refused.
    let neither = Announce {
        modes: Vec::new(),
        serves: Vec::new(),
        ..announce()
    };
    assert!(matches!(
        Announce::decode(neither.encode()),
        Err(WireError::Missing(_))
    ));
    // A serves that is no name.
    let bad = announce_with_serves(&[ChannelMode::Latest], &[vec![0x08, 0x05, b'a']]);
    assert!(matches!(
        Announce::decode(bad),
        Err(WireError::Malformed(_))
    ));
    // An unknown even type beside serves is skipped; an odd one is refused.
    let wire = Announce {
        serves: vec![n("/world")],
        ..announce()
    }
    .encode();
    assert!(Announce::decode(with_extra(&wire, &[(0x06BE, b"x")])).is_ok());
    assert_eq!(
        Announce::decode(with_extra(&wire, &[(0x06BF, b"x")])),
        Err(WireError::UnknownCritical(0x06BF))
    );
}
