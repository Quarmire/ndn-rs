//! The compact introduction (SHAPES-R10 §5): names as wire relative to the
//! namespace, never as text; old text links still read.

use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_tlv::{TlvReader, TlvWriter};

use crate::{
    ANCHOR_FINGERPRINT_LEN, EnvelopeError, Introduction, T_ENVELOPE, T_NAMESPACE, T_OFFER,
    T_RELAY_HINT, TrustEnvelope, TrustKind,
};

/// A fingerprint whose 32 octets are all escaped in a name's text, as an
/// ndf-rs self-certifying component is (96 characters).
fn fp32() -> [u8; 32] {
    core::array::from_fn(|i| 0x80 + i as u8)
}

fn escaped(fp: &[u8; 32]) -> String {
    fp.iter().map(|b| format!("%{b:02X}")).collect()
}

/// A link hint's octets as data-layer.md §19.2 writes them: the key and each
/// candidate (kind, address, port).
fn hint(candidates: &[(u8, &[u8], u16)]) -> Bytes {
    let mut w = TlvWriter::new();
    w.write_tlv(0x05B0, &[0x42; 32]);
    for (kind, ip, port) in candidates {
        let mut v = vec![*kind];
        v.extend_from_slice(ip);
        v.extend_from_slice(&port.to_be_bytes());
        w.write_tlv(0x05B2, &v);
    }
    w.finish()
}

const V4: [(u8, &[u8], u16); 3] = [
    (0, &[192, 0, 2, 7], 4433),
    (1, &[203, 0, 113, 9], 51000),
    (0, &[198, 51, 100, 4], 4433),
];

const V6: [(u8, &[u8], u16); 3] = [
    (
        0,
        &[0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7],
        4433,
    ),
    (
        0,
        &[0x20, 1, 0xd, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8],
        4433,
    ),
    (
        1,
        &[0x20, 1, 0xd, 0xb8, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9],
        51000,
    ),
];

/// A named namespace, a folder of it, two relays.
fn named(relays: usize) -> Introduction {
    Introduction {
        namespace: Some("/home/alice".into()),
        fingerprint: [0xA5; ANCHOR_FINGERPRINT_LEN],
        offer: "/home/alice/laptop/keyword=log/home/alice/keyword=data/notes/seq=12".into(),
        secret: [0x3C; 16],
        link_hint: None,
        relays: (0..relays)
            .map(|i| format!("/community/node/relay-{i:04}"))
            .collect(),
    }
}

/// A self-certifying namespace: `/user/161=<32 octets>`; the device and the
/// folder both start with it.
fn certifying(candidates: &[(u8, &[u8], u16)], relays: usize) -> Introduction {
    let ns = format!("/user/161={}", escaped(&fp32()));
    Introduction {
        namespace: Some(ns.clone()),
        fingerprint: fp32(),
        offer: format!("{ns}/member/laptop/keyword=log{ns}/keyword=data/notes/seq=3"),
        secret: [0x3C; 16],
        link_hint: (!candidates.is_empty()).then(|| hint(candidates)),
        relays: (0..relays)
            .map(|i| format!("{ns}/node/relay-{}", (b'a' + i as u8) as char))
            .collect(),
    }
}

/// `named(2)` as the pre-change encoder wrote it (`to_uri`): text namespace,
/// offer and relays.
const OLD_NAMED: &str = "ndn-trust://intro/_QRwzv0EcQEB_QRyAQf9BHPA_QSJCy9ob21lL2FsaWNl_QSOIKWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWl_QR1OS9ob21lL2FsaWNlL2xhcHRvcC8zMj1sb2cvaG9tZS9hbGljZS8zMj1kYXRhL25vdGVzL3NlcT0xMv0EdxA8PDw8PDw8PDw8PDw8PDw8_QR2Gi9jb21tdW5pdHkvbm9kZS9yZWxheS0wMDAw_QR2Gi9jb21tdW5pdHkvbm9kZS9yZWxheS0wMDAx";

/// `certifying(V4 + V6 mixed, 2)` (a hint of two IPv4 and one IPv6
/// candidate: see [`old_certifying`]) as the pre-change encoder wrote it.
const OLD_CERTIFYING: &str = "ndn-trust://intro/_QRw_QME_QRxAQH9BHIBB_0Ec_0C9P0EiWovdXNlci8xNjE9JTgwJTgxJTgyJTgzJTg0JTg1JTg2JTg3JTg4JTg5JThBJThCJThDJThEJThFJThGJTkwJTkxJTkyJTkzJTk0JTk1JTk2JTk3JTk4JTk5JTlBJTlCJTlDJTlEJTlFJTlG_QSOIICBgoOEhYaHiImKi4yNjo-QkZKTlJWWl5iZmpucnZ6f_QR1_QD9L3VzZXIvMTYxPSU4MCU4MSU4MiU4MyU4NCU4NSU4NiU4NyU4OCU4OSU4QSU4QiU4QyU4RCU4RSU4RiU5MCU5MSU5MiU5MyU5NCU5NSU5NiU5NyU5OCU5OSU5QSU5QiU5QyU5RCU5RSU5Ri9tZW1iZXIvbGFwdG9wLzMyPWxvZy91c2VyLzE2MT0lODAlODElODIlODMlODQlODUlODYlODclODglODklOEElOEIlOEMlOEQlOEUlOEYlOTAlOTElOTIlOTMlOTQlOTUlOTYlOTclOTglOTklOUElOUIlOUMlOUQlOUUlOUYvMzI9ZGF0YS9ub3Rlcy9zZXE9M_0EdxA8PDw8PDw8PDw8PDw8PDw8_QR4Uf0FsCBCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQv0FsgcAwAACBxFR_QWyBwHLAHEJxzj9BbITACABDbgAAAAAAAAAAAAAAAcRUf0EdncvdXNlci8xNjE9JTgwJTgxJTgyJTgzJTg0JTg1JTg2JTg3JTg4JTg5JThBJThCJThDJThEJThFJThGJTkwJTkxJTkyJTkzJTk0JTk1JTk2JTk3JTk4JTk5JTlBJTlCJTlDJTlEJTlFJTlGL25vZGUvcmVsYXktYf0EdncvdXNlci8xNjE9JTgwJTgxJTgyJTgzJTg0JTg1JTg2JTg3JTg4JTg5JThBJThCJThDJThEJThFJThGJTkwJTkxJTkyJTkzJTk0JTk1JTk2JTk3JTk4JTk5JTlBJTlCJTlDJTlEJTlFJTlGL25vZGUvcmVsYXktYg";

/// The introduction `OLD_CERTIFYING` encodes: two IPv4 candidates and an IPv6
/// one.
fn old_certifying() -> Introduction {
    certifying(&[V4[0], V4[1], V6[0]], 2)
}

/// `i` as the strings an old link carried: the data layer's own keyword
/// component written `32=log`, where `Name`'s text is `keyword=log`. An old
/// link reads back as written; only the compact form writes canonical text.
fn legacy(i: Introduction) -> Introduction {
    Introduction {
        offer: i.offer.replace("keyword=", "32="),
        ..i
    }
}

fn intro_body(envelope: &TrustEnvelope) -> Bytes {
    let mut r = TlvReader::new(envelope.encode());
    let (typ, value) = r.read_tlv().unwrap();
    assert_eq!(typ, T_ENVELOPE);
    let mut parts = TlvReader::new(value);
    while !parts.is_empty() {
        let (t, v) = parts.read_tlv().unwrap();
        if t == crate::T_BODY {
            return v;
        }
    }
    panic!("an envelope has a body");
}

fn types_of(body: Bytes) -> Vec<u64> {
    let mut r = TlvReader::new(body);
    let mut types = Vec::new();
    while !r.is_empty() {
        types.push(r.read_tlv().unwrap().0);
    }
    types
}

/// Links the pre-change encoder wrote — text namespace, offer and relays —
/// still decode, to the strings they carried.
#[test]
fn old_text_links_still_decode() {
    for (link, want) in [
        (OLD_NAMED, legacy(named(2))),
        (OLD_CERTIFYING, legacy(old_certifying())),
    ] {
        assert_eq!(
            TrustEnvelope::from_uri(link).unwrap(),
            TrustEnvelope::Intro(want)
        );
    }
}

/// The one encoder writes names as wire, never as text: no namespace, offer
/// or relay text tag, no name in the bytes as text.
#[test]
fn the_encoder_writes_no_name_as_text() {
    for intro in [named(2), old_certifying()] {
        let envelope = TrustEnvelope::Intro(intro);
        let types = types_of(intro_body(&envelope));
        for text_tag in [T_NAMESPACE, T_OFFER, T_RELAY_HINT] {
            assert!(!types.contains(&text_tag), "{types:x?}");
        }
        for wire_tag in [0x0490, 0x0492, 0x0494] {
            assert!(types.contains(&wire_tag), "{types:x?}");
        }
        // Components are octets, not their URI text: no separator, no keyword
        // number, no escape.
        let wire = envelope.encode();
        for text in [
            &b"/home"[..],
            b"/user",
            b"/community",
            b"161=",
            b"%80",
            b"keyword=",
        ] {
            assert!(
                !wire.windows(text.len()).any(|w| w == text),
                "{:?} is in the bytes as text",
                String::from_utf8_lossy(text)
            );
        }
    }
}

/// What the compact form reads back as is exactly what was given, for every
/// shape: named and self-certifying, with and without hint and relays.
#[test]
fn the_compact_form_round_trips() {
    let mut shapes = vec![
        named(0),
        named(2),
        certifying(&[], 0),
        certifying(&V4, 0),
        certifying(&V6, 0),
        certifying(&V6, 2),
        old_certifying(),
        Introduction {
            namespace: None,
            ..named(1)
        },
        Introduction {
            link_hint: Some(Bytes::from_static(&[0x01, 0x02, 0xFF])),
            ..named(0)
        },
    ];
    // The root namespace and an offer that shares none of it.
    shapes.push(Introduction {
        namespace: Some("/".into()),
        ..named(1)
    });
    shapes.push(Introduction {
        offer: "/elsewhere/laptop/keyword=log/elsewhere/keyword=data/f/seq=1".into(),
        ..named(1)
    });
    for intro in shapes {
        let envelope = TrustEnvelope::Intro(intro);
        let bytes = envelope.encode();
        assert_eq!(TrustEnvelope::decode(&bytes).unwrap(), envelope);
        assert_eq!(
            TrustEnvelope::from_uri(&envelope.to_uri()).unwrap(),
            envelope
        );
    }
}

/// How long the links are, in characters: printed for the record and bound
/// to under half of what text names took.
#[test]
fn compact_links_are_under_half_of_the_text_ones() {
    let size = |i: Introduction| TrustEnvelope::Intro(i).to_uri().len();
    println!("shape                                   compact");
    for (shape, intro) in [
        ("named, no hint, no relays", named(0)),
        ("named, no hint, 2 relays", named(2)),
        ("self-certifying, no hint, no relays", certifying(&[], 0)),
        ("self-certifying, 3 IPv4, no relays", certifying(&V4, 0)),
        ("self-certifying, 3 IPv6, no relays", certifying(&V6, 0)),
        ("self-certifying, 3 IPv6, 2 relays", certifying(&V6, 2)),
        (
            "self-certifying, 2 IPv4 + 1 IPv6, 2 relays",
            old_certifying(),
        ),
    ] {
        println!("{shape:<44}{:>5}", size(intro));
    }
    assert!(size(named(2)) < OLD_NAMED.len(), "{}", size(named(2)));
    assert!(
        size(old_certifying()) * 2 <= OLD_CERTIFYING.len(),
        "{} against {}",
        size(old_certifying()),
        OLD_CERTIFYING.len()
    );
    // Each name of a self-certifying namespace is written once in the offer
    // and its relays: a relay shares the namespace, so it costs its tail.
    assert!(size(certifying(&V6, 2)) < size(certifying(&V6, 0)) + 2 * 40);
}

/// A relative name that cannot be: more shared components than the namespace
/// has, a name with nothing, bad components, a second form of one field.
#[test]
fn malformed_compact_names_are_refused() {
    let ns: Name = "/home/alice".parse().unwrap();
    let write = |fields: &dyn Fn(&mut TlvWriter)| {
        let mut w = TlvWriter::new();
        w.write_tlv(crate::T_ANCHOR_FINGERPRINT, &[0xA5; 32]);
        w.write_tlv(crate::T_SECRET, &[1; 16]);
        fields(&mut w);
        TrustEnvelope::decode_body(TrustKind::Intro, w.finish())
    };
    let namespace = |w: &mut TlvWriter| {
        w.write_nested(0x0490, |w| {
            for c in ns.components() {
                w.write_tlv(c.typ, &c.value);
            }
        });
    };
    let relative = |w: &mut TlvWriter, tag: u64, shared: u8, tail: &[u8]| {
        w.write_nested(tag, |w| {
            w.write_raw(&[shared]);
            w.write_raw(tail);
        });
    };
    // 8 = generic component "x".
    let tail = [0x08, 0x01, b'x'];
    let got = write(&|w| {
        namespace(w);
        relative(w, 0x0492, 0, &tail);
    })
    .unwrap();
    assert!(
        matches!(&got, TrustEnvelope::Intro(i) if i.offer == "/x" && i.namespace.as_deref() == Some("/home/alice"))
    );
    let got = write(&|w| {
        namespace(w);
        relative(w, 0x0492, 2, &tail);
    })
    .unwrap();
    assert!(matches!(&got, TrustEnvelope::Intro(i) if i.offer == "/home/alice/x"));
    for shared in [3u8, 255] {
        assert_eq!(
            write(&|w| {
                namespace(w);
                relative(w, 0x0492, shared, &tail);
            }),
            Err(EnvelopeError::Malformed(
                "relative name shares more than its namespace"
            ))
        );
    }
    // No namespace: nothing to share.
    assert_eq!(
        write(&|w| relative(w, 0x0492, 1, &tail)),
        Err(EnvelopeError::Malformed(
            "relative name shares more than its namespace"
        ))
    );
    // An empty value has no shared count; a bad component is not a name.
    assert!(write(&|w| w.write_tlv(0x0492, &[])).is_err());
    assert!(write(&|w| relative(w, 0x0494, 0, &[0x08, 0x05, b'x'])).is_err());
    // Both forms of one field: a repeated field.
    assert_eq!(
        write(&|w| {
            relative(w, 0x0492, 0, &tail);
            w.write_tlv(T_OFFER, b"/x");
        }),
        Err(EnvelopeError::Malformed("repeated field"))
    );
    // Relays in either form, mixed.
    let got = write(&|w| {
        relative(w, 0x0492, 0, &tail);
        relative(w, 0x0494, 0, &tail);
        w.write_tlv(T_RELAY_HINT, b"/y");
    })
    .unwrap();
    assert!(matches!(&got, TrustEnvelope::Intro(i) if i.relays == ["/x", "/y"]));
}

/// A name that is not a URI in its canonical text cannot be carried: `check`
/// says which, and an introduction that passes round-trips.
#[test]
fn names_that_are_not_canonical_uris_fail_the_check() {
    assert_eq!(named(2).check(), Ok(()));
    assert_eq!(certifying(&V6, 2).check(), Ok(()));
    for (intro, what) in [
        (
            Introduction {
                namespace: Some("home/alice".into()),
                ..named(0)
            },
            "introduction namespace is not a canonical NDN URI",
        ),
        (
            Introduction {
                offer: "/a%ZZ".into(),
                ..named(0)
            },
            "introduction offer is not a canonical NDN URI",
        ),
        (
            Introduction {
                relays: vec!["/ok".into(), "relay".into()],
                ..named(0)
            },
            "introduction relay is not a canonical NDN URI",
        ),
        (
            Introduction {
                offer: "/a//b".into(),
                ..named(0)
            },
            "introduction offer is not a canonical NDN URI",
        ),
    ] {
        assert_eq!(
            intro.check(),
            Err(EnvelopeError::Malformed(what)),
            "{intro:?}"
        );
    }
}
