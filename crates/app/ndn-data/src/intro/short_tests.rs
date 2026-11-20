//! The short code's text, its refusals and the hint record's bytes and names
//! (SHAPES-R10 cases 3 and 5's wire half).

use std::net::SocketAddr;

use bytes::Bytes;
use ndn_foundation_types::{Name, NameComponent};
use ndn_packet::tlv_type::SELF_CERTIFYING;

use crate::intro::{
    Contact, HintCandidate, HintKind, HintRecord, IntroRefusal, SHORT_FINGERPRINT_LEN, ShortCode,
    ShortError, hint_name, hint_prefix, hint_token, introduction_prefixes, keyed_fingerprint,
    keyed_fingerprint_matches, parse_hint_name,
};
use crate::version::Timestamp;

fn n(s: &str) -> Name {
    s.parse().expect("a valid name")
}

fn secret() -> [u8; 16] {
    core::array::from_fn(|i| (i * 17 + 3) as u8)
}

fn whole() -> [u8; 32] {
    core::array::from_fn(|i| (i * 7 + 1) as u8)
}

/// `/user/<self-certifying component of fp>/<rest>`.
fn sc(fp: &[u8; 32], rest: &str) -> Name {
    let mut comps = n("/user").components().to_vec();
    comps.push(NameComponent::new(
        SELF_CERTIFYING,
        Bytes::copy_from_slice(fp),
    ));
    comps.extend(n(rest).components().iter().cloned());
    Name::from_components(comps)
}

fn code(device: Name, contact: Option<Contact>, fingerprint: &[u8]) -> ShortCode {
    ShortCode {
        device,
        contact,
        secret: secret(),
        fingerprint: fingerprint.to_vec(),
    }
}

fn v4() -> Contact {
    Contact::Address("192.0.2.7:4433".parse().unwrap())
}

fn worst_v6() -> Contact {
    Contact::Address(
        "[2001:db8:1234:5678:9abc:def0:1234:5678]:65535"
            .parse()
            .unwrap(),
    )
}

fn named() -> ShortCode {
    code(n("/alice/member/laptop"), Some(v4()), &whole()[..10])
}

/// The five shapes of the SHAPES table and their whole-fingerprint twins.
fn shapes() -> Vec<(&'static str, ShortCode)> {
    let fp = whole();
    vec![
        ("IPv4, named", named()),
        (
            "IPv6 worst, named",
            code(n("/alice/member/laptop"), Some(worst_v6()), &fp[..10]),
        ),
        (
            "relay, named",
            code(
                n("/alice/member/laptop"),
                Some(Contact::Relay(n("/alice/node/relay"))),
                &fp[..10],
            ),
        ),
        (
            "IPv4, self-certifying",
            code(sc(&fp, "/member/laptop"), Some(v4()), &fp),
        ),
        (
            "IPv6 worst, self-certifying",
            code(sc(&fp, "/member/laptop"), Some(worst_v6()), &fp),
        ),
        (
            "IPv6 SHAPES row, self-certifying",
            code(
                sc(&fp, "/member/laptop"),
                Some(Contact::Address(
                    "[2001:db8:1:2:3:4:5:6]:4433".parse().unwrap(),
                )),
                &fp,
            ),
        ),
        (
            "relay, self-certifying",
            code(
                sc(&fp, "/member/laptop"),
                Some(Contact::Relay(sc(&fp, "/node/relay"))),
                &fp,
            ),
        ),
        (
            "no contact, named",
            code(n("/alice/member/laptop"), None, &fp[..10]),
        ),
    ]
}

fn words_of(text: &str) -> Vec<&str> {
    text.split_whitespace()
        .filter(|t| !t.starts_with(['/', '[']) && !t.starts_with(|c: char| c.is_ascii_digit()))
        .collect()
}

/// Every shape reads back as it was made, fits the 294 columns of three
/// lines of 98 and is only words and the two text tokens; the lengths are
/// printed for the record.
#[test]
fn short_codes_round_trip_and_fit_three_lines() {
    println!("{:<30} {:>5} {:>5}", "shape", "chars", "words");
    for (name, code) in shapes() {
        let text = code.encode().unwrap();
        let words = words_of(&text);
        println!(
            "{name:<30} {:>5} {:>5}   {text}",
            text.chars().count(),
            words.len()
        );
        // The one shape that does not fit: the longest IPv6 address beside a
        // self-certifying device name. An offer of it makes no short code and
        // says why (`IntroPolicy::short_width`); the full link still works.
        let wide = name == "IPv6 worst, self-certifying";
        assert_eq!(
            text.chars().count() > 294,
            wide,
            "{name}: {} characters",
            text.chars().count()
        );
        assert_eq!(
            words.len(),
            if code.fingerprint.len() == SHORT_FINGERPRINT_LEN {
                20
            } else {
                36
            },
            "{name}"
        );
        assert_eq!(ShortCode::parse(&text, false).unwrap(), code, "{name}");
        // The case of the words, spacing and line breaks do not matter (a
        // device name is case-sensitive: it is not shouted).
        let words = words_of(&text);
        let at = text.find(words[0]).unwrap();
        let shouted = format!(
            "\n {} {}  ",
            text[..at].trim_end().replace(' ', "  \n"),
            words.join("  \n").to_uppercase()
        );
        assert_eq!(ShortCode::parse(&shouted, false).unwrap(), code, "{name}");
    }
}

/// A self-certifying component equal to a 32-octet fingerprint is written
/// `161=*` and read back as the whole component, in the device and in a
/// relay; a named namespace is written out.
#[test]
fn the_whole_fingerprint_is_written_161_star() {
    let fp = whole();
    let both = code(
        sc(&fp, "/member/laptop"),
        Some(Contact::Relay(sc(&fp, "/node/relay"))),
        &fp,
    );
    let text = both.encode().unwrap();
    assert!(
        text.starts_with("/user/161=*/member/laptop /user/161=*/node/relay "),
        "{text}"
    );
    assert!(!text.contains("%"), "{text}");
    let back = ShortCode::parse(&text, false).unwrap();
    assert_eq!(back.device, sc(&fp, "/member/laptop"));
    assert_eq!(back.contact, Some(Contact::Relay(sc(&fp, "/node/relay"))));
    assert_eq!(back.fingerprint, fp);
    // A named device is written as it is.
    assert!(
        named()
            .encode()
            .unwrap()
            .starts_with("/alice/member/laptop 192.0.2.7:4433 ")
    );
    // A component of another key stays written out: it is not the anchor's.
    let other = [0x99; 32];
    let elsewhere = code(sc(&other, "/member/laptop"), Some(v4()), &fp);
    let text = elsewhere.encode().unwrap();
    assert!(!text.contains("161=*"), "{text}");
    assert_eq!(ShortCode::parse(&text, false).unwrap(), elsewhere);
}

/// `161=*` names the whole fingerprint, which 20 words do not carry.
#[test]
fn a_placeholder_needs_36_words() {
    let bound = "/user/161=*/member/laptop 192.0.2.7:4433";
    let mut payload = secret().to_vec();
    payload.extend_from_slice(&whole()[..10]);
    let words = ndn_trust_envelope::words::encode_checked(&payload, bound).unwrap();
    assert_eq!(
        ShortCode::parse(&format!("{bound} {}", &*words), false),
        Err(ShortError::Placeholder)
    );
}

/// What a code of a wrong number of words says: how many it found.
#[test]
fn a_code_of_another_number_of_words_names_the_count() {
    let text = named().encode().unwrap();
    let words = words_of(&text);
    let head = text.split(words[0]).next().unwrap().trim_end();
    for n_words in [0, 1, 19, 21, 24, 35, 37] {
        let cut: Vec<&str> = words.iter().cycle().take(n_words).copied().collect();
        assert_eq!(
            ShortCode::parse(&format!("{head} {}", cut.join(" ")), false),
            Err(ShortError::Words(n_words)),
            "{n_words} words"
        );
    }
    assert_eq!(ShortCode::word_count(&text), 20);
    assert_eq!(ShortCode::word_count(head), 0);
}

/// A word off the list is named by its position among the words, a
/// mistyped one beside it unseen.
#[test]
fn a_word_off_the_list_is_named_by_position() {
    let text = named().encode().unwrap();
    let words = words_of(&text);
    let mut typo: Vec<&str> = words.clone();
    typo[3] = "zzzz";
    typo[8] = "qqqq";
    let head = "/alice/member/laptop 192.0.2.7:4433";
    assert_eq!(
        ShortCode::parse(&format!("{head} {}", typo.join(" ")), false),
        Err(ShortError::UnknownWord(4))
    );
}

/// A typo anywhere before or among the words — a letter of the device, a
/// digit of the port or address, a word replaced, two words swapped — is
/// refused, never read as another code. Single-character edits of the text
/// before the words, every substitution from a small alphabet and every
/// deletion; the 2^-12 chance of an agreeing checksum is why the corpus is
/// fixed and small.
#[test]
fn a_typo_in_the_device_the_address_or_the_words_is_refused() {
    let code = named();
    let text = code.encode().unwrap();
    let head_len = "/alice/member/laptop 192.0.2.7:4433".len();
    let (head, tail) = text.split_at(head_len);
    let mut tried = 0;
    for at in 0..head.len() {
        let mut edits = vec![format!("{}{}", &head[..at], &head[at + 1..])];
        for sub in ['a', 'Z', '0', '9', '/', '.', ':', '-'] {
            if head.as_bytes()[at] as char != sub {
                edits.push(format!("{}{sub}{}", &head[..at], &head[at + 1..]));
            }
        }
        for edit in edits {
            tried += 1;
            let got = ShortCode::parse(&format!("{edit}{tail}"), false);
            assert!(got.is_err(), "{edit:?} read as {got:?}");
        }
    }
    println!("{tried} edits of the device and address, all refused");
    // Two adjacent words swapped.
    let words = words_of(&text);
    for at in 0..words.len() - 1 {
        if words[at] == words[at + 1] {
            continue;
        }
        let mut swapped = words.clone();
        swapped.swap(at, at + 1);
        let got = ShortCode::parse(&format!("{head} {}", swapped.join(" ")), false);
        assert_eq!(got, Err(ShortError::Checksum), "swap at {at}");
    }
}

/// A first contact that is neither an address nor a relay's name, and a
/// device that is not a name, are named by their token.
#[test]
fn a_garbled_contact_or_device_is_named() {
    let text = named().encode().unwrap();
    let words = words_of(&text).join(" ");
    for bad in [
        "999.1.1.1:4433",
        "192.0.2.7",
        "[2001:db8::7]",
        "[::1",
        "7up",
        "/a%ZZ",
    ] {
        assert_eq!(
            ShortCode::parse(&format!("/alice/member/laptop {bad} {words}"), false),
            Err(ShortError::Contact(bad.to_owned())),
            "{bad}"
        );
    }
    for bad in ["alice/member/laptop", "laptop", "/a%ZZ/b"] {
        assert_eq!(
            ShortCode::parse(&format!("{bad} 192.0.2.7:4433 {words}"), false),
            Err(ShortError::Device(bad.to_owned())),
            "{bad}"
        );
    }
    assert_eq!(
        ShortCode::parse("", false),
        Err(ShortError::Words(0)),
        "an empty code"
    );
}

/// A loopback or link-local address is refused from a code unless the
/// policy allows it, after the checksum proves it was meant.
#[test]
fn a_local_contact_is_refused_unless_the_policy_allows() {
    for addr in [
        "127.0.0.1:4433",
        "[::1]:4433",
        "169.254.1.2:4433",
        "[fe80::1]:4433",
    ] {
        let addr: SocketAddr = addr.parse().unwrap();
        let text = code(
            n("/alice/member/laptop"),
            Some(Contact::Address(addr)),
            &whole()[..10],
        )
        .encode()
        .unwrap();
        assert_eq!(ShortCode::parse(&text, false), Err(ShortError::Local(addr)));
        assert_eq!(
            ShortCode::parse(&text, true).unwrap().contact,
            Some(Contact::Address(addr))
        );
        // A typo in it is a checksum error, not "local".
        let typo = text.replacen(&addr.port().to_string(), "4434", 1);
        assert_eq!(ShortCode::parse(&typo, false), Err(ShortError::Checksum));
    }
}

/// Every refusal says what is wrong and what to do.
#[test]
fn refusals_say_what_is_wrong_and_what_to_do() {
    let local: SocketAddr = "127.0.0.1:4433".parse().unwrap();
    for (error, must) in [
        (
            ShortError::Words(19),
            &["19 words", "20 or 36", "24", "copy it again"][..],
        ),
        (
            ShortError::UnknownWord(7),
            &["word 7", "BIP39", "check word 7"],
        ),
        (
            ShortError::Checksum,
            &["does not read", "device name", "address", "check each"],
        ),
        (
            ShortError::Contact("x".into()),
            &[
                "`x`",
                "192.0.2.7:4433",
                "[2001:db8::7]:4433",
                "starting with /",
            ],
        ),
        (ShortError::Placeholder, &["161=*", "36-word"]),
        (
            ShortError::Local(local),
            &["127.0.0.1:4433", "local_candidates", "this machine"],
        ),
        (ShortError::Device("y".into()), &["`y`", "starting with /"]),
    ] {
        let text = error.to_string();
        for part in must {
            assert!(
                text.contains(part),
                "{error:?} says {text:?}, without {part:?}"
            );
        }
    }
}

/// A code matches the anchor it names: the whole fingerprint equal to it, or
/// the tag keyed by the code's secret — never the anchor's plain first
/// octets, which are the same for every code of the namespace.
#[test]
fn a_code_matches_the_anchor_it_names() {
    let fp = whole();
    let keyed = code(
        n("/alice/member/laptop"),
        Some(v4()),
        &keyed_fingerprint(&secret(), &fp),
    );
    assert!(keyed.matches(&fp));
    let mut other = fp;
    other[31] ^= 1;
    assert!(
        !keyed.matches(&other),
        "the tag binds the whole fingerprint, not a prefix of it"
    );
    assert!(
        !named().matches(&fp),
        "the plain first ten octets are no tag"
    );
    assert!(code(n("/a/b"), None, &fp).matches(&fp));
    assert!(!code(n("/a/b"), None, &fp).matches(&other));
}

/// A code that does not carry 10 or 32 octets cannot be made.
#[test]
fn a_fingerprint_of_another_length_is_not_encoded() {
    assert_eq!(
        code(n("/alice/member/laptop"), None, &[1; 16]).encode(),
        Err(ShortError::Fingerprint(16))
    );
}

/// The hint's name is derived from the secret, unguessable without it,
/// and parses back to the device and the token.
#[test]
fn hint_names_are_derived_from_the_secret() {
    let token = hint_token(&secret());
    assert_ne!(token, hint_token(&[0; 16]));
    assert_eq!(token, hint_token(&secret()));
    assert!(!token.windows(4).any(|w| w == &secret()[..4]));
    let device = n("/alice/member/laptop");
    let name = hint_name(&device, &token);
    assert!(name.has_prefix(&hint_prefix(&device)));
    assert_eq!(name.len(), device.len() + 2);
    assert_eq!(name.components()[device.len()].typ, 32);
    assert_eq!(&name.components()[device.len()].value[..], b"hint");
    assert_eq!(parse_hint_name(&name), Some((device.clone(), token)));
    // Not a hint name: another keyword, another length, a longer name.
    assert_eq!(parse_hint_name(&device), None);
    assert_eq!(parse_hint_name(&hint_prefix(&device)), None);
    assert_eq!(parse_hint_name(&name.clone().append("more")), None);
    assert_eq!(
        parse_hint_name(&device.clone().append("x").append(token)),
        None
    );
    let short = hint_prefix(&device).append([1u8; 15]);
    assert_eq!(parse_hint_name(&short), None);
}

/// The names a stranger's link to a device carries: held, intro, hint.
#[test]
fn a_dialled_introduction_link_routes_three_prefixes() {
    let device = n("/alice/member/laptop");
    let [held, intro, hint] = introduction_prefixes(&device);
    assert_eq!(held, crate::wire::held_prefix(&device));
    assert_eq!(intro, crate::intro::intro_prefix(&device));
    assert_eq!(hint, hint_prefix(&device));
}

fn offered() -> HintRecord {
    HintRecord::Offered {
        offer: n("/alice/member/laptop/32=log/alice/32=data/notes/seq=3"),
        key: [0x42; 32],
        candidates: vec![
            HintCandidate {
                kind: HintKind::Host,
                addr: "192.0.2.7:4433".parse().unwrap(),
            },
            HintCandidate {
                kind: HintKind::Reflexive,
                addr: "[2001:db8::7]:4433".parse().unwrap(),
            },
        ],
        relays: vec![n("/alice/node/relay-1"), n("/alice/node/relay-2")],
        until: Timestamp(1_700_000_000_000),
        credentials: vec![Bytes::from_static(&[0x06, 0x01, 0xAA])],
    }
}

/// A hint record and a gone mark read back as they were made.
#[test]
fn hint_records_round_trip() {
    let record = offered();
    assert_eq!(HintRecord::decode(record.encode(), false).unwrap(), record);
    for why in [IntroRefusal::Expired, IntroRefusal::Closed] {
        let gone = HintRecord::Gone {
            why,
            credentials: vec![Bytes::from_static(&[0x06, 0x01, 0xAA])],
        };
        assert_eq!(HintRecord::decode(gone.encode(), false).unwrap(), gone);
    }
}

/// A gone mark carries the inviter's credentials, so that it is verified as a
/// record is; one without them, or with anything of a record beside them, is
/// refused.
#[test]
fn a_gone_mark_carries_credentials_and_nothing_of_a_record() {
    use ndn_tlv::TlvWriter;
    let tlv = crate::wire::tlv::INTRO_HINT;
    let creds = |w: &mut TlvWriter| w.write_tlv(crate::wire::tlv::CREDENTIALS, &[0x06, 0x01, 0xAA]);
    let record = |fields: &dyn Fn(&mut TlvWriter)| {
        let mut w = TlvWriter::new();
        w.write_nested(tlv, |w| fields(w));
        w.finish()
    };
    assert!(
        HintRecord::decode(
            record(&|w| w.write_tlv(crate::wire::tlv::HINT_GONE, &[4])),
            false
        )
        .is_err(),
        "a gone mark with no credentials is read as one that proves nothing"
    );
    assert!(
        HintRecord::decode(
            record(&|w| {
                w.write_tlv(crate::wire::tlv::HINT_GONE, &[4]);
                creds(w);
                w.write_tlv(crate::wire::tlv::LINK_KEY, &[0x42; 32]);
            }),
            false
        )
        .is_err(),
        "a gone mark carries nothing of a record but the credentials"
    );
    assert!(
        HintRecord::decode(
            record(&|w| {
                w.write_tlv(crate::wire::tlv::HINT_GONE, &[4]);
                creds(w);
            }),
            false
        )
        .is_ok()
    );
}

/// The keyed fingerprint a named namespace's short code carries
/// ([`keyed_fingerprint`]): ten octets that depend on the code's secret and on
/// the whole anchor fingerprint, and are not the anchor's own octets; a
/// verifier compares it in constant time and refuses a tag of another length.
#[test]
fn the_keyed_fingerprint_depends_on_the_secret_and_the_whole_anchor() {
    let anchor = whole();
    let tag = keyed_fingerprint(&secret(), &anchor);
    assert_eq!(tag.len(), SHORT_FINGERPRINT_LEN);
    assert_eq!(tag, keyed_fingerprint(&secret(), &anchor), "deterministic");
    assert_ne!(
        tag[..],
        anchor[..SHORT_FINGERPRINT_LEN],
        "not the plain truncation"
    );
    let mut other_secret = secret();
    other_secret[15] ^= 1;
    assert_ne!(
        tag,
        keyed_fingerprint(&other_secret, &anchor),
        "another secret, another tag"
    );
    // An anchor that differs only past the first ten octets gives another tag:
    // the whole fingerprint is bound, not a prefix of it.
    let mut other_anchor = anchor;
    other_anchor[31] ^= 1;
    assert_ne!(
        tag,
        keyed_fingerprint(&secret(), &other_anchor),
        "the last octet counts"
    );

    assert!(keyed_fingerprint_matches(&secret(), &anchor, &tag));
    assert!(!keyed_fingerprint_matches(&other_secret, &anchor, &tag));
    assert!(!keyed_fingerprint_matches(&secret(), &other_anchor, &tag));
    assert!(
        !keyed_fingerprint_matches(&secret(), &anchor, &anchor[..SHORT_FINGERPRINT_LEN]),
        "the plain truncation of the anchor is no tag"
    );
    assert!(
        !keyed_fingerprint_matches(&secret(), &anchor, &tag[..9]),
        "short"
    );
    let mut long = tag.to_vec();
    long.push(0);
    assert!(
        !keyed_fingerprint_matches(&secret(), &anchor, &long),
        "long"
    );
    assert!(!keyed_fingerprint_matches(&secret(), &anchor, &[]), "empty");
}

/// A record without what it needs, with too much, or with another refusal
/// is refused; loopback candidates are dropped unless the policy allows.
#[test]
fn malformed_hint_records_are_refused() {
    use ndn_tlv::TlvWriter;
    let tlv = crate::wire::tlv::INTRO_HINT;
    let record = |fields: &dyn Fn(&mut TlvWriter)| {
        let mut w = TlvWriter::new();
        w.write_nested(tlv, |w| fields(w));
        w.finish()
    };
    assert!(HintRecord::decode(record(&|_| {}), false).is_err(), "empty");
    assert!(
        HintRecord::decode(
            record(&|w| {
                w.write_nested(crate::wire::tlv::HINT_GONE, |w| w.write_raw(&[0x01]));
                w.write_tlv(crate::wire::tlv::CREDENTIALS, &[0x06, 0x01, 0xAA]);
            }),
            false
        )
        .is_err(),
        "a gone mark is an integer"
    );
    for code in [1u8, 2, 5, 6, 9] {
        assert!(
            HintRecord::decode(
                record(&|w| {
                    w.write_tlv(crate::wire::tlv::HINT_GONE, &[code]);
                    w.write_tlv(crate::wire::tlv::CREDENTIALS, &[0x06, 0x01, 0xAA]);
                }),
                false
            )
            .is_err(),
            "gone {code}"
        );
    }
    let not_a_record = Bytes::from_static(&[0x05, 0x00]);
    assert!(HintRecord::decode(not_a_record, false).is_err());
    let HintRecord::Offered { candidates, .. } = HintRecord::decode(
        {
            let mut r = offered();
            if let HintRecord::Offered { candidates, .. } = &mut r {
                candidates.push(HintCandidate {
                    kind: HintKind::Host,
                    addr: "127.0.0.1:4433".parse().unwrap(),
                });
            }
            r.encode()
        },
        false,
    )
    .unwrap() else {
        panic!("a record");
    };
    assert_eq!(candidates.len(), 2, "loopback passed over");
}
