//! The plain types and the host's trait (`host.rs`): the link hint's bytes, the
//! code's link, the defaults of a host that does the least.

use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_tlv::{TlvReader, TlvWriter};
use ndn_trust_envelope::{IntroWords, Introduction, TrustEnvelope};

use crate::host::{
    Adopting, Code, HintCandidate, HintKind, Host, LINK_HINT_CANDIDATES_MAX, LinkHint, Role,
};
use crate::policy::IntroPolicy;
use crate::proofs::SECRET_LEN;
use crate::wire::{OFFER_ID_LEN, offer_name, tlv};

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

fn host(i: u8) -> HintCandidate {
    HintCandidate {
        kind: HintKind::Host,
        addr: SocketAddr::from(([192, 168, 1, i], 7000 + u16::from(i))),
    }
}

fn host6(i: u16) -> HintCandidate {
    HintCandidate {
        kind: HintKind::Advertised,
        addr: SocketAddr::from((
            [0x2001, 0xdb8, 0x1234, 0x5678, 0xaaaa, 0xbbbb, 0xcccc, i],
            9000 + i,
        )),
    }
}

/// An offer's URI under the device `/home/alice/<pad>`: its id holds octets no
/// UTF-8 text holds, so the link carries it as bytes and the words as escapes.
fn offer_uri(pad: &str) -> String {
    let id: [u8; OFFER_ID_LEN] = core::array::from_fn(|i| 0x80 + i as u8);
    offer_name(&n(&format!("/home/alice/{pad}")), &id).to_string()
}

#[test]
fn a_role_is_a_code_and_back() {
    for role in [Role::Reader, Role::Writer] {
        assert_eq!(Role::from_code(role.code()).unwrap(), role);
    }
    assert!(Role::from_code(2).is_err());
}

#[test]
fn a_hint_kind_is_a_code_and_back() {
    for kind in [
        HintKind::Host,
        HintKind::Reflexive,
        HintKind::Advertised,
        HintKind::Mapped,
    ] {
        assert_eq!(HintKind::from_code(kind.code()), Some(kind));
    }
    assert_eq!(HintKind::from_code(4), None);
}

/// A hint round-trips; what a reader does not know — an even type, a candidate
/// kind of a later version — is passed over, and what makes no sense — an odd
/// type, two keys, a candidate of the wrong size, no key — is refused.
#[test]
fn a_link_hint_round_trips_and_malformed_ones_are_refused() {
    let hint = LinkHint {
        key: [0x42; 32],
        candidates: vec![host(2), host6(1), host(3)],
    };
    assert_eq!(LinkHint::decode(&hint.encode(), false).unwrap(), hint);

    let mut w = TlvWriter::new();
    w.write_tlv(tlv::LINK_KEY, &[1; 32]);
    w.write_tlv(0x05BE, b"a later even field");
    w.write_tlv(tlv::LINK_CANDIDATE, &[9, 10, 0, 0, 1, 0x1B, 0x58]);
    w.write_tlv(tlv::LINK_CANDIDATE, &[0, 10, 0, 0, 2, 0x1B, 0x58]);
    let got = LinkHint::decode(&w.finish(), false).unwrap();
    assert_eq!(got.candidates.len(), 1, "an unknown kind is passed over");

    let refused = |build: &dyn Fn(&mut TlvWriter)| {
        let mut w = TlvWriter::new();
        build(&mut w);
        LinkHint::decode(&w.finish(), false).unwrap_err()
    };
    refused(&|w| {
        w.write_tlv(tlv::LINK_KEY, &[1; 32]);
        w.write_tlv(tlv::LINK_KEY, &[2; 32]);
    });
    refused(&|w| w.write_tlv(tlv::LINK_CANDIDATE, &[0, 10, 0, 0, 1, 0x1B, 0x58]));
    refused(&|w| {
        w.write_tlv(tlv::LINK_KEY, &[1; 32]);
        w.write_tlv(tlv::LINK_CANDIDATE, &[0, 10, 0, 0, 1, 0x1B]);
    });
    refused(&|w| {
        w.write_tlv(tlv::LINK_KEY, &[1; 31]);
    });
    refused(&|w| {
        w.write_tlv(tlv::LINK_KEY, &[1; 32]);
        w.write_tlv(0x05BF, b"a later critical field");
    });
}

/// A code from a stranger is not made to send datagrams to addresses nobody is
/// at, and a hint's candidates are bounded and distinct.
#[test]
fn a_link_hint_keeps_only_dialable_distinct_candidates_up_to_its_bound() {
    let unusable = [
        HintCandidate {
            kind: HintKind::Host,
            addr: SocketAddr::from(([0, 0, 0, 0], 7000)),
        },
        HintCandidate {
            kind: HintKind::Host,
            addr: SocketAddr::from(([224, 0, 0, 1], 7000)),
        },
        HintCandidate {
            kind: HintKind::Host,
            addr: SocketAddr::from(([255, 255, 255, 255], 7000)),
        },
        HintCandidate {
            kind: HintKind::Host,
            addr: SocketAddr::from(([10, 0, 0, 1], 0)),
        },
        HintCandidate {
            kind: HintKind::Host,
            addr: SocketAddr::from(([0u16; 8], 7000)),
        },
    ];
    let mut candidates: Vec<HintCandidate> = unusable.to_vec();
    candidates.push(host(1));
    candidates.push(host(1));
    candidates.extend((2..40).map(host));
    let hint = LinkHint {
        key: [3; 32],
        candidates,
    };
    let got = LinkHint::decode(&hint.encode(), false).unwrap();
    assert_eq!(got.candidates.len(), LINK_HINT_CANDIDATES_MAX);
    assert_eq!(got.candidates[0], host(1));
    assert_eq!(got.candidates[1], host(2));
    // The encoding keeps at most the bound whatever the host gave, so a hostile
    // reader gets no more than a conforming one.
    let encoded = hint.encode();
    let mut count = 0;
    let mut r = TlvReader::new(encoded);
    while !r.is_empty() {
        if r.read_tlv().unwrap().0 == tlv::LINK_CANDIDATE {
            count += 1;
        }
    }
    assert!(count <= LINK_HINT_CANDIDATES_MAX);
}

/// A stranger's code does not make this device send datagrams to itself or its
/// link: loopback and link-local addresses are dropped when a hint is read,
/// unless the policy allows them; the inviter's own encoding keeps what its
/// gathering gave.
#[test]
fn a_link_hint_drops_loopback_and_link_local_addresses_unless_the_policy_allows() {
    let at = |ip: std::net::IpAddr| HintCandidate {
        kind: HintKind::Host,
        addr: SocketAddr::new(ip, 7000),
    };
    let local = [
        at("127.0.0.1".parse().unwrap()),
        at("::1".parse().unwrap()),
        at("169.254.7.7".parse().unwrap()),
        at("fe80::1".parse().unwrap()),
        at("::ffff:127.0.0.1".parse().unwrap()),
    ];
    let mut candidates = local.to_vec();
    candidates.push(host(1));
    let hint = LinkHint {
        key: [5; 32],
        candidates,
    };
    let encoded = hint.encode();
    assert_eq!(
        LinkHint::decode(&encoded, false).unwrap().candidates,
        vec![host(1)],
        "only the address that reaches beyond this machine and its link is kept"
    );
    let kept = LinkHint::decode(&encoded, true).unwrap().candidates;
    assert_eq!(kept.len(), local.len() + 1, "{kept:?}");
    assert!(local.iter().all(|c| kept.contains(c)), "{kept:?}");
}

fn code_with(offer: String, relays: usize) -> Introduction {
    Introduction {
        namespace: Some("/home/alice".into()),
        fingerprint: [0xA5; ndn_trust_envelope::ANCHOR_FINGERPRINT_LEN],
        offer,
        secret: [0x3C; SECRET_LEN],
        link_hint: None,
        relays: (0..relays)
            .map(|i| format!("/community/node/relay-{i:04}"))
            .collect(),
    }
}

/// A policy that caps neither candidates nor relays: these tests are about what
/// fits one QR, not about the defaults of a full link.
fn uncapped() -> IntroPolicy {
    IntroPolicy {
        code_candidates: LINK_HINT_CANDIDATES_MAX,
        code_relays: usize::MAX,
        ..IntroPolicy::new()
    }
}

/// The compact link carries an offer's name as the name it is: the 16 octets of
/// its id, which are no text, come back exactly (the envelope's offer is a
/// name, whatever its shape; nothing assumes a log entry's).
#[test]
fn a_link_carries_an_offer_name_whole_and_the_secret_with_it() {
    let uri = offer_uri("laptop");
    let link = LinkHint::code_link(code_with(uri.clone(), 1), None, &uncapped()).unwrap();
    let Ok(TrustEnvelope::Intro(i)) = TrustEnvelope::from_uri(&link) else {
        panic!("an introduction link");
    };
    assert_eq!(i.offer, uri);
    assert_eq!(i.offer.parse::<Name>().unwrap().to_string(), uri);
    assert_eq!(i.secret, [0x3C; SECRET_LEN]);
    // The words form carries it too.
    let words = code_with(uri.clone(), 0).to_words();
    let back = IntroWords::parse(&words).unwrap();
    assert_eq!(back.offer, uri);
}

/// The code's size, with and without a full hint of the most candidates, IPv6
/// (the longest), beside several relay hints: within one QR with room to spare,
/// so the bound on candidates is what keeps it there.
#[test]
fn a_code_with_a_full_link_hint_stays_within_one_qr() {
    let offer = offer_uri("laptop");
    let hint = LinkHint {
        key: [0x42; 32],
        candidates: (0..LINK_HINT_CANDIDATES_MAX as u16).map(host6).collect(),
    };
    let without = LinkHint::code_link(code_with(offer.clone(), 4), None, &uncapped()).unwrap();
    let with = LinkHint::code_link(code_with(offer.clone(), 4), Some(&hint), &uncapped()).unwrap();
    let max = ndn_trust_envelope::qr::MAX_TEXT_LEN;
    assert!(without.len() < with.len() && with.len() <= max / 2);
    let Ok(TrustEnvelope::Intro(i)) = TrustEnvelope::from_uri(&with) else {
        panic!("an introduction link");
    };
    assert_eq!(
        LinkHint::decode(&i.link_hint.unwrap(), false).unwrap(),
        hint,
        "a hint that fits is carried whole"
    );
}

/// A full link carries at most the policy's candidates and relays (3 and 2 by
/// default), the first ones, and the policy's own numbers when it gives others.
#[test]
fn a_full_link_carries_the_policys_candidates_and_relays() {
    let offer = offer_uri("laptop");
    let hint = LinkHint {
        key: [0x42; 32],
        candidates: (0..LINK_HINT_CANDIDATES_MAX as u16).map(host6).collect(),
    };
    let read = |policy: &IntroPolicy| {
        let link = LinkHint::code_link(code_with(offer.clone(), 5), Some(&hint), policy).unwrap();
        let Ok(TrustEnvelope::Intro(i)) = TrustEnvelope::from_uri(&link) else {
            panic!("an introduction link");
        };
        let hint = i.link_hint.map(|h| LinkHint::decode(&h, false).unwrap());
        (hint.map_or(0, |h| h.candidates.len()), i.relays)
    };
    let (candidates, relays) = read(&IntroPolicy::new());
    assert_eq!(candidates, 3);
    assert_eq!(relays, code_with(offer.clone(), 5).relays[..2]);
    let (candidates, relays) = read(&IntroPolicy {
        code_candidates: 5,
        code_relays: 4,
        ..IntroPolicy::new()
    });
    assert_eq!((candidates, relays.len()), (5, 4));
    let (candidates, relays) = read(&IntroPolicy {
        code_candidates: 0,
        code_relays: 0,
        ..IntroPolicy::new()
    });
    assert_eq!((candidates, relays.len()), (0, 0), "no hint, no relays");
}

/// An offer name that leaves room for few candidates keeps the first ones that
/// fit and drops the relays first; one that leaves room for none drops the hint
/// and still gives a code; the secret, offer and fingerprint are never dropped.
#[test]
fn a_code_that_cannot_hold_the_whole_hint_trims_it_and_never_the_secret() {
    let max = ndn_trust_envelope::qr::MAX_TEXT_LEN;
    let hint = LinkHint {
        key: [0x42; 32],
        candidates: (0..LINK_HINT_CANDIDATES_MAX as u16).map(host6).collect(),
    };
    // A device name long enough that only some candidates fit beside it.
    let mut trimmed = None;
    for pad in (1400..1700).step_by(4) {
        let offer = offer_uri(&"n".repeat(pad));
        let Some(link) =
            LinkHint::code_link(code_with(offer.clone(), 40), Some(&hint), &uncapped())
        else {
            break;
        };
        assert!(
            link.len() <= max,
            "a code of {} octets is past one QR",
            link.len()
        );
        let Ok(TrustEnvelope::Intro(i)) = TrustEnvelope::from_uri(&link) else {
            panic!("an introduction link");
        };
        assert_eq!(i.offer, offer);
        assert_eq!(i.secret, [0x3C; SECRET_LEN]);
        assert_eq!(i.fingerprint, [0xA5; 32]);
        if let Some(bytes) = &i.link_hint {
            let got = LinkHint::decode(bytes, false).unwrap();
            assert_eq!(got.candidates[..], hint.candidates[..got.candidates.len()]);
            if got.candidates.len() < hint.candidates.len() {
                assert!(i.relays.is_empty(), "relays go before candidates");
                trimmed = Some(got.candidates.len());
            }
        } else {
            trimmed.get_or_insert(0);
        }
    }
    assert!(trimmed.is_some(), "no offer name length trimmed the hint");
}

/// A code's `Debug` shows the offer and neither the link nor the words, which
/// carry the secret; `share` is the short code when there is one.
#[test]
fn a_code_never_shows_its_secret_and_shares_the_short_form_first() {
    let mut code = Code {
        offer: n("/alice/laptop/32=intro/offer/x"),
        link: "ndn-trust://intro/SECRETLINK".into(),
        words: "SECRETWORDS".into(),
        short: None,
        short_why: Some("no first contact".into()),
    };
    let shown = format!("{code:?}");
    assert!(shown.contains("offer"));
    assert!(!shown.contains("SECRET"), "{shown}");
    assert_eq!(code.share(), "ndn-trust://intro/SECRETLINK");
    code.short = Some("/alice/laptop 192.0.2.7:4433 word".into());
    assert_eq!(code.share(), "/alice/laptop 192.0.2.7:4433 word");
}

/// A host that implements only what it must: no hint, no link layer, nothing
/// to do on a grant; each default says what to do instead.
struct Bare;

impl Host for Bare {
    fn anchor(&self) -> Option<Bytes> {
        None
    }

    fn adopt<'a>(&'a self, _link: &'a TrustEnvelope) -> Adopting<'a> {
        Box::pin(async { Ok(()) })
    }
}

#[tokio::test]
async fn the_defaults_of_a_host_dial_nothing_and_say_so() {
    let bare = Bare;
    assert_eq!(bare.link_hint(), None);
    let hint = LinkHint {
        key: [1; 32],
        candidates: vec![host(1)],
    };
    let within = Duration::from_secs(1);
    let err = bare
        .dial(&hint, &n("/alice/laptop"), within)
        .await
        .unwrap_err();
    assert!(
        err.contains("/alice/laptop") && err.contains("Host::dial"),
        "{err}"
    );
    let err = bare
        .dial_first(
            &n("/alice/laptop"),
            "192.0.2.7:4433".parse().unwrap(),
            within,
        )
        .await
        .unwrap_err();
    assert!(
        err.contains("Host::dial_first") && err.contains("route to it"),
        "{err}"
    );
    bare.undial(&hint, &n("/alice/laptop"));
}
