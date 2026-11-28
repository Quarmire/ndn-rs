//! The two frames of the channel path: golden octets written by hand from docs/specs/channel.md
//! §11.5 and docs/specs/query.md §15, not by the codec under test.

use bytes::Bytes;
use ndn_foundation_types::{Name, NameComponent};
use ndn_transport::SideClass;
use ndn_transport::side_header::{AnswerPrefix, MIN_FRAME_LEN, QueryPrefix, SideHeader, SideKind};

use super::*;

fn name(parts: &[&str]) -> Name {
    Name::from_components(
        parts
            .iter()
            .map(|p| NameComponent::generic(Bytes::copy_from_slice(p.as_bytes()))),
    )
}

const ROUTE: u64 = 0x0102_0304_0506_0708;
const TOKEN: u64 = 0x1112_1314_1516_1718;
const PAIR: [u8; 8] = [0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8];

fn query_header() -> QueryHeader {
    QueryHeader {
        route: ROUTE,
        token: TOKEN,
        ttl_ticks: 5,
        pair: PAIR,
        qseq: 0x0102,
        epoch: 0x07,
    }
}

#[test]
fn a_query_header_is_these_36_octets() {
    let golden: [u8; 36] = [
        0x00, 0x25, // marker, ver 1 | class 0 | kind 5
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // route id
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, // token
        0x05, // ttl, in 100 ms
        0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, // pair id
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, // qseq
        0x07, // key epoch, low octet
    ];
    assert_eq!(QUERY_HEADER_LEN, 36);
    assert_eq!(query_header().encode(), golden);
    let mut frame = golden.to_vec();
    frame.extend_from_slice(&[0xee; 20]);
    let (header, sealed) = QueryHeader::parse(&frame).unwrap();
    assert_eq!(header, query_header());
    assert_eq!(sealed, &[0xee; 20]);
}

#[test]
fn a_relay_reads_the_same_route_token_and_ttl_from_a_query() {
    let wire = query_header().encode();
    let prefix = QueryPrefix::parse(&wire).unwrap();
    assert_eq!(
        (prefix.id, prefix.token, prefix.ttl_ticks),
        (ROUTE, TOKEN, 5)
    );
    assert_eq!(SideHeader::parse(&wire).unwrap().kind(), SideKind::Query);
}

#[test]
fn an_answer_header_is_these_19_octets_on_either_class() {
    let header = AnswerHeader {
        class: SideClass::Datagram,
        route: ROUTE,
        token: TOKEN,
        epoch: 0x07,
    };
    let golden: [u8; 19] = [
        0x00, 0x26, // marker, ver 1 | class 0 | kind 6
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, //
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, //
        0x07,
    ];
    assert_eq!(ANSWER_HEADER_LEN, 19);
    assert_eq!(header.encode(), golden);
    let mut frame = golden.to_vec();
    frame.extend_from_slice(&[0xdd; 30]);
    let (parsed, sealed) = AnswerHeader::parse(&frame).unwrap();
    assert_eq!(parsed, header);
    assert_eq!(sealed, &[0xdd; 30]);

    let stream = AnswerHeader {
        class: SideClass::Stream,
        ..header
    };
    let wire = stream.encode();
    assert_eq!(wire[1], 0x36);
    assert_eq!(AnswerHeader::parse(&wire).unwrap().0, stream);
    let prefix = AnswerPrefix::parse(&wire).unwrap();
    assert_eq!(
        (prefix.class, prefix.id, prefix.token),
        (SideClass::Stream, ROUTE, TOKEN)
    );
}

#[test]
fn the_overheads_are_52_and_35() {
    assert_eq!(QUERY_OVERHEAD, 52);
    assert_eq!(ANSWER_OVERHEAD, 35);
}

#[test]
fn a_header_of_another_kind_or_too_short_is_refused() {
    let q = query_header().encode();
    assert!(QueryHeader::parse(&q[..35]).is_err(), "one octet short");
    assert!(
        QueryHeader::parse(&q[..19]).is_err(),
        "only the relay's prefix"
    );
    // A DATA datagram, an ANSWER and an UP are not a QUERY.
    for first in [0x20u8, 0x26, 0x24, 0x36] {
        let mut wire = q;
        wire[1] = first;
        assert!(QueryHeader::parse(&wire).is_err(), "{first:#x} is no QUERY");
    }
    // A QUERY on a stream is no frame at all.
    let mut wire = q;
    wire[1] = 0x35;
    assert!(QueryHeader::parse(&wire).is_err());
    let a = AnswerHeader {
        class: SideClass::Datagram,
        route: 1,
        token: 2,
        epoch: 3,
    }
    .encode();
    assert!(AnswerHeader::parse(&a[..18]).is_err());
    let mut wire = a;
    wire[1] = 0x25;
    assert!(AnswerHeader::parse(&wire).is_err());
    // Version 2.
    let mut wire = a;
    wire[1] = 0x46;
    assert!(AnswerHeader::parse(&wire).is_err());
}

/// The octets of the query id `0x1122334455667788` that open every query plaintext.
const ID: [u8; 8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
const QUERY_ID: u64 = 0x1122_3344_5566_7788;

/// `rest` after the id octets.
fn with_id(rest: &[u8]) -> Vec<u8> {
    let mut plain = ID.to_vec();
    plain.extend_from_slice(rest);
    plain
}

#[test]
fn a_query_plaintext_is_id_deadline_path_length_path_and_query() {
    let plain = QueryPlain {
        id: QUERY_ID,
        deadline_ms: 3000,
        path: name(&["a", "b"]),
        bytes: Bytes::from_static(b"hi"),
    };
    // varint 3000 = 0x4bb8; the path's value is two generic components (08 01 61, 08 01 62).
    let golden = with_id(&[
        0x4b, 0xb8, 0x06, 0x08, 0x01, 0x61, 0x08, 0x01, 0x62, 0x68, 0x69,
    ]);
    assert_eq!(plain.encode().unwrap(), golden);
    assert_eq!(QueryPlain::decode(&golden).unwrap(), plain);
}

#[test]
fn an_empty_path_and_empty_query_are_fine_a_zero_or_huge_deadline_is_not() {
    let plain = QueryPlain {
        id: QUERY_ID,
        deadline_ms: 1,
        path: Name::root(),
        bytes: Bytes::new(),
    };
    assert_eq!(plain.encode().unwrap(), with_id(&[0x01, 0x00]));
    assert_eq!(QueryPlain::decode(&with_id(&[0x01, 0x00])).unwrap(), plain);
    assert!(
        QueryPlain::decode(&with_id(&[0x00, 0x00])).is_err(),
        "a deadline of 0"
    );
    // 10,001 ms is 0x4000 | 0x2711.
    assert!(
        QueryPlain::decode(&with_id(&[0x67, 0x11, 0x00])).is_err(),
        "over 10 s"
    );
    assert!(
        QueryPlain {
            deadline_ms: 0,
            ..plain.clone()
        }
        .encode()
        .is_err()
    );
    assert!(
        QueryPlain {
            deadline_ms: 10_001,
            ..plain
        }
        .encode()
        .is_err()
    );
}

#[test]
fn a_query_plaintext_that_is_cut_or_names_a_bad_path_is_refused() {
    assert!(QueryPlain::decode(&[]).is_err());
    assert!(QueryPlain::decode(&ID[..7]).is_err(), "the id is cut");
    assert!(QueryPlain::decode(&ID).is_err(), "no deadline");
    assert!(
        QueryPlain::decode(&with_id(&[0x01])).is_err(),
        "no path length"
    );
    // The path claims 6 octets and 2 follow.
    assert!(QueryPlain::decode(&with_id(&[0x01, 0x06, 0x08, 0x01])).is_err());
    // A path that is no sequence of components (a component claims more than is there).
    assert!(QueryPlain::decode(&with_id(&[0x01, 0x02, 0x08, 0x05])).is_err());
    // A path over 255 octets.
    let mut long = with_id(&[0x01, 0x41, 0x00]); // the path claims 256 octets (varint 0x4100)
    long.resize(8 + 3 + 256, 0);
    assert!(QueryPlain::decode(&long).is_err());
    let path = Name::from_components([NameComponent::generic(Bytes::from(vec![b'x'; 254]))]);
    assert!(
        QueryPlain {
            id: QUERY_ID,
            deadline_ms: 5,
            path,
            bytes: Bytes::new()
        }
        .encode()
        .is_err(),
        "a component of 254 octets is a value of 257"
    );
}

fn padded(mut prefix: Vec<u8>) -> Vec<u8> {
    assert!(prefix.len() < 11);
    prefix.push(0x80);
    prefix.resize(11, 0);
    prefix
}

#[test]
fn every_answer_status_has_these_octets_and_is_padded_to_a_46_octet_frame() {
    assert_eq!(MIN_FRAME_LEN - ANSWER_OVERHEAD, 11);
    let cases: Vec<(ChanStatus, Vec<u8>)> = vec![
        (
            ChanStatus::Answered(Bytes::from_static(b"hi")),
            padded(vec![0x00, 0x02, 0x68, 0x69]),
        ),
        (
            ChanStatus::Refused {
                code: 0x0102,
                text: "no".into(),
            },
            padded(vec![0x01, 0x01, 0x02, 0x02, 0x6e, 0x6f]),
        ),
        (
            ChanStatus::Busy { retry_ms: 1000 },
            padded(vec![0x02, 0x43, 0xe8]),
        ),
        (ChanStatus::NotServed, padded(vec![0x03])),
        (
            ChanStatus::TooLarge { max: 4096 },
            padded(vec![0x04, 0x50, 0x00]),
        ),
    ];
    for (status, golden) in cases {
        assert_eq!(status.encode(), golden, "{status:?}");
        assert_eq!(ChanStatus::decode(&golden).unwrap(), status, "{status:?}");
    }
}

#[test]
fn a_long_enough_answer_is_not_padded() {
    let status = ChanStatus::Answered(Bytes::from(vec![7u8; 100]));
    let wire = status.encode();
    assert_eq!(wire.len(), 1 + 2 + 100);
    assert_eq!(
        &wire[..3],
        &[0x00, 0x40, 0x64],
        "a length of 100 is a two-octet varint"
    );
    assert_eq!(ChanStatus::decode(&wire).unwrap(), status);
    // Exactly 11 octets: no pad.
    let status = ChanStatus::Answered(Bytes::from(vec![7u8; 9]));
    assert_eq!(status.encode().len(), 11);
    assert_eq!(ChanStatus::decode(&status.encode()).unwrap(), status);
}

#[test]
fn an_answer_that_is_cut_unknown_or_badly_padded_is_refused() {
    assert!(ChanStatus::decode(&[]).is_err());
    assert!(
        ChanStatus::decode(&[0x05]).is_err(),
        "status 5 is not assigned"
    );
    assert!(
        ChanStatus::decode(&[0x00, 0x05, 0x01]).is_err(),
        "a length past the end"
    );
    assert!(
        ChanStatus::decode(&padded(vec![0x03]).iter().map(|b| b ^ 1).collect::<Vec<_>>()).is_err()
    );
    // A pad whose octets after 0x80 are not all zero.
    let mut bad = padded(vec![0x03]);
    bad[10] = 1;
    assert!(ChanStatus::decode(&bad).is_err());
    // Octets after the fields that are no pad.
    let mut bad = vec![0x03];
    bad.extend_from_slice(&[1, 2, 3]);
    assert!(ChanStatus::decode(&bad).is_err());
    // A refusal text over 256 octets, and one that is no UTF-8.
    let mut long = vec![0x01, 0x00, 0x01, 0x41, 0x00];
    long.resize(5 + 257, b'x');
    assert!(ChanStatus::decode(&long).is_err());
    assert!(ChanStatus::decode(&[0x01, 0x00, 0x01, 0x02, 0xff, 0xfe]).is_err());
}

#[test]
fn a_refusal_text_is_cut_at_256_octets_not_refused() {
    let status = ChanStatus::refused(7, &"y".repeat(400));
    let ChanStatus::Refused { code, text } = &status else {
        panic!("a refusal");
    };
    assert_eq!((*code, text.len()), (7, 256));
    assert_eq!(ChanStatus::decode(&status.encode()).unwrap(), status);
}
