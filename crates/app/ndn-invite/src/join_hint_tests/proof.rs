//! What a first contact's answer has to prove before it can end a code, the keyed
//! fingerprint a named namespace's short code carries, and which refusals of a hint are
//! worth a retry (Round 10: L3, L4, L5): the joiner's half. What the inviter keeps of
//! its served records is `offer_tests`'.

use ndn_tlv::TlvWriter;

use super::*;

/// The text a refusal of a mark that does not prove itself gives.
const UNPROVEN: &str = "the first contact says the offer is closed but can't prove it";

/// A rig whose inviter's hint answers are replaced by `content`, signed by `signer`
/// (digest only: no signature of anyone, when none) with `FreshnessPeriod` 0.
fn answer_hint_with(rig: &Rig, content: Bytes, signer: Option<Device>) {
    rig.gate.tamper(move |wire| {
        let data = Data::decode(wire.clone()).ok()?;
        if !is_hint(&data.name) {
            return Some(wire);
        }
        let built = DataBuilder::new((*data.name).clone(), &content).freshness(Duration::ZERO);
        match &signer {
            Some(signer) => sign_as(signer, built),
            None => Some(built.sign_digest_sha256()),
        }
    });
}

/// The error of a join, which must be one.
fn refusal_of(got: Result<Joined, InviteError>) -> InviteError {
    match got {
        Err(e) => e,
        Ok(joined) => panic!("the join succeeded: {joined:?}"),
    }
}

/// The credentials a device shows.
fn credentials_of(device: &Device) -> Vec<Bytes> {
    let inner = device.invites.inner();
    credentials(&inner.node, &*inner.host).unwrap()
}

/// A mark that does not prove itself: the join is refused as a retry — never the
/// permanent `Closed` or `Expired` — with the text that says so and bounds the retries,
/// and nothing was dialled further, asked or adopted.
fn assert_unproven(rig: &Rig, got: Result<Joined, InviteError>, case: &str) {
    let err = refusal_of(got);
    let InviteError::Refused(why) = &err else {
        panic!("{case}: not an introduction refusal: {err:?}");
    };
    if case == "no credentials" {
        // A mark that does not even read is damage as far as anyone can tell.
        assert!(matches!(why, IntroRefusal::Hint { .. }), "{case}: {why:?}");
    } else {
        assert!(
            matches!(why, IntroRefusal::GoneUnproven { .. }),
            "{case}: a mark that proves nothing was taken as {why:?}"
        );
        assert!(err.to_string().contains(UNPROVEN), "{case}: {err}");
    }
    assert_eq!(err.next(), NextStep::RetryLater, "{case}: {err}");
    assert!(err.retry(), "{case}");
    let shown = err.to_string();
    for says in ["retry", "ask the inviter"] {
        assert!(shown.contains(says), "{case}: {says:?} is not in {shown}");
    }
    assert!(
        shown.contains(&format!("retry at most {HINT_RETRIES_MAX} times")),
        "{case}: the retries are not bounded in {shown}"
    );
    assert!(
        !shown.contains("for good"),
        "{case}: told the user the code is spent: {shown}"
    );
    assert_nothing_went_further(rig, Some(rig.inviter_key()));
}

// ---- L3: a gone mark proves itself as a record does -------------------------------------------

/// A mark anyone on the path could make — unsigned, signed by another key, by another
/// device of the namespace, carrying another namespace's credentials, carrying none, or
/// genuine but not of this code's anchor — is not the end of the code: it is a retry that
/// says it cannot prove itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_gone_mark_that_does_not_prove_itself_is_a_retry_never_closed() {
    let mallory = Person::new("/mallory");
    let mallory_device = start(&mallory, "/mallory/laptop").await;

    for case in [
        "unsigned",
        "signed by another key",
        "signed by another device of the namespace",
        "another namespace's credentials",
        "no credentials",
        "a code of another anchor",
    ] {
        let rig = Rig::new(Shape::address()).await;
        rig.first_contact_answers();
        let alice = credentials_of(&rig.laptop);
        let mark = |credentials: Vec<Bytes>| {
            HintRecord::Gone {
                why: IntroRefusal::Closed,
                credentials,
            }
            .encode()
        };
        let mut code = rig.code.share().to_string();
        match case {
            "unsigned" => answer_hint_with(&rig, mark(alice), None),
            "signed by another key" => {
                answer_hint_with(&rig, mark(alice), Some(Arc::clone(&mallory_device)))
            }
            "signed by another device of the namespace" => {
                let phone = start(&rig.alice, "/alice/phone").await;
                answer_hint_with(&rig, mark(alice), Some(phone))
            }
            "another namespace's credentials" => answer_hint_with(
                &rig,
                mark(credentials_of(&mallory_device)),
                Some(Arc::clone(&mallory_device)),
            ),
            "no credentials" => {
                let mut w = TlvWriter::new();
                w.write_nested(crate::wire::tlv::INTRO_HINT, |w| {
                    w.write_tlv(crate::wire::tlv::HINT_GONE, &[4])
                });
                answer_hint_with(&rig, w.finish(), Some(Arc::clone(&rig.laptop)));
            }
            "a code of another anchor" => {
                // The inviter's own genuine mark, for a code whose fingerprint is not
                // its anchor's: it cannot be tied to the code.
                rig.laptop
                    .invites
                    .close_offer(&rig.code.offer)
                    .await
                    .unwrap();
                code = short_text(
                    &rig,
                    Some(address()),
                    rig.secret,
                    &keyed_fingerprint(&rig.secret, &[0x42; 32]),
                );
            }
            other => unreachable!("{other}"),
        }
        let got = rig.phone.invites.join(&code).await;
        assert_unproven(&rig, got, case);
    }
}

// ---- L4: the fingerprint of a named namespace is keyed by the code's secret -------------------

/// A code whose fingerprint is the anchor's plain first ten octets — as codes were made
/// before the keyed fingerprint — is refused as an anchor mismatch that says so, for
/// good; the keyed one, for the same offer, joins.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_plain_truncated_fingerprint_is_refused_and_the_keyed_one_joins() {
    let rig = Rig::new(Shape::address()).await;
    rig.first_contact_answers();
    let fp = alice_fingerprint(&rig);

    let plain = short_text(&rig, Some(address()), rig.secret, &fp[..10]);
    let got = rig.phone.invites.join(&plain).await;
    let err = refusal_of(got);
    let InviteError::Refused(IntroRefusal::HintMismatch { why }) = &err else {
        panic!("not refused as a mismatch of a record that verifies: {err:?}");
    };
    assert!(why.starts_with("anchor"), "{why}");
    let shown = err.to_string();
    assert!(
        shown.contains(
            "or the code was made before the keyed fingerprint: ask the inviter for a new one"
        ),
        "{shown}"
    );
    assert_eq!(err.next(), NextStep::AskOwner);
    assert_nothing_went_further(&rig, Some(rig.inviter_key()));

    let keyed = short_text(
        &rig,
        Some(address()),
        rig.secret,
        &keyed_fingerprint(&rig.secret, &fp),
    );
    let joined = rig
        .phone
        .invites
        .join(&keyed)
        .await
        .expect("the keyed code joins");
    assert_eq!(joined.space, rig.folder);
}

/// A tag keyed by another secret — whoever saw a code and made a collision against the
/// anchor's plain octets, or another code's tag — is not this code's: refused as a
/// mismatch.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_tag_keyed_by_another_secret_is_refused() {
    let rig = Rig::new(Shape::address()).await;
    rig.first_contact_answers();
    let fp = alice_fingerprint(&rig);
    let text = short_text(
        &rig,
        Some(address()),
        rig.secret,
        &keyed_fingerprint(&[0x55; 16], &fp),
    );
    let got = rig.phone.invites.join(&text).await;
    let err = refusal_of(got);
    assert!(
        matches!(
            &err,
            InviteError::Refused(IntroRefusal::HintMismatch { why }) if why.starts_with("anchor")
        ),
        "{err:?}"
    );
    assert_nothing_went_further(&rig, Some(rig.inviter_key()));
}

/// What a code's fingerprint accepts, by what the code carries: a short code's ten octets
/// are a tag keyed by its secret; the whole 32 octets (a self-certifying namespace, a
/// link) and the words form's plain 16-octet prefix are the anchor's own, compared whole.
#[test]
fn a_fingerprint_is_judged_by_what_the_code_carries() {
    let anchor: [u8; 32] = core::array::from_fn(|i| (i * 5 + 2) as u8);
    let other: [u8; 32] = core::array::from_fn(|i| (i * 5 + 3) as u8);
    let secret = [0x31u8; SECRET_LEN];

    let keyed = Fingerprint::of(&keyed_fingerprint(&secret, &anchor), &secret).expect("10 octets");
    assert!(keyed.matches(&anchor));
    assert!(!keyed.matches(&other));
    let plain = Fingerprint::of(&anchor[..10], &secret).expect("10 octets");
    assert!(!plain.matches(&anchor), "ten plain octets are no keyed tag");

    let whole = Fingerprint::of(&anchor, &secret).expect("32 octets");
    assert!(whole.matches(&anchor));
    assert!(!whole.matches(&other));

    let words = Fingerprint::Prefix(anchor[..16].to_vec());
    assert!(words.matches(&anchor));
    assert!(!words.matches(&other));
    let mut shifted = anchor;
    shifted[15] ^= 1;
    assert!(!words.matches(&shifted), "the 16th octet counts");
}

// ---- L5: only damage in flight is worth a retry ----------------------------------------------

/// A record that verifies — its signature checks under credentials that open — but is not
/// the code's inviter's is no damage in flight: it is `AskOwner`, says so, and does not
/// offer a retry. Another namespace's record, signed by that namespace's device, is one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_record_of_another_namespace_that_verifies_is_ask_the_owner() {
    let rig = Rig::new(Shape::address()).await;
    rig.first_contact_answers();
    let mallory = Person::new("/mallory");
    let device = start(&mallory, "/mallory/laptop").await;
    let genuine = served(&rig, &hint_of(&rig)).unwrap();
    let HintRecord::Offered {
        offer,
        key: link_key,
        candidates,
        relays,
        until,
        ..
    } = record_of(&genuine)
    else {
        panic!("a record");
    };
    let record = HintRecord::Offered {
        offer,
        key: link_key,
        candidates,
        relays,
        until,
        credentials: credentials_of(&device),
    };
    answer_hint_with(&rig, record.encode(), Some(Arc::clone(&device)));
    let got = rig.phone.invites.join(rig.code.share()).await;
    let err = refusal_of(got);
    let InviteError::Refused(IntroRefusal::HintMismatch { why }) = &err else {
        panic!("not a mismatch: {err:?}");
    };
    assert!(why.starts_with("namespace"), "{why}");
    assert_eq!(err.next(), NextStep::AskOwner);
    assert!(!err.retry(), "a retry cannot make it another record");
    let shown = err.to_string();
    for says in [
        "not damage",
        "do not use this code",
        "ask the inviter for a new",
    ] {
        assert!(shown.contains(says), "{says:?} is not in {shown}");
    }
    assert_nothing_went_further(&rig, Some(rig.inviter_key()));
}

/// Damage in flight — any one octet of the packet changed — is a retry, which says how
/// often: never `AskOwner`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_corrupted_record_is_a_bounded_retry() {
    let rig = Rig::new(Shape::address()).await;
    rig.first_contact_answers();
    rig.gate.tamper(move |wire| {
        let Ok(data) = Data::decode(wire.clone()) else {
            return Some(wire);
        };
        if !is_hint(&data.name) {
            return Some(wire);
        }
        let sig = data.sig_value();
        let at = sig.as_ptr() as usize - wire.as_ptr() as usize + sig.len() - 1;
        let mut v = wire.to_vec();
        v[at] ^= 1;
        Some(Bytes::from(v))
    });
    let got = rig.phone.invites.join(rig.code.share()).await;
    let err = refusal_of(got);
    assert!(
        matches!(&err, InviteError::Refused(IntroRefusal::Hint { .. })),
        "{err:?}"
    );
    assert_eq!(err.next(), NextStep::RetryLater);
    assert!(err.retry());
    assert!(
        err.to_string()
            .contains(&format!("retry at most {HINT_RETRIES_MAX} times")),
        "{err}"
    );
}
