//! What an announce is limited by, without a node (docs/specs/channel.md §9, §13.12 item 12):
//! the per-device-per-mode window, the space's bucket for names the record holds nothing of,
//! and what is hashed.

use std::time::Duration;

use ndn_packet::Interest;
use ndn_packet::encode::InterestBuilder;

use super::hub::{
    ANNOUNCE_ASK_EVERY, ANNOUNCE_HASHED, ANNOUNCE_UNVOUCHED_BURST, Heard, announce_params,
};
use super::wire::ChannelMode::{Latest, Reliable, Window};
use crate::node::tests::space;
use crate::rt::Instant;
use crate::test_kit::n;
use crate::wire::{chan_prefix, parse_chan_announce_name, sync_group_of};

fn burst() -> usize {
    ANNOUNCE_UNVOUCHED_BURST as usize
}

/// An unsigned claim that a device has a channel in a mode does not use up the window of the
/// modes the device really offers: a stranger naming a vouched device with a mode it lacks
/// leaves that device's real announce acted on.
#[test]
fn a_claim_for_a_mode_a_device_lacks_does_not_silence_its_real_announce() {
    let (space, device, t0) = (space(), n("/alice/laptop"), Instant::now());
    let mut heard = Heard::default();
    // The stranger's claim, a mode alice's laptop has no channel in.
    assert_eq!(heard.admit(&space, &device, &[Window], true, t0), [Window]);
    // Her real announce, a second later, inside the first claim's window.
    let at = t0 + Duration::from_secs(1);
    assert_eq!(
        heard.admit(&space, &device, &[Latest], true, at),
        [Latest],
        "the real announce is asked about the mode it names"
    );
    // What bounds the cost is the window of each (device, mode): the same claim again, and the
    // same real announce again, are not asked.
    assert!(heard.admit(&space, &device, &[Window], true, at).is_empty());
    assert!(heard.admit(&space, &device, &[Latest], true, at).is_empty());
    let later = t0 + ANNOUNCE_ASK_EVERY + Duration::from_millis(1);
    assert_eq!(
        heard.admit(&space, &device, &[Window], true, later),
        [Window]
    );
}

/// A mode a usable session covers is left out by the caller, so an announce with nothing to ask
/// reaches `admit` with no modes: it spends no token, no slot and stamps nothing.
#[test]
fn an_announce_with_nothing_to_ask_spends_no_token() {
    let (space, t0) = (space(), Instant::now());
    let mut heard = Heard::default();
    for _ in 0..16 {
        assert!(
            heard
                .admit(&space, &n("/bob/phone"), &[], false, t0)
                .is_empty()
        );
    }
    // The bucket is whole: a burst of other names is asked in full.
    for i in 0..burst() {
        let device = n(&format!("/bob/ghost{i}"));
        assert_eq!(
            heard.admit(&space, &device, &[Latest], false, t0),
            [Latest],
            "name {i} of {} finds a token",
            burst()
        );
    }
    assert!(
        heard
            .admit(&space, &n("/bob/one-too-many"), &[Latest], false, t0)
            .is_empty(),
        "the burst is {}",
        burst()
    );
}

/// Each mode asked of a device the record holds nothing of takes a token, and the modes beyond
/// the tokens are left out (so one announce is never more asks than tokens).
#[test]
fn each_mode_of_an_unvouched_device_takes_a_token() {
    let (space, t0) = (space(), Instant::now());
    let mut heard = Heard::default();
    let all = [Latest, Reliable, Window];
    assert_eq!(heard.admit(&space, &n("/bob/a"), &all, false, t0), all);
    // One token is left of the burst of four.
    assert_eq!(
        heard.admit(&space, &n("/bob/b"), &all, false, t0),
        [Latest],
        "only one token was left"
    );
    assert!(
        heard
            .admit(&space, &n("/bob/c"), &all, false, t0)
            .is_empty()
    );
}

/// A device whose answer to an ask was judged good takes no token afterwards: a stranger that
/// empties the bucket cannot keep out a writer this node already heard from.
#[test]
fn a_device_that_answered_takes_no_token() {
    let (space, device, t0) = (space(), n("/bob/phone"), Instant::now());
    let mut heard = Heard::default();
    for i in 0..burst() {
        assert!(
            !heard
                .admit(&space, &n(&format!("/bob/g{i}")), &[Latest], false, t0)
                .is_empty()
        );
    }
    assert!(
        heard
            .admit(&space, &device, &[Latest], false, t0)
            .is_empty(),
        "the bucket is empty"
    );
    heard.answered(&space, &device);
    assert!(heard.has_answered(&space, &device));
    assert_eq!(
        heard.admit(&space, &device, &[Latest], false, t0),
        [Latest],
        "an answered device is not charged to the bucket"
    );
}

fn announce_of(params: usize) -> (Interest, [u8; 32]) {
    let name = chan_prefix(&sync_group_of(&space()).expect("a space has a group"));
    let wire = InterestBuilder::new(name)
        .app_parameters(vec![7u8; params])
        .build();
    let interest = Interest::decode(wire).expect("an Interest");
    let (_, digest) = parse_chan_announce_name(&interest.name).expect("an announce name");
    (interest, digest)
}

fn hashed() -> usize {
    ANNOUNCE_HASHED.with(|n| n.replace(0))
}

/// The length of an announce's parameters is checked before they are hashed: an Interest of
/// any size costs a length comparison, and only parameters of at most 1 KiB reach the hash.
#[test]
fn oversized_announce_parameters_are_not_hashed() {
    hashed();
    let (big, digest) = announce_of(64 * 1024);
    assert!(announce_params(&big, &digest).is_none());
    assert_eq!(hashed(), 0, "no octet of 64 KiB of parameters was hashed");

    let (edge, digest) = announce_of(1024);
    assert!(announce_params(&edge, &digest).is_some(), "1 KiB is taken");
    let octets = hashed();
    assert!(
        (1024..1024 + 16).contains(&octets),
        "what is hashed is the parameters and their header: {octets}"
    );

    // A wrong digest is refused after the hash, and costs no more than 1 KiB.
    let (small, _) = announce_of(100);
    assert!(announce_params(&small, &[0; 32]).is_none());
    assert!(hashed() < 128);
}
