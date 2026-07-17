//! The reassembly key is `base_seq = sequence - frag_index`, NOT the raw
//! `Sequence` off the wire.
//!
//! `fragment_packet` stamps each fragment with `base_seq + i`, so keying on the
//! raw sequence files every fragment of one packet under a different key: each
//! group then holds exactly 1 of N fragments and never completes. The engine's
//! decode stage gets this right (`stages/decode.rs`, `base_seq = sequence -
//! frag_index`); anything reassembling by hand must do the same.
//!
//! Written 2026-07-16 after `monitor_roundtrip`'s own `decapsulate` was found
//! passing the raw sequence — which made the MTU/goodput bench under-report
//! multi-fragment delivery and nearly got read as a property of the radio.

use bytes::Bytes;
use ndn_packet::fragment::{ReassemblyBuffer, fragment_packet};
use ndn_packet::lp::extract_fragment;
use std::time::Duration;

/// Reassemble `fragments` the way a caller does, keyed by `key_of(sequence,
/// frag_index)`. Returns the recovered packet, if any.
fn reassemble_with(
    fragments: &[Bytes],
    key_of: fn(u64, u64) -> u64,
) -> Option<Bytes> {
    let mut rb = ReassemblyBuffer::new(Duration::from_secs(2));
    let mut out = None;
    for f in fragments {
        let h = extract_fragment(f).expect("multi-fragment LpPacket");
        let frag = f.slice(h.frag_start..h.frag_end);
        if let Some(pkt) = rb.process(
            0,
            key_of(h.sequence, h.frag_index),
            h.frag_index,
            h.frag_count,
            frag,
        ) {
            out = Some(pkt);
        }
    }
    out
}

#[test]
fn base_seq_key_reassembles_and_raw_seq_key_never_does() {
    let packet: Vec<u8> = (0..4000u32).map(|i| (i & 0xff) as u8).collect();
    let fragments = fragment_packet(&packet, 1024, 7_000);
    assert!(
        fragments.len() >= 4,
        "expected a multi-fragment packet, got {}",
        fragments.len()
    );

    // Correct: normalize to the group's base sequence.
    let ok = reassemble_with(&fragments, |seq, idx| seq - idx);
    assert_eq!(
        ok.as_deref(),
        Some(&packet[..]),
        "base_seq keying must recover the original packet"
    );

    // The bug: key on the raw wire sequence. Every fragment lands under its own
    // key, so no group ever fills — with zero frames lost.
    let broken = reassemble_with(&fragments, |seq, _idx| seq);
    assert!(
        broken.is_none(),
        "raw-sequence keying cannot reassemble; if this ever passes, the key \
         normalization moved and this test is measuring nothing"
    );
}

/// **Two packets must not share sequence numbers.**
///
/// `fragment_packet(packet, mtu, base)` stamps `base + i` on fragment `i`, so a
/// packet of `n` fragments consumes `n` sequence numbers. A sender that advances
/// its counter by 1 per *packet* (rather than by `n`) therefore overlaps the next
/// packet onto the sequences it just used.
///
/// Reassembly-by-base still separates them, which is why this stayed latent. But
/// the wire then carries two different fragments bearing the same `Sequence`,
/// which NDNLPv2 requires to be unique per link — it is what `LpReliability`
/// Acks/TxSequence reference, so acks become ambiguous. And a receiver keying on
/// the raw sequence does not merely fail: it *silently assembles a packet out of
/// two different ones*, as the second half of this test shows.
#[test]
fn overlapping_sequences_assemble_a_frankenstein_packet() {
    // Two 2-fragment packets, distinguishable byte-for-byte.
    let a: Vec<u8> = vec![0xAA; 1500];
    let b: Vec<u8> = vec![0xBB; 1500];
    const MTU: usize = 1024;

    // A sender advancing by 1 per packet: A gets base 0, B gets base 1.
    let fa = fragment_packet(&a, MTU, 0);
    let fb = fragment_packet(&b, MTU, 1);
    assert_eq!(fa.len(), 2);
    assert_eq!(fb.len(), 2);

    // Correct keying keeps them apart even under the overlap.
    let mut rb = ReassemblyBuffer::new(Duration::from_secs(2));
    let mut recovered = Vec::new();
    for f in fa.iter().chain(fb.iter()) {
        let h = extract_fragment(f).unwrap();
        if let Some(pkt) = rb.process(0, h.sequence - h.frag_index, h.frag_index, h.frag_count, f.slice(h.frag_start..h.frag_end)) {
            recovered.push(pkt);
        }
    }
    assert_eq!(recovered.len(), 2, "base_seq keying recovers both packets");
    assert_eq!(recovered[0].as_ref(), &a[..], "first packet intact");
    assert_eq!(recovered[1].as_ref(), &b[..], "second packet intact");

    // Raw-sequence keying under the same overlap. A.f1 (seq 1, idx 1) and B.f0
    // (seq 1, idx 0) collide on key 1 — and together they look "complete".
    let mut rb = ReassemblyBuffer::new(Duration::from_secs(2));
    let mut mixed = Vec::new();
    for f in fa.iter().chain(fb.iter()) {
        let h = extract_fragment(f).unwrap();
        if let Some(pkt) = rb.process(0, h.sequence, h.frag_index, h.frag_count, f.slice(h.frag_start..h.frag_end)) {
            mixed.push(pkt);
        }
    }
    assert_eq!(
        mixed.len(),
        1,
        "the collision completes a group that was never sent"
    );
    let franken = &mixed[0];
    assert!(
        franken.iter().any(|&x| x == 0xAA) && franken.iter().any(|&x| x == 0xBB),
        "the assembled packet is stitched from BOTH packets: {} 0xAA bytes, {} 0xBB bytes",
        franken.iter().filter(|&&x| x == 0xAA).count(),
        franken.iter().filter(|&&x| x == 0xBB).count(),
    );
    assert_ne!(franken.as_ref(), &a[..]);
    assert_ne!(franken.as_ref(), &b[..]);
}

/// A single-fragment packet has no FragCount > 1, so `extract_fragment` declines
/// it and the caller takes its non-fragmented path. This is why the bug hid: an
/// object small enough for one frame was unaffected, and only multi-fragment
/// objects — the exact ones the bulk argument was about — silently failed.
#[test]
fn single_fragment_packet_is_not_a_fragment_group() {
    let packet: Vec<u8> = (0..200u32).map(|i| (i & 0xff) as u8).collect();
    let fragments = fragment_packet(&packet, 1024, 9_000);
    assert_eq!(fragments.len(), 1);
    assert!(
        extract_fragment(&fragments[0]).is_none(),
        "a 1-fragment LpPacket must not present as a fragment group"
    );
}
