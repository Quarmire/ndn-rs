//! Stage-1 gate for the reliability consolidation (item 2 of
//! `.claude/notes/per-face-option-wiring-triage-2026-05-23.md`).
//!
//! Two deterministic, in-process tests that pin the reliability *contract* the
//! consolidation must satisfy — before any framing/integration change:
//!
//! 1. `canonical_core_recovers_loss` — the spec-canonical `LpReliability` core
//!    (store C's `on_send`) frames with a `TxSequence`, the receiver Acks, and a
//!    dropped frame is recovered by retransmission. **Green today; must stay
//!    green** through every refactor stage (the don't-break-reliability gate).
//!
//! 2. `feature_frame_emits_tx_sequence` — the `ReliabilityFeature` (the
//!    consolidation *target*) frames egress canonically via `frame()`, putting a
//!    `TxSequence` on the wire so the peer can Ack — exactly like the core. (The
//!    pre-consolidation `on_egress`/`on_send_track` path injected no TxSequence;
//!    that stub is gone.)
//!
//! TxSequence is TLV-TYPE 0x0348 → 3-byte encoding `FD 03 48` (see b01 witness).

use ndn_transport::link_service::ReliabilityFeature;
use ndn_transport::reliability::{LpReliability, ReliabilityConfig, RtoStrategy};

const TX_SEQUENCE_TLV: &[u8] = &[0xFD, 0x03, 0x48];

fn has_tx_sequence(wire: &[u8]) -> bool {
    wire.windows(TX_SEQUENCE_TLV.len())
        .any(|w| w == TX_SEQUENCE_TLV)
}

/// Fixed 1 ms RTO so `check_retransmit` fires after a short sleep — no flake.
fn fast_config() -> ReliabilityConfig {
    ReliabilityConfig {
        rto_strategy: RtoStrategy::Fixed { rto_us: 1_000 },
        ..Default::default()
    }
}

fn fake_packet(tag: u8) -> Vec<u8> {
    // A bare TLV that stands in for an Interest/Data fragment.
    vec![0x05, 0x03, tag, 0xBB, 0xCC]
}

/// GREEN today, must stay green: the canonical core emits TxSequence, the
/// receiver Acks, and a dropped frame is recovered via retransmission.
#[test]
fn canonical_core_recovers_loss() {
    let mut sender = LpReliability::from_config(1400, fast_config());
    let mut receiver = LpReliability::from_config(1400, fast_config());

    // Send three frames; each canonical frame must carry a TxSequence.
    let w0 = sender.on_send(&fake_packet(0));
    let w1 = sender.on_send(&fake_packet(1));
    let w2 = sender.on_send(&fake_packet(2));
    for (i, wires) in [&w0, &w1, &w2].iter().enumerate() {
        assert_eq!(wires.len(), 1, "small packet → one frame");
        assert!(
            has_tx_sequence(&wires[0]),
            "canonical on_send frame {i} must carry a TxSequence (0x0348)"
        );
    }
    assert_eq!(sender.unacked_count(), 3, "all three are outstanding");

    // The link drops frame 1; the receiver gets 0 and 2.
    receiver.on_receive(&w0[0]);
    receiver.on_receive(&w2[0]);

    // Receiver Acks what it got; sender clears those, leaving only frame 1.
    let ack = receiver
        .flush_acks()
        .expect("receiver must Ack received frames");
    sender.on_receive(&ack);
    assert_eq!(
        sender.unacked_count(),
        1,
        "Acks for 0 and 2 clear them; frame 1 stays outstanding"
    );

    // After the RTO, the sender retransmits exactly the dropped frame.
    std::thread::sleep(std::time::Duration::from_millis(5));
    let retx = sender.check_retransmit();
    assert_eq!(retx.len(), 1, "only the dropped frame is retransmitted");
    assert!(
        has_tx_sequence(&retx[0]),
        "retransmission still carries TxSequence"
    );

    // The retransmission gets through; the receiver Acks it; sender drains.
    receiver.on_receive(&retx[0]);
    let ack = receiver
        .flush_acks()
        .expect("receiver Acks the recovered frame");
    sender.on_receive(&ack);
    assert_eq!(
        sender.unacked_count(),
        0,
        "loss fully recovered — nothing outstanding"
    );
}

/// The reliability feature must frame egress canonically — emitting a
/// TxSequence so the peer can Ack — exactly like the core. The send loop calls
/// `frame()` (not the inert `on_egress`) when reliability is enabled.
#[test]
fn feature_frame_emits_tx_sequence() {
    let feature = ReliabilityFeature::with_config(fast_config());
    feature.set_enabled(true);

    let frames = feature.frame(&fake_packet(7));
    assert_eq!(frames.len(), 1, "small packet → one reliable frame");
    assert!(
        has_tx_sequence(&frames[0]),
        "ReliabilityFeature::frame must emit a TxSequence (0x0348) so the peer \
         can Ack. Wire: {:02x?}",
        frames[0]
    );
}
