//! Fuzz the per-format 802.11 body parser. Invariant: `frame::parse_dot11` is
//! total for EVERY `FrameFormat` — it returns an `Option` on ANY bytes and must
//! never panic (no out-of-bounds slice, no arithmetic overflow) regardless of
//! format, RSSI, or MCS hint. Every variant (RawNdn, EspNow, Wfb,
//! HaLowVendorAction, Raw80211) is exercised on each input.
//!
//! Run: cargo +nightly fuzz run dot11
#![no_main]

use libfuzzer_sys::fuzz_target;
use ndn_frame_io::FrameFormat;
use ndn_frame_io::frame::parse_dot11;

fuzz_target!(|data: &[u8]| {
    // Spend the first 4 bytes as fuzzer-controlled knobs (ethertype / OUI bytes
    // and the two Option hints), leaving the rest as the 802.11 body — so the
    // fuzzer can steer the format params and the RSSI/MCS presence itself.
    let (ctrl, body) = if data.len() >= 4 {
        (&data[..4], &data[4..])
    } else {
        (data, &data[data.len()..])
    };
    let g = |i: usize| ctrl.get(i).copied().unwrap_or(0);

    let ethertype = u16::from_be_bytes([g(0), g(1)]);
    let oui = [g(0), g(1), g(2)];
    let rssi = if g(3) & 0x01 != 0 {
        Some(g(2) as i8)
    } else {
        None
    };
    let mcs = if g(3) & 0x02 != 0 {
        Some(g(3) >> 2)
    } else {
        None
    };

    for fmt in [
        FrameFormat::RawNdn { ethertype },
        FrameFormat::EspNow { oui },
        FrameFormat::Wfb,
        FrameFormat::HaLowVendorAction,
        FrameFormat::Raw80211,
    ] {
        let _ = parse_dot11(fmt, body, rssi, mcs);
    }
});
