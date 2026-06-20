//! Fuzz the public decode entry points (audit P-3). The invariant: decode must
//! return Ok/Err for ANY input — never panic, hang, or over-allocate. Guards the
//! W-1/W-2 bounds fixes and hunts for new parser bugs.
//!
//! Run: cargo +nightly fuzz run decode
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let b = bytes::Bytes::copy_from_slice(data);
    let _ = ndn_packet::Interest::decode(b.clone());
    let _ = ndn_packet::Data::decode(b.clone());
    let _ = ndn_packet::lp::LpPacket::decode(b);
});
