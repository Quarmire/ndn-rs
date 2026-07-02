//! Fuzz the raw TLV layer. Invariant: TlvReader terminates with Ok/Err on ANY
//! input — never panics, never loops forever (fuel-bounded), never
//! over-allocates (guards the W-1 huge-length fixes).
//!
//! Run: cargo +nightly fuzz run tlv
#![no_main]

use libfuzzer_sys::fuzz_target;
use ndn_tlv::{TlvReader, read_varu64};

fuzz_target!(|data: &[u8]| {
    let _ = read_varu64(data);

    let mut reader = TlvReader::new(bytes::Bytes::copy_from_slice(data));
    // Each successful read_tlv consumes >= 2 bytes, so remaining() strictly
    // decreases; fuel is a belt-and-braces bound against a stuck reader.
    let mut fuel = data.len() + 1;
    while !reader.is_empty() && fuel > 0 {
        if reader.read_tlv().is_err() {
            break;
        }
        fuel -= 1;
    }
    assert!(fuel > 0 || reader.is_empty(), "TlvReader failed to progress");
});
