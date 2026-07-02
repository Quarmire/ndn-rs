//! Fuzz the radiotap RX-header parser. Invariant: `radiotap::parse` is total —
//! it returns an `Option` for ANY input and must never panic, overflow, or hang
//! (the field walk is bounded by `it_len`, which is itself bounded by the
//! buffer). This guards the alignment/bounds arithmetic in the field walker.
//!
//! Run: cargo +nightly fuzz run radiotap
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The property is total termination without panic; the result is ignored.
    let _ = ndn_frame_io::radiotap::parse(data);
});
