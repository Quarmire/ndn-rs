//! Fuzz Name wire decode and URI parsing. Invariants:
//! - decode/parse return Ok/Err on ANY input — never panic;
//! - a successfully parsed URI is a canonical fixed point: rendering and
//!   re-parsing it yields the same Name (idempotence).
//!
//! Run: cargo +nightly fuzz run name
#![no_main]

use libfuzzer_sys::fuzz_target;
use ndn_packet::Name;

fuzz_target!(|data: &[u8]| {
    // Wire decode never panics.
    let _ = Name::decode(bytes::Bytes::copy_from_slice(data));

    // URI parse never panics; on success, render→reparse is idempotent.
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(name) = text.parse::<Name>() {
            let rendered = name.to_string();
            let reparsed: Name = rendered
                .parse()
                .expect("canonical rendering must reparse");
            assert_eq!(name, reparsed, "URI render→reparse must be idempotent");
        }
    }
});
