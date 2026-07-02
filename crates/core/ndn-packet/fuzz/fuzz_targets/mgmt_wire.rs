//! Fuzz the NFD management wire codecs — these parse attacker-reachable
//! mgmt Interests/datasets. Invariant: Ok/Err/None on ANY input, never panic.
//!
//! Run: cargo +nightly fuzz run mgmt_wire
#![no_main]

use libfuzzer_sys::fuzz_target;
use ndn_mgmt_wire::{ControlParameters, ControlResponse};

fuzz_target!(|data: &[u8]| {
    let b = bytes::Bytes::copy_from_slice(data);
    let _ = ControlParameters::decode(b.clone());
    let _ = ControlParameters::decode_value(b.clone());
    let _ = ControlParameters::decode_all(data);
    let _ = ControlResponse::decode(b.clone());
    let _ = ControlResponse::decode_value(b);

    // Command-name parsing over a decoded Name (the mgmt dispatch path).
    if let Ok(name) = ndn_packet::Name::decode(bytes::Bytes::copy_from_slice(data)) {
        let _ = ndn_mgmt_wire::parse_command_name(&name);
    }
});
