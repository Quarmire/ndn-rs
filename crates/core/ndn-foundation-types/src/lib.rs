//! Wire-format primitives shared across the `ndn-rs` stack: TLV codec
//! traits, `Name` / `NameComponent`, `KeyLocator`, `SignatureValue`,
//! `Hash`, and the TLV type-number constants for the above.
//!
//! `std` (default off) enables `bytes/std` and `Hash::of` via `sha2`.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]
#![allow(missing_docs)]

// `alloc` is named unconditionally: `name.rs` and `key_locator.rs` use
// `alloc::` paths in both configs. Unlike `std`/`core`, the bare `alloc` crate
// is not in the extern prelude, so it must be declared even when `std` is on
// (where it is otherwise harmless).
extern crate alloc;

pub mod codec;
pub use codec::{TlvCodecError, TlvDecode, TlvEncode};

/// TLV type numbers per NDN Packet Format v0.3.
pub mod tlv_type {
    pub const NAME: u64 = 0x07;
    pub const GENERIC_NAME_COMPONENT: u64 = 0x08;
    pub const IMPLICIT_SHA256: u64 = 0x01;
    pub const PARAMETERS_SHA256: u64 = 0x02;
    pub const SEGMENT: u64 = 0x32;
    pub const KEYWORD: u64 = 0x20;
    pub const BYTE_OFFSET: u64 = 0x34;
    pub const VERSION: u64 = 0x36;
    pub const TIMESTAMP: u64 = 0x38;
    pub const SEQUENCE_NUM: u64 = 0x3A;
    pub const KEY_LOCATOR: u64 = 0x1c;
    pub const KEY_DIGEST: u64 = 0x1d;
    pub const SIGNATURE_VALUE: u64 = 0x17;
}

pub mod name;
pub use name::{Name, NameComponent};

pub mod hash;
pub use hash::Hash;

pub mod key_locator;
pub use key_locator::KeyLocator;

pub mod signature_value;
pub use signature_value::SignatureValue;
