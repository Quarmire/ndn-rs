// Enable no_std when the `std` feature is disabled.
// The crate requires an allocator (Name uses SmallVec, Bytes uses heap).
#![cfg_attr(not(feature = "std"), no_std)]
#[cfg(not(feature = "std"))]
extern crate alloc;

pub mod error;
pub mod name;
pub mod interest;
pub mod data;
pub mod nack;
pub mod meta_info;
pub mod signature;
pub mod encode;
pub mod lp;

pub use error::PacketError;
pub use name::{Name, NameComponent};
pub use interest::{Interest, Selector};
pub use data::Data;
pub use nack::{Nack, NackReason};
pub use meta_info::MetaInfo;
pub use signature::{SignatureInfo, SignatureType};

/// Well-known NDN TLV type codes.
pub mod tlv_type {
    pub const INTEREST:         u64 = 0x05;
    pub const DATA:             u64 = 0x06;
    pub const NAME:             u64 = 0x07;
    pub const NAME_COMPONENT:   u64 = 0x08;
    pub const IMPLICIT_SHA256:  u64 = 0x01;
    pub const PARAMETERS_SHA256: u64 = 0x02;
    pub const CAN_BE_PREFIX:    u64 = 0x21;
    pub const MUST_BE_FRESH:    u64 = 0x12;
    pub const FORWARDING_HINT:  u64 = 0x1e;
    pub const NONCE:            u64 = 0x0a;
    pub const INTEREST_LIFETIME: u64 = 0x0c;
    pub const HOP_LIMIT:        u64 = 0x22;
    pub const APP_PARAMETERS:   u64 = 0x24;
    pub const META_INFO:        u64 = 0x14;
    pub const CONTENT:          u64 = 0x15;
    pub const SIGNATURE_INFO:   u64 = 0x16;
    pub const SIGNATURE_VALUE:  u64 = 0x17;
    pub const CONTENT_TYPE:     u64 = 0x18;
    pub const FRESHNESS_PERIOD: u64 = 0x19;
    pub const FINAL_BLOCK_ID:   u64 = 0x1a;
    pub const SIGNATURE_TYPE:   u64 = 0x1b;
    pub const KEY_LOCATOR:      u64 = 0x1c;
    pub const KEY_DIGEST:       u64 = 0x1d;
    pub const NACK:             u64 = 0x0320;
    pub const NACK_REASON:      u64 = 0x0321;

    // NDNLPv2 types
    pub const LP_PACKET:        u64 = 0x64;
    pub const LP_FRAGMENT:      u64 = 0x50;
    pub const LP_SEQUENCE:      u64 = 0x51;
    pub const LP_FRAG_INDEX:    u64 = 0x52;
    pub const LP_FRAG_COUNT:    u64 = 0x53;
    pub const LP_CONGESTION_MARK: u64 = 0x0340;

    // Signed Interest (NDN Packet Format v0.3 §5.4)
    pub const INTEREST_SIGNATURE_INFO:  u64 = 0x2C;
    pub const INTEREST_SIGNATURE_VALUE: u64 = 0x2E;
    pub const SIGNATURE_NONCE:          u64 = 0x26;
    pub const SIGNATURE_TIME:           u64 = 0x28;
    pub const SIGNATURE_SEQ_NUM:        u64 = 0x2A;
}
