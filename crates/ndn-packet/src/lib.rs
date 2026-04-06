//! # ndn-packet -- NDN packet types and wire-format codec
//!
//! Defines the core NDN packet structures and their TLV serialization.
//! Fields are decoded lazily via `OnceLock` so that fast-path operations
//! (e.g. Content Store hits) avoid parsing unused fields.
//!
//! ## Key types
//!
//! - [`Name`] / [`NameComponent`] -- NDN hierarchical names (`SmallVec`-backed).
//! - [`Interest`] -- Interest packet with lazy decode and optional [`Selector`].
//! - [`Data`] -- Data packet carrying content, [`MetaInfo`], and [`SignatureInfo`].
//! - [`Nack`] / [`NackReason`] -- Network-layer negative acknowledgement.
//! - [`LpHeaders`] -- NDNLPv2 link-protocol header fields.
//!
//! ## Feature flags
//!
//! - **`std`** (default) -- enables `ring` signatures and fragment reassembly.
//!   Disable for `no_std` environments (an allocator is still required).

#![allow(missing_docs)]
// Enable no_std when the `std` feature is disabled.
// The crate requires an allocator (Name uses SmallVec, Bytes uses heap).
#![cfg_attr(not(feature = "std"), no_std)]
#[cfg(not(feature = "std"))]
extern crate alloc;

pub mod data;
#[cfg(feature = "std")]
pub mod encode;
pub mod error;
#[cfg(feature = "std")]
pub mod fragment;
pub mod interest;
pub mod lp;
pub mod meta_info;
pub mod nack;
pub mod name;
pub mod signature;

pub use data::Data;
pub use error::PacketError;
pub use interest::{Interest, Selector};
pub use lp::{CachePolicyType, LpHeaders};
pub use meta_info::MetaInfo;
pub use nack::{Nack, NackReason};
pub use name::{Name, NameComponent};
pub use signature::{SignatureInfo, SignatureType};

/// Well-known NDN TLV type codes.
pub mod tlv_type {
    pub const INTEREST: u64 = 0x05;
    pub const DATA: u64 = 0x06;
    pub const NAME: u64 = 0x07;
    pub const NAME_COMPONENT: u64 = 0x08;
    pub const IMPLICIT_SHA256: u64 = 0x01;
    pub const PARAMETERS_SHA256: u64 = 0x02;
    pub const SEGMENT: u64 = 0x32;
    pub const KEYWORD: u64 = 0x20;
    pub const BYTE_OFFSET: u64 = 0x34;
    pub const VERSION: u64 = 0x36;
    pub const TIMESTAMP: u64 = 0x38;
    pub const SEQUENCE_NUM: u64 = 0x3A;
    pub const CAN_BE_PREFIX: u64 = 0x21;
    pub const MUST_BE_FRESH: u64 = 0x12;
    pub const FORWARDING_HINT: u64 = 0x1e;
    pub const NONCE: u64 = 0x0a;
    pub const INTEREST_LIFETIME: u64 = 0x0c;
    pub const HOP_LIMIT: u64 = 0x22;
    pub const APP_PARAMETERS: u64 = 0x24;
    pub const META_INFO: u64 = 0x14;
    pub const CONTENT: u64 = 0x15;
    pub const SIGNATURE_INFO: u64 = 0x16;
    pub const SIGNATURE_VALUE: u64 = 0x17;
    pub const CONTENT_TYPE: u64 = 0x18;
    pub const FRESHNESS_PERIOD: u64 = 0x19;
    pub const FINAL_BLOCK_ID: u64 = 0x1a;
    pub const SIGNATURE_TYPE: u64 = 0x1b;
    pub const KEY_LOCATOR: u64 = 0x1c;
    pub const KEY_DIGEST: u64 = 0x1d;
    pub const NACK: u64 = 0x0320;
    pub const NACK_REASON: u64 = 0x0321;

    // NDNLPv2 types
    pub const LP_PACKET: u64 = 0x64;
    pub const LP_FRAGMENT: u64 = 0x50;
    pub const LP_SEQUENCE: u64 = 0x51;
    pub const LP_FRAG_INDEX: u64 = 0x52;
    pub const LP_FRAG_COUNT: u64 = 0x53;
    pub const LP_PIT_TOKEN: u64 = 0x62;
    pub const LP_CONGESTION_MARK: u64 = 0x0340;
    pub const LP_ACK: u64 = 0x0344;
    pub const LP_TX_SEQUENCE: u64 = 0x0348;
    pub const LP_NON_DISCOVERY: u64 = 0x034C;
    pub const LP_PREFIX_ANNOUNCEMENT: u64 = 0x0350;
    pub const LP_INCOMING_FACE_ID: u64 = 0x032C;
    pub const LP_NEXT_HOP_FACE_ID: u64 = 0x0330;
    pub const LP_CACHE_POLICY: u64 = 0x0334;
    pub const LP_CACHE_POLICY_TYPE: u64 = 0x0335;

    // Certificate (NDN Packet Format v0.3 §10)
    pub const VALIDITY_PERIOD: u64 = 0xFD;
    pub const NOT_BEFORE: u64 = 0xFE;
    pub const NOT_AFTER: u64 = 0xFF;
    pub const ADDITIONAL_DESCRIPTION: u64 = 0x0102;
    pub const DESCRIPTION_ENTRY: u64 = 0x0200;
    pub const DESCRIPTION_KEY: u64 = 0x0201;
    pub const DESCRIPTION_VALUE: u64 = 0x0202;

    // Signed Interest (NDN Packet Format v0.3 §5.4)
    pub const INTEREST_SIGNATURE_INFO: u64 = 0x2C;
    pub const INTEREST_SIGNATURE_VALUE: u64 = 0x2E;
    pub const SIGNATURE_NONCE: u64 = 0x26;
    pub const SIGNATURE_TIME: u64 = 0x28;
    pub const SIGNATURE_SEQ_NUM: u64 = 0x2A;
}
