//! NDN packet types and wire-format codec. Fields decode lazily via `OnceLock`
//! so fast-path operations (e.g. Content Store hits) skip unused fields.
//!
//! `std` (default) — enables `ring` signatures and fragment reassembly.
//! Without it, an allocator is still required.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![allow(missing_docs)]
#![cfg_attr(all(not(feature = "std"), not(target_arch = "wasm32")), no_std)]
#[cfg(all(not(feature = "std"), not(target_arch = "wasm32")))]
extern crate alloc;

pub(crate) mod compat;
pub mod data;
#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
pub mod encode;
pub mod error;
#[cfg(any(feature = "std", feature = "std-wasm"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "std", feature = "std-wasm"))))]
pub mod fragment;
pub mod interest;
pub mod lp;
pub mod meta_info;
pub mod nack;
pub mod name;
pub mod prefix_announcement;
pub mod signature;
pub mod subscription;
#[cfg(any(feature = "std", feature = "std-wasm"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "std", feature = "std-wasm"))))]
pub mod wire;

pub use data::{ContentHashTarget, Data};
#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
pub use encode::random_reflexive_name;
pub use error::PacketError;
pub use interest::{Interest, Selector};
pub use lp::{CachePolicyType, LpHeaders};
pub use meta_info::MetaInfo;
pub use nack::{Nack, NackHeader, NackReason};
pub use name::{Name, NameComponent};
pub use ndn_foundation_types::{Hash, KeyLocator, SignatureValue};
pub use prefix_announcement::PrefixAnnouncement;
pub use signature::{SignatureInfo, SignatureType};
pub use subscription::{
    MAX_PERSISTENT_LIFETIME_SECS, SubscriptionRequest, TLV_SUBSCRIPTION_REQUEST,
};

/// The traceroute hop-identity **wire contract** (G9) — the single source of truth shared
/// by the forwarder's responder (`ndn-engine`) and the `ndn-traceroute` prober
/// (`ndn-tools-core`), so the two can't drift. Lives here (the shared wire crate both
/// depend on) rather than being copy-pasted per repo.
pub mod traceroute_wire {
    /// Name-component value (`32=TRH` keyword) marking a probe whose hop-limit expiry should
    /// draw a hop-identity reply instead of a silent drop.
    pub const TRACEROUTE_KEYWORD: &[u8] = b"TRH";
    /// Magic prefix on a hop-identity reply's Content, distinguishing an intermediate hop's
    /// self-identification from the destination producer's own answer.
    pub const HOP_IDENTITY_MAGIC: &[u8] = b"\xF0HOP";
}

/// True when a TLV-TYPE is *critical* per NDN Packet Format v0.3 `tlv.html`:
/// types 0..31 are grandfathered as critical, otherwise odd is critical.
/// Decoders MUST abort on an unrecognized critical TLV at any body level.
pub fn is_critical_tlv_type(typ: u64) -> bool {
    typ <= 31 || (typ & 1) == 1
}

/// Decode a NonNegativeInteger TLV value per NDN Packet Format v0.3 `tlv.html`:
/// width MUST be 1, 2, 4, or 8 octets (big-endian). Any other width returns
/// `PacketError::MalformedPacket`.
pub fn decode_nni(buf: &[u8]) -> Result<u64, PacketError> {
    match buf.len() {
        1 => Ok(buf[0] as u64),
        2 => Ok(u16::from_be_bytes([buf[0], buf[1]]) as u64),
        4 => Ok(u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as u64),
        8 => Ok(u64::from_be_bytes([
            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
        ])),
        other => Err(PacketError::MalformedPacket({
            #[cfg(any(feature = "std", target_arch = "wasm32"))]
            {
                format!("NonNegativeInteger must be 1/2/4/8 octets; got {other}")
            }
            #[cfg(all(not(feature = "std"), not(target_arch = "wasm32")))]
            {
                let _ = other;
                alloc::string::String::from("NonNegativeInteger must be 1/2/4/8 octets")
            }
        })),
    }
}

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
    /// Provisional experimental type for `SubscriptionRequest` inside
    /// `ApplicationParameters`. Even (non-critical) so forwarders that do not
    /// implement this extension silently ignore it.
    pub const SUBSCRIPTION_REQUEST: u64 = 0x230;

    /// Provisional experimental type for the reflexive-forwarding name
    /// (`draft-oran-icnrg-reflexive-forwarding`). A top-level Interest element
    /// whose value is a `Name` TLV: the unpredictable reverse-routable prefix a
    /// producer Interests back along to reach the consumer. Even (non-critical)
    /// so forwarders that do not implement reflexive forwarding ignore it and
    /// treat the Interest normally.
    pub const REFLEXIVE_NAME: u64 = 0x0402;

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
