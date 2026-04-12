//! # ndn-transport -- Face abstraction and transport layer
//!
//! Provides the async face abstraction over which NDN packets are sent and
//! received, plus supporting types for face management and framing.
//!
//! ## Key types
//!
//! - [`Face`] trait -- async `send`/`recv` interface implemented by all transports.
//! - [`FaceId`] / [`FaceKind`] -- face identity and classification (UDP, TCP, etc.).
//! - [`FaceTable`] / [`ErasedFace`] -- runtime registry of type-erased faces.
//! - [`StreamFace`] -- generic `AsyncRead`+`AsyncWrite` face (TCP, Unix, etc.).
//! - [`TlvCodec`] -- `tokio_util::codec` framing for TLV streams.
//! - [`RawPacket`] -- thin wrapper pairing raw `Bytes` with a source [`FaceId`].
//! - [`CongestionController`] -- per-face congestion window management.
//!
//! ## Feature flags
//!
//! - **`serde`** -- derives `Serialize`/`Deserialize` on select types.

#![allow(missing_docs)]

pub mod any_map;
pub mod congestion;
pub mod face;
pub mod face_event;
pub mod face_pair_table;
pub mod face_table;
pub mod forwarding;
pub mod mac_addr;
pub mod raw_packet;
pub mod stream_face;
pub mod tlv_codec;

pub use any_map::AnyMap;
pub use congestion::CongestionController;
pub use face::{Face, FaceAddr, FaceError, FaceId, FaceKind, FacePersistency, FaceScope, LinkType};
pub use forwarding::{ForwardingAction, NackReason};
pub use mac_addr::MacAddr;
pub use face_event::FaceEvent;
pub use face_pair_table::FacePairTable;
pub use face_table::{ErasedFace, FaceInfo, FaceTable};
pub use raw_packet::RawPacket;
pub use stream_face::StreamFace;
pub use tlv_codec::TlvCodec;
