//! `ndn-transport` — async face abstraction and supporting types.
//!
//! `Face = Transport + LinkService`. `Transport` ships wire bytes per
//! physical/IPC channel; `LinkService` owns NDNLPv2 framing, IncomingFaceId,
//! and congestion-mark policy. `FaceTable` is the runtime registry of
//! type-erased faces, keyed by monotonic `FaceId`. `StreamFace` and
//! `TlvCodec` are the generic stream + framing building blocks.
//!
//! `serde` (off) — derives `Serialize`/`Deserialize` on select types.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![allow(missing_docs)]

pub mod any_map;
pub mod congestion;
pub mod face;
pub mod face_event;
pub mod face_options;
pub mod face_pair_table;
pub mod face_sink;
pub mod face_table;
pub mod forwarding;
pub mod link_profile;
pub mod link_service;
pub mod mac_addr;
pub mod raw_packet;
pub mod reliability;
pub mod stream_face;
pub mod tls;
pub mod tlv_codec;
pub mod transport;

pub use ndn_packet::fragment::DEFAULT_UDP_MTU;

pub use any_map::AnyMap;
pub use congestion::CongestionController;
pub use face::{
    CongestionPolicy, Face, FaceAddr, FaceError, FaceId, FaceKind, FacePersistency, FaceScope,
    LinkType, ip_face_uri,
};
pub use face_event::{FaceEvent, FaceLifecycleSink};
pub use face_options::{
    BIT_CONGESTION_MARKING, BIT_LOCAL_FIELDS, BIT_LP_RELIABILITY, FaceOption, FaceOptionError,
    FaceOptions, NFD_FLAG_BITS,
};
pub use face_pair_table::FacePairTable;
pub use face_sink::FaceSink;
pub use face_table::{FaceInfo, FaceTable};
pub use forwarding::{ForwardingAction, NackReason};
pub use link_profile::LinkProfile;
pub use link_service::{
    LinkService, LinkServiceFrame, LpLinkService, PassthroughLinkService,
    default_link_service_for_kind,
};
pub use mac_addr::MacAddr;
pub use ndn_packet::ContentHashTarget;
pub use raw_packet::RawPacket;
pub use stream_face::StreamFace;
pub use tls::ClientTls;
pub use tlv_codec::TlvCodec;
pub use transport::{ErasedTransport, MtuError, PersistencyError, Transport};
