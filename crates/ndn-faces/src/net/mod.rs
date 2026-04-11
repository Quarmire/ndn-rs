//! # `ndn_faces::net` — Network transport faces
//!
//! IP-based face implementations for communicating with remote NDN nodes over
//! UDP, TCP, multicast UDP, and WebSocket transports.
//!
//! ## Key types
//!
//! - [`UdpFace`] — unicast UDP face
//! - [`MulticastUdpFace`] — multicast UDP face for link-local discovery
//! - [`TcpFace`] — stream-oriented TCP face
//! - [`WebSocketFace`] — WebSocket face (requires the `websocket` feature, enabled by default)
//! - [`LpReliability`] — NDNLPv2 reliability/retransmission layer

#![allow(missing_docs)]

pub mod multicast;
pub mod reliability;
pub mod tcp;
pub mod udp;

#[cfg(feature = "websocket")]
pub mod websocket;

pub use multicast::MulticastUdpFace;
pub use ndn_packet::fragment::DEFAULT_UDP_MTU;
pub use reliability::{LpReliability, ReliabilityConfig, RtoStrategy};
pub use tcp::{TcpFace, tcp_face_connect, tcp_face_from_stream};
pub use udp::UdpFace;

#[cfg(feature = "websocket")]
pub use websocket::WebSocketFace;

#[cfg(feature = "websocket-tls")]
pub use websocket::{TlsConfig, TlsWebSocketFace, WebSocketListener};
