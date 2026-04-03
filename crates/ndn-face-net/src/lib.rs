pub mod udp;
pub mod tcp;
pub mod multicast;
pub mod reliability;

#[cfg(feature = "websocket")]
pub mod websocket;

pub use udp::UdpFace;
pub use tcp::{TcpFace, tcp_face_from_stream, tcp_face_connect};
pub use multicast::MulticastUdpFace;
pub use ndn_packet::fragment::DEFAULT_UDP_MTU;
pub use reliability::{LpReliability, ReliabilityConfig, RtoStrategy};

#[cfg(feature = "websocket")]
pub use websocket::WebSocketFace;
