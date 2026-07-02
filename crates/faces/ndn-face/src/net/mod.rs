//! IP-based NDN face transports: [`UdpFace`], [`MulticastUdpFace`], and
//! [`TcpFace`]. (WebSocket moved to the `ndn-face-websocket` extension crate.)

#![allow(missing_docs)]

pub mod multicast;
#[cfg(all(feature = "udp-recvmmsg", target_os = "linux"))]
pub mod recvmmsg;
#[cfg(all(feature = "udp-sendmmsg", target_os = "linux"))]
pub mod sendmmsg;
pub mod sockopt;
pub mod tcp;
pub mod udp;

pub mod reliability {
    pub use ndn_transport::reliability::{LpReliability, ReliabilityConfig, RtoStrategy};
}

pub use multicast::MulticastUdpFace;
pub use ndn_packet::fragment::DEFAULT_UDP_MTU;
pub use reliability::{LpReliability, ReliabilityConfig, RtoStrategy};
pub use tcp::{TcpFace, tcp_face_connect, tcp_face_from_stream};
pub use udp::UdpFace;
