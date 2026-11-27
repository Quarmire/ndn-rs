use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use ndn_packet::Name;
use ndn_transport::{FaceError, FaceId, FaceKind, MtuError, SideClass, SideRefused, Transport};
use tokio::io::unix::AsyncFd;

use super::af_packet::{MacAddr, get_ifindex, open_packet_socket, setup_packet_ring};
use super::port::{AfPacketPort, EtherPort};
use super::radio::RadioFaceMetadata;
use super::{ETHER_PAYLOAD_MTU, check_side_frame, clamp_ether_mtu};
use crate::NDN_ETHERTYPE;

/// NDN face over raw Ethernet (`AF_PACKET` `SOCK_DGRAM` + TPACKET_V2 mmap'd
/// ring). The kernel strips/builds the Ethernet header, so I/O is the NDN
/// TLV payload only. Requires `CAP_NET_RAW`.
///
/// Generic over its [`EtherPort`] so that the side path (channel frames) is
/// the same code over the kernel ring and over a test bus; every caller uses
/// the default, [`AfPacketPort`].
pub struct NamedEtherFace<P: EtherPort = AfPacketPort> {
    id: FaceId,
    pub node_name: Name,
    peer_mac: MacAddr,
    iface: String,
    pub radio: RadioFaceMetadata,
    port: P,
    mtu: AtomicUsize,
}

impl NamedEtherFace {
    pub fn new(
        id: FaceId,
        node_name: Name,
        peer_mac: MacAddr,
        iface: impl Into<String>,
        radio: RadioFaceMetadata,
    ) -> std::io::Result<Self> {
        let iface = iface.into();

        let probe_fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                NDN_ETHERTYPE.to_be() as i32,
            )
        };
        if probe_fd == -1 {
            return Err(std::io::Error::last_os_error());
        }
        let ifindex = {
            let idx = get_ifindex(probe_fd, &iface);
            unsafe {
                libc::close(probe_fd);
            }
            idx?
        };

        let fd = open_packet_socket(ifindex, NDN_ETHERTYPE)?;

        let ring = setup_packet_ring(fd.as_raw_fd())?;
        let socket = AsyncFd::new(fd)?;

        Ok(Self::with_port(
            id,
            node_name,
            peer_mac,
            iface,
            radio,
            AfPacketPort {
                ifindex,
                socket,
                ring,
            },
        ))
    }
}

impl<P: EtherPort> NamedEtherFace<P> {
    /// A face over `port`, sending to `peer_mac`.
    pub fn with_port(
        id: FaceId,
        node_name: Name,
        peer_mac: MacAddr,
        iface: impl Into<String>,
        radio: RadioFaceMetadata,
        port: P,
    ) -> Self {
        Self {
            id,
            node_name,
            peer_mac,
            iface: iface.into(),
            radio,
            port,
            mtu: AtomicUsize::new(ETHER_PAYLOAD_MTU),
        }
    }

    pub fn set_peer_mac(&mut self, mac: MacAddr) {
        self.peer_mac = mac;
    }

    pub fn peer_mac(&self) -> MacAddr {
        self.peer_mac
    }

    pub fn iface(&self) -> &str {
        &self.iface
    }
}

impl<P: EtherPort> Transport for NamedEtherFace<P> {
    fn id(&self) -> FaceId {
        self.id
    }
    fn kind(&self) -> FaceKind {
        FaceKind::Ethernet
    }

    fn remote_uri(&self) -> Option<String> {
        Some(format!("ether://[{}]/{}", self.peer_mac, self.iface))
    }

    fn local_uri(&self) -> Option<String> {
        Some(format!("dev://{}", self.iface))
    }

    fn send_mtu(&self) -> Option<usize> {
        Some(self.mtu.load(Ordering::Relaxed))
    }

    /// A channel frame is one Ethernet payload, never fragmented.
    fn side_frame_max(&self) -> usize {
        self.mtu.load(Ordering::Relaxed)
    }

    /// An Ethernet segment is no ordered, reliable stream: only the datagram class.
    fn side_carries(&self, class: SideClass) -> bool {
        class == SideClass::Datagram
    }

    /// Hand a channel frame to the send queue for the peer without waiting: a
    /// frame that is not a channel frame is
    /// [`Malformed`](SideRefused::Malformed), one over the MTU
    /// [`TooLarge`](SideRefused::TooLarge) (never fragmented), and a queue with
    /// no room [`Full`](SideRefused::Full) (the caller drops the frame and counts
    /// it). Only the datagram class exists on Ethernet: the stream class is
    /// [`NotCarried`](SideRefused::NotCarried), so a reliable channel is not
    /// silently carried by a lossy hop. A NIC pads a payload under 46 octets, so
    /// the receiver sees a shorter frame with trailing zero octets: a frame this
    /// face is given must be self-delimiting or at least
    /// [`MIN_FRAME_LEN`](ndn_transport::side_header::MIN_FRAME_LEN) octets, which
    /// the channel codec guarantees; the face sends what it is given.
    fn forward_side(&self, frame: Bytes, class: SideClass) -> Result<(), SideRefused> {
        check_side_frame(&frame, class, self.side_frame_max())?;
        if !self.port.try_push_tx(&frame, &self.peer_mac) {
            return Err(SideRefused::Full);
        }
        self.port
            .flush_tx()
            .map_err(|e| SideRefused::Io(e.to_string()))
    }

    /// Whether the port's send queue has a slot for a frame: what `forward_side` reads first.
    fn side_room(&self, class: SideClass) -> bool {
        class != SideClass::Datagram || self.port.has_tx_room()
    }

    fn set_send_mtu(&self, mtu: Option<u64>) -> Result<Option<u64>, MtuError> {
        let new = clamp_ether_mtu(mtu)?;
        self.mtu.store(new, Ordering::Relaxed);
        Ok(Some(new as u64))
    }

    /// Only the named peer's frames: on a shared segment any station can address this
    /// station's MAC, and a unicast face stands for one peer, not for the segment. A frame whose
    /// source is another station is dropped here, before the forwarder sees it (as on macOS and
    /// Windows), so a third station cannot speak as this face (forge an `UP` for a sink, send
    /// frames of a route this face sources).
    async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
        loop {
            while let Some((pkt, src)) = self.port.try_pop_rx() {
                if src == self.peer_mac {
                    return Ok(pkt);
                }
            }
            self.port.readable().await?;
        }
    }

    async fn send_bytes(&self, pkt: Bytes) -> Result<(), FaceError> {
        loop {
            if self.port.try_push_tx(&pkt, &self.peer_mac) {
                break;
            }
            self.port.writable().await?;
        }
        self.port.flush_tx()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[tokio::test]
    async fn new_fails_without_cap_net_raw() {
        let name = Name::from_str("/test/node").unwrap();
        let result = NamedEtherFace::new(
            FaceId(1),
            name,
            MacAddr::BROADCAST,
            "lo",
            RadioFaceMetadata::default(),
        );
        if let Err(e) = result {
            let raw = e.raw_os_error().unwrap_or(0);
            assert!(
                raw == libc::EPERM || raw == libc::EACCES,
                "expected EPERM or EACCES, got: {e}"
            );
        }
    }

    #[tokio::test]
    #[ignore = "requires CAP_NET_RAW"]
    async fn loopback_roundtrip() {
        let name = Name::from_str("/test/node").unwrap();
        let lo_mac = MacAddr::new([0; 6]);
        let face_a = NamedEtherFace::new(
            FaceId(1),
            name.clone(),
            lo_mac,
            "lo",
            RadioFaceMetadata::default(),
        )
        .expect("need CAP_NET_RAW");
        let face_b =
            NamedEtherFace::new(FaceId(2), name, lo_mac, "lo", RadioFaceMetadata::default())
                .expect("need CAP_NET_RAW");

        let pkt = Bytes::from_static(b"\x05\x03\x01\x02\x03");
        face_a.send_bytes(pkt.clone()).await.unwrap();

        let received = tokio::time::timeout(std::time::Duration::from_secs(2), face_b.recv_bytes())
            .await
            .expect("timed out")
            .unwrap();

        assert_eq!(received, pkt);
    }
}
