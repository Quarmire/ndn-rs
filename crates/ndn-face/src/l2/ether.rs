use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use ndn_packet::Name;
use ndn_transport::{FaceError, FaceId, FaceKind, MtuError, Transport};
use tokio::io::unix::AsyncFd;

use super::af_packet::{
    MacAddr, PacketRing, get_ifindex, make_sockaddr_ll, open_packet_socket, setup_packet_ring,
};
use super::radio::RadioFaceMetadata;
use super::{ETHER_PAYLOAD_MTU, clamp_ether_mtu};
use crate::NDN_ETHERTYPE;

/// NDN face over raw Ethernet (`AF_PACKET` `SOCK_DGRAM` + TPACKET_V2 mmap'd
/// ring). The kernel strips/builds the Ethernet header, so I/O is the NDN
/// TLV payload only. Requires `CAP_NET_RAW`.
pub struct NamedEtherFace {
    id: FaceId,
    pub node_name: Name,
    peer_mac: MacAddr,
    iface: String,
    ifindex: i32,
    pub radio: RadioFaceMetadata,
    socket: AsyncFd<std::os::unix::io::OwnedFd>,
    ring: PacketRing,
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

        Ok(Self {
            id,
            node_name,
            peer_mac,
            iface,
            ifindex,
            radio,
            socket,
            ring,
            mtu: AtomicUsize::new(ETHER_PAYLOAD_MTU),
        })
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

impl Transport for NamedEtherFace {
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

    fn set_send_mtu(&self, mtu: Option<u64>) -> Result<Option<u64>, MtuError> {
        let new = clamp_ether_mtu(mtu)?;
        self.mtu.store(new, Ordering::Relaxed);
        Ok(Some(new as u64))
    }

    async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
        loop {
            if let Some(pkt) = self.ring.try_pop_rx() {
                return Ok(pkt);
            }
            let mut guard = self.socket.readable().await?;
            guard.clear_ready();
        }
    }

    async fn send_bytes(&self, pkt: Bytes) -> Result<(), FaceError> {
        loop {
            if self.ring.try_push_tx(&pkt) {
                break;
            }
            let mut guard = self.socket.writable().await?;
            guard.clear_ready();
        }

        let dst = make_sockaddr_ll(self.ifindex, &self.peer_mac, NDN_ETHERTYPE);
        let fd = self.socket.get_ref().as_raw_fd();
        let ret = unsafe {
            libc::sendto(
                fd,
                std::ptr::null(),
                0,
                0,
                &dst as *const libc::sockaddr_ll as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if ret == -1 {
            let err = std::io::Error::last_os_error();
            if err.kind() != std::io::ErrorKind::WouldBlock {
                return Err(FaceError::Io(err));
            }
        }
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
