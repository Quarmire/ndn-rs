//! Linux `AF_PACKET` `SOCK_RAW` backend: raw 802.11 injection and capture on a
//! monitor-mode interface.
//!
//! Unlike the Ethernet face (`ndn-face-native`'s `SOCK_DGRAM` + TPACKET ring,
//! where the kernel builds/strips the link header), monitor mode hands us the
//! *whole* frame: we prepend the [`radiotap`](crate::radiotap) TX header (which
//! names the MCS) and the 802.11 + LLC/SNAP headers ourselves, and on RX we
//! strip the radiotap header the driver prepended and the 802.11 header to
//! recover the NDN payload.
//!
//! Requires `CAP_NET_RAW` and an interface already in monitor mode
//! (`iw dev <if> set monitor none` / `ip link set <if> up`). Bringing the
//! interface into monitor mode is an operator/config step, not this backend's
//! job.
//!
//! **Compile-verified on Linux only.** The platform-neutral core (radiotap
//! codec + loopback bus) is exercised by the crate's unit tests on every host.

use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use async_trait::async_trait;
use ndn_transport::FaceError;
use tokio::io::unix::AsyncFd;

use crate::{CapturedFrame, FrameFormat, InjectFrame};

const ETH_P_ALL: u16 = 0x0003;

/// Raw-802.11 monitor-mode injection/capture over one interface. The 802.11
/// addresses come from each [`InjectFrame`] (name-derived or default), so the
/// backend holds no source identity.
pub struct AfPacketBackend {
    socket: AsyncFd<OwnedFd>,
    ifindex: i32,
    format: FrameFormat,
}

impl AfPacketBackend {
    /// Open a `SOCK_RAW` `AF_PACKET` socket bound to monitor-mode interface
    /// `iface`, wrapping payloads per `format`.
    pub fn new(iface: &str, format: FrameFormat) -> std::io::Result<Self> {
        let cname = std::ffi::CString::new(iface)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "iface has NUL"))?;
        let ifindex = unsafe { libc::if_nametoindex(cname.as_ptr()) };
        if ifindex == 0 {
            return Err(std::io::Error::last_os_error());
        }

        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                (ETH_P_ALL.to_be()) as i32,
            )
        };
        if fd == -1 {
            return Err(std::io::Error::last_os_error());
        }
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };

        // Enlarge the socket receive buffer so a fast on-air burst isn't dropped
        // between userspace reads (the default is small; a monitor sees every frame).
        let rcvbuf: libc::c_int = 4 * 1024 * 1024;
        unsafe {
            libc::setsockopt(
                owned.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &rcvbuf as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }

        let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_protocol = ETH_P_ALL.to_be();
        addr.sll_ifindex = ifindex as i32;
        if unsafe {
            libc::bind(
                owned.as_raw_fd(),
                &addr as *const libc::sockaddr_ll as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        } == -1
        {
            return Err(std::io::Error::last_os_error());
        }

        Ok(Self {
            socket: AsyncFd::new(owned)?,
            ifindex: ifindex as i32,
            format,
        })
    }
}

impl AfPacketBackend {
    /// Send pre-built bytes (radiotap ++ 802.11 ++ body) verbatim. For drivers that
    /// require a specific monitor-injection format (e.g. the rtl88x2eu cfg80211
    /// monitor path needs an exactly-14-byte radiotap + an 802.11 *Action* frame).
    pub async fn inject_raw(&self, buf: &[u8]) -> Result<(), FaceError> {
        let mut dst: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        dst.sll_family = libc::AF_PACKET as u16;
        dst.sll_protocol = ETH_P_ALL.to_be();
        dst.sll_ifindex = self.ifindex;
        loop {
            let mut guard = self.socket.writable().await.map_err(FaceError::Io)?;
            let fd: RawFd = self.socket.get_ref().as_raw_fd();
            let ret = unsafe {
                libc::sendto(
                    fd,
                    buf.as_ptr() as *const libc::c_void,
                    buf.len(),
                    0,
                    &dst as *const libc::sockaddr_ll as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
                )
            };
            if ret >= 0 {
                return Ok(());
            }
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                guard.clear_ready();
                continue;
            }
            return Err(FaceError::Io(err));
        }
    }
}

#[async_trait]
impl crate::FrameIo for AfPacketBackend {
    async fn inject(&self, frame: InjectFrame) -> Result<(), FaceError> {
        let buf = crate::frame::build(self.format, &frame)?;

        let mut dst: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        dst.sll_family = libc::AF_PACKET as u16;
        dst.sll_protocol = ETH_P_ALL.to_be();
        dst.sll_ifindex = self.ifindex;

        loop {
            let mut guard = self.socket.writable().await.map_err(FaceError::Io)?;
            let fd: RawFd = self.socket.get_ref().as_raw_fd();
            let ret = unsafe {
                libc::sendto(
                    fd,
                    buf.as_ptr() as *const libc::c_void,
                    buf.len(),
                    0,
                    &dst as *const libc::sockaddr_ll as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
                )
            };
            if ret >= 0 {
                return Ok(());
            }
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                guard.clear_ready();
                continue;
            }
            return Err(FaceError::Io(err));
        }
    }

    async fn recv_frame(&self) -> Result<CapturedFrame, FaceError> {
        let mut buf = [0u8; 4096];
        loop {
            let mut guard = self.socket.readable().await.map_err(FaceError::Io)?;
            let fd: RawFd = self.socket.get_ref().as_raw_fd();
            // try_io clears readiness on WouldBlock (so the next `.readable()`
            // re-registers with the edge-triggered epoll); a plain `recv` + manual
            // clear can wedge after the first packet on a busy monitor socket.
            let n = match guard.try_io(|_| {
                let n = unsafe {
                    libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0)
                };
                if n < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(Ok(n)) => n,
                Ok(Err(e)) => return Err(FaceError::Io(e)),
                Err(_would_block) => continue,
            };
            // A frame we can't decode (wrong format, foreign protocol) is
            // skipped, not an error — keep listening (readiness retained).
            if let Some(frame) = crate::frame::parse(self.format, &buf[..n], None, None) {
                return Ok(frame);
            }
        }
    }
}
