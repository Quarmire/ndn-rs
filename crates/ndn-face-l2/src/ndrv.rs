//! macOS raw Ethernet via `PF_NDRV` (Network Driver Raw).
//!
//! `PF_NDRV` is Darwin's protocol family for accessing the link layer without
//! IP.  It intercepts frames for **unregistered** EtherTypes — which NDN's
//! 0x8624 qualifies as (not registered in the macOS kernel).
//!
//! ## Comparison with Linux `AF_PACKET`
//!
//! | Feature | AF_PACKET (Linux) | PF_NDRV (macOS) |
//! |---|---|---|
//! | Socket API | `socket(AF_PACKET, SOCK_DGRAM, ...)` | `socket(PF_NDRV, SOCK_RAW, 0)` |
//! | EtherType filter | any | unregistered only |
//! | Ethernet header in payload | stripped by SOCK_DGRAM | **full frame** incl. header |
//! | Source MAC in recv | from `sockaddr_ll.sll_addr` | from bytes [6..12] of raw frame |
//! | Multicast join | `PACKET_ADD_MEMBERSHIP` | `NDRV_ADDMULTICAST` |
//! | Ring buffer | TPACKET_V2 | none (regular recv) |
//! | Requires root | yes (CAP_NET_RAW) | yes |
//!
//! Because PF_NDRV returns full Ethernet frames, [`NdrvSocket::send`] also
//! requires a complete frame (destination MAC, source MAC, EtherType 0x8624,
//! then payload).  The helpers [`NdrvSocket::send_to_mcast`] and
//! [`NdrvSocket::send_unicast`] prepend the correct header automatically.
//!
//! ## Multicast
//!
//! The NDN multicast group (`01:00:5e:00:17:aa`) is joined via
//! `NDRV_ADDMULTICAST`.  The socket must be bound before joining.

#![cfg(target_os = "macos")]

use std::ffi::CStr;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};

use bytes::Bytes;
use tokio::io::unix::AsyncFd;

use ndn_discovery::MacAddr;

use crate::NDN_ETHERTYPE;

// ─── Darwin constants (from <net/ndrv.h>) ────────────────────────────────────

/// Protocol family for PF_NDRV sockets.
const PF_NDRV: libc::c_int = 27;
/// Socket option level for `SOL_NDRVPROTO`.
const SOL_NDRVPROTO: libc::c_int = 27;
/// `setsockopt` option to register an EtherType demux descriptor.
const NDRV_SETDMXSPEC: libc::c_int = 1;
/// `setsockopt` option to add a multicast address.
const NDRV_ADDMULTICAST: libc::c_int = 3;
/// Demux descriptor type: EtherType filter.
const NDRV_DEMUXTYPE_ETHERTYPE: u16 = 3;
/// Version of the `ndrv_protocol_desc` structure.
const NDRV_PROTOCOL_DESC_VERS: u32 = 1;
/// Maximum length of an interface name (IFNAMSIZ).
const IFNAMSIZ: usize = 16;

// ─── Darwin structs ───────────────────────────────────────────────────────────

/// `sockaddr_ndrv` — used for `bind()` and `sendto()`.
#[repr(C)]
struct SockaddrNdrv {
    snd_len: u8,
    snd_family: u8,
    snd_name: [u8; IFNAMSIZ],
}

impl SockaddrNdrv {
    fn new(iface: &str) -> Self {
        let mut snd_name = [0u8; IFNAMSIZ];
        let bytes = iface.as_bytes();
        let len = bytes.len().min(IFNAMSIZ - 1);
        snd_name[..len].copy_from_slice(&bytes[..len]);
        Self {
            snd_len: std::mem::size_of::<Self>() as u8,
            snd_family: PF_NDRV as u8,
            snd_name,
        }
    }
}

/// One demux descriptor (EtherType filter).
#[repr(C)]
struct NdrvDemuxDesc {
    desc_type: u16,
    desc_len: u16,
    /// EtherType in network byte order, zero-padded to 4 bytes.
    ether_type: [u8; 4],
}

/// `ndrv_protocol_desc` — passed to `NDRV_SETDMXSPEC`.
#[repr(C)]
struct NdrvProtocolDesc {
    version: u32,
    protocol_family: u32,
    demux_count: u32,
    _pad: u32,
    demux_list: *const NdrvDemuxDesc,
}

/// `sockaddr_dl` — used for multicast join (simplified, MAC-address part only).
///
/// We only need the fields up through `sdl_alen` + 6 bytes of address.
#[repr(C)]
struct SockaddrDl {
    sdl_len: u8,
    sdl_family: u8, // AF_LINK = 18
    sdl_index: u16,
    sdl_type: u8,
    sdl_nlen: u8,
    sdl_alen: u8,
    sdl_slen: u8,
    sdl_data: [u8; 12],
}

impl SockaddrDl {
    fn for_mac(mac: &MacAddr) -> Self {
        let mut sdl_data = [0u8; 12];
        sdl_data[..6].copy_from_slice(mac.as_bytes());
        Self {
            sdl_len: std::mem::size_of::<Self>() as u8,
            sdl_family: 18, // AF_LINK
            sdl_index: 0,
            sdl_type: 0,
            sdl_nlen: 0,
            sdl_alen: 6,
            sdl_slen: 0,
            sdl_data,
        }
    }
}

// ─── NDN Ethernet constants ───────────────────────────────────────────────────

/// NDN Ethernet multicast MAC: `01:00:5e:00:17:aa`
pub const NDN_ETHER_MCAST_MAC: MacAddr = MacAddr([0x01, 0x00, 0x5E, 0x00, 0x17, 0xAA]);
/// Ethernet header size: dst(6) + src(6) + EtherType(2).
const ETHER_HEADER_LEN: usize = 14;

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Return the MAC address of `iface` via `getifaddrs(3)`.
pub fn get_iface_mac(iface: &str) -> std::io::Result<MacAddr> {
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) != 0 {
            return Err(std::io::Error::last_os_error());
        }

        let target = iface.as_bytes();
        let mut result: Option<MacAddr> = None;
        let mut cur = ifap;
        while !cur.is_null() {
            let ifa = &*cur;
            let name = CStr::from_ptr(ifa.ifa_name);
            if name.to_bytes() == target && !ifa.ifa_addr.is_null() {
                let sa = &*ifa.ifa_addr;
                if sa.sa_family as i32 == libc::AF_LINK {
                    let sdl = &*(ifa.ifa_addr as *const SockaddrDl);
                    let nlen = sdl.sdl_nlen as usize;
                    let alen = sdl.sdl_alen as usize;
                    if alen >= 6 && nlen + 6 <= sdl.sdl_data.len() {
                        let mac_bytes: [u8; 6] = sdl.sdl_data[nlen..nlen + 6].try_into().unwrap();
                        result = Some(MacAddr::new(mac_bytes));
                        break;
                    }
                }
            }
            cur = ifa.ifa_next;
        }
        libc::freeifaddrs(ifap);

        result.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("no MAC address found for interface {iface}"),
            )
        })
    }
}

// ─── NdrvSocket ───────────────────────────────────────────────────────────────

/// Async-capable PF_NDRV socket bound to a specific Ethernet interface.
///
/// Receives and sends full raw Ethernet frames for EtherType 0x8624 (NDN).
/// The source MAC of received frames is at bytes `[6..12]` of the frame.
pub struct NdrvSocket {
    socket: AsyncFd<OwnedFd>,
    iface: String,
    local_mac: MacAddr,
    sa: SockaddrNdrv,
}

impl NdrvSocket {
    /// Open a PF_NDRV socket on `iface`, register EtherType 0x8624, and join
    /// the NDN Ethernet multicast group `01:00:5e:00:17:aa`.
    ///
    /// Requires root.
    pub fn new(iface: impl Into<String>) -> std::io::Result<Self> {
        let iface = iface.into();
        let local_mac = get_iface_mac(&iface)?;

        // socket(PF_NDRV, SOCK_RAW, 0)
        let fd = unsafe { libc::socket(PF_NDRV, libc::SOCK_RAW, 0) };
        if fd == -1 {
            return Err(std::io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };

        // bind to interface
        let sa = SockaddrNdrv::new(&iface);
        let rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                &sa as *const SockaddrNdrv as *const libc::sockaddr,
                std::mem::size_of::<SockaddrNdrv>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }

        // Register EtherType 0x8624
        let ethertype_be = NDN_ETHERTYPE.to_be_bytes();
        let demux = NdrvDemuxDesc {
            desc_type: NDRV_DEMUXTYPE_ETHERTYPE,
            desc_len: 2,
            ether_type: [ethertype_be[0], ethertype_be[1], 0, 0],
        };
        let proto_desc = NdrvProtocolDesc {
            version: NDRV_PROTOCOL_DESC_VERS,
            protocol_family: NDN_ETHERTYPE as u32,
            demux_count: 1,
            _pad: 0,
            demux_list: &demux as *const NdrvDemuxDesc,
        };
        let rc = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                SOL_NDRVPROTO,
                NDRV_SETDMXSPEC,
                &proto_desc as *const NdrvProtocolDesc as *const libc::c_void,
                std::mem::size_of::<NdrvProtocolDesc>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }

        // Join NDN Ethernet multicast group
        let mcast_sdl = SockaddrDl::for_mac(&NDN_ETHER_MCAST_MAC);
        let rc = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                SOL_NDRVPROTO,
                NDRV_ADDMULTICAST,
                &mcast_sdl as *const SockaddrDl as *const libc::c_void,
                std::mem::size_of::<SockaddrDl>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }

        // Set non-blocking for tokio
        unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) };

        let socket = AsyncFd::new(fd)?;
        Ok(Self {
            socket,
            iface,
            local_mac,
            sa,
        })
    }

    pub fn iface(&self) -> &str {
        &self.iface
    }

    pub fn local_mac(&self) -> MacAddr {
        self.local_mac
    }

    /// Receive the next raw Ethernet frame for EtherType 0x8624.
    ///
    /// Returns `(payload_bytes, source_mac)`.
    /// The source MAC is extracted from frame bytes [6..12].
    /// The Ethernet header (14 bytes) is stripped from the returned payload.
    pub async fn recv(&self) -> std::io::Result<(Bytes, MacAddr)> {
        let mut buf = vec![0u8; 1514 + ETHER_HEADER_LEN];
        loop {
            let mut guard = self.socket.readable().await?;
            match guard.try_io(|fd| {
                let n = unsafe {
                    libc::recv(
                        fd.as_raw_fd(),
                        buf.as_mut_ptr() as *mut libc::c_void,
                        buf.len(),
                        0,
                    )
                };
                if n == -1 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(Ok(n)) if n >= ETHER_HEADER_LEN => {
                    let src_mac = MacAddr([buf[6], buf[7], buf[8], buf[9], buf[10], buf[11]]);
                    let payload = Bytes::copy_from_slice(&buf[ETHER_HEADER_LEN..n]);
                    return Ok((payload, src_mac));
                }
                Ok(Ok(_)) => {
                    // Frame too short to have a valid header; skip it.
                    continue;
                }
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => continue,
            }
        }
    }

    /// Send `payload` as an NDN Ethernet frame to `dst_mac`.
    ///
    /// Prepends the Ethernet header: `[dst_mac][local_mac][0x86, 0x24]`.
    pub async fn send_to(&self, payload: &[u8], dst_mac: &MacAddr) -> std::io::Result<()> {
        let mut frame = Vec::with_capacity(ETHER_HEADER_LEN + payload.len());
        frame.extend_from_slice(dst_mac.as_bytes());
        frame.extend_from_slice(self.local_mac.as_bytes());
        let et = NDN_ETHERTYPE.to_be_bytes();
        frame.extend_from_slice(&et);
        frame.extend_from_slice(payload);

        loop {
            let mut guard = self.socket.writable().await?;
            match guard.try_io(|fd| {
                let n = unsafe {
                    libc::sendto(
                        fd.as_raw_fd(),
                        frame.as_ptr() as *const libc::c_void,
                        frame.len(),
                        0,
                        &self.sa as *const SockaddrNdrv as *const libc::sockaddr,
                        std::mem::size_of::<SockaddrNdrv>() as libc::socklen_t,
                    )
                };
                if n == -1 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(())
                }
            }) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    /// Send `payload` to the NDN Ethernet multicast MAC.
    pub async fn send_to_mcast(&self, payload: &[u8]) -> std::io::Result<()> {
        self.send_to(payload, &NDN_ETHER_MCAST_MAC).await
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ndrv_mcast_mac_is_multicast() {
        assert_eq!(NDN_ETHER_MCAST_MAC.as_bytes()[0] & 0x01, 0x01);
    }

    #[test]
    fn sockaddr_ndrv_name_encoding() {
        let sa = SockaddrNdrv::new("en0");
        assert_eq!(sa.snd_family, PF_NDRV as u8);
        assert_eq!(&sa.snd_name[..3], b"en0");
        assert_eq!(sa.snd_name[3], 0); // null-terminated
    }

    #[test]
    fn new_without_root_fails_with_eperm() {
        // Without root, socket(PF_NDRV,...) returns EPERM.
        match NdrvSocket::new("en0") {
            Err(e) => {
                let raw = e.raw_os_error().unwrap_or(0);
                assert!(
                    raw == libc::EPERM || raw == libc::EACCES || raw == libc::ENOENT,
                    "expected permission error, got: {e}"
                );
            }
            Ok(_) => {
                // Running as root in CI — acceptable.
            }
        }
    }
}
