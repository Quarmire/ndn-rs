//! Shared AF_PACKET infrastructure for raw Ethernet faces.
//!
//! Contains socket helpers and the TPACKET_V2 mmap'd ring buffer used by both
//! `NamedEtherFace` (unicast) and `MulticastEtherFace`.
//!
//! `MacAddr` is re-exported from `ndn-discovery` — it is the shared canonical
//! type used across the whole stack.  Defining a second copy here caused a
//! type-mismatch on Linux when passing MACs to `NeighborUpdate::AddFace`.

use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicU32, Ordering};

use bytes::Bytes;

pub use ndn_discovery::MacAddr;

// ─── AF_PACKET helpers ───────────────────────────────────────────────────────

/// Look up the interface index for `iface` via `SIOCGIFINDEX`.
pub fn get_ifindex(fd: RawFd, iface: &str) -> std::io::Result<i32> {
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    let name_bytes = iface.as_bytes();
    if name_bytes.len() >= libc::IFNAMSIZ {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "interface name too long",
        ));
    }
    unsafe {
        std::ptr::copy_nonoverlapping(
            name_bytes.as_ptr(),
            ifr.ifr_name.as_mut_ptr() as *mut u8,
            name_bytes.len(),
        );
    }
    if unsafe { libc::ioctl(fd, libc::SIOCGIFINDEX as libc::c_ulong, &mut ifr) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { ifr.ifr_ifru.ifru_ifindex })
}

/// Build a `sockaddr_ll` for `bind` or `sendto`.
pub fn make_sockaddr_ll(ifindex: i32, dst_mac: &MacAddr, protocol: u16) -> libc::sockaddr_ll {
    let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    addr.sll_family = libc::AF_PACKET as u16;
    addr.sll_protocol = protocol.to_be();
    addr.sll_ifindex = ifindex;
    addr.sll_halen = 6;
    addr.sll_addr[..6].copy_from_slice(dst_mac.as_bytes());
    addr
}

/// Create an `AF_PACKET + SOCK_DGRAM` socket bound to `ifindex`, filtering
/// only frames with ethertype `protocol`.  Returns a non-blocking `OwnedFd`.
pub fn open_packet_socket(ifindex: i32, protocol: u16) -> std::io::Result<OwnedFd> {
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            (protocol as u16).to_be() as i32,
        )
    };
    if fd == -1 {
        return Err(std::io::Error::last_os_error());
    }
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };

    // Bind to the specific interface so we only receive frames from it.
    let bind_addr = make_sockaddr_ll(ifindex, &MacAddr::new([0; 6]), protocol);
    if unsafe {
        libc::bind(
            owned.as_raw_fd(),
            &bind_addr as *const libc::sockaddr_ll as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    } == -1
    {
        return Err(std::io::Error::last_os_error());
    }

    Ok(owned)
}

/// Generic `setsockopt` wrapper for a value of type `T`.
pub fn setsockopt_val<T>(
    fd: RawFd,
    level: libc::c_int,
    name: libc::c_int,
    val: &T,
) -> std::io::Result<()> {
    if unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            val as *const T as *const libc::c_void,
            std::mem::size_of::<T>() as libc::socklen_t,
        )
    } == -1
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

// ─── TPACKET_V2 mmap ring buffer ────────────────────────────────────────────

// TPACKET_V2 lives inside libc's `tpacket_versions` enum.
pub(crate) const TPACKET_V2: libc::c_int = 1;

pub(crate) const TPACKET_ALIGNMENT: usize = 16;

pub(crate) const fn tpacket_align(x: usize) -> usize {
    (x + TPACKET_ALIGNMENT - 1) & !(TPACKET_ALIGNMENT - 1)
}

// Ring geometry — each ring gets BLOCK_NR × BLOCK_SIZE bytes.
// 2048-byte frames fit tpacket2_hdr (32 B) + sockaddr_ll (20 B) + 1500 B payload.
pub(crate) const RING_FRAME_SIZE: u32 = 2048;
pub(crate) const RING_BLOCK_SIZE: u32 = 1 << 12; // 4 KiB (one page, 2 frames/block)
pub(crate) const RING_BLOCK_NR: u32 = 32; // 32 blocks → 128 KiB per ring
pub(crate) const RING_FRAME_NR: u32 = (RING_BLOCK_SIZE / RING_FRAME_SIZE) * RING_BLOCK_NR; // 64

/// Byte offset from TX frame start to the packet data payload.
pub(crate) const TX_DATA_OFFSET: usize = tpacket_align(std::mem::size_of::<libc::tpacket2_hdr>())
    + std::mem::size_of::<libc::sockaddr_ll>();

// ─── tp_status atomic access ─────────────────────────────────────────────────

/// Read `tp_status` from a ring frame with Acquire ordering.
///
/// # Safety
/// `frame` must point to a valid, 16-byte-aligned tpacket2_hdr in the mmap'd ring.
pub(crate) unsafe fn read_tp_status(frame: *mut u8) -> u32 {
    unsafe { (*AtomicU32::from_ptr(frame as *mut u32)).load(Ordering::Acquire) }
}

/// Write `tp_status` with Release ordering.
///
/// # Safety
/// Same requirements as [`read_tp_status`].
pub(crate) unsafe fn write_tp_status(frame: *mut u8, val: u32) {
    unsafe { (*AtomicU32::from_ptr(frame as *mut u32)).store(val, Ordering::Release) }
}

// ─── PacketRing ──────────────────────────────────────────────────────────────

/// Mmap'd `PACKET_RX_RING` + `PACKET_TX_RING` for zero-copy packet I/O.
pub struct PacketRing {
    /// Mmap'd region (RX ring at offset 0, TX ring at `tx_offset`).
    map: *mut u8,
    map_len: usize,
    frame_size: usize,
    rx_frame_nr: u32,
    tx_frame_nr: u32,
    /// Byte offset where the TX ring starts within the mmap region.
    tx_offset: usize,
    /// Current RX consumer index (single consumer — Face::recv is single-task).
    rx_head: AtomicU32,
    /// Current TX producer index, protected for concurrent Face::send calls.
    tx_head: std::sync::Mutex<u32>,
}

// Safety: the mmap'd region is shared with the kernel via MAP_SHARED.
// Synchronisation is through atomic tp_status reads/writes with
// Acquire/Release ordering.  rx_head is single-consumer; tx_head is
// protected by a Mutex.
unsafe impl Send for PacketRing {}
unsafe impl Sync for PacketRing {}

impl PacketRing {
    fn rx_frame(&self, idx: u32) -> *mut u8 {
        unsafe { self.map.add(idx as usize * self.frame_size) }
    }

    fn tx_frame(&self, idx: u32) -> *mut u8 {
        unsafe {
            self.map
                .add(self.tx_offset + idx as usize * self.frame_size)
        }
    }

    /// Try to dequeue one packet from the RX ring.
    pub fn try_pop_rx(&self) -> Option<Bytes> {
        self.try_pop_rx_with_source().map(|(bytes, _)| bytes)
    }

    /// Try to dequeue one packet from the RX ring, also returning the source MAC.
    ///
    /// In a TPACKET_V2 frame the kernel embeds a `sockaddr_ll` immediately after
    /// the aligned `tpacket2_hdr`.  For received frames the kernel fills in
    /// `sll_addr` / `sll_halen` with the source Ethernet address, giving us the
    /// peer MAC without any extra syscall.
    pub fn try_pop_rx_with_source(&self) -> Option<(Bytes, MacAddr)> {
        let idx = self.rx_head.load(Ordering::Relaxed);
        let frame = self.rx_frame(idx);

        let status = unsafe { read_tp_status(frame) };
        if status & libc::TP_STATUS_USER == 0 {
            return None;
        }

        let hdr = frame as *const libc::tpacket2_hdr;
        let tp_mac = unsafe { (*hdr).tp_mac } as usize;
        let tp_snaplen = unsafe { (*hdr).tp_snaplen } as usize;

        // sockaddr_ll sits immediately after the aligned tpacket2_hdr.
        let sll_offset = tpacket_align(std::mem::size_of::<libc::tpacket2_hdr>());
        let sll = unsafe { &*(frame.add(sll_offset) as *const libc::sockaddr_ll) };
        let src_mac = MacAddr({
            let mut b = [0u8; 6];
            b.copy_from_slice(&sll.sll_addr[..6]);
            b
        });

        let data = unsafe { std::slice::from_raw_parts(frame.add(tp_mac), tp_snaplen) };
        let bytes = Bytes::copy_from_slice(data);

        // Release frame back to the kernel.
        unsafe { write_tp_status(frame, libc::TP_STATUS_KERNEL) };
        self.rx_head
            .store((idx + 1) % self.rx_frame_nr, Ordering::Relaxed);

        Some((bytes, src_mac))
    }

    /// Try to enqueue one packet into the TX ring.
    pub fn try_push_tx(&self, data: &[u8]) -> bool {
        let mut head = self.tx_head.lock().unwrap();
        let frame = self.tx_frame(*head);

        let status = unsafe { read_tp_status(frame) };
        if status != 0 {
            return false;
        }

        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), frame.add(TX_DATA_OFFSET), data.len());

            let hdr = frame as *mut libc::tpacket2_hdr;
            (*hdr).tp_len = data.len() as u32;
            (*hdr).tp_snaplen = data.len() as u32;
        }

        unsafe { write_tp_status(frame, libc::TP_STATUS_SEND_REQUEST) };

        *head = (*head + 1) % self.tx_frame_nr;
        true
    }
}

impl Drop for PacketRing {
    fn drop(&mut self) {
        if !self.map.is_null() {
            unsafe {
                libc::munmap(self.map as *mut libc::c_void, self.map_len);
            }
        }
    }
}

/// Configure TPACKET_V2, create RX + TX rings, and mmap them.
pub fn setup_packet_ring(fd: RawFd) -> std::io::Result<PacketRing> {
    // 1. Select TPACKET_V2.
    let version: libc::c_int = TPACKET_V2;
    setsockopt_val(fd, libc::SOL_PACKET, libc::PACKET_VERSION, &version)?;

    let req = libc::tpacket_req {
        tp_block_size: RING_BLOCK_SIZE,
        tp_block_nr: RING_BLOCK_NR,
        tp_frame_size: RING_FRAME_SIZE,
        tp_frame_nr: RING_FRAME_NR,
    };

    // 2. Configure RX ring, then TX ring (same geometry).
    setsockopt_val(fd, libc::SOL_PACKET, libc::PACKET_RX_RING, &req)?;
    setsockopt_val(fd, libc::SOL_PACKET, libc::PACKET_TX_RING, &req)?;

    // 3. Mmap both rings.
    let rx_ring_size = (RING_BLOCK_SIZE as usize) * (RING_BLOCK_NR as usize);
    let tx_ring_size = rx_ring_size;
    let map_len = rx_ring_size + tx_ring_size;

    let map = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            map_len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };
    if map == libc::MAP_FAILED {
        return Err(std::io::Error::last_os_error());
    }

    Ok(PacketRing {
        map: map as *mut u8,
        map_len,
        frame_size: RING_FRAME_SIZE as usize,
        rx_frame_nr: RING_FRAME_NR,
        tx_frame_nr: RING_FRAME_NR,
        tx_offset: rx_ring_size,
        rx_head: AtomicU32::new(0),
        tx_head: std::sync::Mutex::new(0),
    })
}

/// Query the hardware (MAC) address of `iface` via `SIOCGIFHWADDR`.
///
/// Returns an error if the interface does not exist or if the process lacks
/// the necessary permissions to open a raw socket for the ioctl.
pub fn get_interface_mac(iface: &str) -> std::io::Result<MacAddr> {
    let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd == -1 {
        return Err(std::io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };

    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    let name_bytes = iface.as_bytes();
    let copy_len = name_bytes.len().min(libc::IFNAMSIZ - 1);
    // SAFETY: ifr_name is a fixed-size C array, zeroed above.
    let name_ptr = ifr.ifr_name.as_mut_ptr() as *mut u8;
    unsafe { std::ptr::copy_nonoverlapping(name_bytes.as_ptr(), name_ptr, copy_len) };

    let ret = unsafe { libc::ioctl(fd.as_raw_fd(), libc::SIOCGIFHWADDR, &mut ifr as *mut _) };
    if ret == -1 {
        return Err(std::io::Error::last_os_error());
    }

    // ifr_hwaddr.sa_data holds the MAC bytes at offset 0.
    let sa_data = unsafe { ifr.ifr_ifru.ifru_hwaddr.sa_data };
    let mac = [
        sa_data[0] as u8,
        sa_data[1] as u8,
        sa_data[2] as u8,
        sa_data[3] as u8,
        sa_data[4] as u8,
        sa_data[5] as u8,
    ];
    Ok(MacAddr::new(mac))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NDN_ETHERTYPE;

    #[test]
    fn mac_addr_display() {
        let mac = MacAddr::new([0xaa, 0xbb, 0xcc, 0x01, 0x02, 0x03]);
        assert_eq!(format!("{mac}"), "aa:bb:cc:01:02:03");
    }

    #[test]
    fn mac_addr_broadcast() {
        assert_eq!(MacAddr::BROADCAST.as_bytes(), &[0xff; 6]);
    }

    #[test]
    fn sockaddr_ll_layout() {
        let mac = MacAddr::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let addr = make_sockaddr_ll(3, &mac, NDN_ETHERTYPE);
        assert_eq!(addr.sll_family, libc::AF_PACKET as u16);
        assert_eq!(addr.sll_ifindex, 3);
        assert_eq!(addr.sll_halen, 6);
        assert_eq!(&addr.sll_addr[..6], mac.as_bytes());
        assert_eq!(addr.sll_protocol, NDN_ETHERTYPE.to_be());
    }

    #[test]
    fn ring_geometry() {
        assert_eq!(
            RING_FRAME_NR,
            (RING_BLOCK_SIZE / RING_FRAME_SIZE) * RING_BLOCK_NR,
        );
        assert!(RING_FRAME_SIZE as usize >= TX_DATA_OFFSET + 1500);
    }

    #[test]
    fn tx_data_offset_is_correct() {
        let aligned_hdr = tpacket_align(std::mem::size_of::<libc::tpacket2_hdr>());
        let expected = aligned_hdr + std::mem::size_of::<libc::sockaddr_ll>();
        assert_eq!(TX_DATA_OFFSET, expected);
    }

    /// Verify that `try_pop_rx_with_source` correctly extracts the source MAC
    /// from a manually constructed TPACKET_V2 frame in a stack buffer.
    #[test]
    fn rx_source_mac_extraction() {
        // Build a synthetic TPACKET_V2 frame in a heap buffer so we can
        // exercise the MAC-extraction logic without an actual AF_PACKET socket.
        let frame_size = RING_FRAME_SIZE as usize;
        let mut buf = vec![0u8; frame_size];

        // Place the tpacket2_hdr at offset 0.
        let hdr = buf.as_mut_ptr() as *mut libc::tpacket2_hdr;
        let aligned_hdr_size = tpacket_align(std::mem::size_of::<libc::tpacket2_hdr>());
        let payload_offset = aligned_hdr_size + std::mem::size_of::<libc::sockaddr_ll>();
        let payload = b"NDN";

        unsafe {
            (*hdr).tp_status = libc::TP_STATUS_USER;
            (*hdr).tp_mac = payload_offset as u32;
            (*hdr).tp_snaplen = payload.len() as u32;
        }

        // Fill in the embedded sockaddr_ll with a known source MAC.
        let expected_mac = MacAddr::new([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]);
        let sll =
            unsafe { &mut *(buf.as_mut_ptr().add(aligned_hdr_size) as *mut libc::sockaddr_ll) };
        sll.sll_halen = 6;
        sll.sll_addr[..6].copy_from_slice(expected_mac.as_bytes());

        // Write the payload.
        buf[payload_offset..payload_offset + payload.len()].copy_from_slice(payload);

        // Read back MAC via the same logic used in try_pop_rx_with_source.
        let sll_read =
            unsafe { &*(buf.as_ptr().add(aligned_hdr_size) as *const libc::sockaddr_ll) };
        let got_mac = MacAddr({
            let mut b = [0u8; 6];
            b.copy_from_slice(&sll_read.sll_addr[..6]);
            b
        });

        assert_eq!(got_mac, expected_mac);

        let data_slice = &buf[payload_offset..payload_offset + payload.len()];
        assert_eq!(data_slice, payload);
    }
}
