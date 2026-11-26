//! Shared AF_PACKET helpers and the TPACKET_V2 mmap'd ring buffer used by
//! `NamedEtherFace` and `MulticastEtherFace`. `MacAddr` is re-exported from
//! `ndn-transport` so the whole stack uses one canonical type.

use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicU32, Ordering};

use bytes::Bytes;

pub use ndn_transport::MacAddr;

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
    // `ioctl`'s request arg is `c_ulong` on glibc but `c_int` on musl — `as _`
    // infers the target-correct type so this cross-compiles for both.
    if unsafe { libc::ioctl(fd, libc::SIOCGIFINDEX as _, &mut ifr) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { ifr.ifr_ifru.ifru_ifindex })
}

pub fn make_sockaddr_ll(ifindex: i32, dst_mac: &MacAddr, protocol: u16) -> libc::sockaddr_ll {
    let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    addr.sll_family = libc::AF_PACKET as u16;
    addr.sll_protocol = protocol.to_be();
    addr.sll_ifindex = ifindex;
    addr.sll_halen = 6;
    addr.sll_addr[..6].copy_from_slice(dst_mac.as_bytes());
    addr
}

/// Non-blocking `AF_PACKET + SOCK_DGRAM` socket bound to `ifindex`.
pub fn open_packet_socket(ifindex: i32, protocol: u16) -> std::io::Result<OwnedFd> {
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            protocol.to_be() as i32,
        )
    };
    if fd == -1 {
        return Err(std::io::Error::last_os_error());
    }
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };

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

// TPACKET_V2 lives inside libc's `tpacket_versions` enum.
pub(crate) const TPACKET_V2: libc::c_int = 1;

pub(crate) const TPACKET_ALIGNMENT: usize = 16;

pub(crate) const fn tpacket_align(x: usize) -> usize {
    (x + TPACKET_ALIGNMENT - 1) & !(TPACKET_ALIGNMENT - 1)
}

pub(crate) const RING_FRAME_SIZE: u32 = 2048;
pub(crate) const RING_BLOCK_SIZE: u32 = 1 << 12; // 4 KiB (1 page, 2 frames/block)
pub(crate) const RING_BLOCK_NR: u32 = 32; // 128 KiB per ring
pub(crate) const RING_FRAME_NR: u32 = (RING_BLOCK_SIZE / RING_FRAME_SIZE) * RING_BLOCK_NR;

// Where `try_push_tx` writes the outgoing packet in a TPACKET_V2 TX frame.
//
// The kernel reads TX data at `ph.raw + tp_hdrlen - sizeof(sockaddr_ll)`, and
// `TPACKET2_HDRLEN = TPACKET_ALIGN(sizeof(tpacket2_hdr)) + sizeof(sockaddr_ll)`,
// so the TX data offset is exactly `TPACKET_ALIGN(sizeof(tpacket2_hdr))`. The
// embedded `sockaddr_ll` is the RX layout only; the TX destination comes from
// the `sendto` address. Adding `sizeof(sockaddr_ll)` here (the prior value)
// wrote the payload 20 bytes too far, so the kernel emitted 20 stale bytes
// then a truncated payload -- invisible to ndn-rs<->ndn-rs (the receiver tp_mac
// tracked the same skew) but corrupt to any standard NDN-over-Ethernet peer.
pub(crate) const TX_DATA_OFFSET: usize = tpacket_align(std::mem::size_of::<libc::tpacket2_hdr>());

/// # Safety
/// `frame` must point to a valid, 16-byte-aligned tpacket2_hdr in the
/// mmap'd ring.
pub(crate) unsafe fn read_tp_status(frame: *mut u8) -> u32 {
    unsafe { (*AtomicU32::from_ptr(frame as *mut u32)).load(Ordering::Acquire) }
}

/// # Safety
/// Same as [`read_tp_status`].
pub(crate) unsafe fn write_tp_status(frame: *mut u8, val: u32) {
    unsafe { (*AtomicU32::from_ptr(frame as *mut u32)).store(val, Ordering::Release) }
}

/// What the TX ring holds that the kernel's frame headers do not: where each queued frame goes.
///
/// A `SOCK_DGRAM` packet socket takes the link-layer destination of every frame a `sendto` sends
/// from that call's address (the `sockaddr_ll` in a TPACKET_V2 TX frame is the RX layout, never
/// read on TX), so one call can address only one destination. The ring therefore keeps the
/// destination of each frame itself and hands the kernel one run of frames with the same
/// destination per call. The queued frames are the slots `[next - released - staged, next)` (mod
/// the frame count), oldest first: first the `released` ones the kernel was told to send and has
/// not yet taken (all one destination), then the `staged` ones that wait for their own call.
struct TxQueue {
    /// The slot the next pushed frame is written to.
    next: u32,
    /// Frames marked `TP_STATUS_SEND_REQUEST` that the kernel has not taken.
    released: u32,
    /// Frames written to a slot but not yet marked: their slot still reads as available.
    staged: u32,
    /// The destination of each slot's frame.
    dst: Box<[MacAddr]>,
}

/// Mmap'd `PACKET_RX_RING` + `PACKET_TX_RING` for zero-copy packet I/O.
pub struct PacketRing {
    map: *mut u8,
    map_len: usize,
    frame_size: usize,
    rx_frame_nr: u32,
    tx_frame_nr: u32,
    tx_offset: usize,
    rx_head: AtomicU32,
    tx: std::sync::Mutex<TxQueue>,
}

unsafe impl Send for PacketRing {}
unsafe impl Sync for PacketRing {}

impl PacketRing {
    /// A ring over `map`, `map_len` bytes: the RX ring, then a TX ring of the same size.
    pub(crate) fn new(map: *mut u8, map_len: usize) -> Self {
        Self {
            map,
            map_len,
            frame_size: RING_FRAME_SIZE as usize,
            rx_frame_nr: RING_FRAME_NR,
            tx_frame_nr: RING_FRAME_NR,
            tx_offset: map_len / 2,
            rx_head: AtomicU32::new(0),
            tx: std::sync::Mutex::new(TxQueue {
                next: 0,
                released: 0,
                staged: 0,
                dst: vec![MacAddr::new([0; 6]); RING_FRAME_NR as usize].into_boxed_slice(),
            }),
        }
    }

    fn rx_frame(&self, idx: u32) -> *mut u8 {
        unsafe { self.map.add(idx as usize * self.frame_size) }
    }

    fn tx_frame(&self, idx: u32) -> *mut u8 {
        unsafe {
            self.map
                .add(self.tx_offset + idx as usize * self.frame_size)
        }
    }

    pub fn try_pop_rx(&self) -> Option<Bytes> {
        self.try_pop_rx_with_source().map(|(bytes, _)| bytes)
    }

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

        // ETH-1: the kernel guarantees tp_mac + tp_snaplen fits the frame for
        // TPACKET_V2, but an unsafe slice built from header-supplied offsets
        // must assert it. On violation, consume the frame and skip it rather
        // than reading out of bounds.
        if tp_mac
            .checked_add(tp_snaplen)
            .is_none_or(|end| end > RING_FRAME_SIZE as usize)
        {
            unsafe { write_tp_status(frame, libc::TP_STATUS_KERNEL) };
            self.rx_head
                .store((idx + 1) % self.rx_frame_nr, Ordering::Relaxed);
            return None;
        }

        let sll_offset = tpacket_align(std::mem::size_of::<libc::tpacket2_hdr>());
        let sll = unsafe { &*(frame.add(sll_offset) as *const libc::sockaddr_ll) };
        let src_mac = MacAddr({
            let mut b = [0u8; 6];
            b.copy_from_slice(&sll.sll_addr[..6]);
            b
        });

        let data = unsafe { std::slice::from_raw_parts(frame.add(tp_mac), tp_snaplen) };
        let bytes = Bytes::copy_from_slice(data);

        unsafe { write_tp_status(frame, libc::TP_STATUS_KERNEL) };
        self.rx_head
            .store((idx + 1) % self.rx_frame_nr, Ordering::Relaxed);

        Some((bytes, src_mac))
    }

    /// Queue `data` for `dst`; `false` when the ring has no room. The frame is only queued:
    /// [`flush_with`](Self::flush_with) sends it, to `dst` and no other address.
    pub fn try_push_tx(&self, data: &[u8], dst: &MacAddr) -> bool {
        // ETH-2: the mmap TX frame is a fixed RING_FRAME_SIZE slot. The unsafe
        // copy must not trust the caller's length — reject anything that would
        // overflow the frame, even though the paired LP fragmenter clamps to the
        // 1500 ether MTU upstream. (Latent OOB write made impossible here.)
        match TX_DATA_OFFSET.checked_add(data.len()) {
            Some(end) if end <= RING_FRAME_SIZE as usize => {}
            _ => return false,
        }

        let mut q = self.tx.lock().unwrap();
        self.reap(&mut q);
        // Every queued frame holds its slot, whether or not the slot reads as available yet.
        if q.released + q.staged >= self.tx_frame_nr {
            return false;
        }
        let slot = q.next;
        let frame = self.tx_frame(slot);

        let status = unsafe { read_tp_status(frame) };
        if status != libc::TP_STATUS_AVAILABLE {
            return false;
        }

        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), frame.add(TX_DATA_OFFSET), data.len());

            let hdr = frame as *mut libc::tpacket2_hdr;
            (*hdr).tp_len = data.len() as u32;
            (*hdr).tp_snaplen = data.len() as u32;
        }

        q.dst[slot as usize] = *dst;
        q.staged += 1;
        q.next = (slot + 1) % self.tx_frame_nr;
        true
    }

    /// Send every queued frame, each to its own destination: `send` is called once per run of
    /// consecutive frames with one destination, after marking exactly that run for the kernel,
    /// and must have the kernel send the marked frames to the address it is given (`sendto`).
    /// A run the kernel did not take (a send that would block) stays marked and is sent again,
    /// to its own destination, by the next flush before any frame queued after it.
    ///
    /// The queue stays locked across `send`: a frame another thread queues cannot be marked, and
    /// so cannot be sent to this call's address, while this run is still the kernel's.
    pub fn flush_with(
        &self,
        mut send: impl FnMut(&MacAddr) -> std::io::Result<()>,
    ) -> std::io::Result<()> {
        let mut q = self.tx.lock().unwrap();
        loop {
            self.reap(&mut q);
            if q.released == 0 {
                if q.staged == 0 {
                    return Ok(());
                }
                let first = self.oldest(&q);
                let dst = q.dst[first as usize];
                let mut run = 0;
                while run < q.staged {
                    let slot = (first + run) % self.tx_frame_nr;
                    if q.dst[slot as usize] != dst {
                        break;
                    }
                    unsafe {
                        write_tp_status(self.tx_frame(slot), libc::TP_STATUS_SEND_REQUEST);
                    }
                    run += 1;
                }
                q.staged -= run;
                q.released = run;
            }
            let dst = q.dst[self.oldest(&q) as usize];
            send(&dst)?;
            self.reap(&mut q);
            if q.released > 0 {
                return Ok(());
            }
        }
    }

    /// The slot of the oldest queued frame.
    fn oldest(&self, q: &TxQueue) -> u32 {
        (q.next + 2 * self.tx_frame_nr - q.released - q.staged) % self.tx_frame_nr
    }

    /// Drop from the queue the released frames the kernel has taken (their slot is no longer
    /// marked `TP_STATUS_SEND_REQUEST`).
    fn reap(&self, q: &mut TxQueue) {
        while q.released > 0 {
            let oldest = self.oldest(q);
            let status = unsafe { read_tp_status(self.tx_frame(oldest)) };
            if status == libc::TP_STATUS_SEND_REQUEST {
                break;
            }
            q.released -= 1;
        }
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

pub fn setup_packet_ring(fd: RawFd) -> std::io::Result<PacketRing> {
    let version: libc::c_int = TPACKET_V2;
    setsockopt_val(fd, libc::SOL_PACKET, libc::PACKET_VERSION, &version)?;

    let req = libc::tpacket_req {
        tp_block_size: RING_BLOCK_SIZE,
        tp_block_nr: RING_BLOCK_NR,
        tp_frame_size: RING_FRAME_SIZE,
        tp_frame_nr: RING_FRAME_NR,
    };

    setsockopt_val(fd, libc::SOL_PACKET, libc::PACKET_RX_RING, &req)?;
    setsockopt_val(fd, libc::SOL_PACKET, libc::PACKET_TX_RING, &req)?;

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

    Ok(PacketRing::new(map as *mut u8, map_len))
}

/// Hardware (MAC) address of `iface` via `SIOCGIFHWADDR`.
pub fn get_interface_mac(iface: &str) -> std::io::Result<MacAddr> {
    let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd == -1 {
        return Err(std::io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };

    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    let name_bytes = iface.as_bytes();
    let copy_len = name_bytes.len().min(libc::IFNAMSIZ - 1);
    let name_ptr = ifr.ifr_name.as_mut_ptr() as *mut u8;
    unsafe { std::ptr::copy_nonoverlapping(name_bytes.as_ptr(), name_ptr, copy_len) };

    let ret = unsafe { libc::ioctl(fd.as_raw_fd(), libc::SIOCGIFHWADDR as _, &mut ifr as *mut _) };
    if ret == -1 {
        return Err(std::io::Error::last_os_error());
    }

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
        // SOCK_DGRAM/TPACKET_V2 TX data offset = TPACKET_ALIGN(tpacket2_hdr)
        // (= tp_hdrlen - sizeof(sockaddr_ll)); NOT past the RX-only sockaddr_ll.
        let aligned_hdr = tpacket_align(std::mem::size_of::<libc::tpacket2_hdr>());
        assert_eq!(TX_DATA_OFFSET, aligned_hdr);
    }

    /// Synthesise a TPACKET_V2 frame in a heap buffer and verify
    /// `try_pop_rx_with_source` extracts the embedded source MAC without
    /// touching an actual AF_PACKET socket.
    #[test]
    fn rx_source_mac_extraction() {
        let frame_size = RING_FRAME_SIZE as usize;
        let mut buf = vec![0u8; frame_size];

        let hdr = buf.as_mut_ptr() as *mut libc::tpacket2_hdr;
        let aligned_hdr_size = tpacket_align(std::mem::size_of::<libc::tpacket2_hdr>());
        let payload_offset = aligned_hdr_size + std::mem::size_of::<libc::sockaddr_ll>();
        let payload = b"NDN";

        unsafe {
            (*hdr).tp_status = libc::TP_STATUS_USER;
            (*hdr).tp_mac = payload_offset as _;
            (*hdr).tp_snaplen = payload.len() as u32;
        }

        let expected_mac = MacAddr::new([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]);
        let sll =
            unsafe { &mut *(buf.as_mut_ptr().add(aligned_hdr_size) as *mut libc::sockaddr_ll) };
        sll.sll_halen = 6;
        sll.sll_addr[..6].copy_from_slice(expected_mac.as_bytes());

        buf[payload_offset..payload_offset + payload.len()].copy_from_slice(payload);

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

    /// A TX ring over anonymous memory instead of a socket's: the ring logic runs without
    /// `CAP_NET_RAW`, and [`kernel_sendto`] plays the kernel's side of it.
    fn memory_ring() -> PacketRing {
        let map_len = 2 * (RING_BLOCK_SIZE as usize) * (RING_BLOCK_NR as usize);
        let map = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                map_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(map, libc::MAP_FAILED);
        PacketRing::new(map as *mut u8, map_len)
    }

    /// The kernel's `sendto` on a TX ring: it addresses every frame it takes to `dst` (the
    /// address of the call, the only one a `SOCK_DGRAM` ring has), takes the frames marked
    /// `TP_STATUS_SEND_REQUEST` in ring order up to `limit` of them (a send that would block
    /// takes fewer), and hands each slot back. `head` is the kernel's own position in the ring.
    struct Kernel {
        head: u32,
        wire: Vec<(MacAddr, Vec<u8>)>,
    }

    impl Kernel {
        fn sendto(&mut self, ring: &PacketRing, dst: &MacAddr, limit: usize) {
            for _ in 0..limit {
                let frame = ring.tx_frame(self.head);
                if unsafe { read_tp_status(frame) } != libc::TP_STATUS_SEND_REQUEST {
                    break;
                }
                let len = unsafe { (*(frame as *const libc::tpacket2_hdr)).tp_len } as usize;
                let payload = unsafe { std::slice::from_raw_parts(frame.add(TX_DATA_OFFSET), len) };
                self.wire.push((*dst, payload.to_vec()));
                unsafe { write_tp_status(frame, libc::TP_STATUS_AVAILABLE) };
                self.head = (self.head + 1) % ring.tx_frame_nr;
            }
        }
    }

    fn station(n: u8) -> MacAddr {
        MacAddr::new([0x02, 0, 0, 0, 0, n])
    }

    const MCAST: MacAddr = MacAddr::new([0x01, 0x00, 0x5e, 0x00, 0x17, 0xaa]);

    /// One flush sends each queued frame to the destination it was queued for: a unicast frame
    /// queued beside multicast frames is not sent to the group, a multicast frame is not sent
    /// to the station of the frame before it, and a second unicast reaches its own station.
    #[test]
    fn one_flush_sends_every_queued_frame_to_its_own_destination() {
        let ring = memory_ring();
        let queued = [
            (station(1), 1u8),
            (MCAST, 2),
            (MCAST, 3),
            (station(2), 4),
            (MCAST, 5),
        ];
        for (dst, tag) in &queued {
            assert!(ring.try_push_tx(&[*tag; 60], dst));
        }
        let mut kernel = Kernel {
            head: 0,
            wire: Vec::new(),
        };
        ring.flush_with(|dst| {
            kernel.sendto(&ring, dst, usize::MAX);
            Ok(())
        })
        .unwrap();
        let expected: Vec<_> = queued
            .iter()
            .map(|(dst, tag)| (*dst, vec![*tag; 60]))
            .collect();
        assert_eq!(kernel.wire, expected);
    }

    /// A flush the kernel did not take (it would block) leaves the frames queued for the
    /// destination they were queued for: a frame queued after it for another station does
    /// not change where they go.
    #[test]
    fn frames_the_kernel_did_not_take_keep_their_destination() {
        let ring = memory_ring();
        let mut kernel = Kernel {
            head: 0,
            wire: Vec::new(),
        };
        assert!(ring.try_push_tx(&[1; 60], &station(1)));
        ring.flush_with(|dst| {
            kernel.sendto(&ring, dst, 0);
            Ok(())
        })
        .unwrap();
        assert!(kernel.wire.is_empty());

        assert!(ring.try_push_tx(&[2; 60], &MCAST));
        ring.flush_with(|dst| {
            kernel.sendto(&ring, dst, usize::MAX);
            Ok(())
        })
        .unwrap();
        assert_eq!(
            kernel.wire,
            vec![(station(1), vec![1; 60]), (MCAST, vec![2; 60])]
        );
    }

    /// A frame queued but not yet flushed is never overwritten by a later push: a full ring
    /// refuses the push, and every frame leaves intact once it drains.
    #[test]
    fn a_full_ring_refuses_a_push_instead_of_overwriting_a_queued_frame() {
        let ring = memory_ring();
        let n = RING_FRAME_NR as usize;
        for i in 0..n {
            assert!(ring.try_push_tx(&[i as u8; 60], &station(i as u8)));
        }
        assert!(!ring.try_push_tx(&[0xff; 60], &MCAST));
        let mut kernel = Kernel {
            head: 0,
            wire: Vec::new(),
        };
        ring.flush_with(|dst| {
            kernel.sendto(&ring, dst, usize::MAX);
            Ok(())
        })
        .unwrap();
        let expected: Vec<_> = (0..n)
            .map(|i| (station(i as u8), vec![i as u8; 60]))
            .collect();
        assert_eq!(kernel.wire, expected);
        assert!(ring.try_push_tx(&[0xff; 60], &MCAST));
    }
}
