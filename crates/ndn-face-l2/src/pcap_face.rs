//! Windows raw Ethernet via Npcap / WinPcap (`pcap` crate).
//!
//! On Windows there is no `AF_PACKET` equivalent in the kernel.  Instead,
//! [Npcap](https://npcap.com/) (the successor to WinPcap) exposes a `pcap`
//! interface that allows capturing and injecting raw Ethernet frames.
//!
//! ## Architecture
//!
//! `pcap`'s capture handle is **blocking** and is not `Send + Sync` in a way
//! that plays nicely with Tokio.  We therefore run two operating-system
//! threads:
//!
//! * **recv thread** — owns a `Capture<Active>` with a BPF filter
//!   (`"ether proto 0x8624"`), calls `next_packet()` in a loop, and sends
//!   `(payload, src_mac)` pairs over an `mpsc` channel to async callers.
//! * **send thread** — owns a second `Capture<Active>` (without a filter) and
//!   receives full Ethernet frames from an `mpsc` channel, injecting them via
//!   `sendpacket`.
//!
//! The async `recv()` and `send_to()` methods on [`PcapSocket`] communicate
//! with those threads through Tokio `mpsc` channels.
//!
//! ## Ethernet header
//!
//! Like `PF_NDRV` on macOS, pcap returns **full Ethernet frames**.
//! [`PcapSocket::recv`] strips the 14-byte header and returns the payload
//! plus the source MAC extracted from bytes `[6..12]`.
//! [`PcapSocket::send_to`] prepends the full header before injecting.
//!
//! ## Multicast
//!
//! Npcap captures promiscuously at the link layer; all frames matching the
//! BPF filter arrive regardless of destination MAC.  The NDN multicast MAC
//! (`01:00:5e:00:17:aa`) need not be joined explicitly — the filter alone is
//! sufficient on Windows.
//!
//! ## MAC address lookup
//!
//! [`get_iface_mac`] uses `GetAdaptersAddresses` from the Windows IP Helper
//! API (`iphlpapi.dll`) to retrieve the physical (link-layer) address of an
//! adapter.  It accepts either the Npcap GUID device name
//! (`\Device\NPF_{...}`) or the adapter's friendly name (e.g. `"Ethernet"`).

#![cfg(target_os = "windows")]

use std::ffi::CStr;

use bytes::Bytes;
use pcap::Capture;
use tokio::sync::{Mutex, mpsc};
use windows_sys::Win32::Foundation::ERROR_BUFFER_OVERFLOW;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
};

use ndn_discovery::MacAddr;

use crate::NDN_ETHERTYPE;

// ─── Ethernet constants ───────────────────────────────────────────────────────

/// NDN Ethernet multicast MAC: `01:00:5e:00:17:aa`
pub const NDN_ETHER_MCAST_MAC: MacAddr = MacAddr([0x01, 0x00, 0x5E, 0x00, 0x17, 0xAA]);
/// Ethernet header: dst(6) + src(6) + EtherType(2).
const ETHER_HEADER_LEN: usize = 14;

// ─── MAC address lookup ───────────────────────────────────────────────────────

/// Return the MAC address of the named adapter via `GetAdaptersAddresses`.
///
/// `iface` may be:
/// * The Npcap device name: `\Device\NPF_{GUID}` — the GUID portion is
///   matched case-insensitively against `AdapterName`.
/// * The adapter's friendly name: `"Ethernet"`, `"Wi-Fi"`, etc.
///
/// Requires `iphlpapi.dll`, which ships with all modern Windows versions.
pub fn get_iface_mac(iface: &str) -> std::io::Result<MacAddr> {
    // Strip Npcap prefix to get just the GUID part.
    let target_guid = iface.strip_prefix(r"\Device\NPF_").unwrap_or(iface);

    // AF_UNSPEC (0) — enumerate adapters of all address families.
    const AF_UNSPEC: u32 = 0;
    // GAA_FLAG_NONE (0) — no special enumeration flags needed.
    const GAA_FLAG_NONE: u32 = 0;

    let mut buf_len: u32 = 16_384;
    let buf: Vec<u8>;

    // GetAdaptersAddresses may return ERROR_BUFFER_OVERFLOW with the required
    // size in buf_len.  Retry once with the updated size.
    loop {
        let mut tmp = vec![0u8; buf_len as usize];
        let ret = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC,
                GAA_FLAG_NONE,
                std::ptr::null(),
                tmp.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
                &mut buf_len,
            )
        };
        if ret == ERROR_BUFFER_OVERFLOW {
            continue; // buf_len updated; reallocate next iteration
        }
        if ret != 0 {
            return Err(std::io::Error::from_raw_os_error(ret as i32));
        }
        buf = tmp;
        break;
    }

    // Walk the singly-linked adapter list.
    let mut ptr = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    while !ptr.is_null() {
        let a = unsafe { &*ptr };

        // AdapterName is a null-terminated UTF-8 GUID string, e.g. "{GUID}".
        let adapter_name = if !a.AdapterName.is_null() {
            unsafe { CStr::from_ptr(a.AdapterName as *const i8) }
                .to_str()
                .unwrap_or("")
        } else {
            ""
        };

        let matched = adapter_name.eq_ignore_ascii_case(target_guid)
            || wide_eq(a.FriendlyName, iface);

        if matched && a.PhysicalAddressLength >= 6 {
            let p = &a.PhysicalAddress;
            return Ok(MacAddr([p[0], p[1], p[2], p[3], p[4], p[5]]));
        }

        ptr = a.Next;
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        format!("no MAC address found for interface {iface}"),
    ))
}

/// Compare a null-terminated wide string (`*const u16 / PWSTR`) to a UTF-8 `&str`.
fn wide_eq(ptr: *const u16, s: &str) -> bool {
    if ptr.is_null() {
        return false;
    }
    let wide: Vec<u16> = s.encode_utf16().collect();
    for (i, &expected) in wide.iter().enumerate() {
        if unsafe { *ptr.add(i) } != expected {
            return false;
        }
    }
    // The wide string must end exactly at this position.
    unsafe { *ptr.add(wide.len()) == 0 }
}

// ─── PcapSocket ───────────────────────────────────────────────────────────────

/// Async-capable pcap socket bound to a specific Ethernet interface.
///
/// Receives and sends full raw Ethernet frames for EtherType 0x8624 (NDN).
/// Internally uses two OS threads (one for recv, one for send) bridged to
/// Tokio via `mpsc` channels.
pub struct PcapSocket {
    iface: String,
    local_mac: MacAddr,
    /// Receives `(payload, src_mac)` pairs from the recv thread.
    ///
    /// Wrapped in a `Mutex` so that `recv(&self)` satisfies the `Face` trait,
    /// which requires `&self` for async receivers.  Only one caller at a time
    /// will actually hold the lock.
    rx: Mutex<mpsc::Receiver<(Bytes, MacAddr)>>,
    /// Sends full Ethernet frames to the send thread.
    tx: mpsc::UnboundedSender<Vec<u8>>,
}

impl PcapSocket {
    /// Open a pcap socket on `iface`.
    ///
    /// The local MAC address is resolved automatically via
    /// [`get_iface_mac`] (`GetAdaptersAddresses`).  `iface` may be the Npcap
    /// device name (`\Device\NPF_{...}`) or the adapter's friendly name.
    ///
    /// Requires Npcap to be installed.
    pub fn new(iface: impl Into<String>) -> std::io::Result<Self> {
        let iface = iface.into();
        let local_mac = get_iface_mac(&iface)?;
        Self::new_with_mac(iface, local_mac)
    }

    /// Like [`PcapSocket::new`] but with an explicitly supplied MAC address.
    ///
    /// Use this when MAC auto-detection is not possible or not desired (e.g.
    /// virtual interfaces without a physical address).
    pub fn new_with_mac(iface: impl Into<String>, local_mac: MacAddr) -> std::io::Result<Self> {
        let iface = iface.into();

        // ── recv capture ─────────────────────────────────────────────────────
        let mut cap_rx = Capture::from_device(iface.as_str())
            .map_err(pcap_err)?
            .promisc(true)
            .snaplen(9000)
            .open()
            .map_err(pcap_err)?;

        cap_rx
            .filter(&format!("ether proto 0x{NDN_ETHERTYPE:04x}"), true)
            .map_err(pcap_err)?;

        // ── send capture ─────────────────────────────────────────────────────
        let cap_tx = Capture::from_device(iface.as_str())
            .map_err(pcap_err)?
            .promisc(true)
            .snaplen(9000)
            .open()
            .map_err(pcap_err)?;

        // ── recv thread ──────────────────────────────────────────────────────
        let (recv_tx, recv_rx) = mpsc::channel::<(Bytes, MacAddr)>(256);
        std::thread::Builder::new()
            .name(format!("pcap-recv-{iface}"))
            .spawn(move || recv_loop(cap_rx, recv_tx))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        // ── send thread ──────────────────────────────────────────────────────
        let (send_tx, send_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        std::thread::Builder::new()
            .name(format!("pcap-send-{iface}"))
            .spawn(move || send_loop(cap_tx, send_rx))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        Ok(Self {
            iface,
            local_mac,
            rx: Mutex::new(recv_rx),
            tx: send_tx,
        })
    }

    pub fn iface(&self) -> &str {
        &self.iface
    }

    pub fn local_mac(&self) -> MacAddr {
        self.local_mac
    }

    /// Receive the next NDN Ethernet frame.
    ///
    /// Returns `(payload, src_mac)` with the 14-byte Ethernet header stripped.
    pub async fn recv(&self) -> std::io::Result<(Bytes, MacAddr)> {
        self.rx.lock().await.recv().await.ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "pcap recv thread exited")
        })
    }

    /// Send `payload` as an NDN Ethernet frame to `dst_mac`.
    ///
    /// Prepends `[dst_mac][local_mac][0x86, 0x24]`.
    pub async fn send_to(&self, payload: &[u8], dst_mac: &MacAddr) -> std::io::Result<()> {
        let mut frame = Vec::with_capacity(ETHER_HEADER_LEN + payload.len());
        frame.extend_from_slice(dst_mac.as_bytes());
        frame.extend_from_slice(self.local_mac.as_bytes());
        let et = (NDN_ETHERTYPE as u16).to_be_bytes();
        frame.extend_from_slice(&et);
        frame.extend_from_slice(payload);

        self.tx.send(frame).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "pcap send thread exited")
        })
    }

    /// Send `payload` to the NDN Ethernet multicast MAC.
    pub async fn send_to_mcast(&self, payload: &[u8]) -> std::io::Result<()> {
        self.send_to(payload, &NDN_ETHER_MCAST_MAC).await
    }
}

// ─── Background thread loops ──────────────────────────────────────────────────

fn recv_loop(mut cap: Capture<pcap::Active>, tx: mpsc::Sender<(Bytes, MacAddr)>) {
    loop {
        match cap.next_packet() {
            Ok(pkt) => {
                let data = pkt.data;
                if data.len() < ETHER_HEADER_LEN {
                    continue;
                }
                let src_mac =
                    MacAddr([data[6], data[7], data[8], data[9], data[10], data[11]]);
                let payload = Bytes::copy_from_slice(&data[ETHER_HEADER_LEN..]);
                if tx.blocking_send((payload, src_mac)).is_err() {
                    break;
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(_) => break,
        }
    }
}

fn send_loop(mut cap: Capture<pcap::Active>, mut rx: mpsc::UnboundedReceiver<Vec<u8>>) {
    while let Some(frame) = rx.blocking_recv() {
        let _ = cap.sendpacket(frame.as_slice());
    }
}

// ─── Error conversion ─────────────────────────────────────────────────────────

fn pcap_err(e: pcap::Error) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ndn_ether_mcast_mac_is_multicast() {
        assert_eq!(NDN_ETHER_MCAST_MAC.as_bytes()[0] & 0x01, 0x01);
    }

    #[test]
    fn ether_header_len_is_14() {
        assert_eq!(ETHER_HEADER_LEN, 14);
    }

    #[test]
    fn wide_eq_matches_ascii() {
        // "Ethernet\0" as a static wide array.
        let wide: Vec<u16> = "Ethernet\0".encode_utf16().collect();
        assert!(wide_eq(wide.as_ptr(), "Ethernet"));
        assert!(!wide_eq(wide.as_ptr(), "Wifi"));
    }

    #[test]
    fn wide_eq_null_returns_false() {
        assert!(!wide_eq(std::ptr::null(), "anything"));
    }
}
