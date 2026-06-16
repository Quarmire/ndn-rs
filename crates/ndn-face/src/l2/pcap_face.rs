//! Windows raw Ethernet via Npcap / WinPcap (`pcap` crate).
//!
//! Npcap's `Capture` handle is blocking and not Tokio-friendly, so `PcapSocket`
//! runs two OS threads — one calling `next_packet()` with a BPF filter, one
//! calling `sendpacket()` — bridged to async via `mpsc` channels. Pcap
//! captures promiscuously, so the NDN multicast MAC needs no explicit join.
//! The local MAC is resolved via `GetAdaptersAddresses` and accepts either an
//! `\Device\NPF_{GUID}` name or the adapter's friendly name.

#![cfg(target_os = "windows")]

use std::ffi::CStr;

use bytes::Bytes;
use pcap::Capture;
use tokio::sync::{Mutex, mpsc};
use windows_sys::Win32::Foundation::ERROR_BUFFER_OVERFLOW;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
};

use ndn_transport::MacAddr;

use crate::NDN_ETHERTYPE;

pub const NDN_ETHER_MCAST_MAC: MacAddr = MacAddr([0x01, 0x00, 0x5E, 0x00, 0x17, 0xAA]);
const ETHER_HEADER_LEN: usize = 14;

/// Accepts either `\Device\NPF_{GUID}` or the adapter's friendly name.
pub fn get_iface_mac(iface: &str) -> std::io::Result<MacAddr> {
    let target_guid = iface.strip_prefix(r"\Device\NPF_").unwrap_or(iface);

    const AF_UNSPEC: u32 = 0;
    const GAA_FLAG_NONE: u32 = 0;

    let mut buf_len: u32 = 16_384;
    let buf: Vec<u8>;

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
            continue;
        }
        if ret != 0 {
            return Err(std::io::Error::from_raw_os_error(ret as i32));
        }
        buf = tmp;
        break;
    }

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

        let matched =
            adapter_name.eq_ignore_ascii_case(target_guid) || wide_eq(a.FriendlyName, iface);

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

/// Compare a null-terminated wide string to a UTF-8 `&str`.
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
    unsafe { *ptr.add(wide.len()) == 0 }
}

/// Async pcap socket bound to one Ethernet interface; runs internal recv/send
/// threads bridged to tokio.
pub struct PcapSocket {
    iface: String,
    local_mac: MacAddr,
    rx: Mutex<mpsc::Receiver<(Bytes, MacAddr)>>,
    tx: mpsc::UnboundedSender<Vec<u8>>,
}

impl PcapSocket {
    /// Requires Npcap installed.
    pub fn new(iface: impl Into<String>) -> std::io::Result<Self> {
        let iface = iface.into();
        let local_mac = get_iface_mac(&iface)?;
        Self::new_with_mac(iface, local_mac)
    }

    /// For virtual interfaces or when MAC auto-detection is undesired.
    pub fn new_with_mac(iface: impl Into<String>, local_mac: MacAddr) -> std::io::Result<Self> {
        let iface = iface.into();

        let mut cap_rx = Capture::from_device(iface.as_str())
            .map_err(pcap_err)?
            .promisc(true)
            .snaplen(9000)
            .open()
            .map_err(pcap_err)?;

        cap_rx
            .filter(&format!("ether proto 0x{NDN_ETHERTYPE:04x}"), true)
            .map_err(pcap_err)?;

        let cap_tx = Capture::from_device(iface.as_str())
            .map_err(pcap_err)?
            .promisc(true)
            .snaplen(9000)
            .open()
            .map_err(pcap_err)?;

        let (recv_tx, recv_rx) = mpsc::channel::<(Bytes, MacAddr)>(256);
        std::thread::Builder::new()
            .name(format!("pcap-recv-{iface}"))
            .spawn(move || recv_loop(cap_rx, recv_tx))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

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

    /// Returns `(payload, src_mac)` with the 14-byte Ethernet header stripped.
    pub async fn recv(&self) -> std::io::Result<(Bytes, MacAddr)> {
        self.rx.lock().await.recv().await.ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "pcap recv thread exited")
        })
    }

    /// Prepends `[dst_mac][local_mac][0x86 0x24]` before injecting.
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

    pub async fn send_to_mcast(&self, payload: &[u8]) -> std::io::Result<()> {
        self.send_to(payload, &NDN_ETHER_MCAST_MAC).await
    }
}

fn recv_loop(mut cap: Capture<pcap::Active>, tx: mpsc::Sender<(Bytes, MacAddr)>) {
    loop {
        match cap.next_packet() {
            Ok(pkt) => {
                let data = pkt.data;
                if data.len() < ETHER_HEADER_LEN {
                    continue;
                }
                let src_mac = MacAddr([data[6], data[7], data[8], data[9], data[10], data[11]]);
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

fn pcap_err(e: pcap::Error) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
}

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
        let wide: Vec<u16> = "Ethernet\0".encode_utf16().collect();
        assert!(wide_eq(wide.as_ptr(), "Ethernet"));
        assert!(!wide_eq(wide.as_ptr(), "Wifi"));
    }

    #[test]
    fn wide_eq_null_returns_false() {
        assert!(!wide_eq(std::ptr::null(), "anything"));
    }
}
