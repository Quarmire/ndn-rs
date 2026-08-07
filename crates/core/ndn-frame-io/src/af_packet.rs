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

// Raw-socket FFI boundary — the one module in this crate allowed to use
// `unsafe` under the workspace `deny(unsafe_code)` policy.
#![allow(unsafe_code)]

use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use async_trait::async_trait;
use ndn_transport::FaceError;
use tokio::io::unix::AsyncFd;

use crate::{CapturedFrame, FrameFormat, FrameIo, InjectFrame};

const ETH_P_ALL: u16 = 0x0003;

/// Raw-802.11 monitor-mode injection/capture over one interface. The 802.11
/// addresses come from each [`InjectFrame`] (name-derived or default), so the
/// backend holds no source identity.
pub struct AfPacketBackend {
    socket: AsyncFd<OwnedFd>,
    ifindex: i32,
    format: FrameFormat,
    /// Advertised capability. `AF_PACKET` wraps an arbitrary kernel NIC, so this is not known
    /// from the socket; a conservative placeholder by default, overridable with
    /// [`with_capability`](Self::with_capability) by a caller that knows its NIC (or, in future,
    /// auto-filled from an nl80211 `NL80211_CMD_GET_WIPHY` query).
    capability: crate::RadioCapability,
    /// Current transmit rate as state ([`crate::FrameIo::set_rate`]); `None` ⇒ the
    /// radiotap header resolves the frame's intent. Retires per-frame `inject_at`.
    cur_mcs: std::sync::Mutex<Option<crate::McsDescriptor>>,
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
            // Placeholder until the caller overrides / an nl80211 query fills it in.
            capability: crate::RadioCapability::wifi_monitor_5ghz(vec![
                36, 40, 44, 48, 149, 153, 157, 161,
            ]),
            cur_mcs: std::sync::Mutex::new(None),
        })
    }

    /// Override the advertised [`RadioCapability`] — a caller that knows the wrapped NIC (its
    /// band(s), rates, channels) supplies the real profile instead of the conservative default.
    pub fn with_capability(mut self, capability: crate::RadioCapability) -> Self {
        self.capability = capability;
        self
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
        // Rate is state: build the radiotap header at the set MCS if present (the
        // kernel honours it), else resolve the frame's intent.
        let buf = match *self.cur_mcs.lock().unwrap() {
            Some(mcs) => crate::frame::build_at(self.format, &frame, mcs)?,
            None => crate::frame::build(self.format, &frame)?,
        };

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

    fn set_rate(&self, mcs: crate::McsDescriptor) -> Result<(), FaceError> {
        *self.cur_mcs.lock().unwrap() = Some(mcs);
        Ok(())
    }

    /// A-MSDU-aggregate a batch that carries **no per-frame rate**, by pinning it to the rate
    /// already set as bearer state — then it is the same aggregation as
    /// [`inject_batch_at`](Self::inject_batch_at).
    ///
    /// Both spellings exist because the two faces model rate differently: `MonitorWifiFace` resolves
    /// an MCS per frame and calls `inject_batch_at`, while `RadioMediumFace` holds rate as state in
    /// the bearer and sends `TxIntent`s, so it can only offer bare frames. Without this, moving
    /// A-MSDU down to the medium would have silently lost the aggregation on exactly the backend
    /// (AF_PACKET/S1G) where it matters most — the same class of quiet loss #82 part 2 fixed one
    /// layer up. Falls back to individual injection when no rate has been set yet.
    async fn inject_batch(&self, frames: Vec<InjectFrame>) -> Result<(), FaceError> {
        let Some(mcs) = *self.cur_mcs.lock().unwrap() else {
            for f in frames {
                self.inject(f).await?;
            }
            return Ok(());
        };
        self.inject_batch_at(frames.into_iter().map(|f| (f, mcs)).collect())
            .await
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
                let n =
                    unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
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
            // The TSFT clock domain is this NIC's — keyed by its ifindex, which
            // is unique per interface on this host.
            let domain = crate::ClockDomainId(self.ifindex as u32);
            if let Some(frame) = crate::frame::parse(self.format, &buf[..n], None, None, domain) {
                return Ok(frame);
            }
        }
    }

    /// A-MSDU-aggregate the batch — the actuator the face-level
    /// [`with_amsdu_batching`](../../../ndn_face_monitor_wifi/index.html) batcher
    /// drives (it calls `inject_batch_at`). One QoS-Data MPDU per destination
    /// (RA), greedily packed up to [`MAX_AMSDU_BODY`], all at the batch's rate:
    /// one PHY preamble for many NDN packets (the big lever at S1G). Each MSDU
    /// stays an independent NDN packet the receiver de-aggregates via
    /// [`parse_dot11`](crate::frame::parse_dot11), so PIT/FIB semantics are
    /// untouched. Non-`RawNdn`/`RawNdnS1g` formats fall back to the derived
    /// default (individual injection).
    ///
    /// **This override is the whole feature**, and it is reachable only through the trait object.
    /// It sat on `impl WifiRadio` until #82 part 2; when the face moved to `Arc<dyn FrameIo>` it
    /// became unreachable, and a caller that reimplements the default body instead — as #82 part 1
    /// did — loses the aggregation with no error and no log. It lives on `FrameIo` now for that
    /// reason. `ndn-face-monitor-wifi`'s `amsdu_batching_dispatches_to_the_backend_override` test
    /// guards the call.
    async fn inject_batch_at(
        &self,
        frames: Vec<(InjectFrame, crate::McsDescriptor)>,
    ) -> Result<(), FaceError> {
        match self.format {
            FrameFormat::RawNdn { .. } | FrameFormat::RawNdnS1g { .. } => {}
            _ => {
                for (f, mcs) in frames {
                    self.set_rate(mcs)?;
                    self.inject(f).await?;
                }
                return Ok(());
            }
        }
        if frames.is_empty() {
            return Ok(());
        }
        // One A-MSDU carries one MPDU rate; the batcher groups a run at one MCS.
        let mcs = frames[0].1;
        self.set_rate(mcs)?;

        // Group by RA (dst) preserving first-seen order — a broadcast face is one
        // group; split-addressed faces get one A-MSDU per destination (a single
        // MPDU has one RA, though each subframe still carries its own DA/SA).
        let mut order: Vec<[u8; 6]> = Vec::new();
        let mut groups: std::collections::HashMap<[u8; 6], Vec<([u8; 6], [u8; 6], bytes::Bytes)>> =
            std::collections::HashMap::new();
        for (f, _) in frames {
            let g = groups.entry(f.dst).or_default();
            if g.is_empty() {
                order.push(f.dst);
            }
            g.push((f.dst, f.src, f.payload));
        }

        for ra in order {
            let msdus = groups.remove(&ra).unwrap();
            let ta = msdus[0].1;
            // Greedily pack MSDUs into A-MSDUs bounded by MAX_AMSDU_BODY.
            let mut batch: Vec<([u8; 6], [u8; 6], bytes::Bytes)> = Vec::new();
            let mut acc = 0usize;
            for m in msdus {
                // Subframe on-air size: DA+SA+Len (14) + LLC/SNAP+ethertype (8) +
                // payload, 4-byte aligned.
                let sub = (14 + 8 + m.2.len() + 3) & !3;
                if !batch.is_empty() && acc + sub > MAX_AMSDU_BODY {
                    let buf = crate::frame::build_amsdu(self.format, ra, ta, &batch, 0, mcs)?;
                    self.inject_raw(&buf).await?;
                    batch.clear();
                    acc = 0;
                }
                acc += sub;
                batch.push(m);
            }
            if !batch.is_empty() {
                let buf = crate::frame::build_amsdu(self.format, ra, ta, &batch, 0, mcs)?;
                self.inject_raw(&buf).await?;
            }
        }
        Ok(())
    }
}

/// Conservative A-MSDU body cap (bytes, excluding radiotap + MPDU header). The
/// classic 802.11 small A-MSDU limit — safe across S1G bandwidths (at 1 MHz the
/// max PSDU is small, so keep aggregates modest); the cognition plane's
/// `amsdu_msdus` bounds the count on top of this. Tunable once per-STA S1G
/// max-A-MSDU-length is queried.
const MAX_AMSDU_BODY: usize = 3839;

#[async_trait]
impl crate::WifiRadio for AfPacketBackend {}

/// A monitor interface exposes the NIC's MAC TSF via radiotap TSFT (when the underlying driver
/// reports it), keyed by ifindex — a free-run per-frame RX-stamp clock. There is no read-now
/// clock over `AF_PACKET`, so `read_clock` stays the default `None`.
impl crate::RadioTime for AfPacketBackend {
    fn time_sources(&self) -> Vec<crate::RadioTimeSource> {
        vec![crate::RadioTimeSource::free_run_rx_stamp(
            crate::ClockDomainId(self.ifindex as u32),
            1_000,
        )]
    }
}

/// Returns the capability set at construction ([`with_capability`](AfPacketBackend::with_capability))
/// — a conservative 5 GHz placeholder by default, since `AF_PACKET` wraps an arbitrary NIC whose
/// real profile isn't visible from the socket (future: fill from an nl80211 wiphy query).
impl crate::RadioProfile for AfPacketBackend {
    fn capability(&self) -> crate::RadioCapability {
        self.capability.clone()
    }
}
