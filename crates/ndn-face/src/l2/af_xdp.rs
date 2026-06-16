//! AF_XDP Ethernet I/O backend (Linux, `af-xdp` feature).
//!
//! A kernel-bypass I/O backend for the NDN-over-Ethernet face (EtherType
//! `NDN_ETHERTYPE` = 0x8624), an alternative to the `af_packet` ring. Built on
//! pure-Rust `aya` (loads a tiny XDP program that `XDP_REDIRECT`s frames into
//! an `XskMap`) + `xdpilone` (UMEM + XSK rings). Validated end-to-end by the
//! Phase A spike (`.claude/afxdp-spike/`).
//!
//! **Phase A:** single queue, copy-mode (UMEM↔`Bytes`), `FaceKind::Ethernet`.
//! All `aya`/`xdpilone` state lives in a dedicated io-thread; the face holds
//! only channel endpoints, so it stays `Send + Sync`. RX frames are filtered to
//! 0x8624 and the 14-byte Ethernet header is stripped before delivery; TX
//! prepends `[peer_mac | src_mac | 0x8624]`. The contract therefore matches
//! `NamedEtherFace` (recv/send carry the bare NDN payload).
//!
//! Privileges: loading/attaching the XDP program + binding the XSK needs
//! CAP_BPF/CAP_NET_ADMIN/CAP_NET_RAW (root). Design:
//! `.claude/notes/afxdp-face-scope-2026-05-24.md`.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use aya::Ebpf;
use aya::maps::XskMap;
use aya::programs::{Xdp, XdpFlags};
use bytes::Bytes;
use tokio::sync::{Mutex as TokioMutex, mpsc};
use xdpilone::{IfInfo, Socket, SocketConfig, Umem, UmemConfig};

use ndn_transport::{FaceError, FaceId, FaceKind, Transport};

use crate::NDN_ETHERTYPE;
use crate::l2::af_packet::MacAddr;

const FRAME_SIZE: u32 = 4096;
const NUM_FRAMES: u32 = 4096;
/// First half of the UMEM feeds the RX/FILL ring; second half is the TX pool.
const RX_FRAMES: u32 = NUM_FRAMES / 2;
const ETH_HDR: usize = 14;
const QUEUE_DEPTH: usize = 2048;

fn io_err<E: std::fmt::Display>(e: E) -> FaceError {
    FaceError::Io(std::io::Error::other(e.to_string()))
}

/// An AF_XDP-backed NDN-over-Ethernet face. See module docs.
pub struct AfXdpFace {
    id: FaceId,
    iface: String,
    peer_mac: MacAddr,
    mtu: usize,
    tx: mpsc::Sender<Bytes>,
    rx: TokioMutex<mpsc::Receiver<Bytes>>,
    cancel: Arc<AtomicBool>,
    io: Option<std::thread::JoinHandle<()>>,
}

/// The XDP redirect-to-XskMap program, vendored at `bpf/redirect.bpf.o` and
/// embedded so the face works with no external object. See `bpf/README.md`.
const DEFAULT_REDIRECT_OBJ: &[u8] = include_bytes!("../../bpf/redirect.bpf.o");

impl AfXdpFace {
    /// Create an AF_XDP face on `iface`/`queue`, sending to `peer_mac`, loading
    /// the XDP redirect object (holding the `redirect` program and the `XSKS`
    /// xskmap) from `bpf_obj`. Returns once the io-thread has set up the socket
    /// and attached the program, or the setup error.
    pub fn new(
        id: FaceId,
        iface: &str,
        queue: u32,
        peer_mac: MacAddr,
        bpf_obj: PathBuf,
    ) -> Result<Self, FaceError> {
        let obj = std::fs::read(&bpf_obj).map_err(FaceError::Io)?;
        Self::new_inner(id, iface, queue, peer_mac, obj)
    }

    /// Like [`new`](Self::new) but uses the redirect program embedded in the
    /// binary ([`DEFAULT_REDIRECT_OBJ`]) — no external object required.
    pub fn new_with_embedded_redirect(
        id: FaceId,
        iface: &str,
        queue: u32,
        peer_mac: MacAddr,
    ) -> Result<Self, FaceError> {
        Self::new_inner(id, iface, queue, peer_mac, DEFAULT_REDIRECT_OBJ.to_vec())
    }

    fn new_inner(
        id: FaceId,
        iface: &str,
        queue: u32,
        peer_mac: MacAddr,
        obj: Vec<u8>,
    ) -> Result<Self, FaceError> {
        let (tx_tx, tx_rx) = mpsc::channel::<Bytes>(QUEUE_DEPTH);
        let (rx_tx, rx_rx) = mpsc::channel::<Bytes>(QUEUE_DEPTH);
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<(), FaceError>>();
        let cancel = Arc::new(AtomicBool::new(false));

        let iface_owned = iface.to_string();
        let src_mac = crate::l2::get_interface_mac(iface).map_err(io_err)?;
        let cancel_io = Arc::clone(&cancel);
        let io = std::thread::Builder::new()
            .name(format!("afxdp-{iface}"))
            .spawn(
                move || match IoState::setup(&iface_owned, queue, src_mac, peer_mac, obj) {
                    Ok(mut st) => {
                        let _ = ready_tx.send(Ok(()));
                        st.run(tx_rx, rx_tx, cancel_io);
                    }
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                    }
                },
            )
            .map_err(FaceError::Io)?;

        ready_rx.recv().map_err(|_| FaceError::Closed)??;

        Ok(Self {
            id,
            iface: iface.to_string(),
            peer_mac,
            mtu: (FRAME_SIZE as usize) - ETH_HDR,
            tx: tx_tx,
            rx: TokioMutex::new(rx_rx),
            cancel,
            io: Some(io),
        })
    }
}

impl Drop for AfXdpFace {
    fn drop(&mut self) {
        // Signal the io-thread, then join so it can flush queued TX frames
        // (it does a final drain on cancel) before the UMEM/socket tear down.
        self.cancel.store(true, Ordering::Relaxed);
        if let Some(h) = self.io.take() {
            let _ = h.join();
        }
    }
}

impl Transport for AfXdpFace {
    fn id(&self) -> FaceId {
        self.id
    }

    fn kind(&self) -> FaceKind {
        FaceKind::Ethernet
    }

    fn remote_uri(&self) -> Option<String> {
        Some(format!("afxdp://[{}]/{}", self.peer_mac, self.iface))
    }

    fn local_uri(&self) -> Option<String> {
        Some(format!("dev://{}", self.iface))
    }

    fn send_mtu(&self) -> Option<usize> {
        Some(self.mtu)
    }

    async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
        let mut rx = self.rx.lock().await;
        rx.recv().await.ok_or(FaceError::Closed)
    }

    async fn send_bytes(&self, pkt: Bytes) -> Result<(), FaceError> {
        self.tx.send(pkt).await.map_err(|_| FaceError::Closed)
    }
}

/// All `aya`/`xdpilone` state, owned by the io-thread (never crosses threads).
struct IoState {
    area: *mut u8,
    /// Held for RAII — dropping the `Umem` tears down the socket/mmap.
    _umem: Umem,
    device: xdpilone::DeviceQueue,
    rx: xdpilone::RingRx,
    tx: xdpilone::RingTx,
    free_tx: Vec<u64>,
    eth_hdr: [u8; ETH_HDR],
    // Kept alive so the attached XDP program + XskMap entry persist.
    _bpf: Ebpf,
    _xsks: XskMap<aya::maps::MapData>,
}

impl IoState {
    fn setup(
        iface: &str,
        queue: u32,
        src_mac: MacAddr,
        peer_mac: MacAddr,
        obj: Vec<u8>,
    ) -> Result<Self, FaceError> {
        // UMEM backing area: page-aligned anonymous mmap.
        let area_len = (FRAME_SIZE * NUM_FRAMES) as usize;
        let area_ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                area_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if area_ptr == libc::MAP_FAILED {
            return Err(io_err("mmap UMEM area failed"));
        }
        let area = area_ptr as *mut u8;
        let nn = std::ptr::NonNull::slice_from_raw_parts(
            std::ptr::NonNull::new(area).unwrap(),
            area_len,
        );

        let umem = unsafe {
            Umem::new(
                UmemConfig {
                    fill_size: RX_FRAMES,
                    complete_size: NUM_FRAMES - RX_FRAMES,
                    frame_size: FRAME_SIZE,
                    headroom: 0,
                    flags: 0,
                },
                nn,
            )
        }
        .map_err(io_err)?;

        let mut ifinfo = IfInfo::invalid();
        let cname = std::ffi::CString::new(iface).map_err(io_err)?;
        ifinfo.from_name(&cname).map_err(io_err)?;
        ifinfo.set_queue(queue);

        let sock = Socket::with_shared(&ifinfo, &umem).map_err(io_err)?;
        let device = umem.fq_cq(&sock).map_err(io_err)?;
        let rxtx = umem
            .rx_tx(
                &sock,
                &SocketConfig {
                    rx_size: std::num::NonZeroU32::new(RX_FRAMES),
                    tx_size: std::num::NonZeroU32::new(NUM_FRAMES - RX_FRAMES),
                    bind_flags: 0,
                },
            )
            .map_err(io_err)?;
        let rx = rxtx.map_rx().map_err(io_err)?;
        let tx = rxtx.map_tx().map_err(io_err)?;
        umem.bind(&rxtx).map_err(io_err)?;

        // Load + attach the redirect program; register our XSK at the queue.
        let mut bpf = Ebpf::load(&obj).map_err(io_err)?;
        let prog: &mut Xdp = bpf
            .program_mut("redirect")
            .ok_or_else(|| io_err("no `redirect` program in bpf object"))?
            .try_into()
            .map_err(io_err)?;
        prog.load().map_err(io_err)?;
        prog.attach(iface, XdpFlags::SKB_MODE).map_err(io_err)?;
        let mut xsks: XskMap<aya::maps::MapData> = bpf
            .take_map("XSKS")
            .ok_or_else(|| io_err("no XSKS map in bpf object"))?
            .try_into()
            .map_err(io_err)?;
        let fd = rxtx.as_raw_fd();
        xsks.set(queue, unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) }, 0)
            .map_err(io_err)?;

        // Prime the FILL ring with the RX frames.
        let mut device = device;
        {
            let mut fq = device.fill(RX_FRAMES);
            fq.insert((0..RX_FRAMES as u64).map(|i| i * FRAME_SIZE as u64));
            fq.commit();
        }

        // TX pool = the second half of the UMEM.
        let free_tx: Vec<u64> = (RX_FRAMES..NUM_FRAMES)
            .map(|i| i as u64 * FRAME_SIZE as u64)
            .collect();

        let mut eth_hdr = [0u8; ETH_HDR];
        eth_hdr[0..6].copy_from_slice(&peer_mac.0);
        eth_hdr[6..12].copy_from_slice(&src_mac.0);
        eth_hdr[12..14].copy_from_slice(&NDN_ETHERTYPE.to_be_bytes());

        Ok(IoState {
            area,
            _umem: umem,
            device,
            rx,
            tx,
            free_tx,
            eth_hdr,
            _bpf: bpf,
            _xsks: xsks,
        })
    }

    fn run(
        &mut self,
        mut tx_rx: mpsc::Receiver<Bytes>,
        rx_tx: mpsc::Sender<Bytes>,
        cancel: Arc<AtomicBool>,
    ) {
        let ethertype = NDN_ETHERTYPE.to_be_bytes();
        while !cancel.load(Ordering::Relaxed) {
            // RX: drain redirected frames, filter 0x8624, strip the eth header.
            let avail = self.rx.available();
            let mut did_work = avail > 0;
            if avail > 0 {
                let mut recycle: Vec<u64> = Vec::with_capacity(avail as usize);
                {
                    let mut r = self.rx.receive(avail);
                    while let Some(desc) = r.read() {
                        let len = desc.len as usize;
                        if len > ETH_HDR {
                            let frame = unsafe {
                                std::slice::from_raw_parts(self.area.add(desc.addr as usize), len)
                            };
                            if frame[12..14] == ethertype {
                                let _ = rx_tx.try_send(Bytes::copy_from_slice(&frame[ETH_HDR..]));
                            }
                        }
                        recycle.push(desc.addr & !(FRAME_SIZE as u64 - 1));
                    }
                    r.release();
                }
                let mut fq = self.device.fill(recycle.len() as u32);
                fq.insert(recycle.into_iter());
                fq.commit();
            }

            self.reclaim_tx();
            did_work |= self.drain_tx(&mut tx_rx);

            if !did_work {
                std::thread::sleep(std::time::Duration::from_micros(50));
            }
        }

        // Graceful flush on cancel: transmit anything still queued, then give
        // the kernel a moment to send before the socket/UMEM tear down.
        self.drain_tx(&mut tx_rx);
        std::thread::sleep(std::time::Duration::from_millis(5));
        self.reclaim_tx();
    }

    /// Reclaim completed TX frames from the completion ring into the pool.
    fn reclaim_tx(&mut self) {
        let mut cq = self.device.complete(u32::MAX);
        while let Some(addr) = cq.read() {
            self.free_tx.push(addr & !(FRAME_SIZE as u64 - 1));
        }
        cq.release();
    }

    /// Transmit queued payloads, prepending the Ethernet header into a free
    /// UMEM frame. Returns whether anything was submitted.
    fn drain_tx(&mut self, tx_rx: &mut mpsc::Receiver<Bytes>) -> bool {
        let mut sent = false;
        while let Ok(pkt) = tx_rx.try_recv() {
            let Some(base) = self.free_tx.pop() else {
                break; // no free TX frame; drop (Phase A)
            };
            let total = ETH_HDR + pkt.len();
            if total > FRAME_SIZE as usize {
                self.free_tx.push(base);
                continue;
            }
            unsafe {
                let dst = self.area.add(base as usize);
                std::ptr::copy_nonoverlapping(self.eth_hdr.as_ptr(), dst, ETH_HDR);
                std::ptr::copy_nonoverlapping(pkt.as_ptr(), dst.add(ETH_HDR), pkt.len());
            }
            let desc = xdpilone::xdp::XdpDesc {
                addr: base,
                len: total as u32,
                options: 0,
            };
            let mut wtx = self.tx.transmit(1);
            wtx.insert(std::iter::once(desc));
            wtx.commit();
            sent = true;
        }
        if self.tx.needs_wakeup() {
            self.tx.wake();
        }
        sent
    }
}

// The raw UMEM pointer + xdpilone rings stay thread-local; the struct is only
// ever owned by the io-thread, so no cross-thread sharing occurs.
unsafe impl Send for IoState {}
