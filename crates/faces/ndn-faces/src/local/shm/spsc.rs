//! Custom SPSC shared-memory face (Unix only, `spsc-shm` feature).
//!
//! A named POSIX SHM region holds two lock-free single-producer/single-consumer
//! ring buffers — one for each direction.  Wakeup uses a named FIFO (pipe)
//! pair on all platforms: the engine creates two FIFOs
//! (`/tmp/.ndn-{name}.a2e.pipe` and `.e2a.pipe`); both sides open them
//! `O_RDWR | O_NONBLOCK` (avoids the blocking-open problem).  The consumer
//! awaits readability via `tokio::io::unix::AsyncFd`; the producer writes 1
//! non-blocking byte.  The parked flag in SHM is still used to avoid
//! unnecessary pipe writes when the consumer is active.
//!
//! This design integrates directly into Tokio's epoll/kqueue loop with zero
//! thread transitions, unlike the previous Linux futex + `spawn_blocking`
//! approach which routed every park through Tokio's blocking thread pool.
//!
//! # SHM layout
//!
//! ```text
//! Cache line 0 (off   0–63):  magic u64 | capacity u32 | slot_size u32 | pad
//! Cache line 1 (off  64–127): a2e_tail AtomicU32  — app writes, engine reads
//! Cache line 2 (off 128–191): a2e_head AtomicU32  — engine writes, app reads
//! Cache line 3 (off 192–255): e2a_tail AtomicU32  — engine writes, app reads
//! Cache line 4 (off 256–319): e2a_head AtomicU32  — app writes, engine reads
//! Cache line 5 (off 320–383): a2e_parked AtomicU32 — set by engine before sleeping on a2e ring
//! Cache line 6 (off 384–447): e2a_parked AtomicU32 — set by app before sleeping on e2a ring
//! Data block (off 448–N):     a2e ring (capacity × slot_stride bytes)
//! Data block (off N–end):     e2a ring (capacity × slot_stride bytes)
//!   slot_stride = 4 (length prefix) + slot_size (payload area)
//! ```
//!
//! # Conditional wakeup protocol
//!
//! The producer checks the parked flag with `SeqCst` after writing to the
//! ring; the consumer stores the parked flag with `SeqCst` before its second
//! ring check.  This total-order guarantee prevents the producer from missing
//! a sleeping consumer.
use std::ffi::CString;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use bytes::Bytes;

use ndn_transport::{Face, FaceError, FaceId, FaceKind};

use crate::local::shm::ShmError;

// ─── Named FIFO wakeup helpers ───────────────────────────────────────────────
//
// Both Linux and macOS use named FIFOs (pipes) for cross-process wakeup,
// wrapped in Tokio's AsyncFd for zero-thread-transition async integration.
// The previous Linux path used futex + spawn_blocking which routed every
// park through Tokio's blocking thread pool — expensive at 100K+ pkt/s
// and responsible for the 2.5× throughput gap vs macOS.

// ─── Constants ───────────────────────────────────────────────────────────────

const MAGIC: u64 = 0x4E44_4E5F_5348_4D00; // b"NDN_SHM\0"

/// Default number of slots per ring.
///
/// Paired with [`DEFAULT_SLOT_SIZE`] so the total default ring memory
/// is ~4.4 MiB per face (256 × 8960 × 2) — the same budget as the
/// original v1 design. Tools that need larger Data packets (chunked
/// producers at 64+ KiB segments) call `faces/create` with an explicit
/// `mtu`, and the router creates a face with a proportionally larger
/// slot_size and smaller capacity via [`capacity_for_slot`].
pub const DEFAULT_CAPACITY: u32 = 256;

/// Default slot payload size in bytes (~8.75 KiB). Covers a standard
/// NDN Data packet (≤8800 bytes on most link types) with a small
/// headroom margin. This is the right default for the majority of
/// NDN traffic: Interests (~60–200 bytes), single-packet Data
/// (~4–8 KiB content), iperf probes, ping, management, etc.
///
/// Tools that produce larger Data (chunked file transfers at 64 KiB,
/// 256 KiB, or 1 MiB segments) negotiate a bigger slot via the `mtu`
/// field of `faces/create` ControlParameters. `ndn-put` does this
/// automatically from `--chunk-size`; `ndn-peek` accepts `--mtu`.
pub const DEFAULT_SLOT_SIZE: u32 = 8960;

/// Target SHM ring memory budget per face, in bytes. Used by
/// [`capacity_for_slot`] to scale capacity inversely with slot_size
/// so that faces with large slots (256 KiB for chunked producers)
/// don't blow up memory, and faces with small slots (8960 for iperf)
/// get a deep ring that stays in L2 cache.
const SHM_BUDGET: usize = 2 * DEFAULT_CAPACITY as usize * slot_stride(DEFAULT_SLOT_SIZE);

/// NDN Data packet wire overhead above the raw content bytes:
/// Data TLV + Name + MetaInfo + SignatureInfo + SignatureValue. 16 KiB
/// is generous enough to cover a Data whose content is `mtu` bytes of
/// payload plus a long name and a large signature (Ed25519, ECDSA with
/// key locator, or a Merkle proof up to a few hundred hashes).
pub const SHM_SLOT_OVERHEAD: usize = 16 * 1024;

/// Pick a slot size for a face that needs to carry NDN Data whose
/// *content* can be up to `mtu` bytes. Rounds up to the next multiple
/// of 64 bytes so the per-slot stride stays cache-line aligned.
/// Does **not** clamp to a floor — an explicit `mtu = 8800` gets a
/// ~25 KiB slot, not the 272 KiB default. If no `mtu` is specified,
/// the caller should use `DEFAULT_SLOT_SIZE` directly.
pub fn slot_size_for_mtu(mtu: usize) -> u32 {
    let raw = mtu.saturating_add(SHM_SLOT_OVERHEAD);
    let aligned = raw.div_ceil(64) * 64;
    aligned.min(u32::MAX as usize) as u32
}

/// Compute ring capacity for a given slot_size, keeping total ring
/// memory within [`SHM_BUDGET`]. Returns at least 16 (to keep some
/// pipeline buffering even for very large slots).
pub fn capacity_for_slot(slot_size: u32) -> u32 {
    let stride = slot_stride(slot_size);
    let cap = SHM_BUDGET / (2 * stride);
    (cap as u32).max(16)
}

// Cache-line–aligned offsets for the four ring index atomics.
const OFF_A2E_TAIL: usize = 64; // app writes (producer)
const OFF_A2E_HEAD: usize = 128; // engine writes (consumer)
const OFF_E2A_TAIL: usize = 192; // engine writes (producer)
const OFF_E2A_HEAD: usize = 256; // app writes (consumer)
// Parked flags: consumer sets to 1 before sleeping, clears on wake.
const OFF_A2E_PARKED: usize = 320; // engine (a2e consumer) parked flag
const OFF_E2A_PARKED: usize = 384; // app (e2a consumer) parked flag
const HEADER_SIZE: usize = 448; // 7 × 64-byte cache lines

const fn slot_stride(slot_size: u32) -> usize {
    4 + slot_size as usize
}

/// Number of spin-loop iterations before falling through to the pipe
/// wakeup path.  64 iterations ≈ sub-µs
/// on modern hardware — enough to catch back-to-back packets without
/// causing thermal throttling from sustained spinning across multiple faces.
const SPIN_ITERS: u32 = 64;

fn shm_total_size(capacity: u32, slot_size: u32) -> usize {
    HEADER_SIZE + 2 * capacity as usize * slot_stride(slot_size)
}

fn a2e_ring_offset() -> usize {
    HEADER_SIZE
}
fn e2a_ring_offset(capacity: u32, slot_size: u32) -> usize {
    HEADER_SIZE + capacity as usize * slot_stride(slot_size)
}

// ─── Path helpers ─────────────────────────────────────────────────────────────

fn posix_shm_name(name: &str) -> String {
    format!("/ndn-shm-{name}")
}

/// Path of the FIFO the *engine* reads from (app writes to wake engine).
fn a2e_pipe_path(name: &str) -> PathBuf {
    PathBuf::from(format!("/tmp/.ndn-{name}.a2e.pipe"))
}

/// Path of the FIFO the *app* reads from (engine writes to wake app).
fn e2a_pipe_path(name: &str) -> PathBuf {
    PathBuf::from(format!("/tmp/.ndn-{name}.e2a.pipe"))
}

// ─── POSIX SHM region ────────────────────────────────────────────────────────

/// Owns a POSIX SHM mapping. The creator unlinks the name on drop.
struct ShmRegion {
    ptr: *mut u8,
    size: usize,
    /// Present when this process created the region; drives shm_unlink on drop.
    shm_name: Option<CString>,
}

unsafe impl Send for ShmRegion {}
unsafe impl Sync for ShmRegion {}

impl ShmRegion {
    /// Create and zero-initialise a new named SHM region.
    fn create(shm_name: &str, size: usize) -> Result<Self, ShmError> {
        let cname = CString::new(shm_name).map_err(|_| ShmError::InvalidName)?;
        let ptr = unsafe {
            let fd = libc::shm_open(
                cname.as_ptr(),
                libc::O_CREAT | libc::O_RDWR | libc::O_TRUNC,
                // 0o666: readable/writable by all users so an unprivileged app
                // can connect to a router running as root.  The SHM name is
                // unique per app instance, limiting exposure.
                0o666 as libc::mode_t as libc::c_uint,
            );
            if fd == -1 {
                return Err(ShmError::Io(std::io::Error::last_os_error()));
            }

            if libc::ftruncate(fd, size as libc::off_t) == -1 {
                libc::close(fd);
                return Err(ShmError::Io(std::io::Error::last_os_error()));
            }

            let p = libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            );
            libc::close(fd);
            if p == libc::MAP_FAILED {
                return Err(ShmError::Io(std::io::Error::last_os_error()));
            }
            p as *mut u8
        };
        Ok(ShmRegion {
            ptr,
            size,
            shm_name: Some(cname),
        })
    }

    /// Open an existing named SHM region created by `ShmRegion::create`.
    fn open(shm_name: &str, size: usize) -> Result<Self, ShmError> {
        let cname = CString::new(shm_name).map_err(|_| ShmError::InvalidName)?;
        let ptr = unsafe {
            let fd = libc::shm_open(cname.as_ptr(), libc::O_RDWR, 0);
            if fd == -1 {
                return Err(ShmError::Io(std::io::Error::last_os_error()));
            }

            let p = libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            );
            libc::close(fd);
            if p == libc::MAP_FAILED {
                return Err(ShmError::Io(std::io::Error::last_os_error()));
            }
            p as *mut u8
        };
        Ok(ShmRegion {
            ptr,
            size,
            shm_name: None,
        })
    }

    fn as_ptr(&self) -> *mut u8 {
        self.ptr
    }

    /// Write the header fields (magic, capacity, slot_size).
    ///
    /// # Safety
    /// Must be called exactly once immediately after `create()`, before any
    /// other process opens the region.
    unsafe fn write_header(&self, capacity: u32, slot_size: u32) {
        unsafe {
            (self.ptr as *mut u64).write_unaligned(MAGIC);
            (self.ptr.add(8) as *mut u32).write_unaligned(capacity);
            (self.ptr.add(12) as *mut u32).write_unaligned(slot_size);
        }
        // Ring indices start at zero (mmap of new ftruncated fd is zero-initialised).
    }

    /// Read and validate the header. Returns `(capacity, slot_size)`.
    ///
    /// # Safety
    /// The region must have been initialised by `write_header`.
    unsafe fn read_header(&self) -> Result<(u32, u32), ShmError> {
        unsafe {
            let magic = (self.ptr as *const u64).read_unaligned();
            if magic != MAGIC {
                return Err(ShmError::InvalidMagic);
            }
            let capacity = (self.ptr.add(8) as *const u32).read_unaligned();
            let slot_size = (self.ptr.add(12) as *const u32).read_unaligned();
            Ok((capacity, slot_size))
        }
    }
}

impl Drop for ShmRegion {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ptr as *mut libc::c_void, self.size);
            if let Some(ref n) = self.shm_name {
                libc::shm_unlink(n.as_ptr());
            }
        }
    }
}

// ─── SPSC ring operations ─────────────────────────────────────────────────────

/// Push `data` into the ring at [`ring_off`] using the tail at [`tail_off`] and
/// head at [`head_off`]. Returns `false` if the ring is full.
///
/// # Safety
/// `base` must be a valid, exclusively-written SHM mapping of sufficient size.
/// `data.len() <= slot_size` must hold.
unsafe fn ring_push(
    base: *mut u8,
    ring_off: usize,
    tail_off: usize,
    head_off: usize,
    capacity: u32,
    slot_size: u32,
    data: &[u8],
) -> bool {
    debug_assert!(data.len() <= slot_size as usize);

    let tail_a = unsafe { AtomicU32::from_ptr(base.add(tail_off) as *mut u32) };
    let head_a = unsafe { AtomicU32::from_ptr(base.add(head_off) as *mut u32) };

    let t = tail_a.load(Ordering::Relaxed);
    let h = head_a.load(Ordering::Acquire);
    if t.wrapping_sub(h) >= capacity {
        return false;
    }

    let idx = (t % capacity) as usize;
    let slot = unsafe { base.add(ring_off + idx * slot_stride(slot_size)) };

    unsafe {
        (slot as *mut u32).write_unaligned(data.len() as u32);
        std::ptr::copy_nonoverlapping(data.as_ptr(), slot.add(4), data.len());
    }
    tail_a.store(t.wrapping_add(1), Ordering::Release);
    true
}

/// Push up to `pkts.len()` packets into the ring in one tail advance.
///
/// Loads the head once (Acquire), determines the free-slot count, writes
/// as many packets as fit into consecutive slots, and publishes the tail
/// with a single Release store. Returns the number of packets pushed
/// (0 if the ring was full, `pkts.len()` on complete success, or a
/// partial count in between).
///
/// Compared to calling [`ring_push`] N times, this function:
/// - Loads the peer head *once* instead of N times (N−1 atomic loads
///   saved).
/// - Publishes a single Release store instead of N (N−1 release fences
///   saved; the consumer sees all pushed packets at once).
/// - Keeps the same per-slot length+memcpy work — batching does not
///   save per-byte cost, only per-packet synchronisation cost.
///
/// The caller is responsible for handling the "ring full" case (yield
/// and retry, same as single-packet `ring_push`).
///
/// # Safety
/// Same as [`ring_push`]. Every packet must satisfy
/// `pkt.len() <= slot_size`.
unsafe fn ring_push_batch(
    base: *mut u8,
    ring_off: usize,
    tail_off: usize,
    head_off: usize,
    capacity: u32,
    slot_size: u32,
    pkts: &[&[u8]],
) -> usize {
    if pkts.is_empty() {
        return 0;
    }
    let tail_a = unsafe { AtomicU32::from_ptr(base.add(tail_off) as *mut u32) };
    let head_a = unsafe { AtomicU32::from_ptr(base.add(head_off) as *mut u32) };

    let mut t = tail_a.load(Ordering::Relaxed);
    let h = head_a.load(Ordering::Acquire);
    let free = capacity.wrapping_sub(t.wrapping_sub(h));
    let to_push = (free as usize).min(pkts.len());
    if to_push == 0 {
        return 0;
    }

    for pkt in &pkts[..to_push] {
        debug_assert!(pkt.len() <= slot_size as usize);
        let idx = (t % capacity) as usize;
        let slot = unsafe { base.add(ring_off + idx * slot_stride(slot_size)) };
        unsafe {
            (slot as *mut u32).write_unaligned(pkt.len() as u32);
            std::ptr::copy_nonoverlapping(pkt.as_ptr(), slot.add(4), pkt.len());
        }
        t = t.wrapping_add(1);
    }
    // Single Release store publishes all `to_push` slots to the consumer.
    tail_a.store(t, Ordering::Release);
    to_push
}

/// Pop one packet from the ring. Returns `None` if empty.
///
/// # Safety
/// Same as [`ring_push`].
unsafe fn ring_pop(
    base: *mut u8,
    ring_off: usize,
    tail_off: usize,
    head_off: usize,
    capacity: u32,
    slot_size: u32,
) -> Option<Bytes> {
    let tail_a = unsafe { AtomicU32::from_ptr(base.add(tail_off) as *mut u32) };
    let head_a = unsafe { AtomicU32::from_ptr(base.add(head_off) as *mut u32) };

    let h = head_a.load(Ordering::Relaxed);
    let t = tail_a.load(Ordering::Acquire);
    if h == t {
        return None;
    }

    let idx = (h % capacity) as usize;
    let slot = unsafe { base.add(ring_off + idx * slot_stride(slot_size)) };

    let len = unsafe { (slot as *const u32).read_unaligned() as usize };
    // Clamp to prevent out-of-bounds read if SHM is corrupted.
    let len = len.min(slot_size as usize);
    let data = unsafe { Bytes::copy_from_slice(std::slice::from_raw_parts(slot.add(4), len)) };

    head_a.store(h.wrapping_add(1), Ordering::Release);
    Some(data)
}

// ─── FIFO wakeup helpers ─────────────────────────────────────────────────────

/// Open a named FIFO (must already exist) with `O_RDWR | O_NONBLOCK`.
///
/// `O_RDWR` avoids the blocking-open problem: the open succeeds immediately
/// even if the other end has not yet opened the FIFO.  Both sides only use
/// the fd in the direction they own (reads or writes), so no cross-reading
/// occurs.
fn open_fifo_rdwr(path: &std::path::Path) -> Result<std::os::unix::io::OwnedFd, ShmError> {
    use std::os::unix::io::{FromRawFd, OwnedFd};
    let cpath = CString::new(path.to_str().unwrap_or("")).map_err(|_| ShmError::InvalidName)?;
    let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDWR | libc::O_NONBLOCK) };
    if fd == -1 {
        return Err(ShmError::Io(std::io::Error::last_os_error()));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Await readability on the pipe fd, then drain all buffered bytes.
///
/// Returns `Err` on EOF (peer died) or any I/O error.
async fn pipe_await(
    rx: &tokio::io::unix::AsyncFd<std::os::unix::io::OwnedFd>,
) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    loop {
        let mut guard = rx.readable().await?;
        let mut buf = [0u8; 64];
        let fd = rx.get_ref().as_raw_fd();
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        guard.clear_ready();
        if n > 0 {
            return Ok(());
        }
        if n == 0 {
            // EOF — peer closed their end.
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "SHM wakeup pipe closed (peer died)",
            ));
        }
        if n == -1 {
            let err = std::io::Error::last_os_error();
            if err.kind() != std::io::ErrorKind::WouldBlock {
                return Err(err);
            }
        }
    }
}

/// Write one wakeup byte to a non-blocking pipe fd.
///
/// Silently ignores `EAGAIN` (pipe buffer full): if the buffer is full the
/// consumer is already being woken by a previous byte.
fn pipe_write(tx: &std::os::unix::io::OwnedFd) {
    use std::os::unix::io::AsRawFd;
    let b = [1u8];
    unsafe {
        libc::write(tx.as_raw_fd(), b.as_ptr() as *const libc::c_void, 1);
    }
}

// ─── SpscFace (engine side) ───────────────────────────────────────────────────

/// Engine-side SPSC SHM face.
///
/// Create with [`SpscFace::create`]; register with the engine via
/// `ForwarderEngine::add_face`. Give the `name` to the application so it can
/// call [`SpscHandle::connect`].
pub struct SpscFace {
    id: FaceId,
    shm: ShmRegion,
    capacity: u32,
    slot_size: u32,
    a2e_off: usize,
    e2a_off: usize,
    /// FIFO the engine awaits readability on (app writes here to wake engine).
    a2e_rx: tokio::io::unix::AsyncFd<std::os::unix::io::OwnedFd>,
    /// FIFO the engine writes to (to wake the app).
    e2a_tx: std::os::unix::io::OwnedFd,
    /// Paths of the FIFOs created by the engine — removed on drop.
    a2e_pipe_path: PathBuf,
    e2a_pipe_path: PathBuf,
}

impl SpscFace {
    /// Create the SHM region and set up the wakeup mechanism.
    ///
    /// `name` identifies this face (e.g. `"sensor-0"`); pass it to
    /// [`SpscHandle::connect`] in the application process.
    pub fn create(id: FaceId, name: &str) -> Result<Self, ShmError> {
        Self::create_with(id, name, DEFAULT_CAPACITY, DEFAULT_SLOT_SIZE)
    }

    /// Create a face sized for Data packets whose content can be up
    /// to `mtu` bytes. Picks `slot_size = slot_size_for_mtu(mtu)` and
    /// scales `capacity` inversely so the total ring memory stays
    /// within [`SHM_BUDGET`]. Use this when an application has
    /// announced its expected packet size via `faces/create`'s `mtu`
    /// ControlParameter.
    pub fn create_for_mtu(id: FaceId, name: &str, mtu: usize) -> Result<Self, ShmError> {
        let ss = slot_size_for_mtu(mtu);
        Self::create_with(id, name, capacity_for_slot(ss), ss)
    }

    /// Create with explicit ring parameters.
    pub fn create_with(
        id: FaceId,
        name: &str,
        capacity: u32,
        slot_size: u32,
    ) -> Result<Self, ShmError> {
        let size = shm_total_size(capacity, slot_size);
        let shm = ShmRegion::create(&posix_shm_name(name), size)?;
        unsafe {
            shm.write_header(capacity, slot_size);
        }

        let a2e_off = a2e_ring_offset();
        let e2a_off = e2a_ring_offset(capacity, slot_size);

        use tokio::io::unix::AsyncFd;

        let a2e_path = a2e_pipe_path(name);
        let e2a_path = e2a_pipe_path(name);

        // Remove stale FIFOs from a previous run.
        let _ = std::fs::remove_file(&a2e_path);
        let _ = std::fs::remove_file(&e2a_path);

        // Create the named FIFOs.
        for p in [&a2e_path, &e2a_path] {
            let cp = CString::new(p.to_str().unwrap_or("")).map_err(|_| ShmError::InvalidName)?;
            if unsafe { libc::mkfifo(cp.as_ptr(), 0o600) } == -1 {
                return Err(ShmError::Io(std::io::Error::last_os_error()));
            }
        }

        // Engine reads from a2e (awaits wakeup from app).
        let a2e_fd = open_fifo_rdwr(&a2e_path)?;
        let a2e_rx = AsyncFd::new(a2e_fd).map_err(ShmError::Io)?;

        // Engine writes to e2a (sends wakeup to app).
        let e2a_tx = open_fifo_rdwr(&e2a_path)?;

        Ok(SpscFace {
            id,
            shm,
            capacity,
            slot_size,
            a2e_off,
            e2a_off,
            a2e_rx,
            e2a_tx,
            a2e_pipe_path: a2e_path,
            e2a_pipe_path: e2a_path,
        })
    }

    fn try_pop_a2e(&self) -> Option<Bytes> {
        unsafe {
            ring_pop(
                self.shm.as_ptr(),
                self.a2e_off,
                OFF_A2E_TAIL,
                OFF_A2E_HEAD,
                self.capacity,
                self.slot_size,
            )
        }
    }

    fn try_push_e2a(&self, data: &[u8]) -> bool {
        unsafe {
            ring_push(
                self.shm.as_ptr(),
                self.e2a_off,
                OFF_E2A_TAIL,
                OFF_E2A_HEAD,
                self.capacity,
                self.slot_size,
                data,
            )
        }
    }

    fn try_push_batch_e2a(&self, pkts: &[&[u8]]) -> usize {
        unsafe {
            ring_push_batch(
                self.shm.as_ptr(),
                self.e2a_off,
                OFF_E2A_TAIL,
                OFF_E2A_HEAD,
                self.capacity,
                self.slot_size,
                pkts,
            )
        }
    }

    /// Send multiple Data/Interest packets to the app in a single tail
    /// advance. See [`SpscHandle::send_batch`] for the semantics — this
    /// is the engine-side mirror.
    pub async fn send_batch(&self, pkts: &[Bytes]) -> Result<(), FaceError> {
        if pkts.is_empty() {
            return Ok(());
        }
        for pkt in pkts {
            if pkt.len() > self.slot_size as usize {
                return Err(FaceError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "packet exceeds SHM slot size",
                )));
            }
        }
        // SAFETY: parked flag within mapped SHM region.
        let parked =
            unsafe { AtomicU32::from_ptr(self.shm.as_ptr().add(OFF_E2A_PARKED) as *mut u32) };
        // Build a `&[&[u8]]` view once — cheaper than re-slicing inside
        // the yield loop.
        let views: Vec<&[u8]> = pkts.iter().map(|p| p.as_ref()).collect();
        let mut start = 0usize;
        while start < views.len() {
            let pushed = self.try_push_batch_e2a(&views[start..]);
            if pushed == 0 {
                tokio::task::yield_now().await;
                continue;
            }
            start += pushed;
            if parked.load(Ordering::SeqCst) != 0 {
                pipe_write(&self.e2a_tx);
            }
        }
        Ok(())
    }
}

impl Drop for SpscFace {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.a2e_pipe_path);
        let _ = std::fs::remove_file(&self.e2a_pipe_path);
    }
}

impl Face for SpscFace {
    fn id(&self) -> FaceId {
        self.id
    }
    fn kind(&self) -> FaceKind {
        FaceKind::Shm
    }

    async fn recv(&self) -> Result<Bytes, FaceError> {
        // SAFETY: parked flag is within the mapped SHM region.
        let parked =
            unsafe { AtomicU32::from_ptr(self.shm.as_ptr().add(OFF_A2E_PARKED) as *mut u32) };
        loop {
            if let Some(pkt) = self.try_pop_a2e() {
                return Ok(pkt);
            }
            // Spin before parking — avoids expensive pipe syscall
            // when packets arrive within microseconds of each other.
            for _ in 0..SPIN_ITERS {
                std::hint::spin_loop();
                if let Some(pkt) = self.try_pop_a2e() {
                    return Ok(pkt);
                }
            }
            // Announce intent to sleep with SeqCst so the app's next SeqCst
            // load on the parked flag observes this before or after it pushes
            // to the ring — never concurrently missed.
            parked.store(1, Ordering::SeqCst);
            // Second ring check: if the app already pushed between our first
            // check and the flag store, we see it here and avoid sleeping.
            if let Some(pkt) = self.try_pop_a2e() {
                parked.store(0, Ordering::Relaxed);
                return Ok(pkt);
            }

            // Sleep until the app sends a wakeup via the FIFO.
            pipe_await(&self.a2e_rx)
                .await
                .map_err(|_| FaceError::Closed)?;

            parked.store(0, Ordering::Relaxed);
        }
    }

    async fn send(&self, pkt: Bytes) -> Result<(), FaceError> {
        if pkt.len() > self.slot_size as usize {
            return Err(FaceError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "packet exceeds SHM slot size",
            )));
        }
        // SAFETY: parked flag within mapped SHM region.
        let parked =
            unsafe { AtomicU32::from_ptr(self.shm.as_ptr().add(OFF_E2A_PARKED) as *mut u32) };
        // Yield until there is space in the e2a ring (backpressure).
        loop {
            if self.try_push_e2a(&pkt) {
                break;
            }
            tokio::task::yield_now().await;
        }
        // Only send a wakeup if the app is actually sleeping.
        if parked.load(Ordering::SeqCst) != 0 {
            pipe_write(&self.e2a_tx);
        }
        Ok(())
    }
}

// ─── SpscHandle (application side) ───────────────────────────────────────────

/// Application-side SPSC SHM handle.
///
/// Connect with [`SpscHandle::connect`] using the same `name` passed to
/// [`SpscFace::create`] in the engine process.
///
/// Set a `CancellationToken` via [`set_cancel`] to abort `recv`/`send` when
/// the router's control face disconnects (the O_RDWR FIFO trick means EOF
/// detection alone is unreliable).
pub struct SpscHandle {
    shm: ShmRegion,
    capacity: u32,
    slot_size: u32,
    a2e_off: usize,
    e2a_off: usize,
    /// FIFO the app awaits readability on (engine writes here to wake app).
    e2a_rx: tokio::io::unix::AsyncFd<std::os::unix::io::OwnedFd>,
    /// FIFO the app writes to (to wake the engine).
    a2e_tx: std::os::unix::io::OwnedFd,
    /// Cancelled when the router control face dies.
    cancel: tokio_util::sync::CancellationToken,
}

impl SpscHandle {
    /// Open the SHM region created by the engine and set up the wakeup mechanism.
    pub fn connect(name: &str) -> Result<Self, ShmError> {
        let shm_name_str = posix_shm_name(name);
        let cname = CString::new(shm_name_str.as_str()).map_err(|_| ShmError::InvalidName)?;

        // Phase 1: open just the header to read capacity and slot_size.
        let (capacity, slot_size) = unsafe {
            let fd = libc::shm_open(cname.as_ptr(), libc::O_RDONLY, 0);
            if fd == -1 {
                return Err(ShmError::Io(std::io::Error::last_os_error()));
            }
            let p = libc::mmap(
                std::ptr::null_mut(),
                HEADER_SIZE,
                libc::PROT_READ,
                libc::MAP_SHARED,
                fd,
                0,
            );
            libc::close(fd);
            if p == libc::MAP_FAILED {
                return Err(ShmError::Io(std::io::Error::last_os_error()));
            }
            let base = p as *const u8;
            let magic = (base as *const u64).read_unaligned();
            if magic != MAGIC {
                libc::munmap(p, HEADER_SIZE);
                return Err(ShmError::InvalidMagic);
            }
            let cap = (base.add(8) as *const u32).read_unaligned();
            let slen = (base.add(12) as *const u32).read_unaligned();
            libc::munmap(p, HEADER_SIZE);
            (cap, slen)
        };

        // Phase 2: open the full region read-write.
        let size = shm_total_size(capacity, slot_size);
        let shm = ShmRegion::open(&shm_name_str, size)?;
        unsafe { shm.read_header()? };

        let a2e_off = a2e_ring_offset();
        let e2a_off = e2a_ring_offset(capacity, slot_size);

        use tokio::io::unix::AsyncFd;

        let a2e_path = a2e_pipe_path(name); // app writes here to wake engine
        let e2a_path = e2a_pipe_path(name); // app reads here (engine wakes app)

        // App writes to a2e FIFO (to wake engine).
        let a2e_tx = open_fifo_rdwr(&a2e_path)?;

        // App reads from e2a FIFO (awaits wakeup from engine).
        let e2a_fd = open_fifo_rdwr(&e2a_path)?;
        let e2a_rx = AsyncFd::new(e2a_fd).map_err(ShmError::Io)?;

        Ok(SpscHandle {
            shm,
            capacity,
            slot_size,
            a2e_off,
            e2a_off,
            e2a_rx,
            a2e_tx,
            cancel: tokio_util::sync::CancellationToken::new(),
        })
    }

    /// Attach a cancellation token (typically a child of the control face's
    /// lifecycle token).  When cancelled, `recv()` returns `None` and `send()`
    /// returns `Err`.
    pub fn set_cancel(&mut self, cancel: tokio_util::sync::CancellationToken) {
        self.cancel = cancel;
    }

    fn try_push_a2e(&self, data: &[u8]) -> bool {
        unsafe {
            ring_push(
                self.shm.as_ptr(),
                self.a2e_off,
                OFF_A2E_TAIL,
                OFF_A2E_HEAD,
                self.capacity,
                self.slot_size,
                data,
            )
        }
    }

    fn try_pop_e2a(&self) -> Option<Bytes> {
        unsafe {
            ring_pop(
                self.shm.as_ptr(),
                self.e2a_off,
                OFF_E2A_TAIL,
                OFF_E2A_HEAD,
                self.capacity,
                self.slot_size,
            )
        }
    }

    fn try_push_batch_a2e(&self, pkts: &[&[u8]]) -> usize {
        unsafe {
            ring_push_batch(
                self.shm.as_ptr(),
                self.a2e_off,
                OFF_A2E_TAIL,
                OFF_A2E_HEAD,
                self.capacity,
                self.slot_size,
                pkts,
            )
        }
    }

    /// Send multiple packets to the engine in one tail advance.
    ///
    /// Equivalent in outcome to calling [`send`](Self::send) `pkts.len()`
    /// times in order, but pays the synchronisation cost once rather than
    /// N times:
    ///
    /// - One head load (Acquire) per ring-full check instead of N.
    /// - One tail store (Release) per successful push batch instead of N.
    /// - One wakeup pipe write at the end instead of up to N.
    /// - Far fewer `tokio::task::yield_now().await` points when the ring
    ///   is not contended: a window-fill of 16 Interests becomes one call,
    ///   one atomic ring transition, and zero scheduler round trips in the
    ///   common case (instead of 16 awaits and potentially 16 yields).
    ///
    /// Like `send`, this yields cooperatively if the ring fills mid-batch
    /// and waits (up to a 5 s wall-clock deadline) for the engine to drain
    /// enough slots. Partial progress is preserved across yields — the
    /// caller is guaranteed that all `pkts` eventually reach the ring or
    /// the call returns `Err(Closed)`.
    ///
    /// Every packet in `pkts` must satisfy `pkt.len() <= slot_size`, or
    /// the call returns `Err(PacketTooLarge)` before publishing anything.
    /// The size check is performed up-front so a batch is either fully
    /// publishable or rejected atomically for the over-size case.
    pub async fn send_batch(&self, pkts: &[Bytes]) -> Result<(), ShmError> {
        if self.cancel.is_cancelled() {
            return Err(ShmError::Closed);
        }
        if pkts.is_empty() {
            return Ok(());
        }
        for pkt in pkts {
            if pkt.len() > self.slot_size as usize {
                return Err(ShmError::PacketTooLarge);
            }
        }
        // SAFETY: parked flag within mapped SHM region.
        let parked =
            unsafe { AtomicU32::from_ptr(self.shm.as_ptr().add(OFF_A2E_PARKED) as *mut u32) };
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        let views: Vec<&[u8]> = pkts.iter().map(|p| p.as_ref()).collect();
        let mut start = 0usize;
        while start < views.len() {
            let pushed = self.try_push_batch_a2e(&views[start..]);
            if pushed == 0 {
                if self.cancel.is_cancelled() {
                    return Err(ShmError::Closed);
                }
                if tokio::time::Instant::now() >= deadline {
                    return Err(ShmError::Closed);
                }
                tokio::task::yield_now().await;
                continue;
            }
            start += pushed;
            // Wake the engine after each partial push so it can drain
            // the ring. Without this, a batch larger than ring capacity
            // deadlocks: we yield waiting for space, the engine parks
            // because nobody woke it to consume the first partial push.
            if parked.load(Ordering::SeqCst) != 0 {
                pipe_write(&self.a2e_tx);
            }
        }
        Ok(())
    }

    /// Send a packet to the engine (enqueue in the a2e ring).
    ///
    /// Yields cooperatively if the ring is full (backpressure from the engine).
    /// Returns `Err(Closed)` if the cancellation token fires (engine dead).
    ///
    /// Uses a wall-clock deadline so backpressure tolerance is independent
    /// of system scheduling speed (the old yield-counter approach returned
    /// `Closed` after ~100k yields ≈ 1s on fast machines, but could be much
    /// shorter under heavy Tokio contention — falsely killing the caller).
    pub async fn send(&self, pkt: Bytes) -> Result<(), ShmError> {
        if self.cancel.is_cancelled() {
            return Err(ShmError::Closed);
        }
        if pkt.len() > self.slot_size as usize {
            return Err(ShmError::PacketTooLarge);
        }
        // SAFETY: parked flag within mapped SHM region.
        let parked =
            unsafe { AtomicU32::from_ptr(self.shm.as_ptr().add(OFF_A2E_PARKED) as *mut u32) };
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if self.try_push_a2e(&pkt) {
                break;
            }
            if self.cancel.is_cancelled() {
                return Err(ShmError::Closed);
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(ShmError::Closed);
            }
            tokio::task::yield_now().await;
        }
        // Only send a wakeup if the engine is sleeping on the a2e ring.
        if parked.load(Ordering::SeqCst) != 0 {
            pipe_write(&self.a2e_tx);
        }
        Ok(())
    }

    /// Receive a packet from the engine (dequeue from the e2a ring).
    ///
    /// Returns `None` when the engine face has been dropped or the
    /// cancellation token fires.
    pub async fn recv(&self) -> Option<Bytes> {
        if self.cancel.is_cancelled() {
            return None;
        }
        // SAFETY: parked flag within mapped SHM region.
        let parked =
            unsafe { AtomicU32::from_ptr(self.shm.as_ptr().add(OFF_E2A_PARKED) as *mut u32) };
        loop {
            if let Some(pkt) = self.try_pop_e2a() {
                return Some(pkt);
            }
            // Spin before parking — avoids expensive pipe syscall
            // when packets arrive within microseconds of each other.
            for _ in 0..SPIN_ITERS {
                std::hint::spin_loop();
                if let Some(pkt) = self.try_pop_e2a() {
                    return Some(pkt);
                }
            }
            parked.store(1, Ordering::SeqCst);
            if let Some(pkt) = self.try_pop_e2a() {
                parked.store(0, Ordering::Relaxed);
                return Some(pkt);
            }

            // Wait for pipe wakeup or cancellation.  We rely on the
            // CancellationToken (propagated from the control face) rather
            // than timeouts — idle waits are legitimate (e.g. iperf server
            // waiting for a client).
            tokio::select! {
                result = pipe_await(&self.e2a_rx) => {
                    parked.store(0, Ordering::Relaxed);
                    if result.is_err() { return None; }
                }
                _ = self.cancel.cancelled() => {
                    parked.store(0, Ordering::Relaxed);
                    return None;
                }
            }
        }
    }
}

// SpscHandle has no Drop impl: ShmRegion handles munmap, OwnedFd closes pipe
// fds, and the FIFOs are created/removed by SpscFace (engine side).

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_transport::Face;

    fn test_name() -> String {
        // Use PID to avoid collisions when tests run concurrently.
        format!("test-spsc-{}", std::process::id())
    }

    // Tests use multi_thread because AsyncFd needs the runtime's I/O driver.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn face_kind_and_id() {
        let name = test_name();
        let face = SpscFace::create(FaceId(7), &name).unwrap();
        assert_eq!(face.id(), FaceId(7));
        assert_eq!(face.kind(), FaceKind::Shm);
    }

    #[test]
    fn slot_size_for_mtu_no_floor_clamp() {
        // slot_size_for_mtu does NOT clamp to DEFAULT_SLOT_SIZE anymore.
        // mtu=1024 → 1024 + 16384 = 17408, aligned to 64 = 17408.
        let small = slot_size_for_mtu(1024);
        assert_eq!(small, 17408);
        assert!(small < DEFAULT_SLOT_SIZE + SHM_SLOT_OVERHEAD as u32);

        // mtu=0 → 0 + 16384 = 16384, aligned = 16384.
        assert_eq!(slot_size_for_mtu(0), 16384);
    }

    #[test]
    fn slot_size_for_mtu_scales_up_for_large_mtu() {
        let one_mib = slot_size_for_mtu(1024 * 1024);
        assert!(one_mib >= 1024 * 1024 + SHM_SLOT_OVERHEAD as u32);
        assert_eq!(one_mib % 64, 0);
    }

    #[test]
    fn capacity_for_slot_inversely_scales() {
        // Default slot → default capacity.
        assert_eq!(capacity_for_slot(DEFAULT_SLOT_SIZE), DEFAULT_CAPACITY);
        // 256 KiB slot → much smaller capacity.
        let cap_256k = capacity_for_slot(272_384);
        assert!(cap_256k < DEFAULT_CAPACITY);
        assert!(cap_256k >= 16);
        // 1 MiB slot → minimum capacity (16).
        let cap_1m = capacity_for_slot(1_064_960);
        assert_eq!(cap_1m, 16);
    }

    #[test]
    fn slot_size_for_mtu_is_cache_line_aligned() {
        for mtu in [256_000, 512_000, 768_000, 1_000_000, 2_000_000] {
            let s = slot_size_for_mtu(mtu);
            assert_eq!(s % 64, 0, "slot_size_for_mtu({mtu}) = {s} not 64-aligned");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn create_for_mtu_large_segment_roundtrip() {
        // Reproduce the symptom that motivated the slot-size change:
        // a Data packet carrying a ~256 KiB content body must pass
        // through the SHM face without hitting "packet exceeds SHM
        // slot size".
        let name = format!("{}-big", test_name());
        let face = SpscFace::create_for_mtu(FaceId(42), &name, 256 * 1024).unwrap();
        let handle = SpscHandle::connect(&name).unwrap();

        let payload = Bytes::from(vec![0xABu8; 260_000]);
        handle.send(payload.clone()).await.unwrap();
        let received = tokio::time::timeout(std::time::Duration::from_secs(2), face.recv())
            .await
            .expect("timed out")
            .unwrap();
        assert_eq!(received.len(), payload.len());
        assert_eq!(&received[..16], &payload[..16]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn send_batch_app_to_engine() {
        let name = format!("{}-bae", test_name());
        let face = SpscFace::create(FaceId(20), &name).unwrap();
        let handle = SpscHandle::connect(&name).unwrap();

        let pkts: Vec<Bytes> = (0u8..16)
            .map(|i| Bytes::from(vec![i; 64]))
            .collect();
        handle.send_batch(&pkts).await.unwrap();

        for i in 0u8..16 {
            let received = tokio::time::timeout(std::time::Duration::from_secs(2), face.recv())
                .await
                .expect("timed out")
                .unwrap();
            assert_eq!(received.len(), 64);
            assert_eq!(received[0], i);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn send_batch_engine_to_app() {
        let name = format!("{}-bea", test_name());
        let face = SpscFace::create(FaceId(21), &name).unwrap();
        let handle = SpscHandle::connect(&name).unwrap();

        let pkts: Vec<Bytes> = (0u8..16)
            .map(|i| Bytes::from(vec![i; 64]))
            .collect();
        face.send_batch(&pkts).await.unwrap();

        for i in 0u8..16 {
            let received = tokio::time::timeout(std::time::Duration::from_secs(2), handle.recv())
                .await
                .expect("timed out")
                .unwrap();
            assert_eq!(received.len(), 64);
            assert_eq!(received[0], i);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn send_batch_exceeds_ring_capacity() {
        let name = format!("{}-bfull", test_name());
        let face = SpscFace::create(FaceId(22), &name).unwrap();
        let handle = SpscHandle::connect(&name).unwrap();

        // DEFAULT_CAPACITY is 32 — send 48 packets. The batch must
        // yield internally until the engine drains some slots.
        let n = 48usize;
        let pkts: Vec<Bytes> = (0..n)
            .map(|i| Bytes::from(vec![(i & 0xFF) as u8; 32]))
            .collect();

        // Spawn the batch send as a task; drain from the engine side
        // concurrently so the ring unblocks.
        let send_handle = tokio::spawn({
            let pkts = pkts.clone();
            async move { handle.send_batch(&pkts).await }
        });
        for i in 0..n {
            let received = tokio::time::timeout(std::time::Duration::from_secs(5), face.recv())
                .await
                .expect("timed out")
                .unwrap();
            assert_eq!(received[0], (i & 0xFF) as u8);
        }
        send_handle.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn app_to_engine_roundtrip() {
        let name = format!("{}-ae", test_name());
        let face = SpscFace::create(FaceId(1), &name).unwrap();
        let handle = SpscHandle::connect(&name).unwrap();

        let pkt = Bytes::from_static(b"\x05\x03\x01\x02\x03");
        handle.send(pkt.clone()).await.unwrap();

        let received = tokio::time::timeout(std::time::Duration::from_secs(2), face.recv())
            .await
            .expect("timed out")
            .unwrap();

        assert_eq!(received, pkt);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn engine_to_app_roundtrip() {
        let name = format!("{}-ea", test_name());
        let face = SpscFace::create(FaceId(2), &name).unwrap();
        let handle = SpscHandle::connect(&name).unwrap();

        let pkt = Bytes::from_static(b"\x06\x03\xAA\xBB\xCC");
        face.send(pkt.clone()).await.unwrap();

        let received = tokio::time::timeout(std::time::Duration::from_secs(2), handle.recv())
            .await
            .expect("timed out")
            .unwrap();

        assert_eq!(received, pkt);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn multiple_packets_both_directions() {
        let name = format!("{}-bi", test_name());
        let face = SpscFace::create(FaceId(3), &name).unwrap();
        let handle = SpscHandle::connect(&name).unwrap();

        // App → Engine: 4 packets
        for i in 0u8..4 {
            handle.send(Bytes::from(vec![i; 64])).await.unwrap();
        }
        for i in 0u8..4 {
            let pkt = face.recv().await.unwrap();
            assert_eq!(&pkt[..], &vec![i; 64][..]);
        }

        // Engine → App: 4 packets
        for i in 0u8..4 {
            face.send(Bytes::from(vec![i + 10; 128])).await.unwrap();
        }
        for i in 0u8..4 {
            let pkt = handle.recv().await.unwrap();
            assert_eq!(&pkt[..], &vec![i + 10; 128][..]);
        }
    }
}
