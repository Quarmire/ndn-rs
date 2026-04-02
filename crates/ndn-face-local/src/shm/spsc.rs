//! Custom SPSC shared-memory face (Unix only, `spsc-shm` feature).
//!
//! A named POSIX SHM region holds two lock-free single-producer/single-consumer
//! ring buffers — one for each direction.  Wakeup uses a platform-selected
//! primitive:
//!
//! - **Linux**: direct futex syscall (without `FUTEX_PRIVATE_FLAG`).  The
//!   parked `AtomicU32` in SHM IS the synchronisation primitive — no extra
//!   file descriptors needed.  The non-private futex keys on the physical
//!   page offset, so it works cross-process over POSIX SHM.
//!
//! - **Other Unix (macOS, etc.)**: named FIFO (pipe) pair.  The engine creates
//!   two FIFOs (`/tmp/.ndn-{name}.a2e.pipe` and `.e2a.pipe`); both sides open
//!   them `O_RDWR | O_NONBLOCK` (avoids the blocking-open problem).  The
//!   consumer awaits readability via `tokio::io::unix::AsyncFd`; the producer
//!   writes 1 non-blocking byte.  The parked flag is still used to avoid
//!   unnecessary writes when the consumer is active.
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

use crate::shm::ShmError;

// ─── Cross-process futex helpers (Linux) ─────────────────────────────────────
//
// `atomic_wait` uses `FUTEX_PRIVATE_FLAG` which only works within a single
// process (keys on virtual address).  For POSIX SHM shared across processes
// we need plain `FUTEX_WAIT` / `FUTEX_WAKE` which key on the physical page
// offset.

/// Block the calling thread while `*a == expected`, with a 100ms timeout.
///
/// Uses the non-private futex so the wait is visible across processes sharing
/// the same POSIX SHM mapping.  The timeout ensures blocking threads don't
/// hang indefinitely during shutdown (tokio waits for all `spawn_blocking`
/// tasks before the runtime drops).
#[cfg(target_os = "linux")]
fn futex_wait(a: &AtomicU32, expected: u32) {
    let timeout = libc::timespec { tv_sec: 0, tv_nsec: 100_000_000 }; // 100ms
    unsafe {
        libc::syscall(
            libc::SYS_futex,
            a as *const AtomicU32,
            libc::FUTEX_WAIT,
            expected,
            &timeout as *const libc::timespec,
        );
    }
}

/// Wake one thread blocked in `futex_wait` on the same address.
#[cfg(target_os = "linux")]
fn futex_wake_one(a: &AtomicU32) {
    unsafe {
        libc::syscall(
            libc::SYS_futex,
            a as *const AtomicU32,
            libc::FUTEX_WAKE,
            1i32,
        );
    }
}

// ─── Constants ───────────────────────────────────────────────────────────────

const MAGIC: u64 = 0x4E44_4E5F_5348_4D00; // b"NDN_SHM\0"

/// Default number of slots per ring.
pub const DEFAULT_CAPACITY: u32 = 256;
/// Default slot payload size in bytes (~8.75 KiB, covers typical NDN packets).
pub const DEFAULT_SLOT_SIZE: u32 = 8960;

// Cache-line–aligned offsets for the four ring index atomics.
const OFF_A2E_TAIL:   usize = 64;   // app writes (producer)
const OFF_A2E_HEAD:   usize = 128;  // engine writes (consumer)
const OFF_E2A_TAIL:   usize = 192;  // engine writes (producer)
const OFF_E2A_HEAD:   usize = 256;  // app writes (consumer)
// Parked flags: consumer sets to 1 before sleeping, clears on wake.
const OFF_A2E_PARKED: usize = 320;  // engine (a2e consumer) parked flag
const OFF_E2A_PARKED: usize = 384;  // app (e2a consumer) parked flag
const HEADER_SIZE:    usize = 448;  // 7 × 64-byte cache lines

fn slot_stride(slot_size: u32) -> usize { 4 + slot_size as usize }

/// Number of spin-loop iterations before falling through to the expensive
/// syscall path (futex on Linux, pipe on macOS).  256 iterations ≈ a few µs
/// on modern hardware — long enough to catch back-to-back packets.
const SPIN_ITERS: u32 = 256;

fn shm_total_size(capacity: u32, slot_size: u32) -> usize {
    HEADER_SIZE + 2 * capacity as usize * slot_stride(slot_size)
}

fn a2e_ring_offset() -> usize { HEADER_SIZE }
fn e2a_ring_offset(capacity: u32, slot_size: u32) -> usize {
    HEADER_SIZE + capacity as usize * slot_stride(slot_size)
}

// ─── Path helpers ─────────────────────────────────────────────────────────────

fn posix_shm_name(name: &str) -> String { format!("/ndn-shm-{name}") }

/// Path of the FIFO the *engine* reads from (app writes to wake engine).
#[cfg(not(target_os = "linux"))]
fn a2e_pipe_path(name: &str) -> PathBuf {
    PathBuf::from(format!("/tmp/.ndn-{name}.a2e.pipe"))
}

/// Path of the FIFO the *app* reads from (engine writes to wake app).
#[cfg(not(target_os = "linux"))]
fn e2a_pipe_path(name: &str) -> PathBuf {
    PathBuf::from(format!("/tmp/.ndn-{name}.e2a.pipe"))
}

// ─── POSIX SHM region ────────────────────────────────────────────────────────

/// Owns a POSIX SHM mapping. The creator unlinks the name on drop.
struct ShmRegion {
    ptr:      *mut u8,
    size:     usize,
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
            if fd == -1 { return Err(ShmError::Io(std::io::Error::last_os_error())); }

            if libc::ftruncate(fd, size as libc::off_t) == -1 {
                libc::close(fd);
                return Err(ShmError::Io(std::io::Error::last_os_error()));
            }

            let p = libc::mmap(
                std::ptr::null_mut(), size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED, fd, 0,
            );
            libc::close(fd);
            if p == libc::MAP_FAILED {
                return Err(ShmError::Io(std::io::Error::last_os_error()));
            }
            p as *mut u8
        };
        Ok(ShmRegion { ptr, size, shm_name: Some(cname) })
    }

    /// Open an existing named SHM region created by `ShmRegion::create`.
    fn open(shm_name: &str, size: usize) -> Result<Self, ShmError> {
        let cname = CString::new(shm_name).map_err(|_| ShmError::InvalidName)?;
        let ptr = unsafe {
            let fd = libc::shm_open(cname.as_ptr(), libc::O_RDWR, 0);
            if fd == -1 { return Err(ShmError::Io(std::io::Error::last_os_error())); }

            let p = libc::mmap(
                std::ptr::null_mut(), size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED, fd, 0,
            );
            libc::close(fd);
            if p == libc::MAP_FAILED {
                return Err(ShmError::Io(std::io::Error::last_os_error()));
            }
            p as *mut u8
        };
        Ok(ShmRegion { ptr, size, shm_name: None })
    }

    fn as_ptr(&self) -> *mut u8 { self.ptr }

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
            let magic     = (self.ptr as *const u64).read_unaligned();
            if magic != MAGIC { return Err(ShmError::InvalidMagic); }
            let capacity  = (self.ptr.add(8)  as *const u32).read_unaligned();
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
    base: *mut u8, ring_off: usize,
    tail_off: usize, head_off: usize,
    capacity: u32, slot_size: u32,
    data: &[u8],
) -> bool {
    debug_assert!(data.len() <= slot_size as usize);

    let tail_a = unsafe { &*AtomicU32::from_ptr(base.add(tail_off) as *mut u32) };
    let head_a = unsafe { &*AtomicU32::from_ptr(base.add(head_off) as *mut u32) };

    let t = tail_a.load(Ordering::Relaxed);
    let h = head_a.load(Ordering::Acquire);
    if t.wrapping_sub(h) >= capacity { return false; }

    let idx  = (t % capacity) as usize;
    let slot = unsafe { base.add(ring_off + idx * slot_stride(slot_size)) };

    unsafe {
        (slot as *mut u32).write_unaligned(data.len() as u32);
        std::ptr::copy_nonoverlapping(data.as_ptr(), slot.add(4), data.len());
    }
    tail_a.store(t.wrapping_add(1), Ordering::Release);
    true
}

/// Pop one packet from the ring. Returns `None` if empty.
///
/// # Safety
/// Same as [`ring_push`].
unsafe fn ring_pop(
    base: *mut u8, ring_off: usize,
    tail_off: usize, head_off: usize,
    capacity: u32, slot_size: u32,
) -> Option<Bytes> {
    let tail_a = unsafe { &*AtomicU32::from_ptr(base.add(tail_off) as *mut u32) };
    let head_a = unsafe { &*AtomicU32::from_ptr(base.add(head_off) as *mut u32) };

    let h = head_a.load(Ordering::Relaxed);
    let t = tail_a.load(Ordering::Acquire);
    if h == t { return None; }

    let idx  = (h % capacity) as usize;
    let slot = unsafe { base.add(ring_off + idx * slot_stride(slot_size)) };

    let len = unsafe { (slot as *const u32).read_unaligned() as usize };
    // Clamp to prevent out-of-bounds read if SHM is corrupted.
    let len = len.min(slot_size as usize);
    let data = unsafe {
        Bytes::copy_from_slice(std::slice::from_raw_parts(slot.add(4), len))
    };

    head_a.store(h.wrapping_add(1), Ordering::Release);
    Some(data)
}

// ─── Platform wakeup helpers ──────────────────────────────────────────────────

/// Open a named FIFO (must already exist) with `O_RDWR | O_NONBLOCK`.
///
/// `O_RDWR` avoids the blocking-open problem: the open succeeds immediately
/// even if the other end has not yet opened the FIFO.  Both sides only use
/// the fd in the direction they own (reads or writes), so no cross-reading
/// occurs.
#[cfg(not(target_os = "linux"))]
fn open_fifo_rdwr(path: &std::path::Path) -> Result<std::os::unix::io::OwnedFd, ShmError> {
    use std::os::unix::io::{FromRawFd, OwnedFd};
    let cpath = CString::new(path.to_str().unwrap_or(""))
        .map_err(|_| ShmError::InvalidName)?;
    let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDWR | libc::O_NONBLOCK) };
    if fd == -1 { return Err(ShmError::Io(std::io::Error::last_os_error())); }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Await readability on the pipe fd, then drain all buffered bytes.
///
/// Returns `Err` only if the `AsyncFd` reports an error (fd closed).
#[cfg(not(target_os = "linux"))]
async fn pipe_await(
    rx: &tokio::io::unix::AsyncFd<std::os::unix::io::OwnedFd>,
) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    loop {
        let mut guard = rx.readable().await?;
        let mut buf = [0u8; 64];
        let fd = rx.get_ref().as_raw_fd();
        let n = unsafe {
            libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
        };
        guard.clear_ready();
        if n > 0 { return Ok(()); }
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
#[cfg(not(target_os = "linux"))]
fn pipe_write(tx: &std::os::unix::io::OwnedFd) {
    use std::os::unix::io::AsRawFd;
    let b = [1u8];
    unsafe { libc::write(tx.as_raw_fd(), b.as_ptr() as *const libc::c_void, 1); }
}

// ─── SpscFace (engine side) ───────────────────────────────────────────────────

/// Engine-side SPSC SHM face.
///
/// Create with [`SpscFace::create`]; register with the engine via
/// `ForwarderEngine::add_face`. Give the `name` to the application so it can
/// call [`SpscHandle::connect`].
pub struct SpscFace {
    id:        FaceId,
    shm:       ShmRegion,
    capacity:  u32,
    slot_size: u32,
    a2e_off:   usize,
    e2a_off:   usize,
    // Linux: futex on the parked AtomicU32 in SHM — no extra fields.
    // Other Unix: named FIFO pair.
    /// Pipe fd the engine awaits readability on (app writes here to wake engine).
    #[cfg(not(target_os = "linux"))]
    a2e_rx:        tokio::io::unix::AsyncFd<std::os::unix::io::OwnedFd>,
    /// Pipe fd the engine writes to (to wake the app).
    #[cfg(not(target_os = "linux"))]
    e2a_tx:        std::os::unix::io::OwnedFd,
    /// Paths of the FIFOs created by the engine — removed on drop.
    #[cfg(not(target_os = "linux"))]
    a2e_pipe_path: PathBuf,
    #[cfg(not(target_os = "linux"))]
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

    /// Create with explicit ring parameters.
    pub fn create_with(
        id: FaceId, name: &str, capacity: u32, slot_size: u32,
    ) -> Result<Self, ShmError> {
        let size    = shm_total_size(capacity, slot_size);
        let shm     = ShmRegion::create(&posix_shm_name(name), size)?;
        unsafe { shm.write_header(capacity, slot_size); }

        let a2e_off = a2e_ring_offset();
        let e2a_off = e2a_ring_offset(capacity, slot_size);

        #[cfg(target_os = "linux")]
        { Ok(SpscFace { id, shm, capacity, slot_size, a2e_off, e2a_off }) }

        #[cfg(not(target_os = "linux"))]
        {
            use tokio::io::unix::AsyncFd;

            let a2e_path = a2e_pipe_path(name);
            let e2a_path = e2a_pipe_path(name);

            // Remove stale FIFOs from a previous run.
            let _ = std::fs::remove_file(&a2e_path);
            let _ = std::fs::remove_file(&e2a_path);

            // Create the named FIFOs.
            for p in [&a2e_path, &e2a_path] {
                let cp = CString::new(p.to_str().unwrap_or(""))
                    .map_err(|_| ShmError::InvalidName)?;
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
                id, shm, capacity, slot_size, a2e_off, e2a_off,
                a2e_rx, e2a_tx, a2e_pipe_path: a2e_path, e2a_pipe_path: e2a_path,
            })
        }
    }

    fn try_pop_a2e(&self) -> Option<Bytes> {
        unsafe {
            ring_pop(self.shm.as_ptr(), self.a2e_off,
                     OFF_A2E_TAIL, OFF_A2E_HEAD, self.capacity, self.slot_size)
        }
    }

    fn try_push_e2a(&self, data: &[u8]) -> bool {
        unsafe {
            ring_push(self.shm.as_ptr(), self.e2a_off,
                      OFF_E2A_TAIL, OFF_E2A_HEAD, self.capacity, self.slot_size, data)
        }
    }
}

impl Drop for SpscFace {
    fn drop(&mut self) {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = std::fs::remove_file(&self.a2e_pipe_path);
            let _ = std::fs::remove_file(&self.e2a_pipe_path);
        }
    }
}

impl Face for SpscFace {
    fn id(&self)   -> FaceId   { self.id }
    fn kind(&self) -> FaceKind { FaceKind::Shm }

    async fn recv(&self) -> Result<Bytes, FaceError> {
        // SAFETY: parked flag is within the mapped SHM region.
        let parked = unsafe {
            &*AtomicU32::from_ptr(self.shm.as_ptr().add(OFF_A2E_PARKED) as *mut u32)
        };
        loop {
            if let Some(pkt) = self.try_pop_a2e() {
                return Ok(pkt);
            }
            // Spin before parking — avoids expensive syscall (pipe/futex)
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

            // Sleep until the app sends a wakeup.
            #[cfg(target_os = "linux")]
            {
                // Futex: block this OS thread while parked == 1.
                // spawn_blocking keeps the async executor responsive.
                let ptr = parked as *const AtomicU32 as usize;
                let _ = tokio::task::spawn_blocking(move || {
                    let p = unsafe { &*(ptr as *const AtomicU32) };
                    futex_wait(p, 1);
                }).await;
            }
            #[cfg(not(target_os = "linux"))]
            {
                pipe_await(&self.a2e_rx).await
                    .map_err(|_| FaceError::Closed)?;
            }

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
        let parked = unsafe {
            &*AtomicU32::from_ptr(self.shm.as_ptr().add(OFF_E2A_PARKED) as *mut u32)
        };
        // Yield until there is space in the e2a ring (backpressure).
        loop {
            if self.try_push_e2a(&pkt) { break; }
            tokio::task::yield_now().await;
        }
        // Only send a wakeup if the app is actually sleeping.
        if parked.load(Ordering::SeqCst) != 0 {
            #[cfg(target_os = "linux")]
            futex_wake_one(parked);

            #[cfg(not(target_os = "linux"))]
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
pub struct SpscHandle {
    shm:       ShmRegion,
    capacity:  u32,
    slot_size: u32,
    a2e_off:   usize,
    e2a_off:   usize,
    // Linux: futex on the parked AtomicU32 in SHM — no extra fields.
    // Other Unix: named FIFO pair.
    /// Pipe fd the app awaits readability on (engine writes here to wake app).
    #[cfg(not(target_os = "linux"))]
    e2a_rx: tokio::io::unix::AsyncFd<std::os::unix::io::OwnedFd>,
    /// Pipe fd the app writes to (to wake the engine).
    #[cfg(not(target_os = "linux"))]
    a2e_tx: std::os::unix::io::OwnedFd,
}

impl SpscHandle {
    /// Open the SHM region created by the engine and set up the wakeup mechanism.
    pub fn connect(name: &str) -> Result<Self, ShmError> {
        let shm_name_str = posix_shm_name(name);
        let cname = CString::new(shm_name_str.as_str()).map_err(|_| ShmError::InvalidName)?;

        // Phase 1: open just the header to read capacity and slot_size.
        let (capacity, slot_size) = unsafe {
            let fd = libc::shm_open(cname.as_ptr(), libc::O_RDONLY, 0);
            if fd == -1 { return Err(ShmError::Io(std::io::Error::last_os_error())); }
            let p = libc::mmap(
                std::ptr::null_mut(), HEADER_SIZE,
                libc::PROT_READ, libc::MAP_SHARED, fd, 0,
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
            let cap  = (base.add(8)  as *const u32).read_unaligned();
            let slen = (base.add(12) as *const u32).read_unaligned();
            libc::munmap(p, HEADER_SIZE);
            (cap, slen)
        };

        // Phase 2: open the full region read-write.
        let size = shm_total_size(capacity, slot_size);
        let shm  = ShmRegion::open(&shm_name_str, size)?;
        unsafe { shm.read_header()? };

        let a2e_off = a2e_ring_offset();
        let e2a_off = e2a_ring_offset(capacity, slot_size);

        #[cfg(target_os = "linux")]
        { Ok(SpscHandle { shm, capacity, slot_size, a2e_off, e2a_off }) }

        #[cfg(not(target_os = "linux"))]
        {
            use tokio::io::unix::AsyncFd;

            let a2e_path = a2e_pipe_path(name);  // app writes here to wake engine
            let e2a_path = e2a_pipe_path(name);  // app reads here (engine wakes app)

            // App writes to a2e FIFO (to wake engine).
            let a2e_tx = open_fifo_rdwr(&a2e_path)?;

            // App reads from e2a FIFO (awaits wakeup from engine).
            let e2a_fd = open_fifo_rdwr(&e2a_path)?;
            let e2a_rx = AsyncFd::new(e2a_fd).map_err(ShmError::Io)?;

            Ok(SpscHandle { shm, capacity, slot_size, a2e_off, e2a_off, e2a_rx, a2e_tx })
        }
    }

    fn try_push_a2e(&self, data: &[u8]) -> bool {
        unsafe {
            ring_push(self.shm.as_ptr(), self.a2e_off,
                      OFF_A2E_TAIL, OFF_A2E_HEAD, self.capacity, self.slot_size, data)
        }
    }

    fn try_pop_e2a(&self) -> Option<Bytes> {
        unsafe {
            ring_pop(self.shm.as_ptr(), self.e2a_off,
                     OFF_E2A_TAIL, OFF_E2A_HEAD, self.capacity, self.slot_size)
        }
    }

    /// Send a packet to the engine (enqueue in the a2e ring).
    ///
    /// Yields cooperatively if the ring is full (backpressure from the engine).
    pub async fn send(&self, pkt: Bytes) -> Result<(), ShmError> {
        if pkt.len() > self.slot_size as usize {
            return Err(ShmError::PacketTooLarge);
        }
        // SAFETY: parked flag within mapped SHM region.
        let parked = unsafe {
            &*AtomicU32::from_ptr(self.shm.as_ptr().add(OFF_A2E_PARKED) as *mut u32)
        };
        loop {
            if self.try_push_a2e(&pkt) { break; }
            tokio::task::yield_now().await;
        }
        // Only send a wakeup if the engine is sleeping on the a2e ring.
        if parked.load(Ordering::SeqCst) != 0 {
            #[cfg(target_os = "linux")]
            futex_wake_one(parked);

            #[cfg(not(target_os = "linux"))]
            pipe_write(&self.a2e_tx);
        }
        Ok(())
    }

    /// Receive a packet from the engine (dequeue from the e2a ring).
    ///
    /// Returns `None` when the engine face has been dropped.
    pub async fn recv(&self) -> Option<Bytes> {
        // SAFETY: parked flag within mapped SHM region.
        let parked = unsafe {
            &*AtomicU32::from_ptr(self.shm.as_ptr().add(OFF_E2A_PARKED) as *mut u32)
        };
        loop {
            if let Some(pkt) = self.try_pop_e2a() {
                return Some(pkt);
            }
            // Spin before parking — avoids expensive syscall (pipe/futex)
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

            #[cfg(target_os = "linux")]
            {
                let ptr = parked as *const AtomicU32 as usize;
                let ok = tokio::task::spawn_blocking(move || {
                    let p = unsafe { &*(ptr as *const AtomicU32) };
                    futex_wait(p, 1);
                }).await;
                if ok.is_err() { return None; }
            }
            #[cfg(not(target_os = "linux"))]
            {
                if pipe_await(&self.e2a_rx).await.is_err() {
                    return None;
                }
            }

            parked.store(0, Ordering::Relaxed);
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

    // Tests use multi_thread because SpscFace::recv uses spawn_blocking on
    // Linux (futex) which requires a multi-threaded runtime.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn face_kind_and_id() {
        let name = test_name();
        let face = SpscFace::create(FaceId(7), &name).unwrap();
        assert_eq!(face.id(), FaceId(7));
        assert_eq!(face.kind(), FaceKind::Shm);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn app_to_engine_roundtrip() {
        let name   = format!("{}-ae", test_name());
        let face   = SpscFace::create(FaceId(1), &name).unwrap();
        let handle = SpscHandle::connect(&name).unwrap();

        let pkt = Bytes::from_static(b"\x05\x03\x01\x02\x03");
        handle.send(pkt.clone()).await.unwrap();

        let received = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            face.recv(),
        ).await.expect("timed out").unwrap();

        assert_eq!(received, pkt);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn engine_to_app_roundtrip() {
        let name   = format!("{}-ea", test_name());
        let face   = SpscFace::create(FaceId(2), &name).unwrap();
        let handle = SpscHandle::connect(&name).unwrap();

        let pkt = Bytes::from_static(b"\x06\x03\xAA\xBB\xCC");
        face.send(pkt.clone()).await.unwrap();

        let received = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            handle.recv(),
        ).await.expect("timed out").unwrap();

        assert_eq!(received, pkt);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn multiple_packets_both_directions() {
        let name   = format!("{}-bi", test_name());
        let face   = SpscFace::create(FaceId(3), &name).unwrap();
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
