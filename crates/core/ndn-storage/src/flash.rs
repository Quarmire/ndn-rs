//! Embedded **flash-backed** [`SyncBackend`](crate::SyncBackend), generic over the
//! standard [`embedded-storage`](https://docs.rs/embedded-storage) `NorFlash` trait.
//!
//! This is the HW seam for F21's embedded leg: ndn-rs owns the *engine* once, and the
//! board/HAL plugs the concrete chip (ESP32 `esp-storage`, an STM32 HAL, …) in through
//! `NorFlash` — so the engine is HW-independent and CI-testable against a mock flash,
//! and only the flash driver is HW-specific.
//!
//! ## Design — RAM index + double-buffered flash write-ahead log
//!
//! The ordered index lives in RAM (a `BTreeMap`, so `scan_prefix` is ordered and
//! efficient); flash is an **append-only log of records** for durability. Each write
//! (a `put`/`delete`, or a whole `write_batch`) is **one** length-framed record with a
//! validity footer — so a record is applied on replay only if it landed in full, giving
//! **power-loss-atomic batches**. On mount the log is replayed into RAM; a torn tail
//! (an interrupted final write) is dropped.
//!
//! ### Atomic compaction via two halves (A/B ping-pong)
//!
//! When the live log fills (or its tail is torn), the store **compacts**: it rewrites
//! the whole live index as one fresh log. Compaction must be power-loss-atomic — if it
//! erased the live region first (the naive single-region design), a power cut between the
//! erase and the rewrite would destroy *all* data. So the region is split into two equal
//! halves: compaction writes the fresh log into the **inactive** half and only switches
//! over once it is fully committed. The active half is never touched until the new one is
//! durable, so a power cut mid-compaction leaves the last committed state intact.
//!
//! The commit point is each half's **superblock, written last** (after its records),
//! carrying a monotonic generation counter. On mount the store reads both superblocks and
//! replays the valid half with the higher generation; a half whose superblock never
//! landed (compaction interrupted before commit) is ignored, so mount falls back to the
//! previous generation. Within the chosen half a torn record tail is still dropped.
//!
//! Values are held in RAM (matching the embedded floor — "an MCU holds few blocks");
//! flash adds durability across power loss. For datasets that exceed RAM, a future
//! offset-indexed variant would read values back from flash.

use crate::{StorageError, StorageResult, SyncBackend, WriteOp};
use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use bytes::Bytes;
use embedded_storage::nor_flash::NorFlash;

const OP_PUT: u8 = 1;
const OP_DEL: u8 = 2;
/// `len ^ COMMIT_MAGIC` footer proves a record was written in full (a torn write
/// leaves the footer erased/wrong → the record is discarded on replay).
const COMMIT_MAGIC: u32 = 0x4E44_4E46; // "NDNF"
/// An erased NOR cell reads as all-ones; a `len` of `0xFFFF_FFFF` marks end-of-log.
const ERASED: u32 = 0xFFFF_FFFF;
/// Superblock magic at the start of each half — identifies an ndn-storage flash log, so
/// `mount` refuses a blank or foreign region instead of clobbering it.
const SUPER_MAGIC: u64 = 0x4E44_4E5F_464C_4F47; // "NDN_FLOG"
/// v2 = double-buffered (two halves, generation-tagged superblock written last). A v1
/// (single-region) image has no per-half generation and is refused, not misread.
const FORMAT_VERSION: u32 = 2;

/// Error opening or operating a [`FlashLogBackend`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlashError {
    /// The region holds neither a valid log nor erased flash — call
    /// [`FlashLogBackend::format`] first (it would otherwise corrupt data).
    Unformatted,
    /// The live set no longer fits in the region, even after compaction.
    OutOfSpace,
    /// The underlying flash returned an error.
    Io,
}

impl core::fmt::Display for FlashError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            FlashError::Unformatted => "flash region is unformatted",
            FlashError::OutOfSpace => "flash region out of space",
            FlashError::Io => "flash I/O error",
        };
        f.write_str(s)
    }
}

impl From<FlashError> for StorageError {
    fn from(e: FlashError) -> Self {
        StorageError::backend(e)
    }
}

fn align_up(n: u32, a: u32) -> u32 {
    n.div_ceil(a) * a
}

fn align_down(n: u32, a: u32) -> u32 {
    (n / a) * a
}

struct FlashState<F> {
    flash: F,
    index: BTreeMap<Vec<u8>, Bytes>,
    /// Size of each of the two halves (ERASE_SIZE-aligned). The region is `[0, half_cap)`
    /// = half A and `[half_cap, 2*half_cap)` = half B.
    half_cap: u32,
    /// Base offset of the **live** half (`0` or `half_cap`).
    live_base: u32,
    /// Generation of the live half — higher = newer; bumped each compaction.
    generation: u32,
    write_off: u32, // next free (erased) absolute offset in the live half
    /// The mounted tail was torn (or unverified) — append must compact before writing.
    dirty_tail: bool,
}

impl<F: NorFlash> FlashState<F> {
    /// Byte length of the superblock (magic + version + generation), rounded to the write
    /// unit; each half's log begins here.
    fn header_len() -> u32 {
        align_up(16, F::WRITE_SIZE as u32)
    }

    /// Size of one half for a region of `cap` bytes — half the region, rounded *down* to
    /// the erase unit so each half can be erased independently.
    fn half_cap_for(cap: u32) -> u32 {
        align_down(cap / 2, F::ERASE_SIZE as u32)
    }

    /// Base offset of the inactive half (the compaction target).
    fn other_base(&self) -> u32 {
        if self.live_base == 0 {
            self.half_cap
        } else {
            0
        }
    }

    fn read_u32(&mut self, off: u32) -> Result<u32, FlashError> {
        let mut b = [0u8; 4];
        self.flash.read(off, &mut b).map_err(|_| FlashError::Io)?;
        Ok(u32::from_le_bytes(b))
    }

    /// Read a half's superblock at `base`; `Some(generation)` if it carries our magic +
    /// format version (i.e. a committed half), `None` otherwise (erased / foreign / older
    /// format / interrupted-before-commit).
    fn read_super(&mut self, base: u32) -> Result<Option<u32>, FlashError> {
        let mut hdr = [0u8; 16];
        self.flash
            .read(base, &mut hdr)
            .map_err(|_| FlashError::Io)?;
        let magic = u64::from_le_bytes(hdr[..8].try_into().unwrap());
        let version = u32::from_le_bytes(hdr[8..12].try_into().unwrap());
        if magic != SUPER_MAGIC || version != FORMAT_VERSION {
            return Ok(None);
        }
        Ok(Some(u32::from_le_bytes(hdr[12..16].try_into().unwrap())))
    }

    /// True if generation `x` is strictly newer than `y`, wraparound-safe (the two halves
    /// only ever hold consecutive generations).
    fn newer(x: u32, y: u32) -> bool {
        x != y && x.wrapping_sub(y) < 0x8000_0000
    }

    /// Rewrite one half as a fresh log: erase it, write `ops` as a single record, then —
    /// **last, as the commit point** — write the superblock with `generation`. Because the
    /// superblock lands only after the records, a power cut mid-rewrite leaves the half
    /// without valid magic, so it's ignored on mount and the other (live) half stands.
    /// Returns the new absolute `write_off` (end of the written record) on success.
    fn write_half(
        &mut self,
        base: u32,
        generation: u32,
        ops: &[WriteOp],
    ) -> Result<u32, FlashError> {
        let hc = self.half_cap;
        self.flash
            .erase(base, base + hc)
            .map_err(|_| FlashError::Io)?;
        let hlen = Self::header_len();
        let mut off = base + hlen;
        if !ops.is_empty() {
            let rec = Self::encode_record(ops);
            if off + rec.len() as u32 > base + hc {
                return Err(FlashError::OutOfSpace);
            }
            self.flash.write(off, &rec).map_err(|_| FlashError::Io)?;
            off += rec.len() as u32;
        }
        // Superblock LAST = the commit. Written into freshly-erased (all-ones) cells.
        let hlen = hlen as usize;
        let mut hdr = vec![0xFFu8; hlen];
        hdr[..8].copy_from_slice(&SUPER_MAGIC.to_le_bytes());
        hdr[8..12].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        hdr[12..16].copy_from_slice(&generation.to_le_bytes());
        self.flash.write(base, &hdr).map_err(|_| FlashError::Io)?;
        Ok(off)
    }

    /// Serialize `ops` into a framed record: `len | payload | footer`, padded to the
    /// flash write granularity (pad bytes are `0xFF` = a no-op on NOR).
    fn encode_record(ops: &[WriteOp]) -> Vec<u8> {
        let mut payload = Vec::new();
        for op in ops {
            match op {
                WriteOp::Put(k, v) => {
                    payload.push(OP_PUT);
                    payload.extend_from_slice(&(k.len() as u32).to_le_bytes());
                    payload.extend_from_slice(k);
                    payload.extend_from_slice(&(v.len() as u32).to_le_bytes());
                    payload.extend_from_slice(v);
                }
                WriteOp::Delete(k) => {
                    payload.push(OP_DEL);
                    payload.extend_from_slice(&(k.len() as u32).to_le_bytes());
                    payload.extend_from_slice(k);
                }
            }
        }
        let len = payload.len() as u32;
        let mut rec = Vec::with_capacity(8 + payload.len());
        rec.extend_from_slice(&len.to_le_bytes());
        rec.extend_from_slice(&payload);
        rec.extend_from_slice(&(len ^ COMMIT_MAGIC).to_le_bytes());
        let padded = align_up(rec.len() as u32, F::WRITE_SIZE as u32) as usize;
        rec.resize(padded, 0xFF);
        rec
    }

    /// Apply a record's payload to the in-RAM index. Returns false on a malformed
    /// payload (treated as a torn/corrupt record by the caller).
    fn apply_payload(payload: &[u8], index: &mut BTreeMap<Vec<u8>, Bytes>) -> bool {
        let mut p = payload;
        while !p.is_empty() {
            let op = p[0];
            p = &p[1..];
            if p.len() < 4 {
                return false;
            }
            let klen = u32::from_le_bytes([p[0], p[1], p[2], p[3]]) as usize;
            p = &p[4..];
            if p.len() < klen {
                return false;
            }
            let key = p[..klen].to_vec();
            p = &p[klen..];
            match op {
                OP_PUT => {
                    if p.len() < 4 {
                        return false;
                    }
                    let vlen = u32::from_le_bytes([p[0], p[1], p[2], p[3]]) as usize;
                    p = &p[4..];
                    if p.len() < vlen {
                        return false;
                    }
                    index.insert(key, Bytes::copy_from_slice(&p[..vlen]));
                    p = &p[vlen..];
                }
                OP_DEL => {
                    index.remove(&key);
                }
                _ => return false,
            }
        }
        true
    }

    /// Replay one half's record log into the index, starting after its superblock and
    /// bounded by the half. Returns `(next free absolute offset, tail_was_torn)`. A torn
    /// or corrupt record ends replay (its tail is dropped).
    fn replay_half(&mut self, base: u32) -> Result<(u32, bool), FlashError> {
        let hlen = Self::header_len();
        let end_cap = base + self.half_cap;
        let mut off = base + hlen;
        let mut dirty = false;
        loop {
            if off + 8 > end_cap {
                break;
            }
            let len = self.read_u32(off)?;
            if len == ERASED {
                break; // clean end of log
            }
            // Bounds: header + payload + footer must fit in this half.
            let Some(end) = off.checked_add(8).and_then(|x| x.checked_add(len)) else {
                dirty = true;
                break;
            };
            if end > end_cap {
                dirty = true;
                break;
            }
            let mut buf = vec![0u8; len as usize + 4];
            self.flash
                .read(off + 4, &mut buf)
                .map_err(|_| FlashError::Io)?;
            let footer = u32::from_le_bytes([
                buf[len as usize],
                buf[len as usize + 1],
                buf[len as usize + 2],
                buf[len as usize + 3],
            ]);
            if footer != (len ^ COMMIT_MAGIC)
                || !Self::apply_payload(&buf[..len as usize], &mut self.index)
            {
                dirty = true; // torn / corrupt tail — drop it, self-heal on next write
                break;
            }
            off += align_up(8 + len, F::WRITE_SIZE as u32);
        }
        Ok((off, dirty))
    }

    /// Pick the valid half with the higher generation and replay it into the index; set
    /// `live_base`/`generation`/`write_off`/`dirty_tail`. Rejects a region with no valid half as
    /// `Unformatted`. A half whose compaction was interrupted before its superblock
    /// committed has no valid magic, so it's skipped and the previous generation stands.
    fn mount(&mut self) -> Result<(), FlashError> {
        let hlen = Self::header_len();
        if self.half_cap < hlen + 8 {
            return Err(FlashError::OutOfSpace);
        }
        let a = self.read_super(0)?;
        let b = self.read_super(self.half_cap)?;
        let (base, generation) = match (a, b) {
            (None, None) => return Err(FlashError::Unformatted),
            (Some(g), None) => (0, g),
            (None, Some(g)) => (self.half_cap, g),
            (Some(ga), Some(gb)) => {
                if Self::newer(ga, gb) {
                    (0, ga)
                } else {
                    (self.half_cap, gb)
                }
            }
        };
        self.live_base = base;
        self.generation = generation;
        self.index.clear();
        let (off, dirty) = self.replay_half(base)?;
        self.write_off = off;
        self.dirty_tail = dirty;
        Ok(())
    }

    /// Compact: rewrite the live index as a fresh log into the **inactive** half with the
    /// next generation, then switch the live half to it. The previously-live half is left
    /// intact until it is itself overwritten by the *next* compaction, so this is atomic
    /// against power loss — a crash before the new half commits leaves the old one live.
    fn compact(&mut self) -> Result<(), FlashError> {
        let ops: Vec<WriteOp> = self
            .index
            .iter()
            .map(|(k, v)| WriteOp::Put(k.clone(), v.clone()))
            .collect();
        let target = self.other_base();
        let new_gen = self.generation.wrapping_add(1);
        let new_off = self.write_half(target, new_gen, &ops)?;
        // Commit: the new half is fully durable (superblock written last) — switch.
        self.live_base = target;
        self.generation = new_gen;
        self.write_off = new_off;
        self.dirty_tail = false;
        Ok(())
    }

    /// Append one record for `ops`, compacting first if the tail is dirty or the live
    /// half is full.
    fn append(&mut self, ops: &[WriteOp]) -> Result<(), FlashError> {
        let rec = Self::encode_record(ops);
        let need = rec.len() as u32;
        if self.dirty_tail || self.write_off + need > self.live_base + self.half_cap {
            self.compact()?;
            // After compaction the log is rewritten from the index, so the *new* ops
            // still need appending (they are not yet in the index).
            if self.write_off + need > self.live_base + self.half_cap {
                return Err(FlashError::OutOfSpace);
            }
        }
        self.flash
            .write(self.write_off, &rec)
            .map_err(|_| FlashError::Io)?;
        self.write_off += need;
        Ok(())
    }

    /// Append then apply to the index (consistent: index updates only if flash wrote).
    /// On a flash failure the index is left unchanged and the error is returned (the
    /// caller learns the write did not land — durability over silent drift).
    fn commit(&mut self, ops: Vec<WriteOp>) -> Result<(), FlashError> {
        self.append(&ops)?;
        for op in ops {
            match op {
                WriteOp::Put(k, v) => {
                    self.index.insert(k, v);
                }
                WriteOp::Delete(k) => {
                    self.index.remove(&k);
                }
            }
        }
        Ok(())
    }
}

/// A flash-backed [`SyncBackend`] over any `embedded-storage` `NorFlash` `F`. The
/// engine is HW-independent; supply the concrete flash driver for your board.
pub struct FlashLogBackend<F> {
    // Interior mutability: NorFlash I/O needs `&mut`, but `SyncBackend` is `&self`.
    #[cfg(feature = "std")]
    state: std::sync::Mutex<FlashState<F>>,
    #[cfg(not(feature = "std"))]
    state: critical_section::Mutex<core::cell::RefCell<FlashState<F>>>,
}

impl<F: NorFlash> FlashLogBackend<F> {
    /// Mount an existing log (replaying it into the RAM index) — use after a reboot.
    /// Returns [`FlashError::Unformatted`] if the region was never [`format`](Self::format)ted.
    pub fn mount(flash: F) -> Result<Self, FlashError> {
        let cap = flash.capacity() as u32;
        let mut st = FlashState {
            flash,
            index: BTreeMap::new(),
            half_cap: FlashState::<F>::half_cap_for(cap),
            live_base: 0,
            generation: 0,
            write_off: 0,
            dirty_tail: false,
        };
        st.mount()?;
        Ok(Self::wrap(st))
    }

    /// Provision a fresh, empty store: erase both halves and lay down half A's superblock
    /// (generation 0). First-time provisioning / reset.
    pub fn format(flash: F) -> Result<Self, FlashError> {
        let cap = flash.capacity() as u32;
        let half_cap = FlashState::<F>::half_cap_for(cap);
        let hlen = FlashState::<F>::header_len();
        if half_cap < hlen + 8 {
            return Err(FlashError::OutOfSpace);
        }
        let mut st = FlashState {
            flash,
            index: BTreeMap::new(),
            half_cap,
            live_base: 0,
            generation: 0,
            write_off: 0,
            dirty_tail: false,
        };
        // Erase the inactive half (so a stale/foreign image there can't masquerade as a
        // newer generation), then lay down half A as the empty live half at generation 0.
        st.flash
            .erase(half_cap, half_cap + half_cap)
            .map_err(|_| FlashError::Io)?;
        let off = st.write_half(0, 0, &[])?;
        st.live_base = 0;
        st.generation = 0;
        st.write_off = off;
        st.dirty_tail = false;
        Ok(Self::wrap(st))
    }

    fn wrap(st: FlashState<F>) -> Self {
        #[cfg(feature = "std")]
        {
            Self {
                state: std::sync::Mutex::new(st),
            }
        }
        #[cfg(not(feature = "std"))]
        {
            Self {
                state: critical_section::Mutex::new(core::cell::RefCell::new(st)),
            }
        }
    }

    fn with<R>(&self, f: impl FnOnce(&mut FlashState<F>) -> R) -> R {
        #[cfg(feature = "std")]
        {
            f(&mut self.state.lock().unwrap())
        }
        #[cfg(not(feature = "std"))]
        {
            critical_section::with(|cs| f(&mut self.state.borrow_ref_mut(cs)))
        }
    }
}

impl<F: NorFlash + Send> SyncBackend for FlashLogBackend<F> {
    fn get(&self, key: &[u8]) -> StorageResult<Option<Bytes>> {
        // The index is the authoritative RAM view (the log was replayed into it on
        // mount); a lookup can't fail, so a miss is a genuine `Ok(None)`.
        Ok(self.with(|s| s.index.get(key).cloned()))
    }
    fn put(&self, key: &[u8], value: Bytes) -> StorageResult<()> {
        self.with(|s| s.commit(vec![WriteOp::Put(key.to_vec(), value)]))?;
        Ok(())
    }
    fn delete(&self, key: &[u8]) -> StorageResult<()> {
        self.with(|s| s.commit(vec![WriteOp::Delete(key.to_vec())]))?;
        Ok(())
    }
    fn scan_prefix(&self, prefix: &[u8], limit: usize) -> StorageResult<Vec<(Bytes, Bytes)>> {
        Ok(self.with(|s| {
            let mut out = Vec::new();
            for (k, v) in s.index.range(prefix.to_vec()..) {
                if !k.starts_with(prefix) {
                    break;
                }
                out.push((Bytes::copy_from_slice(k), v.clone()));
                if limit != 0 && out.len() >= limit {
                    break;
                }
            }
            out
        }))
    }
    fn write_batch(&self, ops: Vec<WriteOp>) -> StorageResult<()> {
        // One framed flash record ⇒ power-loss-atomic across the whole group.
        self.with(|s| s.commit(ops))?;
        Ok(())
    }
    fn name(&self) -> &'static str {
        "flash"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use embedded_storage::nor_flash::{ErrorType, NorFlashError, NorFlashErrorKind, ReadNorFlash};

    /// In-RAM mock NOR flash with realistic semantics: `write` can only clear bits
    /// (`&=`, so writing over un-erased cells corrupts — catching erase-before-write
    /// bugs), `erase` sets `0xFF`.
    struct MockFlash {
        data: Vec<u8>,
    }
    impl MockFlash {
        fn new(size: usize) -> Self {
            Self {
                data: vec![0xFF; size],
            }
        }
    }
    #[derive(Debug)]
    struct MockErr;
    impl NorFlashError for MockErr {
        fn kind(&self) -> NorFlashErrorKind {
            NorFlashErrorKind::Other
        }
    }
    impl ErrorType for MockFlash {
        type Error = MockErr;
    }
    impl ReadNorFlash for MockFlash {
        const READ_SIZE: usize = 1;
        fn read(&mut self, off: u32, bytes: &mut [u8]) -> Result<(), MockErr> {
            let off = off as usize;
            bytes.copy_from_slice(&self.data[off..off + bytes.len()]);
            Ok(())
        }
        fn capacity(&self) -> usize {
            self.data.len()
        }
    }
    impl NorFlash for MockFlash {
        const WRITE_SIZE: usize = 4;
        const ERASE_SIZE: usize = 64;
        fn write(&mut self, off: u32, bytes: &[u8]) -> Result<(), MockErr> {
            assert_eq!(off as usize % Self::WRITE_SIZE, 0, "unaligned write offset");
            assert_eq!(bytes.len() % Self::WRITE_SIZE, 0, "unaligned write length");
            let off = off as usize;
            for (i, b) in bytes.iter().enumerate() {
                self.data[off + i] &= b; // NOR: writes can only clear bits
            }
            Ok(())
        }
        fn erase(&mut self, from: u32, to: u32) -> Result<(), MockErr> {
            assert_eq!(from as usize % Self::ERASE_SIZE, 0, "unaligned erase");
            assert_eq!(to as usize % Self::ERASE_SIZE, 0, "unaligned erase");
            for b in &mut self.data[from as usize..to as usize] {
                *b = 0xFF;
            }
            Ok(())
        }
    }

    #[test]
    fn put_get_scan_delete_round_trip() {
        let f = FlashLogBackend::format(MockFlash::new(4096)).unwrap();
        f.put(b"/a/b", Bytes::from_static(b"v-ab")).unwrap();
        f.put(b"/a/c", Bytes::from_static(b"v-ac")).unwrap();
        f.put(b"/z", Bytes::from_static(b"v-z")).unwrap();
        assert_eq!(f.get(b"/a/b").unwrap().as_deref(), Some(&b"v-ab"[..]));
        let under: Vec<_> = f
            .scan_prefix(b"/a", 0)
            .unwrap()
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        assert_eq!(
            under,
            vec![Bytes::from_static(b"/a/b"), Bytes::from_static(b"/a/c")]
        );
        f.delete(b"/a/b").unwrap();
        assert!(f.get(b"/a/b").unwrap().is_none());
        assert_eq!(f.get(b"/a/c").unwrap().as_deref(), Some(&b"v-ac"[..]));
    }

    #[test]
    fn survives_remount() {
        // Write, then snapshot the raw flash bytes (simulating a power cycle).
        let flash = {
            let f = FlashLogBackend::format(MockFlash::new(4096)).unwrap();
            f.put(b"k1", Bytes::from_static(b"v1")).unwrap();
            f.write_batch(vec![
                WriteOp::Put(b"k2".to_vec(), Bytes::from_static(b"v2")),
                WriteOp::Delete(b"k1".to_vec()),
            ])
            .unwrap();
            f.with(|s| MockFlash {
                data: s.flash.data.clone(),
            })
        };
        // Remount the persisted bytes — the log replays into the index.
        let f = FlashLogBackend::mount(flash).unwrap();
        assert!(f.get(b"k1").unwrap().is_none(), "delete persisted");
        assert_eq!(
            f.get(b"k2").unwrap().as_deref(),
            Some(&b"v2"[..]),
            "batch put persisted"
        );
    }

    #[test]
    fn compaction_reclaims_space() {
        // Small region: repeated overwrites of one key must trigger compaction and
        // keep working (the live set is tiny).
        let f = FlashLogBackend::format(MockFlash::new(512)).unwrap();
        for i in 0..200u32 {
            f.put(b"counter", Bytes::copy_from_slice(&i.to_le_bytes()))
                .unwrap();
        }
        assert_eq!(
            f.get(b"counter").unwrap().as_deref(),
            Some(&199u32.to_le_bytes()[..]),
            "latest value survives many compactions"
        );
    }

    #[test]
    fn compaction_ping_pongs_and_remounts_to_latest() {
        // Many overwrites force repeated compactions that ping-pong between the two
        // halves; a clean power cycle (remount of the raw bytes) must land on the latest
        // generation and recover the live set.
        let snapshot = {
            let f = FlashLogBackend::format(MockFlash::new(512)).unwrap();
            for i in 0..200u32 {
                f.put(b"counter", Bytes::copy_from_slice(&i.to_le_bytes()))
                    .unwrap();
            }
            f.put(b"stable", Bytes::from_static(b"keep")).unwrap();
            f.with(|s| s.flash.data.clone())
        };
        let f = FlashLogBackend::mount(MockFlash { data: snapshot }).unwrap();
        assert_eq!(
            f.get(b"counter").unwrap().as_deref(),
            Some(&199u32.to_le_bytes()[..]),
            "remount lands on the latest generation"
        );
        assert_eq!(f.get(b"stable").unwrap().as_deref(), Some(&b"keep"[..]));
    }

    #[test]
    fn interrupted_compaction_before_commit_is_ignored() {
        // The atomicity guarantee: a compaction that wrote its records into the inactive
        // half but was cut off *before* the superblock (the commit point) landed must be
        // ignored on mount — the previous committed generation stands, no data is lost or
        // replaced by the half-written one.
        let snapshot = {
            let f = FlashLogBackend::format(MockFlash::new(512)).unwrap();
            f.put(b"k1", Bytes::from_static(b"v1")).unwrap();
            f.put(b"k2", Bytes::from_static(b"v2")).unwrap();
            f.with(|s| s.flash.data.clone())
        };
        // Forge an *uncommitted* compaction into half B: a record that would overwrite k1
        // if wrongly trusted, with B's superblock left erased (no valid magic) — exactly
        // the on-flash state after a power cut between the record write and the superblock.
        let half_cap = FlashState::<MockFlash>::half_cap_for(512);
        let hlen = FlashState::<MockFlash>::header_len();
        let bogus = FlashState::<MockFlash>::encode_record(&[WriteOp::Put(
            b"k1".to_vec(),
            Bytes::from_static(b"WRONG"),
        )]);
        let mut data = snapshot;
        let at = (half_cap + hlen) as usize;
        data[at..at + bogus.len()].copy_from_slice(&bogus);

        let f = FlashLogBackend::mount(MockFlash { data }).unwrap();
        assert_eq!(
            f.get(b"k1").unwrap().as_deref(),
            Some(&b"v1"[..]),
            "the uncommitted half is ignored — k1 keeps its committed value"
        );
        assert_eq!(f.get(b"k2").unwrap().as_deref(), Some(&b"v2"[..]));
    }

    #[test]
    fn mount_rejects_unformatted_region() {
        // Non-erased garbage at offset 0 must be refused, not silently overwritten.
        let mut flash = MockFlash::new(256);
        flash.data[0] = 0x00; // not erased, not a valid record
        assert!(matches!(
            FlashLogBackend::mount(flash),
            Err(FlashError::Unformatted)
        ));
    }
}
