//! Embedded **flash-backed** [`SyncBackend`](crate::SyncBackend), generic over the
//! standard [`embedded-storage`](https://docs.rs/embedded-storage) `NorFlash` trait.
//!
//! This is the HW seam for F21's embedded leg: ndn-rs owns the *engine* once, and the
//! board/HAL plugs the concrete chip (ESP32 `esp-storage`, an STM32 HAL, …) in through
//! `NorFlash` — so the engine is HW-independent and CI-testable against a mock flash,
//! and only the flash driver is HW-specific.
//!
//! ## Design — RAM index + flash write-ahead log
//!
//! The ordered index lives in RAM (a `BTreeMap`, so `scan_prefix` is ordered and
//! efficient); flash is an **append-only log of records** for durability. Each write
//! (a `put`/`delete`, or a whole `write_batch`) is **one** length-framed record with a
//! validity footer — so a record is applied on replay only if it landed in full, giving
//! **power-loss-atomic batches**. On mount the log is replayed into RAM; a torn tail
//! (an interrupted final write) is dropped and the store self-heals (the next write
//! compacts: erase the region, rewrite the whole index from RAM — no partial-sector
//! erase, hence no corruption risk). Compaction also reclaims space when the log fills.
//!
//! Values are held in RAM (matching the embedded floor — "an MCU holds few blocks");
//! flash adds durability across power loss. For datasets that exceed RAM, a future
//! offset-indexed variant would read values back from flash.

use crate::{SyncBackend, WriteOp};
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
/// Superblock magic at offset 0 — identifies an ndn-storage flash log, so `mount`
/// refuses a blank or foreign region instead of clobbering it.
const SUPER_MAGIC: u64 = 0x4E44_4E5F_464C_4F47; // "NDN_FLOG"
const FORMAT_VERSION: u32 = 1;

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

fn align_up(n: u32, a: u32) -> u32 {
    n.div_ceil(a) * a
}

struct FlashState<F> {
    flash: F,
    index: BTreeMap<Vec<u8>, Bytes>,
    write_off: u32, // next free (erased) offset in the log
    cap: u32,
    /// The mounted tail was torn (or unverified) — append must compact before writing.
    dirty_tail: bool,
}

impl<F: NorFlash> FlashState<F> {
    /// Byte length of the superblock (magic + version), rounded to the write unit; the
    /// log begins here.
    fn header_len() -> u32 {
        align_up(12, F::WRITE_SIZE as u32)
    }

    fn read_u32(&mut self, off: u32) -> Result<u32, FlashError> {
        let mut b = [0u8; 4];
        self.flash.read(off, &mut b).map_err(|_| FlashError::Io)?;
        Ok(u32::from_le_bytes(b))
    }

    /// Erase the region and lay down a fresh superblock; leaves the log empty.
    fn write_superblock(&mut self) -> Result<(), FlashError> {
        self.flash.erase(0, self.cap).map_err(|_| FlashError::Io)?;
        let hlen = Self::header_len() as usize;
        let mut hdr = vec![0xFFu8; hlen];
        hdr[..8].copy_from_slice(&SUPER_MAGIC.to_le_bytes());
        hdr[8..12].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        self.flash.write(0, &hdr).map_err(|_| FlashError::Io)?;
        // Note: the in-RAM index is left untouched (compaction rewrites *from* it).
        self.write_off = hlen as u32;
        self.dirty_tail = false;
        Ok(())
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

    /// Verify the superblock, then replay the log into the index; set
    /// `write_off`/`dirty_tail`. Rejects a blank/foreign region as `Unformatted`.
    fn mount(&mut self) -> Result<(), FlashError> {
        let hlen = Self::header_len();
        if self.cap < hlen + 8 {
            return Err(FlashError::OutOfSpace);
        }
        let mut magicb = [0u8; 8];
        self.flash.read(0, &mut magicb).map_err(|_| FlashError::Io)?;
        if u64::from_le_bytes(magicb) != SUPER_MAGIC {
            return Err(FlashError::Unformatted);
        }
        let mut off = hlen;
        loop {
            if off + 8 > self.cap {
                break;
            }
            let len = self.read_u32(off)?;
            if len == ERASED {
                break; // clean end of log
            }
            // Bounds: header + payload + footer must fit.
            let Some(end) = off.checked_add(8).and_then(|x| x.checked_add(len)) else {
                self.dirty_tail = true;
                break;
            };
            if end > self.cap {
                self.dirty_tail = true;
                break;
            }
            let mut buf = vec![0u8; len as usize + 4];
            self.flash.read(off + 4, &mut buf).map_err(|_| FlashError::Io)?;
            let footer = u32::from_le_bytes([
                buf[len as usize],
                buf[len as usize + 1],
                buf[len as usize + 2],
                buf[len as usize + 3],
            ]);
            if footer != (len ^ COMMIT_MAGIC)
                || !Self::apply_payload(&buf[..len as usize], &mut self.index)
            {
                self.dirty_tail = true; // torn / corrupt tail — drop it, self-heal on write
                break;
            }
            off += align_up(8 + len, F::WRITE_SIZE as u32);
        }
        self.write_off = off;
        Ok(())
    }

    /// Erase the region, re-lay the superblock, and rewrite the live index as one
    /// fresh record (also reclaims superseded/tombstoned entries).
    fn compact(&mut self) -> Result<(), FlashError> {
        let ops: Vec<WriteOp> = self
            .index
            .iter()
            .map(|(k, v)| WriteOp::Put(k.clone(), v.clone()))
            .collect();
        self.write_superblock()?; // erase + header; write_off = header_len
        if ops.is_empty() {
            return Ok(());
        }
        let rec = Self::encode_record(&ops);
        if self.write_off + rec.len() as u32 > self.cap {
            return Err(FlashError::OutOfSpace);
        }
        let at = self.write_off;
        self.flash.write(at, &rec).map_err(|_| FlashError::Io)?;
        self.write_off += rec.len() as u32;
        Ok(())
    }

    /// Append one record for `ops`, compacting first if the tail is dirty or full.
    fn append(&mut self, ops: &[WriteOp]) -> Result<(), FlashError> {
        let rec = Self::encode_record(ops);
        let need = rec.len() as u32;
        if self.dirty_tail || self.write_off + need > self.cap {
            self.compact()?;
            // After compaction the log is rewritten from the index, so the *new* ops
            // still need appending (they are not yet in the index).
            if self.write_off + need > self.cap {
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
    fn commit(&mut self, ops: Vec<WriteOp>) {
        if self.append(&ops).is_ok() {
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
        }
        // On flash failure the index is left unchanged (durability over silent drift).
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
            write_off: 0,
            cap,
            dirty_tail: false,
        };
        st.mount()?;
        Ok(Self::wrap(st))
    }

    /// Erase the region, lay a fresh superblock, and start an empty store (first-time
    /// provisioning / reset).
    pub fn format(flash: F) -> Result<Self, FlashError> {
        let cap = flash.capacity() as u32;
        let hlen = FlashState::<F>::header_len();
        if cap < hlen + 8 {
            return Err(FlashError::OutOfSpace);
        }
        let mut st = FlashState {
            flash,
            index: BTreeMap::new(),
            write_off: 0,
            cap,
            dirty_tail: false,
        };
        st.write_superblock()?;
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
    fn get(&self, key: &[u8]) -> Option<Bytes> {
        self.with(|s| s.index.get(key).cloned())
    }
    fn put(&self, key: &[u8], value: Bytes) {
        self.with(|s| s.commit(vec![WriteOp::Put(key.to_vec(), value)]));
    }
    fn delete(&self, key: &[u8]) {
        self.with(|s| s.commit(vec![WriteOp::Delete(key.to_vec())]));
    }
    fn scan_prefix(&self, prefix: &[u8], limit: usize) -> Vec<(Bytes, Bytes)> {
        self.with(|s| {
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
        })
    }
    fn write_batch(&self, ops: Vec<WriteOp>) {
        // One framed flash record ⇒ power-loss-atomic across the whole group.
        self.with(|s| s.commit(ops));
    }
    fn name(&self) -> &'static str {
        "flash"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use embedded_storage::nor_flash::{
        ErrorType, NorFlashError, NorFlashErrorKind, ReadNorFlash,
    };

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
        f.put(b"/a/b", Bytes::from_static(b"v-ab"));
        f.put(b"/a/c", Bytes::from_static(b"v-ac"));
        f.put(b"/z", Bytes::from_static(b"v-z"));
        assert_eq!(f.get(b"/a/b").as_deref(), Some(&b"v-ab"[..]));
        let under: Vec<_> = f
            .scan_prefix(b"/a", 0)
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        assert_eq!(under, vec![Bytes::from_static(b"/a/b"), Bytes::from_static(b"/a/c")]);
        f.delete(b"/a/b");
        assert!(f.get(b"/a/b").is_none());
        assert_eq!(f.get(b"/a/c").as_deref(), Some(&b"v-ac"[..]));
    }

    #[test]
    fn survives_remount() {
        // Write, then snapshot the raw flash bytes (simulating a power cycle).
        let flash = {
            let f = FlashLogBackend::format(MockFlash::new(4096)).unwrap();
            f.put(b"k1", Bytes::from_static(b"v1"));
            f.write_batch(vec![
                WriteOp::Put(b"k2".to_vec(), Bytes::from_static(b"v2")),
                WriteOp::Delete(b"k1".to_vec()),
            ]);
            f.with(|s| MockFlash {
                data: s.flash.data.clone(),
            })
        };
        // Remount the persisted bytes — the log replays into the index.
        let f = FlashLogBackend::mount(flash).unwrap();
        assert!(f.get(b"k1").is_none(), "delete persisted");
        assert_eq!(f.get(b"k2").as_deref(), Some(&b"v2"[..]), "batch put persisted");
    }

    #[test]
    fn compaction_reclaims_space() {
        // Small region: repeated overwrites of one key must trigger compaction and
        // keep working (the live set is tiny).
        let f = FlashLogBackend::format(MockFlash::new(512)).unwrap();
        for i in 0..200u32 {
            f.put(b"counter", Bytes::copy_from_slice(&i.to_le_bytes()));
        }
        assert_eq!(
            f.get(b"counter").as_deref(),
            Some(&199u32.to_le_bytes()[..]),
            "latest value survives many compactions"
        );
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
