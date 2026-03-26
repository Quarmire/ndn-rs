# TLV Encoding

## Wire Format

Every NDN element is a Type-Length-Value triple. Both Type and Length use variable-width unsigned integer encoding:

| First byte | Width | Range |
|-----------|-------|-------|
| `0x00`–`0xFC` | 1 byte | 0–252 |
| `0xFD` | 3 bytes (prefix + u16 BE) | 253–65535 |
| `0xFE` | 5 bytes (prefix + u32 BE) | 65536–4294967295 |
| `0xFF` | 9 bytes (prefix + u64 BE) | 2³²–2⁶⁴-1 |

Standard NDN type codes and most lengths are below 253, so the common case is one byte with no branching overhead.

## `read_varu64` — the hot-path primitive

Every TLV decode requires two calls to this function (Type and Length). A typical NDN Interest has ~15–20 TLV elements, so ~30–40 calls per packet decode. Keep it small enough to inline.

```rust
pub fn read_varu64(buf: &mut &[u8]) -> Result<u64, TlvError> {
    match buf.first().ok_or(TlvError::UnexpectedEof)? {
        &b if b < 253 => { *buf = &buf[1..]; Ok(b as u64) }
        253 => {
            let v = u16::from_be_bytes(buf[1..3].try_into().unwrap());
            *buf = &buf[3..]; Ok(v as u64)
        }
        254 => {
            let v = u32::from_be_bytes(buf[1..5].try_into().unwrap());
            *buf = &buf[5..]; Ok(v as u64)
        }
        _ => {
            let v = u64::from_be_bytes(buf[1..9].try_into().unwrap());
            *buf = &buf[9..]; Ok(v)
        }
    }
}
```

## `TlvReader` — Zero-Copy Design

`TlvReader` operates over `bytes::Bytes`. The `slice()` method on `Bytes` returns a new `Bytes` sharing the same underlying allocation (atomic ref-count increment, no `memcpy`). Decoded fields — name components, content, signature value — are `Bytes` views into the original receive buffer.

```rust
pub struct TlvReader {
    buf: Bytes,
    pos: usize,
}

impl TlvReader {
    pub fn read_tlv(&mut self) -> Result<(u64, Bytes), TlvError> {
        let typ = self.read_varu64()?;
        let len = self.read_varu64()? as usize;
        if self.pos + len > self.buf.len() {
            return Err(TlvError::UnexpectedEof);
        }
        let value = self.buf.slice(self.pos..self.pos + len);
        self.pos += len;
        Ok((typ, value))
    }

    pub fn scoped(&self, value: Bytes) -> TlvReader {
        TlvReader { buf: value, pos: 0 }
    }
}
```

**CS consequence**: `CsEntry` stores wire-format `Bytes` — a reference-counted view of the receive buffer. A CS hit serves packets directly from the original allocation. Memory cost is proportional to actual data size, not doubled by copying.

## Partial Decode with `OnceLock`

Pay only for fields that are actually accessed. The CS lookup stage needs `Name` and `MustBeFresh` — not the nonce, lifetime, forwarding hint, or app parameters. On a CS hit the pipeline short-circuits and those fields are never decoded.

```rust
pub struct PartialInterest {
    raw:       Bytes,
    name:      Arc<Name>,                // always decoded (needed for FIB)
    nonce:     OnceLock<u32>,
    lifetime:  OnceLock<Option<Duration>>,
    selectors: OnceLock<Selector>,
}

impl PartialInterest {
    pub fn nonce(&self) -> Result<u32> {
        self.nonce.get_or_try_init(|| decode_nonce(&self.raw)).copied()
    }
}
```

## Unknown TLV Types — Critical-Bit Rule

NDN spec requires: if type number is odd (critical bit set) and unknown → drop packet. If type is even (non-critical) and unknown → skip silently.

```rust
fn skip_unknown(&mut self, typ: u64) -> Result<(), TlvError> {
    if typ & 1 == 1 {
        Err(TlvError::UnknownCriticalType(typ))
    } else {
        let len = self.read_length()?;
        self.pos += len;
        Ok(())
    }
}
```

This is required for forward compatibility — new NDN spec versions add non-critical TLV types.

## `TlvWriter` — Nested Encoding

Outer TLV lengths depend on inner content. `write_nested` reserves a 4-byte length placeholder, encodes inner content, then backfills the actual length.

```rust
impl TlvWriter {
    pub fn write_nested<F: FnOnce(&mut TlvWriter)>(&mut self, typ: u64, f: F) {
        self.write_varu64(typ);
        let len_pos = self.buf.len();
        self.buf.extend_from_slice(&[0u8; 4]); // 4-byte placeholder (max varu64 for u32)
        f(self);
        let value_len = (self.buf.len() - len_pos - 4) as u32;
        // backfill — patch the placeholder with the actual length
        self.buf[len_pos..len_pos + 4].copy_from_slice(&value_len.to_be_bytes());
        // if length fits in 1 byte, compact (remove leading 3 zero bytes)
    }
}
```

## Error Types

```rust
pub enum TlvError {
    UnexpectedEof,
    UnknownCriticalType(u64),
    InvalidLength { typ: u64, expected: usize, got: usize },
    InvalidUtf8 { typ: u64 },
    NonceMissing,
    DuplicateField(u64),
}
```

## COBS Framing (Serial Links)

COBS (Consistent Overhead Byte Stuffing) delimits frames with `0x00` bytes that never appear in the encoded payload. After line noise or corruption, resync happens at the next `0x00` — no need to reset the connection. Used by `SerialFace` for UART, RS-485, and LoRa modem links.

## Tool Choice: Hand-rolled vs `nom`/`winnow`

Hand-rolled `TlvReader` is the right choice for the engine hot path — the format is simple (~200 lines) and the performance is predictable. Use `winnow` for less performance-sensitive parsing: NDN URI strings (`/foo/bar/%AB`), TOML config, management protocol messages.
