# ndn-tlv

Zero-copy TLV (Type-Length-Value) codec for Named Data Networking packets. All parsing operates over `bytes::Bytes` slices without copying. Compiles `no_std` for embedded targets; an allocator is still required.

## Key Types

| Type / Function | Role |
|-----------------|------|
| `TlvReader` | Zero-copy, streaming cursor for parsing TLV byte slices |
| `TlvWriter` | Growable encoder that produces wire-format `BytesMut` |
| `TlvError` | Error type covering truncated input and non-minimal encodings |
| `read_varu64` / `write_varu64` | NDN variable-width integer codec (1/3/5/9 bytes) |
| `varu64_size` | Compute encoded byte length without writing |

## Feature Flags

| Flag | Default | Description |
|------|---------|-------------|
| `std` | on | Enables `std` support in `bytes`. Disable for `no_std` targets. |

## Usage

```rust
use ndn_tlv::{TlvReader, TlvWriter};

// Encode a TLV element
let mut w = TlvWriter::new();
w.write_tlv(0x07, b"/example/name");
let wire = w.finish();

// Decode
let mut r = TlvReader::new(&wire);
let (typ, value) = r.read_tlv().unwrap();
assert_eq!(typ, 0x07);
```

Part of the [ndn-rs](../../README.md) workspace.
