# ndn-face-serial

NDN face transport over serial (UART/RS-232/RS-485) links, intended for embedded
and IoT deployments where TCP/IP is unavailable. Packets are delimited using COBS
(Consistent Overhead Byte Stuffing) framing, which guarantees that the `0x00` byte
is never present inside a frame, enabling reliable resynchronisation after line noise.

## Key types

| Type | Description |
|------|-------------|
| `SerialFace` | `StreamFace` alias for a tokio-serial port transport |
| `serial_face_open()` | Open a named serial port as an NDN face (requires `serial` feature) |
| `cobs::CobsCodec` | Tokio codec implementing COBS frame encode/decode |

## Feature flags

| Feature | Default | Description |
|---------|---------|-------------|
| `serial` | yes | Enable hardware serial port support via `tokio-serial`; disable for WASM or bare-metal targets |

## Usage

```toml
[dependencies]
ndn-face-serial = { version = "*" }
# Disable on targets without serial port support:
ndn-face-serial = { version = "*", default-features = false }
```

```rust
use ndn_face_serial::serial_face_open;

let face = serial_face_open("/dev/ttyUSB0", 115_200).await?;
```
