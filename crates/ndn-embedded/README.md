# ndn-embedded

Minimal NDN forwarder for bare-metal embedded targets. Always `#![no_std]`; targets
ARM Cortex-M, RISC-V, ESP32, and similar MCUs. The design follows the zenoh-pico
approach: reuse the protocol core (`ndn-tlv`, `ndn-packet`) while replacing the
async runtime and OS-level services with synchronous, allocation-optional
alternatives. COBS framing for serial links is included.

## Key types

| Type | Description |
|------|-------------|
| `Forwarder<PIT, FIB, CLK>` | Core forwarder; const-generic PIT and FIB sizes |
| `Fib<N>` | Static FIB with longest-prefix match; capacity `N` set at compile time |
| `Pit<N>` | Static PIT; entries expire according to the provided `Clock` |
| `NoOpClock` | Clock that never expires entries (useful with FIFO eviction) |
| `FnClock` | Clock backed by a user-supplied `fn() -> u64` millisecond counter |
| `Face` / `FaceId` | Trait and identifier for outbound faces |
| `wire::encode_interest_name()` | Zero-allocation Interest encoder |
| `wire::encode_data_name()` | Zero-allocation Data encoder |
| `cobs` | COBS frame encoder/decoder for serial links |

## Feature flags

| Feature | Default | Description |
|---------|---------|-------------|
| `alloc` | no | Heap-backed collections via `hashbrown`; requires a global allocator |
| `cs` | no | Optional content store |
| `ipc` | no | App-to-forwarder SPSC queues |

## Usage

```toml
[dependencies]
ndn-embedded = { version = "*", default-features = false }
# With allocator (ESP32, Cortex-M with heap):
ndn-embedded = { version = "*", features = ["alloc"] }
```

```rust
use ndn_embedded::{Forwarder, Fib, NoOpClock};

let mut fib = Fib::<8>::new();
fib.add_route("/ndn/sensor", 1);
let mut fw = Forwarder::<64, 8, _>::new(fib, NoOpClock);
// In the MCU main loop: fw.process_packet(&raw_bytes, in_face, &mut faces);
```
