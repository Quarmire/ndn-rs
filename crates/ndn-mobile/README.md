# ndn-mobile

Pre-configured, in-process NDN forwarder optimised for Android and iOS/iPadOS.
On mobile the forwarder runs inside the application (no separate router daemon).
App traffic flows through `AppFace`; network connectivity uses standard UDP/TCP
faces. Raw Ethernet faces and POSIX SHM are intentionally excluded so the crate
compiles cleanly for `aarch64-linux-android` and `aarch64-apple-ios`.

## Key types

| Type | Description |
|------|-------------|
| `MobileEngine` | Embedded forwarder with FIB, PIT, CS, and all configured faces |
| `MobileEngineBuilder` | Fluent builder: add UDP multicast, unicast hub, persistent CS |
| `Consumer` | Re-exported from `ndn-app`; fetch named data via `AppFace` |
| `Producer` | Re-exported from `ndn-app`; serve named data via `AppFace` |
| `bluetooth_face_from_parts()` | Wrap a platform-supplied async BT stream with `CobsCodec` |

## Feature flags

| Feature | Default | Description |
|---------|---------|-------------|
| `fjall` | no | Persistent on-disk content store; enables App Group CS sharing on iOS |

## Usage

```toml
[dependencies]
ndn-mobile = { version = "*" }
```

```rust
use ndn_mobile::{MobileEngine, Consumer};

let (engine, handle) = MobileEngine::builder()
    .with_udp_multicast(local_iface_addr)
    .build().await?;

let mut consumer = Consumer::from_handle(handle);
let data = consumer.fetch("/ndn/edu/example/data/1").await?;
engine.shutdown().await;
```
