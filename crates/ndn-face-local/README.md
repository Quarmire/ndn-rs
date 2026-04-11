# ndn-face-local

Local and IPC face implementations for NDN. These faces connect application code or
co-located processes to the NDN forwarder on the same machine without going through
the network stack. `AppFace` is the preferred interface for library-embedded use;
`ShmFace` offers the lowest latency for high-throughput producer/consumer apps on
desktop Linux.

## Key types

| Type | Description |
|------|-------------|
| `AppFace` / `AppHandle` | In-process channel pair (tokio `mpsc`); works on all platforms |
| `UnixFace` | Unix domain socket face (Unix only) |
| `IpcFace` / `IpcListener` | Cross-platform IPC (Unix sockets on Unix, named pipes on Windows) |
| `ShmFace` / `ShmHandle` | POSIX shared-memory SPSC ring buffer; wakeup via `AsyncFd`-backed FIFO pairs |

## Feature flags

| Feature | Default | Description |
|---------|---------|-------------|
| `spsc-shm` | no | Enable `ShmFace` — requires POSIX `shm_open` and `mkfifo` (Linux/macOS only, not Android/iOS) |

## Usage

```toml
[dependencies]
ndn-face-local = { version = "*" }
ndn-face-local = { version = "*", features = ["spsc-shm"] }  # high-throughput
```

```rust
use ndn_face_local::{AppFace, AppHandle};

let (face, handle) = AppFace::pair();
// Pass `face` to the engine, use `handle` in application code.
```
