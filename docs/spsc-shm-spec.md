# SPSC Shared-Memory Face Specification

**Version:** 1.0-draft
**Status:** Draft
**Date:** 2026-04-03

This document specifies the binary layout, wakeup protocol, and connection
lifecycle of the SPSC (single-producer/single-consumer) shared-memory face
used for high-performance local IPC between an NDN application and the
ndn-router forwarder engine.

## 1. Overview

The SPSC SHM face provides bidirectional, cross-process NDN packet delivery
through a POSIX shared memory region containing two lock-free ring buffers.
A pair of named FIFOs (pipes) provides conditional wakeup when a consumer
has no work.

| Property | Value |
|----------|-------|
| Transport | POSIX `shm_open` + `mmap` (`MAP_SHARED`) |
| Wakeup | Named FIFOs (`mkfifo`) via `epoll`/`kqueue` |
| Direction | Full-duplex (two independent SPSC rings) |
| Concurrency | Lock-free; exactly one producer and one consumer per ring |
| Framing | 4-byte little-endian length prefix per slot |
| Packet content | Raw NDN TLV wire bytes (Interest, Data, Nack, or LpPacket) |

## 2. Naming Conventions

Given a face name `{name}` (e.g. `"app-12345-0"`):

| Resource | Path / Identifier |
|----------|-------------------|
| POSIX SHM object | `/ndn-shm-{name}` |
| App-to-engine FIFO | `/tmp/.ndn-{name}.a2e.pipe` |
| Engine-to-app FIFO | `/tmp/.ndn-{name}.e2a.pipe` |

The SHM name is passed to `shm_open(3)` verbatim (leading `/` required by
POSIX). The FIFOs are filesystem paths created by `mkfifo(3)`.

## 3. Shared Memory Layout

The SHM region is a contiguous mapping of size:

```
total_size = HEADER_SIZE + 2 * capacity * slot_stride
slot_stride = 4 + slot_size
```

### 3.1 Header (448 bytes, 7 cache lines)

Each field occupies its own 64-byte cache line to prevent false sharing
between the producer and consumer of each ring.

```
Offset    Size   Field                Description
──────    ────   ─────                ───────────
0         8      magic                0x4E44_4E5F_5348_4D00 ("NDN_SHM\0")
8         4      capacity             Number of slots per ring (u32)
12        4      slot_size            Max payload bytes per slot (u32)
16–63     48     (padding)            Reserved, zero-filled

64        4      a2e_tail             App→Engine ring tail index (AtomicU32)
68–127    60     (padding)

128       4      a2e_head             App→Engine ring head index (AtomicU32)
132–191   60     (padding)

192       4      e2a_tail             Engine→App ring tail index (AtomicU32)
196–255   60     (padding)

256       4      e2a_head             Engine→App ring head index (AtomicU32)
260–319   60     (padding)

320       4      a2e_parked           Engine parked flag for a2e ring (AtomicU32)
324–383   60     (padding)

384       4      e2a_parked           App parked flag for e2a ring (AtomicU32)
388–447   60     (padding)
```

All integer fields are **native-endian** (the SHM region is only shared
between processes on the same host). The `magic` field is written and read
with unaligned u64 access. Ring indices and parked flags are accessed
through `AtomicU32` operations.

### 3.2 Ring Data Regions

Immediately after the header:

```
Offset                                     Contents
──────                                     ────────
448                                        a2e ring: capacity * slot_stride bytes
448 + capacity * slot_stride               e2a ring: capacity * slot_stride bytes
```

Each ring is an array of `capacity` fixed-size slots.

### 3.3 Slot Format

Each slot is `slot_stride` bytes (= 4 + `slot_size`):

```
Offset   Size        Field
──────   ────        ─────
0        4           length    Packet size in bytes (u32, native-endian)
4        slot_size   payload   Packet bytes (only first `length` bytes valid)
```

The `length` field is written by the producer before advancing the tail.
The consumer clamps `length` to `slot_size` to prevent out-of-bounds reads
from a corrupted region.

### 3.4 Default Parameters

| Parameter | Default | Rationale |
|-----------|---------|-----------|
| `capacity` | 256 | Slots per ring; deep enough to keep an iperf-class stream in L2 cache |
| `slot_size` | 8960 | Covers a standard NDN Data packet (≤8800 bytes on most link types) with headroom |
| Total size | ~4.4 MB | `448 + 2 * 256 * 8964` ≈ 4,590,016 bytes |

These defaults are sized for the majority of NDN traffic: Interests,
single-packet Data, iperf probes, ping, management, etc. The ring
fits in L2 cache on modern CPUs and maintains ~30 Gbps throughput on
iperf benchmarks.

Applications that need to carry larger Data (chunked file producers at
64 KiB, 256 KiB, or 1 MiB segments) negotiate a bigger ring via the
`mtu` field of `faces/create` (see §3.5). The router scales
`slot_size` up and `capacity` down automatically to keep total ring
memory within the same ~4.4 MiB budget via `capacity_for_slot()`.

### 3.5 Per-Face Slot-Size Negotiation

An application that plans to emit larger segments — e.g. a chunked
producer at 256 KiB or 1 MiB per segment — can request a larger slot
when creating its face by setting the `mtu` field of the `faces/create`
`ControlParameters`.

```
faces/create {
    Uri  = "shm://app-12345-0"
    Mtu  = 1048576        // bytes of content body the app will emit
}
```

The router rounds the requested `mtu` up to a cache-line-aligned
`slot_size` covering `mtu` plus a fixed overhead reserve for TLV,
Name, MetaInfo, SignatureInfo, and SignatureValue (currently 16 KiB,
see `SHM_SLOT_OVERHEAD` in `spsc.rs`). `capacity` is computed by
`capacity_for_slot(slot_size)` to keep total ring memory within the
same ~4.4 MiB budget (minimum 16 slots, even for very large slots).
The resulting `slot_size` and `capacity` are written into the SHM
header and auto-discovered by `SpscHandle::connect` with no
additional round-trip.

Apps that do not set `mtu` receive a face sized to the default
`slot_size` (8960) and `capacity` (256). The router echoes the
requested `mtu` back in the `faces/create` response.

Clients built on `ForwarderClient` request a per-face slot size via
[`connect_with_mtu`]; `ndn-put` derives its `mtu` from
`--chunk-size` automatically, so producers emitting 1 MiB segments
"just work" without any extra flag. `ndn-peek` accepts an explicit
`--mtu` flag for the consumer side.

## 4. Ring Buffer Protocol

### 4.1 Index Semantics

Each ring has a `tail` (write cursor, advanced by the producer) and a
`head` (read cursor, advanced by the consumer). Both are `u32` values that
wrap around naturally via unsigned wrapping arithmetic.

- **Ring empty:** `head == tail`
- **Ring full:** `tail - head >= capacity` (wrapping subtraction)
- **Slot index:** `tail % capacity` (or `head % capacity`)

### 4.2 Push (Producer)

```
1. Load tail (Relaxed)
2. Load head (Acquire)          — observe consumer's latest progress
3. If tail - head >= capacity → ring full, return false
4. idx = tail % capacity
5. Write length prefix (u32) at slot[idx].offset(0)
6. Copy packet bytes to slot[idx].offset(4)
7. Store tail + 1 (Release)     — make writes visible to consumer
```

### 4.2.1 Batch Push

A batch variant of §4.2 pushes up to N packets with a single
Acquire head load and a single Release tail store:

```
1. Load tail (Relaxed)
2. Load head (Acquire)          — one head load, not N
3. free = capacity - (tail - head)
4. to_push = min(N, free)
5. If to_push == 0 → ring full, return 0
6. For each of the to_push packets:
   a. idx = tail % capacity
   b. Write length prefix at slot[idx].offset(0)
   c. Copy packet bytes to slot[idx].offset(4)
   d. tail += 1                 — local register bump, not a store
7. Store tail (Release)         — single fence publishes all N slots
8. Return to_push
```

This saves `N-1` Acquire loads and `N-1` Release stores compared to
calling §4.2 in a loop. More importantly, when wrapped in the async
`send_batch` API, the batch path collapses N tokio await-points and
their associated scheduler round-trips into a single call — the
primary motivation for the API (see `SpscHandle::send_batch` /
`SpscFace::send_batch` in `spsc.rs`).

When the batch exceeds ring capacity, the caller pushes a partial
batch (up to `free` slots), wakes the peer to drain, yields, and
retries the remainder. Partial pushes are published immediately
(step 7 fires after each partial), so the peer can make forward
progress without waiting for the full batch.

### 4.3 Pop (Consumer)

```
1. Load head (Relaxed)
2. Load tail (Acquire)          — observe producer's latest writes
3. If head == tail → ring empty, return None
4. idx = head % capacity
5. Read length prefix from slot[idx].offset(0)
6. Clamp length to min(length, slot_size)
7. Copy `length` bytes from slot[idx].offset(4)
8. Store head + 1 (Release)     — make slot available to producer
```

### 4.4 Memory Ordering Summary

| Operation | Ordering | Rationale |
|-----------|----------|-----------|
| Producer loads own tail | Relaxed | Only this thread writes it |
| Producer loads peer head | Acquire | See consumer's Release |
| Producer stores tail | Release | Make payload visible before index advances |
| Consumer loads own head | Relaxed | Only this thread writes it |
| Consumer loads peer tail | Acquire | See producer's Release |
| Consumer stores head | Release | Make slot reusable before index advances |

## 5. Wakeup Protocol

When the ring is empty, the consumer parks (sleeps) until the producer
signals new data. The protocol uses a **parked flag** in SHM plus a
**named FIFO** for the actual wakeup.

### 5.1 FIFO Setup

Both FIFOs are created by the engine with `mkfifo(path, 0600)`. Both
sides open each FIFO with `O_RDWR | O_NONBLOCK`:

- `O_RDWR` avoids the blocking-open problem (the open succeeds immediately
  regardless of whether the other end has opened).
- `O_NONBLOCK` prevents writes from blocking when the pipe buffer is full.

Each side uses only the direction it owns:

| Side | a2e FIFO | e2a FIFO |
|------|----------|----------|
| Engine | read (await wakeup) | write (send wakeup) |
| App | write (send wakeup) | read (await wakeup) |

### 5.2 Consumer Park Sequence

```
1. Try pop from ring → if data, return it (fast path)
2. Spin SPIN_ITERS (64) iterations:
   a. spin_loop hint
   b. Try pop → if data, return it
3. Store parked = 1 (SeqCst)
4. Try pop from ring → if data:
   a. Store parked = 0 (Relaxed)
   b. Return data
5. Await FIFO readability (epoll/kqueue via AsyncFd)
6. Drain FIFO (read up to 64 bytes, discard contents)
7. Store parked = 0 (Relaxed)
8. Go to step 1
```

### 5.3 Producer Wakeup Check

After every successful push:

```
1. Load parked flag (SeqCst)
2. If parked != 0:
   a. Write 1 byte to wakeup FIFO (non-blocking)
   b. Silently ignore EAGAIN (pipe buffer full → previous byte pending)
```

### 5.4 Correctness Argument

The `SeqCst` ordering on both the parked flag store (consumer, step 3) and
the parked flag load (producer, step 1) establishes a total order. This
prevents the following race:

```
Consumer                          Producer
────────                          ────────
pop → empty
                                  push(data)
                                  load parked → 0 (not yet stored)
store parked = 1
pop → empty (data in ring but
  consumer checked before push)
sleep on FIFO...                  (no wakeup sent — LOST WAKEUP)
```

With `SeqCst`, the consumer's second pop (step 4) after the flag store is
guaranteed to observe the producer's push if it happened before the
producer's flag load. Conversely, if the push happens after the flag load,
the producer will observe `parked == 1` and send a wakeup.

## 6. Connection Lifecycle

### 6.1 Engine-Side Initialization (SpscFace::create)

```
1. shm_open("/ndn-shm-{name}", O_CREAT | O_RDWR | O_TRUNC, 0666)
2. ftruncate(fd, total_size)
3. mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)
4. close(fd)
5. Write header: magic, capacity, slot_size
   (ring indices are zero-initialized by mmap of fresh fd)
6. Remove stale FIFOs from previous run (best-effort)
7. mkfifo("/tmp/.ndn-{name}.a2e.pipe", 0600)
8. mkfifo("/tmp/.ndn-{name}.e2a.pipe", 0600)
9. Open both FIFOs O_RDWR | O_NONBLOCK
10. Wrap a2e read fd in AsyncFd (for Tokio integration)
```

The SHM region is created with mode `0666` so unprivileged applications
can connect to a router running as root. The FIFOs use `0600` (owner-only)
since both sides open them before any other process.

### 6.2 App-Side Connection (SpscHandle::connect)

```
1. Phase 1 — validate header:
   a. shm_open("/ndn-shm-{name}", O_RDONLY, 0)
   b. mmap(NULL, HEADER_SIZE, PROT_READ, MAP_SHARED, fd, 0)
   c. Read and validate magic (reject if != 0x4E44_4E5F_5348_4D00)
   d. Read capacity and slot_size
   e. munmap + close

2. Phase 2 — open full region:
   a. shm_open("/ndn-shm-{name}", O_RDWR, 0)
   b. mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)
   c. close(fd)

3. Open FIFOs:
   a. Open "/tmp/.ndn-{name}.a2e.pipe" O_RDWR | O_NONBLOCK (app writes)
   b. Open "/tmp/.ndn-{name}.e2a.pipe" O_RDWR | O_NONBLOCK (app reads)
   c. Wrap e2a read fd in AsyncFd
```

The two-phase open ensures the app does not map a truncated or stale
region. If the magic check fails, the app gets `ShmError::InvalidMagic`
without ever mapping the data portion.

### 6.3 Management Plane Handshake

The SHM face is set up through the router's NFD-compatible management
protocol over a Unix domain socket control channel:

```
App                                  Router
───                                  ──────
connect(/tmp/ndn.sock)    →
                                     accept → UnixFace (control)
faces/create {Uri:"shm://{name}"}→
                                     SpscFace::create(id, name)
                                     register face in face table
                                ←    ControlResponse {FaceId: N}
SpscHandle::connect(name)
rib/register {Name:"/prefix",   →
              FaceId: N}
                                     install FIB entry
                                ←    ControlResponse {ok}
send/recv packets over SHM      ⇔   forward packets through SHM face
```

If SHM setup fails at any step, the app falls back to using the Unix
control socket as both control and data plane (higher latency but always
available).

### 6.4 Teardown

**Engine drop (SpscFace):**
1. `munmap` the SHM region
2. `shm_unlink("/ndn-shm-{name}")` — removes the POSIX SHM object
3. Remove both FIFO files from `/tmp`

**App drop (SpscHandle):**
1. `munmap` the SHM region (no `shm_unlink` — engine owns the name)
2. Close FIFO file descriptors (no file removal — engine owns the FIFOs)

### 6.5 Crash Detection

The app holds a `CancellationToken` propagated from the control face
(Unix socket). If the router process dies:

1. The Unix control socket closes → `CancellationToken` fires
2. SpscHandle `recv()` returns `None`, `send()` returns `Err(Closed)`
3. The app can call `probe_alive()` to confirm before reconnecting

FIFO EOF alone is **not** a reliable death signal because `O_RDWR` means
the fd's own write side keeps the pipe open. The cancellation token
(driven by the control socket) is the authoritative signal.

## 7. Backpressure

### 7.1 Ring Full (Producer)

When the ring is full (`tail - head >= capacity`), behavior differs by
side:

- **Engine (`send`):** Yields cooperatively via `tokio::task::yield_now()`
  in a loop until a slot becomes available. This applies backpressure from
  a slow app without blocking the engine's other faces.

- **App (`send`):** Yields with a **5-second wall-clock deadline**. If the
  ring remains full after the deadline, returns `Err(Closed)`. The
  wall-clock approach prevents false failures under heavy Tokio contention
  (a yield-counter would expire faster on fast machines).

### 7.2 Packet Too Large

If a packet exceeds `slot_size`, the send operation fails immediately:

- Engine: returns `FaceError::Io` with `InvalidInput`
- App: returns `ShmError::PacketTooLarge`

Callers that need to send packets larger than `slot_size` must fragment at
a higher layer (NDNLPv2 fragmentation).

## 8. Performance Characteristics

| Metric | Value | Notes |
|--------|-------|-------|
| Push/pop latency (hot) | ~80–125 ns | No wakeup needed, spin catches it |
| Push/pop latency (cold) | ~2 µs | Includes FIFO wakeup round-trip |
| Throughput (small pkts) | ~100K pkt/s | FIFO-limited when every packet parks |
| Throughput (batched) | ~1M+ pkt/s | Spin loop catches back-to-back packets |
| Memory per face | ~4.6 MB | Default parameters |

Compared to Unix socket IPC (~2 µs per packet, kernel copy on every
send/recv), the SHM face eliminates kernel-mediated data copies and
achieves sub-microsecond delivery on the hot path.

## 9. Versioning

The `magic` field (`0x4E44_4E5F_5348_4D00`) serves as a version tag. Any
breaking change to the SHM layout or ring protocol MUST change the magic
value. The app's `connect` validates magic before mapping the data region,
so a version mismatch produces a clear `InvalidMagic` error rather than
silent corruption.

Future versions may reserve header bytes 16–63 for additional fields
(e.g., explicit version number, feature flags). Implementations MUST
zero-fill this region and MUST ignore non-zero values in fields they do
not recognize.

## 10. Security Considerations

- The SHM region is created with mode `0666` to allow unprivileged apps to
  connect to a privileged router. This means any local user can open the
  region. The SHM name includes the app instance identifier, limiting
  the window of exposure.
- FIFOs are created with mode `0600` (owner-only). However, since both
  sides must open them, they must run under the same user or the router
  must adjust permissions.
- A malicious process with access to the SHM region can corrupt ring
  indices or packet data. The consumer clamps slot lengths to prevent
  out-of-bounds reads, but cannot fully validate ring integrity. SHM
  faces should only be used between mutually trusting processes.
- Packet-level authentication (NDN signatures) provides end-to-end
  integrity independent of the transport.
