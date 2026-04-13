# Interoperability Testing

ndn-rs is tested against three other NDN implementations across an 8-scenario matrix:

| Implementation | Role(s) tested |
|---|---|
| **ndn-cxx** (C++) | consumer and producer, via NFD and ndn-fwd |
| **NDNts** (TypeScript/Node.js) | consumer and producer, via yanfd and ndn-fwd |
| **NFD** (C++ forwarder) | external forwarder (ndn-rs as an application client) |
| **yanfd** (Go forwarder) | external forwarder (ndn-rs as an application client) |

## Scenario Matrix

| Scenario | Consumer | Forwarder | Producer |
|----------|----------|-----------|----------|
| `fwd/cxx-consumer` | ndn-cxx (ndnpeek) | ndn-fwd | **ndn-rs** (ndn-put) |
| `fwd/cxx-producer` | **ndn-rs** (ndn-peek) | ndn-fwd | ndn-cxx (ndnpoke) |
| `fwd/ndnts-consumer` | NDNts (ndncat) | ndn-fwd | **ndn-rs** (ndn-put) |
| `fwd/ndnts-producer` | **ndn-rs** (ndn-peek) | ndn-fwd | NDNts (ndncat) |
| `app/nfd-cxx-producer` | **ndn-rs** (ndn-peek) | NFD | ndn-cxx (ndnpoke) |
| `app/nfd-cxx-consumer` | ndn-cxx (ndnpeek) | NFD | **ndn-rs** (ndn-put) |
| `app/yanfd-ndnts-producer` | **ndn-rs** (ndn-peek) | yanfd | NDNts (ndncat) |
| `app/yanfd-ndnts-consumer` | NDNts (ndncat) | yanfd | **ndn-rs** (ndn-put) |

ndn-rs appears in **bold** in every row — it is the implementation under test. The tests run in Docker Compose with each forwarder on a shared virtual network. Results are published automatically to [Interop Test Results](../reference/interop-results.md).

---

## The Journey to Full Interoperability

Getting ndn-rs to pass all eight scenarios required resolving a series of compatibility gaps, roughly in order from fundamental wire format through protocol semantics to test infrastructure. Each gap is described below.

### 1. NDNLPv2 Framing on Unix Sockets

**The problem.** The NDN Link Protocol v2 (NDNLPv2, type `0x64`) is the standard framing used on all NDN faces, including Unix-domain sockets. NFD and yanfd wrap every Interest and Data inside an `LpPacket` before writing it to the socket, and they expect the same from their peers.

ndn-rs was sending *bare* TLV bytes on Unix sockets — no `0x64` wrapper. Every packet sent to NFD or yanfd was silently discarded. Every packet received from them was an `LpPacket` that ndn-rs stripped correctly, but the asymmetry meant the external forwarder got nothing back.

**The fix.** `encode_lp_packet()` was added and called unconditionally on outgoing bytes for all Unix-socket faces to external forwarders. The `uses_lp` flag (auto-detected from the first inbound packet) gates LP wrapping for ndn-fwd's own local-app faces.

---

### 2. NonNegativeInteger Encoding

**The problem.** NDN's `NonNegativeInteger` type mandates *minimal* encoding: the value `0` uses a zero-byte TLV value field, values 1–255 use one byte, 256–65535 use two bytes, and so on. ndn-rs was emitting some integers with extra leading zeros — most visibly for SegmentNameComponent values (e.g., segment `0` as a two-byte value instead of one byte).

ndn-cxx and NDNts both enforce this strictly. Segment and version numbers decoded to wrong values, causing content-fetching pipelines to fail silently (looking for a segment that wasn't there, or returning the wrong data).

**The fix.** The TLV integer encoder was corrected to always use the smallest encoding for the given value. Existing unit tests were extended to cover the boundary cases.

---

### 3. Default Signature: DigestSha256

**The problem.** ndn-cxx's ndnpeek validates Data signatures it receives. When ndn-rs produced Data with no signature (or with an ephemeral Ed25519 key that the consumer had never seen), the consumer rejected the packet.

Ed25519 authentication requires a trust anchor — the consumer must have the producer's certificate. That is appropriate for production but not for an interop smoke-test between strangers. `DigestSha256` (type 0x01 per NDN Packet Format v0.3) is a self-contained integrity check: the `SignatureValue` is SHA-256 of the signed portion of the packet; no key distribution is needed.

**The fix.** DigestSha256 became the default signing mode for all ndn-rs-produced Data (`DataBuilder::sign_digest_sha256()`). Consumers can verify it with the public material already in the packet.

---

### 4. CanBePrefix Response Naming

**The problem.** Segmented-fetch consumers (NDNts `ndncat get-segmented`, ndn-cxx `ndnpeek --pipeline`) work in two phases:

1. Send a CanBePrefix Interest for the *prefix* (e.g., `/example`).
2. Extract the **versioned name** from the first response, then fetch each segment by its `SegmentNameComponent` (TLV `0x32`).

Step 2 relies on the response being named `/example/v=<timestamp>/<seg=0>`, where the `VersionNameComponent` (TLV `0x36`) sits at `name[-2]`. NDNts specifically probes `name[-2]` when using `--ver=cbp` (version via CanBePrefix).

ndn-put was responding to CanBePrefix Interests with a Data named `/example/<seg=0>` — no version component. NDNts found no version at `name[-2]`, assumed the response was a bare (non-versioned) packet, and aborted or returned wrong content.

**The fix.** ndn-put now always builds a versioned prefix (`/<name>/v=<µs-timestamp>`) at startup and responds to CanBePrefix discovery with a Data named `/<name>/v=<ts>/<seg=0>`, matching ndnputchunks behavior exactly.

---

### 5. NDNts Signed Interest v0.3 Format

**The problem.** NDNts uses the NDN Packet Format v0.3 **Signed Interest** format for management commands (rib/register, etc.). A v0.3 Signed Interest looks like:

```
/prefix/params-sha256=<digest>  ← ParametersSha256DigestComponent at name[-1]
  ApplicationParameters TLV    ← ControlParameters encoded here
  InterestSignatureInfo TLV
  InterestSignatureValue TLV
```

The `ParametersSha256DigestComponent` (type `0x02`) appears as `name[4]` when the Interest name has four ordinary components. ndn-fwd's management handler read ControlParameters from `name[4]`, found the digest component (not ControlParameters), and returned a parse error. The rib/register attempt was silently dropped.

**The fix.** The management handler now falls back to `interest.app_parameters()` when the named position doesn't decode as ControlParameters:

```rust
let params = parsed.params
    .or_else(|| interest.app_parameters()
        .and_then(|app| ControlParameters::decode(app).ok()));
```

This handles both the legacy four-component format and the v0.3 Signed Interest format in one path.

---

### 6. Dataset Queries Must Use Unsigned Interests

**The problem.** The NFD Management Protocol distinguishes between two kinds of requests:

- **Command verbs** (rib/register, face/create, …) — modify state; require a **Signed Interest**.
- **Dataset queries** (face/list, fib/list, rib/list) — read state; accept **unsigned Interests**.

yanfd enforces this strictly: a signed Interest to a dataset endpoint is rejected. NFD accepts either but logs a warning.

ndn-ctl was sending Signed Interests for everything, including `face list` and `route list`. Against yanfd, these always failed. The interop scripts were using the returned face list to figure out which face NDNts had connected on; a failed face list meant the route registration fallback couldn't work.

As a workaround, ndn-ctl used `nfdc` (ndn-cxx's management tool) for face listing. This introduced a dependency on ndn-cxx being installed in the test container.

**The fix.** ndn-ctl was updated to send unsigned Interests for dataset-query verbs and Signed Interests only for command verbs. The `nfdc` dependency was removed.

---

### 7. Nack LP Packet Pass-Through

**The problem.** When no route exists for a prefix, a forwarder sends back a `Nack(NoRoute)` message wrapped in an LP packet:

```
LpPacket (0x64)
  Nack (0xFD0320)
    NackReason: NoRoute (0x64)
  Fragment
    Interest (0x05) …
```

The `strip_lp()` function was designed to unwrap LP-framed packets and return the inner bytes. For *data* LP packets it returned the inner Interest or Data bytes correctly. For *Nack* LP packets, however, it returned the raw LP bytes unchanged (starting with `0x64`). The caller then tried `Data::decode(bytes_starting_with_0x64)` and got:

```
Error: decode: unknown packet type 0x64
```

This appeared as a fetch failure with no indication that a NoRoute Nack had been received. It made timing-related flakes very hard to diagnose, since the consumer saw a decode error rather than a routing error.

**The fix.** `strip_lp()` was updated to detect Nack LP packets and return an `Err(Nack)` instead of raw bytes. Callers that only handle Data (like ndn-peek) propagate this as an intelligible "NoRoute Nack received" error.

---

### 8. Face ID Recycling in NDNts Route Registration

**The problem.** When NDNts's automatic `rib/register` fails (e.g., because of a Signed Interest format mismatch — see §5), the interop script must manually register a route to NDNts's face. To do that, it needs to know NDNts's face ID.

The original approach was a PRE/POST face-list diff:

```bash
PRE=$(ndn-ctl face list)   # snapshot before ndncat starts
ndncat put-segmented &     # start NDNts producer
sleep 1
POST=$(ndn-ctl face list)  # snapshot after
NDNTS_FACE=$(comm -13 <(echo "$PRE") <(echo "$POST") | ...)
```

The assumption: any face ID in POST but not in PRE belongs to ndncat.

This broke because of **LIFO face ID recycling**. The face table's free list is a `Vec` (stack). When the PRE `ndn-ctl` process connects, it gets face ID 1. When it disconnects, face ID 1 goes back on the free list. When `ndncat` connects next, it also gets face ID 1 (reused). When the POST `ndn-ctl` connects, it gets face ID 2. The diff sees:

- PRE: `{1}`
- POST: `{1 (ndncat), 2 (POST ndn-ctl)}`
- `comm -13`: `{2}` — the POST ndn-ctl's own face, not ndncat's

The script then ran `route add --face 2`, which pointed to the now-disconnected POST ndn-ctl. That face was immediately removed from the FIB when ndn-ctl exited, leaving no route and producing a NoRoute Nack.

**The fix.** The PRE/POST diff was replaced with a two-step strategy:

1. **FIB inspection** (primary): After the sleep, query the FIB. If NDNts's prefix is already there, it self-registered via rib/register — no manual step needed.
2. **Lowest-non-reserved face** (fallback): If the prefix is not in the FIB, enumerate all faces with ID below `0xFFFF_0000` (the reserved range) and pick the lowest numeric ID. NDNts connected before this query, so it has the smallest face ID currently active.

```bash
NDNTS_FACE=$(
  ndn-ctl --socket "${FWD_SOCK}" face list \
    | grep -oE 'faceid=[0-9]+' | sed 's/faceid=//' \
    | awk '$1 < 4294901760' | sort -n | head -1
)
```

---

### 9. Registration Timing: Node.js and NFD

**The problem.** Two timing issues caused intermittent failures under the original `sleep 0.5` wait:

- **Node.js startup**: NDNts runs on Node.js, which loads and JIT-compiles modules before doing anything. In a cold Docker container, startup plus rib/register plus FIB propagation took more than 500 ms, causing ndn-peek to send its Interest before NDNts had registered.

- **NFD's RIB manager**: NFD separates route management into a dedicated RIB daemon (nrd). A rib/register from ndnpoke travels: ndnpoke → NFD socket → RIB handler → FIB. This IPC hop adds latency that ndn-fwd (which applies RIB changes in the same async task) doesn't have.

Both failures produced a NoRoute Nack (see §7), which appeared as "unknown packet type 0x64" before that fix was in place.

**The fix.** Sleep durations were matched to each forwarder's characteristics:

| Scenario | Sleep | Reason |
|----------|-------|--------|
| ndn-fwd + NDNts | 2 s | Node.js JIT warmup + rib/register + FIB |
| NFD + ndn-cxx | 1 s | NFD RIB manager IPC hop |
| ndn-fwd + ndn-cxx | 0.5 s | C++ startup is fast; ndn-fwd applies routes inline |
| yanfd + NDNts | 2 s | yanfd RIB propagation + Node.js startup |

---

### 10. Manual Route Registration Fallback

**The problem.** Even after fixing the Signed Interest format (§5), NDNts's automatic rib/register is not guaranteed: the RIB handler may not be ready, the Interest may expire in transit, or the route may be registered on the wrong prefix scope. Without a fallback, any registration failure means no route and a silent test failure.

**The fix.** All NDNts interop scripts now check whether automatic registration succeeded (via FIB inspection) and, if not, explicitly call:

```bash
ndn-ctl route add "${PREFIX}" --face "${NDNTS_FACE}"
```

This makes the happy path (NDNts self-registers) fast and the fallback path (manual) robust, with diagnostic output at each decision point so failures are visible in CI logs.

---

## Current Status

See [Interop Test Results](../reference/interop-results.md) for the live test matrix from the most recent CI run.

All eight scenarios pass on every scheduled weekly run and on every push to `main` that touches `testbed/` or `binaries/ndn-fwd/`. Failures are tracked as separate quality signals — they do not block merges but are investigated promptly.

### What Is Not Yet Tested

- **NDNCERT handshake** between ndn-rs and ndn-cxx CAs
- **SVS (State Vector Sync)** against NDNts SVS library
- **Multicast UDP** face interop (ndn-fwd ↔ NFD multicast group)
- **ndn-cxx signed Interests** for management (tested with NDNts v0.3 format; ndn-cxx uses a different format)
