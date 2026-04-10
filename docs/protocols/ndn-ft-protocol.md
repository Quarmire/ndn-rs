# NDN File Transfer Protocol (NDN-FT) v0.1

> **Status:** Draft / Experimental
> **Library:** `crates/ndn-filestore`
> **Tools:** `ndn-send`, `ndn-recv`
> **Dashboard:** Tools → File Transfer tab

---

## Overview

NDN-FT is an AirDrop-like file transfer protocol built natively on Named Data
Networking. Unlike IP-based file sharing, there is no connection setup, no port
forwarding, and no IP addresses — files are named content objects and routed by
the NDN forwarder according to prefix policies.

### Design goals

| Goal | Decision |
|------|----------|
| Platform agnostic | Pure NDN — works on any OS/device with an NDN router |
| No infrastructure | No central server; sender hosts content, receiver fetches |
| Content integrity | SHA-256 verified after reassembly |
| Optional security | Per-file: signed (Ed25519/HMAC), encrypted (AES-GCM), or hash-only |
| Discoverable | Catalog served under node's prefix; browseable without prior knowledge |
| Consent | Receiver must acknowledge before transfer starts |

---

## Name Hierarchy

All protocol names are rooted under a node's NDN prefix:

```
/<node-prefix>/ndn-ft/v0/
├── catalog/0               → paginated JSON list of hosted files
├── file/<file-id>/
│   ├── meta                → JSON FileMetadata
│   └── <seg>               → binary segment (0, 1, 2, …)
└── notify                  → incoming offer endpoint
```

**`<node-prefix>`** — the operator-assigned NDN name of a node, e.g. `/alice/laptop`.

**`<file-id>`** — `sha256-<first-16-hex-chars-of-SHA256>`. Globally unique for
distinct content; identical content produces the same ID (natural deduplication).

**`<seg>`** — zero-based segment index as an ASCII GenericNameComponent, matching
the `ndn-put`/`ndn-peek` segment encoding convention.

---

## Data Formats

### FileMetadata (served at `/meta`, also embedded in `FileOffer`)

```json
{
  "id":           "sha256-abc123def456789a",
  "name":         "photo.jpg",
  "size":         1048576,
  "segments":     128,
  "segment_size": 8192,
  "sha256":       "abc123...full-64-hex-chars...",
  "mime":         "image/jpeg",
  "sender_prefix":"/alice/laptop",
  "ts":           1680000000,
  "signing":      "ed25519",
  "encryption":   "none"
}
```

### FileOffer (Interest AppParam to `/notify`)

```json
{
  "version": 1,
  "meta": { /* FileMetadata */ }
}
```

### OfferResponse (Data content from `/notify`)

```json
{ "accept": true }
// or
{ "accept": false, "reason": "user_declined" }
```

### Catalog (served at `/catalog/0`)

```json
[
  { /* FileMetadata */ },
  { /* FileMetadata */ }
]
```

For large catalogs (> ~100 files), the catalog is segmented using the standard
NDN chunked-content convention with `FinalBlockId` on each segment.

---

## Transfer Flow

```
Sender                              Receiver
  |                                    |
  |─── Interest /receiver/ndn-ft/v0/notify ──▶|
  |    (AppParam = JSON FileOffer)             |
  |                                            |
  |           [user sees system notification]  |
  |                                            |
  |◀── Data (OfferResponse: accept=true) ──────|
  |                                            |
  |─── [sender serves segments] ─────────────  |
  |                                            |
  |◀── Interest /sender/ndn-ft/v0/file/<id>/meta ─|
  |─── Data (FileMetadata JSON) ──────────────▶|
  |                                            |
  |◀── Interest /sender/ndn-ft/v0/file/<id>/0  |
  |◀── Interest /sender/ndn-ft/v0/file/<id>/1  |  (pipelined)
  |◀── Interest /sender/ndn-ft/v0/file/<id>/N  |
  |─── Data (segment 0) ──────────────────────▶|
  |─── Data (segment 1) ──────────────────────▶|
  |─── Data (segment N) ──────────────────────▶|
  |                                            |
  |                [verify SHA-256]            |
  |                [write to disk]             |
  |                [system notification]       |
```

---

## Segment Naming Convention

Segments use **GenericNameComponents** (TLV type `0x08`) containing the ASCII
decimal representation of the segment index.  This matches the naming used by
`ndn-put` and `ndn-peek`.

Each segment's `Data` packet carries a `FinalBlockId` so the consumer can
discover the total segment count from any individual segment — useful for
parallel fetching without first fetching metadata.

### Example names

```
/alice/laptop/ndn-ft/v0/file/sha256-abc123/0
/alice/laptop/ndn-ft/v0/file/sha256-abc123/127
```

---

## Security

### Content integrity (always on)

After reassembly, the receiver computes `SHA-256` of the raw content and
compares it against `meta.sha256`. Mismatches are fatal — the file is discarded.

### Segment signing (optional, per-file)

| Mode | Description | Cost |
|------|-------------|------|
| `none` | No signature; integrity from hash only | Zero per-segment |
| `ed25519` | Ed25519 per segment | ~0.1 ms/seg on modern hardware |
| `hmac` | HMAC-SHA256 with pre-shared key | ~0.01 ms/seg |

### Encryption (optional, per-file)

| Mode | Description |
|------|-------------|
| `none` | Plaintext segments |
| `aes-gcm` | AES-256-GCM applied to content before chunking; key negotiated out-of-band |

Key exchange for AES-GCM is **out of scope for v0.1** and is left to the NDN
trust model (NDNCERT / DID). A future version will add in-protocol key
negotiation using ECDH.

---

## ndn-iperf Protocol Extensions

### Session Negotiation

Clients send a negotiation Interest before the main test:

```
Interest /<prefix>/<flow-id>/session
  AppParam: {"duration":10,"signing":"none","size":0,"reverse":false,"callback":""}
```

Server responds with agreed parameters:

```
Data /<prefix>/<flow-id>/session
  Content: {"signing":"none","size":8192,"reverse":false,"session_id":"<flow-id>"}
```

### Reverse Mode

The server becomes the consumer:

1. Client sends `session` Interest with `"reverse":true,"callback":"/<node>/iperf-reverse/<flow-id>"`.
2. Server spawns a consumer task targeting `/<node>/iperf-reverse/<flow-id>/<seq>`.
3. Client registers `/<node>/iperf-reverse/<flow-id>` and serves data.
4. Server stores result at `/<prefix>/<flow-id>/result` (JSON, same format as normal results).
5. Client fetches `/<prefix>/<flow-id>/result` after test duration.

---

## Known Gaps (v0.1)

| Gap | Impact | Planned fix |
|-----|--------|-------------|
| No in-protocol key exchange for AES-GCM | Encrypted transfers require out-of-band key | v0.2: ECDH handshake |
| Catalog pagination hard-coded to 1 segment | Breaks for > ~500 files | v0.2: full chunked catalog |
| No transfer resume | Interrupted transfers must restart | v0.2: segment-level resume with bloom filter |
| No parallel multi-file transfer | Sequential only | v0.2: multiple outstanding session Interests |
| Receiver auto-download after accept | Currently prints CLI command | v0.3: dashboard embedded downloader |
| No offer broadcast | Must know target prefix | v0.2: multicast Interest to `/local/ndn-ft/v0/notify` |
| OS share sheet integration | Dashboard placeholder only | v1.0: macOS Share Extension, Windows Send To |

---

## v1.0 Target Feature List

The following capabilities define the v1.0 milestone:

- [ ] **Encrypted transfers** — in-protocol ECDH key agreement (P-256).
- [ ] **Multicast offers** — send to `/local/ndn-ft/v0/notify` to reach all nodes on a LAN segment without knowing their prefix.
- [ ] **Transfer resume** — restart interrupted downloads from the last received segment.
- [ ] **Chunked catalog** — serve catalogs of arbitrary size with proper NDN segmentation.
- [ ] **Dashboard-native downloader** — integrated progress bar, no CLI required.
- [ ] **OS share sheet** — send files to NDN nodes from Finder (macOS), Explorer (Windows), or Files (Linux/Android).
- [ ] **System notification with accept/reject** — pop-up for incoming offers with one-click accept.
- [ ] **Signed catalog** — catalog Data packets signed by node identity, preventing spoofing.
- [ ] **Streaming mode** — begin playback/processing before full transfer completes (pipeline to stdout or FUSE mount).
- [ ] **Access control** — Interest AppParam with receiver's NDN identity; sender can restrict who can fetch.
- [ ] **Versioning** — multiple versions of a file under a single prefix with version-component selection.
- [ ] **Deduplication** — content-addressed IDs enable zero-cost hosting of identical files.
- [ ] **Mobile support** — iOS/Android NDN-FT via `ndn-mobile` embedded engine.

---

## Implementation Status

| Component | Status |
|-----------|--------|
| `crates/ndn-filestore` | ✅ v0.1 implemented |
| `ndn-send` binary | ✅ v0.1 implemented |
| `ndn-recv` binary | ✅ v0.1 implemented |
| Dashboard Tools → File Transfer | ✅ UI scaffolding (CLI command hints) |
| Dashboard embedded downloader | 🔲 Not yet |
| System notification (accept popup) | 🔲 Not yet |
| OS share sheet | 🔲 Placeholder in settings |
| AES-GCM encryption | 🔲 Parsing only, no key exchange |
| Multicast offers | 🔲 Not yet |

---

## Future Direction

NDN-FT is designed to be the foundation for higher-level applications:

- **NDN Sync** (`crates/ndn-sync`) — synchronise datasets across nodes using SVS or PSync, building on the same content-addressing primitives.
- **NDN Streaming** — live video/audio streams served as sequential named segments, fetched by receivers using `ndn-peek --pipeline`.
- **Distributed content store** — optionally push hosted files into the router's CS for network-wide caching.
