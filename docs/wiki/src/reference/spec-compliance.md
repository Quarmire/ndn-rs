# NDN Specification Compliance

ndn-rs is wire-compatible with NFD and other NDN forwarders for the core Interest/Data exchange, NDNLPv2 framing, and basic certificate validation. Five items from the original compliance audit remain open — none affect wire-level interoperability with NFD on the plain forwarding path — and two forwarding-behavior features used by the wider ecosystem (forwarding hints and PIT tokens) are not yet active in the pipeline and are tracked separately in ["Not Yet Implemented"](#not-yet-implemented) below.

## Reference Specifications

> **Note:** NDN is not CCNx. NDN Architecture and RFC 8609 define CCNx 1.0 semantics and
> packet encoding respectively and are **not** applicable to NDN. The NDN protocol
> is defined by the documents below.

| Document | Scope |
|----------|-------|
| [NDN Packet Format v0.3](https://docs.named-data.net/NDN-packet-spec/current/) | Canonical TLV encoding, packet types, name components |
| [NDN Architecture (NDN-0001)](https://named-data.net/publications/techreports/tr001ndn-proj/) | Project architecture vision and research roadmap — motivates the design but does **not** specify forwarding behavior |
| [NFD Developer Guide (NDN-0021)](https://named-data.net/publications/techreports/ndn-0021-11-nfd-guide/) | The de-facto reference for NFD's forwarding pipeline, strategy API, and management protocol |
| [NDNLPv2](https://redmine.named-data.net/projects/nfd/wiki/NDNLPv2) | Link-layer protocol: fragmentation, reliability, per-hop headers |
| [NDN Certificate Format v2](https://docs.named-data.net/NDN-packet-spec/current/certificate.html) | Certificate TLV layout, naming conventions, validity period |
| [NDNCERT Protocol 0.3](https://github.com/named-data/ndncert/wiki/NDNCERT-Protocol-0.3) | Automated certificate issuance over NDN |

> **Note on forwarding specification.** There is no single comprehensive document defining NDN forwarding behavior. NDN-0001 is the architecture vision. NDN-0021 (the NFD Developer Guide) describes one implementation's behavior, which the community treats as the de-facto reference. Recent forwarding developments — in particular **forwarding hints** (partially described in NFD redmine issues [#3000](https://redmine.named-data.net/issues/3000) and [#3333](https://redmine.named-data.net/issues/3333)) and **PIT tokens** (pioneered by NDN-DPDK) — are not yet folded into any single spec document. ndn-rs tracks these as open work, not as completed compliance items; see "Not Yet Implemented" below.

## What's Implemented

### TLV Wire Format (NDN Packet Format v0.3)

The TLV codec handles all four VarNumber encoding widths and enforces shortest-encoding on read — a `NonMinimalVarNumber` error is returned for non-minimal forms. TLV types 0–31 are grandfathered as always critical regardless of LSB, per NDN Packet Format v0.3 §1.3. `TlvWriter::write_nested` uses minimal length encoding. Zero-component Names are rejected at decode time.

### Packet Types

**Interest** — full encode/decode: Name, Nonce, InterestLifetime, CanBePrefix, MustBeFresh, HopLimit, ForwardingHint, ApplicationParameters with `ParametersSha256DigestComponent` verification, and InterestSignatureInfo/InterestSignatureValue for signed Interests with anti-replay fields (`SignatureNonce`, `SignatureTime`, `SignatureSeqNum`).

**Data** — full encode/decode: Name, Content, MetaInfo (ContentType including LINK, KEY, NACK, PREFIX_ANN), FreshnessPeriod, FinalBlockId, SignatureInfo, SignatureValue. `Data::implicit_digest()` computes SHA-256 of the wire encoding for exact-Data retrieval via ImplicitSha256DigestComponent.

**Nack** — encode/decode with NackReason (NoRoute, Duplicate, Congestion).

**Typed name components** — `KeywordNameComponent` (0x20), `SegmentNameComponent` (0x32), `ByteOffsetNameComponent` (0x34), `VersionNameComponent` (0x36), `TimestampNameComponent` (0x38), `SequenceNumNameComponent` (0x3A) — all with typed constructors, accessors, and `Display`/`FromStr`.

### NDNLPv2 Link Protocol

All network faces use NDNLPv2 LpPacket framing (type 0x64). Fully implemented:

- **LpPacket encode/decode** — Nack header, Fragment, Sequence (0x51), FragIndex (0x52), FragCount (0x53)
- **Fragmentation and reassembly** — `fragment_packet` splits oversized packets; `ReassemblyBuffer` collects fragments and reassembles on receive
- **Reliability** — TxSequence (0x0348), Ack (0x0344); per-hop adaptive RTO on unicast UDP faces (NDNLPv2 §6)
- **Per-hop headers** — PitToken (0x62), CongestionMark, IncomingFaceId (0x032C), NextHopFaceId (0x0330), CachePolicy/NoCache (0x0334/0x0335), NonDiscovery (0x034C), PrefixAnnouncement (0x0350)
- **`encode_lp_with_headers()`** — encodes all optional LP headers in correct TLV-TYPE order
- **Nack framing** — correctly wrapped as LpPacket with Nack header and Fragment, not standalone TLV

### Forwarding Semantics (NDN Architecture)

- **HopLimit** — decoded (TLV 0x22); Interests with HopLimit=0 are dropped; decremented before forwarding
- **Nonce** — `ensure_nonce()` adds a random Nonce to any Interest that lacks one before forwarding
- **FIB** — name trie with longest-prefix match, multi-nexthop entries with costs
- **PIT** — DashMap-based, Interest aggregation, nonce-based loop detection, ForwardingHint included in PIT key per NDN Architecture §4.2, expiry via hierarchical timing wheel
- **Content Store** — pluggable backends (LRU, sharded, persistent); MustBeFresh/CanBePrefix semantics; CS admission policy rejects FreshnessPeriod=0 Data; NoCache LP header respected; implicit digest lookup
- **Strategy** — BestRoute and Multicast with per-prefix StrategyTable dispatch; MeasurementsTable tracking EWMA RTT and satisfaction rate per face/prefix
- **Scope enforcement** — `/localhost` prefix restricted to local faces inbound and outbound

### Security

- **Ed25519** — type code 5 per spec; sign and verify end-to-end
- **HMAC-SHA256** — symmetric signing for high-throughput use cases
- **BLAKE3** — two **distinct** experimental type codes pending reservation on the [NDN TLV SignatureType registry](https://redmine.named-data.net/projects/ndn-tlv/wiki/SignatureType):
  - **Plain BLAKE3 digest** (type 6) — `Blake3Signer` / `Blake3DigestVerifier`; analogous to `DigestSha256` (type 0). Provides integrity and self-certifying naming but **no authentication** — anyone can produce a valid signature.
  - **Keyed BLAKE3** (type 7) — `Blake3KeyedSigner` / `Blake3KeyedVerifier`; analogous to `SignatureHmacWithSha256` (type 4). Requires a 32-byte shared secret; provides both integrity and authentication.
  - Rationale for distinct codes: sharing one code between plain and keyed modes enables a downgrade substitution attack where an attacker strips the keyed signature and replaces it with a plain BLAKE3 digest over their forged content — on the wire both look identical, and a verifier dispatching on type code alone would accept the forgery. Using two codes mirrors the existing NDN pattern (`DigestSha256` vs. `HmacWithSha256`).
  - BLAKE3 is 3–8× faster than SHA-256 on modern SIMD CPUs.
- **Signed Interests** — InterestSignatureInfo/InterestSignatureValue with anti-replay fields
- **Trust chain validation** — `Validator::validate_chain()` walks Data → cert → trust anchor; cycle detection; configurable depth limit; `CertFetcher` deduplicates concurrent cert requests
- **Trust schema** — native `SchemaRule` rules in a `data_pattern => key_pattern` text grammar, plus import of **LightVerSec (LVS)** binary trust schemas via `TrustSchema::from_lvs_binary` — interoperable with the compiled output of python-ndn, NDNts `@ndn/lvs`, and ndnd `std/security/trust_schema`. Supports `ValueEdge` literal matches, `PatternEdge` captures, and `SignConstraint` graph walks; user functions (`$eq`, `$regex`, …) parse cleanly but do not dispatch in v0.1.0 and are flagged via `LvsModel::uses_user_functions()`. Version `0x00011000` of the binary format is accepted
- **Certificate TLV format** — `Certificate::decode()` parses ValidityPeriod (0xFD) with NotBefore/NotAfter; certificate time validity enforced; `AdditionalDescription` TLV constants defined
- **ValidationStage** — sits in Data pipeline between PitMatch and CsInsert; drops Data failing chain validation
- **NDNCERT 0.3** — all four routes (INFO/PROBE/NEW/CHALLENGE/REVOKE) now use TLV wire format; JSON protocol types removed from CA handler
- **Self-certifying namespaces** — `ZoneKey` in `ndn-security`: zone root = `BLAKE3_DIGEST(blake3(ed25519_pubkey))`; `Name::zone_root_from_hash()`, `Name::is_zone_root()` in `ndn-packet`
- **DID integration** — `ZoneKey::zone_root_did()` bridges zone names ↔ `did:ndn:v1:…` DIDs; top-level `DidDocument`, `UniversalResolver`, `name_to_did`, `did_to_name` exports added to `ndn_security`

### Transports

- **UDP / TCP / WebSocket** — standard IP transports with NDNLPv2 framing
- **Multicast UDP** — NFD-compatible multicast group (`224.0.23.170:6363`)
- **Ethernet** — raw AF_PACKET frames with Ethertype 0x8624 (Linux); PF_NDRV (macOS); Npcap (Windows)
- **Unix socket** — local IPC
- **Shared memory (SHM)** — zero-copy ring for same-host apps
- **Serial/UART** — COBS framing over tokio-serial
- **Bluetooth LE** — NDNts/esp8266ndn-compatible GATT server (`bluetooth` feature, Linux/BlueZ and macOS/CoreBluetooth); Service UUID `099577e3-0788-412a-8824-395084d97391`, CS `cc5abb89-a541-46d8-a351-2f95a6a81f49` (client→server write), SC `972f9527-0d83-4261-b95d-b1b2fc73bde4` (server→client notify); oversized packets are fragmented via NDNLPv2 at the Face layer — the BLE protocol itself defines no framing, matching NDNts and esp8266ndn exactly; interoperable with Web Bluetooth API and ESP32 devices

### Management

NFD-compatible TLV management protocol over Unix domain socket (`/localhost/nfd/`). Modules: `rib`, `faces`, `fib`, `strategy-choice`, `cs`, `status`.

## Not Yet Implemented

Two forwarding-behavior features used by the wider NDN ecosystem are not yet handled by ndn-rs. Both are tracked in [issue #13](https://github.com/Quarmire/ndn-rs/issues/13) and are slated for v0.2.0.

| Feature | Spec/reference | Status in ndn-rs |
|---------|----------------|------------------|
| **Forwarding hint handling** in the forwarding pipeline | NFD redmine [#3000](https://redmine.named-data.net/issues/3000), [#3333](https://redmine.named-data.net/issues/3333) | `ForwardingHint` is parsed and included in the PIT key, but the pipeline does not perform hint-based FIB lookup or fallback — it treats hints as opaque |
| **PIT tokens** (NDN-DPDK convention) | NDNLPv2 PitToken field (0x62) | PitToken LP header is encoded/decoded on the wire, but is not generated or consumed by the forwarder — upstream producers cannot use it to demultiplex |

## Remaining Compliance Gaps

Five items remain unresolved. None affect wire-level interoperability with NFD.

| Gap | Spec reference | Impact |
|-----|---------------|--------|
| **/localhop scope** — only `/localhost` is enforced; `/localhop` packets (one-hop restriction) are forwarded without checking | NDN Architecture §4.1 | Low — affects multi-hop scenarios involving `/localhop` prefixes |
| **Name canonical ordering** — no `Ord` impl on `Name` or `NameComponent`; cannot use `BTreeMap` or `.sort()` with NDN names | NDN Packet Format v0.3 §2.1 | Low — affects sorted data structures; doesn't affect forwarding |
| **Certificate naming convention** — cert Data packets use arbitrary names instead of `/<Identity>/KEY/<KeyId>/<IssuerId>/<Version>` | NDN Certificate Format v2 §4 | Moderate — certificates not exchangeable with ndn-cxx in the standard way |
| **Certificate content encoding** — public key bytes stored raw rather than DER-wrapped SubjectPublicKeyInfo | NDN Certificate Format v2 §5 | Moderate — same; interoperability with external cert issuers limited |
| **TLV element ordering** — recognized elements accepted in any order; spec requires defined order | NDN Packet Format v0.3 §1.4 | Low — lenient decoding; packets we produce are correctly ordered |

## Summary

```mermaid
%%{init: {'theme': 'default'}}%%
pie title Spec Compliance (41 tracked items)
    "Resolved" : 34
    "Not yet implemented (forwarding features)" : 2
    "Remaining compliance gaps" : 5
```

34 explicitly tracked compliance items are resolved. Two forwarding-behavior features used by the wider ecosystem — forwarding-hint dispatch and PIT-token echo — are partially wired but not yet active end-to-end. Five compliance gaps remain in certificate format details, name ordering, and lenient TLV parsing; none prevent interoperability with NFD on the plain forwarding path.
