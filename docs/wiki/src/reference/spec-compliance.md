# NDN Specification Compliance

> **Status: under review.** This page previously made broad compliance
> claims that did not survive an evidence-based audit against the NDN
> specifications. The full audit is at
> [`docs/notes/spec-compliance-audit-2026-04-20.md`](https://github.com/Quarmire/ndn-rs/blob/main/docs/notes/spec-compliance-audit-2026-04-20.md)
> (970+ findings across nine phases). The summary below is derived from
> that audit and will be updated only against hard evidence —
> packet-level interop with NFD, ndn-cxx, NDNts, ndnd, or python-ndn —
> produced by the harness under `testing/interop/`.
>
> Until those interop tests exist and pass, **do not** rely on wire
> compatibility claims from this library against any other NDN
> implementation.

## Reference specifications

> NDN is not CCNx. NDN Architecture and RFC 8609 define CCNx 1.0 semantics
> and packet encoding respectively and are **not** applicable to NDN.

| Document | Scope |
|----------|-------|
| [NDN Packet Format v0.3](https://docs.named-data.net/NDN-packet-spec/current/) | Canonical TLV encoding, packet types, name components |
| [NFD Developer Guide (NDN-0021)](https://named-data.net/publications/techreports/ndn-0021-11-nfd-guide/) | The de-facto reference for NFD's forwarding pipeline, strategy API, and management protocol |
| [NDNLPv2](https://redmine.named-data.net/projects/nfd/wiki/NDNLPv2) | Link-layer protocol: fragmentation, reliability, per-hop headers |
| [NDN Certificate Format v2](https://docs.named-data.net/ndn-cxx/current/specs/certificate.html) | Certificate TLV layout, naming conventions, validity period |
| [NDNCERT Protocol 0.3](https://github.com/named-data/ndncert/wiki/NDNCERT-Protocol-0.3) | Automated certificate issuance over NDN |

## Verified compliant

Code paths whose behaviour was traced to a specific spec clause during
the audit and matched it. "Verified" here means the code matches the
spec text; it does **not** mean an end-to-end interop run passed.

- **TLV codec** (`ndn-tlv`): VAR-NUMBER 1/3/5/9-byte encoding with
  minimality enforcement, critical-bit rule (types 0–31
  grandfathered-critical, LSB for ≥32), zero-copy `Bytes` slicing.
- **Packet TLV-TYPE registry** for Interest (0x05), Data (0x06),
  Name (0x07), GenericNameComponent (0x08), and all standard Name
  component types (0x01, 0x02, 0x20, 0x32, 0x34, 0x36, 0x38, 0x3a).
- **Interest v0.3 field TLV-TYPEs**: CanBePrefix (0x21),
  MustBeFresh (0x12), ForwardingHint (0x1e), Nonce (0x0a),
  InterestLifetime (0x0c), HopLimit (0x22), ApplicationParameters
  (0x24), InterestSignatureInfo (0x2c), InterestSignatureValue
  (0x2e), SignatureNonce (0x26), SignatureTime (0x28),
  SignatureSeqNum (0x2a).
- **Data field TLV-TYPEs**: MetaInfo (0x14), Content (0x15),
  SignatureInfo (0x16), SignatureValue (0x17), ContentType (0x18),
  FreshnessPeriod (0x19), FinalBlockId (0x1a), SignatureType (0x1b),
  KeyLocator (0x1c), KeyDigest (0x1d).
- **NDNLPv2 header TLV-TYPEs**: LpPacket (0x64), Fragment (0x50),
  Sequence (0x51), FragIndex (0x52), FragCount (0x53),
  PitToken (0x62), Nack (0x0320), NackReason (0x0321),
  IncomingFaceId (0x032c), NextHopFaceId (0x0330),
  CachePolicy (0x0334), CachePolicyType (0x0335),
  CongestionMark (0x0340), Ack (0x0344), TxSequence (0x0348),
  NonDiscovery (0x034c), PrefixAnnouncement (0x0350).
- **Data signed-region boundary**: from start of Name through end
  of SignatureInfo — matches spec.
- **Implicit SHA-256 digest** computed over full Data wire encoding.
- **PIT loop detection** via per-entry nonce set.
- **CS MustBeFresh semantics**: stale entries don't satisfy
  MustBeFresh Interests (LRU and Fjall backends both check).
- **CS admission rejects FreshnessPeriod = 0** Data.
- **`/localhost` scope enforcement** on ingress and egress.
- **Ethernet face**: EtherType `0x8624`, multicast MAC
  `01:00:5e:00:17:aa`.
- **UDP face**: NDN port 6363 (but see "unverified" on multicast
  port).
- **Unix socket face**: default path `/run/nfd/nfd.sock`.
- **WebSocket face**: one LpPacket per binary frame; `wss://`
  listener supported via rustls.
- **BLE face**: NDNLPv2 fragmentation, no private framing header;
  GATT UUIDs match NDNts `@ndn/web-bluetooth-transport` and
  esp8266ndn `BleServerTransport`.
- **SafeBag**: outer TLV `0x80`, EncryptedKey TLV `0x81`, PKCS#8
  EncryptedPrivateKeyInfo via rustcrypto `pkcs8` with PBES2 /
  PBKDF2-HMAC-SHA256 / AES-256-CBC — matches ndn-cxx on-wire.
- **SVS TLV registry**: StateVector (0xc9), StateVectorEntry
  (0xca), SeqNo (0xcc), MappingData (0xcd), MappingEntry (0xce) —
  match ndn-svs `tlv.hpp`.
- **NFD management TLV-TYPEs**: ControlParameters (0x68),
  ControlResponse (0x65), StatusCode (0x66), StatusText (0x67),
  and all sub-fields (FaceId 0x69 through Mtu 0x89). Dataset field
  codes (FaceStatus 0x80 through NOutNacks 0x98).
- **NDNCERT 0.3 message TLV-TYPEs**: all 24 codes from ca-prefix
  (0x81) through auth-tag (0xaf) match the community wiki.
- **`Name` / `NameComponent` canonical `Ord`**: TLV-TYPE ascending,
  then length ascending, then lexicographic — matches NDN Packet
  Format §2.1.

## Known non-compliant

Each entry below cites the audit section and severity. See the
audit doc for file-line citations and recommended remediation.

### BLOCKER — will be rejected or mis-decoded by any conforming NDN peer

- **`BLAKE3_DIGEST` name component uses TLV-TYPE 0x03**, which is
  unassigned and in the grandfathered-critical 0–31 range. Any
  `Name` containing this component is rejected by conforming
  decoders. Takes the `ZoneKey` zone-root naming and `did:ndn:v1:…`
  DID integration with it. (*Audit A.01.*)
- ~~Signed Interest signing computes the signature over a
  placeholder `ParametersSha256DigestComponent`~~ **RESOLVED
  2026-05-01.** `InterestBuilder::sign_sync` / `sign` now emit
  the spec two-range signed region (Name-without-PSDC ‖
  AppParameters ‖ InterestSignatureInfo) and compute the PSDC
  value per spec after the signer returns. `Interest::signed_region`
  on the receive side reconstructs the same two ranges. A new
  regression witness in `ndn-packet`
  (`interest_builder_sign_sync_signed_region_matches_extractor`)
  asserts that the bytes passed to `sign_fn` equal the bytes an
  extractor reconstructs from the wire. (*Audit A.09.*)
- **Link-layer reliability emits `Sequence` (0x51, fragmentation)
  where NDNLPv2 requires `TxSequence` (0x0348, reliability).**
  Cross-implementation reliability is broken in both directions.
  (*Audit B.01.*)
- **`Validator` hard-wires `Ed25519Verifier` as a concrete
  field** instead of dispatching on `SignatureType`. RSA and ECDSA
  packets — every NDN testbed packet — return `Invalid`. No
  `DigestSha256` or `HmacSha256` verifier exists at all.
  (*Audit C.01, C.02, C.03, C.05.*)
- **HopLimit is dropped-if-zero on ingress but never decremented
  on forward.** Packets keep their original HopLimit through the
  ndn-rs segment; combined with nonce-collision false positives
  (D.08) this removes the redundancy NDN relies on for loop
  bounding. (*Audit D.01.*)
- **Management command Interests accepted without signature
  verification.** Any local process with access to the management
  socket has full forwarder control. (*Audit E.01.*)
- **PSync IBF uses ndn-rs-authored hash mixing**, not the
  reference C++ PSync hash. Diffs between ndn-rs and C++ PSync
  peers produce no common sets. (*Audit G.03.*)

### MAJOR — deviations a reference implementation would reject or
### misinterpret in a non-edge case

- **`DataBuilder::build()` emits Data labelled `DigestSha256` with
  a 32-byte all-zeros signature** — self-integrity-failing. Used
  by benchmarks and any caller who doesn't sign. Sibling
  `DataBuilder::sign_none` is honestly non-conformant by
  omitting signature fields; `build()` is the dishonest one.
  (*A.10.*)
- **Unknown critical TLVs are silently skipped inside packet
  bodies.** `Interest::decode`, `Data::decode`, `MetaInfo::decode`,
  and `SignatureInfo::decode` all iterate with `_ => {}` rather
  than honouring the critical-bit rule at body level. (*A.03.*)
- **`Nack::decode` accepts an invented "bare Nack TLV (0x0320)"
  form** that NDN does not define. Test helper `build_nack` emits
  this non-standard form. (*A.12.*)
- **KeyLocator required/forbidden rules per `SignatureType` are
  unenforced.** `DigestSha256` packets may carry KeyLocator;
  `Ed25519` packets may omit it. (*A.15.*)
- **BLAKE3 SignatureType codes 6 and 7** live in the
  `signature.html`-reserved range (`Values 2, 6-200 are
  reserved`). Any future registry assignment collides with
  ndn-rs's private use. (*A.17.*)
- **`HmacSha256Signer` exists but no `HmacSha256Verifier`**;
  HMAC-signed packets round-trip through the validator as
  `Invalid`. (*C.02.*)
- **`KeyChain::sign_data` / `sign_interest` hard-code
  `SignatureType::SignatureEd25519`** regardless of the
  underlying signer's actual algorithm — so non-Ed25519 packets
  are mislabelled on the wire. (*C.06.*)
- **Certificate naming and Content format do not match NDN
  Certificate Format v2.** ndn-rs emits `/<Identity>/KEY/v=0`
  (two components, version as a generic string literal); the
  spec requires `/<Identity>/KEY/<KeyId>/<IssuerId>/<Version>`
  with `<Version>` encoded as `VersionNameComponent` (0x36).
  Content is the raw Ed25519 public key, not DER-wrapped
  `SubjectPublicKeyInfo`. Identities built by ndn-rs cannot be
  used by ndn-cxx's `ndnsec`. (*C.07, C.08.*)
- **No path validates signed Interests.** `ValidationStage`
  handles Data only; `mgmt_ndn.rs` dispatches on command
  Interests without touching signature fields. (*C.11,
  also the root of E.01.*)
- **NDNCERT 0.3 CHALLENGE parameters still carry JSON** inside
  ApplicationParameters, despite the earlier claim that all four
  routes had moved to TLV. The reference ndncert-client emits
  TLV-encoded parameters; ndn-rs's CA cannot decode those.
  (*C.13.*)
- **NDNCERT `ErrorCode` enum diverges from the spec values.** A
  reference CA returning error-code 5 (RunOutOfTries) is decoded
  by ndn-rs as `NameNotAllowed`. (*C.14 — pending numeric
  confirmation against the NDNCERT wiki.*)
- **LightVerSec user functions (`$eq`, `$regex`, …) parse but
  do not dispatch.** Imported LVS schemas that rely on them are
  fail-unsafe by default — the schema is applied but those
  constraints silently never match. (*C.16.*)
- **`/localhop` scope is not enforced anywhere.** Only
  `/localhost`. `/localhop` Interests received on a non-local
  face are forwarded further, violating the one-hop contract.
  (*D.02.*)
- **`NextHopFaceId` LP header is decoded and stored in the tag
  set but never consulted by the strategy stage.** Management
  tools that use it to pin commands to specific faces are
  ignored. (*D.03.*)
- **PIT is keyed on `(name-hash, selectors, forwarding-hint)`,
  not on name alone.** Data match then enumerates 5+ selector
  combinations per prefix length. Two consumers issuing the
  same Name with different selectors produce two PIT entries
  (NFD merges them). MustBeFresh is not re-checked at match
  time. (*D.04.*)
- **PIT in-records store the NDNLPv2 PitToken but the
  outbound Data/Nack path does not echo it.** NDN-DPDK-style
  multiplexing consumers cannot use ndn-rs as an upstream.
  (*D.07.*)
- **`BestRouteStrategy` does not retry on Nack.** A single
  nexthop Nack immediately propagates; the second-best nexthop
  is never tried. (*D.09.*)
- **CS admits Data without verifying its signature** when the
  engine is built without a `Validator`. Default factory does
  not install one. (*D.12.*)
- **`ValidationStage` skips all `/localhost/...` Data as
  "unsigned management data"** — but NFD signs management
  responses (minimum DigestSha256). ndn-rs trusts any bytes
  under that prefix. (*D.13.*)
- **FaceUri scheme emits `udp4://` regardless of IP family.**
  An IPv6 peer is reported as `udp4://[...]:port`, which NFD
  rejects. (*F.01.*)
- **FaceUri does not distinguish `wsclient` / `wsserver`, nor
  `tcp4` / `tcp6`.** FaceMgmt-level interop with `nfdc` parse
  fails. (*F.03, F.06.*)
- **Status datasets are not segmented per NFD convention**
  (no `FinalBlockId`, no `/seg=N` name suffix). Any dataset
  exceeding one Data packet truncates; `nfdc` cannot reassemble.
  (*E.04.*)
- **Management notification streams
  (`/localhost/nfd/<module>/notifications`) are absent.**
  Observers must poll status datasets. (*E.05.*)
- **NLSR is not implemented.** Cannot participate in the NDN
  testbed's routing mesh. (*G.04.*)
- **Neighbor discovery is a SWIM protocol over NDN.** The Hello
  protocol and gossip modules are valid engineering but are
  not NDN-standard autoconfig or self-learning. Presenting
  them as "NDN-native" misrepresents the ecosystem standard.
  (*G.06.*)
- **SVS peer identity uses stringified Name as HashMap key.**
  If peers serialise typed name components with a different
  URI rendering, keys won't match across implementations.
  (*G.02.*)

### MINOR — strictness gaps, documentation drift, edge cases

See the audit document for 30+ additional findings including
TLV field ordering not enforced on decode (A.04), Nonce length
mismatch silently dropped (A.13), `MetaInfo::ContentType` missing
`Manifest (4)` and `PrefixAnn (5)` variants (A.14), reassembly
buffer unbounded (B.10), strategy names missing `%FD%01` version
component (D.10), `ndn-ping`/`ndn-iperf` using proprietary prefixes
(H.02, H.03), and further items across all phases.

### DOCS — claims this page previously made that the code contradicts

- This page previously claimed "no `Ord` impl on `Name` or
  `NameComponent`." The code has correct `Ord` impls. (*A.06.*)
- This page previously claimed "zero-component Names are
  rejected at decode time." `Name::decode` accepts them (which
  is actually correct per spec — root name is valid); only
  outer Interest/Data reject empty Names. (*A.07.*)
- This page previously claimed "NDNCERT 0.3 — JSON protocol
  types removed from CA handler." The JSON types are still
  exported and in use for CHALLENGE parameters. (*C.13.*)
- This page previously claimed "HopLimit — decremented before
  forwarding." It is not. (*D.01.*)
- This page previously claimed "BLE face … oversized packets
  are fragmented via NDNLPv2 at the Face layer … matching
  NDNts and esp8266ndn exactly." This part is accurate — the
  BLE face is actually compliant with the NDNts/esp8266ndn
  contract; the earlier complaint in issue #10 appears
  resolved. (*B.11, F.09.*)
- This page previously claimed "34 of 41 tracked compliance
  items resolved." Pending the audit's re-scoring, that number
  is withdrawn. It will not be replaced until interop
  evidence is in place.

## Not yet verified by end-to-end interop

Items where the code matches the spec on paper but no packet
exchange against a reference implementation has been run:

- Interest/Data/Nack round-trips with NFD, ndn-cxx, NDNts,
  ndnd, python-ndn.
- NDNLPv2 fragmentation and reassembly over UDP/Ethernet with
  NFD.
- NFD management ControlCommand / StatusDataset exchange.
- BLE GATT interop with Web Bluetooth (Android/iOS) and
  esp8266ndn on ESP32.
- Multicast UDP group membership with NFD (noting the
  port-6363-vs-56363 question in F.02).
- SVS state-vector exchange with ndn-svs.
- NDNCERT 0.3 enrollment against ndncert-ca-server.

The harness that will produce this evidence lives under
[`testing/interop/`](../../../../testing/interop/) and is
explicitly called out as scaffolding pending real runs — any
claim added to this page after this point must cite a specific
test from that directory.

## How to report a spec compliance issue

File it against
[github.com/Quarmire/ndn-rs/issues](https://github.com/Quarmire/ndn-rs/issues)
with:

- The NDN spec clause you believe is violated (link + section).
- A minimal wire capture or source reference showing ndn-rs's
  behaviour.
- Your expected behaviour.

Related open issues: [#3](https://github.com/Quarmire/ndn-rs/issues/3),
[#7](https://github.com/Quarmire/ndn-rs/issues/7),
[#9](https://github.com/Quarmire/ndn-rs/issues/9),
[#12](https://github.com/Quarmire/ndn-rs/issues/12),
[#13](https://github.com/Quarmire/ndn-rs/issues/13),
[#17](https://github.com/Quarmire/ndn-rs/issues/17),
[#18](https://github.com/Quarmire/ndn-rs/issues/18),
[#20](https://github.com/Quarmire/ndn-rs/issues/20),
[#21](https://github.com/Quarmire/ndn-rs/issues/21).
