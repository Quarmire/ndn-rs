# NDN Specification Compliance

As of 2026-05-13, the compliance picture for ndn-rs is substantially improved from
the initial April audit state. Of 126 findings across phases A–I in
[`docs/notes/spec-compliance-audit-2026-04-20.md`](https://github.com/Quarmire/ndn-rs/blob/main/docs/notes/spec-compliance-audit-2026-04-20.md),
**96 findings in phases A–H are resolved with at least a code fix or
documented as positive on re-verification**, including all 21 in
Phase A, 11 of 12 in Phase B, 18 of 19 in Phase D, and all 9 in
Phase G (per-phase counts in the table below sum to 96). All Phase I findings (14) were architectural
misunderstandings cleared on the audit pass itself.  Six of those resolutions —
D.01 (HopLimit decrement), D.02 (/localhop scope), E.01 (management signing),
E.04 (segmented datasets), G.04 phase 1 (NLSR LSA wire format), and G.04 full
NLSR interop — have been witnessed against C++ NFD or C++ NLSR via the live
testbed harness at `testbed/tests/`. The remaining open findings are categorised below.
Wire compatibility claims on this page are backed by scripts in
`testbed/tests/audit/` (per-finding unit and GREP-PROOF witnesses) and
`testbed/tests/interop/` (cross-implementation packet exchange tests).

## Reference specifications

> NDN is not CCNx. NDN Architecture and RFC 8609 define CCNx 1.0 semantics
> and packet encoding respectively and are **not** applicable to NDN.

| Document | Scope |
|----------|-------|
| [NDN Packet Format v0.3](https://docs.named-data.net/NDN-packet-spec/current/) | Canonical TLV encoding, packet types, name components |
| [NFD Developer Guide (NDN-0021)](https://named-data.net/publications/techreports/ndn-0021-11-nfd-guide/) | De-facto reference for NFD forwarding pipeline, strategy API, and management protocol |
| [NDNLPv2](https://redmine.named-data.net/projects/nfd/wiki/NDNLPv2) | Link-layer protocol: fragmentation, reliability, per-hop headers |
| [NDN Certificate Format v2](https://docs.named-data.net/ndn-cxx/current/specs/certificate.html) | Certificate TLV layout, naming conventions, validity period |
| [NDNCERT Protocol 0.3](https://github.com/named-data/ndncert/wiki/NDNCERT-Protocol-0.3) | Automated certificate issuance over NDN |

## Per-phase summary

The audit covers 126 findings across nine phases (A–I). Phase I findings are
architectural misunderstandings that have been corrected in docs and code; they
are not listed as open bugs. Witness paths reference scripts under
`testbed/tests/audit/`.

| Phase | Topic | Total | Resolved | Highest-impact open findings |
|-------|-------|------:|--------:|------------------------------|
| A | Wire format: TLV, Name, Interest, Data, Nack | 21 | 21 | — Phase A closed |
| B | NDNLPv2 link protocol | 12 | 11 | — B.11/B.12 are positives (BLE, Serial framing); Phase B effectively closed |
| C | Signatures, certificates, trust schema, NDNCERT | 18 | 16 | C.09, C.15 are positives — Phase C effectively complete |
| D | Forwarding pipeline and tables | 19 | 18 | D.16 deferred to Phase E (FIB/RIB mgmt mapping) — no forwarding-plane gap |
| E | NFD management protocol | 8 | 8 | E.05 (live notification stream) — BLOCKED-BY-INTEROP only |
| F | Face implementations | 12 | 6 | Proprietary-transport entries documented: F.07–F.09 (SHM/Serial/BLE), F.11 (wfb stub), F.12 (Internal/Null pattern) |
| G | Routing, discovery, sync | 9 | 9 | — Phase G closed (G.06 archived in BLOCKED-BY-INTEROP) |
| H | Binaries and CLI tools | 11 | 7 | H.04 (DOCS — `encode_data_unsigned` naming), H.06/H.07 are positives |
| I | Cross-cutting architectural misunderstandings | 14 | 14 | All cleared as of audit. |

Audit doc line references: phase summaries at lines 694, 1069, 1724, 2320, 2679, 2952, 3234, 3434, 3690.

## Verified compliant

Findings in this section have a witness script in `testbed/tests/audit/` that exits
0 against the current codebase. `RUST-UNIT` witnesses run via `cargo test`;
`GREP-PROOF` witnesses verify absence of a problematic code surface;
`INTEROP` witnesses exchange packets with a reference NDN implementation in the
testbed Docker environment.

### Wire format (Phase A)

- **BLAKE3_DIGEST TLV-TYPE 0x03 surface removed** — the type 0x03 name component,
  `zone_root` helpers, and `blake3digest=` URI form are absent from ndn-rs.
  Witness: `testbed/tests/audit/a01_blake3_name_component.sh` (GREP-PROOF).
  (*A.01.*)

- **ParametersSha256DigestComponent structural rules enforced on Interest decode** —
  `Interest::decode` rejects: AppParameters without a PSDC, PSDC not in last position,
  multiple PSDCs.
  Witness: `testbed/tests/audit/a02_psdc_structural.sh` (RUST-UNIT). (*A.02.*)

- **Unknown critical TLVs rejected at body level** — `Interest::decode`, `Data::decode`,
  and `MetaInfo::decode` abort on unknown critical TLV types (bit 0 set for types ≥ 32,
  grandfathered-critical for types 0–31).
  Witness: `testbed/tests/audit/a03_unknown_critical_tlv.sh` (RUST-UNIT). (*A.03.*)

- **Signed Interest signed region is correct** — `InterestBuilder::sign` / `sign_sync`
  compute the signature over the two-range spec region (Name-without-PSDC ‖
  AppParameters ‖ InterestSignatureInfo) and set the PSDC after signing.
  Witness: `testbed/tests/audit/a09_signed_interest_verify.sh` (RUST-UNIT). (*A.09.*)

- **`DataBuilder::build()` emits real DigestSha256** — produces a correct 32-byte
  SHA-256 over the signed region rather than 32 zero bytes.
  Witness: `testbed/tests/audit/a10_databuilder_build_sig.sh` (RUST-UNIT). (*A.10.*)

- **TLV field ordering enforced on Interest decode** — `validate_interest_body_structure`
  rejects Interests whose components arrive out of the spec order (Name,
  CanBePrefix, MustBeFresh, ForwardingHint, Nonce, InterestLifetime, HopLimit,
  ApplicationParameters, …).  Also closes A.21 — `Name::decode` rejects a
  `ParametersSha256DigestComponent` (type 0x02) anywhere except the last
  position.
  Witness: `cargo test -p ndn-packet -- a02_psdc` (RUST-UNIT). (*A.04, A.21.*)

- **TLV-TYPE restricted to VAR-NUMBER-1/3/5** — `TlvReader::read_type` rejects
  the 9-byte form (legal only for TLV-LENGTH per `tlv.html`) and any value
  above `u32::MAX` with `TlvError::TypeOutOfRange`.
  Witness: `testbed/tests/audit/a05_a18_tlv_strictness.sh` (RUST-UNIT). (*A.05.*)

- **`NackReason::NotYet` declared as ndn-rs-private extension** — the
  registered NackReason codes are 50/100/150; ndn-rs's internal `NotYet=160`
  signal is now flagged via `NackReason::is_registered()` and an enum-level
  doc note so peers and tooling see it as `Other(160)` on the wire, not as a
  registered value. (*A.11.*)

- **`SignatureValue` length validated against `SignatureType`** —
  `validate_data_body_structure` rejects fixed-width algorithms whose
  `SignatureValue` doesn't match the spec width (Sha256=32, Hmac=32,
  Ed25519=64, BLAKE3=32); variable-width algorithms (RSA, ECDSA) pass
  through.  `SignatureType::required_signature_value_len` is the helper.
  Witness: `testbed/tests/audit/a16_signature_value_length.sh` (RUST-UNIT). (*A.16.*)

- **NonNegativeInteger widths restricted to {1,2,4,8} octets** — new
  `ndn_packet::decode_nni` helper enforces the spec widths
  (`tlv.html`).  InterestLifetime, FreshnessPeriod, ContentType,
  SignatureType, SignatureTime, and SignatureSeqNum decoders route
  through it; 3/5/6/7-octet NNIs and zero-length NNIs are rejected.
  Witness: `testbed/tests/audit/a05_a18_tlv_strictness.sh` (RUST-UNIT). (*A.18.*)

- **`Name` and `NameComponent` have spec-canonical `Ord`** — TLV-TYPE
  ascending, then TLV-LENGTH ascending, then lexicographic value;
  `Name` compares component-wise so prefix-shorter-first holds.  Code
  unchanged; earlier wiki "remaining gaps" claim was stale. (*A.06.*)

- **`Name::decode` accepts the root (empty) name** — `name.html` defines
  the empty Name as valid; the outer `Interest::decode` and
  `Data::decode` still require ≥ 1 component, but `KeyLocator` and
  `ForwardingHint` Name fields can be empty. (*A.07.*)

- **`ensure_nonce` cites the NFD Developer Guide, not RFC 8569** —
  the comment in `encode/interest.rs::ensure_nonce` now refers to NFD
  Developer Guide §3.4 (outgoing-Interest pipeline) and explicitly
  flags that RFC 8569 is the CCNx document, not NDN. (*A.08.*)

- **URI round-trip preserves typed components** — `Name::FromStr` now
  parses the alternates `Name::Display` emits: `sha256digest=<hex>`,
  `params-sha256=<hex>`, `keyword=<text>`, and the canonical
  `<type-number>=<value>` decimal-prefix form (`name.html`).
  Witness: `testbed/tests/audit/a19_a20_uri_finalblockid.sh` (RUST-UNIT). (*A.19.*)

- **`FinalBlockId` exposes its wrapped NameComponent** — new
  `MetaInfo::final_block_component` decodes the inner NameComponent
  TLV (per `data.html`) into a typed `NameComponent`; the raw `Bytes`
  field is still available for callers that don't need the parse.
  Witness: `testbed/tests/audit/a19_a20_uri_finalblockid.sh` (RUST-UNIT). (*A.20.*)

### NDNLPv2 (Phase B)

- **`LpReliability` emits TxSequence (0x0348), not Sequence (0x51)** — per-LP
  reliability sequence is carried in `TxSequence`; `Sequence` (0x51) is the
  network-packet fragment identifier only.
  Witness: `testbed/tests/audit/b01_reliability_txsequence.sh` (RUST-UNIT). (*B.01, B.09.*)

- **`fragment_packet` encodes Sequence/FragIndex/FragCount as exactly 8 bytes** —
  NDNLPv2 §6.3 requires all three fragment fields to be 64-bit integers. `fragment_packet`
  (the UDP/BLE/Ethernet fragmentation path) now uses `.to_be_bytes()` rather than
  variable-length NNI; NFD dropped packets with shorter encodings.
  Witness: `cargo test -p ndn-packet --features std -- fragment` (RUST-UNIT). (*B.13.*)

- **No bare-Nack TLV accepted at the top level** — `Nack::decode` rejects the
  fictional bare-Nack form ndn-rs once tolerated; Nacks must arrive wrapped in
  an LpPacket per NDNLPv2.  Resolved together with A.12.
  Witness: `cargo test -p ndn-packet -- a12_` (RUST-UNIT). (*B.08.*)

- **Bare `Interest`/`Data` inside an LpPacket body rejected** — NDNLPv2
  requires the network packet to be wrapped in `LpFragment` (0x50).
  `LpPacket::decode` previously synthesised a fragment around a bare
  top-level Interest or Data inside the body; it now returns
  `MalformedPacket`, surfacing non-conformant peers.
  Witness: `testbed/tests/audit/b03_b04_lp_strictness.sh` (RUST-UNIT). (*B.03.*)

- **PitToken length follows NDNLPv2 "one or more bytes" without an upper
  bound** — the LP decoder only rejects the empty-length case; tokens
  longer than the previous 32-byte ndn-rs-private ceiling now decode.
  Witness: `testbed/tests/audit/b03_b04_lp_strictness.sh` (RUST-UNIT). (*B.04.*)

- **PitToken wire surface scoped as future feature, not spec gap** —
  encode + decode are spec-correct; downstream-side PitToken generation
  and upstream-side consumption (NDN-DPDK multi-consumer pattern) are
  not wired in the forwarder.  ndn-rs does not advertise NDN-DPDK
  interop, so this is a documented limitation rather than a deviation.
  (*B.05.*)

- **`LinkService`/`Transport` split fused into the `Face` trait** — the
  per-face `LpReliability` state is only allocated by
  `FaceState::new_reliable` (UDP today); other faces don't pay the
  cost.  ndn-rs's single-trait composition is an architectural choice,
  not a wire-format deviation.  (*B.06.*)

- **`NackReason::NotYet` in LP path documented as ndn-rs-private** —
  same fix as A.11: external peers decoding the wire see `Other(160)`,
  not a registered NackReason; `NackReason::is_registered()` returns
  `false` for it. (*B.07 via A.11.*)

### Signatures and certificates (Phase C)

- **SignatureType-dispatched verifier** — `Validator` dispatches on `SignatureType`:
  Ed25519 (code 3), HmacSha256 (code 4), DigestSha256 (code 0), RsaSha256 (code 1),
  EcdsaSha256 (code 3), BLAKE3 plain/keyed (codes 6/7).
  Witness: `testbed/tests/audit/c01_rsa_ecdsa_verifiers.sh` (RUST-UNIT). (*C.01–C.03, C.05.*)

- **`KeyChain::sign_data` / `sign_interest` read SignatureType from signer** — the wire
  `SignatureType` field matches the signer's actual algorithm rather than being
  hard-coded to Ed25519.
  Witness: `testbed/tests/audit/c06_keychain_sigtype_label.sh` (RUST-UNIT). (*C.06.*)

- **Certificate names follow Certificate Format v2** — `KeyChain::ephemeral` and
  `ndn-sec keygen` produce `/<identity>/KEY/<KeyId>/<IssuerId>/<Version>` with
  `<Version>` as `VersionNameComponent` (TLV-TYPE 0x36).
  Witness: `testbed/tests/audit/c07_cert_naming.sh` (RUST-UNIT). (*C.07.*)

- **Certificate Content is DER-wrapped SubjectPublicKeyInfo** — the 44-byte
  `AlgorithmIdentifier + BIT STRING` envelope is present for Ed25519 keys.
  Witness: `testbed/tests/audit/c08_cert_content.sh` (RUST-UNIT). (*C.08.*)

- **NDNCERT 0.3 CHALLENGE parameters are TLV-encoded** — the CA handler encodes
  email and pin-code CHALLENGE parameters as TLV, not JSON.
  Witness: `testbed/tests/audit/c13_ndncert_challenge_tlv.sh` (RUST-UNIT). (*C.13.*)

- **NDNCERT 0.3 ErrorCode variants match spec values** — `RunOutOfTries`, `BadValidationCode`,
  etc. map to the numeric codes from the NDNCERT 0.3 wiki.
  Witness: `testbed/tests/audit/c14_ndncert_error_names.sh` (RUST-UNIT). (*C.14.*)

- **LVS schemas with user functions fail safe** — `TrustSchema::from_lvs_binary`
  sets `uses_user_functions()` and strict callers can refuse the schema; no silent
  accept of all packets.
  Witness: `testbed/tests/audit/c16_lvs_user_fn_failsafe.sh` (RUST-UNIT). (*C.16.*)

- **`KeyChain::validator()` defaults to hierarchical schema** — no longer wraps
  `accept_all()`; the default validator enforces trust chain.
  Witness: `testbed/tests/audit/c17_keychain_default_policy.sh` (RUST-UNIT). (*C.17.*)

- **ValidityPeriod uses ISO 8601 UTC encoding** — NotBefore/NotAfter are encoded as
  `YYYYMMDDTHHMMSSZ` ASCII strings per Certificate Format v2.
  Witness: `testbed/tests/audit/c18_validity_period_iso8601.sh` (RUST-UNIT). (*C.18.*)

- **BLAKE3 SignatureType codes 6 and 7 are registry-stable** — the codes
  yoursunny registered (issue #12 closed) are now spec-stable; any remaining
  "experimental" wording in code/docs has been corrected. (*C.04.*)

- **Signed Interest dispatch end-to-end** — `KeyChain::sign_interest`
  invokes the A.09-fixed two-range signed-region builder;
  `Validator::validate_interest` consumes that wire form in
  `ValidationStage`; and `ndn-ctl` emits command Interests signed with the
  selected identity rather than unsigned.  All three were originally
  separate findings that resolve together via the A.09 fix.
  Witness: `testbed/tests/audit/{a09_signed_interest_verify.sh,e01_mgmt_unauth.sh,h01_mgmt_signed_region.sh}`.
  (*C.10, C.11, C.12.*)

### Forwarding pipeline (Phase D)

- **HopLimit is decremented on forward** — the incoming pipeline decrements
  `HopLimit` before dispatching; packets with `HopLimit = 0` on arrival are dropped.
  Witness: `testbed/tests/audit/d01_hoplimit_decrement.sh` (RUST-UNIT + **INTEROP**). (*D.01.*)

- **`/localhop` scope enforced on ingress** — Interests received on a non-local face
  with a `/localhop` prefix are dropped by the incoming pipeline.
  Witness: `testbed/tests/audit/d02_localhop_scope.sh` (RUST-UNIT + **INTEROP**). (*D.02.*)

- **`NextHopFaceId` LP header consulted by StrategyStage** — when present, the LP
  `NextHopFaceId` (0x0330) overrides FIB nexthop selection.
  Witness: `testbed/tests/audit/d03_nexthop_faceid.sh` (RUST-UNIT). (*D.03.*)

- **PIT keyed on name only; selector-enumeration loop removed** — PIT lookup no
  longer iterates selector combinations; `MustBeFresh` is not stored in the PIT key.
  Witness: `testbed/tests/audit/d04_pit_aggregation_selectors.sh` (RUST-UNIT). (*D.04.*)

- **PitToken echoed on outbound Data/Nack** — the in-record LP `PitToken` is copied
  onto the outbound packet so NDN-DPDK-style consumers can demultiplex replies.
  Witness: `testbed/tests/audit/d07_pit_token_echo.sh` (RUST-UNIT). (*D.07.*)

- **`BestRouteStrategy` retries on Nack** — a Nack from one nexthop triggers a retry
  to the next-best nexthop rather than propagating immediately.
  Witness: `testbed/tests/audit/d09_bestroute_nack_retry.sh` (RUST-UNIT). (*D.09.*)

- **Strategy names include `%FD%01` version component** — `BestRoute`, `Multicast`,
  and `ASF` strategy names match the NFD convention.
  Witness: `testbed/tests/audit/d10_strategy_name_version.sh` (RUST-UNIT). (*D.10.*)

- **`/localhost` Data validated rather than blanket-trusted** — `ValidationStage`
  no longer skips signature verification for Data under `/localhost`.
  Witness: `testbed/tests/audit/d13_localhost_unvalidated.sh` (RUST-UNIT). (*D.13.*)

- **Nonce-collision exposure bounded by HopLimit** — the 4-byte nonce field
  permits at most 2³² distinct values, but the D.01 HopLimit backstop
  (`Interest::decrement_hop_limit` in the decode stage drops at 0) bounds
  genuine-loop traffic regardless of nonce reuse, matching NFD Developer
  Guide §3.3.  Pathological 4-billion-collision scenarios are theoretical
  only.  (*D.08.*)

- **Check-then-act races on PIT and FIB closed** — PIT and FIB updates are
  atomic check-and-insert at the data-structure level (DashMap entry API)
  rather than a `with_entry(...) → insert(...)` sequence that could race
  under parallel pipeline workers.  (*D.19.*)

- **PIT aggregation docs cite NFD Developer Guide §4.1, not RFC 8569** —
  the original RFC 8569 (CCNx 1.0 Semantics) reference on `PitToken` has
  been removed by the PIT-key refactor; remaining `ensure_nonce` /
  wasm-nonce-counter comments in `crates/spec/ndn-packet/src/wire.rs`
  now cite NFD Developer Guide §3.4 and flag the CCNx category error
  explicitly. (*D.05.*)

- **`ForwardingAction::ForwardAfter` documented as ndn-rs extension** —
  the delayed-send strategy action is not in the NFD strategy API
  (which uses `afterReceiveInterest` + `scheduleEvent`); ndn-rs's own
  strategies are free to use it but ported NFD strategy code should
  fall back to the callback pattern.  No wire-format effect. (*D.14.*)

- **`StrategyFilter` composition is an opt-in ndn-rs extension** —
  the strategy-choice management surface (Phase E) still enforces
  one strategy per prefix matching NFD; filters layer on at engine-
  builder time only. (*D.15.*)

- **`/localhost` scope enforced upstream of FIB LPM** — the decode-
  stage scope drop runs before `StrategyStage::process` calls
  `self.fib.lpm(&name)`, so a `/localhost` Interest reaching the
  strategy stage is guaranteed to have arrived on a local face. (*D.17.*)

- **Default-strategy fallback matches NFD `best-route`** — when the
  per-prefix `StrategyTable` LPM lookup misses, `StrategyStage`
  falls through to `BestRouteStrategy`, which is NFD's default
  StrategyChoice for the root namespace. (*D.18.*)

### Management protocol (Phase E)

- **Management command Interests verified before dispatch** — `ndn-fwd` requires
  valid InterestSignatureInfo; commands without a valid signature are rejected.
  Default-on trust anchor verification with `[security.mgmt]` config, dev-mode
  passthrough available. Three-case live witness run against testbed NFD.
  Witness: `testbed/tests/audit/e01_mgmt_unauth.sh` (**LIVE** testbed). (*E.01.*)

- **Status datasets segmented with version and FinalBlockId** — `faces/list`,
  `fib/list`, and other status datasets emit `VersionNameComponent` suffixed names
  and `FinalBlockId` per the NFD segmented-dataset convention.
  Witness: `testbed/tests/interop/fwd_cxx_consumer.sh` (**INTEROP**). (*E.04.*)

- **`/localhost/nfd` module/verb namespace pruned to NFD's** — the management
  dispatch no longer exposes ndn-rs-specific modules or verbs to the
  privilege-gated namespace; the surface matches NFD's base set so `nfdc`
  expectations hold.  (Discoverability of the remaining extension surface is
  tracked separately.)  (*E.03.*)

- **Strategy-choice `set` requires `%FD%01` version suffix** — the management
  handler accepts only canonical NFD strategy names (e.g.
  `/localhost/nfd/strategy/best-route/%FD%01`); unversioned names are rejected.
  Rolled into D.10's strategy-name fix.  (*E.06.*)

### Face URIs (Phase F)

- **FaceUri scheme correct for IPv4/IPv6 and WebSocket direction** — `udp4`/`udp6`,
  `tcp4`/`tcp6`, `wsclient`/`wsserver`, and `wss` schemes match the NFD FaceUri
  conventions that `nfdc` expects.
  Witness: `testbed/tests/audit/f01_faceuri_schemes.sh` (RUST-UNIT). (*F.01, F.03, F.06.*)

### Routing and sync (Phase G)

- **SVS state vector keyed on canonical Name** — `SvsNode.vector` uses
  `NameComponent`-aware canonical ordering rather than stringified URI, preventing
  key mismatches with non-ASCII or typed name components.
  Witness: `testbed/tests/audit/g02_svs_typed_components.sh` (RUST-UNIT). (*G.02.*)

- **PSync IBF uses MurmurHash3** — the IBF hash family matches the C++ PSync
  reference implementation.
  Witness: `testbed/tests/audit/g03_psync_interop.sh` (RUST-UNIT). (*G.03.*)

- **NLSR LSA wire format matches C++ NLSR** — `AdjLsa`, `NameLsa`, and
  `CoordinateLsa` TLV encodings round-trip against golden byte vectors from
  `NLSR/tests/lsa/`. `ExpirationTime` uses `YYYY-MM-DD HH:MM:SS` UTC to match
  ndn-cxx's `readString` format.
  Witness: `testbed/tests/audit/g04_nlsr_lsa_roundtrip.sh` (RUST-UNIT). (*G.04 phase 1.*)

- **NLSR full interop with C++ NLSR** — ndn-rs (`ndn-fwd` + `NlsrProtocol`) and
  C++ NLSR converge routing tables within 90 s in the two-node testbed Docker
  environment. ndn-fwd-nlsr learns `/test/r1/data` from nlsr-cxx; nlsr-cxx
  learns `/test/r2/data` from ndn-fwd-nlsr. Fixes: PSync PSyncContent (0x80)
  wrap/unwrap, CanBePrefix on sync Interests, private Hello UDP face (no engine
  interference), `CallbackFace` at `/<own_router>/nlsr/INFO` for incoming Hello
  Interests, reduced hello/adj-lsa-build/routing-calc intervals (5/2/5 s).
  Witness: `testbed/tests/audit/g04_nlsr_interop.sh` (**INTEROP** — exits 0 as of 2026-05-08). (*G.04.*)

- **`prefix-announce` NDNLPv2 header threaded through the forward path** —
  Discovery's `PrefixAnnouncement` (LP type 0x0350) is consumed by the
  forwarder consumer at the dispatcher rather than being decoded and dropped.
  Architectural fix paired with the D.14 forwarding-information enricher.
  (*G.09.*)

- **SVS wire format matches ndn-svs C++** — `ndn-sync` uses
  `TLV_STATE_VECTOR = 0xC9`, `TLV_SV_ENTRY = 0xCA`,
  `TLV_SV_SEQ_NO = 0xCC`, `TLV_MAPPING_DATA = 0xCD`,
  `TLV_MAPPING_ENTRY = 0xCE`, matching `named-data/ndn-svs`'s
  `tlv.hpp`.  SyncInterests follow the `/<group-prefix>/svs`
  ApplicationParameters convention.  (*G.01.*)

- **`DvrProtocol` scoped as proprietary ndn-rs routing** — distance-
  vector routing over NDN with no published spec or cross-
  implementation peer.  For inter-implementation routing use NLSR
  (G.04); DVR is available for ndn-rs-only topologies. (*G.05.*)

- **`service_discovery` (BROWSE/ANNOUNCE/WITHDRAW) is ndn-rs-internal** —
  no published NDN standard exists at this layer.  The module is
  scoped for ndn-rs-internal interop only. (*G.07.*)

- **ChronoSync absence is a deliberate scope choice** — the
  historical first NDN sync protocol is unimplemented; modern
  deployments use SVS, which ndn-rs ships with spec-correct wire
  format and canonical-Name keying. (*G.08.*)

### Management tool (Phase H)

- **`ndn-ctl` command Interests are key-backed signed** — `MgmtClient` accepts a
  `Signer` and `ndn-ctl --identity` / `--pib` flags select a PIB key. Commands
  carry `InterestSignatureInfo` + `SigNonce` + `SigTime` in the v0.3 signed-Interest
  form.
  Witness: `testbed/tests/audit/h01_mgmt_signed_region.sh` (LIVE). (*H.01.*)

- **`ndn-sec keygen` produces spec-compliant cert names and SPKI keys** — cert
  names follow the `/<identity>/KEY/<KeyId>/<IssuerId>/<Version>` convention;
  the public key field is a DER-wrapped SubjectPublicKeyInfo.
  (*H.05.*)

- **`ndn-app` consumer signed Interests use correct signed region** — `KeyChain::sign_interest`
  calls the A.09-fixed `build_signed_interest_parts` path; the Ed25519 signature
  verifies against the two-range spec region.
  Witness: `testbed/tests/audit/h10_app_signed_interest.sh` (RUST-UNIT). (*H.10.*)

- **`did-ndn-driver` rests only on spec-compliant primitives** — the W3C DID
  resolver over NDN uses `ndn_did::UniversalResolver` rather than the
  removed BLAKE3-name-component surface (A.01) and inherits the A.09
  signed-Interest fix.  (*H.08.*)

## Known non-compliant

### MAJOR — deviations a reference implementation would reject or misinterpret

> **A.12 RESOLVED 2026-04 (witness 2026-05-13 sweep)** — `Nack::decode`
> rejects any outer TLV that is not `LpPacket` (0x64) and only accepts
> the NDNLPv2-wrapped Nack form.  The legacy bare-Nack test helper has
> been removed.  Witness: `testbed/tests/audit/a12_nack_lp_only.sh`.

> **A.15 RESOLVED 2026-05-13** — `Data::decode` and `Interest::decode`
> now call `SignatureInfo::decode` eagerly when they see the signature
> TLV.  KeyLocator-by-`SignatureType` rule violations
> (`DigestSha256` with a KeyLocator, `Ed25519` without one, etc.)
> are now surfaced as `KeyLocatorRule` errors at outer-packet decode
> time instead of being silently swallowed by the lazy `sig_info()`
> accessor.  Witness: `testbed/tests/audit/a15_keylocator_rules.sh`
> (extended with `a15_data_decode_rejects_*` cases).

> **B.02 RESOLVED 2026-05-13** — `LpPacket::decode` enforces the
> critical-bit rule (`is_critical_tlv_type`) on unknown LP header
> TLVs instead of silently skipping them.  Unknown ODD types
> (critical) reject with `MalformedPacket`; unknown EVEN types
> (non-critical) are tolerated for forward compat.  Witness:
> `testbed/tests/audit/b02_lp_unknown_critical.sh`.

> **D.12 RESOLVED 2026-05-13** — `ValidationStage::process` no longer
> opportunistically sets `ctx.verified = true` when the engine was built
> without a `Validator`.  The fix is fail-secure: `validator = None`
> returns `Action::Satisfy(ctx)` without touching `verified`, so
> `CsInsertStage` (`stages/cs.rs:50`) skips admission.  Local-face Data
> is still cached because `dispatcher/pipeline.rs:320` short-circuits
> `verified = true` for `FaceScope::Local` Data before this stage runs.
> Witness: `testbed/tests/audit/d12_cs_unverified_admission.sh`.

> **G.06 ARCHIVED 2026-05-13** — SWIM-over-NDN is now scoped as a
> non-testbed ndn-rs extension rather than an AutoConfig substitute.
> See the BLOCKED-BY-INTEROP entry below for the standards-track gap.
> Open work on NDN AutoConfig itself is tracked separately and not a
> blocker for testbed interop today.

### MINOR — strictness gaps and edge cases

> **A.17 RESOLVED 2026-05-12** — BLAKE3 SignatureType codes 6 and 7 are
> now registered on the NDN TLV SignatureType registry (yoursunny issue #12
> closed).  Any remaining documentation describing them as "experimental
> and unregistered" should be updated; the codes are spec-stable.

> **A.13 RESOLVED 2026-05-12** — `Interest::decode` now rejects any
> Nonce TLV whose length is not exactly 4 bytes (NDN Packet Format
> v0.3 §3.2).  Witness: `testbed/tests/audit/a13_nonce_length_rejected.sh`.

> **A.14 RESOLVED 2026-05-12** — `ContentType::Manifest` (4) and
> `ContentType::PrefixAnn` (5) are now typed enum variants.
> Witness: `testbed/tests/audit/a14_content_type_typed_variants.sh`.

> **B.10 RESOLVED 2026-05-13** — `ReassemblyBuffer` is now capped at
> `MAX_PENDING_PACKETS = 1024` concurrent partial groups.  Insertions
> over the cap run a lazy `purge_expired` first and then evict the
> oldest entry, so a peer flooding never-completed first-fragments
> cannot inflate buffer memory between external ticks.  Witness:
> `testbed/tests/audit/b10_reassembly_cap.sh`.

> **D.06 RESOLVED 2026-05-13** — `StrategyStage` now records each
> outbound `(face_id, nonce)` pair in the PIT entry's `out_records`
> and suppresses any re-send to the same face with the same nonce
> (`crates/spec/ndn-engine/src/stages/strategy.rs`, `Forward`
> branch).  If every chosen out-face is a duplicate, the Interest
> is dropped with `DropReason::Suppressed`.  Mirrors NFD
> Developer Guide §3.4.  Witness:
> `testbed/tests/audit/d06_pit_out_record_dedup.sh`.

> **D.11 RESOLVED 2026-05-13 (positive finding)** — Re-verified
> against the audit doc: both LRU and Fjall CS backends drop stale
> entries when `MustBeFresh` is set
> (`crates/spec/ndn-store/src/{lru_cs.rs:83,fjall_cs.rs:267}`), and
> `CsLookupStage` returns `Action::Continue` on every miss
> (`crates/spec/ndn-engine/src/stages/cs.rs:33`) so the Interest
> falls through to PIT + strategy + upstream forwarding.  The
> earlier wiki summary was incorrect.

> **E.02 RESOLVED 2026-05-13** — `run_ndn_mgmt_handler` binds
> `source_face = Some(handle.face_id())` directly from the
> `InProcHandle` it is reading from.  Previously the handler called
> `engine.source_face_id(&interest)`, which walked the PIT and
> returned the first in-record's face_id for a matching name hash;
> two commands from different faces with identical name hashes
> inside the 4-second PIT lifetime could resolve to each other's
> face_id, an authorization boundary bug.  `InProcHandle` now
> exposes the paired `InProcFace.id` via `face_id()`.  Witness:
> `testbed/tests/audit/e02_source_face_from_handle.sh`.

> **E.07 RESOLVED 2026-05-13** — `mgmt::faces_*` dispatches
> `verb::UPDATE` to a `faces_update` handler that honours NFD
> `Flags`+`Mask` semantics: each bit set in `Mask` selects whether
> the corresponding `Flags` bit replaces the current per-face
> bitmap (`FaceState.flags`), and the 200 ControlResponse echoes
> the new `Flags` value.  Without `Mask`, `Flags` is ignored.
> Parameters ndn-rs does not yet wire up at runtime
> (`FacePersistency`, `Mtu`) return 409 CONFLICT.  Management
> privilege gate matches `faces/destroy`.  Witness:
> `testbed/tests/audit/e07_faces_update_verb.sh`.

> **E.08 RESOLVED 2026-05-13** — `FaceStatus` emits `Flags` (0x6c),
> `NSatisfiedInterests` (0x99), and `NUnsatisfiedInterests` (0x9a)
> per ndn-cxx `tlv-nfd.hpp` with live per-face values.  Each
> `FaceState` carries `in_satisfied_interests` and
> `in_unsatisfied_interests` `AtomicU64` counters: the satisfied
> counter is bumped in `dispatcher/outbound.rs::satisfy` for every
> downstream face the matched Data is sent to, and the unsatisfied
> counter is bumped in `run_expiry_task` for every in-face on a
> timed-out PIT entry.  `FaceState.flags` carries the NFD
> `FaceFlagBit` bitmap: bit 0 (LocalFieldsEnabled) auto-set for
> local-scope faces, bit 1 (LpReliabilityEnabled) auto-set when
> `face-net` reliability is wired up.  Witness:
> `testbed/tests/audit/e08_face_status_flags.sh`.

> **F.10 RESOLVED 2026-05-13 (positive)** — Re-verified against the
> audit doc: the wire-level pieces are spec-correct on every backend
> (`l2/{ether,ether_macos,ether_windows,af_packet,ndrv,pcap_face,
> multicast_ether}.rs`) — EtherType `0x8624` and NDN multicast MAC
> `01:00:5e:00:17:aa`, matching NFD.  The original audit text
> flagged ~46 FIXMEs around `AF_PACKET` mmap tuning / socket
> lifecycle as implementation quality (not a spec gap); they remain
> tracked as engineering work in `docs/notes/`.

> **F.04 RESOLVED 2026-05-13** — Egress on non-local faces is
> wrapped in an LpPacket so per-hop NDNLPv2 headers
> (`CongestionMark`, `NextHopFaceId`, `IncomingFaceId`,
> `PitToken` on Data) have a frame to live in, matching NFD's
> `GenericLinkService` behaviour on network faces.  Local-scope
> faces keep bare TLV.  Witness:
> `testbed/tests/audit/f04_lp_wrap_nonlocal_egress.sh`.

> **F.02 RESOLVED 2026-05-12** — `MulticastUdpFace::ndn_default` now
> binds the multicast group on UDP/56363, matching NFD's
> `DEFAULT_MULTICAST_PORT` (`daemon/face/multicast-udp-factory.cpp`).
> The new `NDN_MULTICAST_PORT` constant disambiguates from
> `NDN_PORT` (unicast).  Witness:
> `testbed/tests/audit/f02_multicast_port_56363.sh`.

> **H.02 RESOLVED 2026-05-13** — `ndn-ping` server now registers
> `<prefix>/ping` (matching ndn-tools `ping-server.cpp:43`) and the
> CLI default `--prefix` is `/ndn`, so the default registered name
> is `/ndn/ping` per the ndn-cxx ndnping convention.  Witness:
> `testbed/tests/audit/h02_ping_prefix_ndnping_compat.sh`.

> **H.03 DOCUMENTED 2026-05-13** — `ndn-iperf` is scoped as a
> proprietary ndn-rs-only tool: no ndn-cxx `ndniperf` equivalent
> exists and the segment naming / `--sign-mode` parameter are
> not standardised.  Crate-level doc on `binaries/tooling/ndn-tools/src/iperf.rs`
> declares this; the tool is interop only between `ndn-iperf` peers.

### DOCS — documentation was incorrect or stale

> **H.09 RESOLVED 2026-05-13** — `ndn-bench` does not actually emit
> signed Data; on inspection it measures `InProcHandle ↔
> InProcFace` channel round-trip overhead with a fixed 3-byte
> dummy payload and never reaches the signing or CS paths.  The
> crate-level doc on `binaries/tooling/ndn-bench/src/main.rs`
> declares this scope explicitly (no end-to-end forwarding, no
> signing throughput) so readers do not misinterpret the numbers.
> Use `ndn-iperf` against a wired-up `ForwarderEngine` for real
> benchmarks.

## BLOCKED-BY-INTEROP

These findings have code-level implementations but their wire-level correctness
against a reference NDN peer is not yet confirmed by a passing interop test.
The specific blocker for each is noted.

- **NDNCERT 0.3 CHALLENGE round-trip against ndncert-ca-server** (*C.13* — PENDING).
  The ndn-rs CHALLENGE encoder is TLV; the decoder path is present. Requires
  running the full enrollment flow against `named-data/ndncert` CA. Not currently
  wired into `testbed/tests/interop/`.

- **PSync dataset sync with a C++ PSync peer** (*G.03* — PENDING). The IBF hash
  family is now MurmurHash3 (matching C++). A full sync exchange against
  `named-data/PSync` has not been run. Blocker: no PSync-specific interop
  container in the testbed.

- **E.05 — live management notification streams** (*E.05* — PENDING). The
  `NotificationStream` publisher is implemented. Interop requires a live
  `nfdc watch` subscriber or equivalent. Testbed container integration pending.

- **`nfdc` trust-schema validation of mgmt responses signed by ndn-rs** (*N.12* —
  PENDING). Management responses are signed with the daemon identity. A real
  `nfdc` client enforcing the default NFD trust schema has not been run against
  an ndn-rs forwarder. Blocker: trust schema configuration for the testbed
  ndn-fwd container.

- **NDN AutoConfig interop** (*G.06* — BLOCKED). ndn-rs uses SWIM-over-NDN for
  discovery; the NDN standard is `ndn-autoconfig` (DNS-based probe/cert
  discovery). Resolving this requires either implementing AutoConfig or clearly
  scoping SWIM as a non-testbed extension. The present SWIM protocol does not
  interoperate with `ndn-autoconfig` or NFD's prefix-announcement flow.

## How to report a spec compliance issue

File it against
[github.com/Quarmire/ndn-rs/issues](https://github.com/Quarmire/ndn-rs/issues)
with:

- The NDN spec clause you believe is violated (link + section).
- A minimal wire capture or source reference showing ndn-rs's behaviour.
- Your expected behaviour.

Per the project's witness-first workflow: new issues are resolved by adding a
witness script to `testbed/tests/audit/<id>_<slug>.sh` that exits 1 against the
broken code and 0 after the fix, with before/after transcripts in
`testbed/tests/audit/transcripts/`.

Related open issues:
[#3](https://github.com/Quarmire/ndn-rs/issues/3),
[#7](https://github.com/Quarmire/ndn-rs/issues/7),
[#9](https://github.com/Quarmire/ndn-rs/issues/9),
[#12](https://github.com/Quarmire/ndn-rs/issues/12),
[#13](https://github.com/Quarmire/ndn-rs/issues/13),
[#17](https://github.com/Quarmire/ndn-rs/issues/17),
[#18](https://github.com/Quarmire/ndn-rs/issues/18),
[#20](https://github.com/Quarmire/ndn-rs/issues/20),
[#21](https://github.com/Quarmire/ndn-rs/issues/21).

---

Full per-finding detail: [`docs/notes/spec-compliance-audit-2026-04-20.md`](https://github.com/Quarmire/ndn-rs/blob/main/docs/notes/spec-compliance-audit-2026-04-20.md).
Witness harness: `testbed/tests/audit/` (per-finding) and `testbed/tests/interop/` (cross-impl).
