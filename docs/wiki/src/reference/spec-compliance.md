# NDN Specification Compliance

As of 2026-05-13, the compliance picture for ndn-rs is substantially improved from
the initial April audit state. Of 126 findings across phases A–I in
[`docs/notes/spec-compliance-audit-2026-04-20.md`](https://github.com/Quarmire/ndn-rs/blob/main/docs/notes/spec-compliance-audit-2026-04-20.md),
57 findings in phases A–H are resolved with at least a code fix. Six of those —
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
| A | Wire format: TLV, Name, Interest, Data, Nack | 21 | 12 | — |
| B | NDNLPv2 link protocol | 12 | 3 | B.10 (reassembly buffer unbounded, MINOR) |
| C | Signatures, certificates, trust schema, NDNCERT | 18 | 16 | C.09, C.15 are positives — Phase C effectively complete |
| D | Forwarding pipeline and tables | 18 | 9 | D.06 (nonce regeneration on outgoing, MINOR), D.08 (4-byte nonce collision handling, MINOR) |
| E | NFD management protocol | 8 | 5 | E.02 (source-face identity from PIT not face, MINOR), E.07 (faces/update stub, MINOR), E.08 (FaceStatus Flags field absent, MINOR) |
| F | Face implementations | 12 | 4 | F.04 (TCP bare TLV, no LP wrapping, MINOR), F.10 (Ethernet open TODOs, MINOR) |
| G | Routing, discovery, sync | 9 | 4 | G.06 (SWIM vs AutoConfig, MAJOR) |
| H | Binaries and CLI tools | 11 | 4 | H.02 (ndn-ping prefix not ndn-cxx compatible, MINOR), H.03 (ndn-iperf proprietary naming, MINOR) |
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

- **Neighbor discovery uses a SWIM-style protocol, not NDN AutoConfig.** The
  Hello/gossip protocol in `ndn-discovery` uses ndn-rs-defined TLV types and
  SWIM failure-detector semantics. It does not interoperate with NDN AutoConfig
  (`ndn-autoconfig`) or the NFD `/localhop/nfd/*` prefix-announcement flow.
  Presenting this as "NDN-native" discovery is inaccurate; it is NDN-transport
  SWIM. (*G.06.*)

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

- **NDNLPv2 reassembly buffer memory unbounded.** A peer may inflate ndn-rs
  memory by sending many partial fragment chains. (*B.10.*)

- **PIT outgoing Interest does not regenerate or verify the outbound Nonce.**
  (*D.06.*)

- **ContentStore freshness check at match time does not fall through to upstream
  on a MustBeFresh miss.** The pipeline drops rather than forwarding. (*D.11.*)

- **`faces/update` verb declared but not implemented in the management handler.**
  (*E.07.*)

- **`FaceStatus` TLV omits `Flags` (0x6C)** and aggregate counters `NInSatisfied` /
  `NInUnsatisfied`. `nfdc face list` shows these as zero. (*E.08.*)

> **F.02 RESOLVED 2026-05-12** — `MulticastUdpFace::ndn_default` now
> binds the multicast group on UDP/56363, matching NFD's
> `DEFAULT_MULTICAST_PORT` (`daemon/face/multicast-udp-factory.cpp`).
> The new `NDN_MULTICAST_PORT` constant disambiguates from
> `NDN_PORT` (unicast).  Witness:
> `testbed/tests/audit/f02_multicast_port_56363.sh`.

- **`ndn-ping` default prefix `/ping` is not ndn-cxx `ndnping`-compatible.** The
  reference tool expects `/ndn/ping`. (*H.02.*)

- **`ndn-iperf` uses an ndn-rs-specific name convention.** (*H.03.*)

### DOCS — documentation was incorrect or stale

- **`ndn-bench` uses `DataBuilder::build()` for load Data.** Benchmark throughput
  numbers reflect the DigestSha256 path, not real Ed25519 signing. Results are
  valid for relative comparisons but not as absolute throughput under production
  signing. (*H.09.*)

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
