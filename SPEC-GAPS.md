# NDN Spec Compliance Gaps

Tracking deviations from official NDN specifications (RFC 8569, NDN Packet Format v0.3, NDNLPv2).

---

## Critical

- [x] **1. HopLimit not decoded or enforced** — `ndn-packet` does not parse HopLimit (TLV 0x22) from Interest packets; forwarder does not decrement or drop at zero. (NDN Packet Format v0.3 §5.2)
- [x] **2. Nonce not inserted by forwarder** — when forwarding an Interest upstream, forwarder must add a random Nonce if absent and detect loops via Nonce+Name. Currently no Nonce generation. (RFC 8569 §4.2)
- [x] **3. Ed25519 signature type code wrong** — code is 7; NDN spec says 5. (NDN Packet Format v0.3 §10.3)
- [x] **4. Signed Interest support** — Interest decodes InterestSignatureInfo (0x2C) and InterestSignatureValue (0x2E) lazily; `signed_region()` returns the Name-through-SigInfo byte range for verification. (NDN Packet Format v0.3 §5.4)
- [x] **5. Nack not NDNLPv2 framed** — Nack is now encoded as LpPacket (0x64) with Nack header and Fragment. Decode accepts both formats. (NDNLPv2 spec)
- [x] **6. No NDNLPv2 LpPacket framing** — `lp` module implements LpPacket decode/encode with Nack, CongestionMark, and Fragment support. Decode stage unwraps LpPackets. (NDNLPv2 spec)
- [x] **7. VarNumber shortest-encoding not validated** — TLV reader accepts any encoding; spec requires shortest form. (NDN Packet Format v0.3 §1.2)
- [x] **8. Types 0–31 grandfathered as always critical** — TLV type criticality check only looks at LSB; types 0–31 must be treated as critical regardless. (NDN Packet Format v0.3 §1.3)
- [x] **9. Zero-component Name not rejected** — empty Name (no components) should be rejected for Interest/Data. (NDN Packet Format v0.3 §2)
- [x] **10. ForwardingHint not decoded** — ForwardingHint (TLV 0x1E) is ignored during Interest parsing; forwarder cannot use delegation for multi-hop routing. (NDN Packet Format v0.3 §5.2)

## Important

- [x] **11. ContentType values incomplete** — BLOB(0), LINK(1), KEY(2), NACK(3) all handled; PREFIX_ANN(5) and FLIC(1024) mapped to Other(n). (NDN Packet Format v0.3 §6.3)
- [x] **12. FinalBlockId not decoded** — Data MetaInfo FinalBlockId (TLV 0x1A) is not parsed; consumers cannot detect last segment. (NDN Packet Format v0.3 §6.2)
- [x] **13. Signed Interests not supported** — Interest now decodes InterestSignatureInfo/InterestSignatureValue and exposes `signed_region()` for verification. (NDN Packet Format v0.3 §5.4)
- [x] **14. ParametersSha256DigestComponent not verified** — decoder validates SHA-256 digest against ApplicationParameters TLV. (NDN Packet Format v0.3 §2.3)
- [x] **15. CanBePrefix / MustBeFresh semantics incomplete** — MustBeFresh is parsed but CS lookup may not filter on FreshnessPeriod expiry. CanBePrefix longest-match may be incomplete. (RFC 8569 §4.2)
- [x] **16. PIT aggregation rules incomplete** — spec requires same (Name, Selectors, ForwardingHint) tuple; current PIT key may not include ForwardingHint. (RFC 8569 §4.2)
- [x] **17. CS admission policy** — `CsAdmissionPolicy` trait with `DefaultAdmissionPolicy` (rejects FreshnessPeriod=0) and `AdmitAllPolicy`. `CsInsertStage` consults policy before caching. (RFC 8569 §4.3)
- [x] **18. InterestLifetime default** — already defaults to 4000ms in PIT check stage. (NDN Packet Format v0.3 §5.2)
- [x] **19. Data packet freshness tracking** — CS must track insertion time and compute staleness from FreshnessPeriod. (RFC 8569 §4.3)
- [x] **20. Implicit SHA-256 digest component** — `Data::implicit_digest()` computes SHA-256 of wire bytes; CS lookup matches Interests with ImplicitSha256DigestComponent by verifying the digest against cached Data. (NDN Packet Format v0.3 §2.2)

## Moderate

- [x] **21. SignatureNonce / SignatureTime / SignatureSeqNum** — `SignatureInfo` now decodes `sig_nonce`, `sig_time`, and `sig_seq_num` from InterestSignatureInfo. (NDN Packet Format v0.3 §5.4)
- [x] **22. ApplicationParameters encoding constraints** — encoder adds ParametersSha256DigestComponent; decoder validates its presence. (NDN Packet Format v0.3 §5.2)
- [x] **23. Link object support** — `Data::link_delegations()` parses Name TLVs from Content field when ContentType=LINK. (NDN Packet Format v0.3 §6.3.1)
- [x] **24. Congestion marking** — LpPacket decodes CongestionMark; propagated via pipeline tags. (NDNLPv2 spec)
- [x] **25. Fragmentation / reassembly** — `LpPacket` decodes Sequence (0x51), FragIndex (0x52), and FragCount (0x53); `is_fragmented()` helper. Full reassembly engine is a future task. (NDNLPv2 spec)
- [x] **26. Typed name components** — `KeywordNameComponent` (0x20), `ByteOffsetNameComponent` (0x34), `VersionNameComponent` (0x36), `TimestampNameComponent` (0x38), `SequenceNumNameComponent` (0x3A) with typed constructors, accessors, and Display/FromStr. (NDN Packet Format v0.3 §2)
- [x] **27. NDNLPv2 PitToken** — `LpPacket` decodes PitToken (0x62, 1-32 opaque bytes). Stored in `InRecord`, echoed in Data/Nack fan-back. Pipeline propagates via `PacketContext::lp_pit_token`. (NDNLPv2 spec)
- [x] **28. NDNLPv2 IncomingFaceId / NextHopFaceId** — `LpPacket` decodes IncomingFaceId (0x032C) and NextHopFaceId (0x0330). NextHopFaceId propagated as pipeline tag. (NDNLPv2 spec)
- [x] **29. NDNLPv2 CachePolicy** — `LpPacket` decodes CachePolicy (0x0334) with CachePolicyType (0x0335, NoCache=1). `CsInsertStage` skips caching when NoCache policy is present. (NDNLPv2 spec)
- [x] **30. NDNLPv2 TxSequence** — TLV type constant (0x0348) added alongside existing LP_ACK (0x0344) reliability support. (NDNLPv2 spec)
- [x] **31. NDNLPv2 NonDiscovery / PrefixAnnouncement** — `LpPacket` decodes NonDiscovery (0x034C, presence flag) and PrefixAnnouncement (0x0350, raw Data bytes). (NDNLPv2 spec)
- [x] **32. Certificate TLV decoding** — `Certificate::decode()` parses ValidityPeriod (0xFD) with NotBefore (0xFE) and NotAfter (0xFF) from Data Content field. Validator checks certificate time validity. TLV constants for AdditionalDescription (0x0102), DescriptionEntry/Key/Value (0x0200-0x0202) defined. (NDN Packet Format v0.3 §10)
- [x] **33. LpHeaders encode helper** — `encode_lp_with_headers()` encodes LpPackets with optional PitToken, CongestionMark, IncomingFaceId, CachePolicy in correct TLV-TYPE order. (NDNLPv2 spec)
- [x] **34. Certificate chain validation** — `Validator::validate_chain()` walks Data → cert → ... → trust anchor with cycle detection and depth limit. `CertFetcher` retrieves missing certs over NDN with deduplication. `ValidationStage` in engine data pipeline drops unverified Data. (NDN Certificate Format v2, NDN trust model)
