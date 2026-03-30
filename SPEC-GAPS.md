# NDN Spec Compliance Gaps

Tracking deviations from official NDN specifications (RFC 8569, NDN Packet Format v0.3, NDNLPv2).

---

## Critical

- [x] **1. HopLimit not decoded or enforced** — `ndn-packet` does not parse HopLimit (TLV 0x22) from Interest packets; forwarder does not decrement or drop at zero. (NDN Packet Format v0.3 §5.2)
- [x] **2. Nonce not inserted by forwarder** — when forwarding an Interest upstream, forwarder must add a random Nonce if absent and detect loops via Nonce+Name. Currently no Nonce generation. (RFC 8569 §4.2)
- [x] **3. Ed25519 signature type code wrong** — code is 7; NDN spec says 5. (NDN Packet Format v0.3 §10.3)
- [ ] **4. Signed Interest support** — InterestSignatureInfo (0x2C) / InterestSignatureValue (0x2E) not yet implemented. Depends on gap #13. (NDN Packet Format v0.3 §5.4)
- [x] **5. Nack not NDNLPv2 framed** — Nack is now encoded as LpPacket (0x64) with Nack header and Fragment. Decode accepts both formats. (NDNLPv2 spec)
- [x] **6. No NDNLPv2 LpPacket framing** — `lp` module implements LpPacket decode/encode with Nack, CongestionMark, and Fragment support. Decode stage unwraps LpPackets. (NDNLPv2 spec)
- [x] **7. VarNumber shortest-encoding not validated** — TLV reader accepts any encoding; spec requires shortest form. (NDN Packet Format v0.3 §1.2)
- [x] **8. Types 0–31 grandfathered as always critical** — TLV type criticality check only looks at LSB; types 0–31 must be treated as critical regardless. (NDN Packet Format v0.3 §1.3)
- [x] **9. Zero-component Name not rejected** — empty Name (no components) should be rejected for Interest/Data. (NDN Packet Format v0.3 §2)
- [x] **10. ForwardingHint not decoded** — ForwardingHint (TLV 0x1E) is ignored during Interest parsing; forwarder cannot use delegation for multi-hop routing. (NDN Packet Format v0.3 §5.2)

## Important

- [x] **11. ContentType values incomplete** — BLOB(0), LINK(1), KEY(2), NACK(3) all handled; PREFIX_ANN(5) and FLIC(1024) mapped to Other(n). (NDN Packet Format v0.3 §6.3)
- [x] **12. FinalBlockId not decoded** — Data MetaInfo FinalBlockId (TLV 0x1A) is not parsed; consumers cannot detect last segment. (NDN Packet Format v0.3 §6.2)
- [ ] **13. Signed Interests not supported** — no InterestSignatureInfo/InterestSignatureValue parsing or verification. (NDN Packet Format v0.3 §5.4)
- [x] **14. ParametersSha256DigestComponent not verified** — decoder validates SHA-256 digest against ApplicationParameters TLV. (NDN Packet Format v0.3 §2.3)
- [x] **15. CanBePrefix / MustBeFresh semantics incomplete** — MustBeFresh is parsed but CS lookup may not filter on FreshnessPeriod expiry. CanBePrefix longest-match may be incomplete. (RFC 8569 §4.2)
- [x] **16. PIT aggregation rules incomplete** — spec requires same (Name, Selectors, ForwardingHint) tuple; current PIT key may not include ForwardingHint. (RFC 8569 §4.2)
- [ ] **17. CS admission policy** — no policy hooks for cache admission (e.g., respecting MustBeFresh, cache directives). (RFC 8569 §4.3)
- [x] **18. InterestLifetime default** — already defaults to 4000ms in PIT check stage. (NDN Packet Format v0.3 §5.2)
- [x] **19. Data packet freshness tracking** — CS must track insertion time and compute staleness from FreshnessPeriod. (RFC 8569 §4.3)
- [ ] **20. Implicit SHA-256 digest component** — Name matching must support implicit digest as final component for exact Data retrieval. (NDN Packet Format v0.3 §2.2)

## Moderate

- [ ] **21. SignatureNonce / SignatureTime / SignatureSeqNum** — signed Interest anti-replay fields not parsed. (NDN Packet Format v0.3 §5.4)
- [x] **22. ApplicationParameters encoding constraints** — encoder adds ParametersSha256DigestComponent; decoder validates its presence. (NDN Packet Format v0.3 §5.2)
- [ ] **23. Link object support** — ContentType=LINK Data contains delegation list; not parsed. (NDN Packet Format v0.3 §6.3.1)
- [x] **24. Congestion marking** — LpPacket decodes CongestionMark; propagated via pipeline tags. (NDNLPv2 spec)
- [ ] **25. Fragmentation / reassembly** — NDNLPv2 FragIndex/FragCount not supported. (NDNLPv2 spec)
