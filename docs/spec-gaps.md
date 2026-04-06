## NDN Spec Compliance Gap Analysis

### CRITICAL — Spec violations / missing required behavior

| # | Gap | Spec Requirement | Current State | Location |
|---|-----|-----------------|---------------|----------|
| 1 | **HopLimit not decoded or enforced** | Interest field (0x22), 1 octet. MUST drop if value is 0; MUST decrement before forwarding | TLV type defined but never decoded, never decremented, never checked | `interest.rs`, `dispatcher.rs` |
| 2 | **Nonce not added by forwarder** | Forwarder MUST add a Nonce if Interest arrives without one | Pipeline forwards without checking/adding nonce | `dispatcher.rs`, `pit.rs` |
| 3 | **Ed25519 signature type code is wrong** | Spec assigns code **5** to SignatureEd25519 | Codebase uses code **7** | `signature.rs:25` |
| 4 | **InterestSignatureValue type code is wrong** | Spec assigns **0x2e** (46) | `tlv_type` has `0x2d` (comment in summary said 0x2d) — but actually it's not defined at all | `lib.rs` |
| 5 | **Nack is not NDNLPv2 framed** | Nacks are LP headers inside `LpPacket` (0x50) wrapping the original Interest as a Fragment | Nack encoded as standalone TLV type 0x0320 — correct type but missing LpPacket wrapper | `nack.rs`, `encode.rs` |
| 6 | **No NDNLPv2 / LpPacket framing** | Network packets on links are wrapped in `LpPacket` (type 0x50) with optional headers (Nack, Fragment, Sequence, CachePolicy) | Not implemented at all — bare Interest/Data/Nack TLVs sent on all faces | Entire face layer |
| 7 | **VarNumber shortest-encoding not validated on read** | Spec: "A number MUST be encoded using the shortest possible format" | `read_varu64` accepts non-shortest encodings (e.g., 3-byte encoding of value 100) | `ndn-tlv/src/lib.rs:21` |
| 8 | **Types 0-31 not grandfathered as critical** | Spec: types 0-31 are always critical regardless of LSB | `skip_unknown` only checks LSB (odd/even), so type 0x12 (MustBeFresh=18, even) would be skipped as non-critical, but types ≤31 should all be critical | `reader.rs:74` |
| 9 | **Zero-component Name not rejected** | Spec: Interest with zero-component Name MUST be discarded | No validation — empty names pass through decode | `interest.rs`, `decode.rs` |
| 10 | **ForwardingHint not decoded** | Optional Interest field (0x1e) containing delegation Names for forwarding hints | TLV type defined, never decoded or used | `interest.rs` |

### IMPORTANT — Missing features required for interoperability

| # | Gap | Spec Requirement | Current State |
|---|-----|-----------------|---------------|
| 11 | **Signed Interests** | `InterestSignatureInfo` (0x2c) and `InterestSignatureValue` (0x2e) inside ApplicationParameters | Not implemented — no types defined, no decoding |
| 12 | **ParametersSha256DigestComponent enforcement** | When ApplicationParameters is present, Name MUST include a ParametersSha256DigestComponent (0x02); forwarder MUST verify digest | Type defined but no digest verification |
| 13 | **Name canonical ordering** | Components ordered by: (1) type precedence, (2) length, (3) lexicographic bytes | No `Ord` impl on Name or NameComponent — prefix matching only |
| 14 | **Fragmentation / reassembly** | NDNLPv2 defines Fragment (0x50), FragIndex (0x52), FragCount (0x53), Sequence (0x51) for MTU-exceeding packets | Not implemented (comment says "planned") |
| 15 | **KeyDigest in SignatureInfo** | KeyLocator may contain a KeyDigest (0x1d) instead of a Name | TLV type defined but never decoded |
| 16 | **ValidityPeriod in SignatureInfo** | Certificates include ValidityPeriod (0xFD) with NotBefore/NotAfter as ISO 8601 strings "YYYYMMDDThhmmss" | Implemented in security manager but uses u64 nanoseconds, not ISO 8601 string format |
| 17 | **Certificate naming convention** | `/<Identity>/KEY/<KeyId>/<IssuerId>/<Version>` with VersionNameComponent | No structured certificate naming — arbitrary Name used |
| 18 | **Certificate content format** | Content is DER-encoded SubjectPublicKeyInfo | Raw public key bytes used (not DER/SPKI wrapped) |
| 19 | **CachePolicy LP header** | NDNLPv2 CachePolicy (0x0334) allows forwarders to signal `NoCache` on Data | Not implemented |
| 20 | **Scope enforcement** | `/localhost` prefix restricted to local faces; `/localhop` restricted to one-hop | No scope checking in pipeline |

### MODERATE — Missing typed name components and encoding details

| # | Gap | Spec defines | Current State |
|---|-----|-------------|---------------|
| 21 | **Typed name components missing** | KeywordNameComponent (0x20), SegmentNameComponent (0x32), ByteOffsetNameComponent (0x34), VersionNameComponent (0x36), TimestampNameComponent (0x38), SequenceNumNameComponent (0x3a) | Not defined in `tlv_type` — all components treated as opaque (type, value) pairs |
| 22 | **Signature sub-fields missing** | SignatureNonce (0x26), SignatureTime (0x28), SignatureSeqNum (0x2a) for signed Interest replay protection | Not defined or decoded |
| 23 | **Certificate extension TLVs** | AdditionalDescription (0x0102), DescriptionEntry (0x0200), DescriptionKey (0x0201), DescriptionValue (0x0202) | Not implemented |
| 24 | **TLV element ordering validation** | Decoders MUST validate recognized elements appear in spec-defined order | No ordering checks — elements decoded by scanning all TLVs |
| 25 | **`write_nested` always uses 5-byte length** | Spec: lengths MUST use shortest encoding | `TlvWriter::write_nested` always emits 0xFE + 4-byte length even for small values | `writer.rs:46` |

### SUMMARY

**Critical (must fix for basic interop):** 10 items — HopLimit, Nonce insertion, Ed25519 code, NDNLPv2 framing, VarNumber validation, critical-type grandfathering, empty-name rejection, ForwardingHint

**Important (needed for full compliance):** 10 items — Signed Interests, ParametersSha256 verification, name ordering, fragmentation, ValidityPeriod format, certificate naming/DER, scope enforcement

**Moderate (completeness):** 5 items — typed name components, signature sub-fields, certificate extensions, element ordering, nested TLV length encoding
