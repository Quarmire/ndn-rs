# BLAKE3 Signature Types

This document specifies two NDN `SignatureType` values backed by the BLAKE3
cryptographic hash function. They follow the structure and conventions of
the existing `DigestSha256` and `SignatureHmacWithSha256` definitions in the
[NDN Packet Format Specification](https://docs.named-data.net/NDN-packet-spec/current/signature.html).

| Name | TLV-VALUE of `SignatureType` | Authenticated | Output length |
|---|:---:|:---:|:---:|
| `DigestBlake3` | 6 | no | 32 octets |
| `SignatureBlake3Keyed` | 7 | yes (32-byte shared key) | 32 octets |

Both type codes are reserved on the
[NDN TLV `SignatureType` registry](https://redmine.named-data.net/projects/ndn-tlv/wiki/SignatureType).

## 1. DigestBlake3

`DigestBlake3` provides a content-integrity digest of an Interest or Data
packet computed with the BLAKE3 hash function. Like `DigestSha256`, it
provides no information about the provenance of a packet and no guarantee
that the packet originated from any particular signer; it is intended for
self-certifying content names and high-throughput integrity checks where
authentication is provided by other means (for example, a name carried
inside an enclosing signed packet).

- The TLV-VALUE of `SignatureType` is `6`.
- `KeyLocator` is forbidden; if present, it MUST be ignored.
- The signature is the unkeyed BLAKE3 hash, in default 256-bit output mode,
  of the *signed portion* of the Data or Interest as defined in
  [§3.1](https://docs.named-data.net/NDN-packet-spec/current/signature.html#signed-portion)
  of the NDN Packet Format Specification.

```
SignatureValue = SIGNATURE-VALUE-TYPE
                 TLV-LENGTH ; == 32
                 32OCTET    ; == BLAKE3{Data signed portion}

InterestSignatureValue = INTEREST-SIGNATURE-VALUE-TYPE
                         TLV-LENGTH ; == 32
                         32OCTET    ; == BLAKE3{Interest signed portion}
```

The hash function is BLAKE3 as defined in the
[BLAKE3 specification, §2 ("BLAKE3")](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf),
invoked with no key material and no key-derivation context, producing a
32-octet output.

## 2. SignatureBlake3Keyed

`SignatureBlake3Keyed` defines a message authentication code calculated over
the *signed portion* of an Interest or Data packet using BLAKE3 in keyed
mode. It is the BLAKE3 analogue of `SignatureHmacWithSha256`: the verifier
and signer share a 32-byte symmetric secret, and a successful verification
demonstrates that the packet was produced by a holder of that secret.

- The TLV-VALUE of `SignatureType` is `7`.
- `KeyLocator` is required and MUST identify the shared key by name, using
  the `KeyDigest` or `Name` form as appropriate.
- The signature is BLAKE3 in keyed mode (BLAKE3 specification, §2.3
  *"Keyed Hashing"*) with the 32-octet shared key, computed over the signed
  portion of the Data or Interest, producing a 32-octet output.
- The shared key MUST be exactly 32 octets in length. Implementations MUST
  reject keys of any other length rather than padding or truncating.

```
SignatureValue = SIGNATURE-VALUE-TYPE
                 TLV-LENGTH ; == 32
                 32OCTET    ; == BLAKE3-keyed(key, Data signed portion)

InterestSignatureValue = INTEREST-SIGNATURE-VALUE-TYPE
                         TLV-LENGTH ; == 32
                         32OCTET    ; == BLAKE3-keyed(key, Interest signed portion)
```

## 3. Rationale: distinct type codes for plain and keyed BLAKE3

NDN already separates an unauthenticated digest (`DigestSha256`, type 0)
from its keyed counterpart (`SignatureHmacWithSha256`, type 4). The
plain-vs-keyed split for BLAKE3 follows the same pattern, and exists for
the same reason: a verifier that dispatches on signature type alone must be
able to tell which algorithm to run.

If both modes shared a single type code, an attacker holding a packet
signed with `SignatureBlake3Keyed` could strip the keyed signature, replace
the Content with arbitrary forged bytes, and append an unkeyed BLAKE3 hash
of the new payload. On the wire the two values are indistinguishable — both
are 32-octet BLAKE3 outputs — so a verifier that selected the unkeyed code
path would accept the forgery. Distinct type codes prevent this downgrade
by forcing the verifier to commit to a verification algorithm before
inspecting the signature value.

## 4. Why BLAKE3

BLAKE3 was chosen because it offers ~3–8× the throughput of SHA-256 on
modern x86 and ARM CPUs (due to internal SIMD parallelism and a
tree-structured compression function) while providing equivalent
cryptographic guarantees: 256-bit collision resistance for the unkeyed
mode and 128-bit security for the keyed mode against a key-recovery
adversary, as analysed in the BLAKE3 specification. For NDN deployments
that sign or verify large numbers of small Data packets — sensor
telemetry, named-data sync digests, high-rate pub/sub — the per-packet
hashing cost is often the dominant security overhead, and BLAKE3 reduces
it without changing the surrounding KeyChain or trust-schema model.

## 5. Test vectors

All vectors operate on the signed portion of a packet (the byte sequence
that the signer hashes), not on a full packet. Implementers can verify
against any conforming BLAKE3 library: `blake3::hash` for `DigestBlake3`,
`blake3::keyed_hash` for `SignatureBlake3Keyed`. All hex strings are
lowercase, big-endian byte order.

### Vector 1 — `DigestBlake3`, empty signed portion

```
signed portion : (empty, 0 octets)
SignatureValue : af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262
```

This output matches the BLAKE3 specification's published hash of the empty
input and serves as a sanity check that the underlying hash library is
configured correctly.

### Vector 2 — `DigestBlake3`, sample Data signed portion

The signed portion below is the byte concatenation of a Name TLV
(`/ndn/test/blake3`), a MetaInfo TLV (ContentType=BLOB, FreshnessPeriod=4000
ms), a Content TLV (`"BLAKE3 NDN test"`), and a SignatureInfo TLV with
`SignatureType=6`.

```
signed portion (57 octets):
  0719080308036e646e0804746573740806626c616b6533360100140c180102
  190210a0150f424c414b4533204e444e207465737416030f0106
SignatureValue : e709c95387c663ff293bce17cf7ec685840ce9d0bc7785ce6fbd0b9fda3aaedb
```

### Vector 3 — `SignatureBlake3Keyed`, empty signed portion, all-zero key

```
key (32 octets) : 0000000000000000000000000000000000000000000000000000000000000000
signed portion  : (empty, 0 octets)
SignatureValue  : a7f91ced0533c12cd59706f2dc38c2a8c39c007ae89ab6492698778c8684c483
```

### Vector 4 — `SignatureBlake3Keyed`, sample Data signed portion

Same Name, MetaInfo, and Content as Vector 2, with `SignatureType=7` in the
SignatureInfo TLV and a key of `0x00 0x01 ... 0x1f`.

```
key (32 octets) : 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
signed portion (57 octets):
  0719080308036e646e0804746573740806626c616b6533360100140c180102
  190210a0150f424c414b4533204e444e207465737416030f0107
SignatureValue : 997f788fb4a8d03156ef964ffc52cfb6b7889ef88e4bea0c8d28c4db5e1686a3
```

## 6. Interoperability

A reference implementation is available in the `ndn-security` crate of the
[ndn-rs project](https://github.com/Quarmire/ndn-rs):

- `Blake3Signer` / `Blake3DigestVerifier` — `DigestBlake3` (type 6)
- `Blake3KeyedSigner` / `Blake3KeyedVerifier` — `SignatureBlake3Keyed` (type 7)

Both signers expose the same `Signer` trait used by the rest of the
KeyChain and integrate with the LightVerSec trust schema validator.

## 7. References

- NDN Packet Format Specification, §3 "Signature":
  <https://docs.named-data.net/NDN-packet-spec/current/signature.html>
- BLAKE3 specification:
  <https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf>
- NDN TLV registry — SignatureType:
  <https://redmine.named-data.net/projects/ndn-tlv/wiki/SignatureType>
