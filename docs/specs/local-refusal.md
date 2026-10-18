# Local refusal: NackReason 170–176

> **Status:** Draft.
> **Scope:** how a validating ndn-rs forwarder tells a consumer on a local face that it
> refused the Data answering the consumer's Interest, the NDNLPv2 encoding, which faces
> receive it, how a forwarder relays a refusal it receives, and what a consumer does with it.
> **Codes:** NackReason `170`–`176`. These are ndn-rs-private. They are not in the NDNLPv2
> NackReason registry.
> **Reference implementation:** `ndn-rs/crates/core/ndn-packet/src/nack.rs` (codes),
> `ndn-rs/crates/forwarding/ndn-engine` (emission and relaying), `ndn-rs/crates/app/ndn-app`
> (consumer). For file:line references see [Appendix A](#appendix-a-code-references-non-normative).

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT",
"RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in
all capitals, as shown here.

Related specs: the trust contexts whose verdicts these codes report are specified in
[trust-context.md](trust-context.md). Adoption by expected fingerprint (the source of code
175) is covered in [trust-context.md](trust-context.md) and
[trust-envelope.md](trust-envelope.md). Certificates issued through
[ndncert-extensions.md](ndncert-extensions.md) are validated the same way as any other Data.
The design is in [personal-namespace.md](personal-namespace.md).

## 1. Terminology

- **Validating forwarder**: an NDN forwarder that checks the signature and certificate chain
  of the Data it forwards against the trust context governing the Data's name. ndn-rs
  forwarders (`ndn-fwd`, and the engine embedded in apps and in `ndn-mobile`) work this way
  whenever a validator is configured.
- **Local face**: a face whose other end is on the same host. §4.4 says exactly which faces
  count as local. Every other face is a **non-local face**.
- **Downstream / upstream**: in the NDN sense. A downstream is a face an Interest arrived on
  and a Data or Nack is returned to. An upstream is a face an Interest was forwarded to.
- **Local downstream**: a downstream that is a local face. Examples: an app connected over
  a Unix socket, an in-process app face, the forwarder's own internal consumers (certificate
  fetch, trust-context refresh, context sync, enrollment).
- **Local upstream**: an upstream that is a local face, typically a second forwarder on the
  same host.
- **Refusal**: a Nack whose NackReason is one of `170`–`176`. It tells a local downstream that
  the forwarder received a Data answering its Interest and refused it after validation.
- **Final refusal**: codes `170`–`175`. A verdict on the Data itself. Asking again returns
  the same answer.
- **Refusal for now**: code `176` (`unverifiable`). The forwarder could not verify the Data
  at this time. Asking again later may succeed.
- **Token**: the stable lowercase ASCII name of a code (e.g. `bad-signature`), used in logs,
  CLI output and FFI error values.
- **Trust context**, **namespace**, **adopt**, **expected fingerprint**: as in
  [trust-context.md](trust-context.md).

## 2. Wire encoding

### 2.1 Packet

A refusal is an ordinary NDNLPv2 network Nack:

```text
LpPacket   = 0x64 TLV-LENGTH
               [PitToken]            ; 0x62, only if the downstream's Interest carried one
               Nack                  ; 0x0320
               Fragment              ; 0x50
Nack       = 0x0320 TLV-LENGTH NackReason
NackReason = 0x0321 TLV-LENGTH NonNegativeInteger   ; 170..176
Fragment   = 0x50 TLV-LENGTH Interest
```

- TLV-TYPEs `0x0320` and `0x0321` are VAR-NUMBERs, so they are encoded as the 3-byte forms
  `FD 03 20` and `FD 03 21`. `0x64`, `0x62` and `0x50` are single bytes.
- A sender MUST encode NackReason as a NonNegativeInteger in its shortest form. All codes in
  this spec are below 256, so the value is always one byte: `AA` (170) to `B0` (176).
- A sender MUST place the headers in ascending TLV-TYPE order: PitToken (`0x62`), then Nack
  (`0x0320`), then Fragment (`0x50`) last. ndn-rs emits no other LP header on a refusal.
- A sender MUST LP-frame a refusal on every face kind, including faces that otherwise carry
  bare TLV (Unix sockets, in-process app faces). A bare `0x0320` TLV outside an LpPacket is
  not a Nack. ndn-rs rejects it on decode.
- When the downstream's Interest arrived with an NDNLPv2 PitToken, the sender MUST echo it
  unchanged in the refusal.

A receiver:

- MUST accept any other NDNLPv2 header a peer adds, as NDNLPv2 specifies.
- MUST read NackReason as a NonNegativeInteger. It SHOULD accept the 1-, 2-, 4- and 8-byte
  encodings: test vector V10 is a 2-byte encoding of 171, and ndn-rs decodes it as `revoked`.
- MUST treat a Nack element with no NackReason as a Nack without reason. That is not a refusal.
- MUST use only the first NackReason inside a Nack. This is what ndn-rs does.

### 2.2 The Interest in the Fragment

The forwarder emitting a refusal (§4) no longer has the downstream's Interest packet. It
rebuilds the Interest from the state it kept for that downstream, and the result contains
exactly:

| Order | Element | Value |
|---|---|---|
| 1 | Name (`0x07`) | the PIT entry's name: the Interest name the downstream sent, all components and component types preserved |
| 2 | CanBePrefix (`0x21`, empty) | present iff the downstream's Interest had it |
| 3 | MustBeFresh (`0x12`, empty) | present iff the downstream's Interest had it |
| 4 | Nonce (`0x0A`, 4 bytes) | the nonce the downstream sent |

InterestLifetime, HopLimit, ForwardingHint, ApplicationParameters and the Interest signature
elements are left out.

A receiver MUST match a refusal to its pending Interest by the enclosed Interest's Name, with
CanBePrefix taken into account, or by PitToken. A receiver MUST NOT require the other
elements of its original Interest to be present. A receiver SHOULD NOT reject the enclosed
Interest because its Name ends in a ParametersSha256DigestComponent with no
ApplicationParameters present (see §8, item 3).

A refusal relayed by a second forwarder (§5) carries the Interest that forwarder received in
the upstream's Nack instead.

## 3. Codes

| Code | Hex value byte | Token | ndn-rs `Refusal` | Meaning | Final |
|---|---|---|---|---|---|
| 170 | `AA` | `chain` | `Chain` | The certificate chain was rejected for a reason not listed below: chain too deep, a cycle, an unsupported signature type, a key-store error, or another chain-walk failure. | yes |
| 171 | `AB` | `revoked` | `Revoked` | A certificate on the chain is revoked in the governing trust context. | yes |
| 172 | `AC` | `bad-signature` | `BadSignature` | The signature does not verify (forged, or altered in transit), the key encoding is invalid, or the Data has no usable signing-key reference (see §4.2). | yes |
| 173 | `AD` | `schema` | `Schema` | The trust schema or trust context does not authorize this signer for this name, or does not allow an issuer to certify a certificate on the chain. | yes |
| 174 | `AE` | `untrusted-root` | `UntrustedRoot` | The chain ends at a self-signed certificate that is not a trust anchor of the governing trust context. | yes |
| 175 | `AF` | `context` | `Context` | A trust context Data arrived for a namespace that is being adopted or updated and failed that expectation: it is signed by an anchor whose fingerprint is not the expected fingerprint, an update is not signed by an anchor of the held version, or the context does not open. | yes |
| 176 | `B0` | `unverifiable` | `Unverifiable` | The Data cannot be verified now. Every source the forwarder asked for the signing certificate answered definitively that none is available there (a NoRoute Nack), or served a certificate this forwarder refused. | **no** |

- The codes are ndn-rs-private. They lie outside the NDNLPv2 registry (Congestion 50,
  Duplicate 100, NoRoute 150) and away from the ndn-rs-private NotYet (160).
- Codes 169 and 177 are not refusals. ndn-rs decodes them as an unknown reason (V11).
- Tokens are stable. An implementation that shows a refusal to a user or writes it to a log
  SHOULD use the token.

Informative: the one-line "next step" ndn-rs shows for each code:

| Token | Next step (ndn-rs `Refusal::next_step`) |
|---|---|
| `chain` | the signer's certificate chain is unusable: the publisher must sign with a certificate issued in the namespace |
| `revoked` | the signer's certificate was revoked: the publisher must enroll again |
| `bad-signature` | fetch it over another path, or ask the publisher to publish it again |
| `schema` | publish under a name the signer is authorized for, or have an admin change the schema |
| `untrusted-root` | adopt the namespace's anchor link |
| `context` | check the anchor link or expected fingerprint you adopted |
| `unverifiable` | retry later: the signing certificate could not be fetched (if it never can, the publisher has no certificate) |

## 4. Emitting a refusal

### 4.1 Which Data is validated

A forwarder validates a received Data, and so may refuse it, only when both of these hold:

1. A validator is configured. With `[security] profile = "disabled"` nothing is validated and
   nothing is refused.
2. The Data arrived on a non-local face, or on a local face that requires validation. In
   ndn-fwd, `[engine] require_local_validation = true` makes every local face require it. The
   default is `false`.

By default, Data from a local producer is not validated and never refused.

A Data signed with DigestSha256 is accepted when the digest matches. When it does not match,
it is refused with 172.

### 4.2 Verdict to code

The forwarder walks the chain using only certificates it has already cached. A walk ends in
one of three ways: valid, invalid with an error, or pending on a missing certificate.

| Validation outcome | Refusal |
|---|---|
| Valid | none: the Data is forwarded and may be cached |
| Revoked | 171 |
| Signature does not verify; invalid key encoding | 172 |
| No SignatureInfo; no KeyLocator on a non-DigestSha256 signature; a KeyDigest KeyLocator whose certificate is not cached | 172 (see §8, item 1) |
| Schema mismatch; certificate not authorized by its issuer | 173 |
| Chain ends at a self-signed certificate that is not an anchor | 174 |
| Trust context at an expected name fails the adoption or update expectation | 175 |
| Any other chain error (too deep, cycle, unsupported signature type, key store, certificate not found) | 170 |
| Pending: the signing (or an issuer) certificate is not cached | none yet; see below |

A pending Data is parked, and the forwarder fetches the missing certificate in the background.
The fetch is routed by the FIB and is also sent directly out of the face the Data arrived on.
Every 100 ms the forwarder re-checks parked Data:

- **The certificate is now cached** (or the forwarder has refused the certificate itself):
  the Data is validated again. A valid result releases it. An invalid result refuses it with
  the code for that error from the table above. If the next certificate up the chain is
  missing, the Data is parked again under its original deadline.
- **Every source asked answered definitively** (a NoRoute Nack, or a refusal of the
  certificate it served): the Data is refused with **176**. "Definitively" excludes a timeout
  and any other Nack reason. These count as no answer.
- **The deadline passed** (4 s after the Data first parked): the Data is dropped and **no
  refusal is sent**. The same happens when the certificate is still missing after its fetch
  completes, and when a full parking queue (256 entries or 4 MiB) evicts its oldest Data.

A forwarder MUST NOT send a refusal for Data that has no verdict yet. A pending Data, a
certificate fetch that timed out, and an evicted Data get no refusal.

The certificate fetcher remembers a failed fetch for 4 s (`negative_ttl`, equal to the fetch
timeout). During that time the certificate is not fetched again, and a Data waiting on a
certificate known to be absent is refused 176 at the next 100 ms check. From the start of a
failed fetch, the earliest the certificate can be fetched again is 4 s (fetch timeout) + 4 s
(negative TTL) = 8 s.

### 4.3 Recipients

When the forwarder refuses a Data:

1. The Data MUST NOT be forwarded to any face and MUST NOT be inserted into the Content Store.
2. The forwarder consumes the PIT in-records the Data matched, exactly as if it had been
   forwarded: the exact-name entry, the parameters- or implicit-digest-stripped entry, and
   CanBePrefix entries at shorter prefixes. Their nonces enter the Dead Nonce List. Persistent
   (subscription) in-records are not consumed and get no refusal.
3. For each matched downstream face (deduplicated by face, first match wins):
   - **Local face**: the forwarder MUST send one refusal Nack (§2), enclosing that
     downstream's own Interest (§2.2) and echoing its PitToken.
   - **Non-local face**: the forwarder MUST NOT send anything. To the network, a refused
     Data looks the same as a dropped one, so a remote peer cannot probe the forwarder's
     trust state.

A forwarder MUST NOT send a NackReason in `170`–`176` on a non-local face.

### 4.4 What counts as local

Locality comes from the face kind and, for IP and overlay transports, from the remote
address:

| Face kinds | Local? |
|---|---|
| Unix socket, App (in-process), Shm, Internal, Compute, Management | always local |
| Ethernet, EtherMulticast, Serial, Bluetooth, Wfb, WifiAware, WifiDirect, Multicast | never local |
| UDP, TCP, WebSocket, WebTransport, WebRTC, InfraTunnel, QUIC | local iff the remote FaceUri host is a loopback address (`127.0.0.0/8`, `::1`) or the literal `localhost` (case-insensitive). A missing or unparseable remote counts as non-local. |

An app from another stack therefore receives refusals when it connects to an ndn-rs
forwarder over its Unix socket, or over TCP, UDP or WebSocket to a loopback address. An app
connecting from another host never receives one.

## 5. Relaying a received refusal

A forwarder that receives a Nack carrying `170`–`176` from an upstream handles it as follows.

1. The ordinary Nack checks apply first. A Nack received on a multi-access or ad-hoc face is
   dropped. A Nack with no matching PIT entry is dropped.
2. The forwarding strategy sees the refusal as **NoRoute**: that upstream has nothing usable,
   and another upstream might. This also applies to any reason code the forwarder does not
   know. If the strategy retries another upstream, no Nack goes downstream.
3. If the strategy decides to Nack, the forwarder removes the PIT entry and chooses the reason
   to relay:
   - **The refusal came from a local upstream** (a forwarder on this host): the refusal code
     is kept. It MUST be sent only to local downstreams. Non-local downstreams MUST get
     nothing.
   - **The refusal came from a non-local upstream**: the code is an unverified claim. Anyone
     could forge "revoked". The forwarder MUST relay it as **NoRoute (150)**, to every
     point-to-point downstream, local and non-local alike.
4. A relayed Nack encloses the Interest from the upstream Nack's Fragment, unchanged. ndn-rs
   does not attach the downstream's PitToken to a relayed Nack (see §8, item 4).

A consumer MUST NOT treat a refusal code received over a non-local face as a refusal. It MUST
treat it as NoRoute. A conforming forwarder never sends one there (§4.3), so if one arrives,
the code is unverified.

## 6. Consumer behaviour

These rules apply to a consumer attached to a validating forwarder over a local face.

### 6.1 Recognising a refusal

A Nack from the local forwarder whose NackReason is in `170`–`176` is a refusal of the Data
that answered the enclosed Interest. A consumer SHOULD report it distinctly from a timeout and
from other Nacks, giving the code, its token, whether it is final, and the Interest name.
The Data was there, and this host's forwarder rejected it.

A consumer that does not implement this spec meets the NDNLPv2 rule for unknown reason codes:
it treats the refusal as a Nack without reason and does not drop the packet. It therefore
still fails fast instead of waiting out the Interest lifetime.

### 6.2 Final refusals (170–175)

- A consumer MUST NOT automatically re-express the Interest, and MUST NOT start a new
  automatic retry for the same name, because of a final refusal. Retry loops MUST stop at once
  and report the refusal.
- A segmented or multi-Interest fetch (e.g. RDR object fetch) MUST stop the whole fetch at the
  first final refusal of any of its Interests.
- A consumer MAY ask again after the local trust state changes, for example after adopting a
  namespace (174), refreshing or updating a trust context (171, 173, 175), or the publisher
  re-enrolling (171). Such a retry SHOULD be driven by the user or the trust-state change, not
  by a timer.

### 6.3 Refusal for now (176)

- A consumer MAY re-express the Interest within its normal retry budget, treating 176 like a
  timeout or a loss.
- It SHOULD NOT re-express sooner than 4 s after the refusal, because the forwarder refuses
  again until its negative cache expires (§4.2). Waiting at least 8 s between attempts is
  RECOMMENDED, which is ndn-app's guidance: twice `CERT_FETCH_TIMEOUT`.
- If the retry budget runs out and the last failure was a 176, the consumer SHOULD report the
  176 refusal rather than a timeout.
- In a segmented fetch, a 176 on one segment is handled like a lost segment: it is
  retransmitted within the fetch's no-progress budget.

### 6.4 Forwarder-internal consumers

The rules in §6.2 and §6.3 also apply to a forwarder's own consumers, which are local
downstreams of their own forwarder. In ndn-rs:

- The certificate fetcher counts a refusal of the certificate it fetched as a definitive
  answer from that source.
- Trust-context refresh and context sync treat a final refusal as "refused" and a 176 as
  "missing, fetch again later".
- Certificate renewal treats a 176 refusal of the CA's answer as "CA unreachable", which can
  be retried, and any other refusal as final.

## 7. Test vectors

All vectors are in hex. They were produced by ndn-rs's own encoder and decoded back by its
decoder (see Provenance).

Common enclosed Interest, `/home/bob/doc` (three GenericNameComponents, type `0x08`), Nonce
`01020304`, no selectors:

```text
I1 = 051807100804686F6D650803626F620803646F630A0401020304
```

**V1–V7: one refusal Nack per code, no PitToken.**

| Vector | Code | Token | Final | LpPacket |
|---|---|---|---|---|
| V1 | 170 | `chain` | yes | `6425FD032005FD032101AA501A051807100804686F6D650803626F620803646F630A0401020304` |
| V2 | 171 | `revoked` | yes | `6425FD032005FD032101AB501A051807100804686F6D650803626F620803646F630A0401020304` |
| V3 | 172 | `bad-signature` | yes | `6425FD032005FD032101AC501A051807100804686F6D650803626F620803646F630A0401020304` |
| V4 | 173 | `schema` | yes | `6425FD032005FD032101AD501A051807100804686F6D650803626F620803646F630A0401020304` |
| V5 | 174 | `untrusted-root` | yes | `6425FD032005FD032101AE501A051807100804686F6D650803626F620803646F630A0401020304` |
| V6 | 175 | `context` | yes | `6425FD032005FD032101AF501A051807100804686F6D650803626F620803646F630A0401020304` |
| V7 | 176 | `unverifiable` | **no** | `6425FD032005FD032101B0501A051807100804686F6D650803626F620803646F630A0401020304` |

Breakdown of V1:

```text
64 25                         LpPacket, length 37
   FD0320 05                  Nack, length 5
      FD0321 01 AA            NackReason = 170
   50 1A                      Fragment, length 26
      05 18                   Interest, length 24
         07 10                Name, length 16
            08 04 686F6D65    "home"
            08 03 626F62      "bob"
            08 03 646F63      "doc"
         0A 04 01020304       Nonce
```

**V8: refusal 171 with PitToken `CAFE0001`, enclosing an Interest with CanBePrefix and
MustBeFresh, Nonce `A1B2C3D4`.**

```text
enclosed Interest:
051C07100804686F6D650803626F620803646F63210012000A04A1B2C3D4

LpPacket:
642F6204CAFE0001FD032005FD032101AB501E051C07100804686F6D650803626F620803646F63210012000A04A1B2C3D4
```

**V9: the same Interest relayed as NoRoute (150).** This is what a downstream receives when a
non-local upstream sent a refusal (§5):

```text
6425FD032005FD03210196501A051807100804686F6D650803626F620803646F630A0401020304
```

**V10: receiver leniency.** NackReason 171 in a non-minimal 2-byte encoding (`00AB`). ndn-rs
decodes it as `Refused(Revoked)`. A sender MUST NOT produce it.

```text
6426FD032006FD03210200AB501A051807100804686F6D650803626F620803646F630A0401020304
```

**V11: range bounds.** NackReason 169 decodes as `Other(169)` and 177 as `Other(177)`.
Neither is a refusal.

### Provenance

- V1–V11 come from a throwaway example built against `ndn-packet` (feature `std`):
  `cargo run -p ndn-packet --features std --example specvec_refusal`, run on 2026-10-18
  against the working tree, after which the file was deleted.
  - The enclosed Interests were built with `Nack::interest_wire`, the function the forwarder
    uses in `refuse`.
  - The Nacks were built with `encode_lp_nack` (V1–V7, V9) and `encode_lp_nack_with_pit_token`
    (V8). The engine's `frame_with_intent` calls these to frame a Nack.
  - Every vector was decoded back with `LpPacket::decode` / `Nack::decode`, and the program
    asserted the code, the token, the name, the PitToken and the selectors.
  - V10 was hand-built with `TlvWriter` and decoded with `LpPacket::decode`.
- Behavioural coverage in the repository: `ndn-engine/tests/local_refusal.rs`.
  - `a_remote_refusal_is_relayed_as_no_route`
  - `a_local_refusal_is_relayed_to_local_downstreams_only`
  - `revoked_data_is_refused_to_the_local_consumer_only`
  - `forged_data_is_refused_to_the_local_consumer_only`
  - `pending_data_is_refused_to_nobody`
  - `data_whose_certificate_is_absent_is_refused_unverifiable`
  - Code and token round-trips are in `ndn-packet/src/nack.rs` tests.

## 8. Open questions

1. **Missing KeyLocator gives 172, but the documentation says 176.**
   - `Refusal::Unverifiable`'s doc comment and the wiki table say a Data that "names no
     signing key (no KeyLocator)" is refused `unverifiable`.
   - In the code, `validate_chain_inner` returns `Invalid(InvalidSignature)` for a missing
     KeyLocator, a missing SignatureInfo, and an uncached KeyDigest locator. That error maps
     to **172 `bad-signature`**.
   - The `Pending`-with-no-missing-certificate branch in the validation stage that would
     produce 176 cannot be reached: `validate_chain_cached` returns a missing name iff the
     result is `Pending`.
   - This spec states what the code does (172). One of the two needs to change. If 176 is
     intended, it would be refused for now although retrying can never help.
2. **Should 176 be final when retrying cannot help?** This only matters if item 1 is resolved
   towards 176.
3. **The enclosed Interest is rebuilt and loses elements.**
   - `Nack::interest_wire` keeps the PIT entry's full name. For a parameterized Interest that
     name includes the ParametersSha256DigestComponent, but ApplicationParameters is left out.
   - A strict decoder that enforces "a PSDC requires ApplicationParameters" could drop the
     Nack. ndn-rs and ndn-cxx (according to ndn-rs's own decoder comments) accept it. Whether
     NDNts and python-ndn accept it is [INFERENCE: unverified].
   - Options: drop the PSDC from the name, or keep the full Interest per in-record.
4. **Relayed Nacks are built differently from originated refusals.**
   - A relayed Nack (§5) does not echo the downstream's PitToken.
   - It also carries the Interest from the upstream Nack instead of each downstream's own
     Interest (own nonce).
   - `refuse` does both correctly. A downstream that matches replies only by PitToken cannot
     match a relayed refusal or NoRoute.
5. **Only the first pending Interest per face is answered.**
   - Downstreams are deduplicated by face.
   - If one Data consumes two in-records of the same local face, for example an exact
     Interest and a CanBePrefix Interest at a shorter prefix, only the first gets a refusal.
     The other times out.
6. **Non-local downstreams get nothing when the refusal came from a local upstream.**
   - The PIT entry is removed, so a non-local downstream waits out its Interest lifetime.
   - This matches "a refused Data is a dropped one".
   - It differs from the non-local-upstream case, where every downstream gets NoRoute. The
     brief for this spec said "relayed to non-local faces as NoRoute". The code does that
     only when the refusal came from a non-local upstream.
7. **Range registration.** 170–176 (and 160) are unregistered. Another stack could assign
   these numbers differently. Whether to request an NDNLPv2 registry entry is open.
8. **Leniency in decoding NackReason.**
   - ndn-rs decodes a NackReason of any length, folding bytes big-endian.
   - A zero-length value decodes as code 0. A value longer than 8 bytes silently loses its
     high bytes.
   - NDN requires NonNegativeInteger lengths of 1, 2, 4 or 8.
9. **Silent drops.** A Data that times out or is evicted from the pending queue gets no
   refusal, so the consumer sees a timeout. The queue limits (4 s, 256 entries, 4 MiB) are
   compiled-in defaults (`PendingQueueConfig::default()`) and cannot be configured.

## Appendix A. Code references (non-normative)

The paths are relative to the workspace root. Lines are as read on 2026-10-18. Code in
`ndn-fwd` may move to `ndn-rs` library crates while other refactors are in progress.

**Codes and wire format**

| Claim | Location |
|---|---|
| `NackReason` enum, codes 50/100/150/160 | `ndn-rs/crates/core/ndn-packet/src/nack.rs:12-44` |
| `is_registered` excludes NotYet and refusals | `ndn-rs/crates/core/ndn-packet/src/nack.rs:48-53` |
| `refusal()` | `ndn-rs/crates/core/ndn-packet/src/nack.rs:56-61` |
| `Refusal` variants and meanings | `ndn-rs/crates/core/ndn-packet/src/nack.rs:64-105` |
| Codes 170–176 | `ndn-rs/crates/core/ndn-packet/src/nack.rs:119-129` |
| `from_code`, unknown codes become `Other` | `ndn-rs/crates/core/ndn-packet/src/nack.rs:36-44`, `131-133` |
| Tokens | `ndn-rs/crates/core/ndn-packet/src/nack.rs:137-152` |
| `is_final` (only Unverifiable is not final) | `ndn-rs/crates/core/ndn-packet/src/nack.rs:159-161` |
| `next_step` texts | `ndn-rs/crates/core/ndn-packet/src/nack.rs:164-196` |
| Rebuilt enclosed Interest (Name, CanBePrefix, MustBeFresh, Nonce) | `ndn-rs/crates/core/ndn-packet/src/nack.rs:266-279` |
| Round-trip tests (169/177 are `Other`) | `ndn-rs/crates/core/ndn-packet/src/nack.rs:323-343` |
| TLV types: Nack 0x0320, NackReason 0x0321, LpPacket 0x64, Fragment 0x50, PitToken 0x62 | `ndn-rs/crates/core/ndn-packet/src/lib.rs:128-129`, `143-148` |
| LP Nack encoder, header order | `ndn-rs/crates/core/ndn-packet/src/lp/encode.rs:7-33` |
| Shortest-form NNI | `ndn-rs/crates/core/ndn-packet/src/lp/mod.rs:46-57` |
| Nack header decode (empty means no reason, first NackReason wins, any length) | `ndn-rs/crates/core/ndn-packet/src/lp/decode.rs:233-249` |
| `Nack::decode` rejects a bare 0x0320 and requires a Fragment | `ndn-rs/crates/core/ndn-packet/src/nack.rs:239-260`, `396-428` |

**Forwarder: emitting a refusal**

| Claim | Location |
|---|---|
| Egress framing: a Nack is always LP-framed, PitToken echoed | `ndn-rs/crates/forwarding/ndn-engine/src/engine.rs:95-101`, `115-125` |
| `is_local_face` | `ndn-rs/crates/forwarding/ndn-engine/src/dispatcher/outbound.rs:44-48` |
| `nacks_allowed_on_face` (point-to-point only) | `ndn-rs/crates/forwarding/ndn-engine/src/dispatcher/outbound.rs:38-40` |
| `refuse`: local downstreams only, own Interest, PitToken | `ndn-rs/crates/forwarding/ndn-engine/src/dispatcher/outbound.rs:57-77` |
| `Action::Refuse` dispatched to `refuse` | `ndn-rs/crates/forwarding/ndn-engine/src/dispatcher/outbound.rs:240` |
| Refused Data is never cached or forwarded | `ndn-rs/crates/forwarding/ndn-engine/src/pipeline/action.rs:40-43` |
| Which Data is validated (non-local, or `require_data_validation`); downstream recording | `ndn-rs/crates/forwarding/ndn-engine/src/dispatcher/pipeline.rs:574-641` |
| `require_local_validation` config | `ndn-rs/crates/platform/ndn-config/src/config.rs:1346-1350`; `ndn-rs/crates/forwarding/ndn-engine/src/builder.rs:86`, `100`; `ndn-rs/crates/forwarding/ndn-engine/src/engine.rs:634-636`; `ndn-fwd/binaries/ndn-fwd/src/main.rs:553` |
| PIT match records downstreams (exact, digest-stripped, CanBePrefix) | `ndn-rs/crates/forwarding/ndn-engine/src/stages/pit.rs:480-558` |
| In-records consumed, deduplicated by face, nonces into the Dead Nonce List | `ndn-rs/crates/forwarding/ndn-engine/src/stages/pit.rs:679-745` |
| `out_interests` / `DownstreamInterest`; persistent in-records excluded | `ndn-rs/crates/forwarding/ndn-engine/src/pipeline/context.rs:36-45`, `80-83` |
| Pending queue defaults (256, 4 MiB, 4 s) | `ndn-rs/crates/forwarding/ndn-engine/src/stages/validation.rs:64-72` |
| Pending queue eviction and timeout | `ndn-rs/crates/forwarding/ndn-engine/src/stages/validation.rs:91-125` |
| Ready check, then known-absent check, gives 176 | `ndn-rs/crates/forwarding/ndn-engine/src/stages/validation.rs:127-153` |
| Inline verdicts | `ndn-rs/crates/forwarding/ndn-engine/src/stages/validation.rs:281-319` |
| Re-validation after parking | `ndn-rs/crates/forwarding/ndn-engine/src/stages/validation.rs:323-388` |
| `invalid_reason` (TrustError to Refusal) | `ndn-rs/crates/forwarding/ndn-engine/src/stages/validation.rs:394-418` |
| 100 ms drain tick | `ndn-rs/crates/forwarding/ndn-engine/src/dispatcher/pipeline.rs:714-735` |
| `TrustError` variants | `ndn-rs/crates/security/ndn-security/src/error.rs:4-43` |
| No SigInfo, no KeyLocator, or uncached KeyDigest gives `InvalidSignature`; DigestSha256 handling | `ndn-rs/crates/security/ndn-security/src/validator/chain.rs:97-130` |
| `Pending` iff a missing name; a refused certificate is remembered | `ndn-rs/crates/security/ndn-security/src/validator/chain.rs:62-76`, `158-172` |
| Expected-context refusal (175) | `ndn-rs/crates/security/ndn-security/src/validator/expected.rs:247-288` |
| `FetchMiss` (Absent = NoRoute, Refused), combining sources | `ndn-rs/crates/security/ndn-security/src/cert_fetcher.rs:50-79` |
| `retry_after`, `known_absent` | `ndn-rs/crates/security/ndn-security/src/cert_fetcher.rs:178-193` |
| Negative cache `retry_at = now + negative_ttl` | `ndn-rs/crates/security/ndn-security/src/cert_fetcher.rs:270-284` |
| `CERT_FETCH_TIMEOUT` = 4 s; cert Interest (CanBePrefix, MustBeFresh) | `ndn-rs/crates/app/ndn-app/src/cert_fetch.rs:44-52` |
| Fetch error to `FetchMiss` | `ndn-rs/crates/app/ndn-app/src/cert_fetch.rs:58-66` |
| Engine fetcher (timeout = negative TTL = 4 s; direct fetch) | `ndn-rs/crates/app/ndn-app/src/cert_fetch.rs:122-131` |
| Face locality by kind | `ndn-rs/crates/core/ndn-transport/src/face.rs:111-135` |
| Locality by remote address, loopback test | `ndn-rs/crates/core/ndn-transport/src/face.rs:258-293` |

**Forwarder: relaying a received refusal**

| Claim | Location |
|---|---|
| Ingress Nack checks (point-to-point, PIT entry exists) | `ndn-rs/crates/forwarding/ndn-engine/src/dispatcher/pipeline.rs:366-383` |
| Strategy sees a refusal or unknown code as NoRoute | `ndn-rs/crates/forwarding/ndn-engine/src/dispatcher/pipeline.rs:457-468` |
| Failover sends no Nack | `ndn-rs/crates/forwarding/ndn-engine/src/dispatcher/pipeline.rs:476-506` |
| Relay: kept only from a local upstream, else NoRoute; refusal to local downstreams only; no PitToken | `ndn-rs/crates/forwarding/ndn-engine/src/dispatcher/pipeline.rs:508-541` |

**Consumers**

| Claim | Location |
|---|---|
| `AppError::Refused` message and `from_nack` | `ndn-rs/crates/app/ndn-app/src/error.rs:16-35`, `66-74` |
| Pairing a Nack by its enclosed Interest's name | `ndn-rs/crates/app/ndn-app/src/consumer.rs:385-389` |
| Segment replies | `ndn-rs/crates/app/ndn-app/src/consumer.rs:130-159` |
| `fetch_with_retry` (final stops; back-off guidance) | `ndn-rs/crates/app/ndn-app/src/consumer.rs:553-584` |
| Segmented fetch: final stops, 176 retransmitted, reported at budget end | `ndn-rs/crates/app/ndn-app/src/consumer.rs:1015-1025`, `1078-1080` |
| Object fetch retry | `ndn-rs/crates/app/ndn-app/src/consumer.rs:1109-1135` |
| `ndn-peek` exit code 3, `refused: <token>`, finality line | `ndn-fwd/binaries/tooling/ndn-tools/src/peek.rs:5-22`, `107-112`; `ndn-fwd/crates/tooling/ndn-tools-core/src/peek.rs:55-101` |
| Context sync: final means Refused, otherwise Missing | `ndn-fwd/binaries/ndn-fwd/src/context_sync.rs:584-603` |
| Context update fetch: final means Dropped | `ndn-rs/crates/security/ndn-cert/src/context_update.rs:798-810` |
| Renewal: 176 means CA unreachable | `ndn-rs/crates/security/ndn-cert/src/renewal.rs:177-186` |
| Mobile FFI `NdnError::Refused {refusal, final_verdict, hint}` | `ndn-mobile/crates/ndn-boltffi/src/types.rs:551-556` |
| Engine integration tests | `ndn-rs/crates/forwarding/ndn-engine/tests/local_refusal.rs:189-304` |
| Operator-level description | `ndn-rs/docs/wiki/src/inside/architecture/security-model.md:196-247` |
