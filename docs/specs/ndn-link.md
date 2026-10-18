# ndn-link/1: QUIC links between NDN forwarders

- **Status:** Draft
- **Scope:** This spec covers the wire protocol and the admission rules of a *link*: a QUIC connection between two NDN forwarders. Each device is identified by its NDN key, which it presents in TLS 1.3 as an RFC 7250 raw public key. The spec defines:
  - the handshake, the key fingerprint, and the link messages (LinkHello, LinkVerdict, EnrollmentLink);
  - how NDN packets are framed in QUIC datagrams, and the timeouts;
  - the close reason codes;
  - admission and enrollment-link scope, routes, the duplicate-link rule, backoff and rate limits.

  The goal is an independent implementation (NDNts, python-ndn, …) that can dial an ndn-fwd link and accept one from ndn-fwd.
- **Design context:** [personal-namespace.md](personal-namespace.md) §9 ("QUIC links"), F6 and F11. Where the two disagree on wire detail, this spec governs.
- **Related specs:** [trust-context.md](trust-context.md) (link policy, revocations, CA endpoints, validation), [ndncert-extensions.md](ndncert-extensions.md) (what an enrollment link carries), [trust-envelope.md](trust-envelope.md), [recovery-kit.md](recovery-kit.md), [local-refusal.md](local-refusal.md).

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 ([RFC 2119], [RFC 8174]) when, and only when, they appear in all capitals, as shown here.

The normative text describes what ndn-rs does today: crate `ndn-face-quic` (ndn-ext) for the transport and messages, and crate `ndn-link` (ndn-ext) for admission, enrollment links, routes, redial and the duplicate-link rule. ndn-fwd is a host of `ndn-link`: it supplies the configuration, the certificates it serves and its faces and RIB. Points where the code was ambiguous or looked unintended were decided; the [Decisions](#16-decisions) say how and why. All byte-level claims are traced to code in [Appendix A](#appendix-a-code-references-non-normative).

---

## 1. Terminology

| Term | Meaning |
|---|---|
| link | A QUIC connection between two forwarders, admitted by both sides under this spec. It becomes one NDN face on each side. |
| dialer / listener | The QUIC client / server of a link. |
| link key | The device's NDN signing key (Ed25519 or ECDSA P-256), used as the TLS raw public key of the link. |
| NDN public key | The key as an NDN certificate's `Content` carries it, after the normalization in §3.2: the raw 32 bytes for Ed25519, the DER SubjectPublicKeyInfo for P-256. |
| fingerprint | SHA-256 of the NDN public key (§3.3). |
| expected fingerprint | A fingerprint the operator configured for a peer (`[[peer]] key`). A dial that has one fails unless the listener presents exactly that key. |
| namespace | A personal namespace `/<ns>`. Its devices are named `/<ns>/<role>/<device>`, with role ∈ {`admin`, `member`, `node`, `guest`}. |
| trust context | The signed object that defines a namespace's anchors, revocations, CA endpoints and link policy ([trust-context.md](trust-context.md)). A device *holds* a namespace when it has adopted that namespace's trust context. |
| link policy | The trust context field (LinkPolicy, TLV 0x0412) that says which roles may link, which may relay, and whether enrollment links are admitted (§7.4). |
| relay | A forwarder that other devices link to and reach each other through. For link policy purposes, a device holding a certificate whose role the link policy lets relay. |
| enrollment link | A link admitted with a *scope*: it carries only one device's enrollment in the listed namespaces (§8). |
| full link | A link without a scope. |
| route | A FIB/RIB entry that sends a prefix over a link's face, with a cost (§10). |
| enroll | Obtain a certificate `/<ns>/<role>/<device>/KEY/…` from the namespace's CA (invite or approval; see [ndncert-extensions.md](ndncert-extensions.md)). |
| `[[peer]]` | ndn-fwd's configuration entry for a peer device. Its fields are `key` (expected fingerprint), `device` (expected device name), `endpoint`, `relay`, `routes`, `persistent` and `reliability`. Other implementations need an equivalent; only its effect on the wire is normative. |

TLV notation follows the NDN Packet Format v0.3: TLV-TYPE and TLV-LENGTH are VAR-NUMBERs; `0xFD xx xx` is the 3-byte form.

## 2. Protocol overview

```
dialer                                              listener
  | QUIC v1 Initial ... TLS 1.3, ALPN "ndn-link/1",     |
  | raw public keys both ways (client auth mandatory)   |
  |<--------------------------------------------------->|  §3
  | open bidi stream 0 (control stream)                 |
  | LinkHello (0x0450) -------------------------------> |  §5.2
  | <------------------------------- LinkHello (0x0450) |
  |        each side decides admission (§7)             |
  | LinkVerdict (0x0452) -----------------------------> |  §5.3 (sent concurrently;
  | <----------------------------- LinkVerdict (0x0452) |       or CONNECTION_CLOSE, §6)
  | FIN on control stream            FIN on control stream
  | NDNLPv2 frames in QUIC DATAGRAM frames, both ways   |  §9
```

## 3. Transport and TLS identity

### 3.1 QUIC and TLS parameters

1. The connection MUST be QUIC version 1 ([RFC 9000]) secured with TLS 1.3 ([RFC 9001], [RFC 8446]). Other TLS versions MUST NOT be offered or accepted.
2. ALPN ([RFC 7301]): the dialer MUST offer exactly the protocol ID `ndn-link/1` (ASCII, 10 bytes: `6e 64 6e 2d 6c 69 6e 6b 2f 31`). The listener MUST select it, and MUST fail any handshake that does not offer it. ndn-rs listeners speak no other protocol on a link socket.
3. The dialer MUST NOT send SNI. ndn-rs uses the internal server name `ndn-link`, which nothing checks and which is not sent. Listeners MUST NOT depend on SNI.
4. Session resumption and 0-RTT MUST NOT be used. Each link proves its keys with a full handshake. ndn-rs listeners issue no session tickets and accept no early data; ndn-rs dialers disable resumption.
5. Both sides MUST advertise the `max_datagram_frame_size` transport parameter ([RFC 9221]) with a non-zero value. ndn-rs advertises 65535. A side whose peer does not support datagrams closes the link with code 0x15 (Protocol) before sending its verdict (§5.4).
6. Streams: each side MUST allow its peer at most one bidirectional stream (`initial_max_streams_bidi` = 1) and SHOULD allow no unidirectional streams (`initial_max_streams_uni` = 0); ndn-rs sends exactly these values. Only the dialer opens a stream (§5.1).
7. Timers (ndn-rs values; other implementations SHOULD use the same):

   | Parameter | Value | Note |
   |---|---|---|
   | `max_idle_timeout` | 30 000 ms | QUIC transport parameter |
   | Keep-alive (PING when idle) | every 10 s | keeps NAT bindings open |
   | Dial handshake timeout | 5 s | a dial with no completed handshake by then fails; QUIC ignores ICMP, so this is the only fast failure for an address where nothing listens |

8. Cipher suites and key exchange are those of the rustls *ring* provider. Suites: `TLS_AES_256_GCM_SHA384`, `TLS_AES_128_GCM_SHA256`, `TLS_CHACHA20_POLY1305_SHA256`. Groups: X25519, secp256r1, secp384r1. An implementation MUST support at least `TLS_AES_128_GCM_SHA256` together with X25519 or secp256r1.

### 3.2 Link keys as raw public keys

A link key MUST be Ed25519 or ECDSA P-256; these are the two NDN device key types. Both sides MUST use RFC 7250 raw public keys and nothing else:

- The dialer MUST send `client_certificate_type` and `server_certificate_type` offering only `RawPublicKey` (2). The listener MUST select `RawPublicKey` for both.
- The listener MUST request client authentication (CertificateRequest), and the dialer MUST answer with its raw public key. A dialer without one fails the handshake.
- Each TLS `Certificate` message MUST carry exactly one entry. Its `cert_data` is the DER SubjectPublicKeyInfo (SPKI) of the link key, encoded byte-exactly as follows (any other encoding is refused):

  | Key type | SPKI length | SPKI bytes |
  |---|---|---|
  | Ed25519 ([RFC 8410]) | 44 | `30 2a 30 05 06 03 2b 65 70 03 21 00` ‖ 32-byte public key |
  | P-256 (id-ecPublicKey, prime256v1) | 91 | `30 59 30 13 06 07 2a 86 48 ce 3d 02 01 06 08 2a 86 48 ce 3d 03 01 07 03 42 00` ‖ `04` ‖ X (32) ‖ Y (32) |

  A P-256 key MUST use the uncompressed point (`04`).
- The CertificateVerify signature MUST be made with the link key using `ed25519` (0x0807) for an Ed25519 key or `ecdsa_secp256r1_sha256` (0x0403) for a P-256 key. Both sides MUST list exactly these two schemes in `signature_algorithms` and MUST NOT accept any other. TLS 1.2 signatures are refused.
- The **NDN public key** of a link key is defined as:
  - Ed25519: the 32 raw key bytes (the SPKI without its 12-byte prefix);
  - P-256: the whole 91-byte SPKI.

  This is the form ndn-rs compares with a certificate's public key. When ndn-rs decodes a certificate, a 44-byte `Content` that starts with the Ed25519 SPKI prefix is reduced to its 32 raw bytes, and any other non-empty `Content` is taken as is. NDN certificates MAY therefore carry an Ed25519 key either as an SPKI (as ndn-rs and ndn-cxx write it) or raw.

The TLS 1.3 CertificateVerify signs a context string that no NDN packet starts with, so the same key safely signs both TLS handshakes and NDN packets.

### 3.3 Key fingerprint

```
fingerprint = SHA-256( NDN public key )        ; 32 bytes
```

The exact input is the 32 raw bytes for Ed25519, and the 91-byte SPKI for P-256 (§3.2). This is the same fingerprint an anchor link uses for a namespace's root key ([trust-envelope.md](trust-envelope.md)), so a key's fingerprint reads the same everywhere it is shown.

- **Text form:** 64 lowercase hexadecimal digits. Parsers MUST accept upper- or lowercase and MAY trim surrounding whitespace; ndn-rs does both. A `[[peer]] key` MUST be 64 hex digits.
- **Order:** fingerprints are ordered as unsigned 32-byte big-endian strings, i.e. lexicographic by byte. This order is used by the duplicate-link rule (§11).

### 3.4 Checking the peer's key during the handshake

The handshake proves one thing only: the peer holds the private half of the key it presents. Admission (§7) happens after the handshake, from signed data.

- **Dialer:** MUST refuse a listener key that is not one of the forms in §3.2. If the dial has an expected fingerprint, the dialer MUST fail the handshake unless the listener's fingerprint equals it. No link message is exchanged with the wrong device. ndn-rs reports this locally as "unexpected key" and does not retry it as transient (§13).
- **Listener:** MUST refuse a dialer key not in the forms of §3.2. It makes no other check during the handshake.
- A device selects its link key at each handshake. A device that switches keys (for example after enrolling, §8.5) presents the new key on its next link.

## 4. Control stream

### 4.1 Stream use

1. After the handshake, the dialer opens the first client-initiated bidirectional stream (stream ID 0). This is the **control stream**.
2. Each direction of the control stream carries exactly two link messages, in this order: one LinkHello, then one LinkVerdict. Each message is one complete TLV with no other framing.
3. After it has written its LinkVerdict and read the peer's, a side finishes (FIN) its sending half. Nothing else is sent on the control stream. A receiver MUST NOT expect a FIN before the link is up, and MUST ignore any bytes after the verdict.
4. NDN packets never travel on a stream (§9).

### 4.2 Reading a message

1. A receiver reads the TLV-TYPE and TLV-LENGTH VAR-NUMBERs. If no complete header has arrived after 20 bytes, the message is malformed.
2. If TLV-TYPE is not the expected message (0x0450 for the first message, 0x0452 for the second), the message is malformed.
3. If TLV-LENGTH exceeds 65 536 (`MAX_MESSAGE`, 64 KiB, applied to the TLV-VALUE), the message is malformed.
4. Otherwise the receiver reads exactly TLV-LENGTH more bytes. A stream that ends early is malformed. If the connection closed, the peer's close reason is reported instead.

A sender MUST NOT send a message whose TLV-VALUE exceeds 65 536 bytes.

## 5. Link messages

All TLV-TYPEs are in the application range (types above 252, written as 3-byte VAR-NUMBERs). Inside LinkHello and LinkVerdict, a receiver MUST ignore an unrecognized TLV-TYPE that is even and greater than 31, and MUST treat any other unrecognized TLV-TYPE (odd, or in 0–31) as a malformed message. This is the rule of NDN Packet Format v0.3, where types 0–31 are always critical ([Decision 3](#16-decisions)).

### 5.1 TLV-TYPE registry

| TLV-TYPE | Name | Appears in | Value |
|---|---|---|---|
| 0x0450 | LinkHello | control stream, message 1 | LinkVersion, Data* |
| 0x0451 | LinkVersion | LinkHello | 1 byte: the protocol version, `0x01` |
| 0x0452 | LinkVerdict | control stream, message 2 | EnrollmentLink? |
| 0x0453 | (unassigned) | — | — |
| 0x0454 | EnrollmentLink | LinkVerdict | Name* |
| 0x06 | Data | LinkHello | a certificate Data packet, whole |
| 0x07 | Name | EnrollmentLink | a namespace Name |

### 5.2 LinkHello (0x0450)

```
LinkHello      = LINK-HELLO-TYPE TLV-LENGTH
                 LinkVersion
                 *Certificate
LinkVersion    = LINK-VERSION-TYPE TLV-LENGTH(=1) %x01
Certificate    = Data              ; NDN Certificate Format v2 Data packet
```

**Sender rules**

- MUST include exactly one LinkVersion, with a 1-byte value `0x01`, as the first element. ndn-rs writes it first.
- After LinkVersion come zero or more certificate Data TLVs, copied unchanged:
  - The first is the sender's own certificate for the key it presented in TLS (the *leaf*).
  - The rest are the issuers the sender keeps, nearest first (the leaf's issuer, then that certificate's issuer, …).
- A sender with no certificate for its link key (a device not enrolled anywhere, linked by expected fingerprint or on an enrollment link) sends LinkVersion only.
- How ndn-fwd builds the chain: it takes its newest currently valid certificate under the current key name. It then repeatedly takes the newest currently valid certificate under the key name in the previous certificate's KeyLocator (the certificate name without its last two components). It stops at a self-signed certificate (KeyLocator names the certificate's own key), at a certificate it does not keep, at a certificate already in the chain, or at **8 certificates in total**. A self-signed root that ndn-fwd keeps is therefore included as the last element.

**Receiver rules**

- Elements are processed in order:
  - LinkVersion: the value MUST be exactly one byte, the version. A value of any other length makes the hello malformed. If LinkVersion appears more than once, the last one wins.
  - Data (0x06): appended to the certificate list in order. The Data is not parsed at this stage.
  - Any other even type above 31: ignored.
  - Any other type (odd, or 0–31): malformed.
- If no version is present, the hello is malformed.
- If the version is present and ≠ 1, the receiver MUST NOT admit the link. ndn-rs logs that the peer speaks a different version and asks the user to update the older device.
- A receiver uses the leaf and at most the **first 8** issuer certificates (`MAX_CHAIN` = 8) and ignores the rest.

### 5.3 LinkVerdict (0x0452) and EnrollmentLink (0x0454)

```
LinkVerdict    = LINK-VERDICT-TYPE TLV-LENGTH
                 [EnrollmentLink]
EnrollmentLink = ENROLLMENT-LINK-TYPE TLV-LENGTH
                 *Name             ; each a namespace, e.g. /home
```

- **Meaning.** Sending a LinkVerdict means the sender **admits** the link. A refusal is never a verdict; the refusing side closes the connection instead (§6).
- **Without EnrollmentLink:** the sender admits a full link.
- **With EnrollmentLink:** the sender admits the link only as an enrollment link (§8). Over it, the sender carries only the receiver's enrollment in the listed namespaces: their CA, their trust context and certificates. This lasts until the receiver links again holding a certificate.
  - An EnrollmentLink MUST list at least one Name. An empty EnrollmentLink makes the verdict malformed ([Decision 4](#16-decisions)). A relay with no eligible namespace refuses instead (§7.3 rule 4).
- **Receiver rules:**
  - Inside EnrollmentLink, every element MUST be a Name (0x07). Any other type makes the message malformed.
  - Each Name value is decoded as an NDN Name.
  - If EnrollmentLink appears more than once, the last one wins.
  - Other elements of LinkVerdict follow the even/odd rule of §5.
- **What the verdict changes.** The peer's verdict changes how the receiver explains the link and when it relinks (§8.5). It does not change what the receiver forwards: the scope is enforced by the side that set it, on its own face, in both directions (§8.3).

### 5.4 Exchange sequence and deadlines

`MESSAGE_DEADLINE` = 10 s.

1. **Hello exchange.** This step as a whole MUST complete within `MESSAGE_DEADLINE` on each side.
   - The dialer opens the control stream, writes its LinkHello, then reads the listener's.
   - The listener accepts the stream, reads the dialer's LinkHello completely, and only then writes its own.
2. **Decision.** Each side decides admission (§7) from the peer's TLS key and LinkHello.
   - A side that refuses closes the connection with a close reason (§6) and sends no verdict.
   - Before admitting, a side checks that the peer supports QUIC datagrams. If not, it closes with 0x15 (Protocol).
3. **Verdict exchange.** Each side that admits writes its LinkVerdict, then reads the peer's. This step as a whole MUST complete within `MESSAGE_DEADLINE`. Both sides write without waiting for each other.
   - The deadline also bounds the decision: a side SHOULD send its verdict within `MESSAGE_DEADLINE` of receiving the peer's hello, because the peer is already waiting.
   - If the peer closes the connection instead of sending a verdict, the reason is the peer's close reason.
4. **Up.** The link is up once a side has written its verdict and read the peer's.
   - From then on it carries NDN packets (§9). A side MUST NOT send NDN datagrams before this point.
   - Datagrams that arrive before this point are buffered by the QUIC stack (ndn-rs: up to 4 MiB) and delivered once the face starts reading.
5. **Duplicate check.** After the link is up, the duplicate-link rule (§11) may close it at once with 0x01 (Replaced).

A side that receives a malformed message or an unsupported LinkVersion, or whose peer misses a `MESSAGE_DEADLINE`, does not admit the link. It closes the connection with 0x15 (Protocol) and a reason (§6.3).

## 6. Closing a link

### 6.1 Close reason codes

A side closes a link with a QUIC `CONNECTION_CLOSE` of type 0x1d (application). Its Error Code is one of the codes below, and its Reason Phrase is a UTF-8 sentence for the person reading the other side's log. That sentence SHOULD say what to do. It is not machine-readable.

| Code | Name | Sent when | Transient |
|---|---|---|---|
| 0x00 | Shutdown | The device is shutting down. ndn-fwd closes every link with it, then waits up to 1 s for the peer to be told. | yes |
| 0x01 | Replaced | A newer link between the same two devices took this link's place (§11). | yes |
| 0x02 | Idle | An enrollment link carried nothing for `ENROLLMENT_IDLE` (§8.4). | yes |
| 0x03 | Enrolled | The device enrolled. It closes its enrollment link and links again holding its certificate (§8.5). | yes |
| 0x10 | Unrecognized | The key has no valid certificate in a namespace the closing side holds, no `[[peer]]` expects its fingerprint, and no enrollment link is possible. | no |
| 0x11 | CertificateForAnotherKey | The leaf certificate in the hello certifies a different key than the one the handshake proved. | no |
| 0x12 | Revoked | The leaf, or a sent issuer, is revoked by a held trust context. Also sent when a revocation is adopted while the link is up (§12). | no |
| 0x13 | RoleNotAllowed | The namespace's link policy does not let the peer's role link, or does not let it relay when this side reaches others through it. | no |
| 0x14 | NotTheExpectedDevice | The peer is valid, but not the device or key a `[[peer]]` entry expects. | no |
| 0x15 | Protocol | A link message is malformed or carries another LinkVersion, the peer sent no link message within `MESSAGE_DEADLINE` (§6.3), a certificate in the hello does not decode, the peer does not support datagrams, or the peer misbehaved. | no |
| 0x16 | Busy | Too many link attempts (§13), or too many enrollment links (§8.4). | yes |
| 0x17 | NoLinkKey | This device has no usable link key. | yes¹ |

¹ ndn-rs never sends 0x17 on the wire. A device without a link key cannot complete a handshake.

The **Transient** column drives the dialer's backoff (§13):
- a transient close is retried with exponential backoff;
- a non-transient close means "refused until the trust data or the configuration changes".

A received code not in this table MUST be treated as transient.

### 6.2 Refusal before the handshake

A listener over its handshake limits (§13.2) refuses an Initial with the QUIC transport error `CONNECTION_REFUSED` (0x02). Dialers SHOULD treat this like application code 0x16 (Busy). ndn-rs does.

### 6.3 Failed exchange

A side whose hello or verdict exchange fails MUST close the connection with 0x15 (Protocol) and a reason phrase that says what went wrong. Failures are a malformed message (§4.2, §5), an unsupported LinkVersion, and a missed `MESSAGE_DEADLINE` (§5.4). For a version mismatch the reason names both versions and asks the user to update the older device. A listener counts the close against the source like any refusal (§13.2).

A side MUST NOT just drop the connection. A QUIC stack then closes it with application code 0x00 and an empty reason phrase, which the peer reads as Shutdown (transient) and redials at once ([Decision 1](#16-decisions)).

ndn-rs versions before this rule dropped the connection. A receiver therefore MUST NOT read 0x00 with an empty reason as proof of an orderly shutdown. ndn-rs treats it as transient (§13.1).

## 7. Admission

Admission is decided by each side independently, after the hello exchange. Inputs:

- the peer's NDN public key and fingerprint, from TLS;
- the peer's LinkHello;
- the side's held trust contexts;
- the side's configured peers;
- whether this side dialed the link, and for which `[[peer]]`.

The rules below are those of the `ndn-link` crate, which ndn-fwd uses. An implementation that wants ndn-fwd peers to behave predictably MUST NOT admit a link that these rules refuse, and MUST use the close codes given here. It MAY refuse more.

### 7.1 Identifying the peer from its hello

Before these steps, a side that knows a certificate of the peer's key MUST refuse with **0x12** if a held trust context revokes that certificate, whatever the hello carries. "Knows" means a certificate it serves or has cached whose public key is the peer's NDN public key; ndn-rs looks it up by the key's SHA-256 fingerprint. A revoked device that sends no certificate therefore gets no enrollment link either. A key the side knows no certificate of cannot be told from a new key, because a revoked device can always make one. For such keys the CA, which refuses to certify a revoked device again, is the backstop ([Decision 5](#16-decisions)).

Steps, in order. *Unknown(why)* means "no namespace identity". It is not a refusal: an expected fingerprint or an enrollment link may still admit the peer.

1. If the hello carries no certificate: **Unknown**.
2. Decode the leaf as a Data packet, then as a certificate. On failure, refuse with **0x15**.
3. If the leaf's public key (normalized per §3.2) ≠ the peer's NDN public key, refuse with **0x11**. The comparison is byte by byte, so a certificate MUST carry a P-256 key as the uncompressed-point SPKI of §3.2 ([Decision 12](#16-decisions)).
4. Find the held trust context whose namespace is the longest prefix of the leaf's name. If there is none: **Unknown**.
5. If the context revokes the leaf, refuse with **0x12**. A revocation entry covers every name it is a prefix of, so revoking a key name covers all of its certificates ([trust-context.md](trust-context.md)).
6. The leaf's name MUST be a device key name `/<ns>/<role>/<device>/KEY/<key-id>[/…]`, where:
   - `<role>` is a GenericNameComponent (0x08) equal to `admin`, `member`, `node` or `guest`;
   - `<device>` is a GenericNameComponent of 1–63 bytes from `[A-Za-z0-9._-]`, starting with a letter or digit, and not `KEY`, `CA` or a role word (in any case);
   - the component after `<device>` is the GenericNameComponent `KEY`.

   Otherwise: **Unknown**.
7. If the leaf is not within its ValidityPeriod now: **Unknown**.
8. Decode the first `MAX_CHAIN` (8) issuers. If any fails to decode, refuse with **0x15**.
9. If the context revokes any of those issuers, refuse with **0x12**.
10. Validate the leaf in the held trust context ([trust-context.md](trust-context.md): chain to an anchor, schema, hierarchical rule), with a chain depth of at most 8.
    - Issuers come from the hello first. A missing issuer may then be taken from certificates the side itself serves or has cached.
    - The side MUST NOT fetch anything (the link is not up yet). It also MUST NOT add the peer's certificates to its general certificate cache.
    - If validation fails or the chain is incomplete: **Unknown**.
11. Otherwise the peer is the device `/<ns>/<role>/<device>` of namespace `/<ns>`. The leaf and issuer names are remembered for §12.

### 7.2 Configured peers

A configured peer has an optional expected fingerprint (`key`) and an optional expected device name (`device`); at least one is present. The **peer entry** for a link is:

- the `[[peer]]` this side dialed, for a dialed link;
- otherwise the first `[[peer]]` whose `key` equals the fingerprint, or whose `device` equals the identified device name.

*key-expected* means a peer entry exists and its `key` equals the fingerprint.

### 7.3 Decision

Rules are evaluated in order. The first that applies decides.

1. If a peer entry exists and has a `key` that ≠ the fingerprint: refuse **0x14**.
2. If a peer entry exists and has a `device`:
   - If the peer was identified as a different device: refuse **0x14**.
   - If the peer is Unknown and not key-expected:
     - If this side dialed the link, and holds no certificate (for the key it links with now) in `ns`, admit as a **device-side enrollment link** for `ns` (§8.2). Here `ns` is the held namespace that is the longest prefix of the expected device name; if none is held, it is the expected device name without its last two components.
     - Otherwise refuse **0x10**.
3. If the peer was identified in a namespace, look up that namespace's link policy (§7.4):
   - If the policy does not allow the peer's role to link: refuse **0x13**.
   - If the peer entry is a relay for another `[[peer]]` (another entry names it in `relay`), and the policy does not allow the peer's role to relay: refuse **0x13**.
4. If the peer is Unknown and not key-expected:
   - If the link was not dialed by this side, has no peer entry, and this side is eligible to relay enrollments (§8.1), admit as a **relay-side enrollment link**. If no enrollment slot is free, refuse **0x16** instead (§8.4).
   - Otherwise refuse **0x10**.
5. Otherwise admit a **full link**. This covers a peer identified in a namespace, and a key-expected peer whether identified or not.

A revoked key or issuer is refused in §7.1 before any of these rules, so it never reaches an enrollment link through them. This includes a peer that sends no certificate, when the side knows a revoked certificate of its key (§7.1).

### 7.4 Link policy semantics

The link policy is defined in [trust-context.md](trust-context.md) (TLV 0x0412, UTF-8 `<roles>;<relay roles>;<enrollment|no-enrollment>`). It has three fields:

- `roles`: a list of role words. Empty means every role.
- `relay_roles`: a list of role words.
- `enrollment_links`: a boolean.

A context that carries no link policy uses the default: `roles` = [] (any role), `relay_roles` = [`node`], `enrollment_links` = true.

- A role *may link* iff `roles` is empty or contains it.
- A role *may relay* iff it may link and `relay_roles` contains it.
- A context *admits enrollment links* iff `enrollment_links` is true and the context names at least one CA endpoint.

## 8. Enrollment links

An enrollment link lets a device that is reachable only over QUIC enroll. It carries the device's Interests for the namespace's CA endpoints, trust context and certificates, and the answers to them. Nothing else crosses it, in either direction.

### 8.1 Relay side

A side is eligible to relay enrollments for namespace `ns` when all of these hold for a held context of `ns`:

- the link policy has `enrollment_links` = true;
- the context names at least one CA endpoint;
- the side's current certificate is a device certificate in `ns` whose role the policy lets relay.

The relay's LinkVerdict carries an EnrollmentLink listing **every** namespace it is eligible for, in no defined order. Its face scope (§8.3) is:

| | |
|---|---|
| receives from the device | Interests only |
| sends to the device | answers only (Data and Nacks) |
| name filter | `in_enrollment(namespaces, name, relay = true)` |
| receive rate limit | `ENROLLMENT_INTERESTS` (burst 32, 4/s) |

The relay installs **no routes** over an enrollment link. Answers return the way their Interests came.

### 8.2 Device side

A device that dialed a `[[peer]]` naming a device in namespace `ns`, where it holds no certificate in `ns`, cannot confirm that peer yet, so it admits the link as an enrollment link for `ns` only (rule 7.3-2). Its LinkVerdict is a full verdict (no EnrollmentLink). Its face scope is:

| | |
|---|---|
| receives from the relay | answers only (Data and Nacks) |
| sends to the relay | Interests only |
| name filter | `in_enrollment([ns], name, relay = false)` |
| receive rate limit | `ENROLLMENT_ANSWERS` (burst 512, 128/s) |

It installs one route, `ns` at cost 0, over the link. A device that is admitted on an enrollment link by the relay's verdict, but admitted the link fully itself, applies no scope of its own; the relay's scope still holds.

### 8.3 Scope rules

**Name filter.** `in_enrollment(namespaces, name, relay)` is true iff, for some `ns` in `namespaces`, all of these hold:

1. `name` has prefix `ns` (component-wise, types included);
2. on the relay side: the held context of `ns` currently admits enrollment links (§7.4). The relay re-checks this for every packet, so a policy change takes effect at once;
3. at least one of:
   - `name` has prefix `ns` + KeywordNameComponent (0x20) `trust-context`, i.e. `/<ns>/32=trust-context`, the trust context and its RDR metadata ([trust-context.md](trust-context.md));
   - `name` has prefix one of the CA endpoint Names the held context of `ns` lists;
   - the components of `name` after `ns` contain a GenericNameComponent (0x08) `KEY`, and the **first** such component is followed by 1–3 further components. This matches `…/KEY/<key-id>`, `…/KEY/<key-id>/<issuer-id>` and `…/KEY/<key-id>/<issuer-id>/<version>`.

Examples for `ns` = `/home`, with CA endpoint `/home/CA`:

| Name | Carried |
|---|---|
| `/home/32=trust-context/…` | yes |
| `/home/CA/NEW`, `/home/CA/CHALLENGE/abc` | yes |
| `/home/member/phone/KEY/k1/NDNCERT/v=1` | yes |
| `/home/KEY/root` | yes |
| `/home/member/phone/album` | no |
| `/home/member/phone/KEY` (nothing after `KEY`) | no |
| `/home/member/phone/files/KEY/a/b/c/d` (4 after `KEY`) | no |
| `/elsewhere/CA/NEW` | no |

**Judging frames.** The scope judges each NDNLPv2 frame (§9) as it crosses the face, in both directions. Received frames are rate-limited before they are judged.

1. A frame whose outer TLV-TYPE is not LpPacket (0x64) is judged as a whole network packet.
2. An LpPacket without a Fragment field (an Ack-only or idle frame) **passes**, and does not count as activity.
3. An LpPacket with FragCount > 1:
   - FragIndex > 0: the frame passes iff the first fragment of its packet passed. The packet is identified by `Sequence − FragIndex`; the scope remembers the last 32 passed packets per direction. Otherwise it is dropped.
   - FragIndex = 0: judged by the packet head inside the fragment.
4. Otherwise the frame is judged by its whole fragment.
5. A network packet's kind is decided as follows:
   - Interest if its outer type is 0x05;
   - Data if 0x06;
   - Nack if the LpPacket carries a Nack header (0x0320), whatever the fragment type.
   
   Its name is the first element, which MUST be a Name. Any other shape is dropped.
6. The frame passes iff both hold:
   - its kind is what that direction carries: Interests for an Interest direction; Data or Nack for an answer direction;
   - the name filter accepts its name.

   Otherwise it is dropped.
7. **Nack.** When a scope drops a *whole* Interest, it answers immediately with an LpPacket Nack, reason NoRoute (150), carrying that Interest:
   - an Interest received from the peer is Nacked to the peer, in a QUIC datagram;
   - an Interest this side would send is Nacked back to this side's forwarder.

   A dropped Interest first fragment, or any other dropped frame, is dropped silently.

**Rate limit.** This is a token bucket per link, on received frames only. It starts full at `burst` tokens and refills continuously at `per_sec` tokens per second, up to `burst`. Every received frame that carries a network packet or a fragment of one costs one token. A frame with no Fragment (an Ack-only or idle frame, rule 2) costs nothing, so the peer's acknowledgements of the fragments this side sends cannot crowd out the peer's packets ([Decision 7](#16-decisions)). A frame that finds no token is dropped without a Nack.

### 8.4 Slots and idle close (relay side)

- A relay holds at most `ENROLLMENT_LINKS_MAX` = 32 enrollment links at once, and at most `ENROLLMENT_LINKS_PER_SOURCE` = 4 from one source IP address (several devices may enroll behind one NAT).
- A relay that is out of slots refuses with **0x16** after deciding and before sending its verdict. A slot is released when the link ends.
- **Idle close.** If a relay-side enrollment link passes no packet (rule 2 frames excluded) for `ENROLLMENT_IDLE` = 120 s, the relay closes it with **0x02**.
  - 120 s is twice `MAX_STATUS_HOLD` (60 s), so a device waiting for an approval keeps its link ([ndncert-extensions.md](ndncert-extensions.md)).
  - ndn-fwd checks every 30 s (`ENROLLMENT_IDLE / 4`), so the close happens 120–150 s after the last packet.
  - The device side applies no idle close.

### 8.5 Relink after enrollment

Each side records, per link, the namespaces the link is an enrollment link for *on this device's behalf*. These are:

- the namespaces in the peer's EnrollmentLink; and
- `ns`, if this side admitted the link as a device-side enrollment link.

When the device switches to another key (it enrolled), it checks each such link. If its new current certificate is a device certificate in one of the recorded namespaces, it closes that link with **0x03** (Enrolled) and dials that `[[peer]]` again once, even if the peer is not persistent. It now presents its certificate and gets a full link.

## 9. NDN packets: datagram framing

1. NDN packets MUST travel in QUIC DATAGRAM frames ([RFC 9221]). Each datagram payload is exactly one NDNLPv2 frame: one LpPacket (0x64) TLV. No stream carries NDN packets, so there is no head-of-line blocking.
2. **Sending.**
   - A packet whose length + 4 ≤ the connection's current maximum datagram payload goes out as `LpPacket { Fragment(0x50) = packet }`. Other LP headers (for example a Nack 0x0320) come before the Fragment, in increasing TLV-TYPE order, per NDNLPv2.
   - A larger packet is fragmented per NDNLPv2:
     - every fragment carries Sequence (0x51, an 8-byte NonNegativeInteger), FragIndex (0x52) and FragCount (0x53);
     - Sequences are consecutive within a packet (`Sequence − FragIndex` is the same for every fragment) and unique on the link;
     - ndn-rs sizes each fragment's payload as `max_datagram − 50` (minus 10 bytes per piggybacked Ack).
   - The maximum datagram payload is the QUIC connection's current value, which grows as path MTU discovery finds room. If the QUIC stack cannot report it, ndn-rs uses 1100 bytes (`DATAGRAM_FLOOR`).
   - If the path shrinks between framing and sending, the oversized frame is dropped, as on any datagram link.
3. **Reliability.**
   - ndn-rs fragments always carry a TxSequence (0x0348), and ndn-rs retransmits unacknowledged fragments.
   - When `[[peer]] reliability = true`, every frame carries a TxSequence. The retransmit tuning is `ReliabilityConfig::ethernet()`: QUIC-style RTO, 1 retry, 256 unacknowledged frames.
   - A receiver SHOULD acknowledge each TxSequence it receives with Ack (0x0344) headers, either piggybacked or in an Ack-only LpPacket. It MUST tolerate retransmitted duplicates. ndn-rs drops a duplicate before reassembly and forwarding.
4. **Receiving.** A receiver MUST accept LpPackets with or without TxSequence, Sequence, FragIndex and FragCount, and MUST reassemble fragments keyed by `Sequence − FragIndex`. It SHOULD also accept a datagram that is a bare Interest or Data TLV; the enrollment-link scope does.
5. Other NDNLPv2 fields follow the ndn-rs NDNLPv2 implementation for non-local faces. Examples are Nack 0x0320 / NackReason 0x0321, PitToken 0x62, and CongestionMark. A link face is a non-local face, so it never carries LocalFields.

## 10. Routes

When a link is up, the admitting side installs routes over its face. These are static origin, with flag CHILD-INHERIT and no expiry:

| Link | Routes (prefix, cost) |
|---|---|
| relay-side enrollment link | none |
| device-side enrollment link for `ns` | (`ns`, 0) |
| full link | the peer's *default routes* at cost 0, plus, for every `[[peer]]` X whose `relay` names this link's peer entry, X's default routes at cost `VIA_RELAY_COST` = 10 |

**Default routes** of the peer entry P, given the identified peer (if any), are the first of these that applies:

1. P's `routes`, if configured;
2. `/<ns>` of the identified peer, if it is a `node` device and P is a peer this side dials, meaning the host gives P at least one path candidate (§13.1). This holds whichever side dialed this link: when both dial, the duplicate-link rule keeps one link (§11), and both sides still route the same way. A `node` whose peer entry this side does not dial (it only accepts that node's links) falls to rule 3 ([Decision 8](#16-decisions));
3. the identified peer's device name `/<ns>/<role>/<device>`;
4. P's `device`, if the peer was not identified;
5. otherwise none.

For a peer reached through a relay, the default routes are computed from that peer's own entry with no identity, so they are its `routes`, else its `device`.

A direct link to a peer costs 0. A route through a relay costs 10, so the direct link wins while it is up.

## 11. Duplicate-link rule

Between two devices there is at most one link, keyed by the peer's fingerprint.

When a link to a fingerprint is up and another link to the same fingerprint comes up, the side compares them:

- **Both sides dialed each other** (the two links have opposite directions on this side): the link **dialed by the device with the smaller fingerprint** (§3.3 order) stays. The other is closed with **0x01** (Replaced).
- **Same direction** (the peer dialed again after losing the old link, or this side redialed): the **newer** link stays and the older is closed with **0x01**.

Both sides apply the rule independently, after the link is up (§5.4 step 5). For the opposite-direction case they reach the same result. A side whose own fingerprint is unavailable treats every duplicate as same-direction ([Decision 11](#16-decisions)). The rule is `ndn_link::keeps_existing(existing direction, new direction, own fingerprint, peer fingerprint)`, which returns whether the link already in place stays.

Example with the test keys of §15: the P-256 key's fingerprint `0ca9…` is smaller than the Ed25519 key's `3475…`, so if they dial each other at once, the link the P-256 device dialed stays.

## 12. Revocation while linked

When a side adopts a trust context version, it checks every up link whose identified device lies under that context's namespace. If any recorded certificate name of the link (the leaf or an issuer sent in the hello, §7.1 step 11) is revoked by the new version, the side closes the link at once with **0x12**.

A link admitted only by expected fingerprint (no identity) is not affected. It ends when the operator removes the `[[peer]] key`.

## 13. Dialing, backoff and inbound limits

### 13.1 Dialing and backoff

- A peer is dialed at startup if the host gives it at least one path candidate. A candidate is either a socket address or a `host:port` endpoint; ndn-fwd gives the `[[peer]] endpoint` list. Each attempt tries the candidates in order, and each endpoint's resolved addresses in order. The first address that yields a link wins; otherwise the attempt fails with the last error.
- A dial carries the `[[peer]]` `key` as its expected fingerprint, if one is set (§3.4).
- If the peer is already linked (it dialed this side), the dialer waits for that link to end instead of dialing.
- `persistent` (default true) peers are redialed:

  | After | Wait before redial |
  |---|---|
  | an up link ended (any reason) | `BACKOFF_FIRST` = 500 ms |
  | a failure that is transient | starts at 500 ms and doubles after each consecutive failure, up to `BACKOFF_MAX` = 30 s; reset by a successful link |
  | a failure that is not transient | `BACKOFF_REFUSED` = 60 s |

- A non-persistent peer is not redialed after its link ends or a dial fails. The exception is the one redial after 0x03 (§8.5).
- A failure is **non-transient** if any of these holds:
  - the peer closed with a non-transient code (§6.1), including 0x15 after a failed exchange (§6.3);
  - this side refused with one, including 0x15 after the peer's malformed message or unsupported LinkVersion;
  - the handshake failed on an unexpected key (§3.4);
  - TLS configuration failed;
  - there is no local link key.

  Every other failure is **transient**: connect and handshake timeouts, an unreachable address, a `MESSAGE_DEADLINE` the peer missed (this side closes with 0x15, but the peer may only be slow), the transport-level refusal of §6.2, or an unknown or 0x00 code.

### 13.2 Inbound handshake limits

A listener bounds the inbound connections that have not been admitted yet. A source counts as "in flight" from the Initial until its link is admitted or refused.

| Limit | Value |
|---|---|
| in flight in total | 64 |
| in flight per source IP | 4 |
| refusals of one source IP within the refusal window before a cooldown | 8 |
| refusal window | 60 s |
| cooldown | 60 s |

- An attempt over a limit, or from a source in cooldown, is refused before its handshake (§6.2).
- When at least half the total (32) are in flight, the listener first sends a QUIC Retry to any source whose address is not yet validated.
- A refusal counts against the source when its handshake fails, when admission refuses it with a close code, or when its hello or verdict exchange fails (§6.3). Refusals older than the refusal window are forgotten: the count starts again at the first refusal after the window of the previous first refusal ends. It also resets when it reaches the threshold and the cooldown starts ([Decision 9](#16-decisions)).

## 14. Constants

| Name | Value | Section |
|---|---|---|
| ALPN | `ndn-link/1` | §3.1 |
| LinkVersion | 1 | §5.2 |
| `MAX_MESSAGE` | 65 536 bytes (TLV-VALUE) | §4.2 |
| message header read limit | 20 bytes | §4.2 |
| `MESSAGE_DEADLINE` | 10 s (hello exchange; verdict exchange) | §5.4 |
| dial handshake timeout | 5 s | §3.1 |
| QUIC idle timeout / keep-alive | 30 s / 10 s | §3.1 |
| `MAX_CHAIN` | 8 issuers validated; 8 certificates sent | §5.2, §7.1 |
| `VIA_RELAY_COST` | 10 | §10 |
| `BACKOFF_FIRST` / `BACKOFF_MAX` / `BACKOFF_REFUSED` | 500 ms / 30 s / 60 s | §13.1 |
| `ENROLLMENT_LINKS_MAX` / `_PER_SOURCE` | 32 / 4 | §8.4 |
| `ENROLLMENT_IDLE` | 120 s (checked every 30 s) | §8.4 |
| `ENROLLMENT_INTERESTS` | burst 32, 4 per s | §8.1 |
| `ENROLLMENT_ANSWERS` | burst 512, 128 per s | §8.2 |
| scope fragment memory | 32 packets per direction | §8.3 |
| `DATAGRAM_FLOOR` | 1100 bytes | §9 |
| fragment overhead reserve | 50 bytes | §9 |
| `max_datagram_frame_size` advertised | 65 535 | §3.1 |
| handshake limits | 64 / 4 per IP / 8 refusals within 60 s → 60 s | §13.2 |
| shutdown grace | 1 s | §6.1 |

## 15. Test vectors

All vectors were produced by running the real ndn-rs code. The hello and verdict wires come from `ndn-face-quic`'s `message.rs`; keys and fingerprints from its public `LinkKey` / `PeerKey` / `KeyFingerprint` API; certificates from `ndn_security::encode_cert_data`; LP frames from `ndn_packet::lp`. Each hello and verdict was also decoded back with the real decoder. Hex is lowercase with no separators. Line breaks inside a vector carry no meaning.

### 15.1 Ed25519 link key and fingerprint

```
private seed (RFC 8032)  0101010101010101010101010101010101010101010101010101010101010101
public key (raw, 32 B)   8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c
TLS raw public key (SPKI, 44 B)
  302a300506032b6570032100
  8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c
NDN public key           = raw public key (32 B)
fingerprint = SHA-256(raw public key)
  34750f98bd59fcfc946da45aaabe933be154a4b5094e1c4abf42866505f3c97e
```

`LinkKey::fingerprint`, `PeerKey::from_spki(spki).fingerprint` and `KeyFingerprint::of_ndn_key(raw)` all return this value.

### 15.2 P-256 link key and fingerprint

The key is ndn-rs `EcdsaP256Signer::from_seed([0x09; 32])`. The seed-to-key derivation is ndn-rs-specific and not part of this spec; use the SPKI below directly.

```
TLS raw public key = NDN public key (SPKI, 91 B)
  3059301306072a8648ce3d020106082a8648ce3d030107034200
  04
  7135fa4fd93a09dce98bbf681b4bfcf50e7c0d6354e62afb0bff2a3429617865
  ed4c1f02ddb9023ee56a557e515d6a9dc66c11f220960de594334df588776724
fingerprint = SHA-256(91-byte SPKI)
  0ca9bbe6c59d6a770f864ca136e378b35033297cef665289225f4357d1c2d744
```

Order: `0ca9…` < `3475…`, so in a mutual dial between these two keys, the P-256 device's dial stays (§11).

### 15.3 Certificates used in 15.5

Both certificates are signed by the root key `/home/KEY/0102030405060708` (Ed25519 seed `02`×32), with version 1767225600000 (`v=` = 2026-01-01T00:00:00Z in ms).

**Root**, self-signed: `/home/KEY/0102030405060708/self/v=1767225600000`, valid 20260101T000000–20360101T000000, 265 B:

```
06fd0105072d0804686f6d6508034b4559081030313032303330343035303630373038080473656c6636080000019b76daa8001414180800000000000000021908000000000036ee80152c302a300506032b65700321008139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394164e1b01051c1f071d0804686f6d6508034b4559081030313032303330343035303630373038fd00fd26fd00fe0f323032363031303154303030303030fd00ff0f32303336303130315430303030303017407e4045832a44ee3e6df10b0a835b3259b4975f369a46c0112d404af1ddea8d3b559b9c4d1d4accd457c9e6e2d21644dfc9033621cd134096dade05d11528f00c
```

**Leaf**, the device key of 15.1: `/home/member/phone/KEY/1112131415161718/NDNCERT/v=1767225600000`, issued by the root, valid 20260101T000000–20270101T000000, 283 B:

```
06fd0117                                   Data, length 279
  073f                                     Name
    0804686f6d65                             "home"
    0806 6d656d626572                        "member"
    0805 70686f6e65                          "phone"
    0803 4b4559                              "KEY"
    0810 31313132313331343135313631373138    "1112131415161718"
    0807 4e444e43455254                      "NDNCERT"
    3608 0000019b76daa800                    v=1767225600000 (VersionNameComponent 0x36)
  1414                                     MetaInfo
    1808 0000000000000002                    ContentType = KEY (2)
    1908 000000000036ee80                    FreshnessPeriod = 3600000 ms
  152c 302a300506032b6570032100            Content = Ed25519 SPKI (44 B)
       8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c
  164e                                     SignatureInfo
    1b01 05                                  SignatureType = Ed25519 (5)
    1c1f 071d 0804686f6d65 08034b4559        KeyLocator = /home/KEY/0102030405060708
              0810 30313032303330343035303630373038
    fd00fd 26                                ValidityPeriod
      fd00fe 0f 323032363031303154303030303030     NotBefore "20260101T000000"
      fd00ff 0f 323032373031303154303030303030     NotAfter  "20270101T000000"
  1740 5c22d990715a0d13c850565825fbc35afcf87aec2c8d39922f2046ee4c2004a6
       d286c8c4214af762cb62ff6f8d5d99b268a79d3d91221c5e469100460a539f01   SignatureValue
```

The same leaf as one string:

```
06fd0117073f0804686f6d6508066d656d626572080570686f6e6508034b455908103131313231333134313531363137313808074e444e4345525436080000019b76daa8001414180800000000000000021908000000000036ee80152c302a300506032b65700321008a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c164e1b01051c1f071d0804686f6d6508034b4559081030313032303330343035303630373038fd00fd26fd00fe0f323032363031303154303030303030fd00ff0f32303237303130315430303030303017405c22d990715a0d13c850565825fbc35afcf87aec2c8d39922f2046ee4c2004a6d286c8c4214af762cb62ff6f8d5d99b268a79d3d91221c5e469100460a539f01
```

### 15.4 LinkHello with no certificate (9 B)

```
fd0450 05        LinkHello, length 5
  fd0451 01 01   LinkVersion = 1
```
`fd045005fd04510101`

### 15.5 LinkHello with leaf and root (559 B)

```
fd0450 fd0229    LinkHello, length 553
  fd0451 01 01   LinkVersion = 1
  <leaf, 283 B, 15.3>
  <root, 265 B, 15.3>
```

The wire is `fd0450fd0229fd04510101` ‖ leaf ‖ root (5 + 283 + 265 = 553). A receiver whose key is the TLS key of 15.1 passes step 3 of §7.1: the leaf's Content SPKI reduces to the raw key `8a88…6f5c`.

### 15.6 LinkVerdict, full link (4 B)

```
fd0452 00
```
`fd045200`

### 15.7 LinkVerdict, enrollment link for `/home` (16 B)

```
fd0452 0c                LinkVerdict, length 12
  fd0454 08              EnrollmentLink, length 8
    07 06 0804 686f6d65  Name /home
```
`fd04520cfd04540807060804686f6d65`

### 15.8 LinkVerdict, enrollment link for `/home` and `/work/lab` (29 B)

```
fd0452 19
  fd0454 15
    07 06 0804686f6d65
    07 0b 0804776f726b 0803 6c6162
```
`fd045219fd04541507060804686f6d65070b0804776f726b08036c6162`

### 15.9 LinkVerdict with an empty EnrollmentLink (8 B)

`fd045204fd045400`. Malformed (§5.3): a receiver closes the link with 0x15.

### 15.10 Decoder behaviour

These are the TLV-VALUEs given to the real decoders (the outer TLV already stripped):

| Message value (hex) | Result |
|---|---|
| hello `0600` (Data, no LinkVersion) | malformed: no protocol version |
| hello `fd045100` (empty LinkVersion) | malformed: LinkVersion is not one byte |
| hello `fd04510102` (version 2) | refused: different version (closed with 0x15, §6.3) |
| hello `fd0451020100` (2-byte version value) | malformed: LinkVersion is not one byte |
| hello `fd045101010a00` (unknown even 0x0A, in 0–31) | malformed: unknown critical field |
| hello `fd04510101fd045600` (unknown even 0x0456) | accepted, 0 certificates |
| hello `fd04510101fd045700` (unknown odd 0x0457) | malformed: unknown critical field |
| verdict `fd045700` | malformed: unknown critical field |
| verdict `fd0454020800` (non-Name inside EnrollmentLink) | malformed |
| verdict `fd045400` (empty EnrollmentLink) | malformed |

### 15.11 NDNLPv2 frames on a link

Interest used below, hand-encoded as input: Name `/home/CA/NEW`, Nonce `01020304`:
`0517070f0804686f6d650802434108034e45570a0401020304`

| Frame | Hex |
|---|---|
| whole packet (`encode_lp_packet`) | `641b50190517070f0804686f6d650802434108034e45570a0401020304` |
| scope Nack, NoRoute (§8.3 rule 7) | `6424fd032005fd0321019650190517070f0804686f6d650802434108034e45570a0401020304` |
| fragment 0 of 3: Sequence 100, TxSequence 7, piggybacked Ack 5, first 10 bytes of the Interest | `642651080000000000000064520100530103fd03440105fd03480107500a0517070f0804686f6d65` |
| Ack-only frame for TxSequence 5 | `6405fd03440105` |

Field breakdown of the fragment:
- `51 08 0000000000000064`: Sequence = 100
- `52 01 00`: FragIndex = 0
- `53 01 03`: FragCount = 3
- `fd0344 01 05`: Ack = 5
- `fd0348 01 07`: TxSequence = 7
- `50 0a …`: Fragment

## 16. Decisions

These points were open when this spec was first written. Each was decided, and code and spec now agree.

1. **Failed exchanges close with 0x15** (§6.3). Earlier, a malformed message, an unsupported LinkVersion or a missed `MESSAGE_DEADLINE` dropped the connection, and quinn closed it with code 0 and an empty reason. The peer read that as Shutdown (transient) and redialed every ≤ 30 s forever, and the "update the older of the two" text was only logged locally. Now the side that detects the failure closes with 0x15 and the reason, and a listener counts it against the source. A version mismatch is non-transient on both sides: the peer backs off `BACKOFF_REFUSED`, because only a software update on one side changes the outcome. A missed deadline stays transient for the side that waited, since the peer may only be slow.
2. **Chain length: kept as is.** The sender sends at most 8 certificates in total (leaf + 7 issuers). The receiver accepts the leaf + up to 8 issuers. Accepting one more than is sent costs nothing and interoperates both ways. No wire change.
3. **TLV criticality follows NDN** (§5). Types 0–31 are critical, as in NDN Packet Format v0.3, and LinkVersion is exactly one byte. Version policy: the ALPN `ndn-link/1` names the transport framing (control stream and datagrams) and changes only for a protocol that cannot share this handshake. LinkVersion versions the link messages, and a peer of another version is refused with 0x15 naming both versions. No implementation sent either of the newly malformed forms.
4. **An empty EnrollmentLink is malformed** (§5.3). It meant "an enrollment link for no namespace", which carries nothing. No sender produces it: a relay with no eligible namespace refuses with 0x10.
5. **A known revoked key gets no enrollment link** (§7.1). A side refuses with 0x12 any key it knows a revoked certificate of, whatever the hello carries; `ndn-link` asks the host (`LinkTrust::known_certificate_of_key`), and ndn-fwd looks the key up in the validator's certificate cache. A key the side knows no certificate of cannot be told from a new one, and a revoked device can always make a new key. For those keys the CA, which refuses to certify a revoked device again, remains the backstop. The design statement in [personal-namespace.md](personal-namespace.md) §9 holds for every key a relay can tie to a revoked certificate.
6. **CA endpoints outside the namespace: kept.** A trust context that names a CA endpoint outside `/<ns>` is valid, but an enrollment link does not carry that endpoint: a relay forwards only names under the namespace for a device it does not know. Root devices put CA endpoints under the namespace; ndn-rs uses `/<ns>/CA`.
7. **Ack-only frames are free** (§8.3). The enrollment-link bucket now charges only frames that carry a network packet or a fragment of one. Before, a device's acknowledgements of a fragmented answer drained the relay's bucket (burst 32, 4/s), so the relay dropped the device's Interests and retransmitted its fragments needlessly.
8. **The namespace route goes to a `node` this side dials** (§10 rule 2), whichever side's dial the link came from. This is what the `ndn-link` documentation said. A node that only links in gets its device route. Keying on "this side dials that peer", and not on the link's direction, keeps the routes the same when the duplicate-link rule keeps the other side's dial.
9. **The refusal count decays** (§13.2). Refusals count within a 60 s window (`HandshakeLimits::refusal_window`). Before, a source's refusals added up with no time limit, so 8 refusals spread over days still triggered the cooldown.
10. **No device-side idle close.** The relay's idle close frees scarce enrollment slots. A device has no slots to free, and it must keep its link while it waits for an approval.
11. **Duplicate rule without an own fingerprint: kept** (newer wins). A side lacks its own fingerprint only when it lost its link key mid-run, and then it cannot complete another handshake anyway. If the two sides disagree, both links close with 0x01 (transient) and the redial converges.
12. **P-256 key comparison stays byte-exact** (§7.1 step 3). A certificate MUST carry a P-256 key as the uncompressed-point SPKI of §3.2, which is how ndn-rs and ndn-cxx write it. A compressed point is refused with 0x11.
13. **Datagrams before the verdict.** A sender MUST NOT send them (§5.4). A receiver MAY deliver ones that arrived early once it has admitted the link. ndn-rs does this, through the scope of an enrollment link. Discarding them would lose packets for no gain, since the link is admitted by then.
14. **Location of the code** (informative). The admission rules (§7–§13) are in the `ndn-link` crate (ndn-ext/crates/faces/ndn-link), and ndn-fwd hosts it. ndn-mobile has no link implementation, so there is no second copy to diverge.

## Appendix A. Code references (non-normative)

`Q` = `ndn-ext/crates/faces/ndn-face-quic/src`; `N` = `ndn-ext/crates/faces/ndn-link/src` (admission; moved there from ndn-fwd); `F` = `ndn-fwd/binaries/ndn-fwd/src` (the daemon's host glue). Lines are as read on 2026-10-18.

| Claim | Location |
|---|---|
| ALPN `ndn-link/1`; internal server name `ndn-link` | Q/endpoint.rs:20, :24 |
| TLS 1.3 only; ALPN set; SNI off; resumption off (dialer) | Q/endpoint.rs:344, :353–356 |
| TLS 1.3 only; ALPN; no session storage, 0 tickets, 0 early data (listener) | Q/endpoint.rs:417, :421–426 |
| keep-alive 10 s, idle 30 s, dial handshake 5 s | Q/endpoint.rs:46–48, :398–401 |
| 1 bidi stream, 0 uni streams, 4 MiB datagram buffers | Q/endpoint.rs:404–407 |
| `max_datagram_frame_size` = min(buffer, 65535) | quinn-proto 0.11.16 src/transport_parameters.rs:170–172 |
| handshake limits 64 / 4 / 8 / 60 s, refusal window 60 s; refusal count, decay and reset | Q/endpoint.rs:59–84, :108–162 (test :459–484) |
| Retry when busy (in_flight × 2 ≥ max); refuse over limits | Q/endpoint.rs:191–193, :293–318 |
| CONNECTION_REFUSED → Busy | Q/link.rs:74–83 |
| stateless-reset key derived from the device key (local) | Q/endpoint.rs:441–456 |
| endpoint close with code + text, 1 s grace | Q/endpoint.rs:331–335; N/links.rs:102–114 |
| Ed25519 SPKI prefix (12 B), P-256 SPKI prefix (26 B), `04` check | Q/key.rs:18–26, :103–122 |
| NDN public key form (raw Ed25519 / P-256 SPKI) | Q/key.rs:133–141 |
| fingerprint = SHA-256(NDN public key); hex text; parse; `Ord` | Q/key.rs:55–85 |
| link key from signer: Ed25519 wrapped to SPKI; P-256 SPKI as is | Q/key.rs:193–236 |
| signature schemes ed25519 / ecdsa_secp256r1_sha256 | Q/key.rs:36–41, :297–308; Q/verify.rs:21–24 |
| raw public keys required; client auth mandatory; TLS 1.2 sigs refused | Q/verify.rs:83–90, :105–107, :119–125, :141–148, :163–165, :194, :208 |
| dialer checks expected fingerprint in the handshake | Q/verify.rs:64–81 |
| listener checks key type only | Q/verify.rs:131–138 |
| certificate Content: Ed25519 SPKI unwrapped to raw, else as is | ndn-rs/crates/security/ndn-security/src/cert_cache.rs:31–38; …/spki.rs:30–58 |
| TLV-TYPEs 0x0450/0x0451/0x0452/0x0454; version 1; MAX_MESSAGE | Q/message.rs:21–32 |
| hello encode / decode (version exactly one byte, types 0–31 and odd critical) | Q/message.rs:44–89, :150–155 |
| verdict encode / decode (Name only in 0x0454, never empty) | Q/message.rs:101–148 |
| decoder tests (vectors of §15.10) | Q/message.rs:284–295 |
| close codes and transient set | Q/message.rs:173–253 |
| hello exchange order; verdict exchange; datagram check; FIN | Q/link.rs:151–242 |
| failed exchange closes with 0x15 and its reason, counted against the source | Q/link.rs:254–280 (test: tests/link.rs:140–177) |
| message read and write: 20-byte header, expected type, MAX_MESSAGE, peer's close reason | Q/link.rs:282–338 |
| close mapping and `is_transient` of errors | Q/link.rs:66–101 |
| a dropped connection closes with code 0 and an empty reason (what §6.3 forbids) | quinn 0.11.12 src/connection.rs:946–961, :1254–1257 (lockfile pins quinn 0.11.9; same code at :928–939, :1241–1243) |
| DATAGRAM_FLOOR 1100; send_mtu; TooLarge dropped | Q/link.rs:24, :456–459, :422–424 |
| scoped face send / receive, Nack paths | Q/link.rs:460–495 |
| scope: frame classification, fragments, rate bucket (Ack-only frames free), Nack | Q/scope.rs:28–35, :141–243, :245–247, :274–335 |
| LP wrap / fragment / reliable / Nack / Ack encoders | ndn-rs/crates/core/ndn-packet/src/lp/encode.rs:7–92 |
| fragment if len + 4 > mtu; plain LP wrap otherwise | ndn-rs/crates/core/ndn-transport/src/link_service/mod.rs:364–428 |
| fragments always carry TxSequence (not gated) | …/link_service/features/reliability.rs:140–156; …/link_service/mod.rs:287–313 |
| FRAG_OVERHEAD 50; per-Ack 10 B; consecutive Sequences | ndn-rs/crates/core/ndn-packet/src/fragment.rs:25; ndn-rs/crates/core/ndn-transport/src/reliability.rs:256–326 |
| `ReliabilityConfig::ethernet()` | ndn-rs/crates/core/ndn-transport/src/reliability.rs:85–92 |
| NackReason NoRoute = 150 | ndn-rs/crates/core/ndn-packet/src/nack.rs:29, :40 |
| constants MESSAGE_DEADLINE … ENROLLMENT_ANSWERS (`ndn_link::policy`) | N/policy.rs:10–42 |
| MAX_STATUS_HOLD = 60 s | ndn-rs/crates/security/ndn-cert/src/approval.rs:104 |
| LinkTransportConfig::default used by ndn-fwd | F/links.rs:175 |
| hello = own certificate chain | N/links.rs:166–169; F/links.rs:76–78; F/own_certs.rs:218–250 |
| known certificates for offline validation (served, then engine cache); certificate of a key by fingerprint | F/links.rs:80–92; N/host.rs:26–38 |
| own certificate / own role / namespace_of | N/admission.rs:93–121 |
| enrollment eligibility | N/admission.rs:125–159 |
| enrollment slots 32 / 4 per source, Busy | N/slots.rs:34–71 |
| admission → verdict + scope (directions, filter, rates) | N/admission.rs:340–385 |
| relink on key switch, 0x03 | N/links.rs:119–123, :496–498; N/table.rs:139–176; F/links.rs:218–231 |
| known revoked key refused 0x12 before the hello is read | N/admission.rs:162–165, :295–315 (test :802–857) |
| identify steps 1–11 | N/admission.rs:166–271 |
| offline validation, depth 8, no fetch | N/admission.rs:274–293 |
| peer entry lookup (first by key or device); is_relay | N/peer.rs:42–56, :63–68 |
| decision rules 7.3 | N/admission.rs:320–336, :399–530 |
| routes and VIA_RELAY_COST; namespace route only for a node this side dials | N/routes.rs:11–51; N/links.rs:247–252 |
| route origin static, CHILD_INHERIT | F/links.rs:111–128 |
| establish: hello, decide, slot, admit, reliability choice, register, routes, idle close | N/links.rs:164–307 |
| duplicate-link rule `keeps_existing`; register | N/table.rs:24–35, :89–115 (test :206) |
| revocation closes links | N/links.rs:85–89; N/table.rs:179–200 |
| dial loop, `Backoff` (500 ms doubling to 30 s; refused 60 s) / persistence | N/links.rs:435–493; N/policy.rs:48–80 |
| dial over path candidates and resolved addresses | N/links.rs:365–398; N/host.rs:66–90 |
| `[[peer]]` → PeerSpec | F/links.rs:30–58 |
| `in_enrollment` / `is_key_or_certificate_name` | N/admission.rs:539–560 |
| name filter test cases | N/admission.rs:584–617 |
| LinkPolicy fields, default, allows_link / allows_relay | ndn-rs/crates/security/ndn-security/src/trust_context/mod.rs:278–318 |
| link_policy default; admits_enrollment_links; is_revoked prefix | …/trust_context/mod.rs:596–598, :606–608, :660–662 |
| `trust-context` keyword; rdr_prefix | …/trust_context/mod.rs:55; ndn-rs/crates/security/ndn-cert/src/onboarding.rs:57–63 |
| context_for = longest held namespace prefix | ndn-rs/crates/security/ndn-security/src/keyring.rs:240–253 |
| role words; device-name rules; parse_device_key | ndn-rs/crates/security/ndn-cert/src/roles.rs:67–101, :150–179, :260–301 |
| `[[peer]]` fields, persistent default true | ndn-rs/crates/platform/ndn-config/src/config.rs:1533–1585 |
| certificate wire (vectors): name, MetaInfo, SPKI Content, ValidityPeriod | ndn-rs/crates/security/ndn-security/src/manager.rs:514–594; …/cert_name.rs:74–80 |
| rustls ring cipher suites and groups | rustls 0.23.40 src/crypto/ring/mod.rs:68–80, :179–180 |

[RFC 2119]: https://www.rfc-editor.org/rfc/rfc2119
[RFC 8174]: https://www.rfc-editor.org/rfc/rfc8174
[RFC 7250]: https://www.rfc-editor.org/rfc/rfc7250
[RFC 7301]: https://www.rfc-editor.org/rfc/rfc7301
[RFC 8410]: https://www.rfc-editor.org/rfc/rfc8410
[RFC 8446]: https://www.rfc-editor.org/rfc/rfc8446
[RFC 9000]: https://www.rfc-editor.org/rfc/rfc9000
[RFC 9001]: https://www.rfc-editor.org/rfc/rfc9001
[RFC 9221]: https://www.rfc-editor.org/rfc/rfc9221
