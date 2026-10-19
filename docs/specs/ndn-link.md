# ndn-link/1: QUIC links between NDN forwarders

- **Status:** Draft
- **Scope:** This spec covers the wire protocol and the admission rules of a *link*: a QUIC connection between two NDN forwarders. Each device is identified by its NDN key, which it presents in TLS 1.3 as an RFC 7250 raw public key. The spec defines:
  - the handshake, the key fingerprint, and the link messages (LinkHello, LinkVerdict, EnrollmentLink, ObservedAddress, Reachability, Presence), and the memberships a hello carries for the namespaces a device takes part in beyond the one its link key is certified in;
  - how NDN packets are framed in QUIC datagrams, and the timeouts;
  - the close reason codes;
  - admission and enrollment-link scope, routes, the duplicate-link rule, backoff and rate limits;
  - direct paths: address discovery, the NDN-native punch that signals a NAT hole punch through a relay, probes, how a punched connection joins a link as its direct path, and direct paths by membership between devices of a namespace that meet at a relay (§14);
  - relays: whom a relay serves (its serving policy and quotas) and which relays a device uses (§15);
  - link modes (`always`, `on-demand`, `off`), idle close and the Interests that wait for a link (§16);
  - reachability while asleep: Interests a relay holds for a sleeping device, and the wake hook (§17).

  The goal is an independent implementation (NDNts, python-ndn, …) that can dial an ndn-fwd link and accept one from ndn-fwd.
- **Design context:** [personal-namespace.md](personal-namespace.md) §9 ("QUIC links"), F6 and F11. Where the two disagree on wire detail, this spec governs.
- **Related specs:** [trust-context.md](trust-context.md) (link policy and its direct-path role matrix §3.3.10, advertised relays §3.3.11, revocations, CA endpoints, validation), [ndncert-extensions.md](ndncert-extensions.md) (what an enrollment link carries), [trust-envelope.md](trust-envelope.md), [recovery-kit.md](recovery-kit.md), [local-refusal.md](local-refusal.md).

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 ([RFC 2119], [RFC 8174]) when, and only when, they appear in all capitals, as shown here.

The normative text describes what ndn-rs does today: crate `ndn-face-quic` (ndn-ext) for the transport, the messages and the probes, and crate `ndn-link` (ndn-ext) for admission, enrollment links, routes, redial, the duplicate-link rule, direct paths, relays, link modes and reachability while asleep. ndn-fwd and ndn-boltffi (ndn-mobile) are hosts of `ndn-link`: they supply the configuration, the certificates they serve, their faces and RIB, and (on a relay) the wake notifier. Points where the code was ambiguous or looked unintended were decided; the [Decisions](#20-decisions) say how and why. All byte-level claims are traced to code in [Appendix A](#appendix-a-code-references-non-normative).

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
| link policy | The trust context field (LinkPolicy, TLV 0x0412) that says which roles may link, which may relay, whether enrollment links are admitted, whether direct paths are, and between which pairs of roles (the *direct-path role matrix*) (§7.4). |
| relay | A forwarder that other devices link to and reach each other through (§15). Any device others can reach is a relay for the devices its serving policy serves. For link policy purposes, a device holding a certificate whose role the link policy lets relay. |
| serving policy | Whom a relay admits on links nobody asked for: `own` (its own namespaces), `listed` (also namespaces listed by root key fingerprint) or `open` (any namespace, under quotas) (§15.2). |
| root key fingerprint | The fingerprint (§3.3) of a namespace's anchor key: the key of its self-signed root certificate `/<ns>/KEY/<id>/…`. |
| served device | A device of a namespace the relay does not hold, admitted by its serving policy after offline validation against the root certificate in its hello (§7.1). |
| relay source | Where a device learned of a relay it uses: its namespace advertises it (trust context, `namespace:<ns>`) or its person added it (`user`) (§15.5). |
| link mode | When a link to a peer is up: `always`, `on-demand` or `off` (§16). |
| waiting face | A face of `ndn-link` that takes Interests for a link that is down: for an on-demand link it dials (§16.3); on a relay it holds Interests for a sleeping device (§17.3). |
| asleep | On a relay: a device whose last path ended after it asked, with a Reachability message, to have its Interests held or to be woken (§17.2). |
| wake token / wake notifier | An opaque token a device registers with a relay (for example a platform push token), and the relay host's hook that receives it to wake the device (§17.4). |
| presence | A relay's list of the devices of a namespace linked to it now, sent to each of them on the control stream (§5.7, §14.8). |
| member | A device of a namespace identified in a trust context this side holds. |
| membership | A namespace a device is a member of with a key other than its link key: that key's certificate chain, shown in the hello (and in punch messages) with a *binding*, that key's signature over the link key's fingerprint and a value of this connection only (§5.8). A device takes part in many namespaces with one link key. |
| enrollment link | A link admitted with a *scope*: it carries only one device's enrollment in the listed namespaces (§8). |
| full link | A link without a scope. |
| path | One QUIC connection of a link. A link has at most one path of each kind: the *link path* (dialled to a configured endpoint, or accepted) and the *direct path* (made by a punch, §14). |
| direct path | A path between two devices that otherwise reach each other through a relay, made by a NAT hole punch (§14). |
| punch | The signed Interest and Data by which two devices agree on a direct-path attempt, then probe and connect (§14). |
| candidate | A UDP address at which a device may be reached directly: host (an interface address), reflexive (the address a linked device sees it at), advertised (configured) or mapped (port mapping) (§14.2). |
| route | A FIB/RIB entry that sends a prefix over a link's face, with a cost (§10). |
| enroll | Obtain a certificate `/<ns>/<role>/<device>/KEY/…` from the namespace's CA (invite or approval; see [ndncert-extensions.md](ndncert-extensions.md)). |
| `[[peer]]`, `[[relay]]` | ndn-fwd's configuration entries for a peer device and for a relay the user adds. `[[peer]]` fields are `key` (expected fingerprint), `device` (expected device name), `endpoint`, `relay`, `routes`, `persistent`, `reliability`, `direct`, `mode`, `idle_secs`, `hold` and `wake_token`; `[[relay]]` fields are `key`, `device`, `endpoint`, `preference`, `mode`, `idle_secs`, `hold` and `wake_token`. ndn-fwd's `[relays]`, `[relay_service]`, `[links]` and `[direct]` tables hold the device-wide options of §14.9 and §15–§17. Other implementations need an equivalent; only its effect on the wire is normative. |

TLV notation follows the NDN Packet Format v0.3: TLV-TYPE and TLV-LENGTH are VAR-NUMBERs; `0xFD xx xx` is the 3-byte form.

## 2. Protocol overview

```
dialer                                              listener
  | QUIC v1 Initial ... TLS 1.3, ALPN "ndn-link/1",     |
  | raw public keys both ways (client auth mandatory)   |
  |<--------------------------------------------------->|  §3
  | open bidi stream 0 (control stream)                 |
  | LinkHello (0x0450), with its Memberships (0x045C) -> |  §5.2, §5.8
  | <------------------------------- LinkHello (0x0450) |
  |        each side decides admission (§7)             |
  | LinkVerdict (0x0452) -----------------------------> |  §5.3 (sent concurrently;
  | <----------------------------- LinkVerdict (0x0452) |       or CONNECTION_CLOSE, §6)
  | ObservedAddress (0x0458) on the control stream, both ways, at once and when it changes   §5.5
  | Reachability (0x0440) device -> relay, when it asks to be held for or woken            §5.6, §17
  | Presence (0x0446) relay -> member, per namespace, at once and when it changes         §5.7, §14.8
  | NDNLPv2 frames in QUIC DATAGRAM frames, both ways   |  §9
  | FIN on control stream when the link ends            |
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
   | `max_idle_timeout` | 30 000 ms | QUIC transport parameter; the connection takes the smaller of both sides' offers. A host MAY set it within the bounds of §16.4 |
   | Keep-alive (PING when idle) | every 10 s | keeps NAT bindings open. A host MAY set it within the bounds of §16.4 |
   | Dial handshake timeout | 5 s | a dial with no completed handshake by then fails; QUIC ignores ICMP, so this is the only fast failure for an address where nothing listens |
   | Direct path: `max_idle_timeout` offered by its dialer | 8 000 ms | the connection takes the smaller offer, so it applies to both sides; a dead direct path is noticed within it and its traffic falls back to the relay (§14.7). The listener of a direct path offers 8 000 ms too |
   | Direct path: keep-alive of its dialer | every 2 s | keeps the NAT mappings of both sides open (the listener's ACKs refresh its side) |

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
- A device has **one link key**, whatever the number of namespaces it takes part in: in ndn-fwd, its node key. Its other namespaces' keys never appear in TLS; the hello shows them as memberships bound to the connection (§5.8).

## 4. Control stream

### 4.1 Stream use

1. After the handshake, the dialer opens the first client-initiated bidirectional stream (stream ID 0). This is the **control stream**.
2. Each direction of the control stream carries, in this order: one LinkHello, one LinkVerdict, then, for as long as the link is up, zero or more of the messages of §5.5–§5.7 (ObservedAddress both ways; Reachability from a device to a relay; Presence from a relay to a device), in any order. Each message is one complete TLV with no other framing.
3. A side finishes (FIN) its sending half when the link ends, or earlier once it sends nothing more. A receiver MUST NOT expect a FIN before the link is up. After the verdict, a receiver reads further messages: it MUST ignore a message of an unrecognized TLV-TYPE that is even and greater than 31, and SHOULD close the link with 0x15 (Protocol) on any other unrecognized type (ndn-rs does). A side that stops reading after the verdict (an implementation before ObservedAddress) only loses those messages; its peer's writes then fail, and the peer stops sending them. Every message defined after the verdict has an even TLV-TYPE above 31, so a receiver that predates it skips it.
4. NDN packets never travel on a stream (§9).

### 4.2 Reading a message

1. A receiver reads the TLV-TYPE and TLV-LENGTH VAR-NUMBERs. If no complete header has arrived after 20 bytes, the message is malformed.
2. If TLV-TYPE is not the expected message (0x0450 for the first message, 0x0452 for the second, any type after the verdict, §4.1), the message is malformed.
3. If TLV-LENGTH exceeds 65 536 (`MAX_MESSAGE`, 64 KiB, applied to the TLV-VALUE), the message is malformed.
4. Otherwise the receiver reads exactly TLV-LENGTH more bytes. A stream that ends early is malformed. If the connection closed, the peer's close reason is reported instead.

A sender MUST NOT send a message whose TLV-VALUE exceeds 65 536 bytes.

## 5. Link messages

All TLV-TYPEs are in the application range (types above 252, written as 3-byte VAR-NUMBERs). Inside every link message (LinkHello, LinkVerdict, Reachability, Presence and their nested elements), a receiver MUST ignore an unrecognized TLV-TYPE that is even and greater than 31, and MUST treat any other unrecognized TLV-TYPE (odd, or in 0–31) as a malformed message. This is the rule of NDN Packet Format v0.3, where types 0–31 are always critical ([Decision 3](#20-decisions)). A malformed message after the verdict closes the link with 0x15 (Protocol) and a reason phrase that says what was wrong.

### 5.1 TLV-TYPE registry

| TLV-TYPE | Name | Appears in | Value |
|---|---|---|---|
| 0x0440 | Reachability | control stream, after the verdict, device → relay | HoldInterests?, WakeToken? (§5.6) |
| 0x0442 | HoldInterests | Reachability | empty |
| 0x0444 | WakeToken | Reachability | 1–1024 bytes, opaque |
| 0x0446 | Presence | control stream, after the verdict, relay → device | Name, PresentDevice* (§5.7) |
| 0x0448 | PresentDevice | Presence | Name, KeyDigest |
| 0x044A | KeyDigest | PresentDevice | 32 bytes: a key fingerprint (§3.3) |
| 0x0450 | LinkHello | control stream, message 1 | LinkVersion, Data*, Membership*, DirectPath? |
| 0x0451 | LinkVersion | LinkHello | 1 byte: the protocol version, `0x01` |
| 0x0452 | LinkVerdict | control stream, message 2 | EnrollmentLink? |
| 0x0453 | (unassigned) | — | — |
| 0x0454 | EnrollmentLink | LinkVerdict | Name* |
| 0x0456 | (unassigned) | — | — |
| 0x0458 | ObservedAddress | control stream, after the verdict | a UDP address (§5.5) |
| 0x045A | DirectPath | LinkHello | 8 bytes: the session of the punch whose direct path this connection is (§14.6) |
| 0x045C | Membership | LinkHello, PunchMessage | Data+, MembershipBinding (§5.8) |
| 0x045E | MembershipBinding | Membership | the signature of the membership certificate's key over the binding transcript (§5.8) |
| 0x06 | Data | LinkHello, Membership | a certificate Data packet, whole |
| 0x07 | Name | EnrollmentLink, Presence, PresentDevice | a Name: a namespace (EnrollmentLink, Presence) or a device (PresentDevice) |

The other numbers of 0x0440–0x045F are unassigned. The punch messages of §14 use 0x0460–0x046C ([§14.3](#143-the-punch-interest-and-its-answer)).

### 5.2 LinkHello (0x0450)

```
LinkHello      = LINK-HELLO-TYPE TLV-LENGTH
                 LinkVersion
                 *Certificate
                 *Membership       ; §5.8
                 [DirectPath]
LinkVersion    = LINK-VERSION-TYPE TLV-LENGTH(=1) %x01
Certificate    = Data              ; NDN Certificate Format v2 Data packet
DirectPath     = DIRECT-PATH-TYPE TLV-LENGTH(=8) 8OCTET
```

**Sender rules**

- MUST include exactly one LinkVersion, with a 1-byte value `0x01`, as the first element. ndn-rs writes it first.
- After LinkVersion come zero or more certificate Data TLVs, copied unchanged:
  - The first is the sender's own certificate for the key it presented in TLS (the *leaf*).
  - The rest are the issuers the sender keeps, nearest first (the leaf's issuer, then that certificate's issuer, …).
- A sender with no certificate for its link key (a device not enrolled anywhere, linked by expected fingerprint or on an enrollment link) sends no certificate.
- After the certificates come the sender's memberships (§5.8): one per namespace it is a member of with a key other than its link key, at most `MEMBERSHIPS_MAX` = 8. A sender that links for its enrollment only (§8.2) sends neither certificates nor memberships.
- DirectPath: the dialer of a direct path MUST send the session of its punch (§14.6); a listener that punches the dialer's key now sends the session of that punch (of the one it began last, when it runs several). Otherwise it is absent. ndn-rs writes it last.
- How ndn-fwd builds the chain: it takes its newest currently valid certificate under the current key name. It then repeatedly takes the newest currently valid certificate under the key name in the previous certificate's KeyLocator (the certificate name without its last two components). It stops at a self-signed certificate (KeyLocator names the certificate's own key), at a certificate it does not keep, at a certificate already in the chain, or at **8 certificates in total**. A self-signed root that ndn-fwd keeps is therefore included as the last element.
- The root at the end: a sender SHOULD end the chain with its namespace's self-signed root certificate, so that a relay that does not hold the namespace can check the chain offline against it (§7.1, §15.2). When the chain the host keeps does not end in a self-signed certificate, `ndn-link` appends the anchor of the held trust context that the last certificate's issuer names, if there is one. A hello therefore carries at most 9 certificates: the leaf and at most 8 issuers, which is what a receiver uses ([Decision 2](#20-decisions)). Punch messages carry the same chain (§14.3).

**Receiver rules**

- Elements are processed in order:
  - LinkVersion: the value MUST be exactly one byte, the version. A value of any other length makes the hello malformed. If LinkVersion appears more than once, the last one wins.
  - Data (0x06): appended to the certificate list in order. The Data is not parsed at this stage.
  - Membership (0x045C): decoded as §5.8 says (a malformed one makes the hello malformed) and appended to the membership list. Its certificates are not parsed at this stage. A receiver that predates memberships ignores them, as any even type above 31, and admits the sender by its link key's certificate alone.
  - Any other even type above 31: ignored.
  - DirectPath (0x045A): the value MUST be exactly 8 bytes; any other length makes the hello malformed.
  - Any other type (odd, or 0–31): malformed.
- If no version is present, the hello is malformed.
- If the version is present and ≠ 1, the receiver MUST NOT admit the link. ndn-rs logs that the peer speaks a different version and asks the user to update the older device.
- A receiver uses the leaf and at most the **first 8** issuer certificates (`MAX_CHAIN` = 8) and ignores the rest; of the memberships, it uses at most the first `MEMBERSHIPS_MAX` = 8, and of each, its first certificate and at most 8 issuers.

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
  - An EnrollmentLink MUST list at least one Name. An empty EnrollmentLink makes the verdict malformed ([Decision 4](#20-decisions)). A relay with no eligible namespace refuses instead (§7.3 rules 5 and 6).
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
6. **Observed addresses.** From here on, each side tells the other the address it sees it at (§5.5).

A side that receives a malformed message or an unsupported LinkVersion, or whose peer misses a `MESSAGE_DEADLINE`, does not admit the link. It closes the connection with 0x15 (Protocol) and a reason (§6.3).

### 5.5 ObservedAddress (0x0458)

```
ObservedAddress = OBSERVED-ADDRESS-TYPE TLV-LENGTH UdpAddress
UdpAddress      = 4OCTET 2OCTET     ; IPv4 address, port   (TLV-LENGTH 6)
                / 16OCTET 2OCTET    ; IPv6 address, port   (TLV-LENGTH 18)
```

Network byte order. An IPv4-mapped IPv6 address MUST be written as IPv4. It is the address the sender sees the receiver's packets come from: the receiver's address beyond every NAT between them (its *server-reflexive* address, as STUN or QUIC address discovery would report it).

- **Sender.** Once its verdict is written and the peer's read, each side SHOULD send an ObservedAddress with the peer's current address, and again whenever that address changes (the peer's NAT remapped, or the peer migrated the connection). ndn-rs sends it at once and checks for a change every 5 s (`OBSERVE_INTERVAL`).
- **Receiver.** A value of another length makes the message malformed; ndn-rs closes the link with 0x15. The latest ObservedAddress replaces the earlier ones. A device uses the addresses its *full* links report as its reflexive candidates (§14.2); an enrollment link's report is not used (its other side is not confirmed). The report is a claim of the linked device, not a proof: a device that lies can only make the receiver offer a wrong candidate, which its punch partner then probes a few times (§14.5).

### 5.6 Reachability (0x0440)

```
Reachability  = REACHABILITY-TYPE TLV-LENGTH
                [HoldInterests]
                [WakeToken]
HoldInterests = HOLD-INTERESTS-TYPE TLV-LENGTH(=0)
WakeToken     = WAKE-TOKEN-TYPE TLV-LENGTH 1*1024OCTET   ; opaque
```

Sent by a device to a relay, after the verdicts: how the device is reached while it does not keep its link up (§17).

- **HoldInterests** present: hold Interests for this device while it is asleep, within the relay's bounds, and send them to it when it links again (§17.3).
- **WakeToken** present: an opaque token (for example a platform push token) the relay hands to its wake notifier when an Interest arrives for the device while it is asleep (§17.4). Absent: do not wake this device. `WAKE_TOKEN_MAX` = 1024 bytes.
- **Sender.** A device sends a Reachability on each new full link to a peer it asks something of (§17.1), and again whenever its wake token for that peer changes. An empty Reachability withdraws both. A sender MUST NOT send a WakeToken that is empty or longer than 1024 bytes; ndn-rs logs a warning and sends nothing instead, so the relay keeps what it was told before. ndn-rs writes the fields in the order above, and the latest Reachability not yet written replaces an earlier one still queued.
- **Receiver.** A HoldInterests of non-zero length, or a WakeToken of 0 or more than 1024 bytes, makes the message malformed (0x15). If a field appears more than once, the last one wins. The latest Reachability received on a link replaces the earlier ones; it applies to that link's device when the link ends (§17.2).

### 5.7 Presence (0x0446)

```
Presence      = PRESENCE-TYPE TLV-LENGTH
                Name               ; the namespace
                *PresentDevice
PresentDevice = PRESENT-DEVICE-TYPE TLV-LENGTH
                Name               ; the device, /<ns>/<role>/<device>
                KeyDigest
KeyDigest     = KEY-DIGEST-TYPE TLV-LENGTH(=32) 32OCTET   ; the key fingerprint (§3.3)
```

Sent by a relay to a device of a namespace it holds, after the verdicts: which other devices of that namespace are linked to the relay now (§14.8). Each PresentDevice is one device's name and the fingerprint of the key it linked with. **Presence carries no address**: addresses travel only in the signed punch messages (§14.3).

- **Sender.** The message is the full list for its namespace; an empty list says that no device of the namespace the receiver may meet is linked there. ndn-rs writes the namespace Name first, and lists at most `PRESENCE_MAX` = 256 devices in one message. A sender MUST NOT send a Presence whose TLV-VALUE exceeds `MAX_MESSAGE` (§4.2); ndn-rs logs a warning and sends nothing instead. The latest Presence for a namespace not yet written replaces an earlier one still queued for the same namespace.
- **Receiver.** A Presence without its namespace Name, a PresentDevice without its Name or KeyDigest, or a KeyDigest that is not 32 bytes makes the message malformed (0x15). If a field appears more than once, the last one wins. The latest Presence for a namespace replaces the earlier one for that namespace; an empty list removes the namespace. A receiver MAY bound the number of namespaces it keeps; ndn-rs keeps at most 256 at once and closes the link with 0x15 when a Presence would add another.

### 5.8 Membership (0x045C) and its binding

A device takes part in many namespaces with one link key (§3.4). In each namespace other than the one its link key is certified in, it holds another key and that key's certificate. The hello shows each such namespace as a Membership:

```
Membership        = MEMBERSHIP-TYPE TLV-LENGTH
                    1*Certificate       ; the namespace certificate, then its issuers, root last
                    MembershipBinding
MembershipBinding = MEMBERSHIP-BINDING-TYPE TLV-LENGTH 1*OCTET   ; a signature value
```

The certificates are the chain of the namespace key as §5.2 describes it for the link key: the device's certificate in the namespace first, then the issuers it keeps nearest first, ending in the namespace's self-signed root (`ndn-link` appends the anchor of the held context as for the link key's chain). The **binding** is the namespace key's signature over the *binding transcript*:

```
binding transcript = "ndn-link/1 membership" %x00     ; 22 bytes: 21 ASCII bytes and a zero byte
                     link-key-fingerprint             ; 32 bytes: the SENDER's link key fingerprint (§3.3)
                     channel-binding                  ; 32 bytes: the value of this connection (below)
                     SHA-256(certificate)             ; 32 bytes: of the membership's first certificate, its whole Data TLV
```

118 bytes in all. The signature algorithm is that of the certificate's key: Ed25519 (RFC 8032, 64 bytes) for an Ed25519 key, ECDSA P-256 with SHA-256 (the DER `Ecdsa-Sig-Value`, as NDN signatures carry it) for a P-256 key. Any other key cannot be bound.

**The channel binding** is what makes a binding hold on one connection only:

- on a link (a QUIC connection): the TLS 1.3 exporter of the connection ([RFC 8446] §7.5), `TLS-Exporter("EXPORTER-ndn-link/1 membership", "", 32)`: label `EXPORTER-ndn-link/1 membership` (30 ASCII bytes), an empty context, 32 bytes. Both sides of one connection compute the same value, and no other connection has it (quinn `Connection::export_keying_material`);
- in a punch message (§14.3), which no connection carries yet: SHA-256(`"ndn-link/1 punch"` ‖ the 8-byte session), the same in the request and its answer. The punch's signature by the link key and its SignatureNonce/SignatureTime make it fresh (§14.4); the binding ties the membership to that link key and that punch.

**Sender rules.**

- A sender MUST show a membership only with the key its certificate certifies, and MUST compute its binding anew for each connection (or punch), over the fingerprint of the link key that connection's handshake presented (or that signs the punch message). A device that switches link keys binds its next connection to the new key; ndn-rs fixes the key of each connection when its handshake starts (`Handshaken::local_key`). It shows one membership per namespace, at most `MEMBERSHIPS_MAX` = 8, and none for the namespace its link key's certificate is in nor for a certificate of its link key. ndn-rs writes the certificates in chain order, then the binding.
- A membership whose key cannot sign is left out; ndn-rs logs why.

**Receiver rules.**

- Inside a Membership, every Data (0x06) is appended to its certificates in order; MembershipBinding is its binding (non-empty; the last wins when repeated); any other even type above 31 is ignored; any other type makes the message malformed. A Membership without a certificate, or without a binding, makes the message malformed.
- How a receiver identifies the sender from its memberships, and what it refuses, is §7.1.

**What a binding proves, and what it cannot.** The sender's link key was proven in the handshake (§3.4); the binding is a signature by the namespace key over that link key and a value only this connection has. So the holder of the namespace key vouches, for this connection, that the device behind this link key is it. A certificate of a key the sender does not hold cannot be bound (the binding does not verify under the certificate's key), and a binding taken from another connection names another exporter value, so neither verifies (§7.1 M3). The receiver recomputes the transcript from its own view of the connection: the peer's TLS key and the exporter; nothing in it is read from the hello but the certificate.

## 6. Closing a link

### 6.1 Close reason codes

A side closes a link with a QUIC `CONNECTION_CLOSE` of type 0x1d (application). Its Error Code is one of the codes below, and its Reason Phrase is a UTF-8 sentence for the person reading the other side's log. That sentence SHOULD say what to do. It is not machine-readable.

| Code | Name | Sent when | Transient |
|---|---|---|---|
| 0x00 | Shutdown | The device is shutting down. ndn-fwd closes every link with it, then waits up to 1 s for the peer to be told. | yes |
| 0x01 | Replaced | A newer link between the same two devices took this link's place (§11), or another path of the same punch came up first (§14.6). Also closes a direct path whose device punches again: after the closing side's network changed, or when the other device punches while this side still has a direct path to it (§14.7). | yes |
| 0x02 | Idle | An enrollment link carried nothing for `ENROLLMENT_IDLE` (§8.4). | yes |
| 0x03 | Enrolled | The device enrolled, or its memberships changed otherwise. It closes its enrollment link and links again holding its certificate, or closes a full link whose hello no longer shows the namespaces it holds now, so that the other side knows it in each (§8.5). | yes |
| 0x04 | PathExpired | A connection names, in its DirectPath, a punch the closing side does not run with that key (it ended, or never began), or the listener of a direct path did not take it as one (§14.6). | yes |
| 0x05 | Asleep | The device closed its link to sleep: its on-demand link carried nothing for its idle time while its host was not active, or its link mode is `off` and nobody asks for the link (§16.2). It links again when it has something to send or is woken; a relay it asked meanwhile holds Interests for it and wakes it (§17). | yes |
| 0x06 | Released | The device no longer uses this relay: a relay it prefers is back, this relay is not among the ones chosen now, or it was removed from the device's configuration or no longer advertised by its namespace (§15.6). Not a fault of either side. | yes |
| 0x10 | Unrecognized | The key has no valid certificate in a namespace the closing side holds or can check (§7.1), no `[[peer]]` expects its fingerprint, and no enrollment link is possible. | no |
| 0x11 | CertificateForAnotherKey | The leaf certificate in the hello certifies a different key than the one the handshake proved. | no |
| 0x12 | Revoked | The leaf, or a sent issuer, is revoked by a held trust context, and no other certificate or membership of the hello identifies the peer (§7.1). Also sent when a revocation adopted while the link is up leaves it no identity (§12). | no |
| 0x13 | RoleNotAllowed | The namespace's link policy does not let the peer's role link, or does not let it relay when this side reaches others through it. | no |
| 0x14 | NotTheExpectedDevice | The peer is valid, but not the device or key a `[[peer]]` entry expects. | no |
| 0x15 | Protocol | A link message is malformed or carries another LinkVersion, the peer sent no link message within `MESSAGE_DEADLINE` (§6.3), a certificate in the hello (of its link key or of a membership) does not decode, the peer does not support datagrams, or the peer misbehaved. | no |
| 0x16 | Busy | Too many link attempts (§13), too many enrollment links (§8.4), too many punches (§14.4), as many direct paths as the side may have (§14.9), or a serving quota is full (§15.3). | yes |
| 0x17 | NoLinkKey | This device has no usable link key. | yes¹ |
| 0x18 | DirectPathsOff | Direct paths between the two devices are off: the link policy of every namespace the peer is identified in turns them off or does not pair the two devices' roles there (§7.4; one namespace that pairs them is enough), or the closing side's `[[peer]]` for it says `direct = false`. Refuses a direct path (§14.6) or a punch (§14.4). | no |
| 0x19 | NotServed | This relay's serving policy does not serve the device's namespace or key (§15.2), or another root key's namespace of the same name is served or held here (§15.3). Use another relay, or ask this relay's operator to serve the namespace. | no |
| 0x1A | MembershipNotBound | A Membership of the hello is not bound to this link: its binding does not verify under its certificate's key for the sender's link key on this connection (§5.8, §7.1 M3) — the sender does not hold the certificate's key (a forged membership), or the binding was made for another connection (a replayed one) — or the certificate's key is neither Ed25519 nor P-256. | no |

¹ ndn-rs never sends 0x17 on the wire. A device without a link key cannot complete a handshake.

The **Transient** column drives the dialer's backoff (§13):
- a transient close is retried with exponential backoff;
- a non-transient close means "refused until the trust data or the configuration changes".

A received code not in this table MUST be treated as transient. The same codes, and their transient column, are what a punch refusal carries (§14.4).

### 6.2 Refusal before the handshake

A listener over its handshake limits (§13.2) refuses an Initial with the QUIC transport error `CONNECTION_REFUSED` (0x02). Dialers SHOULD treat this like application code 0x16 (Busy). ndn-rs does.

### 6.3 Failed exchange

A side whose hello or verdict exchange fails MUST close the connection with 0x15 (Protocol) and a reason phrase that says what went wrong. Failures are a malformed message (§4.2, §5), an unsupported LinkVersion, and a missed `MESSAGE_DEADLINE` (§5.4). For a version mismatch the reason names both versions and asks the user to update the older device. A listener counts the close against the source like any refusal (§13.2).

A side MUST NOT just drop the connection. A QUIC stack then closes it with application code 0x00 and an empty reason phrase, which the peer reads as Shutdown (transient) and redials at once ([Decision 1](#20-decisions)).

ndn-rs versions before this rule dropped the connection. A receiver therefore MUST NOT read 0x00 with an empty reason as proof of an orderly shutdown. ndn-rs treats it as transient (§13.1).

## 7. Admission

Admission is decided by each side independently, after the hello exchange. Inputs:

- the peer's NDN public key and fingerprint, from TLS;
- the peer's LinkHello;
- the side's held trust contexts;
- the side's configured peers;
- whether this side dialed the link, and for which `[[peer]]`;
- the side's serving policy and the links it serves now (§15.2, §15.3).

The rules below are those of the `ndn-link` crate, which ndn-fwd uses. An implementation that wants ndn-fwd peers to behave predictably MUST NOT admit a link that these rules refuse, and MUST use the close codes given here. It MAY refuse more.

### 7.1 Identifying the peer from its hello

A peer is identified by its link key's certificate (the leaf, steps 1–11 below) and by each membership its hello carries (steps M1–M5). Each yields an *identity* — a device of a namespace — or nothing. Some outcomes refuse the link at once (*refuse*); others, marked *refuse unless identified*, refuse it only when no other certificate or membership of the hello identifies the peer: the refusal of the first such outcome applies then. This keeps a revocation per namespace: a device revoked in A but a member of C in good standing is still identified in C ([Decision 31](#20-decisions)).

Before these steps, a side that knows a certificate of the peer's key MUST, if a held trust context revokes that certificate, skip steps 1–11 and *refuse unless identified* with **0x12**, whatever the hello carries. "Knows" means a certificate it serves or has cached whose public key is the peer's NDN public key; ndn-rs looks it up by the key's SHA-256 fingerprint. A revoked device that sends no certificate and no membership therefore gets no enrollment link either. A key the side knows no certificate of cannot be told from a new key, because a revoked device can always make one. For such keys the CA, which refuses to certify a revoked device again, is the backstop ([Decision 5](#20-decisions)).

Steps, in order. *Unknown(why)* means "no namespace identity". It is not a refusal: another membership, an expected fingerprint or an enrollment link may still admit the peer.

1. If the hello carries no certificate: **Unknown**.
2. Decode the leaf as a Data packet, then as a certificate. On failure, refuse with **0x15**.
3. If the leaf's public key (normalized per §3.2) ≠ the peer's NDN public key, refuse with **0x11**. The comparison is byte by byte, so a certificate MUST carry a P-256 key as the uncompressed-point SPKI of §3.2 ([Decision 12](#20-decisions)).
4. Decode the first `MAX_CHAIN` (8) issuers. If any fails to decode, refuse with **0x15**. Find the held trust context whose namespace is the longest prefix of the leaf's name. If there is none, the peer is identified offline against its root instead: steps R1–R7 below.
5. If the context revokes the leaf, *refuse unless identified* with **0x12**. A revocation entry covers every name it is a prefix of, so revoking a key name covers all of its certificates ([trust-context.md](trust-context.md)).
6. The leaf's name MUST be a device key name `/<ns>/<role>/<device>/KEY/<key-id>[/…]`, where:
   - `<role>` is a GenericNameComponent (0x08) equal to `admin`, `member`, `node` or `guest`;
   - `<device>` is a GenericNameComponent of 1–63 bytes from `[A-Za-z0-9._-]`, starting with a letter or digit, and not `KEY`, `CA` or a role word (in any case);
   - the component after `<device>` is the GenericNameComponent `KEY`.

   Otherwise: **Unknown**.
7. If the leaf is not within its ValidityPeriod now: **Unknown**.
8. (The issuers were decoded in step 4.)
9. If the context revokes any of those issuers, *refuse unless identified* with **0x12**.
10. Validate the leaf in the held trust context ([trust-context.md](trust-context.md): chain to an anchor, schema, hierarchical rule), with a chain depth of at most 8.
    - Issuers come from the hello first. A missing issuer may then be taken from certificates the side itself serves or has cached.
    - The side MUST NOT fetch anything (the link is not up yet). It also MUST NOT add the peer's certificates to its general certificate cache.
    - If validation fails or the chain is incomplete: **Unknown**, except that a side whose serving policy is not `own` *refuses unless identified* with **0x19** when the last decoded issuer is a self-signed certificate that is not an anchor of the held context: the peer is of another root's namespace with the held namespace's name, or a name under it, and the side could not route both (§15.3).
11. Otherwise the peer is the device `/<ns>/<role>/<device>` of namespace `/<ns>`. The leaf and issuer names are remembered for §12.

**A namespace this side does not hold.** The peer is checked offline against the self-signed root certificate at the end of the chain its hello carries (§5.2). Steps:

- R1. The last decoded issuer MUST be self-signed (its KeyLocator names its own key). Otherwise: **Unknown**.
- R2. The namespace `/<ns>` is the root's key name without its last two components (`/<ns>/KEY/<key-id>`); it MUST NOT be empty. Otherwise: **Unknown**.
- R3. The leaf's name MUST be a device key name of `/<ns>` (as step 6). Otherwise: **Unknown**.
- R4. The leaf MUST be within its ValidityPeriod now. Otherwise: **Unknown**.
- R5. `/<ns>` MUST be a valid namespace name for `ndn-cert`'s namespace schema, and the root MUST be within its ValidityPeriod now. Otherwise: **Unknown**.
- R6. Validate the leaf in the trust context `ndn-cert` makes for a namespace — its namespace schema (authoritative), its CA at `/<ns>/CA`, with the root as its only anchor — using only the certificates of the hello, with a chain depth of at most 8, never fetching. If validation fails or the chain is incomplete: **Unknown**.
- R7. Otherwise the peer is the device `/<ns>/<role>/<device>` of namespace `/<ns>`, a *served device* whose root key fingerprint (§1) is that of the root's key. Nothing about it can be revoked or checked against a link policy: the side holds neither (§15.2).

A served device is never matched to a `[[peer]]` by its device name: only a held namespace confirms the device a peer entry names. When a peer entry exists for a link anyway (it was dialed, or its `key` matches), a served identity counts as **Unknown** for §7.3.

**Memberships.** Then, for each of the first `MEMBERSHIPS_MAX` (8) Memberships of the hello, in order (§5.8):

- M1. Decode its first certificate as a Data packet, then as a certificate. On failure, refuse with **0x15**.
- M2. Recompute the binding transcript (§5.8) from this side's own view: the **peer's** link key fingerprint (from TLS), this connection's channel binding (the TLS exporter; for a punch, the punch value), and SHA-256 of that certificate's Data.
- M3. Verify the binding over it under the certificate's public key, with the algorithm of that key (Ed25519 or ECDSA P-256). If the key is of another type, or the signature does not verify, refuse with **0x1A** (MembershipNotBound): the sender does not hold the certificate's key, or the binding was made for another connection or another link key. The check comes before anything is validated, and nothing of the membership is used when it fails.
- M4. Identify the certificate with the membership's other certificates as its issuers, exactly as steps 4–11 (or R1–R7) do for the leaf, with the bound key in place of the TLS key (step 3 is M3). Its outcomes are those of the leaf's: 0x15 refuses; 0x12 and 0x19 *refuse unless identified*; Unknown identifies nothing.
- M5. An identity in a namespace already identified (by the leaf or an earlier membership) is not counted again.

The peer's identities are, in order, the leaf's and those of its memberships. When there are none, the first *refuse unless identified* refusal applies, if any; otherwise the peer is **Unknown** (why: the leaf's reason; for a hello without a leaf, the first membership's).

### 7.2 Configured peers

A configured peer has an optional expected fingerprint (`key`) and an optional expected device name (`device`); at least one is present. The **peer entry** for a link is:

- the `[[peer]]` this side dialed, for a dialed link;
- otherwise the first `[[peer]]` whose `key` equals the fingerprint, or whose `device` equals a device name identified in a held namespace (by the leaf or by a membership).

*key-expected* means a peer entry exists and its `key` equals the fingerprint.

### 7.3 Decision

Rules are evaluated in order. The first that applies decides. *Identified* means the peer has at least one identity (§7.1); each rule that speaks of "the identity" applies to each of them, as said.

1. If a peer entry exists and has a `key` that ≠ the fingerprint: refuse **0x14**.
2. If a peer entry exists and has a `device`:
   - If the peer was identified, and none of its identities is that device: refuse **0x14**. Otherwise the identity that is that device *decides* the link (it comes first).
   - If the peer is Unknown and not key-expected:
     - If this side dialed the link, and holds no certificate in `ns` (of its link key or of a membership), admit as a **device-side enrollment link** for `ns` (§8.2). Here `ns` is the held namespace that is the longest prefix of the expected device name; if none is held, it is the expected device name without its last two components.
     - Otherwise refuse **0x10**.
3. Each identity in a held namespace is judged by that namespace's link policy (§7.4); the identities it does not allow are dropped:
   - the policy does not allow the identity's role to link: **0x13**;
   - the peer entry is a relay — another entry names it in `relay`, or this side uses it as a relay (§15.5) — and the policy does not allow the identity's role to relay: **0x13**.

   If the identity rule 2 chose is dropped, or every identity is: refuse with the first of these refusals.
4. If the peer was identified and a peer entry exists: admit a **full link**, by the remaining identities (served identities do not count here, §7.1).
5. If the peer was identified and no peer entry exists, the serving policy decides (§15.2), for each remaining identity:
   - the peer is admitted on a **full link** by every identity the policy serves (for a namespace other than this side's own, under its quotas, §15.3). Identities of this side's own namespaces come first, then those served without limits, then those under quotas; the first decides the link (its quotas, if any, bound the link, §15.3);
   - when the policy serves none, refuse with the refusal of the first (**0x19**, or **0x16** for a full quota). A served device gets no enrollment link: it proved who it is, and this side does not serve it. When this side is eligible to relay enrollments (§8.1), the 0x19 reason says the device can enroll over it by linking with a hello that holds no certificate of another namespace (rule 6).
6. If the peer is Unknown and not key-expected:
   - If the link was not dialed by this side, has no peer entry, and this side is eligible to relay enrollments (§8.1), admit as a **relay-side enrollment link**. If no enrollment slot is free, refuse **0x16** instead (§8.4).
   - Otherwise, if its hello carries no certificate, it has no peer entry and the serving policy is `listed` or `open`: refuse **0x19** (a relay routes a served device by the device name its certificate gives).
   - Otherwise refuse **0x10**.
7. Otherwise admit a **full link**: a key-expected peer, whether identified or not.

The identities a link is admitted by are what the rest of this spec calls the peer's identities on the link: its routes (§10), presence (§14.8), revocation while linked (§12) and transit (§15.7) apply to each.

A revoked key or issuer is refused in §7.1 before any of these rules, unless another certificate or membership identifies the peer, so it never reaches an enrollment link through them. This includes a peer that sends no certificate, when the side knows a revoked certificate of its key (§7.1).

Under the default serving policy `own`, rule 5 admits unasked only the devices of the namespaces this side holds a certificate in. A device of a held namespace this side has no certificate in, which earlier versions admitted, is refused with 0x19 unless a peer entry names it ([Decision 20](#20-decisions)).

### 7.4 Link policy semantics

The link policy is defined in [trust-context.md](trust-context.md) §3.3.10 (TLV 0x0412, UTF-8 `<roles>;<relay roles>;<enrollment|no-enrollment>[;<direct|no-direct>[;<pairs>]]`). It has five fields:

- `roles`: a list of role words. Empty means every role.
- `relay_roles`: a list of role words.
- `enrollment_links`: a boolean.
- `direct_paths`: a boolean (absent from the wire means true).
- `direct_pairs`: the *direct-path role matrix*, a list of unordered role pairs (absent from the wire means the default pairs).

A context that carries no link policy uses the default: `roles` = [] (any role), `relay_roles` = [`node`], `enrollment_links` = true, `direct_paths` = true, `direct_pairs` = every pair of `admin`, `member` and `node` (each role with itself too), none with `guest`.

- A role *may link* iff `roles` is empty or contains it.
- A role *may relay* iff it may link and `relay_roles` contains it.
- A context *admits enrollment links* iff `enrollment_links` is true and the context names at least one CA endpoint.
- Two devices of the namespace with roles `a` and `b` *may make a direct path* iff `direct_paths` is true and `{a, b}` is one of `direct_pairs` (`allows_direct_path`). A device punches no device of that namespace, and refuses its punches and direct paths with 0x18, unless the pair of its own role and the other's is allowed (§14.1, §14.4, §14.6); a relay lists to a device in presence only the devices whose role pairs with that device's role (§14.8). With the default pairs a `guest` makes no direct path, and its addresses go to nobody. Turning direct paths off, or removing a pair, is a narrowing ([trust-context.md](trust-context.md) §5.3); links that are up stay up, and a direct path that is up ends at its next drop.

## 8. Enrollment links

An enrollment link lets a device that is reachable only over QUIC enroll. It carries the device's Interests for the namespace's CA endpoints, trust context and certificates, and the answers to them. Nothing else crosses it, in either direction.

### 8.1 Relay side

A side is eligible to relay enrollments for namespace `ns` when all of these hold for a held context of `ns`:

- the link policy has `enrollment_links` = true;
- the context names at least one CA endpoint;
- the side holds a device certificate in `ns` (of its link key, or of a membership, §5.8) whose role the policy lets relay.

The relay's LinkVerdict carries an EnrollmentLink listing **every** namespace it is eligible for, in no defined order. Its face scope (§8.3) is:

| | |
|---|---|
| receives from the device | Interests only |
| sends to the device | answers only (Data and Nacks) |
| name filter | `in_enrollment(namespaces, name, relay = true)` |
| receive rate limit | `ENROLLMENT_INTERESTS` (burst 32, 4/s) |

The relay installs **no routes** over an enrollment link. Answers return the way their Interests came.

### 8.2 Device side

A device that dialed a `[[peer]]` naming a device in namespace `ns`, where it holds no certificate in `ns`, cannot confirm that peer yet, so it admits the link as an enrollment link for `ns` only (§7.3 rule 2). Its LinkVerdict is a full verdict (no EnrollmentLink). Its face scope is:

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

**Rate limit.** This is a token bucket per link, on received frames only. It starts full at `burst` tokens and refills continuously at `per_sec` tokens per second, up to `burst`. Every received frame that carries a network packet or a fragment of one costs one token. A frame with no Fragment (an Ack-only or idle frame, rule 2) costs nothing, so the peer's acknowledgements of the fragments this side sends cannot crowd out the peer's packets ([Decision 7](#20-decisions)). A frame that finds no token is dropped without a Nack. A scope MAY also name a bucket shared with other links (the serving quotas of §15.3); a received frame that passed the link's own bucket then takes a token from the shared one too, and is dropped without a Nack when it finds none.

### 8.4 Slots and idle close (relay side)

- A relay holds at most `ENROLLMENT_LINKS_MAX` = 32 enrollment links at once, and at most `ENROLLMENT_LINKS_PER_SOURCE` = 4 from one source IP address (several devices may enroll behind one NAT).
- A relay that is out of slots refuses with **0x16** after deciding and before sending its verdict. A slot is released when the link ends.
- **Idle close.** If a relay-side enrollment link passes no packet (rule 2 frames excluded) for `ENROLLMENT_IDLE` = 120 s, the relay closes it with **0x02**.
  - 120 s is twice `MAX_STATUS_HOLD` (60 s), so a device waiting for an approval keeps its link ([ndncert-extensions.md](ndncert-extensions.md)).
  - ndn-fwd checks every 30 s (`ENROLLMENT_IDLE / 4`), so the close happens 120–150 s after the last packet.
  - The device side applies no idle close.

### 8.5 Relink after enrollment, and when memberships change

Each side records, per link, the namespaces the link is an enrollment link for *on this device's behalf*. These are:

- the namespaces in the peer's EnrollmentLink; and
- `ns`, if this side admitted the link as a device-side enrollment link.

It also records, per full link, the namespaces its own hello showed there: its link key certificate's and its memberships' (§5.8).

When the device's identities change — it enrolled (its link key changed, or a membership was added), or a membership ended — it checks each link:

- an enrollment link for a namespace it now holds a device certificate in (of its link key, or of a membership): it closes the link with **0x03** (Enrolled) and dials that `[[peer]]` again once, even if the peer is not persistent. It now presents its certificate and gets a full link;
- a full link whose hello showed other namespaces than the device holds now: it closes the link path with **0x03** too, so that it is made again with a hello showing them (a hello is sent once per connection). A link this device dialled it dials again once; one the other device dialled, that device dials again (0x03 is transient). Direct paths stay until they end.

ndn-rs does this in `Links::identities_changed`, which the host calls on each change of its signing identities or link key (ndn-fwd: the identity watch of its node identity; a mobile host: its identity core).

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
| link path to a relay this device uses (§15.5) | the namespaces of this device it uses the relay for (§15.5: for a relay its person added, every namespace it holds a certificate in, of its link key or of a membership; for one a namespace advertises, each of its namespaces whose trust context advertises that relay) at cost *r*, the relay's rank (§15.6) — or, when the relay's entry has `routes`, or there is no such namespace, its default routes at *r*; plus, for every `[[peer]]` X whose `relay` names it, X's default routes at *r* + `VIA_RELAY_COST` |
| other full link | the peer's *default routes* at cost 0, plus, for every `[[peer]]` X whose `relay` names this link's peer entry, X's default routes at cost `VIA_RELAY_COST` = 10 |

**Default routes** of the peer entry P (if any), given the identities the link was admitted by (if any, §7.3), are the first of these that applies:

1. P's `routes`, if configured;
2. for each identity: `/<ns>` of the identity, if it is a `node` device and P is a peer this side dials, meaning the host gives P at least one path candidate (§13.1); else its device name `/<ns>/<role>/<device>` (also for a served device, §15.2: the relay routes it by the name its certificate gives). The `node` rule holds whichever side dialed this link: when both dial, the duplicate-link rule keeps one link (§11), and both sides still route the same way. A `node` whose peer entry this side does not dial (it only accepts that node's links) is routed by its device name ([Decision 8](#20-decisions));
3. P's `device`, if the peer was not identified;
4. otherwise none.

A device admitted by its A certificate and its C membership is thus routed by both of its device names, and loses the routes of one when that membership is revoked (§12).

For a peer reached through a relay, the default routes are computed from that peer's own entry with no identity, so they are its `routes`, else its `device`.

A direct link to a peer costs 0. A route through a relay costs at least 10, so the direct link wins while it is up. A direct path (§14) gets the routes of a full link to its peer, computed the same way, on its own face; the relay's routes stay, so when the direct path ends its face and routes go and the relay carries the traffic again.

Besides the routes a link gets when it comes up, `ndn-link` installs:

- for a member a relay lists in presence, the member's device name over that relay's link face at `VIA_RELAY_COST`, taken away when the relay no longer lists it (§14.8);
- routes to the waiting face at `WAITING_COST` = 1000: the routes an on-demand link will get, while it is down (§16.3), and on a relay, the routes a sleeping device's link had (§17.2). Every link's routes cost less, so they win while a link is up.

## 11. Duplicate-link rule

Between two devices there is at most one link, keyed by the peer's fingerprint. A link has at most one path of each kind (§1): the rule below applies among paths of the same kind, so a direct path joins a link path to the same device instead of replacing it. Direct paths are always dialled by the device with the smaller fingerprint (§14.5), so two direct paths are always of the same direction and the newer stays.

When a link to a fingerprint is up and another link to the same fingerprint comes up, the side compares them:

- **Both sides dialed each other** (the two links have opposite directions on this side): the link **dialed by the device with the smaller fingerprint** (§3.3 order) stays. The other is closed with **0x01** (Replaced).
- **Same direction** (the peer dialed again after losing the old link, or this side redialed): the **newer** link stays and the older is closed with **0x01**.

Both sides apply the rule independently, after the link is up (§5.4 step 5). For the opposite-direction case they reach the same result. A side whose own fingerprint is unavailable treats every duplicate as same-direction ([Decision 11](#20-decisions)). The rule is `ndn_link::keeps_existing(existing direction, new direction, own fingerprint, peer fingerprint)`, which returns whether the link already in place stays.

Example with the test keys of §19: the P-256 key's fingerprint `0ca9…` is smaller than the Ed25519 key's `3475…`, so if they dial each other at once, the link the P-256 device dialed stays.

## 12. Revocation while linked

When a side adopts a trust context version, it checks, on every up link, each identity the link was admitted by (§7.3) that lies under that context's namespace. If any recorded certificate name of that identity (its certificate or an issuer sent with it in the hello or the membership, §7.1 step 11, M4) is revoked by the new version, the identity is taken from the link:

- when no identity is left, the side closes the link at once with **0x12**;
- otherwise the link stays, admitted by the others: its faces lose the routes of that identity (its device name, and its namespace for a `node` this side dials, §10), and, on a relay, the device is told the namespace's empty presence list and the other members of that namespace no longer see it listed (§14.8).

A link admitted only by expected fingerprint (no identity) is not affected. It ends when the operator removes the `[[peer]] key`.

## 13. Dialing, backoff and inbound limits

### 13.1 Dialing and backoff

- A peer is dialed while the host gives it at least one path candidate and its link is wanted: always for mode `always`, when asked for `off`, when asked, the host is active or an Interest waits for it for `on-demand` (§16.1), and, for a relay this device uses, only while it is chosen or retried (§15.6). A candidate is either a socket address or a `host:port` endpoint; ndn-fwd gives the `[[peer]] endpoint` list. Each attempt tries the candidates in order, and each endpoint's resolved addresses in order. The first address that yields a link wins; otherwise the attempt fails with the last error.
- A dial carries the `[[peer]]` `key` as its expected fingerprint, if one is set (§3.4).
- If the peer is already linked (it dialed this side), the dialer does not dial: it keeps that link as its mode says (§16.2) and waits for it to end.
- `persistent` (default true) peers are redialed while their link is wanted:

  | After | Wait before redial |
  |---|---|
  | an up link ended (any reason) | `BACKOFF_FIRST` = 500 ms |
  | a failure that is transient | starts at 500 ms and doubles after each consecutive failure, up to `BACKOFF_MAX` = 30 s; reset by a successful link |
  | a failure that is not transient | `BACKOFF_REFUSED` = 60 s |

- A non-persistent peer of mode `always` is not redialed after its link ends or a dial fails; the exception is the one redial after 0x03 (§8.5). For the other modes, `persistent` has no effect: the mode decides when the link is wanted.
- A link this device closed itself because it no longer wants it (0x05, 0x06, §15.6, §16.2) is not followed by the redial wait; the device dials again as soon as the link is wanted again.
- When the host reports a network change (`Links::network_changed`), every peer's backoff is skipped: links are dialled again at once, and direct paths are punched again at once as §14.7 says.
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
- A refusal counts against the source when its handshake fails, when admission refuses it with a close code, or when its hello or verdict exchange fails (§6.3). Refusals older than the refusal window are forgotten: the count starts again at the first refusal after the window of the previous first refusal ends. It also resets when it reaches the threshold and the cooldown starts ([Decision 9](#20-decisions)).

## 14. Direct paths

Two devices that each reach a relay but not each other (NATs, firewalls) talk through the relay (§10). A *direct path* is a QUIC path between them made by a NAT hole punch: the punch is signalled with NDN packets through whatever routes reach the other device (normally its relay), both devices send probes from their link sockets to the other's candidate addresses, and one dials. The relay takes no part beyond forwarding the punch, reporting addresses (§5.5) and, for direct paths by membership, telling the members of a namespace which others are linked to it (presence, §14.8).

### 14.1 When a device punches

A device punches a peer entry P while all of these hold, and again after a direct path ends, a punch fails, or its network changes (§14.7):

- P names a `device` (the punch is sent to that name) and a `relay` (P is reached through it), and P's `direct` is not false;
- the link to P's relay is up, and no link path to P is up;
- the link policy of the namespace of P's `device`, if this device holds it, allows a direct path between this device's role and P's (§7.4);
- this device has fewer direct paths up than its bound (§14.9); otherwise it waits and checks again every 5 s.

It also punches, without a peer entry, the members its relays list in presence (§14.8). A device answers the punches of devices without a peer entry for them (§14.4): only one side needs one.

### 14.2 Candidates

A candidate is a kind and a UDP address (§5.5 encoding). Kinds: 0 host (an interface address on the link socket's port; loopback and link-local skipped; a socket bound to one address offers that address), 1 reflexive (an address a full link's other side reports, §5.5, for the same socket), 2 advertised (configured, e.g. a port forward; ndn-fwd `[[face]] kind = "quic" advertise`), 3 mapped (a port-mapping protocol). A sender lists reflexive candidates first and sends at most `CANDIDATES_MAX` = 8; a receiver uses at most 8 and ignores candidates of an unknown kind. The punch uses the socket of the link to the relay, so the reflexive candidate is the NAT mapping the relay saw.

### 14.3 The punch Interest and its answer

Name: `<device>/32=link/32=punch/<session>` followed by a ParametersSha256DigestComponent, where `<device>` is the punched device's name (any of its names: a device takes punches under the name of each namespace it holds a certificate in) and `<session>` 8 random bytes as a GenericNameComponent. The Interest MUST be an NDN signed Interest (InterestSignatureInfo with SignatureNonce and SignatureTime) signed with the sender's *punch key*, MustBeFresh, InterestLifetime `PUNCH_ANSWER_TIMEOUT` = 4 s. Its ApplicationParameters, and the Content of the answering Data (named as the Interest, signed with the answerer's punch key), are a punch message. The punch key is the sender's link key, KeyLocator its certificate's name — except when the message shows a Membership (below): then it is that membership's key, KeyLocator the membership certificate's name, because the punch is named under that namespace and the forwarders on its way (the relay, both devices) validate it in that namespace, where the link key has no certificate:

```
PunchMessage = PunchKey *Candidate [PunchRefusal] *Certificate *Membership
PunchKey     = 0x0460 TLV-LENGTH SubjectPublicKeyInfo   ; the sender's link key, as in TLS (§3.2)
Candidate    = 0x0462 TLV-LENGTH CandidateKind UdpAddress
CandidateKind = 0x0464 TLV-LENGTH(=1) OCTET
UdpAddress   = 0x0466 TLV-LENGTH(=6|18) 4OCTET/16OCTET 2OCTET
PunchRefusal = 0x0468 TLV-LENGTH RefusalCode RefusalText
RefusalCode  = 0x046A TLV-LENGTH NonNegativeInteger    ; a code of §6.1
RefusalText  = 0x046C TLV-LENGTH *OCTET                 ; UTF-8, for a person
Certificate  = Data                                     ; the sender's certificate, then issuers (as §5.2)
Membership   = 0x045C …                                 ; as §5.8, bound to this punch
```

Exactly one PunchKey is REQUIRED. Unknown even types above 31 are skipped; any other unknown type makes the message malformed.

**Punches per namespace.** A punch is about one namespace: that of the punched device's name (the request), or of the name of this device the request was sent to (the answer, and a refusal). When the sender's link key is not certified in that namespace but it is a member of it with another key, its message carries that one Membership (§5.8), and no other, and is signed by that membership's key (above). Its binding's channel value is the punch's: SHA-256(`"ndn-link/1 punch"` ‖ session), so it binds the fingerprint of the sender's link key (the PunchKey, with which the direct path will be dialled or accepted) and holds for this punch only. The PunchKey stays the link key: the direct path's TLS key is the one the punch names (§14.5), and its hello shows the same membership again, bound to the direct path's connection (§14.6). A punch signed by a link key with no certificate in the namespace would be dropped by the forwarders validating it there (the relay first), and the punching device would see no answer.

Each side verifies the other's signature with its punch key — the first Membership's certificate key when the message shows one, else the PunchKey — and identifies the sender from the certificates and memberships exactly as from a LinkHello (§7.1 with the punch's channel value: the membership's binding ties its key to the PunchKey; §7.3: the punched side as for a link it did not dial, the punching side as for the peer entry it dialled, or, for a member, as for a link it did not dial). An answer that does not verify, or identifies another device than P, makes no direct path. For a member punched by membership (§14.8), the answer's PunchKey MUST also be the key its relay listed, and one of its identities MUST be the listed device ([Decision 31](#20-decisions)).

### 14.4 Answering a punch

The punched device, before anything else, takes a token from a bucket over all requesters (`PUNCH_CHECKS`: burst 16, 4/s) and drops the Interest silently without one, and drops silently an Interest that is malformed or whose signature does not verify under its PunchKey. Then it refuses, with a signed answer carrying a PunchRefusal, when:

- SignatureTime is more than `PUNCH_GRACE` = 120 s from its clock, or the (SignatureNonce, SignatureTime) pair was seen from that key before: 0x15;
- the key sent more than `PUNCH_BURST` = 3 requests at once (one more per `PUNCH_REFILL` = 20 s): 0x16;
- admission (§7, as for a link this device did not dial, serving policy included) refuses the sender, or would admit it only on an enrollment link: the code of that refusal, or 0x10;
- direct paths are off for it, or the role matrix does not pair the two devices' roles (§7.4), or its `[[peer]]` says `direct = false`: 0x18;
- it runs `PUNCHES_MAX` = 16 punches already: 0x16;
- it has no direct path up to that key and already has as many direct paths up as its bound (§14.9): 0x16;
- the request offers no candidate: 0x15; it has no link socket for the request's first candidate: 0x16.

A refused punch causes no probe and no dial. Otherwise it answers with its own candidates and certificates, and starts its side of the punch (§14.5). A refusal with a transient code (§6.1) is retried by the punching side with its backoff; a non-transient one after `DIRECT_RETRY_REFUSED`.

### 14.5 Probes and the dial

Once a side has sent (punched side) or verified (punching side) the answer, it:

1. accepts, on that link socket, connections from the other's candidates for `PUNCH_WINDOW` = 10 s — a socket that does not listen accepts nothing else, and accepts these only while the punch runs;
2. sends a probe from that socket to each of the other's candidates of a family the socket reaches, every `PROBE_INTERVAL` = 200 ms for `PROBE_WINDOW` = 4 s. A probe is 24 bytes: `00` ‖ ASCII `ndn-link probe` ‖ `01` ‖ the session. Probes MUST go only to candidates the other device signed. A receiver hands probes to the punch of their session (to report whether any arrived) and never to QUIC; probes of an unknown session are dropped;
3. if its fingerprint is the smaller (§3.3), dials, `PROBE_INTERVAL` after its first probes, the other's candidates in this order, each `DIAL_STAGGER` = 250 ms after the previous: IPv6 host, IPv4 host on one of its own subnets, reflexive, advertised and mapped (other host candidates are probed but not dialled). The dial expects the other's PunchKey fingerprint (§3.4) and uses the direct-path timers (§3.1). The first admitted connection wins; the others are closed.

If no direct path is admitted within `PUNCH_WINDOW`, the punch failed; its status says what was probed and whether probes from the other device arrived (none: both networks drop unsolicited UDP or map each destination to another port, e.g. symmetric NATs on both sides).

### 14.6 Admitting a direct path

The dialer's LinkHello carries DirectPath = the session (§5.2); the listener's carries the session of the punch it runs with the dialer's key, if any — when it runs several (the other device restarted, or punched again, while an earlier punch was still in its window), the one it began last, which is the one that device dials now. The connection is the punch's direct path iff both name the same session. A listener that runs no punch of the named session with that key closes with 0x04; a dialer whose listener did not name the session closes with 0x04. A direct path is admitted like any link (§7) and further: it MUST be a full link (else 0x10), direct paths MUST NOT be off for the peer, nor its role unpaired with this device's (else 0x18), and only the first path of a session is admitted (later ones 0x01). It is registered as the direct path of the link to that device (§11) and gets routes (§10).

### 14.7 Fallback and retry

A direct path ends like any link (idle timeout 8 s, close). Its face and routes go; traffic follows the relay's routes again without any action. The punching side punches again `DIRECT_RETRY_FIRST` = 5 s after a direct path ended; after a failed punch it waits 5 s, doubling to `DIRECT_RETRY_MAX` = 300 s, and `DIRECT_RETRY_REFUSED` = 600 s after a non-transient refusal; a direct path that comes up resets the doubling. A direct path that a newer one replaced (§11) is not followed by the retry wait.

**After a network change.** When the host reports a network change (`Links::network_changed`), a device closes with 0x01 every direct path to a device whose name it knows (from its certificate or its peer entry: the punch is sent to that name, §14.3), and punches each of those devices again at once (§14.3–§14.6). It does so whichever side punched before, from the link socket that path used; it leaves any other direct path as it is. The punch goes once the path's face and routes are gone, so through the routes that reach the device without it (normally its relay's). This is needed because a QUIC server cannot move to another address (RFC 9000 §9): a path this device accepted is dead after the change, and the other device would keep sending into it until its idle timeout. A path this device dialled migrates with it, but the other device's NAT may filter the new address. The punch carries the candidates of the new network. Its reflexive candidates are what the device's full links report at that moment, and a relay reports a migrated link's new address within ndn-rs's `OBSERVE_INTERVAL` of 5 s (§5.5), so behind a NAT this punch may fail. If the device punches that peer (§14.1, §14.8), it goes on from this punch as from any other: retry with backoff after a failure. Otherwise the other device punches again as above, its path having been closed by the punch (next paragraph).

**A punch from a device with a direct path up.** A device punches only while no direct path to the other is up from its view (§14.1, §14.8), or after its network changed. So a device that accepts a punch (it answers with its candidates, §14.4) from a key it still has a direct path up to first closes that path with 0x01. That path's routes go at once, not at its idle timeout.

### 14.8 Direct paths by membership (presence)

Devices of a namespace that are linked to a common relay make direct paths with each other without a peer entry for each other, where the namespace's role matrix allows them. Nothing watches traffic: membership and the policy decide.

**Relay side.** A relay that holds a namespace's trust context sends each *member* linked to it — a device the link was admitted by an identity in that held context (§7.1 steps 1–11 for its link key, M1–M5 for a membership; not a served device) over a full link path — a Presence for that namespace (§5.7). A device admitted in several held namespaces gets one Presence per namespace, and is listed in each under its name there; the key fingerprint listed is always its link key's. It lists the other members linked to it now whose role the context's role matrix pairs with the receiver's (`allows_direct_path(receiver's role, other's role)`), each by device name and key fingerprint. The relay sends it when a member's full link comes up, when a member's last path ends, when a member's identity in the namespace is revoked while it stays linked by another (it gets the namespace's empty list, §12), and when it adopts a new version of a trust context (the matrix may have changed). A member whose role pairs with none of the others gets an empty list. The relay needs no certificate in the namespace, only its trust context. A relay MUST NOT send presence for a namespace whose trust context it does not hold: it serves such a namespace by root fingerprint or as an open relay (§15.2), and can apply neither its membership nor its policy.

**Why the control stream.** The alternatives were signed presence records (published per device, or in a namespace sync group) and a signed-Interest listing the relay answers. The control stream was chosen ([Decision 27](#20-decisions)) because:

- it is authenticated already: both keys were proven in the link's handshake (§3.4) and the member was certified in the namespace at admission (§7.1), so a list on the stream is as authentic as a signed record, without a signature per list;
- it reaches only devices the relay admitted as members, each filtered by the role matrix for its role. Records in a sync group would show every participant every member, regardless of role, and anyone can follow a sync group by name;
- it is current by construction: it changes when links come and go, with no record lifetimes, no polling and no freshness to tune, and it says "linked here now", which a record cannot;
- it costs nothing while nothing changes: no Interests, no signatures, no state outside the links.

**Device side.** A device follows the presence sent on the full link path to each peer entry that is a relay — one it uses (§15.5) or one another peer is reached through — or that is identified in a held namespace whose link policy lets its role relay (`allows_relay`, §7.4), such as a plain `[[peer]]` for the namespace's relay. Unless direct paths by membership are off (`DirectOptions::membership`, default on; ndn-fwd `[direct] membership`), for each listed namespace it holds a certificate in (of its link key or of a membership), it punches every listed device that

- is not itself (by key or by any of its device names);
- has a key fingerprint greater than its own (§3.3 order). The device with the smaller fingerprint punches and the other answers, the order in which the smaller fingerprint also dials (§14.5), so two members never punch each other at once;
- is named under the listed namespace;
- has no peer entry (by key or device name): a peer entry is punched as such (§14.1);
- is paired with this device's role in that namespace by the role matrix of this device's own trust context of it (§7.4);
- is not punched already for another namespace the relay lists it in (a device is punched once, by its link key).

The punch is in the listed namespace: it shows this device's membership of it when its link key is not certified there (§14.3).

For each such member it routes the member's device name over the relay's link face at `VIA_RELAY_COST` (§10), and punches it through that relay with the rules of §14.3–§14.7 and the bound of §14.9, for as long as the relay lists it. When the relay no longer lists the member, or the relay's link ends, the device stops punching it and removes that route; a direct path that is up stays until it ends.

**Addresses.** Presence carries no address. A device's candidates travel only in its signed punch request and its signed answer (§14.3), to a device whose punch it admitted under the same role matrix (§14.4). They are signed, not encrypted: the relay and any forwarder that carries a punch can read them; the relay sees each device's reflexive address anyway. With the default pairs a `guest` is listed to nobody, is told of nobody, and neither punches nor admits a punch by role, so its addresses go to nobody.

**A relay that lies.** A relay can list devices that are not linked, or keys that are not theirs. A member then punches the named device; each punch needs a signed answer from the listed key whose certificate validates as the listed device in the member's held namespace, so no direct path is made with anyone else. What the relay learns from it is the punch request it forwards. A device trusts the presence of the relays it uses as far as it trusts them to forward its traffic.

### 14.9 How many direct paths

A device has at most `max_paths` direct paths up at once (`DirectOptions::max_paths`, default 8; ndn-fwd `[direct] max_paths`): those it punched and those it answered, to peer entries and members alike; a device to which a direct path is up counts once.

- **Punching side.** While the bound is reached, a punch of a peer entry waits, and is checked again every 5 s. Of the members that wait for a direct path (none is up to them), a member punches only when it is among the first *free* = `max_paths` − (direct paths up) in this order: the members whose last direct path carried NDN datagrams and ended most recently first, then those that never had one, each group by key fingerprint (smaller first). Others wait and are checked again every 5 s. Recent traffic only orders members that membership already qualifies; it never starts a punch.
- **Answering side.** A device that has no direct path up to the punching key, and as many direct paths up as its bound, refuses the punch with **0x16** (§14.4).

### 14.10 Status and link commands

ndn-rs reports per device (`Links::report`): its paths (kind `link`, `direct` or `relay` — the relay's link face —, face, remote address, RTT, age) and the direct-path state: `none`, `off`, `trying`, `up`, `not-possible` or `refused`, with a sentence and when the next punch is due; for a configured device, its link mode and, when it is not linked, why; for a relay this device uses, its source, preference and state (`linked`, `trying`, `down`, `standby` or `off`, §15.6) with a sentence; on a relay, for a device asleep here, how long, the Interests held for it, whether it asked to be held for and to be woken, and the wakes sent (§17). For the device itself: its key, the probes it sent, the punches it refused, its serving policy in one line (§15.2), the Interests it holds for sleeping devices, and the wakes it sent.

ndn-fwd serves this as the management dataset `/localhost/nfd/links/list` (local operators only), and `ndn-ctl link list` prints it ([reference/links.md](../wiki/src/reference/links.md)). Its TLVs are those of ndn-mgmt-wire `link_status` (`link_tlv`), all even and so skippable by an older decoder: 0x04A0–0x04BE for keys, paths and direct-path state, and

| TLV-TYPE | Field | In | Value |
|---|---|---|---|
| 0x04C0 | mode | LINK | `always`, `on-demand` or `off` |
| 0x04C2 | idle_secs | LINK, mode `on-demand` | NonNegativeInteger: the idle close (s) |
| 0x04C4 | relay | LINK | nested: the device is a relay this device uses |
| 0x04C6 | source | relay | `user` or `namespace:<namespace>` |
| 0x04C8 | preference | relay | NonNegativeInteger, lower preferred |
| 0x04CA | state | relay | `linked`, `trying`, `down`, `standby` or `off` |
| 0x04CC | text | relay | why, and what to do if anything |
| 0x04CE | asleep | LINK (relay side) | nested: the device is asleep here |
| 0x04D0 | since_secs | asleep | NonNegativeInteger (s) |
| 0x04D2 | held | asleep; top level | NonNegativeInteger: Interests held for that device; top level: `held_total`, for all |
| 0x04D4 | hold | asleep | empty: it asked for its Interests to be held |
| 0x04D6 | wake | asleep | empty: it registered a wake token |
| 0x04D8 | wakes | asleep; top level | NonNegativeInteger: wakes sent to that device; top level: `wakes_sent`, to all |
| 0x04DA | down | LINK | why a configured device is not linked now |
| 0x04DC | serve | top level | this device's serving policy, one line |

Strings are UTF-8. The link commands, also for local operators only, name a configured link by its label (as `link list` shows it) in `ControlParameters` Uri, and change only the running daemon:

- `/localhost/nfd/links/connect` — `Links::connect`: the link is wanted now, whatever its mode, and dialled at once (§16.1);
- `/localhost/nfd/links/disconnect` — `Links::disconnect`: the link is no longer asked for; an `off` link closes now, an `on-demand` link once idle, an `always` link stays (set its mode to `off` to close it);
- `/localhost/nfd/links/mode` — `Links::set_mode`: the mode in `ControlParameters` LocalUri, `always`, `on-demand`, `on-demand:<idle seconds>` (10–86 400; without seconds the link's current idle time, else 60 s) or `off`.

A device that linked in without a peer entry has no mode and cannot be named by these commands. Presentation is not normative.

## 15. Relays

### 15.1 Relays are a role

Any device that others can reach — a listening link socket at an address they can dial — is a relay for the devices it admits: a device of the namespace on a home server, a community relay that serves several namespaces, a hosted service. Nothing on the wire marks a relay: a relay is a link whose other side forwards. Two decisions are kept apart, and both are data, not code:

- **whom a relay serves**: its serving policy and quotas (§15.2–§15.4), chosen by its operator;
- **which relays a device uses**: its relay sources and options (§15.5–§15.6), chosen by its person and its namespace.

The link policy still decides which roles of a namespace may relay for it (§7.3 rule 3).

### 15.2 Serving policy

The serving policy applies to links nobody asked for: no peer entry of the relay dialled the link, expects its key or names its device (§7.3 rule 5). A peer entry admits its device whatever the policy. The policies (`ServePolicy`; ndn-fwd `[relay_service] serve`):

- **`own`** (the default): devices of the namespaces in which the relay holds a certificate (of its link key, or of a membership, §5.8). A device of a namespace whose trust context it holds but in which it holds no certificate, or of a namespace it does not hold, is refused with **0x19** — unless another of its identities is served (§7.3 rule 5): a device of A and C is served by a relay of C by its C membership.
- **`listed`** (`roots`, optional quotas): those, and devices of the namespaces whose root key fingerprint is in `roots`. A device of a held namespace is checked as any device of it (revocations, link policy, §7.1 steps 1–11) and served when the fingerprint of one of the held context's anchors is listed. A device of a namespace the relay does not hold is checked offline against the root in its hello (§7.1 R1–R7) and served when that root's fingerprint is listed. Without quotas, only the one-root-per-name rule of §15.3 bounds them.
- **`open`** (quotas): devices of any namespace whose hello chain ends in a self-signed root certificate that validates the device's certificate (§7.1 R1–R7), under the quotas of §15.3. The relay's own namespaces are never under quota.

A refusal says whom the relay serves, which namespace and root key the device has, and what to do (use another relay, or ask the operator to serve the namespace by its root key fingerprint).

**Offline validation, and what it cannot check.** For a namespace it does not hold, the relay's only trust input is the self-signed root certificate the hello carries. That is why a `listed` relay is configured with root key fingerprints — expected fingerprints of namespaces — and an `open` relay takes any root. Without the namespace's trust context:

- **revocations cannot be checked**: a revoked device of such a namespace keeps linking until its certificate expires;
- the namespace's link policy is unknown, so it is not applied: every role is served;
- the schema is the one `ndn-cert` makes for any namespace (§7.1 R6), not the namespace's own.

An operator who needs a namespace's revocations honoured makes the relay hold that namespace's trust context and lists its root: its devices are then checked as devices of a held namespace.

### 15.3 Quotas, and one root per namespace name

`Quotas` bound what a relay serves for namespaces other than its own; a namespace here is one root key. Defaults: 256 links, 32 per namespace, 100 per s per key (burst 200), 400 per s per namespace (burst 800). ndn-fwd takes the rates per second with a burst of twice that.

| Quota | Bound | Over it |
|---|---|---|
| `links_total` | served links at once, all other namespaces together | refused **0x16** |
| `links_per_namespace` | served links at once of one root key | refused **0x16** |
| `interests_per_key` | packets one served device sends over its link: a per-link bucket on received frames (§8.3) | dropped, no Nack |
| `interests_per_namespace` | packets all served devices of one root key send together: a bucket the links of that root share (§8.3) | dropped, no Nack |

The two rates count every received packet (Interests, Data and Nacks), as the scope's bucket does; Ack-only frames are free. Otherwise a served link under quotas is a full link: its scope carries Interests and answers in both directions with any name.

**One root per namespace name.** Among the live links the relay serves for other namespaces, a namespace name is bound to one root key, because the relay routes served devices by name (§10) and cannot route two namespaces of one name. A device of another root claiming a bound name is refused with **0x19** until the last served link of the bound root ends. So is a device whose namespace has the name of, or a name under, a namespace the relay holds (§7.1 step 10, under `listed` and `open`). This rule applies with or without quotas, and is checked first; then `links_per_namespace`, then `links_total`. A served link keeps its place for as long as it is up and gives it back when it ends.

### 15.4 What a relay of another namespace sees

A relay forwards packets; it does not take part in trust. Every Data is signed by its producer and validated by its consumer against the consumer's trust context, so a relay **cannot forge** Data or change it undetected, and it **cannot read** content the application encrypts. It does see, plainly:

- **every name it forwards**: Interest and Data names, which in a personal namespace name the devices and often the apps, files and records exchanged;
- **who talks to whom, and when**: the device names and keys of the devices linked to it, their addresses, and the timing and sizes of their traffic;
- the content of any Data that is not encrypted (signed is not secret);
- the candidate addresses in the punch messages it forwards (§14.8), and the wake tokens devices register with it (§17.4).

Using a relay of another namespace (a community relay, a hosted service) means showing it this. A namespace that wants none of it uses relays of its own (`own`) and, where the networks allow, direct paths.

### 15.5 Which relays a device uses

A relay a device uses is a peer entry with a *relay use*: its source and preference (`PeerSpec::relay_use`). The sources:

1. **The namespace advertises it.** Each trust context this device holds, and in whose namespace it holds a certificate, may list relays: [trust-context.md](trust-context.md) §3.3.11 "AdvertisedRelay (`0x0420`)". Unless the device turns this off (`RelayOptions::use_namespace`, default on; ndn-fwd `[relays] namespace`), each entry becomes a peer entry: label and `device` the entry's Name, `key` its RelayKey (the relay's expected fingerprint) if any, its endpoints in order, its preference, mode `RelayOptions::namespace_mode` (default `always`) and hold `RelayOptions::namespace_hold` (default false), source `namespace:<ns>`. An entry is skipped when it names this device (by device name or key), or a device or key a peer entry of the host already names (the host's entry wins). The entries follow the trust context: at start, on every adoption and after a key switch, a new entry is added, an entry whose endpoints, key or preference changed is updated and dialled again, and an entry no longer advertised is dropped and its link closed with **0x06**. A namespace relay the host removed (`Links::remove_peer`) is not added back while links run. A device that has just enrolled thus uses its namespace's relays without local configuration.
2. **Its person adds it**: an entry the host adds (ndn-fwd `[[relay]]`, an app's `Links::add_peer`), source `user`: its own server, a community relay, a hosted service. For a relay outside the namespaces this device holds, the entry MUST carry the relay's expected fingerprint (`key`): such a relay can be confirmed only by its key, since a served identity never confirms a device name (§7.1). ndn-fwd refuses a `[[relay]]` without `key` unless its `device` is a device of a namespace this device holds.
3. **None**: the device uses no relay and links only with its peers (LAN only).

A relay of the device's own namespace must still hold a role the link policy lets relay, or the device refuses it with **0x13** (§7.3 rule 3).

**Which of the device's namespaces a relay is used for.** A device in several namespaces uses relays for each: a relay its person added is used for every namespace it holds a certificate in; a relay a namespace advertises, for each of the device's namespaces whose held trust context advertises it (by device name or key), however many of them do (`relay_namespaces`). A device in none counts all its relays together.

### 15.6 Choosing relays, failover and failback

**Order.** Relays are ordered by preference (lower first); of equal preference, a `user` relay comes before a `namespace` one, then they keep the order in which they were added. `count` relays are linked at once for each namespace the device uses relays for (`RelayOptions::count`, default 1; ndn-fwd `[relays] count`, 1–8).

**Choice.** Walking the order, a relay is considered while at least one of the namespaces it is used for has fewer than `count` relays chosen:

- an `off` relay that the host does not ask for and that is not linked is skipped;
- a relay that is linked, or whose last dial did not fail, is **chosen**;
- a relay whose last dial failed, or that closed its link with **0x00** (Shutdown), is **retried**: dialled again with its backoff (§13.1) while the next one in the order stands in.

Relays not considered stand by, undialled. Chosen and retried relays are dialled as their mode says (§16.1). A chosen relay counts for each namespace it is used for; a retried one for none. The choice is made again whenever a relay's link comes up or ends, a dial of a relay fails, or a peer is added, removed, connected, disconnected or changes mode.

**Routes.** The link path to a relay routes the namespaces of this device it is used for at a cost equal to the relay's rank in the whole order (0 for the first, 1 for the next, …), and the routes of the peers reached through it at that rank + 10 (§10). Traffic of each namespace therefore takes the most preferred linked relay used for it.

**Failover.** When the link to a relay drops, its face and routes go, and traffic takes the next linked relay at once (with `count` > 1). A relay that closed the link with 0x00 (Shutdown) said it is going away: it is retried at once, so the next relay in the order is chosen and dialled without waiting for a dial of the first to fail. A link that dropped otherwise (timed out, replaced, …) may be a relay restarting or a short outage: the relay stays chosen and is dialled again after `BACKOFF_FIRST`; once a dial of it fails, it is retried and the next relay in the order is chosen and dialled.

**Failback.** When a retried relay links again, it is chosen again, and a relay that no longer fits within `count` is **released**: the device closes its link with **0x06** (Released), saying it uses a more preferred relay now and will use this one again if that one is lost. A device also closes with 0x06 the link to a relay its host removed or its namespace no longer advertises.

An Interest waiting for an on-demand relay that is not chosen is answered with a Nack NoRoute (§16.3). Status reports each relay as `linked`, `trying` (chosen; being dialled, or on demand and waiting for traffic), `down` (its last dial failed, or it shut down), `standby` or `off` (§14.10).

### 15.7 Transit: Data of a namespace the relay does not hold

A forwarder validates the Data it forwards against the trust contexts it holds. A relay serving the devices of a namespace it does not hold (`listed` without its trust context, or `open`) cannot: it holds neither that namespace's trust context nor its certificates. While at least one device served for such a namespace is linked, the relay carries the namespace's Data **in transit**:

- it forwards that Data to the Interests pending for it **without validating it**: the Data is still signed, and the devices that asked for it validate it end to end;
- it caches none of it: Data in transit never enters the Content Store;
- unsolicited Data is still dropped, as for any Data that answers no pending Interest;
- Data under a namespace the relay holds is always validated, whatever is in transit.

The namespace leaves transit when the last link of a device served for it ends. Host interface: `ndn-link` calls `FaceSink::transit(namespace, true)` when a path of a served device comes up — once for each namespace a served identity of the link is in (§7.3) — and `FaceSink::transit(namespace, false)` when it ends; the calls pair up, so the host counts them per namespace ([Decision 30](#20-decisions)). The ndn-rs engine keeps the counts in `TransitPrefixes`. A forwarder that validates nothing in transit anyway does nothing here.

### 15.8 Devices behind one address

Devices behind one NAT, or on one host, reach a relay from the same IP address. A link is one connection to one device, identified by its key, and a relay forwards between the links of such devices. A forwarder MUST NOT apply "never send an Interest back to the node it came from" by remote IP address across link faces; it applies it, by face, only to the face the Interest came in on. The ndn-rs strategy compares remote hosts only for faces other than QUIC link faces, which it never treats as the same node by address.

## 16. Link modes

### 16.1 Modes

Each peer entry has a link mode (`LinkMode`; ndn-fwd `[[peer]]`/`[[relay]] mode` and `idle_secs`, `[relays] mode` and `idle_secs` for the namespace's relays; default `always`):

| Mode | The link is wanted |
|---|---|
| `always` | always: dialled at once, and again whenever it drops (§13.1) |
| `on-demand` (`idle`) | while the host asks for it (`Links::connect`), while the host is active (`Links::set_active(true)`, e.g. an app in the foreground), or while an Interest waits for it (§16.3); closed when idle (§16.2) |
| `off` | only while the host asks for it (`Links::connect`, until `Links::disconnect`) |

A relay's link is, in addition, wanted only while the relay is chosen or retried (§15.6). The mode is that of the side that keeps the peer entry: it decides when this side dials, and when it closes a link it no longer wants, whichever side dialled. Nothing is sent over a closed link; the first Interest after it waits for a handshake. ndn-fwd takes `idle_secs` in 10–86 400 s (default 60).

### 16.2 Idle close and the Asleep close

A device checks each link it keeps: an on-demand link every `idle` / 4, clamped to 250 ms – 30 s; other links every 60 s; and at once when the host changes something. *Activity* is the NDN datagrams sent or received on the link (QUIC DATAGRAM frames); keep-alive PINGs and control-stream messages are not activity, so keep-alives do not hold an idle link open. The device closes the link:

- with **0x05** (Asleep), when an `on-demand` link is not asked for, the host is not active, and the link carried no datagram for `idle` (the close comes within one check after that);
- with **0x05**, when an `off` link is no longer asked for;
- with **0x06** (Released), when a relay is no longer chosen (§15.6) or the peer was removed.

A host going inactive (`set_active(false)`) closes nothing at once: its on-demand links close once idle. After closing a link itself, the device dials again as soon as the link is wanted again (§13.1). A relay that sees a device's link end may count it asleep (§17.2).

### 16.3 The waiting face

While an on-demand peer has a path to dial, the routes its link will get — its `routes`; else, for a relay this device uses, the namespaces it uses that relay for (§15.5); else its `device` — lead to the waiting face at `WAITING_COST` = 1000, above any link's cost. An Interest the forwarder sends there:

- if the link is up already, is sent over it;
- if the peer is a relay that is not chosen now, is answered with a Nack NoRoute;
- otherwise makes the link wanted (it is dialled) and waits for it, until its InterestLifetime ends (4 s when it has none), at most `DEMAND_PER_PEER` = 64 for one peer and `DEMAND_TOTAL` = 1024 for all on-demand peers together. An Interest beyond a bound is answered at once with a Nack Congestion.

When the link comes up, the waiting Interests still within their lifetime are sent over the new link's face directly, past the forwarder. The forwarder's pending entry for each (whose out-record is the waiting face) is still there, so the Data that comes back over the link satisfies it by name. If the dial fails, the waiting Interests are answered at once with a Nack NoRoute rather than at the end of their lifetime. Nacks reaching the waiting face are ignored.

### 16.4 Keep-alive and idle timeout bounds

A host may set the keep-alive and the QUIC idle timeout of its link paths (§3.1), within these bounds (`LinkTransportConfig::bounded`; ndn-fwd `[links] keep_alive_secs` and `idle_timeout_secs`, default 10 s and 30 s):

| Setting | Bound | Why |
|---|---|---|
| keep-alive | at least 2 s | each keep-alive wakes the radio and costs battery and data; no NAT needs them more often |
| keep-alive | at most 60 s | most NATs drop a UDP binding after 30 s or more without traffic, some sooner; a link whose binding is gone receives nothing until it is dialled again |
| idle timeout | at least 3 × keep-alive | one or two lost keep-alives must not count a working link as lost |
| idle timeout | at most 600 s | a link whose path broke counts as up that long, and traffic sent over it is lost meanwhile |

A setting out of bounds is refused with a sentence that says which bound and why. The connection's idle timeout is the smaller of both sides' offers; each side sends its own keep-alives. A keep-alive longer than the NAT binding lifetime on a path saves battery but makes a quiet `always` link unreachable from the other side until it is dialled again. Direct paths keep their own timers (§3.1).

### 16.5 Battery and data

| Mode | While nothing is exchanged | When something is to be sent | Reachable by others while idle |
|---|---|---|---|
| `always` | a small packet each way (a QUIC PING and its acknowledgement) per keep-alive interval: 8 640 a day at 10 s, 1 440 at 60 s; on a phone each wakes the radio | sent at once | yes, over the link |
| `on-demand` | keep-alives only until the idle close, then nothing | the first Interest waits for a dial and a full handshake (at most the 5 s handshake timeout, §3.1) | after the idle close, only through a relay that holds its Interests or wakes it (§17); otherwise Interests for it are answered with a Nack |
| `off` | nothing | nothing is sent until the host asks | no |

In short: `always` costs the most battery and data and is reachable at once; `on-demand` costs nothing while closed, plus a handshake for each time it links again and keep-alives while it is open; `off` costs nothing and reaches nobody until asked. A longer keep-alive (§16.4) lowers the cost of `always` where the NATs on the path allow it.

## 17. Reachability while asleep

### 17.1 Asking

A device asks a peer, normally a relay, per peer entry:

- to **hold** its Interests while it is asleep (`PeerSpec::hold`; ndn-fwd `hold`; for the namespace's relays `RelayOptions::namespace_hold`);
- to **wake** it, by registering a wake token (`Links::set_wake_token`; ndn-fwd `wake_token`, UTF-8, at most 1024 bytes).

It sends a Reachability (§5.6) with what it asks when a full link path to that peer comes up, if it asks for either, and at once when its wake token changes (a cleared token sends a Reachability without one). Asking is the device's choice; whether a relay offers it is the relay's (§17.2). A device that asks for neither sends nothing, and is not counted asleep anywhere.

### 17.2 When a relay counts a device asleep

What a relay offers is its `RelayService`: its serving policy, `hold` (`HoldLimits`, or none: holds no Interests), `wake` (a `WakeNotifier`, or none: wakes nobody) and `asleep_max`. The default offers neither holding nor waking. When a path of a link ends, the relay counts the device **asleep** iff all of these hold:

- the device sent a Reachability on that link;
- it was the device's last path (it is linked over no other), the link was not an enrollment link, and it had routes;
- the link did not end with 0x06 (Released) or 0x12 (Revoked), and no recorded certificate of the device (§7.1) is revoked by the held trust context;
- the relay offers what it asked: it asked to be held and the relay holds Interests, or it registered a wake token and the relay has a wake notifier.

Any other end counts: 0x05 (Asleep), a path that broke (idle timeout), the device shutting down. The device then counts as asleep for at most `asleep_max` (default 24 h; ndn-fwd `[relay_service] asleep_secs`): the routes its link had lead to the waiting face at `WAITING_COST`. A device that does not link again within `asleep_max` is forgotten: its routes go, and its held Interests are answered with a Nack NoRoute.

### 17.3 Held Interests

An Interest that reaches the waiting face for a sleeping device:

- if the device linked again meanwhile, is sent to it over its link;
- if the device is not asleep here (any more), is answered with a Nack NoRoute;
- otherwise wakes the device first, when it registered a token (§17.4); then, if the device asked to be held and the relay holds Interests, is **held** until its InterestLifetime ends (4 s when it has none) or `max_hold`, whichever is sooner, within `per_device` Interests for that device and `total` for all sleeping devices (defaults 64, 4096 and 60 s; ndn-fwd `[relay_service] hold`, `hold_per_device`, `hold_total`, `hold_secs`). An Interest beyond a bound is answered at once with a **Nack Congestion**. Otherwise it is answered with a Nack NoRoute.

The `total` for sleeping devices is counted apart from the on-demand bound of §16.3. When the device links again over a full link path, it is awake: the waiting routes go, and its held Interests still within their lifetime are sent over the new link's face directly, past the forwarder. The relay's pending entries for them are still there, so the Data the device answers with returns to the requesters by name. A requester that wants an answer from a sleeping device sends a long InterestLifetime; the relay holds it at most `max_hold`.

### 17.4 The wake hook

The library defines the interface; the host provides the notifier — an external command, a webhook, a platform push service. No vendor integration is part of the protocol.

```rust
pub trait WakeNotifier: Send + Sync + 'static {
    fn wake(&self, request: WakeRequest);
}
pub struct WakeRequest {
    pub device: Option<Name>,   // the device's name from its certificate; None for a device linked by its expected fingerprint alone
    pub key: KeyFingerprint,    // the key it linked with
    pub token: Bytes,           // the opaque token it registered
    pub held: usize,            // Interests held for it now
}
```

- **When.** An Interest arrives at the waiting face for a device asleep here that registered a token, and the relay has a notifier: the relay calls `wake` at most once per `WAKE_INTERVAL` = 30 s per device while Interests keep arriving. `wake` is called on the relay's runtime thread and MUST NOT block; it hands the work off.
- **Never for a linked device.** A device is asleep only after its last path ended, and is awake again as soon as it links; an Interest for a device that linked again goes to it, and wakes nothing.
- **Never the Interest names.** The notifier gets the device's name, its key, its token and a count — never the names of the Interests that wait.
- ndn-fwd's notifier is `[relay_service] wake_command`: run once per wake, without a shell, with `NDN_WAKE_TOKEN` (the token, hex), `NDN_WAKE_DEVICE` (the name, or empty), `NDN_WAKE_KEY` (the fingerprint, hex) and `NDN_WAKE_HELD` in its environment, killed after 10 s.

A woken device is expected to link (its host becomes active, or an Interest of its own wants its on-demand link) and so receive what was held. A wake token often identifies the device to a push service: register one only with relays trusted with it (§15.4).

### 17.5 Restarts

Sleeping devices and their held Interests live in the relay's memory only. A relay that restarts forgets them: every link with it ended, and a device registers again on its next link, since it sends its Reachability on every new link (§17.1). Until a device links again, the restarted relay has no route for it.

## 18. Constants

| Name | Value | Section |
|---|---|---|
| ALPN | `ndn-link/1` | §3.1 |
| LinkVersion | 1 | §5.2 |
| `MAX_MESSAGE` | 65 536 bytes (TLV-VALUE) | §4.2 |
| message header read limit | 20 bytes | §4.2 |
| `MESSAGE_DEADLINE` | 10 s (hello exchange; verdict exchange) | §5.4 |
| dial handshake timeout | 5 s | §3.1 |
| QUIC idle timeout / keep-alive (defaults) | 30 s / 10 s | §3.1, §16.4 |
| keep-alive bounds / idle timeout bounds | 2–60 s / ≥ 3 × keep-alive, ≤ 600 s | §16.4 |
| `MAX_CHAIN` | 8 issuers validated; at most 8 certificates kept and sent, plus the namespace root | §5.2, §7.1 |
| `VIA_RELAY_COST` | 10 | §10 |
| `WAITING_COST` | 1000 | §10, §16.3 |
| relay route cost | the relay's rank: 0, 1, … | §15.6 |
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
| `WAKE_TOKEN_MAX` | 1024 bytes | §5.6 |
| `PRESENCE_MAX` | 256 devices per Presence | §5.7 |
| presence namespaces kept per link | 256 | §5.7 |
| `MEMBERSHIPS_MAX` | 8 memberships sent and used per hello (one per namespace); 1 per punch message | §5.2, §5.8, §14.3 |
| membership exporter | label `EXPORTER-ndn-link/1 membership`, empty context, 32 bytes | §5.8 |
| binding transcript | `ndn-link/1 membership` 0x00 ‖ link key fingerprint ‖ channel binding ‖ SHA-256(certificate): 118 bytes | §5.8 |
| punch channel binding | SHA-256(`ndn-link/1 punch` ‖ session) | §5.8, §14.3 |
| `Quotas` default | 256 links, 32 per namespace, 100/s (burst 200) per key, 400/s (burst 800) per namespace | §15.3 |
| `RelayOptions` default | count 1, namespace relays on, mode `always`, no hold | §15.5, §15.6 |
| `DirectOptions` default | membership on, `max_paths` 8 | §14.8, §14.9 |
| member / bounded punch recheck | 5 s | §14.1, §14.9 |
| on-demand idle check | `idle` / 4, within 250 ms – 30 s (other links: 60 s) | §16.2 |
| `DEMAND_PER_PEER` / `DEMAND_TOTAL` | 64 / 1024 | §16.3 |
| default InterestLifetime at the waiting face | 4 s | §16.3, §17.3 |
| `HoldLimits` default | 64 per device, 4096 in total, 60 s | §17.3 |
| `asleep_max` default | 24 h | §17.2 |
| `WAKE_INTERVAL` | 30 s | §17.4 |

## 19. Test vectors

All vectors were produced by running the real ndn-rs code. The hello and verdict wires come from `ndn-face-quic`'s `message.rs`; keys and fingerprints from its public `LinkKey` / `PeerKey` / `KeyFingerprint` API; certificates from `ndn_security::encode_cert_data`; LP frames from `ndn_packet::lp`. Each hello and verdict was also decoded back with the real decoder. Hex is lowercase with no separators. Line breaks inside a vector carry no meaning.

### 19.1 Ed25519 link key and fingerprint

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

### 19.2 P-256 link key and fingerprint

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

### 19.3 Certificates used in 19.5

Both certificates are signed by the root key `/home/KEY/0102030405060708` (Ed25519 seed `02`×32), with version 1767225600000 (`v=` = 2026-01-01T00:00:00Z in ms).

**Root**, self-signed: `/home/KEY/0102030405060708/self/v=1767225600000`, valid 20260101T000000–20360101T000000, 265 B:

```
06fd0105072d0804686f6d6508034b4559081030313032303330343035303630373038080473656c6636080000019b76daa8001414180800000000000000021908000000000036ee80152c302a300506032b65700321008139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394164e1b01051c1f071d0804686f6d6508034b4559081030313032303330343035303630373038fd00fd26fd00fe0f323032363031303154303030303030fd00ff0f32303336303130315430303030303017407e4045832a44ee3e6df10b0a835b3259b4975f369a46c0112d404af1ddea8d3b559b9c4d1d4accd457c9e6e2d21644dfc9033621cd134096dade05d11528f00c
```

**Leaf**, the device key of 19.1: `/home/member/phone/KEY/1112131415161718/NDNCERT/v=1767225600000`, issued by the root, valid 20260101T000000–20270101T000000, 283 B:

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

### 19.4 LinkHello with no certificate (9 B)

```
fd0450 05        LinkHello, length 5
  fd0451 01 01   LinkVersion = 1
```
`fd045005fd04510101`

### 19.5 LinkHello with leaf and root (559 B)

```
fd0450 fd0229    LinkHello, length 553
  fd0451 01 01   LinkVersion = 1
  <leaf, 283 B, 19.3>
  <root, 265 B, 19.3>
```

The wire is `fd0450fd0229fd04510101` ‖ leaf ‖ root (5 + 283 + 265 = 553). A receiver whose key is the TLS key of 19.1 passes step 3 of §7.1: the leaf's Content SPKI reduces to the raw key `8a88…6f5c`. The chain ends in the namespace's self-signed root, the form §5.2 asks for.

### 19.6 LinkVerdict, full link (4 B)

```
fd0452 00
```
`fd045200`

### 19.7 LinkVerdict, enrollment link for `/home` (16 B)

```
fd0452 0c                LinkVerdict, length 12
  fd0454 08              EnrollmentLink, length 8
    07 06 0804 686f6d65  Name /home
```
`fd04520cfd04540807060804686f6d65`

### 19.8 LinkVerdict, enrollment link for `/home` and `/work/lab` (29 B)

```
fd0452 19
  fd0454 15
    07 06 0804686f6d65
    07 0b 0804776f726b 0803 6c6162
```
`fd045219fd04541507060804686f6d65070b0804776f726b08036c6162`

### 19.9 LinkVerdict with an empty EnrollmentLink (8 B)

`fd045204fd045400`. Malformed (§5.3): a receiver closes the link with 0x15.

### 19.10 Decoder behaviour

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
| hello `fd04510101fd045c070600fd045e01aa` (a Membership: one Data, binding `aa`) | accepted, 0 certificates, 1 membership |
| hello `fd04510101fd045c05fd045e01aa` (Membership without a certificate) | malformed |
| hello `fd04510101fd045c020600` (Membership without a binding) | malformed |
| hello `fd04510101fd045c060600fd045e00` (empty MembershipBinding) | malformed |
| hello `fd04510101fd045c0b0600fd045e01aafd045f00` (unknown odd 0x045F inside a Membership) | malformed |
| verdict `fd045700` | malformed: unknown critical field |
| verdict `fd0454020800` (non-Name inside EnrollmentLink) | malformed |
| verdict `fd045400` (empty EnrollmentLink) | malformed |

### 19.11 NDNLPv2 frames on a link

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

### 19.12 ObservedAddress and UDP addresses

ObservedAddress for 192.0.2.7:6363: `fd045806c000020718db`. The UDP address `[2001:db8::1]:443`: `20010db800000000000000000000000101bb` (18 B). An IPv4-mapped `[::ffff:192.0.2.7]:6363` is written `c000020718db`.

### 19.13 LinkHello of a direct-path dialer with no certificate, session 01…08 (21 B)

```
fd0450 11              LinkHello, length 17
  fd0451 01 01         LinkVersion = 1
  fd045a 08 0102030405060708   DirectPath
```
`fd045011fd04510101fd045a080102030405060708`

### 19.14 Punch name and probe

The punch of `/home/member/phone` with session 01…08, before its ParametersSha256DigestComponent:
`072c0804686f6d6508066d656d626572080570686f6e6520046c696e6b200570756e636808080102030405060708`
(`/home/member/phone/32=link/32=punch/%01%02%03%04%05%06%07%08`).

The probe of that session (24 B): `006e646e2d6c696e6b2070726f6265010102030405060708`.

### 19.15 Punch messages

PunchKey is the Ed25519 key of §19.1 (`fd04602c` ‖ the 44-byte SPKI). A request with a reflexive candidate 203.0.113.9:40000 and a host candidate 192.168.1.2:6367, no certificate:

```
fd04602c302a300506032b65700321008a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c
fd04620f fd046401 01 fd046606 cb0071099c40
fd04620f fd046401 00 fd046606 c0a8010218df
```

A refusal with code 0x18 and the text "direct paths are off":

```
fd04602c302a…6f5c (as above)
fd04681d fd046a01 18 fd046c14 64697265637420706174687320617265206f6666
```

These are asserted by `the_spec_vectors_are_what_this_code_writes` (N/punch.rs) and `a_direct_path_session_is_eight_bytes` (Q/message.rs).

### 19.16 Reachability

Hold, with the wake token `tok` (15 B):

```
fd0440 0b          Reachability, length 11
  fd0442 00        HoldInterests
  fd0444 03 746f6b WakeToken "tok"
```
`fd04400bfd044200fd044403746f6b`

Neither (4 B), which withdraws both: `fd044000`.

Malformed, as TLV-VALUEs: `fd04420101` (HoldInterests of length 1), `fd044400` (empty WakeToken), and a WakeToken of 1025 bytes; a WakeToken of exactly 1024 bytes is accepted.

### 19.17 Presence

Namespace `/home`, one device `/home/d` with key fingerprint `ab`×32 (63 B):

```
fd0446 3b                     Presence, length 59
  07 06 0804 686f6d65         Name /home
  fd0448 2f                   PresentDevice, length 47
    07 09 0804 686f6d65 0801 64     Name /home/d
    fd044a 20 abab…ab (32 B)        KeyDigest
```
`fd04463b07060804686f6d65fd04482f07090804686f6d65080164fd044a20abababababababababababababababababababababababababababababababab`

The same namespace with no device, which removes it at the receiver (12 B): `fd04460807060804686f6d65`. Malformed, as TLV-VALUEs: an empty value (no namespace), `0700fd0448070700fd044a01ab` (KeyDigest of 1 byte), `0700fd0448020700` (PresentDevice without KeyDigest).

The full vectors, the malformed cases and the round trip of the empty list are asserted by `reachability_matches_the_spec_vectors_and_round_trips` and `presence_matches_the_spec_vector_and_round_trips` (Q/message.rs); the codes 0x05, 0x06, 0x19 and 0x1A and their transient flags by `close_codes_round_trip` (Q/message.rs); the Membership decoder cases of §19.10 by `a_membership_needs_a_certificate_and_a_binding` (Q/message.rs).

### 19.18 A membership and its binding

The link key is the Ed25519 key of §19.1 (fingerprint `3475…c97e`). The device is also a member of `/work` with another key. All certificates have version 1767225600000 (`v=` = 2026-01-01T00:00:00Z in ms).

- **Root of `/work`**: Ed25519 seed `03`×32, key `/work/KEY/2122232425262728`, public key `ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1`; self-signed certificate `/work/KEY/2122232425262728/self/v=1767225600000`, valid 20260101T000000–20360101T000000, 265 B:

  ```
  06fd0105072d0804776f726b08034b4559081032313232323332343235323632373238080473656c6636080000019b76daa8001414180800000000000000021908000000000036ee80152c302a300506032b6570032100ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1164e1b01051c1f071d0804776f726b08034b4559081032313232323332343235323632373238fd00fd26fd00fe0f323032363031303154303030303030fd00ff0f3230333630313031543030303030301740841fa024d19bb23a63bf6f9228af413d5a6281014f1524362c4ba19f74ac9fea7bc07d14e8de6fa8a6688769860da04fc92c865f2dc6c6bd58e7184487a35601
  ```

- **The device's `/work` certificate**: Ed25519 seed `04`×32, key `/work/member/phone/KEY/3132333435363738`, public key `ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c`; certificate `/work/member/phone/KEY/3132333435363738/NDNCERT/v=1767225600000` issued by the root, valid 20260101T000000–20270101T000000, 283 B:

  ```
  06fd0117073f0804776f726b08066d656d626572080570686f6e6508034b455908103331333233333334333533363337333808074e444e4345525436080000019b76daa8001414180800000000000000021908000000000036ee80152c302a300506032b6570032100ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c164e1b01051c1f071d0804776f726b08034b4559081032313232323332343235323632373238fd00fd26fd00fe0f323032363031303154303030303030fd00ff0f32303237303130315430303030303017403dc98f25465f7561620a7da039e130d69c5e9607d96aa3ee0d3a04703a1a480c5f9add6f6affc116c0efdd5e36f20629a0f9d05668545bcc4778c33fc9854f0b
  ```

- **Channel binding** (in place of a connection's exporter value): `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`.

The binding transcript (118 B):

```
6e646e2d6c696e6b2f31206d656d6265727368697000                         "ndn-link/1 membership" 00
34750f98bd59fcfc946da45aaabe933be154a4b5094e1c4abf42866505f3c97e     link key fingerprint (§19.1)
000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f     channel binding
14bb26fdde55b6a50683847e00cc12f05e7b754b93304b858d9321e68d2691d4     SHA-256 of the /work certificate (283 B)
```

Its Ed25519 signature by the `/work` device key (seed `04`), the binding (64 B):

```
e77a3e5d85e0380c7c409d4b43a779b63c04e133ae3ba1f130dfad0a72042e768c3612fd1077ce641742f08c464a49c8e29a5a78c1878bb9f263cec1bf85c700
```

The Membership TLV (622 B): `fd045c fd0268` (length 616) ‖ the `/work` certificate ‖ the root ‖ `fd045e 40` ‖ the binding. A hello carrying it after the link key's chain of §19.5 identifies the device as `/home/member/phone` (by its link key) and `/work/member/phone` (by the membership) at a side that holds both namespaces; the same binding under another channel value, another link key fingerprint, or a key other than `ca93…be7c` does not verify (refused with 0x1A).

These are asserted by `the_spec_vectors_are_what_this_code_writes` and `a_binding_holds_only_for_its_key_link_key_and_connection` (Q/membership.rs).

### 19.19 The channel binding of a punch

For the punch of session `0102030405060708` (§19.14), memberships are bound to SHA-256(`6e646e2d6c696e6b2f312070756e6368` ‖ `0102030405060708`), i.e. of ASCII `ndn-link/1 punch` and the session:

```
b2d0a9d0b6405643f3fba3edebfb5e1b6d777776ba5a3b90377f3635a6f489fa
```

Asserted by `the_spec_vectors_are_what_this_code_writes` (N/punch.rs).

## 20. Decisions

These points were open when this spec was first written. Each was decided, and code and spec now agree.

1. **Failed exchanges close with 0x15** (§6.3). Earlier, a malformed message, an unsupported LinkVersion or a missed `MESSAGE_DEADLINE` dropped the connection, and quinn closed it with code 0 and an empty reason. The peer read that as Shutdown (transient) and redialed every ≤ 30 s forever, and the "update the older of the two" text was only logged locally. Now the side that detects the failure closes with 0x15 and the reason, and a listener counts it against the source. A version mismatch is non-transient on both sides: the peer backs off `BACKOFF_REFUSED`, because only a software update on one side changes the outcome. A missed deadline stays transient for the side that waited, since the peer may only be slow.
2. **Chain length.** The host keeps at most 8 certificates (leaf + 7 issuers); `ndn-link` appends the namespace's root when the kept chain does not end in a self-signed certificate (§5.2), so a hello carries at most 9: the leaf and the 8 issuers a receiver uses. No wire change: receivers always accepted the leaf + up to 8 issuers.
3. **TLV criticality follows NDN** (§5). Types 0–31 are critical, as in NDN Packet Format v0.3, and LinkVersion is exactly one byte. Version policy: the ALPN `ndn-link/1` names the transport framing (control stream and datagrams) and changes only for a protocol that cannot share this handshake. LinkVersion versions the link messages, and a peer of another version is refused with 0x15 naming both versions. No implementation sent either of the newly malformed forms.
4. **An empty EnrollmentLink is malformed** (§5.3). It meant "an enrollment link for no namespace", which carries nothing. No sender produces it: a relay with no eligible namespace refuses instead (0x10, or 0x19 for a device it identified but does not serve).
5. **A known revoked key gets no enrollment link** (§7.1). A side refuses with 0x12 any key it knows a revoked certificate of, whatever the hello carries; `ndn-link` asks the host (`LinkTrust::known_certificate_of_key`), and ndn-fwd looks the key up in the validator's certificate cache. A key the side knows no certificate of cannot be told from a new one, and a revoked device can always make a new key. For those keys the CA, which refuses to certify a revoked device again, remains the backstop. The design statement in [personal-namespace.md](personal-namespace.md) §9 holds for every key a relay can tie to a revoked certificate.
6. **CA endpoints outside the namespace: kept.** A trust context that names a CA endpoint outside `/<ns>` is valid, but an enrollment link does not carry that endpoint: a relay forwards only names under the namespace for a device it does not know. Root devices put CA endpoints under the namespace; ndn-rs uses `/<ns>/CA`.
7. **Ack-only frames are free** (§8.3). The enrollment-link bucket now charges only frames that carry a network packet or a fragment of one. Before, a device's acknowledgements of a fragmented answer drained the relay's bucket (burst 32, 4/s), so the relay dropped the device's Interests and retransmitted its fragments needlessly.
8. **The namespace route goes to a `node` this side dials** (§10 rule 2), whichever side's dial the link came from. This is what the `ndn-link` documentation said. A node that only links in gets its device route. Keying on "this side dials that peer", and not on the link's direction, keeps the routes the same when the duplicate-link rule keeps the other side's dial.
9. **The refusal count decays** (§13.2). Refusals count within a 60 s window (`HandshakeLimits::refusal_window`). Before, a source's refusals added up with no time limit, so 8 refusals spread over days still triggered the cooldown.
10. **No device-side idle close.** The relay's idle close frees scarce enrollment slots. A device has no slots to free, and it must keep its link while it waits for an approval.
11. **Duplicate rule without an own fingerprint: kept** (newer wins). A side lacks its own fingerprint only when it lost its link key mid-run, and then it cannot complete another handshake anyway. If the two sides disagree, both links close with 0x01 (transient) and the redial converges.
12. **P-256 key comparison stays byte-exact** (§7.1 step 3). A certificate MUST carry a P-256 key as the uncompressed-point SPKI of §3.2, which is how ndn-rs and ndn-cxx write it. A compressed point is refused with 0x11.
13. **Datagrams before the verdict.** A sender MUST NOT send them (§5.4). A receiver MAY deliver ones that arrived early once it has admitted the link. ndn-rs does this, through the scope of an enrollment link. Discarding them would lose packets for no gain, since the link is admitted by then.
14. **Location of the code** (informative). The admission rules and everything after them (§7–§17) are in the `ndn-link` crate (ndn-ext/crates/faces/ndn-link); ndn-fwd and ndn-boltffi (ndn-mobile) host it. There is no second copy to diverge.
15. **Signalling is NDN, not a relay protocol** (§14.3). A punch is a signed Interest to the other device's name, so any forwarder that routes the name carries it, its freshness and replay protection are those of NDN signed Interests, and its answer is signed Data the punching side validates offline like a hello. The candidate list is signed by its owner, and probes go to signed candidates only.
16. **Reflexive address in a link message** (§5.5). quinn has no QUIC address-discovery extension, so each side tells the other what it sees on the control stream, which otherwise sat idle after the verdict. Old receivers ignore it; the stream now ends with the link.
17. **The smaller fingerprint dials** (§14.5), the same order as the duplicate-link rule, so the two sides never race two direct paths, and a socket that does not listen still accepts the punched connection, from the signed candidates only, while the punch runs.
18. **Short timers on direct paths** (§3.1). A direct path that dies is noticed within 8 s instead of 30 s, so traffic falls back to the relay sooner; the 2 s keep-alive also keeps port-restricted NAT mappings open. The relay link keeps the normal timers.
19. **Refusals are signed answers** (§14.4), carrying a link close code: a refusal crosses the relay, where NDNLPv2 Nack reasons (local-refusal codes are local only) cannot say why. A request that does not verify gets no answer at all, so a stranger cannot make a device sign for it beyond the `PUNCH_CHECKS` bucket.
20. **Relays are a role, and whom they serve is data** (§15.1, §15.2). A deployer picks the serving policy: `own` (default), `listed` by root key fingerprint, or `open` under quotas; a device picks the relays it uses. Under `own`, a device of a held namespace in which the relay holds no certificate is now refused with 0x19 unless a peer entry names it; earlier it was admitted as a full link. A relay serves the namespaces it is a member of; serving others is the operator's explicit choice.
21. **Namespaces a relay does not hold are checked against the root in the hello** (§7.1 R1–R7, §15.2). Fetching their trust contexts would need a route before the link is up, and an operator configures a root key fingerprint far more easily than a trust context. The cost is stated: revocations of such a namespace cannot be checked, and its link policy is not applied. An operator who needs them holds the namespace's trust context.
22. **One root per namespace name** (§15.3). A relay routes served devices by name, so two namespaces of one name, or one under a held namespace, cannot both be served; the first root holds the name while any of its links lives.
23. **Relay preference by rank** (§15.6). Route costs follow the rank in the whole order, not among the linked ones, so costs do not change when another relay links or drops; of equal preference the person's choice (`user`) comes before the namespace's. A relay that is no longer needed is closed with 0x06 so that the relay's log says it was not a fault.
24. **Idle is measured in NDN datagrams** (§16.2). Keep-alives and control messages do not count, so an on-demand link closes when its traffic stops, whatever its keep-alive. The close is 0x05, so the other side's log says the device went to sleep by choice; a relay counts the device asleep after any end of its last path, a broken one included (§17.2).
25. **Waiting Interests go out past the forwarder** (§16.3, §17.3). The forwarder already sent them to the waiting face and keeps their pending entries; sending them over the link's face directly needs no second forwarding decision, and the Data that comes back matches the pending entries by name.
26. **Held Interests and wakes live in memory, bounded** (§17). A relay keeps no state for sleeping devices across restarts; devices register on every link, so a restart costs one relink. The notifier gets the device's name, key and token and a count, never Interest names, and at most one wake per 30 s per device, so a stream of Interests cannot become a stream of pushes.
27. **Presence travels on the control stream** (§14.8), not as signed records or in a sync group: the stream is authenticated by the link's handshake and admission, reaches only the members the relay admitted, filtered per role, says who is linked now, and costs nothing while nothing changes. Presence never carries addresses.
28. **The smaller fingerprint punches members; direct paths are bounded** (§14.8, §14.9). The same order as the dial (Decision 17) means two members never punch each other at once. `max_paths` bounds the state and keep-alives of direct paths; recent traffic only breaks ties among members membership already qualifies, and an answerer at its bound refuses with 0x16 so the punching side backs off.
29. **Control messages after the verdict** (§5.6, §5.7) use the even types 0x0440–0x044A, so receivers that predate them skip them. The latest of each (per namespace for Presence) replaces what was sent before, at the receiver and in the sender's queue, so a slow reader costs no memory.
30. **Served namespaces are carried in transit, unvalidated and uncached** (§15.7). A relay cannot validate the Data of a namespace whose trust context and certificates it does not hold, and fetching them would make serving depend on that namespace's infrastructure. Dropping that Data would make serving useless. Its consumers validate it end to end; the relay answers only pending Interests and caches nothing it could not validate, so it never serves unvalidated Data from its cache to a later requester. Validation is skipped only while a served link of that namespace is up, and never under a namespace the relay holds.
31. **A link carries every membership** (§5.8, §7.1, §7.3, §12). A device takes part in many namespaces, with a key in each. A link keeps one key per device (the node key, in TLS); each other namespace is shown as a Membership: that key's chain and its signature binding the link key to this connection. Alternatives were one link per namespace key (a second handshake and connection per namespace and peer, and two links between the same two devices, which the duplicate-link rule forbids) and the same key certified in each namespace (the roles layout gives each namespace its own key, and a key compromised in one would be in all). The binding covers the link key fingerprint, so a membership cannot be moved to another device's link, and the TLS exporter, so it cannot be replayed onto another connection; the receiver recomputes both from its own view of the connection. A forged or replayed membership refuses the link with a code of its own (0x1A), since an honest device never sends one. The peer is admitted by any identity the local policy accepts, and routes, presence, transit and revocation follow each identity: a revocation in A takes A from the link and keeps it up by C. Revocations are per namespace at admission too: a revoked leaf or membership refuses the link only when nothing else identifies the peer. Relays are chosen per namespace (`count` for each), so a device of A and C is reachable through a relay of each. Punch messages carry the membership of the namespace the punch is in, bound to the punch's session, while the PunchKey stays the link key that the direct path's handshake proves. The Membership is an even TLV-TYPE above 31, so a receiver that predates it ignores it and admits the device by its link key's certificate, as before; a device's hello without memberships is the hello of ndn-link/1 before them.

## Appendix A. Code references (non-normative)

`Q` = `ndn-ext/crates/faces/ndn-face-quic/src`; `N` = `ndn-ext/crates/faces/ndn-link/src` (admission; moved there from ndn-fwd); `F` = `ndn-fwd/binaries/ndn-fwd/src` (the daemon's host glue); `S` = `ndn-rs/crates/security/ndn-security/src`. Lines are as read on 2026-10-18, and on 2026-10-19 for the rows of memberships (§5.8, Decision 31) and the rows they changed, while concurrent work was still landing; a location names the line an item (function, type, constant) starts at, or its span.

| Claim | Location |
|---|---|
| ALPN `ndn-link/1`; internal server name `ndn-link` | Q/endpoint.rs:25, :29 |
| TLS 1.3 only; ALPN set; SNI off; resumption off (dialer); the link key fixed for each dial | Q/endpoint.rs:559, :568–581 (`client_config`), :400–403 |
| TLS 1.3 only; ALPN; no session storage, 0 tickets, 0 early data (listener); the link key fixed for each inbound connection | Q/endpoint.rs:668, :672–683 (`server_config`), :497–524 |
| keep-alive 10 s, idle 30 s, dial handshake 5 s, direct path 2 s / 8 s (defaults) | Q/endpoint.rs:56–67; applied in `transport_config` :653–666 |
| keep-alive and idle timeout bounds 2–60 s, ≥ 3 × keep-alive, ≤ 600 s, refusal texts | Q/endpoint.rs:71–135 (`bounded`; test `transport_settings_stay_within_nat_safe_bounds` :743) |
| 1 bidi stream, 0 uni streams, 4 MiB datagram buffers | Q/endpoint.rs:661–664 |
| `max_datagram_frame_size` = min(buffer, 65535) | quinn-proto 0.11.16 src/transport_parameters.rs:170–172 |
| handshake limits 64 / 4 / 8 / 60 s, refusal window 60 s; refusal count, decay and reset | Q/endpoint.rs:142–167, :211–277 (test :725) |
| Retry when busy; refuse over limits | Q/endpoint.rs:274 (`busy`), :488–496, :532 |
| CONNECTION_REFUSED → Busy; close mapping and `is_transient` of errors | Q/link.rs:69–107 |
| stateless-reset key derived from the device key (local) | Q/endpoint.rs:698 (`endpoint_config`) |
| endpoint close with code + text, 1 s grace | Q/endpoint.rs:553–557; N/links.rs:185–192 |
| link endpoint on a host-bound socket; rebind | Q/endpoint.rs:327 (`from_socket`), :540 (`rebind`) |
| Ed25519 SPKI prefix (12 B), P-256 SPKI prefix (26 B), `04` check | Q/key.rs:18–26, :128–147 |
| NDN public key form (raw Ed25519 / P-256 SPKI) | Q/key.rs:158–166 |
| fingerprint = SHA-256(NDN public key); hex text; parse; `Ord` | Q/key.rs:77–111 |
| link key from signer: Ed25519 wrapped to SPKI; P-256 SPKI as is | Q/key.rs:218–262 |
| signature schemes ed25519 / ecdsa_secp256r1_sha256 | Q/key.rs:36–41, :333–344; Q/verify.rs:21–24 |
| raw public keys required; client auth mandatory; TLS 1.2 sigs refused | Q/verify.rs:83–90, :105–107, :119–125, :141–148, :163–165, :194, :208 |
| dialer checks expected fingerprint in the handshake | Q/verify.rs:64–81 |
| listener checks key type only | Q/verify.rs:131–138 |
| certificate Content: Ed25519 SPKI unwrapped to raw, else as is | S/cert_cache.rs:31–38; S/spki.rs:30–58 |
| link message TLV-TYPEs 0x0440–0x045E; version 1; MAX_MESSAGE | Q/message.rs:47–60, :67, :70; Q/membership.rs:31–32 |
| hello encode / decode (version exactly one byte, types 0–31 and odd critical; Memberships) | Q/message.rs:91–157 |
| verdict encode / decode (Name only in 0x0454, never empty) | Q/message.rs:171–219 |
| Reachability: `WAKE_TOKEN_MAX` 1024, encode / decode, malformed cases | Q/message.rs:231–298 |
| Presence and PresentDevice: encode / decode, malformed cases | Q/message.rs:300–373 |
| unknown even types above 31 skippable | Q/message.rs:410 (`skippable`) |
| close codes (0x05, 0x06, 0x19, 0x1A included) and transient set | Q/message.rs:430–560 |
| decoder tests (vectors of §19.10); Membership decoder cases; close-code test; Reachability and Presence vectors (§19.16, §19.17) | Q/message.rs:563–, :632 (`a_membership_needs_a_certificate_and_a_binding`), :675 (`close_codes_round_trip`) |
| Membership TLV 0x045C / 0x045E: encode, decode (certificate and binding required); `MEMBERSHIPS_MAX` | Q/membership.rs:31–43, :149–180 |
| binding transcript (label ‖ link key fingerprint ‖ channel binding ‖ SHA-256 of the certificate); sign (Ed25519 / P-256 only); verify under the certificate's key | Q/membership.rs:63–72 (`binding_transcript`), :79 (`Membership::sign`), :117 (`Membership::verify`); Q/key.rs:54 (`LinkKeyAlgorithm::of_ndn_key`) |
| channel binding: TLS exporter, label `EXPORTER-ndn-link/1 membership`, empty context, 32 bytes; same on both sides, differs per connection; bound to the key this connection's handshake presented | Q/membership.rs:36; Q/link.rs:177 (`channel_binding`), :151 (`local_key`; test `both_sides_share_a_connections_binding_value_and_no_other_connection_does` in ndn-face-quic/tests/link.rs) |
| vectors of §19.18 | Q/membership.rs:232 (`the_spec_vectors_are_what_this_code_writes`), :278 |
| hello exchange order; verdict exchange; datagram check | Q/link.rs:187–290 (`exchange_hello`, `admit`) |
| failed exchange closes with 0x15 and its reason, counted against the source | Q/link.rs:292–328 (tests in ndn-face-quic/tests/link.rs) |
| message read and write: 20-byte header, expected type, MAX_MESSAGE, peer's close reason | Q/link.rs:330–402 |
| after the verdict: outbox (latest replaces), received messages routed, 256 presence namespaces, Protocol close; ObservedAddress every 5 s | Q/link.rs:404–558 (`Outbox`, `Heard::take`, `observe`) |
| `send_reachability`, `peer_reachability`, `send_presence`, `presence`, `datagrams` (DATAGRAM frames only) | Q/link.rs:657–712 |
| a dropped connection closes with code 0 and an empty reason (what §6.3 forbids) | quinn 0.11.12 src/connection.rs:946–961, :1254–1257 (lockfile pins quinn 0.11.9; same code at :928–939, :1241–1243) |
| DATAGRAM_FLOOR 1100; send_mtu; TooLarge dropped | Q/link.rs:28, :778, :740 |
| scoped face send / receive, Nack paths | Q/link.rs:720–810 |
| scope: `Carries::Everything`, `SharedRate`, rate buckets (Ack-only frames free, shared bucket after the link's), frame classification, fragments, Nack | Q/scope.rs:44–100, :128–156, :194–272, :292, :322 (test `links_sharing_a_rate_take_no_more_than_it_together` :475) |
| LP wrap / fragment / reliable / Nack / Ack encoders | ndn-rs/crates/core/ndn-packet/src/lp/encode.rs:7–92 |
| fragment if len + 4 > mtu; plain LP wrap otherwise | ndn-rs/crates/core/ndn-transport/src/link_service/mod.rs:372–428, :253–300 |
| fragments always carry TxSequence (not gated) | …/link_service/features/reliability.rs:141–160 (`frame_fragments`) |
| FRAG_OVERHEAD 50; per-Ack 10 B; consecutive Sequences | ndn-rs/crates/core/ndn-packet/src/fragment.rs:25; ndn-rs/crates/core/ndn-transport/src/reliability.rs:256 (`on_send`) |
| `ReliabilityConfig::ethernet()` | ndn-rs/crates/core/ndn-transport/src/reliability.rs:85–92 |
| NackReason NoRoute = 150 | ndn-rs/crates/core/ndn-packet/src/nack.rs:29, :40 |
| constants MESSAGE_DEADLINE … DIRECT_RETRY_REFUSED (`ndn_link::policy`); `Backoff` | N/policy.rs:10–79, :87 |
| MAX_STATUS_HOLD = 60 s | ndn-rs/crates/security/ndn-cert/src/approval.rs:104 |
| host chain: newest valid certificate and kept issuers, at most 8 | S/cert_set.rs:23, :118 (`chain_of`); ndn-rs/crates/security/ndn-namespace/src/publish/certificates.rs:188; F/links.rs:296 |
| hello and punch chain end in the namespace root (`hello_chain`, `with_root`) | N/admission.rs:933, :942 |
| known certificates for offline validation; certificate of a key by fingerprint | F/links.rs:336–347; N/host.rs:61–72 |
| own certificates (link key's, then memberships'), own role, own device names, namespace_of; enrollment eligibility | N/admission.rs:155–241 |
| `LinkTrust::own_memberships`, `OwnMembership`; memberships shown in a hello or punch (one per namespace, not the link key's, bound to the link key the handshake presented and the channel) | N/host.rs:19–59; N/admission.rs:965 (`own_memberships`); N/links.rs:472–502 |
| ndn-fwd memberships: every engine signing identity other than the node key, in a held namespace, with a served chain; relink on the identity watch | F/links.rs:283–335 (`DaemonTrust`), :490, :502 (`follow_identity_changes`) |
| enrollment slots 32 / 4 per source, Busy | N/slots.rs:34–71 |
| known revoked key refused 0x12 (unless a membership identifies the peer) | N/admission.rs:255, :537 (test `a_revoked_key_sending_no_certificate_is_refused_as_revoked`) |
| identify: leaf (steps 1–3), memberships (M1–M5), refusals held back unless identified; steps 4–11; collision with a held name → 0x19 | N/admission.rs:251–325 (`identify`), :331–427 (`identify_chain`) |
| identify offline against the root in the hello (R1–R7) | N/admission.rs:434–508, :1030 (`namespace_context`) |
| offline validation in held contexts, depth 8, no fetch | N/admission.rs:514–530 |
| peer entry lookup (first by key or any held device name; served identities not by device); is_relay | N/admission.rs:558–582; N/peer.rs:181, :197–213 (`find_any`) |
| decision rules 7.3 over identities; link policy per identity; serving per identity, own namespaces first | N/admission.rs:668–845, :838 (`link_policy_refusal`), :872 (`serve`) |
| admission → verdict + scope (directions, filter, rates, served quotas) | N/admission.rs:586–653 |
| serving policy, quotas and their defaults, one root per name, `serves` | N/serving.rs:45–121, :174–226, :244–308 (tests `own_serves_only_the_namespaces_this_device_is_in`, `listed_serves_listed_roots_only`, `open_enforces_quotas_and_one_root_per_name` in N/admission.rs) |
| routes and VIA_RELAY_COST; routes per identity; relay routes at rank for the namespaces the relay is used for; namespace route only for a node this side dials | N/routes.rs:26–96; N/links.rs:617–624; N/relays.rs:154 (`relay_namespaces`) |
| route origin static, CHILD_INHERIT; remove_routes | N/engine.rs:32–58 |
| establish: channel binding, hello (link key chain and memberships), decide, slot, admit, reliability choice, register (identities, namespaces shown), routes, transit per served identity, idle close; on end: asleep, presence per identity, relay choice | N/links.rs:451–745 |
| link up: awake, waiting Interests sent, Reachability sent, presence followed (relays, and peers one of whose roles may relay) and announced per identity | N/links.rs:751–783 |
| duplicate-link rule `keeps_existing`; register | N/table.rs:32, :172–222 (test :544) |
| revocation while linked: per identity; routes and presence of a revoked membership taken; close when none is left | N/links.rs:155–159, :237 (`revoked`); N/table.rs:482 (`close_revoked`) (test `revoking_one_membership_keeps_the_link_by_another_and_the_last_closes_it` in ndn-link/tests/memberships.rs) |
| relink after enrollment and when memberships change, 0x03 | N/links.rs:201 (`identities_changed`), :219 (`shown_namespaces`); N/table.rs:411, :430, :446; F/links.rs:502 |
| dial loop, `Backoff` (500 ms doubling to 30 s; refused 60 s), persistence for `always` only | N/links.rs:991–; N/policy.rs:87 |
| link wanted by mode and relay choice; keep: idle by datagrams, 0x05 / 0x06 closes | N/links.rs:876–947; N/control.rs:357–365 |
| dial over path candidates and resolved addresses | N/links.rs:840 (`dial_once`); N/host.rs:114–137 |
| `LinkMode`, `RelaySource`, `RelayUse`, `PeerSpec` and defaults | N/peer.rs:19–132 |
| host calls: add/remove peer, set_mode, connect, disconnect, set_active, set_wake_token, network_changed | N/control.rs:100–239 |
| waiting face: WAITING_COST, DEMAND_PER_PEER / TOTAL, 4 s default lifetime, Congestion Nack, sending past the forwarder | N/waiting.rs:39–48, :106–232, :236–288; N/control.rs:243–331 |
| relay order, choice per namespace, rank cost, status, namespace-advertised relays, release | N/relays.rs:66–119, :80 (`relay_choice`), :154–177, :178–240, :242–332, :336 (test `losing_the_preferred_relay_moves_to_the_next` in ndn-link/tests/links.rs) |
| asleep: `RelayService`, `HoldLimits`, `WakeNotifier`, `WakeRequest`, `WAKE_INTERVAL`; when asleep, held Interests, wake, forget, awake | N/asleep.rs:50–121, :144–309 (test `a_relay_holds_and_wakes_a_sleeping_device_and_delivers_when_it_links_again` in ndn-link/tests/links.rs) |
| presence: `PRESENCE_MAX`, `DirectOptions`; announce per namespace over every identity (role matrix, held contexts only), follow, punch members (smaller fingerprint) and their routes | N/presence.rs:42–67, :79–122, :126–231; N/table.rs:286 (`members`) |
| punch messages carry the Membership of the punch's namespace, bound to SHA-256(`ndn-link/1 punch` ‖ session); punches taken under each of this device's names | N/punch.rs:108, :195 (`punch_binding`); N/direct.rs:611 (`punch`), :679 (`check_answer`), :728 (`answer_punch`), :1066 (`refuse_punch`) |
| invariants: a relay of C admits an A+C device by its C membership; an A-only relay by the leaf; forged and replayed bindings refused 0x1A; hellos without memberships, and listeners that skip them, still link | ndn-link/tests/memberships.rs:339, :380, :457, :491, :546 |
| direct paths off over every identity / role pair (`pair_off`), bound (`direct_full`), member tie-breaker (`member_turn`), traffic record, member answer check, Busy at the bound | N/direct.rs:185, :347, :376–441, :679–724 |
| after a network change: direct paths closed (0x01) and punched again from the new address, the loop going on from that punch; a punch from a key with a direct path up closes that path (0x01); a path replaced or punched again ends with no retry wait | N/control.rs:237; N/direct.rs:922–1062; N/table.rs:320–353 (test ndn-link/tests/direct.rs) |
| status: mode, relay, asleep, down, serve, held_total, wakes_sent | N/status.rs; N/links.rs:254 |
| `links/list` TLVs 0x04A0–0x04DC; `LinkModeArg` | ndn-rs/crates/core/ndn-mgmt-wire/src/link_status.rs:22–93, :97–168, :174 |
| `links/connect`, `links/disconnect`, `links/mode` | ndn-rs/crates/core/ndn-mgmt-wire/src/nfd_command.rs:70–79; F/links_mgmt.rs:38–157 |
| `[[peer]]` / `[[relay]]` → PeerSpec; `[relay_service]` → RelayService and the wake command; `[links]` → `bounded`; `[relays]`, `[direct]` | F/links.rs:61–152, :153–281, :401, :466–476 |
| `[[peer]]`, `[relays]`, `[[relay]]`, `[relay_service]`, `[links]`, `[direct]` fields and bounds | ndn-rs/crates/platform/ndn-config/src/config.rs:1684, :1966, :2026, :2113, :2304, :2356 |
| `in_enrollment` / `is_key_or_certificate_name`; name filter test cases | N/admission.rs:1059–1080, test `an_enrollment_link_carries_only_the_enrollment` |
| LinkPolicy fields, default, allows_link / allows_relay / allows_direct_paths / allows_direct_path, default pairs | S/trust_context/mod.rs:304–400 |
| link_policy; relays; admits_enrollment_links; is_anchor; anchor_for; is_revoked prefix | S/trust_context/mod.rs:894, :903, :908, :929, :939, :962 |
| `trust-context` keyword; rdr_prefix | S/trust_context/mod.rs:61; ndn-rs/crates/security/ndn-cert/src/onboarding.rs:57–63 |
| context_for = longest held namespace prefix | S/keyring.rs:281 |
| role words; device-name rules; parse_device_key | ndn-rs/crates/security/ndn-cert/src/roles.rs:67–101, :150–179, :260–301 |
| certificate wire (vectors): name, MetaInfo, SPKI Content, ValidityPeriod | S/manager.rs:514–594; S/cert_name.rs:74–80 |
| rustls ring cipher suites and groups | rustls 0.23.40 src/crypto/ring/mod.rs:68–80, :179–180 |
| transit: `FaceSink::transit` and its pairing (per served identity); engine `TransitPrefixes` (counted per namespace); validation skipped (so never cached) for a namespace in transit and not held | N/host.rs:101–109; N/links.rs:651–661, :722–724; N/engine.rs:60–66; ndn-rs/crates/forwarding/ndn-engine/src/transit.rs:1–53; …/ndn-engine/src/stages/validation.rs:260–268 |
| "never back to the node it came from" not applied by address to QUIC link faces | ndn-rs/crates/forwarding/ndn-engine/src/stages/strategy.rs:119–130 (`peer_host`), :441–456 |

[RFC 2119]: https://www.rfc-editor.org/rfc/rfc2119
[RFC 8174]: https://www.rfc-editor.org/rfc/rfc8174
[RFC 7250]: https://www.rfc-editor.org/rfc/rfc7250
[RFC 7301]: https://www.rfc-editor.org/rfc/rfc7301
[RFC 8410]: https://www.rfc-editor.org/rfc/rfc8410
[RFC 8446]: https://www.rfc-editor.org/rfc/rfc8446
[RFC 9000]: https://www.rfc-editor.org/rfc/rfc9000
[RFC 9001]: https://www.rfc-editor.org/rfc/rfc9001
[RFC 9221]: https://www.rfc-editor.org/rfc/rfc9221
