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
  - introduction links, and dialling a device by the key and addresses of an introduction code's link hint, or by the one address of a short code with no key to expect (§8.6, §13.3, §13.3A);
  - the test-only fault layer: a seeded drop/duplicate/forge/delay profile on the packets arriving on a link, behind the cargo feature `fault-injection` (§17B).

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
5. Both sides MUST advertise the `max_datagram_frame_size` transport parameter ([RFC 9221]) with a non-zero value. ndn-rs advertises 65535. A side whose peer does not support datagrams closes the link with code 0x15 (Protocol) before sending its verdict (§5.4). The datagram payloads carry NDNLPv2 frames (§9) and, between devices that agreed to (§5.1, `ChannelCaps`), channel frames, told apart by their first octet (§9 item 7); both share the connection's send buffer and its one congestion controller.
6. Streams: each side MUST allow its peer at most one bidirectional stream (`initial_max_streams_bidi` = 1) and, **at the handshake**, no unidirectional streams (`initial_max_streams_uni` = 0); ndn-rs sends exactly these values, so a peer that opens a unidirectional stream before the verdict is refused by QUIC, and nothing about channels costs a link a byte before it. Only the dialer opens a stream (§5.1). **After the verdict**, a side whose hello and whose peer's hello both carried `ChannelCaps` (§5.1) and whose own admission carries channel frames (§9 item 8) raises the limit to exactly one (`MAX_STREAMS`, ndn-rs `Connection::set_max_concurrent_uni_streams(1)`), and no other side does: a link with a peer that did not advertise the capability, or one this side does not carry channels on, still has no unidirectional stream. The one stream each direction then has carries channel frames only (§9 item 7); NDN packets never travel on a stream (§4.1 item 4).
7. Timers (ndn-rs values; other implementations SHOULD use the same):

   | Parameter | Value | Note |
   |---|---|---|
   | `max_idle_timeout` | 30 000 ms | QUIC transport parameter; the connection takes the smaller of both sides' offers. A host MAY set it within the bounds of §16.4 |
   | Keep-alive (PING when idle) | every 10 s | keeps NAT bindings open. A host MAY set it within the bounds of §16.4 |
   | Dial handshake timeout | 5 s | a dial with no completed handshake by then fails; QUIC ignores ICMP, so this is the only fast failure for an address where nothing listens |
   | Direct path: `max_idle_timeout` offered by its dialer | 8 000 ms | the connection takes the smaller offer, so it applies to both sides; a dead direct path is noticed within it and its traffic falls back to the relay (§14.7). The listener of a direct path offers 8 000 ms too |
   | Direct path: keep-alive of its dialer | every 2 s | keeps the NAT mappings of both sides open (the listener's ACKs refresh its side) |

   Channel frames add no timer: they ride the connection's own keep-alive, idle timeout and congestion control.

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

- **Dialer:** MUST refuse a listener key that is not one of the forms in §3.2. If the dial has an expected fingerprint, the dialer MUST fail the handshake unless the listener's fingerprint equals it. No link message is exchanged with the wrong device. ndn-rs reports this locally as "unexpected key" and does not retry it as transient (§13). A dial with **no** expected fingerprint (a first contact, §13.3A) accepts whichever key the listener presents, within the forms of §3.2, and the dialler reads the key the handshake proved before any link message; the key is then the expected one for the rest of the dial.
- **Listener:** MUST refuse a dialer key not in the forms of §3.2. It makes no other check during the handshake.
- A device selects its link key at each handshake. A device that switches keys (for example after enrolling, §8.5) presents the new key on its next link.
- A device has **one link key**, whatever the number of namespaces it takes part in: in ndn-fwd, its node key. Its other namespaces' keys never appear in TLS; the hello shows them as memberships bound to the connection (§5.8).

## 4. Control stream

### 4.1 Stream use

1. After the handshake, the dialer opens the first client-initiated bidirectional stream (stream ID 0). This is the **control stream**.
2. Each direction of the control stream carries, in this order: one LinkHello, one LinkVerdict, then, for as long as the link is up, zero or more of the messages of §5.5–§5.7 and §5.9 (ObservedAddress both ways; Reachability from a device to a relay; Presence from a relay to a device; Departure from an inviter to a person it let go of a folder), in any order. Each message is one complete TLV with no other framing.
3. A side finishes (FIN) its sending half when the link ends, or earlier once it sends nothing more. A receiver MUST NOT expect a FIN before the link is up. After the verdict, a receiver reads further messages: it MUST ignore a message of an unrecognized TLV-TYPE that is even and greater than 31, and SHOULD close the link with 0x15 (Protocol) on any other unrecognized type (ndn-rs does). A side that stops reading after the verdict (an implementation before ObservedAddress) only loses those messages; its peer's writes then fail, and the peer stops sending them. Every message defined after the verdict has an even TLV-TYPE above 31, so a receiver that predates it skips it.
4. NDN packets never travel on a stream (§9). This stays true with channel frames (§9 item 7): the one unidirectional stream a link may have after the verdict (§3.1 item 6) carries channel frames only, never an NDNLPv2 frame or an NDN packet, and a side never writes a frame there that does not start with the channel marker.

### 4.2 Reading a message

1. A receiver reads the TLV-TYPE and TLV-LENGTH VAR-NUMBERs. If no complete header has arrived after 20 bytes, the message is malformed.
2. If TLV-TYPE is not the expected message (0x0450 for the first message, 0x0452 for the second, any type after the verdict, §4.1), the message is malformed.
3. If TLV-LENGTH exceeds 65 536 (`MAX_MESSAGE`, 64 KiB, applied to the TLV-VALUE), the message is malformed.
4. Otherwise the receiver reads exactly TLV-LENGTH more bytes. A stream that ends early is malformed. If the connection closed, the peer's close reason is reported instead.

A sender MUST NOT send a message whose TLV-VALUE exceeds 65 536 bytes.

## 5. Link messages

All TLV-TYPEs are in the application range (types above 252, written as 3-byte VAR-NUMBERs). Inside every link message (LinkHello, LinkVerdict, Reachability, Presence, Departure and their nested elements), a receiver MUST ignore an unrecognized TLV-TYPE that is even and greater than 31, and MUST treat any other unrecognized TLV-TYPE (odd, or in 0–31) as a malformed message. This is the rule of NDN Packet Format v0.3, where types 0–31 are always critical ([Decision 3](#20-decisions)). A malformed message after the verdict closes the link with 0x15 (Protocol) and a reason phrase that says what was wrong.

### 5.1 TLV-TYPE registry

| TLV-TYPE | Name | Appears in | Value |
|---|---|---|---|
| 0x0440 | Reachability | control stream, after the verdict, device → relay | HoldInterests?, WakeToken? (§5.6) |
| 0x0442 | HoldInterests | Reachability | empty |
| 0x0444 | WakeToken | Reachability | 1–1024 bytes, opaque |
| 0x0446 | Presence | control stream, after the verdict, relay → device | Name, PresentDevice* (§5.7) |
| 0x0448 | PresentDevice | Presence | Name, KeyDigest |
| 0x044A | KeyDigest | PresentDevice | 32 bytes: a key fingerprint (§3.3) |
| 0x044C | Departure | control stream, after the verdict, inviter → the person it let go | Name (the folder), Name (the members record's log entry) (§5.9) |
| 0x044E | ChannelCaps | LinkHello | 1 byte, a bit set: bit 0 = channel frames, version 1 (§5.2, §9 item 7) |
| 0x0450 | LinkHello | control stream, message 1 | LinkVersion, Data*, Membership*, Follows?, DirectPath?, ChannelCaps |
| 0x0451 | LinkVersion | LinkHello | 1 byte: the protocol version, `0x01` |
| 0x0452 | LinkVerdict | control stream, message 2 | EnrollmentLink? |
| 0x0453 | (unassigned) | — | — |
| 0x0454 | EnrollmentLink | LinkVerdict | Name* |
| 0x0456 | Follows | LinkHello | Name+: the space groups the sender follows, each `<owner>/32=sync/<space>` (§5.10) |
| 0x0458 | ObservedAddress | control stream, after the verdict | a UDP address (§5.5) |
| 0x045A | DirectPath | LinkHello | 8 bytes: the session of the punch whose direct path this connection is (§14.6) |
| 0x045C | Membership | LinkHello, PunchMessage | Data+, MembershipBinding (§5.8) |
| 0x045E | MembershipBinding | Membership | the signature of the membership certificate's key over the binding transcript (§5.8) |
| 0x06 | Data | LinkHello, Membership | a certificate Data packet, whole |
| 0x07 | Name | EnrollmentLink, Presence, PresentDevice, Departure, Follows | a Name: a namespace (EnrollmentLink, Presence), a device (PresentDevice), a folder and a log entry (Departure) or a space's sync group (Follows) |

The other numbers of 0x0440–0x045F are unassigned. **Gap note:** 0x044C was unassigned until round 7, when the `Departure` message took it (§5.9); 0x044E was unassigned until the channel carrier, when the hello's `ChannelCaps` took it (§5.2); 0x0453 stays unassigned beside the verdict's number; 0x0456 was unassigned until the re-founding's relay fix, when the hello's `Follows` took it (§5.10, [Decision 42](#20-decisions)). A message or field added so needs no new LinkVersion (it stays 1): it is an even type above 31, so a receiver that predates it skips it (§4.1 rule 3). The punch messages of §14 use 0x0460–0x046C ([§14.3](#143-the-punch-interest-and-its-answer)).

### 5.2 LinkHello (0x0450)

```
LinkHello      = LINK-HELLO-TYPE TLV-LENGTH
                 LinkVersion
                 *Certificate
                 *Membership       ; §5.8
                 [Follows]         ; §5.10
                 [DirectPath]
                 ChannelCaps
LinkVersion    = LINK-VERSION-TYPE TLV-LENGTH(=1) %x01
Certificate    = Data              ; NDN Certificate Format v2 Data packet
DirectPath     = DIRECT-PATH-TYPE TLV-LENGTH(=8) 8OCTET
ChannelCaps    = CHANNEL-CAPS-TYPE TLV-LENGTH(=1) OCTET   ; bit 0 = channel frames v1; other bits 0
Follows        = FOLLOWS-TYPE TLV-LENGTH 1*Name   ; each a space's sync group, §5.10
```

**Sender rules**

- MUST include exactly one LinkVersion, with a 1-byte value `0x01`, as the first element. ndn-rs writes it first.
- After LinkVersion come zero or more certificate Data TLVs, copied unchanged:
  - The first is the sender's own certificate for the key it presented in TLS (the *leaf*).
  - The rest are the issuers the sender keeps, nearest first (the leaf's issuer, then that certificate's issuer, …).
- A sender with no certificate for its link key (a device not enrolled anywhere, linked by expected fingerprint or on an enrollment link) sends no certificate.
- After the certificates come the sender's memberships (§5.8): one per namespace it is a member of with a key other than its link key, at most `MEMBERSHIPS_MAX` = 8. A sender that links for its enrollment only (§8.2), or that dials a short code's first contact with no key to expect (§13.3A, until the link is made again holding the party's namespace), sends neither certificates nor memberships.
- Follows (§5.10): a device that follows spaces tells a peer it uses as a relay the **exact sync group** of each — `<owner>/32=sync/<space>`, as the layer above names it, not the namespace and not the owner's whole group `<owner>/32=sync` — at most `FOLLOWS_MAX` = 32, in name order. The host says which spaces the device follows; `ndn-link` knows no spaces and derives none from the trust contexts it holds (a context names a namespace, which names every space of it). A sender that links for its enrollment only, a direct path's dialer, a peer that is no relay of this device's, and a device that follows no space send no Follows. ndn-rs writes it after the memberships and before DirectPath.
- DirectPath: the dialer of a direct path MUST send the session of its punch (§14.6); a listener that punches the dialer's key now sends the session of that punch (of the one it began last, when it runs several). Otherwise it is absent. ndn-rs writes it after Follows.
- ChannelCaps (0x044E): a sender MUST include it, one byte, with bit 0 set when it carries channel frames (§9 item 7) and all other bits clear. It is always sent, so a hello is never without it; a peer that predates it sends none. ndn-rs writes it last. A side MUST NOT send a channel frame, or grant a unidirectional stream (§3.1 item 6), to a peer whose hello did not carry it with bit 0 set; sending the field says only that this side *can* carry channel frames, and whether it does on this link is its admission's (§9 item 8).
- How ndn-fwd builds the chain: it takes its newest currently valid certificate under the current key name. It then repeatedly takes the newest currently valid certificate under the key name in the previous certificate's KeyLocator (the certificate name without its last two components). It stops at a self-signed certificate (KeyLocator names the certificate's own key), at a certificate it does not keep, at a certificate already in the chain, or at **8 certificates in total**. A self-signed root that ndn-fwd keeps is therefore included as the last element.
- The root at the end: a sender SHOULD end the chain with its namespace's self-signed root certificate, so that a relay that does not hold the namespace can check the chain offline against it (§7.1, §15.2). When the chain the host keeps does not end in a self-signed certificate, `ndn-link` appends the anchor of the held trust context that the last certificate's issuer names, if there is one. A hello therefore carries at most 9 certificates: the leaf and at most 8 issuers, which is what a receiver uses ([Decision 2](#20-decisions)). Punch messages carry the same chain (§14.3).

**Receiver rules**

- Elements are processed in order:
  - LinkVersion: the value MUST be exactly one byte, the version. A value of any other length makes the hello malformed. If LinkVersion appears more than once, the last one wins.
  - Data (0x06): appended to the certificate list in order. The Data is not parsed at this stage.
  - Membership (0x045C): decoded as §5.8 says (a malformed one makes the hello malformed) and appended to the membership list. Its certificates are not parsed at this stage. A receiver that predates memberships ignores them, as any even type above 31, and admits the sender by its link key's certificate alone.
  - Any other even type above 31: ignored.
  - DirectPath (0x045A): the value MUST be exactly 8 bytes; any other length makes the hello malformed.
  - ChannelCaps (0x044E): the value MUST be exactly one byte; any other length makes the hello malformed. A hello with none (a peer that predates the field) is read as no capability; bits this receiver does not know are ignored.
  - Any other type (odd, or 0–31): malformed.
- If no version is present, the hello is malformed.
- If the version is present and ≠ 1, the receiver MUST NOT admit the link. ndn-rs logs that the peer speaks a different version and asks the user to update the older device.
- A receiver uses the leaf and at most the **first 8** issuer certificates (`MAX_CHAIN` = 8) and ignores the rest; of the memberships, it uses at most the first `MEMBERSHIPS_MAX` = 8, and of each, its first certificate and at most 8 issuers; of Follows, the first `FOLLOWS_MAX` = 16 names (§5.10).

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
   - From then on it carries NDN packets (§9) and, when both sides advertised and admitted them, channel frames (§9 item 7). A side MUST NOT send NDN datagrams, or channel frames, before this point; no unidirectional stream is granted before it (§3.1 item 6).
   - Datagrams that arrive before this point are buffered by the QUIC stack (ndn-rs: quinn's own queue of a connection, 1.25 MB to receive and 1 MiB to send, deliberately not larger: datagrams flow before the verdict from any dialer whose key the handshake proves, so a larger queue is memory a stranger may fill, 64 handshakes and 1,024 links over) and delivered once the face starts reading.
   - The link socket's own buffers are asked to be 4 MiB each way (`LINK_SOCKET_BUFFER`, on every socket the endpoint uses, a host-bound one and a rebind's included; the kernel grants up to its `rmem_max` / `wmem_max`, and an endpoint whose request was cut says so once in its log). A window of the data layer's pieces (128 Data of 4,096 bytes, fragmented) reaches a device as some 600 datagrams in a burst, and the kernel's default of 208 KiB holds about 90: what it drops there is lost without any Nack, and costs its asker a re-expression timer (the ladder's 1 MiB put→watch showed it: 50 to 100 datagrams lost per series of 270 runs, `RcvbufErrors` of the host).
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

### 5.9 Departure (0x044C)

```
Departure = DEPARTURE-TYPE TLV-LENGTH
            Name               ; the folder:  <O>/32=data[/<path>]
            Name               ; the record:  <signer device>/32=log/<folder>/seq=<n>
```

Sent by the device that let a person go of a folder to that person's device, after the verdicts, on the control stream of a link that has narrowed to the departure or was admitted as a departure link (§8.8): it names the members record the person should fetch. The folder is a space name (heap.md §2.3, the field keeps the name `folder`); the record is the log entry name of the held members entry of that space that leaves the person out ([invite.md](invite.md) §11 rule 14).

- **A hint of which name to fetch, with no authority.** The message says nothing the person has to believe. The receiver fetches the named record by name and judges it as any members entry, by its signatures and its chain; a record that does not validate is not taken, whoever named it (§8.8 rule 6, [invite.md](invite.md) §11 rule 15). A receiver MUST NOT act on a Departure in any way that does not go through that check.
- **Sender.** A sender MUST send a Departure only to a peer whose key the handshake proved and which it let go of that folder (§8.8 rule 6). It MUST NOT send a message whose TLV-VALUE exceeds `MAX_MESSAGE` (§4.2): ndn-rs logs a warning and sends nothing instead. The latest Departure for a folder not yet written replaces an earlier one still queued for the same folder. A link tells at most `DEPARTURES_MAX` = 16 distinct folders over its life; a sender MUST NOT send a Departure for a 17th folder (ndn-rs logs a warning and sends nothing instead). ndn-rs writes the queued Departures after the other queued messages.
- **Receiver.** The value is **exactly two Names**, in this order: the folder, then the record. A value with fewer than two Names, with a third Name, with a Name that does not decode as a Name, or with any other unrecognized TLV-TYPE that is odd or in 0–31, makes the message malformed (0x15, §5); an unrecognized TLV-TYPE that is even and greater than 31 is ignored. The latest Departure for a folder replaces the earlier one for that folder (a repeat that is identical is no news). A receiver keeps at most `DEPARTURES_MAX` = 16 folders per link and closes the link with 0x15 and a reason phrase that says so when a Departure would add a 17th ([§5.7](#57-presence-0x0446)'s rule for Presence, applied to folders). A receiver that predates the message skips it (§4.1): the person is not told over the link, and learns of the record as it learns of any record, through the data layer.
- **What it is for.** The receiver's host takes the record by a registered `DepartureSink` (§8.8 rule 6), which the invitations' surface answers by `Surface::take_departure(from, folder, record)` ([invite.md](invite.md) §11 rule 15), `from` being the authenticated device of the peer that sent the message, which must lie under the namespace of the folder named; a Departure on an enrollment link, an introduction link, a departure link or a direct path is not handed to the sink (§8.8 rule 12). The message is also what lets the receiver's link status say *which folder and which record* the closing link was about, once the sink took the record (`LinkState::Down`, §8.8 rule 8).

The test vector is §19.20.

### 5.10 Follows (0x0456)

```
Follows = FOLLOWS-TYPE TLV-LENGTH 1*Name     ; in a LinkHello (§5.2); each Name a space's sync group
```

A device that follows a space tells the relay it uses (§15.5), in its hello, the space's **exact sync group** — `<owner>/32=sync/<space>`, the group the layer above names (the owner's group plus the components after `32=data`, [heap.md](heap.md) §2.5; `ndn_heap::wire::sync_group_of`) — so that the relay routes that group over the link (§10) and no other. Two people each the root of a namespace, each following a space of the other's, reach each other through a community relay that holds neither namespace: the relay routes each linked device's own namespace group (§10) and, from this field, the group of each space its device follows; without it a Sync Interest of Alice's space, multicast out of her relay face, has no route toward Bob and Bob never hears the space ([Decision 42](#20-decisions)). The field names groups, never namespaces: the owner's whole group `<owner>/32=sync` is the prefix of every space of the owner, so a claim of it would deliver the state vector of every space of the owner, private ones included, to any identified peer of the relay ([Decision 43](#20-decisions), [§13.6](#136-follows-threat-notes)).

- **Sender.** A device MUST send it only to a peer it uses as a relay whose entry has no `routes` of its own (a relay with `routes` routes those and no more, §10), in the hello of a full link: not on an enrollment link or first contact (§8.2, §13.3A), not on a direct path (§14.6). It names the groups of the spaces it follows and no others, each as given by the host, once each, in name order. **The host says which spaces the device follows** (`Links::set_followed_groups`, the whole set at each change): `ndn-link` knows no spaces, and holding a namespace's trust context says nothing of which of its spaces the device follows, so none is derived from the contexts held. A group is `<owner>/32=sync/<s1>[/…/<s4>]`: a non-empty owner namespace of plain components (no keyword, no digest), the keyword `32=sync`, then one to `FOLLOW_SPACE_MAX` = 4 generic components, and at most `FOLLOW_DEPTH_MAX` = 13 components in all (an owner namespace of at most 8, the keyword and the space's 4: the depth a namespace had, plus what a group adds). At most `FOLLOWS_MAX` = 32 groups, counted as spaces and not namespaces, so a device follows a few dozen spaces over a handful of people; a host that gives more is refused whole, saying why (`Links::set_followed_groups` leaves the set as it was), so no space is silently left unrouted. A device that follows no space sends no Follows. When the groups it follows change while the link is up, `Links::set_followed_groups` closes each link whose hello told others and dials it again, as for a change of memberships (§8.5): the relay learns the new set from the new hello, and the group routes of the old link go with it.
- **Receiver.** The value is one or more Names. A Follows with no Name, a TLV-TYPE inside it other than Name that is odd or in 0–31, a Name that does not decode, or a Name that is no space group (no `32=sync` keyword after a non-empty owner, a keyword or digest in the owner, **no component after `32=sync`** — the owner's whole group —, more than `FOLLOW_SPACE_MAX` components after it or one that is not generic, or more than `FOLLOW_DEPTH_MAX` components in all) makes the hello malformed (0x15, §5, §6.3): a namespace is no group, and a claim that would route more than the spaces it names is refused, not trimmed. An unrecognized even type above 31 inside it is ignored. More than one Follows in a hello add their Names. A receiver uses the first `FOLLOWS_MAX` = 32 Names of all and ignores the rest. A receiver that predates the field skips it (§4.1).
- **What it buys.** A claim, not a proof: the receiver asks no proof of following (a trust context is public, so none could be asked), and the claim buys **only** the routes of §10 for the groups it names, on a full link whose peer an identity admitted and no grant admitted: never another space of the same owner, another name, a trust context, an entry, a quota or a scope. §13.6 says what a false claim gets.
- **How a daemon learns the set.** A daemon runs the links, and the data layer runs in a host process beside it, so the host says which spaces the device follows over management: it marks the space's group on `security/transit` ([mgmt-trust.md](mgmt-trust.md) "Transit"), over a management connection it keeps open, and the daemon calls `Links::set_followed_groups` with the groups all its faces mark. A mark is owned by its connection and gone when it closes, so a host that ends or crashes leaves no space followed. It carries nothing in transit and is gated as the transit marks are (a local operator or a member of a transit group). A name that is no group, more than `FOLLOWS_MAX` groups together, or a daemon with no links is refused (`transit-not-personal`, `transit-follows-full`, `links-not-running`), saying why. A host marks the group of each space it follows whose owner is not its own namespace (the relays route a namespace's own group for the devices they serve, §10): `ndn-heap` marks `<owner>/32=sync/<space>` of each space open as a member or carried, and `ndn-repo follow` of each space it carries.

The test vector is §19.21.

## 6. Closing a link

### 6.1 Close reason codes

A side closes a link with a QUIC `CONNECTION_CLOSE` of type 0x1d (application). Its Error Code is one of the codes below, and its Reason Phrase is a UTF-8 sentence for the person reading the other side's log. That sentence SHOULD say what to do, in terms of no particular host (ndn-rs sends the neutral sentence of its refusal's detail, §14.10). It is not machine-readable.

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

**The shape of a device certificate (a rule of its own).** A device is named `/<namespace>/<role>/<device>`: the namespace's name, then **one** component naming the role (what the device does there: `admin`, `member`, `node` or `guest`), then **one** component naming the device. Its certificate is named `/<namespace>/<role>/<device>/KEY/<key-id>/<issuer>/<version>`. A certificate of any other shape (`/<namespace>/<device>/KEY/…` with no role, a role word the namespace does not know, a device component outside the rule of step 6, no `KEY` after the device) identifies no device: steps 6 and R3 leave the peer **Unknown**, which another certificate, an expected key, a grant or an enrollment link may still admit.

1. A side that finds this MUST say so in the reason of that outcome (the link details `not-device-certificate` and, for a namespace it does not hold, `foreign-not-device-certificate`; [mgmt-trust.md](mgmt-trust.md)): **the shape expected** (`/<namespace>/<role>/<device>`, here with the namespace filled in, and `…/KEY/<key-id>/<issuer>/<version>` for the certificate), **the name the certificate had**, and **what to do**: issue the device's certificate under that shape, for example `/<namespace>/member/<device>` (a host that names its devices by a label of its own names them `<namespace>/member/<label>`; ndf does).
2. The name received is the peer's words. A side MUST show it as received but cleaned of control and invisible characters (control, bidirectional-control, zero-width and tag characters removed, runs of whitespace collapsed to one space: what ndn-face-quic's `clean_text` does to a peer's close text) and, when it is long, cut to at most 200 characters ending in `…`, in the sentence and in the fact `certificate`; the root certificate's name of the foreign case (`root`) the same. The facts are `certificate`, `namespace`, `expected` (the shape under the namespace) and, in the foreign case, `root`.
3. *Threat note.* The reason names the certificate the peer itself sent and the namespace this side already holds or the peer's own root names; it discloses nothing the peer did not send, and it does not say which names or roles this side's policy would accept beyond the public shape above.

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
   - when the policy serves none, and declined at least one identity (not for a quota or a name collision), and the policy is not `open`: a live **grant** (§8.7) of the peer's key admits it by the identities in the namespaces its entries list, under the quotas, in each entry's role's scope; and when the key has **no live entry** but a live **departure mark** (§8.8), an identity in one of the mark's namespaces admits it on a **departure link**, which carries one members record and nothing else;
   - otherwise, when the policy serves none, refuse with the refusal of the first (**0x19**, or **0x16** for a full quota), naming the entry ended last of the key if there was one. A served device gets no enrollment link: it proved who it is, and this side does not serve it. When this side is eligible to relay enrollments (§8.1), the 0x19 reason says the device can enroll over it by linking with a hello that holds no certificate of another namespace (rule 6).
6. If the peer is Unknown and not key-expected:
   - If the link was not dialed by this side, has no peer entry, and this side is eligible to relay enrollments (§8.1), admit as a **relay-side enrollment link**. A device with no certificate is also what a joiner's first contact is (its hello is empty, §13.3A), so **while this side's introduction surface is open (§8.6) the link also carries the introduction's names** (the union of the two scopes, §8.6 *Enrollment and introduction*); the enrollment verdict it tells the peer is the same. If no enrollment slot is free, refuse **0x16** instead (§8.4).
   - Otherwise, if its hello carries no certificate, it has no peer entry and the serving policy is `listed` or `open`: refuse **0x19** (a relay routes a served device by the device name its certificate gives).
   - Otherwise refuse **0x10**.
7. Otherwise admit a **full link**: a key-expected peer, whether identified or not.
8. **Introduction links** (§8.6). A refusal of rules 2, 5 or 6 with **0x10** or **0x19** is replaced by admitting the peer on an **introduction link**, when this side did not dial the link and takes introductions (its host named introduction prefixes). If no slot is free (§8.4), refuse **0x16** instead. No other refusal is replaced: a revoked key, a role the policy does not let link, a key a peer entry does not expect.

The identities a link is admitted by are what the rest of this spec calls the peer's identities on the link: its routes (§10), presence (§14.8), revocation while linked (§12) and transit (§15.7) apply to each.

A revoked key or issuer is refused in §7.1 before any of these rules, unless another certificate or membership identifies the peer, so it never reaches an enrollment link through them. This includes a peer that sends no certificate, when the side knows a revoked certificate of its key (§7.1).

Under the default serving policy `own`, rule 5 admits unasked only the devices of the namespaces this side holds a certificate in, and, by a **grant** of their key (§8.7), the one device and namespaces an introduction admitted. A device of a held namespace this side has no certificate in, which earlier versions admitted, is refused with 0x19 unless a peer entry or a grant names it ([Decision 20](#20-decisions), [Decision 36](#20-decisions)).

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
   - a **key or certificate name**: the components of `name` after `ns` contain a GenericNameComponent (0x08) `KEY`, and the **first** such component (a) comes right after the identity part of the name: at most two components before it (none for the root's key, `CA` for the CA's, `<role>/<device>` for a device's, §7.1), none of them a KeywordNameComponent (0x20), and (b) is followed by 1–3 further components. This matches `…/KEY/<key-id>`, `…/KEY/<key-id>/<issuer-id>` and `…/KEY/<key-id>/<issuer-id>/<version>`. A name inside a collection (`…/32=log/…`, `…/32=data/…`) has a keyword component before any `KEY` its path spells, so it is no key name: the test is the same everywhere it is used (enrollment links, grant links, §8.7 rule 10, and the departure link, §8.8), so a collection path with a literal `KEY` component does not let its entries cross as certificates.

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
| `/home/member/phone/32=log/home/32=data/diary/KEY/x/seq=3` (an entry of a collection whose path has a `KEY` component: a keyword component comes before it) | no |
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
7. **Nack.** When a scope drops a *whole* Interest, it answers immediately with an LpPacket Nack carrying that Interest, and the reason says why:
   - **NoRoute (150)** for an Interest the scope does not carry (its name is outside the names, or the kind of packet is not what that direction carries): "there is nothing here for that name";
   - **Congestion (50)** for an Interest dropped for a **rate** (the link's frames, its bytes, a bucket shared with other links, or an answered budget that has less than a 32nd of its burst left, see below): "dropped for rate, ask again soon with a backoff". It never means "not there". A Congestion Nack is the link's whole message to the asker; an asker that retries after a short, growing pause (the data layer's: 10–20 ms, doubling to at most 160 ms, at most 8 times in a fetch) finds a token again within one refill.

   An Interest received from the peer is Nacked to the peer, in a QUIC datagram; an Interest this side would send is Nacked back to this side's forwarder (NoRoute only: what this side sends is judged by the names, not by rates). A dropped Interest first fragment, or any other dropped frame (a Data, a fragment, an Interest over the rate of its names, below), is dropped silently.

   **A Nack must not amplify a flood.** Each Congestion Nack costs the link one datagram sent (about the size of the Interest it carries), so the Congestion Nacks of one link are bounded by a bucket of their own, `CONGESTION_NACKS` (`ndn-face-quic`): **256 at once, refilled at 128 a second**, per link. A peer that floods gets one Nack per Interest it lost for the first 256 and then one per 8 ms at most, the rest of its drops silent and counted; its Nacks are never more than its own Interests (one for one) and never more than about 128 × 100 bytes = 13 KB a second after the burst. An honest asker that meets a rate loses a window of 32 or so, which the burst covers; one that keeps asking past a rate for as long as a series lasts (a pull of many MiB back to back over the answered budget of a grant link) must cut its window at the Nack, as the data layer does (heap.md §7.4: halved once for the asks in flight, then one more a round), or it empties this bucket as well and what it is Nacked past it is dropped silently. A bucket of Nacks is per link, so a namespace of 32 links is answered at most 4,096 a second.

**Rate limits.** Received frames are bounded by buckets, each a token bucket that starts full at `burst` tokens and refills continuously at `per_sec` tokens per second, up to `burst`. They are taken in this order, and a frame that finds a bucket empty is dropped (rule 7 says with what answer), without taking from the later ones:

1. **Frames, per link.** Every received frame that carries a network packet or a fragment of one costs one token. A frame with no Fragment (an Ack-only or idle frame, rule 2) takes no token of it, so the peer's acknowledgements of the fragments this side sends cannot crowd out the peer's packets ([Decision 7](#20-decisions)); it takes one of the **frames with no packet** buckets, below (round 12, L1).
2. **Interests, per link** (optional, `LinkScope::interests`, round 12, M2): an Interest, whole or its first fragment, takes a token of a bucket below the frames' (it is a small frame that may cost this side a Data of kilobytes: the frame bucket was sized for pushed fragments, the Interests are bounded below it); an Interest that finds none is dropped **with a Congestion Nack**, as for any rate. Data and fragments take none of it.
3. **Bytes, per link** (optional, `LinkScope::bandwidth`): the length of the frame, in bytes. A link bounded by bandwidth as well as by frames: the frame bucket bounds the small frames (the CPU spent per packet), the byte bucket the large ones (what is received and stored). Its `burst` MUST be at least the largest frame. A scope with no byte bucket is bounded in bytes by its frames times the datagram size.
4. **The names rated apart** (optional, `LinkScope::rated`, a list of classes, round 12, H1): the Interests of some names take a token of a bucket of their own per class, after the link's buckets, the first class that names the Interest deciding which: the data layer's asks (`<device>/32=grant/…`: the first keyword after plain components, as the data layer routes a served name; §15.3). An Interest that finds none is dropped **without a Nack** (a flood of asks deserves no answer) and takes nothing of the shared buckets.
5. **Shared with other links** (optional, `LinkScope::shared`: the serving quotas of §15.3): a frame that passed the link's buckets then takes a token (and, when the shared bucket has a byte bound, its length) from the bucket the links of a namespace share.

**Frames with no packet** (round 12, L1) take no token of the buckets above, and are bounded by their own, per link: those that carry **no TxSequence** (acknowledgements, idle frames) take a token of `LINK_ONLY_FRAMES` (`ndn-face-quic`): **1,024 at once, refilled at 1,024 a second**. An honest peer sends them from its idle-Ack pump, which ticks every 5 ms (200 a second) and sends one frame, or a few when more acks are pending than one frame holds, so even at 100,000 packets a second received it sends some 600 a second, and a frame of acks carries as many as the MTU holds (about 250), which no per-frame count of acks may limit. Those that **carry a TxSequence** besides (no honest peer sends one: a frame with a TxSequence carries the fragment it numbers) also take a token of `STAMPED_LINK_ONLY_FRAMES`: **16 at once, refilled at 4 a second**; each would make this side remember the sequence for up to two RTOs and queue an Ack. A frame over either is dropped silently. The reliability layer, for its part, reads an ack only when it names a frame still in flight (`LpReliability::on_receive`: `unacked.remove(ack_seq)` finds it; an ack of a TxSequence not yet sent, or no longer held, is nothing, and counts as evidence of no loss), and reads at most twice `max_unacked` acks of one frame.

**What this side sends** (round 12, M2): a scope that has `LinkScope::answered` bounds the **bytes of answers** (Data, Nacks and their fragments) it sends the peer, in `sending()`: an answer over it is dropped silently (a Data has no one to be Nacked to), so what a peer can make this side send is bounded by more than the Interests it sends. The Congestion Nacks the scope itself sends take none of it (they have their own bucket). **An Interest is told, not left to a timer:** a Data dropped over the budget leaves its asker to its timer (250 ms, the first re-expression of the data layer), so the Interest is judged where it comes in: it is admitted only while at least a 32nd of the budget's burst is left in the bucket (`ANSWER_ROOM`: 2 MiB of a grant link's 64 MiB, which holds the answers of 480 pieces of 4 KiB, more than three windows of the data layer's 128) and is otherwise Nacked Congestion like an Interest over any rate. The bound on what is sent is the budget, which this does not move; the room only means that the answers of the Interests already admitted find their bytes. (Found by the ladder: a 1 MiB put→watch series that outran the budget had its answers dropped silently, 6,500 frames in a series, and the p95 of the series was the timer.)

Every frame dropped for a rate is counted (`ndn_face_quic::ScopeCounts`: `over_rate`, and `congestion_nacks` for the Nacks sent), per host, and shown in the link report (`LinkReport::frames_over_rate`, `LinkReport::congestion_nacks`; §15.3). The scope also logs the first drop of each ten seconds with the reason and what to do ("dropped an Interest … over the rate limit: …").

### 8.4 Slots and idle close (relay side)

- A relay holds at most `ENROLLMENT_LINKS_MAX` = 32 enrollment links at once, and at most `ENROLLMENT_LINKS_PER_SOURCE` = 4 from one source IP address (several devices may enroll behind one NAT). Introduction links (§8.6) and departure links (§8.8) are counted in the same slots.
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

### 8.6 Introduction links

An introduction link lets a device that hands out introduction codes ([invite.md](invite.md) §8, §9) answer the one exchange of a joiner it knows nothing of: the offer fetch, the ask, and their answers. Nothing else crosses it, in either direction, and none is taken unless an offer is open.

- **Taking them.** The host gives its links the device's **introduction surface** (`Links::set_introductions`, the `Introductions` trait; for an `ndn-invite` device `Invites::surface()`, invite.md §13.1; `LinkHints::serve(&invites)` does it). A stranger is admitted on an introduction link only while the surface is **open**: some offer of the device has not expired by its clock, a closed offer included. With none open it is refused as any device nobody knows; the prefixes are cleared by the offer's expiry, with no timer of the links'. Links already up stay until they end.
- **Who holds whom.** `LinkHints` holds its `Links` **weakly**: whoever started the links owns and ends them, and a host that keeps the hints (the invitations hold the host, the node's judge may hold it as its adopter) does not keep the links, their sockets or the store a `DeviceMemory` over the node's store holds. The links hold the invitations' surface, which holds the invitations' state weakly; the invitations hold their host and the node through a `NodeHandle`. Nothing leads from the links back to the host, the invitations or the node, so a host that sets its hints after the links start leaks nothing, and a closed node's store directory opens again at once. With the links gone, the hints fail closed and say so: no hint, a dial refused with "the device's links are closed … start the links again", no grant installed (logged at `warn`).
- **Admitted by.** Rule 8 of §7.3: a link this side did not dial, which no peer entry expects and no namespace held here, nor the serving policy, vouches for. It is admitted with no identity: nothing is known of the peer but its key, which the handshake proved. Its LinkVerdict is a full verdict (no EnrollmentLink).
- **Enrollment and introduction.** A device with no certificate may be a joiner (a first contact's hello is empty, §13.3A) or a device that enrolls. An inviter that also admits enrollment links (§7.3 rule 6: it is eligible to relay enrollments) cannot tell them apart by the hello, so while an offer is open the relay-side enrollment link carries the **union** of the two scopes: the names its enrollment scope names (§8.3) and the names the surface carries, in both directions, with the enrollment link's receive rate and slots. The introduction names are not carried once no offer is open. The joiner's link is not an enrollment link on its side: the peer entry it dialled is the introduction's (§13.3), and it is made again when it holds the inviter's namespace whatever enrollment verdict the inviter sent.
- **Scope** (§8.3):

  | | |
  |---|---|
  | receives from the peer | Interests only |
  | sends to the peer | answers only (Data and Nacks) |
  | name filter | the surface carries the name, judged at every packet (invite.md §13.1): an ask `<D>/32=intro/<ParametersSha256Digest>` while an offer is open, or the offer's own packet `<D>/32=intro/32=offer/<id>` of an unexpired offer of `D`, or the hint record `<D>/32=hint/<token>` where `token` is the token of one of `D`'s own offers with a short code (the record, or the mark that the offer is gone, is answered for no other token: a name of that family for an unknown token is not carried and gets no answer). No bare `<D>/32=intro` prefix or other name under it, no log entry, piece or other packet the device holds by name, and no other name of the hint family |
  | receive rate limit | `ENROLLMENT_INTERESTS` (burst 32, 4/s) |

- **No routes**, presence or sync group: answers return the way their Interests came.
- **Slots and idle close.** Introduction links share the enrollment links' slots (`ENROLLMENT_LINKS_MAX`, `ENROLLMENT_LINKS_PER_SOURCE`) and their idle close (`ENROLLMENT_IDLE`), §8.4.
- **Replaced by a full link.** The joiner dials again (§13.3) once it holds the inviter's namespace. This side adopted the joiner's namespace answering its ask, so the new connection's hello identifies the joiner in a namespace this side holds the trust context of; it is a full link only if this side's serving policy serves it (§7.3 rule 5, §15.2) or a **grant** of its key serves it (§8.7): a device of another person's namespace, which this side holds but holds no certificate in, is refused with **0x19** under the default `own`, and without a grant stays on an introduction link, which carries no sync. An inviter therefore keeps `own` and grants the person it introduced (an `ndn-invite` device does it by itself on admitting the joiner, invite.md §10 rule 1). The earlier advice, that an inviter which wants to sync with the people it introduced chooses `open` (within quotas) or `listed`, is **withdrawn**: `own` plus the grant is tighter and enough, and `open` stays what it was (§8.7 rule 4). When served, the new link is admitted by rules 3 to 5 as a full link, and replaces the introduction link under the duplicate-link rule (§11: a newer link dialed the same way replaces the older).

The scope is why a stranger needs no admission: what it can send is the offer packet of an open offer (signed by the device, public to whoever holds the code) and an ask, which the invitations judge, counting wrong tries and bounding the asks it holds (invite.md §9.1, §9.6), within the enrollment links' bounds. Earlier text served the whole `<D>/32=held` prefix, which also reached every packet the device holds by name; the surface narrows it to the offer.

### 8.7 Grants

A **grant** says: *the device holding link key K may link here, as a person of the namespaces N₁…Nₖ, in the scope of the folder F, until U* (or with no date: rule 6). It exists so that a device that keeps the default serving policy `own` (§15.2) still links with the one person it introduced (§8.6), and with no one else it merely holds a context of. The person's namespace is held here, but no certificate of it is, so `own` refuses it (0x19, §7.3 rule 5); the grant serves exactly that key in exactly those namespaces, and the link it makes carries the names of the folder F and little else (rule 10). It is authority to *link*; what the layer above answers on the link is its own gating's, within the names the link carries. A grant has **two ends**: the inviter's entry for the person (rules 1–15) and the joiner's **mirror** of it, an entry for the inviter (rule 16), with the joiner's own routes toward the folder's other writers (rule 18).

1. **The table: a set of entries per key.** A grant is an **entry** `Grant { key, namespaces, folder, role, until }` (`until: Option<SystemTime>`, `None` for no date), identified by `(key, folder)`; the table holds, per key, the **set of its entries**, one per folder: a person this device invited into two folders has two entries, and a second offer never replaces the first. `Links::grant(grant)` adds the entry of `grant.folder`, or replaces the entry of the same key and folder, and never closes a link while another entry of the key stands; `Links::revoke_grant(&key, &folder) -> bool` ends the entry of that key and folder now (`true` when one was in force) and closes the key's links only when it was the key's last entry (or narrows them to the departure, §8.8); `Links::revoke_grants(&key) -> bool` ends every entry of the key (the host ends the person; no departure is told) and closes the links; `Links::grants()` lists the entries in force, sorted by key, then folder. The table is in memory and the host's: ndn-link persists none. An `ndn-invite` device is the single source of its grants: `LinkHints::serve(&invites)` installs `Invites::departures()` (§8.8) and `Invites::grants()` at start, and the host forwards the invitations' `Host::grant`, `departure` and `revoke_grant(key, folder)` to `LinkHints::grant`, `LinkHints::depart` and `LinkHints::revoke_grant(key, folder)` (invite.md §10 rule 8; `grant` is called again when a held members entry changes the role it admits the person in), so a grant survives a restart without ndn-link keeping it. `LinkHints::revoke_grant` is the in-memory forward only (the invitations make their own ends durable); a host that ends or renews a grant itself calls `LinkHints::end_grant(&invites, &key)` (every entry of the key: `Links::revoke_grants`, then `Invites::end_grant`), `LinkHints::end_grant_in(&invites, &key, &folder)` (one entry: `Links::revoke_grant`, then `Invites::end_grant_in`) or `LinkHints::renew_grant(&invites, &key, until)`, which close or update the links and make the change durable in the grant's note, so that a restart does not undo it (invite.md §10 rule 9). A date the invitations hold that the platform's clock cannot count to makes the entry already over, never unending. An entry that replaces another of the same key and folder moves its `until` and its role and leaves the links it admitted; one that lists other namespaces closes only the links that no live entry of the key admits any more (rule 6), and the device links again to be judged by the entries then. Making an entry also forgets the departure mark of that key and folder: the person was invited again (§8.8).
2. **Where it is consulted.** Only in rule 5 of §7.3, where the serving policy serves none of the peer's identities and *declines* at least one (0x19: the sentence of `not-served-own`, `not-served-unlisted` or `not-served-uncertified`), never for a refusal of a quota (0x16) or a name collision, and never under `open`. A link the policy already serves is as before: the grant adds nothing to it and is not recorded on it.
3. **By key and namespace, both.** An entry admits the peer when the key the handshake proved is the entry's key *and* the peer has an identity in a held namespace the entry lists: that identity was validated as for any device (offline, revocations and the namespace's link policy judged first, §7.1, §7.4). An identity served by a root this side does not hold (`served`, §7.1) never qualifies. Only the identities in the namespaces of the key's entries are admitted: the routes, presence and sync groups of the other namespaces the hello showed are not added (§10). Another key of the same namespace gets nothing; the same key showing another namespace gets the link for the granted one only.
4. **Never wider.** A grant link counts against the link limits of the serving policy (`Listed`'s quotas, when it has them, or `Quotas::default()`: `links_total`, `links_per_namespace`, §15.3); the quota or the name collision that refuses it refuses the link (0x16, 0x19). Its **rates** are the grant link's, not the strangers': a member the owner invited, authenticated and revocable, takes a frame and byte rate that an ordinary transfer never meets, with the byte and frame buckets and the ask bucket as the bound on a member that misbehaves (§15.3, which states the numbers and why). **Under `serve = open` a grant changes nothing:** `open` serves any held namespace already, under its quotas, and the link is the one an open relay gives (a stranger's rates). The round-4 `open` posture (§8.6) is unchanged. `own` plus grants is the tighter choice, which this spec recommends to an inviter, and the advice that an inviter must choose `open` or `listed` to sync with the people it introduced is withdrawn.
5. **The role narrows the scope, per entry and per packet** (§8.3). Each entry's role is the one the space's members in force give (the invitations re-derive it and call `grant` again when it changes). The link's `LinkScope` is **not fixed at admission**: its name filter and its `answers_in` filter are evaluated **at every packet against the entries live then**:

   | | |
   |---|---|
   | receives from the peer | Interests under the carried names (rule 10); Data (answers) only **under the peer's own device names, or under the carried names of an entry whose role is `writer`** |
   | sends to the peer | everything the name filter carries |
   | name filter | the names of rule 10, over the live entries |
   | receive rate limit | the grant link's (§15.3): per link 65,536 frames burst, 32,768 a second, 64 MiB burst, 32 MiB a second; per namespace four times that; an Interest over it is Nacked Congestion |

   A person who writes in folder A and only reads in folder B pushes Data under A's names and not under B's; a demotion, a promotion or an entry's end takes effect **at the next packet**, with no close and no relink (round 6 closed the link of the old role instead). A reader writes nothing, so what it sends toward this side is Interests; the Data it pushes under any other name is dropped at the link. The answers *under its own device names* pass, because the layer fetches them from the reader: its certificates (a signed request of the reader is validated by fetching its chain by name) and the seal the owner fetches to wrap a folder's epoch key for it (heap.md §6.5, invite.md §13.2: without them a reader's join cannot complete, which the reader case proves). The layer's own gating still decides what is answered.
6. **Entries end one by one; a link stands while one is live.** An entry ends at its `until` (judged on this side's clock at every admission, and by one task that sleeps until the earliest `until` of any entry and wakes when an entry is made or ended, so a link closes at the last `until` with no polling of the table), on `revoke_grant(key, folder)`, and, for a key's whole set, on `revoke_grants`. An entry that ends closes **no link while another entry of the key stands**: the person keeps syncing the other folder, and the next packet is judged by the entries that remain. Replacing an entry with one of other namespaces closes only the links that no live entry admits any more (by any identity the link was admitted by). A **link** a grant admitted is tagged with its key and ends only when the **last** entry of the key ends: with **0x19**, the sentence saying which entry ended last and what to do (`grant-ended`: *"your key K was granted a link here as a person of N, until U, in the folder F, and the grant ended: it expired | it was revoked … | it was replaced …. Ask the person who invited you to invite you again"*); or, when the last entry ended by `revoke_grant` and a held members entry left the person out of that folder (a departure mark of it is installed, §8.8), the link **narrows in place** to the departure and closes after the record is carried. An expired last entry and `revoke_grants` close with no departure. A grant with **no date** (`until: None`, the invitations' default, invite.md §10 rule 2) follows the space's members: it lasts while the held members admit the person and ends when the invitations end it on an entry that leaves them out; there is no day on which the link silently stops. The expiry task sleeps on the monotonic clock, which stands still while a machine is suspended and does not follow a step of the wall clock the dates are on, so while a dated entry is in force it looks at the wall clock again at least once a minute: a suspend or a clock step is seen within a minute. Links another rule also admits stay.
7. **Refusals say why and what to do.** A device refused under `own` or `listed` with no grant is told, besides what it was told before, that its inviter can grant it by inviting it ("inviting you", §8.7). A device whose key had entries that have all ended is told so in the refusal of the next link of that key, as a cause (`grant-ended`, with `ended` = `expired`, `revoked` or `replaced`, and the `folder` and `until` of the entry **ended last** of the key); the table remembers the last 64 ended entries, one per (key, folder). A device whose key is granted but whose certificates are of none of the granted namespaces is told which it showed and which are listed (`grant-unmatched`). The grant's sentence **comes first** in the refusal: a peer's words are bounded where they are read (`PEER_TEXT_MAX`), and the sentence of a refusal under `own` is long. A key with no live entry but a live departure mark is not refused: it is admitted on a departure link (§8.8), and a key whose mark ran out or was used up gets the refusal of a key whose grant ended with no mark. `Links::report()` lists the entries in force (`LinkReport::grants`) and shows, for each link a grant alone admitted, the **first live entry of its key** by folder (`LinkStatus::granted`, `granted until … as a writer in …`, or `granted with no end date (it follows the folder's members record) as a writer in …`).
8. **Hosts with another link key.** The invitations' grant names the asker *device's* key. A host whose link key is another key calls `Links::grant` itself with that key (a host step, as for a `PeerSpec`).
9. **Grants add no wire change.** A grant is local to a process: no TLV-TYPE, close code or message is added or changed by it. The departure (§8.8), the one end that tells the person, adds one link message (`Departure`, §5.9); the details `grant-ended` (which gains a `folder` fact) and `let-go` are `LinkDetail` codes (mgmt-trust.md), not registered wire numbers.
10. **What a grant link carries, and what it does not.** The link's name filter (`LinkScope::names`, judged at every packet in both directions, and against the entries live at that packet: an entry that has ended carries nothing from that instant, whether or not its link has been closed yet) admits only the union, over the key's live entries, of:

    - the names under the person's own devices (the identities the link was admitted by);
    - the sync groups (`<ns>/32=sync`), trust contexts (`<ns>/32=trust-context`) and key and certificate names of the grant's namespaces, and the trust context and key and certificate names of the folder's namespace: public by design (a hello already carries the chain; the group carries no data). **The folder's own sync group is not the namespace's:** with an `ndn-heap` node, two kinds of name of the one group `Introductions::sync_group(folder)` gives the folder (rule 20), exactly: its Sync Interests (`<group>/v=N`, the version component, then what the sync protocol appends) and its **channel announce** (`<group>/32=chan/<ParametersSha256Digest>`, [channel.md](channel.md) §9: the unsigned hint that a device has live data, which every member's forwarder carries on the group; without it a person's `get` never hears that another person's device emits). The announce is a name of its own in the filter, not a widened Sync Interest: the group, the keyword `32=chan` and one 32-octet parameters digest and nothing after, so a name that follows the group with another keyword, a digest of another size or a longer tail is neither kind. Not the owner's other spaces' groups, and not the group of a space nested in the folder (`<O>/32=data/n/f1` under `n`: its group name extends `n`'s with a generic component, never a version, so neither its Sync Interests nor its announce `<group of n>/f1/32=chan/…` are carried). The announce decides nothing where it is heard ([channel.md](channel.md) §9, §10); the ask it leads to is the channel ask below;
    - the sync group (`<W>/32=sync`), trust context (`<W>/32=trust-context`) and key and certificate names (`…/KEY/<key-id>[/<issuer>[/<version>]]`) of the namespace `W` of **every other writer** the space's members in force list (`Introductions::writer_namespaces(folder)`, read live at every packet; the folder's own namespace excluded, it is the entry's): public by the same reasoning, and what lets a member validate the other writer's device certificate and learn her devices from her sync notices (rule 13);
    - what this device's introductions carry (`Introductions::carries`, §8.6): a person may ask again;
    - the asks of a channel to a device of the folder's owner namespace, `<device>/32=chan/…` (the channel layer names its setup under the sender's device name), and the session answered under such a name: the device's name is plain components under the folder's namespace, then the keyword `32=chan`. The link layer judges this itself, so a device with no `Introductions` carries them too: the setup is signed NDN judged at its two ends, and what it opens is a channel the link carries under the fair share of §9 item 9; and
    - the names of the entry's folder as the layer above names them (`Introductions::grant_carries(folder, name)`; for an `ndn-invite` device `Surface::grant_carries`, which is `folder_carries` or `writer_carries` over the **namespaces** of the writers the space's fold lists *now* (`Surface::writer_namespaces`, a person's namespace matched whole, so a writer below a broader namespace unlocks only her own), invite.md §13.2, §13.3): the log entries, pieces and piece manifest nodes of the space whatever device wrote them, the seal keys (`<W>/<role>/<device>/32=seal/<key>`) of the devices of the space's own owner namespace and the grant asks of the space to a device of it (those of the listed writers' devices by `writer_carries`), and a held copy `<H>/32=held/<Name TLV>` about a name so carried (rule 13).

    Nothing else this device serves by name crosses: a **public space other than the folder's own** (the layer answers a public space's entries by name to whoever asks) is not answered over a grant link. A device with no invitations (no `Introductions` given) carries the grant's namespaces' public names and the folder namespace's trust context and key names (the first two kinds) and the channel asks above, no group of the folder, and no folder. **What stays public by the layer's model:** the folder's sync group carries "device D moved" and nothing else; the members entries and the entries of a public space are signed, not sealed, and a person given the folder reads them (heap.md §6.1). Unsealed data of the folder itself is the folder's, and readable by whoever the link carries it to. The person can also no longer use this device's forwarder to reach other peers' names: an Interest outside the names above is Nacked at the link.

    With **no** live entry, a link the key's entries admitted carries the names of the departure only (§8.8), from that packet on, whether or not it has been narrowed or closed yet. With entries live, it carries **besides** their names the record names of every departure mark of the key in force (§8.8 rule 10): the folder of an entry ended by a record while another stands.
11. **A link whose grant ends during its handshake is closed.** The entries are read when the hello is judged and the link is registered after the verdicts (up to `MESSAGE_DEADLINE`); the close that ends an entry only finds links already registered. So a link a grant admitted is looked up against the table again once registered, and closed (0x19, naming the entry ended last of its key) when no live entry of its key admits any identity it was admitted by. The entry leaves the table before the close looks for links, and the link enters the table before the lookup, so either the close finds the link or the lookup finds the entry gone: a person who always has a handshake in flight (or stalls one past the date) keeps no link.
12. **A remembered peer is judged as it was first.** A peer remembered by link memory (§17C) whose first link was one it **dialled in** (`PeerRecord::origin = Accepted`, `PeerSpec::linked_in`) is judged, when this device redials it, by the serving policy and the grants exactly as a stranger that dials in is (rules 2–4): the link is tagged with its grant, quota and reader scope, so the grant's end closes it, and a peer no policy or grant serves is refused as it would be on the link it made. A peer this device dialled itself is admitted by its entry as before.
13. **Writers who never met.** `Introductions::grant_carries(folder, name)` and `Introductions::writer_namespaces(folder)` are **live**: on every call the invitations read the fold of the space's members (`Heap::members()`) and, besides the names of the folder, the link carries for each *other* writer the fold lists (a writer is a person, a namespace matched exactly; the folder's own namespace is the folder's and is not added): (a) the **seal keys** of her devices (`<W>/<role>/<device>/32=seal/<key>`), the grant asks of the space to them and a held copy about a name so carried (`writer_carries`, invite.md §13.3); (b) the sync group, trust context and key and certificate names of `W` (`writer_namespaces`, rule 10). It exists so that Bob and Carol, each invited by Ann by an invitation of its own, validate each other's device certificates, hear each other's devices and ask each other's devices for the epoch key: the entries and pieces of the space already cross whichever device wrote them, and what stopped them was the names that validate what they name. It is derived at every packet from the fold in force, with no cache: a writer the fold no longer lists drops out at the next packet, and one it lists appears at the next. Nothing else of a writer outside the folder is added: not an entry of its other spaces, no other name under its namespace (§13.5). A **reader** entry gains no push scope from it: these names cross toward a reader as they cross for any person admitted to the folder, but what the person may push is rule 5's. The space's members entries, which Ann's devices signed, are the single authority. What crosses is what this device's own store holds and answers (the person asks it by held asks, `<Ann>/32=held/<name>`) **and what this device's forwarder relays between two grant links, bounded**: a grant link gets a route for its person's device name (§10), so Ann's forwarder has a route for Carol's device name over Carol's link, and a name under it that Bob's link carries (Carol's log entries of the folder, whichever device wrote them) is forwarded there when it reaches Ann's forwarder: Bob's Interest passes his link's filter (rule 10), Ann's forwarder sends it over Carol's link, which carries it (names under the person's own devices), and the Data returns the same way and is judged against Bob's entries again before it crosses to him. Such an Interest reaches Ann only when Bob's forwarder routes the name over his link to Ann: Bob's own link layer installs that route, for the namespace of each writer the fold in force lists, from the folders his device joined (the joiner's routes, rule 18), or a `[[peer]]` entry for Carol reached through Ann does (§10). Ann's grant installs no route on Bob's side; the route is Bob's own, made from Bob's own fold and over Bob's own link to Ann. The relay is bounded by Bob's link's per-link and per-namespace receive rates (rule 4), by Carol's link's receive limits, by the per-packet judgment of both links against the entries and the members live at that packet, so a writer the fold drops loses her link and with it Ann's route, and a Data that returns for an Interest already pending is dropped at the next packet when Bob's entries no longer carry its name, and by the filter itself, which never carries what is outside the folder and the public names above (Carol's diary does not cross to Bob, nor is it fetched on his behalf). It is a bounded relay of what both links already carry, not a transit for any name.
14. **The end by a record tells the person** (§8.8): a member let go of the folder by a held record is told which record to fetch, on a narrow link, instead of finding the link closed.
15. **Two offers for one key and folder: the last wins, and it fails closed.** A person who joins the same folder by two codes (or an offer made again) has two grant notes for the same `(key, folder)`, and the entries are identified by `(key, folder)` (rule 1): `Links::grant` for the second **replaces** the first, whatever order the device lists them in at a restart, including its `until`. Nothing widens by it: both notes are this device's own, MAC'd after the person's proof of an offer (invite.md §10 rules 11 and 13); the entry carries the folder's names alone and the role the held members give the person now, not the role the note named; a members entry that leaves the person out, `revoke_grant`, `end_grant` and `end_grant_in` end the entry of the pair whichever note it came from. What differs between the notes is `until` alone: the winner's earlier date ends the entry earlier (less access), and its later date is one this device itself gave in an offer the person proved.
16. **The mirror grant: the joiner's end of a grant.** Until round 9 a grant was built at one end: the inviter admitted the person it introduced (rules 1–15), and the person's own `own` policy admitted no one, so once the inviter's address had changed and the person had restarted, the inviter's redial of the person was refused (0x19: the inviter's namespace is held at the joiner, no certificate of it is, §7.3 rule 5). At the end of a successful `join` the invitations therefore keep the **mirror** of the inviter's grant (invite.md §11 rule 17), and the link layer holds it as it holds every grant, with nothing new in ndn-link:

    - **The entry.** `Grant { key: the inviter's key, namespaces: [the inviter's namespace], folder: the folder the offer admitted this device to, role, until: None }`, made by `Links::grant` through the same path as every entry: the host forwards the invitations' `Host::grant` to `LinkHints::grant`, and `LinkHints::serve(&invites)` installs `Invites::grants()`, which lists mirror entries like any other, after a restart; nothing in a host changes. Rules 1–15 apply to it unchanged: it is identified by `(key, folder)`; it is consulted only where the policy declines (rule 2), by key and namespace, both (rule 3), under the quotas (rule 4), and a refusal says why and what to do (rule 7). It adds **no wire change** (rule 9): the note behind it is the device's own, local, never served, and no TLV-TYPE is registered for it (invite.md §11 rule 17).
    - **The key it holds is the key that signed the verified answer.** The join verifies that the answer to the offer was signed by a key belonging to the offering device under the anchor the code named; the digest of that key is the entry's key. Under a host whose link key is its device key (ndf's) it is the inviter's `KeyFingerprint`. **A host whose link key is another key calls `Links::grant` itself with the inviter's link key** (rule 8), and `Links::set_joined_routes` the same way (rule 18): the entry the invitations name would otherwise never match the key the handshake proves.
    - **Admission.** Under the default `ServePolicy::Own`, a link the inviter dials to this device is refused by the policy, found by the entry (the inviter's key, an identity that validates in the inviter's namespace, which this device now holds, the namespace the entry lists) and admitted as a **grant link for that folder only** (rules 3 and 4). Under `open` the entry changes nothing (rule 4). A key that is not remembered and holds no entry stays refused, and is told how to get one (rule 7). Link memory counts it: a link a live grant admitted is a link of a person a grant covers (§17C.2 rule 3), and when the inviter's address changes its redial is admitted by this entry and brings the record's address up to date (§17C.2 rule 7).
    - **The filter, per packet, in the other direction.** What crosses this link is rule 10 read from the joiner's side: the union, over the live entries of the key, of the names under the inviter's own devices, the public names of the inviter's namespace and of the folder's other writers, and the names of the folder as the layer names them (`Introductions::grant_carries(folder, name)`, over **this device's own fold in force**). Never a collection of this device outside the folder, and never the names of a folder of which the key holds no live entry. What the inviter pushes toward this device passes under her own devices only, and under the folder's carried names only when the entry's role is writer (rule 5): a reader-role mirror pushes only under her own devices.
    - **The role is the inviter's in the fold, never wider.** It is re-derived from the fold at every judgement: a writer when the space lists the inviter's namespace as a writer, else a reader (invite.md §11 rule 17). The invitations call `grant` again when a held entry changes it, and the filter follows at the next packet (rule 5).
    - **It stands only while the fold lists this device's person**, as a writer or a reader. A space not open here: no entry, since there is nothing to judge by, and so nothing is granted. A members entry that leaves this device out ends the entry: the host is told first, in memory (`revoke_grant(key, folder)`, rule 1), then the end is made durable behind the store barrier.
    - **Ends.** The entry that leaves this device out; the host (`Invites::end_grant(key)` ends the key's inviter notes **and** mirror notes, `end_grant_in(key, folder)` those of the folder; both through `LinkHints::end_grant` and `end_grant_in`, rule 1). One entry per `(inviter key, folder)`; the entries of other folders stand, and the link closes with the key's last entry (rule 6). A second join of the same folder by the same inviter key replaces the entry (an invitation again after being let go starts it again); another key of the same person (a second device) is another entry. It carries no date (`until: None`): it follows the fold (rule 6).
    - **No departure mark is ever made for it** (§8.8 rule 13).
    - **Refusals say why and what to do.** A mirror note whose MAC fails or that is of an unread version is ignored with a warning that says so and to join again with a new offer. An offer that names a folder that does not lie under the inviter's own namespace keeps no note (the inviter would otherwise be granted a link into a folder it does not own: §13.4), and says so and to join a folder of the inviter's namespace. A fold that no longer lists this device's person keeps no note, and says so and to ask the inviter for a new offer.
17. **Mutual invitations: entries of different folders for one key.** Ann invites Bob to folder A (Ann holds an inviter note of Bob and A; Bob holds the mirror of it) and Bob invites Ann to folder B (Bob holds an inviter note of Ann and B; Ann holds the mirror of it). Each device then holds, for the one peer key, an entry of A and an entry of B: the inviter's grant of one and the mirror of the other. A folder has one owner, so an inviter entry and a mirror entry of one `(key, folder)` cannot both exist, and neither replaces the other. Rules 1 and 6 apply as they are: `revoke_grant(key, folder)` and `end_grant_in` end one and leave the other and the link standing; `revoke_grants` and `end_grant` end both (the host ended the person); the link closes with the last entry of the key (0x19, `grant-ended`, naming the entry ended last); the filter is the union over both entries, each judged by its folder and its role (a person who writes in A and reads in B pushes under A's names only, rule 5). An entry of folder A never lets the key fetch folder B's names: only a folder the key holds a live entry of is carried.
18. **The joiner's routes.** The inviter's link carries the names of the folder's other writers (rule 13), but a forwarder sends an Interest over a link only when it has a route, and the joiner's forwarder had none for those names: the Interest that fetches Carol's trust context died in Bob's forwarder (`no route for /user/…/keyword=trust-context/v=1`) before it left. Only the link layer knows both the link's face and the record, and a host keeps no link state, so the link layer installs the route itself, on the strength of data its device verified:

    ```rust
    pub struct JoinedRoutes { pub inviter: KeyFingerprint, pub owner: Name, pub namespaces: Vec<Name>, pub push: bool }   // one per joined folder; `push`: this device writes in it
    impl Links { pub fn set_joined_routes(&self, routes: Vec<JoinedRoutes>); }
    ```

    `Links::set_joined_routes` replaces the whole set; it is idempotent and never blocks. **`LinkHints::serve(&invites)` calls it** with `Invites::joined_folders()` (each `JoinedFolder`'s inviter, owner and `writers`, and `push`, true when the device's role in the fold is Writer) at once, and again at every change of `Invites::joined_changes()` (a join, a members entry that changed a role or a writer, an entry that ended or began), by **one** task per `Links`: a second `serve` stops the first's task and starts its own (a restarted device on the same links is followed, and never twice), and the task ends when the invitations' watch sender is gone, when the links are cancelled or when they are dropped. A host that does not use `serve`, or whose link key is not its device key, calls `Links::set_joined_routes` itself with the inviter's link key and `push` (rule 8).

    1. **Which prefixes.** For each joined folder and each namespace `W` of its `writers`: the prefix `W` itself, over the inviter's link, at `JOINED_ROUTE_COST` = `VIA_RELAY_COST` + 1000 (1010: above every route the link layer makes for a real path and above `WAITING_COST`). **Cost decides only among routes for the same prefix.** A forwarder takes the longest matching prefix first and looks at cost only among the routes of that prefix (the forwarder returns that one entry alone), so a path to the namespace's own devices wins over this route for `W` itself, but this route beats every shorter route of the joiner's for the names under `W`, whatever its cost. A route at `W` is therefore safe only for a `W` that cannot take a name away from a better route of the joiner's; item 3 is the filter that makes it so, and it is the filter, not the cost, that holds. `W` covers what the joiner fetches of the writer through the inviter's filter (rules 10 and 13): the seal keys and grant asks of `W`'s devices (named by a device under `W`, so only `W` can route them), the trust context, and the key and certificate names under `W`: the same set the inviter carries, never more. **A writer-role joiner is routed the sync group `<W>/32=sync` as well**, at the same cost (item 2): a node registers the group prefixes it holds with its own forwarder (a local app face, heap.md §7.1), and the forwarder's longest-prefix match returns that entry alone, so a route at `W` is shadowed for every name of a group under it and the group's Interests would never leave. The group is how a writer's notices and pushes travel.
    2. **A route is a path, not a right; only a writer-role joiner is routed the group.** What may be fetched is decided by the inviter's filter at every packet, for the entry she holds for this device. `JoinedRoutes::push` is true when this device's role in the record in force is Writer (set from `JoinedFolder.role`; a host with another link key sets it itself), and only then is `<W>/32=sync` routed beside `<W>`. A reader-role joiner is routed `<W>` only, because everything it reads of a writer lies under `W`; the group, over which notices and pushes travel, is the writer-push route, and a reader gets **none**: nothing is installed for the reader's own writes, and nothing that lets a reader push; and the inviter's filter still drops what a reader may not fetch and what a reader pushes. A namespace in a writer entry and in a reader entry of one key is routed its group. A record that promotes or demotes the device changes its `role`, so `joined_changes` fires and the routes follow at the next notification (the set is replaced whole).
    3. **Never a route that was not listed, that is the joiner's own, or that can take a name from a better route.** `writers` is derived by the invitations from the fold in force, whose entries the node verified: the namespaces of the other writers the fold lists (rule 13), minus the folder's owner (the inviter's own names are routed already by the link's default routes, §10), minus the joiner's own namespace and every namespace above or below it (a hostile inviter's entry cannot divert the joiner's own names, nor `/` or a broad parent of them). **A writer in the fold is a person the inviter's owner devices listed, and the inviter's word**, so each remaining name `W` is kept only when all of these hold (invite.md §11 rule 18): (a) `IntroPolicy::refuses(W)` says nothing against it: not the root, not `/localhost` or `/localhop` (the reserved names), not a broad shared name (`/user`, `/com`, `/org`, … the default list) and not fewer than `min_components` components; (b) it **names itself**: it is the namespace of a trust context held here, or a self-certifying person's namespace (`/user/<0xA1: …>`), never a free-form prefix: a name `/dave/member` of a `/dave` the joiner reaches without holding its context is not listed, because a route at `/dave/member` would win the longest-prefix match over the joiner's own route for `/dave`; (c) it is neither above nor below any namespace held here or adopted for a folder, except an exact match (the same prefix, where cost decides). Only names that are namespaces, sorted in `Name` order and cut to `JOINED_WRITERS_MAX` = 16 per folder (the first 16 in that order).
    4. **Never toward a link that is not the inviter's identified link.** A route is installed only over a registered `PathKind::Link` path that (a) proved `inviter` as its handshake key, (b) was admitted by an identity of the namespace `owner` that validates in a namespace held here, and (c) is a full link: no enrollment link, introduction link or departure link, no direct path. Whichever side dialled it counts for nothing: the mirror's grant link (rule 16) is the inviter's full link as the dialled one is. A link of another key, however it is named, gets none; an identity **served** by a root this side does not hold (§7.1, §15.2) never counts as one of the owner's, whatever its hello claims; a link made only to introduce (before the inviter's namespace is held) gets none, and gets them once it is made again as a full link.
    5. **It follows the record, the entry and the link.** The set is replaced whole at every change of `joined_changes`: a writer that leaves the record loses the route at the next notification (no timer); an entry that ends (the record leaves this device out, the host ends the mirror) removes every route it made; a link that goes down loses its routes with its face (`remove_face` drops them); a link that comes up gets them at its registration.
    6. **Bounds.** At most `JOINED_WRITERS_MAX` = 16 writers per folder (the invitations), `JOINED_ROUTES_MAX` = 64 distinct **namespaces** in all (each with its sync group when routed as a writer: at most 128 routes in one `set_joined_routes`) and `JOINED_FOLDERS_MAX` = 16 folders (the link layer); the same writer in two folders is one route. **Each inviter key has an equal share of both bounds**: the bound divided by the number of inviters in the set, at least one (a sole inviter has all of it), taken from its folders in the order given; a share an inviter does not use is not lent to another, which keeps the rule to one line and makes what one inviter lists never change what another gets. Without the share, an inviter whose folders sort first and list the most writers uses every slot, and the folders of each other inviter get no route. What exceeds the bounds is dropped with a warning that says why and what to do (end the folders no longer used; a folder with fewer writers). **Defence in depth:** `set_joined_routes` never routes a prefix that equals, lies under or lies over `/localhost` or `/localhop` (the root included), whatever the host passes; it is dropped with a warning that says so.
    7. **Registration, and the table lock.** A path registers with no joined route, and the routes it is owed are decided right after its face and its own routes are given to the forwarder (before the link event), by the same function that applies a change of the set. The routes are decided and given to the `FaceSink` **while the link table is locked**, and the set itself lives in the table, read under the same lock: a change that raced the registration is the one the path gets, the routes are never given before the face exists, and never to a face already removed (a path leaves the table before its face is removed). **A `FaceSink` MUST NOT call back into `Links` from `add_routes` or `remove_routes`.**
    8. **A real route is never overwritten.** A prefix that one of the path's own routes already has is left to that route: never added again at the joiner's cost, never removed on its behalf.
    9. **No wire change, and it is said.** No TLV or close code is added. Each change of the set is logged at info with the face and the prefixes added or removed, and `LinkHints::serve` logs the joined folders with their inviters and writers when they change.
19. **A grant link routes the person's public names beyond its devices.** Ann's forwarder relays Bob's Interest for Carol's trust context or certificate toward Carol only when it has a route for the name over Carol's link; that link routed Carol's device names and her sync group and nothing else, so the Interest died at Ann's forwarder (a NoRoute Nack: `this forwarder has no route for /user/…/keyword=trust-context/v=1`; found by the by-name G11 case, §8.9). On a link **admitted by a live grant entry** (the inviter's grant and the mirror alike: the link is tagged with its grant, rule 6), the routes of the link therefore also include, for each identity of the link that is **held here** and lies in a namespace `ns` the grant lists: `rdr_prefix(ns)` (the trust context's name prefix), `<ns>/KEY` and `<ns>/CA/KEY`, each once, at `JOINED_ROUTE_COST` (so a path to the namespace's own devices wins). They are the public names rule 10 already carries for the grant's namespaces, so they widen no filter: a path, not a right. **Never given to** a link a policy admitted (it has no grant), an enrollment, introduction or departure link, a served identity (a device of a namespace not held: it proves nothing about the namespace) or a namespace the grant does not list. They live and die with the face, as the other routes of the link do.
20. **A grant link routes the owner's sync group prefix and carries only the granted space's group.** The groups of an `ndn-heap` node lie under the namespace of the space's **owner** (`<O>/32=sync/<rest of the space>`, heap.md §2.5), not under the namespaces of its writers, and the node registers the owner prefix `<O>/32=sync` in the forwarder's FIB. A grant link to a person of another namespace routed only that person's groups, so the inviter's forwarder had no route for her own group over the person's link and her announcements never reached the person (a version written while no link was up was not announced when the link came up). The link layer therefore also routes `sync_group(O)`, for the owner `O` of each live entry's folder, when the node gives that folder a group (`Introductions::sync_group(folder)`; none, no route), once, at cost 0 (`grant_group_routes`), over **every full link to the entry's key** (dialled or accepted, admitted by the entry, a peer entry or a policy: two people who invited each other share one link, made for the first entry), at link-up and when an entry is added (`Links::grant`). **Why the owner prefix and not the space's group:** the forwarder takes the longest matching FIB entry and returns that one alone, so a route at `<O>/32=sync/<rest>` holding only the link's face would shadow the node's registration at `<O>/32=sync`: the person's Sync Interest would be answered NoRoute and never reach the local node; the route must share the node's entry. **What crosses is the filter's, not the route's:** the entry carries the **Sync Interests** `<group>/v=N[/…]` of the group `Introductions::sync_group(folder)` gives its folder, exactly (the component after the group is a version): not the owner's other groups (other spaces), and not the group of a space nested in the folder (`<O>/32=sync/n/f1/v=N` under the group of `n`: the component after `n`'s group is a generic one), in both directions and for the pushes of a writer entry; everything else is routed and dropped at the link at every packet, so a person learns nothing of the announcements of spaces she was not granted. The namespaces' own groups (the person's, the other writers') stay public as before. **Routes are not taken back while the link stands:** when an entry ends and another stands (or the same owner's entry ended), its owner's route stays on the link until the link ends; the filter drops what it carried from that packet on and the forwarder answers such Interests NoRoute or Nacks them at the link. That costs availability of nothing (no name crosses), only a Nack, and is not repaired because the route is shared with the node's own entry and with the other entries of the owner.

### 8.8 The departure

A person this device let into a folder can be let go of it: a held members entry of the space no longer lists them, and the invitations end their entry (§8.7 rule 6). Closing the link says only that the grant ended; the person's own device cannot tell whether it was removed, whether this device restarted or whether the network failed, and a device that was offline when the entry was written may never hold it. The **departure** gives the person the one fact it needs, as signed data it can check: **the members entry that leaves it out** (called the record below). It is a *mark* in the inviter's link layer, a *narrow link* that carries that record and nothing else, a message that names the record (§5.9), and a bounded set of closing rules.

1. **The mark.** `Departure { key, namespaces, folder, record, until }` (`ndn_link::Departure`): the link key of the person's device (the grant's), the namespaces the grant admitted it in, the folder, the log entry name of the held members entry that leaves the person out (`<signer device>/32=log/<folder>/seq=<n>`; its pieces and manifest nodes are named by it), and the date, by this device's clock, after which the mark is no longer served. `Links::depart(mark)` installs it and `Links::departures()` lists the marks in force, oldest first. A mark whose date is not after now is not installed. A mark replaces the mark of the same key and folder; the admissions already counted stay only when the new mark names the same record and the same date. **The invitations make the marks**: when a held entry ends a grant by leaving the person out, and `IntroPolicy::departure_for` is not zero (default 7 days), the grant's note keeps a mark under its MAC, naming the entry chosen as invite.md §11 rule 14 says (`Heap::removed_by`); no entry found means no mark, and the link then closes as §8.7 rule 6 says (a fallback that is never an open link). A host's own end (`end_grant`, `end_grant_in`, `revoke_grants`) makes none: the person was not let go by a record. `LinkHints::serve(&invites)` installs `Invites::departures()` at start and the host forwards `Host::departure` to `LinkHints::depart`; the invitations call it **once, just before** `revoke_grant` of the same end, so a link that narrows at its last entry's end already holds the mark. ndn-link persists no mark: after a restart `serve` installs them again, and the admissions counted for them (rule 4) start again at zero.
2. **The bounds.** `DepartureOptions`, set by `Links::set_departure_options`:

   | Option | Default | Meaning |
   |---|---|---|
   | `hold` | 30 s | the longest a departure link lasts from its admission, or from the narrowing of a link |
   | `settle` | 2 s | how long after the record's entry crossed the link stays, so that the cut manifests follow |
   | `attempts` | 3 | how many departure links one mark admits, per key per mark, counted when a link is registered, in memory, and not reset by a new link |
   | `marks_max` | 256 | how many marks are kept; past it the oldest are forgotten (at least 1; lowering it evicts at once) |
   | `retry` | 15 s | the person's half: how long before the link layer asks its sink again for a departure it was not ready for (rule 6) |

3. **Narrowing a link in place.** When `revoke_grant(key, folder)` ends the **last** entry of a key and a mark of that key and folder is held, each link the key's entries admitted is **narrowed in place**: the same connection and the same face, no reconnect. The scope's `narrowing` (`ndn_face_quic::Narrowing`, asked at every packet) makes it receive **Interests only** and send **answers only** while the key has no live entry, with the name filter of rule 5: so a narrowing takes effect at the next packet, and a link whose key is granted again while narrowed **widens back** at the next packet to what its entries carry and is left open. An entry ending by its date, a host's end or with no mark closes the link as §8.7 rule 6 says. Every mark of the key in force is told and carried, not only the one of the folder that ended last. A narrowed link keeps the quota slots it held until it closes, which is at most `hold` later.
4. **The departure link.** A device whose key has **no live entry** but a live mark of it — a person who was offline when the record was written and dials again — is admitted on a **departure link**, in rule 5 of §7.3 where the entries would have admitted it: the serving policy serves none of its identities and declined at least one (not for a quota, not for a name collision), the policy is not `open`, the handshake proved the key of a mark in force that has attempts left, and the peer has an identity in one of that mark's namespaces that validates in a namespace held here (never one served by a root not held, §7.1). Each departure link **registered** counts once toward `attempts` for every mark it carries (rule 9: deciding to admit counts nothing, and a handshake refused after it — a direct path, no enrollment slot — costs no attempt). The link is **in the enrollment links' slots** (§8.4: `ENROLLMENT_LINKS_MAX`, `ENROLLMENT_LINKS_PER_SOURCE`, refusal 0x16, idle close `ENROLLMENT_IDLE`), at the `ENROLLMENT_INTERESTS` rate, with a full verdict (no EnrollmentLink); **no identity is recorded on it, no route (§10), no presence, no sync group and no quota slot.**
5. **What the narrow link carries.** On a narrowed link and on a departure link:

   | | |
   |---|---|
   | receives from the peer | Interests only |
   | sends to the peer | answers only (Data and Nacks) |
   | name filter | for each mark of the key in force, judged **at every packet** against the live marks: `departure_carries(record, name)` (invite.md §13.4: the record's log entry name, with or without its implicit digest; its pieces `<record>/32=piece/seg=<i>` and its manifest nodes `<record>/32=piece/32=manifest/seg=<k>`), and the key and certificate names (`…/KEY/<key-id>[/<issuer>[/<version>]]`, as §8.3 rule 3) under the folder's namespace and under the device that signed the record, so that the record can be validated |
   | receive rate limit | `ENROLLMENT_INTERESTS` (burst 32, 4/s) |

   **Nothing else crosses: no sync group, no trust context, no other log entry or piece of the folder, no other folder, no introduction.** A mark that has run out carries nothing from that packet on.
6. **Telling the person.** When a link narrows, when a departure link is registered, and when a link a grant admitted is registered (rule 11), the inviter sends the peer one `Departure` (§5.9) for each mark of the key in force, on the control stream of that link and on no other. When an entry ended by a record while **another entry of the key still stands**, the link does not narrow, and the person is told of the ended folder's mark only (rule 10). It is told only on a link whose key the handshake proved. The person's `Links` hears the Departures of every **full** link that has an identity of a held namespace — never an enrollment link, an introduction link, a departure link or a direct path (rule 12) — and hands each `(folder, record)` it has not settled on that link to the **`DepartureSink`** its host registered (`Links::set_departure_sink`, before the links are made: a link takes the sink registered when it was registered; the trait's one method `departure(&self, from, folder, record)` returns a future of `Result<(), NotTaken>`, `NotTaken { why, again }` saying in words why the hint was not taken and whether to ask again). **`from` is the peer's authenticated device** (the identity the link was admitted by, read at the time), and a Departure is handed to the sink **only when `from` lies under the namespace of the folder it names** (the part of the folder name before `32=data`): only a device of the folder's own namespace lets a member go of it, so a connected peer of another namespace, whoever it is, cannot hold the folder's fetch slot or drain the device's bound of takes. The sink takes them one at a time, so one take in flight per link, and at most `TAKEN_PER_LINK_MAX` = 32 different ones over a link's life. A departure the sink was **not ready for** (`again`: a take of the folder in flight, the minute's bound used, the record not fetchable yet) is **asked again** after `DepartureOptions::retry` (15 s), up to `TAKE_TRIES` = 6 asks of one record, while the link stays up; one taken, or refused for good, is not asked again. `LinkHints::serve(&invites)` registers the invitations' sink, which calls `Surface::take_departure(from, folder, record)`: the host does nothing more. **The name carries no authority.** The sink fetches the record by name and takes it as any held entry (validated, applied, judged as ever), and only for a space the device has open, told by a device of the space's owner namespace, a record that is a log entry of that space whose device lies under a namespace the device holds (invite.md §11 rule 15); a hint that is none of these is refused with a reason and ignored. The record, taken, makes the person's own space stop listing it and withdraw what it wrote after the cut, as for any entry; correctness never depends on being told. A sink's `Err` is logged and never closes the link.
7. **Closing.** The inviter closes a narrowed or departure link, whichever of these comes first: (a) **the record has been carried** — for each mark of the key in force, an Interest for the record's entry name (with or without its digest) passed toward this device **and** its answer passed toward the peer — and `settle` has passed since, so that its pieces follow; (b) `hold` has passed since the link's admission or narrowing; (c) for a departure link, the idle close of §8.4 (which `hold` precedes in ndn-rs). The close is **0x19** (NotServed, non-transient: the person's dial loop waits `BACKOFF_REFUSED`, §13.1) with `LinkDetail` `let-go`, whose facts are `folder` and `record` (lists, when the link carried several marks) and whose text reads: *"you were let go of /folder: the members record /record leaves you out; this device carried it to you and closed the link; ask the person who invited you to invite you again"*. A link whose marks have all run out under it closes with 0x19 and a sentence saying the departure it carried has expired. A link whose key is granted again before it closes is not closed by this rule.
8. **What the status says.** `LinkState::Down { why }` names the folder and the record **on both sides**: on the inviter's side from the reason it closed with (a `let-go` cause of the `Down`), on the person's from the Departure message it heard and the close it saw (a `let-go` cause, worded "the device that let you go carried it to you and closed the link"), **but only for a record its sink took** (`Ok`): a notice the sink did not take — a name that is no members entry, a record that could not be fetched, a peer that may not tell it — is the inviter's say-so and is not reported as a let-go, though the inviter's own close text is shown as the other device's words. A host that registered no sink hears no Departure, and the `Down` it shows carries the plain close. The person's node shows that the record is held and that it was let go; `let-go` is in [mgmt-trust.md](mgmt-trust.md).
9. **Bounded, and not a way back in.** The departure link is bounded in time (`hold`), in attempts (`attempts` per key per mark; **counted when a departure link is registered**, so a handshake the mark admitted that is refused afterwards — a direct path, no enrollment slot, a link that already exists — costs the person none; the count is in memory, is not reset by a new link or by the link's end, and starts again at zero only for a replaced mark or after the inviter restarts. It is **not persisted** with the grant note: the note is the invitations', MAC'd, and written behind a store barrier, so a counter in it would cost a durable write for every attempt a stranger's handshake provokes. A restart gives three more attempts per mark until the mark's own expiry, and each attempt carries only the signed record the person is entitled to, so nothing is learned beyond the person's own record and no probe is made easier), in marks (`marks_max`, the oldest evicted), by the mark's own expiry (`IntroPolicy::departure_for`, 7 days by default, zero for no mark), in slots (the enrollment links'), in rate (`ENROLLMENT_INTERESTS`) and, per link, in folders told (`DEPARTURES_MAX` = 16, §5.9) and taken (`TAKEN_PER_LINK_MAX`). A mark is looked up **only for a key the handshake proved and whose identity validates in one of the mark's namespaces**, and the invitations list marks only from grant notes whose MAC checks: a key that never held a grant has no note and so no mark. The threat notes are §13.5.
10. **An entry ended by a record while another stands.** When `revoke_grant(key, folder)` ends an entry that is **not** the key's last and a mark of that key and folder is held, the links the key's entries admitted are **neither narrowed nor closed**: the person still syncs the other folder. Two things change on them. (a) The inviter sends a `Departure` for the marks **of that folder** on every link a grant admitted for the key. (b) From the next packet the grant name filter carries, **besides the live entries' names** (§8.7 rule 10), the names of **every mark of the key in force**, judged per packet like rule 5's: `departure_carries(record, name)` and the key and certificate names under the folder's namespace and the record's signer. So the person's device learns it was let go of that folder and fetches the record over the link that stays. The link's direction and rates are the grant link's, not the narrow link's; **the person's push scope is not widened** (what the peer may push is §8.7 rule 5's, and no mark enters it). Nothing here closes the link: no `hold`, no `settle`, no `let-go` close, and nothing counts toward `attempts`. The added names last as long as the mark (`until`; a new entry of that key and folder removes the mark) and are bounded by `marks_max` and, per link, by the Departure caps (16 told, 32 taken). If the key's last entry later ends by a record, the link narrows (rule 3) and every mark is told again (a repeat is no news, §5.9).
11. **A person who was away is told when they return.** When a link **a grant admitted** for the key (a full link: not a departure link, not an introduction or enrollment link, not a direct path) is **registered**, the inviter sends it a `Departure` for **every mark of the key in force** (the marks of rule 10, at registration instead of at the end of an entry). An entry may have ended by a record while the person was away and another entry of the key stood: nothing was narrowed and nobody was told then, and the person would keep walking the folder the inviter no longer serves. The link carries the marks' names from its first packet (rule 10 (b)), so the person's device fetches the record over the link it returned on. A mark that a grant replaced is gone (§8.7 rule 1), so a folder the person was invited into again is not told. **Told by text only, left as it is:** an entry that ends by its **date**, and a host's `revoke_grants` / `LinkHints::end_grant`, leave no mark (no held record left the person out, and the host says no departure is told); the link closes with the `grant-ended` text (§8.7 rule 6) and a later dial's refusal carries it, which is all the person has to act on (ask the inviter to invite them again). A host that does not forward `Host::departure` to `LinkHints::depart` has no mark to tell, and a plain close is all the person gets.
12. **Who may tell a person of a departure.** The person's side accepts a `Departure` (§5.9) only from a peer whose **authenticated device lies under the namespace of the folder the message names** (rule 6), only on a full link, never on an enrollment, introduction or departure link and never on a direct path. The sink is handed that device; the invitations check it again (invite.md §11 rule 15). A refusal never touches the device's one fetch in flight per folder or its bound of takes a minute.
13. **A mirror entry makes no departure mark.** An entry of the mirror grant (§8.7 rule 16) never makes or carries a departure mark: `Host::departure` is not called when it ends (by a record that leaves this device out, or by the host), `Links::depart` is not given one for it, and its end closes the links it admitted as §8.7 rule 6 says for an entry with no mark (0x19, `grant-ended`). The person who is let go is told **by the inviter**, as before (rules 1–12): when the owner's record leaves the mirror's holder out, the owner's mark, narrow link and `Departure` reach the holder, whose own mirror entry ends because the record leaves it out. The mirror only admits the inviter's own link to its holder, and the holder does not sign the folder's members records and lets no one go of it; a mark exists so that a person who cannot hold the record can fetch it, and the owner needs none. A mutual invitation (§8.7 rule 17) is two entries of two folders, and each end makes the marks of its own inviter entries alone.

### 8.9 Conformance cases: the mirror grant and the joiner's routes

ndn-ext `crates/faces/ndn-link/tests/joiner.rs` (real QUIC, no FIB entry made by a test; the test's engine records what `FaceSink::add_routes` was given): at link level, `the_route_is_installed_over_the_inviters_identified_link_and_over_no_other`, `a_device_that_only_claims_the_owners_namespace_gets_no_route`, `an_enrollment_link_gets_none`, `an_introduction_link_gets_none_and_the_full_link_made_again_gets_them`, `a_route_the_set_drops_is_removed_and_the_same_set_again_changes_nothing`, `the_set_is_bounded_and_the_same_writer_in_two_folders_is_one_route`, `the_routes_go_with_the_link_and_return_when_it_is_up_again`, `a_reader_is_routed_the_writers_namespaces_and_what_it_pushes_stays_dropped` and `only_a_writer_entry_is_routed_the_sync_groups` (rule 18 items 1–8; the last fails first with `a reader entry was routed the writer's sync group` when `push` is ignored, and with `/c's sync group was not routed over the inviter's link` when the group is never routed); with real data-layer devices, **G11** (`g11_bob_is_routed_carols_namespace_and_reads_carol_through_ann` and, by name through the engine, `g11_bob_fetches_carols_context_by_name_through_the_joiners_route_and_anns`, each clean and in a `g11_faulty_…` form under `--features fault-injection`: Ann invites Bob and, by a second invitation, Carol; Carol writes; Bob's forwarder has the routes the device derived, and nothing else, and Bob reads Carol through Ann; the by-name case found the two things rule 18 item 1 and rule 19 say: with a route at `<W>` only, `not within 60s: bob reads carol's note`, and with no public-name routes on Ann's grant link, `not within 60s: ann routes carol's trust context toward carol`, the host's log carrying `this forwarder has no route for /user/…/keyword=trust-context/v=1` on every attempt), `bobs_route_goes_with_his_link_and_returns_when_it_is_up_again`, `a_link_of_another_key_gets_no_route` (a second device of the owner's person, admitted by a grant, is the strictest form of another key the harness can make), `a_reader_joiner_is_routed_the_namespace_and_not_the_group_until_a_record_promotes_it` (Bob's own FIB: `a reader was routed the writer's sync group` when the group is always routed; Ann promotes and demotes him by members records and the group follows) and `a_restarted_joiner_is_routed_from_its_device_when_the_link_is_up`. Rule 19: in `src/routes.rs`, `a_grant_link_routes_the_public_names_of_its_namespaces_outside_the_devices` and `only_the_granted_namespaces_of_a_grant_link_are_routed_by_public_names` (a policy-admitted, served or unlisted case gets none; each fails if one of the three prefixes is dropped, as equality on the whole list), and the expectations of `tests/grant_rules.rs` (`a_grant_links_its_key_in_its_namespace_and_routes_nothing_else_it_shows`) updated to them.

`tests/mirror.rs` (real QUIC, real devices over `DeviceMemory`; each device on a loopback address of its own, so one can move with the same keys, store and port; also under the fault profile): **F4**, clean and faulty (`after_the_laptop_moved_and_the_joiner_restarted_her_redial_is_admitted_and_his_memory_follows`, `…_the_same_on_a_faulty_network`: Ann's address changes and Bob restarts; Ann's redial is admitted by Bob's mirror grant as a grant link for her folder only; Bob's record is `[new IP:port, old IP:port]` with the same port; Bob restarts again with Ann's record forgotten from memory and dials the new address; words cross both ways), `the_source_port_of_a_link_the_peer_opened_is_never_recorded`, `a_key_that_is_not_remembered_and_holds_no_grant_stays_refused`, `a_peer_whose_entry_ended_by_a_record_is_refused_and_changes_no_record`, `a_peer_whose_entry_the_host_ended_is_refused_and_changes_no_record`, `a_mirror_grant_of_one_folder_does_not_carry_the_names_of_another`, `a_link_another_key_opened_changes_only_that_keys_record` and `mutual_invitations_keep_both_entries_and_the_link_closes_with_the_last`. **F3** (the port changed) is `tests/online.rs` and `tests/memory.rs`, unchanged. The memory units are in §17C.7.

ndn-rs `ndn-invite` (`grants_tests`, `mirror_tests`, `surface_tests` in `crates/app/ndn-invite/src`): the mirror note reads back as written and not under another key, and an inviter's note does not read as a mirror nor the reverse (labels of their own); a join keeps the mirror, lists it in `Invites::grants()` undated and tells the host once; the role is the inviter's in the fold and the host is told again when it changes; the entry ends, with no departure, when the members leave the device out, and the host is told before it is durable; the host ends it (`end_grant`, `end_grant_in`) and a second join replaces it; no note is kept without the space or for a space the inviter does not own; two entries of one inviter end one by one; mutual invitations are entries of different spaces; `joined_folders` lists the other writers and never the device's own names, is bounded and sorted, and `joined_changes` fires when the list changes and only then. ndn-sim `crates/ndn-data-conformance/src/cases/` (the conformance suite of heap.md §13.5, run clean and `--faulty`): `i22_joiners_list_follows_the_record.rs` (Bob's `joined_folders` lists the inviter, owner, his role and Carol's namespace alone as the other writers; Bob reads Carol through Ann; `joined_changes` moves with each change of the list and never repeats; an entry that leaves Carol out drops her), `i23_joiner_holds_a_grant_for_the_inviter.rs` (the host is told one grant per folder for the inviter's key with her role as the fold gives it, told again when a change demotes her, `revoke_grant` once when a change leaves the joiner out, no departure ever, and the grants stand after a restart) and `i24_mutual_invitations_two_folders.rs` (each device holds an inviter entry and a mirror entry for the one peer key; a change ends the mirror and the inviter entry of one folder and only those; `end_grant_in` of one folder leaves the other's entry).

## 9. NDN packets: datagram framing

1. NDN packets MUST travel in QUIC DATAGRAM frames ([RFC 9221]). Each datagram payload is exactly one NDNLPv2 frame: one LpPacket (0x64) TLV. No stream carries NDN packets, so there is no head-of-line blocking.
2. **Sending.**
   - A packet whose length + 4 ≤ the connection's current maximum datagram payload goes out as `LpPacket { Fragment(0x50) = packet }`. Other LP headers (for example a Nack 0x0320) come before the Fragment, in increasing TLV-TYPE order, per NDNLPv2.
   - A larger packet is fragmented per NDNLPv2:
     - every fragment carries Sequence (0x51, an 8-byte NonNegativeInteger), FragIndex (0x52) and FragCount (0x53);
     - Sequences are consecutive within a packet (`Sequence − FragIndex` is the same for every fragment) and unique on the link;
     - ndn-rs sizes each fragment's payload as `max_datagram − 50` (minus 10 bytes per piggybacked Ack).
   - The maximum datagram payload is the QUIC connection's current value, which grows as path MTU discovery finds room. If the QUIC stack cannot report it, ndn-rs uses 1100 bytes (`DATAGRAM_FLOOR`).
   - **The bound of the search (ndn-rs: `LinkTransportConfig::path_mtu_max`).** Path-MTU discovery probes upward from the 1,200 octets every QUIC path carries and settles on what the path acknowledges, up to a bound that ndn-rs sets to **9,000** octets of UDP payload (8,962 of datagram) by default. The bound is not a size: an Ethernet path still ends near 1,452 octets of payload (1,414 of datagram: 1,500 less the IPv6 and UDP headers), a jumbo-frame LAN near 9,000, and loopback or a same-host path at the bound, where a link carries 2.9 times the 1 KiB datagrams and 2.4 times the 8 KiB stream messages a second that it does at 1,452. A bound above the path costs about a dozen probes. The default was 1,452 (quinn's own bound) until the cost of 9,000 was measured: 200 idle loopback links held 17 KB more resident memory per connection at 9,000 than at 1,452 (90 KB against 73 KB, both ends of the link in one process, median of three runs), and after a burst of channel datagrams and a 1 MiB stream on each, 206 KB more (1.74 MB against 1.53 MB). The rule was that a default costing more than about 1 MiB more per connection stays at 1,452; this one costs a fifth of that. A host that wants the old behaviour sets `path_mtu_max` to 1,452. The bound also fixes the endpoint's UDP receive buffer (64 GRO segments of 32 packets of the bound: 18 MB, zeroed and not resident until used), one per socket and not per link.
   - **The first congestion window follows the bound (ndn-rs).** The QUIC stack ndn-rs uses sends nothing while the bytes in flight plus one datagram of the connection's current size reach the congestion window, and that includes the CONNECTION_CLOSE that carries a refusal. Its initial window of 14,720 octets leaves no room beside a discovery probe of 8,000 octets in flight, and with the bound at 9,000 a link refused soon after its handshake lost its refusal: the dialer read a stateless reset ("reset by peer") instead of the reason, in about one run in two of the refusal tests of `ndn-link` (none at 1,452). ndn-rs therefore starts a connection's window at four datagrams of the bound when that is more than 14,720 (36,000 octets at 9,000); a bound of 1,452 or less keeps 14,720. The cost: a link on an Ethernet path under the default bound starts with a window 2.4 times quinn's own, before its first loss or acknowledgements adjust it (the stack paces what it sends).
   - If the path shrinks between framing and sending, the oversized frame is dropped, as on any datagram link.
3. **Reliability.**
   - ndn-rs fragments always carry a TxSequence (0x0348), and ndn-rs retransmits unacknowledged fragments.
   - A link **frames reliability** when every frame it sends carries a TxSequence. The retransmit tuning is `ReliabilityConfig::ethernet()`: QUIC-style RTO (333 ms before the first sample, 1 ms floor), 1 retry, 256 unacknowledged frames. What it adds to the fragments' protection is the packets that fit one frame (every Interest, a small Data, a Nack), and a repair within one retransmit tick (50 ms) where the fragments alone wait for the RFC 6298 RTO (200 ms floor, 1 s before the first sample), which is past the data layer's first re-expression (250 ms).
   - A receiver SHOULD acknowledge each TxSequence it receives with Ack (0x0344) headers, either piggybacked or in an Ack-only LpPacket, **whether or not it frames reliability itself**. It MUST tolerate retransmitted duplicates. ndn-rs drops a duplicate before reassembly and forwarding. Reliability is therefore a choice of each sender: the two ends of a link need no agreement, and a peer that frames none is acknowledged and works.
   - **Which links frame it (ndn-link, round 12).** `LinkSetup::reliability` (`LinkReliability`) has one switch per way a link is made; **every one is on by default**. A link is of the kind that made it, at each end for what that end sends:
     - `introduced`: the link a device dialled by the key and addresses of a code's hint (`dial_by_key`), including the link a first contact became when it was made again, and the introduction link (§8.6) the inviter took from a stranger.
     - `first_contact`: the link dialled with no key to expect (`dial_first`, §13.3A), until it is made again. A kind of its own so that a host can switch it off alone.
     - `granted`: the link a grant admitted (§8.7), at the device that granted it.
     - `remembered`: the link a memory redial made (§17C), at the device that dialled it, and the link of a remembered peer that dialled in.
     - A **configured** peer is as its entry says: `[[peer]] reliability` (`PeerSpec::reliability`, off unless set) is the explicit setting and is kept; it can turn a link on, and the kinds' switches do not turn a configured link off. A direct path (§14) and a punched link are of the kind of the device's own link.
   - **Why on for these.** They are the links a join and a joined folder's transfers cross, and a frame the path loses costs a piece a whole re-expression timer where the link layer repairs it in a round trip: over a link that loses 1 frame in 10 on arrival, a 1 MiB transfer (256 pieces of 4096 bytes, 32 in flight) needed 23–32 re-expressions with the kind off and 2–4 with it on (the residue is a frame whose one retransmission was lost too), over a link dialled by key and over a grant link alike (`tests/reliability.rs`, `lossy::`). The cost is per-frame state and an Ack: ladder rungs 3c → 3d (a configured peer with and without it, ndn-ext `examples/ladder.rs`, baseline of round 12) measured +0.17 ms at 1 KiB (0.260 → 0.429 ms p50), +0.19 ms at 16 KiB and +0.20 ms at 1 MiB; ndf measured +0.36 ms at 1 KiB. No cheaper fix was found or tried.
   - **What an unidentified peer can make a device hold** (the security question of reliability on links of strangers). It is bounded by the layer, not by the peer: a link keeps at most `max_unacked` (256) sent frames, the oldest dropped first (`unacked_evictions`); resends each at most `max_retries` (1) times, at most `max_retx_per_tick` (8) per 50 ms; so a peer that never acknowledges holds the sender at 256 frames and is sent each frame twice at most. The receiving side's state (Acks owed, TxSequences seen, aged out after two RTOs) is kept whatever the setting, because a receiver always acknowledges: the setting adds nothing a peer can grow. No frame is read before the link is admitted (§7, the key is checked and the slots and quotas taken first). An introduction link is further bounded by its slots (§8.4) and a grant link by its grant.
   - **Not a kind**, so as before (`PeerSpec::reliability` only): a device the serving policy admits with no entry of its own (§15.2) and a relay's link, advertised or added. The one place the per-link bound multiplies is a relay serving strangers under `Open` or `Listed`: `Quotas::links_total` (256 by default) × 256 frames × one datagram (about 1.2–1.4 KiB on an Ethernet path; a frame is at most the connection's datagram size, so up to 8,962 octets on a jumbo-frame or same-host path under the default `path_mtu_max`, §9 item 2) is about 90 MB at the worst on Ethernet, which a relay's operator chooses by entry, not by default.
4. **Receiving.** A receiver MUST accept LpPackets with or without TxSequence, Sequence, FragIndex and FragCount, and MUST reassemble fragments keyed by `Sequence − FragIndex`. It SHOULD also accept a datagram that is a bare Interest or Data TLV; the enrollment-link scope does.
5. Other NDNLPv2 fields follow the ndn-rs NDNLPv2 implementation for non-local faces. Examples are Nack 0x0320 / NackReason 0x0321, PitToken 0x62, and CongestionMark. A link face is a non-local face, so it never carries LocalFields.
6. **Trust.** A link face is a **validated** face whatever its remote address, a peer on the same host (a loopback address) included: the forwarder validates the Data that arrives on it and caches only Data that passed (trust-context.md §6.6). A link is never a program face; a program of the same host that wants the program standing uses a Unix socket or shared memory. Threat: any process of any user on the host can open a loopback link, so what comes over it is no more believed than what a stranger sends. A served namespace carried in transit (§15.7) stays unvalidated and uncached, as before.
7. **Channel frames.** A *channel frame* is not an NDN packet: its first octet is `0x00` (the **marker**). TLV-TYPE 0 is not assigned, so no Interest, Data, Nack or LpPacket starts with it and no NDN decoder accepts it: **a datagram whose first octet is 0x00 is a channel frame, never NDN.** Between two devices whose hellos both carried `ChannelCaps` bit 0 (§5.2), on a link this side's admission carries (item 8):
   - **Datagram carrier.** A channel frame is the payload of one DATAGRAM frame, at most the connection's current maximum datagram payload (item 2). A longer one is refused by its sender, never fragmented (ndn-rs: `SideRefused::TooLarge`, naming the limit now); a writer cuts its frames to the limit the face reports (`side_frame_max`). A frame that does not start with the marker (an NDN packet, or no octet at all) is no channel frame, and its sender refuses it before anything moves, on either carrier (ndn-rs: `SideRefused::Malformed`, saying that a side frame starts with 0x00 and an NDN packet goes on the face as an Interest or Data), so no NDN packet takes this path or goes unjudged by the scope. A receiver that reads a datagram starting with 0x00 returns it unchanged to its caller **before** the link's scope, rate limits and NDNLPv2 reliability see it: it is no LpPacket, owes no Ack, takes no token of the scope's buckets and is never answered with a Nack (a Nack answers an Interest). On a link that does not carry channel frames, or whose peer did not advertise them, the datagram is dropped and counted (`refused`) and the link stays up.
   - **Headroom rule.** A sender hands a channel datagram to QUIC only while fewer than the *headroom* octets of datagrams wait in the connection's send buffer (`queued` = the buffer's size less the room the library says it has left, less what it says is taken while nothing is queued, read when the link comes up: quinn-proto 0.11.16 counts payload only, so that is 0, and 0.11.19 counts 32 octets for each queued datagram and keeps 32 in reserve, so an idle link has 32 octets less room and reads `queued` 0 all the same; the buffer is quinn's own 1 MiB, `DATAGRAM_SEND_BUFFER`). The headroom is **about a millisecond of the connection's send rate**: the octets the connection sent in the last windows, smoothed, over 1 ms, never under `QUEUE_FLOOR` = 128 KiB (a millisecond at 1 Gbit/s, so a link at that rate or slower, or one that has sent nothing yet, has exactly 128 KiB) and never over `QUEUE_CAP` = 512 KiB (half the buffer, so room for NDN datagrams is always left). A channel frame therefore waits behind about a millisecond of NDN traffic whatever the rate, and it never makes the stack drop an older NDN datagram to find room. The rate is read from the connection's own counters of octets sent (`udp_tx.bytes`), at most once per millisecond and once per 16 channel datagrams, over a window of at least 1 ms, and smoothed (a 20 ms window replaces the estimate, a shorter one moves it by its share); never per message. A non-blocking sender (`forward_side`) refuses the frame over the headroom (`Full`, counted `sink_full`); a blocking one (`send_side`) yields to the runtime and looks again, then every millisecond. The floor is one GSO batch of the link socket doubled: 64 KiB, one batch, left the driver an empty queue between batches and cost a saturating 1 KiB publisher 8 % against raw datagrams. The cap is what a fast link needs for the same reason: at a `path_mtu_max` of 9,000 (the default) a fixed 128 KiB moved about two batches per driver poll against sixteen for raw datagrams, and cost the same publisher 15 %.
   - **Stream carrier.** One unidirectional stream per direction, opened by its sender on its first stream-class frame (it waits for the peer to grant it, §3.1 item 6), carries records `length (4 octets, big-endian) | frame`. A frame starts with 0x00 and has at least one and at most 1 MiB (`STREAM_FRAME_MAX`) octets; it is delivered to the face's reader in order, unchanged. A reader that finds a record of no octets, or one that does not start with 0x00, counts it `dropped_malformed`, stops the stream (STOP_SENDING) and grants no other: the link stays up. A record longer than 1 MiB is more than this side granted: it closes the link with 0x15 (Protocol), counted too. A write blocks on the stream's flow control (counted `stream_blocked`); the non-blocking path queues at most 4 MiB (`STREAM_QUEUE_MAX`) in front of the stream's writer and refuses `Full` past it, and frames written in the same write as an earlier one are counted `coalesced`. A stream that ended or was stopped is not opened again on that link. A reader holds at most 4 MiB of received frames for its caller; past it the stream is not read and QUIC flow control slows the peer. No frame that does not start with 0x00 is ever written to it.
   - **The stream's grant and its end.** A side grants its peer exactly one stream, and **no credit for another**: it sets the peer's limit to 0 again when it takes the peer's stream, so when that stream finishes or is reset QUIC hands the peer no credit for a second (a second would only let the peer buffer a flow-control window of octets nobody reads). A sender that opened no stream because the peer granted none (the hello says the capability, not the peer's policy, so a peer whose policy does not carry never grants) waits **10 s** (`STREAM_GRANT_WAIT`, a resource bound, not a judgement: whether a stream is granted is the peer's frame) and then gives the channel stream of that link up for good: that send and every later one is refused with a sentence saying the peer granted no stream, what was queued for it is dropped, datagrams and NDN are unaffected, and the stream lock is not held past the bound.
   - **One connection.** Both carriers use the link's own QUIC connection, its keep-alive and its one congestion controller; a channel opens no socket, no second connection and no extra reader of the connection's datagrams (the face's own reader returns channel frames like any frame). The host sees a link only as a face: no connection, key, address or `FaceId`-to-connection map is exported.
   - **Room, read without the frame, and for it.** The headroom rule's read is also exposed without a frame (ndn-rs: `Transport::side_room`, `LinkFace::side_room`): the datagram class is *room* while fewer octets wait than the headroom, the stream class while the stream's queue is under `STREAM_QUEUE_MAX`. `LinkFace::side_room_for(frame, class)` reads it for a frame in hand: the same, and the stream class only while the queue holds **this frame** under `STREAM_QUEUE_MAX`, and, where the link has a quota (§9 item 9), only while the quota's bucket holds the frame (`FairMember::would_admit`, which takes nothing and marks no activity; a member that is alone always has room). A forwarder uses it for a frame its own node hands over (channel.md §14.4): when no sink has room it refuses the frame `Full` to the node, which keeps it, instead of handing it to the link to be refused there (`sink_full` or `dropped_over_quota`, lost); the node holds back a datagram's messages (they coalesce) and a stream frame itself (it waits for room), so a `Reliable` frame is not dropped at the first hop. Room is a hint, not a reservation: a frame that finds the buffer full by the time it is sent is refused and counted as above. **What the hint does not count:** the datagram's own octets against the headroom (a queue under the headroom by less than the frame says room for it), and another sender's frame taken between the read and the send. A frame the hint said room for and the send refused is lost at that sink, counted `sink_full` and told to no one: the hold-back narrows that loss and does not close it (channel.md §14.4, §14.10). The forwarder's wait for room is a poll (channel.md §14.10), because a link has no notification when its room changes.
   - **What the frames are.** This section says how a frame travels; what is in it is [channel.md](channel.md): the 20-octet header and its seal, the messages and the 46-octet floor that keeps a NIC's padding off a frame (§11), the receiver's checks before any cryptography (§12), the sender's batching over the headroom rule above (§13), and the setup by signed NDN, `<device>/32=chan/<digest>`, that gives two devices a key (§3). A link judges none of it: it carries a frame to the face's reader unchanged, or refuses it for the reasons of this item and item 8.
   - **Where the frames go.** On the host the face's reader peels a frame that starts with the marker, before anything NDN, and hands it to the forwarder's **side table**, which routes it by the channel id in its first ten octets and copies it to the faces that asked for it ([channel.md](channel.md) §14). A frame is routed only if the link's face is the **source** of the route of its id (a route's one source is the face the session Data arrived on): **a frame from a face is bound to that face**, and a frame from any other face, or of an id no route holds, is dropped and counted by the forwarder (`wrong_source`, `unrouted`). The face is also what a receiver is told the frame came over, which is what a checkpoint's evidence names and what the receiver's forwarder bars (channel.md §14.7, §15.5).
8. **Which links carry channel frames.** Each side decides for the link it admits, with its scope (§7.3), as a policy (`ChannelPolicy { carry, quota }`). A link that is not carried sends no channel frame, grants its peer no stream and drops and counts the frames its peer sends, **without closing** the link:

   | Link | Channel frames |
   |---|---|
   | The peer is an `admin`, `member` or `node` of a namespace this device holds a certificate in, on a full link | carried, **no quota**: the link's congestion control decides |
   | The peer is a `guest` of that namespace (§15.3) | not carried (a guest is no member of a space) |
   | A grant link (§8.7) | carried, under the fair share of item 9; the asks of a channel to the devices of the folder's owner namespace (`<device>/32=chan/…`) are among the names the link carries (§8.7 rule 5) |
   | An enrollment link (§8.1), an introduction link (§8.6), a departure link (§8.8), a stranger a relay serves under quotas (§15.3), a peer admitted by its expected key alone (no certificate shown), a link dialled from an introduction code to a party that shows no certificate (§13.3) | not carried |
   | A device of another namespace this device serves without limits, or a relay of another namespace this device follows (§15.4) | carried as a forwarder: it routes frames of routes installed on it and judges none |

   **Carriage is judged live.** A policy's `carry` is not fixed at admission: a link whose scope narrows in place (§8.8: a grant's last entry ended, the departure link) stops carrying channel frames at the moment its scope narrows, by the same judgement (`Narrowing::when`, asked at every use, in the datagram path, the stream reader and the send check), in both directions. It sends none (`NotCarried`), drops and counts the datagrams its peer sends, stops reading the peer's stream (STOP_SENDING; the stream is not taken up again, datagrams follow the judgement) and drops what was queued for its own; the link stays up. So a person who has been let go of a folder has no channel on the link that carries the record of their going.

   **Identity lost, link kept.** The routes the forwarder holds over a link were installed under the channel authority the link's identities gave it. When a link loses an identity but stays (another membership still admits it), `Links` calls `FaceSink::side_remove_face(face)` for each face of the link, and the forwarder drops every route that has the face as its source or as a sink. Channel authority is link-wide and a route's id cannot be tied to a namespace, so **any** identity lost counts: that is the fail-closed reading, and rare. No channel frame then crosses the link on the strength of the lost identity. A receiver behind the link asks again, and the new session Data installs the routes the link's remaining identities allow. A face that ends is removed from the table by the forwarder's own `remove_face`, which drops its routes too. A host whose forwarder has no side table keeps the method's default, which does nothing.

9. **The quota is a fair share, and work-conserving.** The bytes a link carries each way as channel frames are held to a **fair share** of a pool when its policy has one, never to a fixed ceiling per member and never to one for a member alone (ndn-rs `FairShare { capacity, floor, interval }`, in `ndn-face-quic`). `active` is the number of the namespace's links that passed, or tried to pass, a channel frame in the last `interval` (1 s), or joined in it; the rule has two cases, each direction apart:

   - **A lone active link takes no bucket.** With one link active every frame is admitted (Tx and Rx alike), so nothing but the link's own bounds holds it: QUIC congestion control and flow control, the datagram headroom rule, `STREAM_QUEUE_MAX` and `STREAM_FRAME_MAX` (item 7). The pool is not a ceiling on a link alone. (Before this rule the pool of `FAIR_CAPACITY` = 128 MiB/s was one: a lone member was held to it in each direction, which capped ordinary bulk transfer at 128 MiB/s per namespace and each way; the owner decided the quota is a fair share and must not cap a transfer, and the pool as a fixed ceiling was a defect against that.)
   - **Contending links each have a bucket.** With two or more active, link *i* has a token bucket per direction at `clamp(max(capacity, carried) / active, floor, max(capacity, carried))` bytes per second, burst one second's worth. `carried` is a decaying high-water mark of the bytes per second the pool's links were admitted in that direction: once per `interval` it becomes `max(0.9 · carried, measured)`, where `measured` is the bytes admitted in the window over its length. An interval in which links contended never raises it above the pool they divided (a burst out of full buckets is not counted) and holds it there while they took nine tenths of it or more; so only what a link carried while alone raises the pool, contention does not ratchet it, a pool the contenders use does not leak away, and an unused one decays to `capacity`. **`FAIR_CAPACITY` (128 MiB/s) is the least pool contenders divide**, not a ceiling; `floor` (`FAIR_FLOOR`, 256 KiB/s) is the least a contending link gets. A link that was alone is moved onto its bucket as soon as a second link becomes active (a link that was idle and passes a frame again, or that joins, triggers the recomputation at once, not at the next `interval`): its bucket is refilled to at most one burst of its new rate, so it keeps no free burst beyond its share.

   The two directions have buckets of their own and their own `carried`. Two active links get half of the pool each, and an idle link costs the others nothing. A frame longer than the burst waits for a full bucket and is then charged whole, so the average is the rate. Over its bucket a received datagram is dropped and counted (`dropped_over_quota`, and no Nack is sent); a received stream frame is not dropped (that would break the channel's order) but waited for, and QUIC's flow control slows the peer; a blocking sender waits for its tokens and a non-blocking one is refused `Full`, counted too. `FairMember::would_admit` reads the bucket without taking from it or marking the link active. The pool of a grant link's namespace is shared by its grant links on this device; its memory is `O(links)`. Replacing the grant link's `GRANT_BYTES` and `GRANT_ANSWERED` ceilings (§15.3), which bound NDN packets and not channel frames, by this rule is a later change.

   **What bounds what (the security posture of this rule).** *Before:* a granted link's channel bytes were bounded in each direction by its namespace's pool, 128 MiB/s for all of its grant links together on this device (a lone one included), plus the link's own bounds. *Now, a lone grantee:* the pool no longer bounds it; only the link's own bounds do (congestion control, flow control, the headroom rule, the stream queue bound, and on the receive side the 4 MiB held for the face's reader), the same bounds that hold an own link, which has no quota. *Contended grantees:* each is bounded at its share, `max(capacity, carried) / active` lifted to `floor`, and together they are bounded by `max(capacity, carried)` a second plus one burst each (and the floors, with very many links); `carried` is raised only by bytes a link carried alone, which the link's own bounds limited, so a flood cannot raise the pool it divides. *The owner's own traffic* (links with no quota: `admin`, `member` and `node` of the device's own namespaces on full links) is protected **structurally, not by weight**: an own link is never a member of a pool, so it is never charged to a pool, never refused for one and never counted in `active`; it is a separate QUIC connection with its own congestion controller, send buffer, headroom, stream queue and reader, and grant traffic cannot fill or consume any of them; the grant links' aggregate under contention is bounded by the pool above. **What that does not give:** no priority weight of own traffic over grant traffic (own links are not counted into the pool and the contenders' share is not reduced by them), so a lone grantee, or the contenders up to the pool, share the device's CPU, memory bandwidth and network interface with the own links under the connections' congestion controllers and the scheduler's fairness only; an operator who must guarantee the owner's traffic a rate sets it on the interface, not here. Unchanged: a refusal is counted (`dropped_over_quota`, §17A) and visible as before; `GRANT_FRAMES`, `GRANT_BYTES`, `GRANT_INTERESTS`, `GRANT_ANSWERED` and their namespace aggregates still bound the NDN packets of a grant link (§15.3).

   **Joining.** A link counts as active from the moment it joins, for one `interval`, and the pool's rates are recomputed then with it counted: its first burst is its share of the pool as it is now (not the rate left over from when fewer links were active), and links that join together share one second of the pool between them instead of one second each (`active` above also counts the links that joined in the last `interval`). A link that joins an otherwise idle pool is alone (no bucket) until another is active. **What the share is not.** It is per link, not per person: the link layer knows a device key and a certificate's device name at the quota, not a person, so a grantee with N links to this device holds N shares. And the floor is per active member, so with more than `max(capacity, carried) / floor` active links (512 at the defaults, with `carried` below `capacity`) the floors add up to more than the pool: the pool bounds the contenders' total up to that many active links, and beyond it the total is bounded by the number of links the relay admits, each at its floor.

## 10. Routes

When a link is up, the admitting side installs routes over its face. These are static origin, with flag CHILD-INHERIT and no expiry:

| Link | Routes (prefix, cost) |
|---|---|
| relay-side enrollment link | none |
| device-side enrollment link for `ns` | (`ns`, 0) |
| link path to a relay this device uses (§15.5) | the namespaces it routes over the relay (§15.5: the namespaces the relay is used for — for a relay its person added, every namespace it holds a certificate in, of its link key or of a membership; for one a namespace advertises, each of its namespaces whose trust context advertises that relay — then every namespace it follows) at cost *r*, the relay's rank (§15.6), then the relay's own default routes at *r* (its device name, or its namespace for a `node` this side dials: an Interest whose ForwardingHint names the relay goes over the link, §15.5) — or, when the relay's entry has `routes`, its default routes (those `routes`) at *r* alone; plus, for every `[[peer]]` X whose `relay` names it, X's default routes at *r* + `VIA_RELAY_COST`; plus the issuer routes and the group routes at *r*. The namespaces it routes follow what the device follows while the link path is up (§15.5) |
| other full link | the peer's *default routes* at cost 0, plus, for every `[[peer]]` X whose `relay` names this link's peer entry, X's default routes at cost `VIA_RELAY_COST` = 10; plus the issuer routes and the group routes at cost 0 |

**Default routes** of the peer entry P (if any), given the identities the link was admitted by (if any, §7.3), are the first of these that applies:

1. P's `routes`, if configured;
2. for each identity: `/<ns>` of the identity, if it is a `node` device and P is a peer this side dials, meaning the host gives P at least one path candidate (§13.1); else its device name `/<ns>/<role>/<device>` (also for a served device, §15.2: the relay routes it by the name its certificate gives). The `node` rule holds whichever side dialed this link: when both dial, the duplicate-link rule keeps one link (§11), and both sides still route the same way. A `node` whose peer entry this side does not dial (it only accepts that node's links) is routed by its device name ([Decision 8](#20-decisions));
3. P's `unidentified_routes`, if configured and the peer was not identified (a peer dialed by key from a code's link hint, §13.3, or dialed with no key to expect, §13.3A: only the introduction's prefixes);
4. P's `device`, if the peer was not identified;
5. otherwise none.

A device admitted by its A certificate and its C membership is thus routed by both of its device names, and loses the routes of one when that membership is revoked (§12).

**Issuer routes** of a link are, for each served identity (§15.2), the key name `<identity>/KEY/<key-id>` of each certificate its hello showed (§7.1) that is not under its device name, once each. This side holds no trust context of a served namespace, so it neither validates nor caches that namespace's certificates; a consumer validating a served device's Data fetches the chain by name through it, and the device answers its own issuer certificates (the ones it keeps from its enrollment, or its CA's own). A held identity gets none: this side resolves a held namespace's chain itself. Issuer routes go with the link.

**Group routes** of a link are the sync group `<ns>/32=sync` ([heap.md](heap.md) §2.5, §7.9) of each namespace an identity of the link was admitted in (§7.3), once each: a namespace this side holds, and a namespace it serves without holding it (§15.2). The forwarder runs each such group with the multicast strategy: the trust-context library does for a held namespace; the host does for a served one while it is in transit (§15.7). A group route goes with the link's other routes: when the link ends, or when a revocation takes the last identity in its namespace from the link (§12).

**Followed group routes** of a full link, beside the group routes above: each space group `<owner>/32=sync/<space>` the peer's hello says it follows (§5.10), **exactly as named**, once each, at the link's cost, unless the link routes that prefix already. The route is the named group's alone: not the owner's whole group `<owner>/32=sync` and not another space of the owner, which the claim does not name (a hello that names either is malformed, §5.10). They are added for a link whose peer an identity admitted (§7.3), and for no link of another kind: an enrollment, introduction or departure link gets no route, and a link admitted by a live grant entry carries the groups of its granted spaces only (§8.7 rule 20) and ignores the claim. They go with the link, like its other routes. A route is installed with CHILD_INHERIT as every route here is, so the forwarder gives the exact group the nexthops of the group routes above it (`<owner>/32=sync` of a namespace a served device is linked in) as well: the claimant is added to the group's recipients and none is taken from them. The forwarder runs the group with the multicast strategy while the namespace is in transit here (§15.7), or when this side holds the namespace (the trust-context library), by the longest-prefix match of `<owner>/32=sync`; for a namespace with no served device linked and none held, no strategy is run and none is needed: no device is there to hear a Sync Interest the claimant's route would carry. At most `FOLLOWS_MAX` = 32 routes a link ([§13.6](#136-follows-threat-notes)).

For a peer reached through a relay, the default routes are computed from that peer's own entry with no identity, so they are its `routes`, else its `device`.

A direct link to a peer costs 0. A route through a relay costs at least 10, so the direct link wins while it is up. A direct path (§14) gets the routes of a full link to its peer, computed the same way, on its own face; the relay's routes stay, so when the direct path ends its face and routes go and the relay carries the traffic again.

Besides the routes a link gets when it comes up, `ndn-link` installs:

- for a member a relay lists in presence, the member's device name over that relay's link face at `VIA_RELAY_COST`, taken away when the relay no longer lists it (§14.8);
- routes to the waiting face at `WAITING_COST` = 1000: the routes an on-demand link will get, while it is down (§16.3), and on a relay, the routes a sleeping device's link had (§17.2). Every link's routes cost less, so they win while a link is up.
- for a folder this device joined, the namespaces of the folder's other writers over the **full link of the folder's inviter**, and, for a writer-role joiner, each writer's sync group beside it, at `JOINED_ROUTE_COST` = `VIA_RELAY_COST` + 1000, taken away when the record no longer lists the writer, the entry ends or the link goes (the joiner's routes, §8.7 rule 18). They are routes of a path and never a right: the inviter's filter decides what crosses;
- for a link admitted by a live grant entry, for each held identity in a namespace the grant lists: the trust context's prefix (`rdr_prefix`), `<ns>/KEY` and `<ns>/CA/KEY`, at `JOINED_ROUTE_COST`, with the face (§8.7 rule 19).

## 11. Duplicate-link rule

Between two devices there is at most one link, keyed by the peer's fingerprint. A link has at most one path of each kind (§1): the rule below applies among paths of the same kind, so a direct path joins a link path to the same device instead of replacing it. Direct paths are always dialled by the device with the smaller fingerprint (§14.5), so two direct paths are always of the same direction and the newer stays.

When a link to a fingerprint is up and another link to the same fingerprint comes up, the side compares them:

- **Both sides dialed each other** (the two links have opposite directions on this side): the link **dialed by the device with the smaller fingerprint** (§3.3 order) stays. The other is closed with **0x01** (Replaced).
- **Same direction** (the peer dialed again after losing the old link, or this side redialed): the **newer** link stays and the older is closed with **0x01**.

A device does not run two dials of one fingerprint at once, because the two ends order two same-direction connections that come up together by what each registered first, and when the orders differ each end closes the connection the other keeps and the pair is left with no link. The dialling side takes a **turn** per fingerprint from the handshake's proof of the peer's key to the registration of its link: a second connection to that key (a peer entry that is kept dialled, a dial by key from a join or a hint) waits for the turn and, if the first's link is up when it gets it, is closed with **0x01** before its hello, so the device that accepted it never has the two to choose between; its dial answers as the dial of the link that stays does (`dial_by_key` returns `Ok` while the key is linked), and a kept peer entry holds that link. A dial that finds no link up when it gets the turn goes on and is the newer link as before.

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

### 13.3 Dialing by key: a code's link hint

A device that holds an introduction code whose link hint ([invite.md](invite.md) §6.1) names a device key and addresses dials the inviter's device by them: `Links::dial_by_key(key, device, addresses, within, routes)`.

1. It adds a peer entry `{key, device, unidentified_routes: routes}`: not persistent, direct paths off, whose only paths are the hint's addresses in the order given (at most `CANDIDATES_MAX` = 8; the rest are dropped). The addresses are **where to try and nothing more**: no address is trusted for anything. Nor is `device`: it is only what the code claims.
2. It starts a handshake to **every address at once**, each expecting `key` (§3.4: the handshake fails unless the listener presents exactly that key), from the host's link socket when it has that address family, else a dial-only socket (§13.1). The first handshake to succeed becomes the link and is admitted as a dialed peer entry's link (§7.3 rule 7: the key is expected); the other attempts are dropped. When no handshake succeeds within `within`, or admission refuses, the dial fails saying, per address, why; the peer entry is removed. An address whose device presents another key is no link.
3. While the device is unidentified the link routes only `routes` at cost 0 (§10): for a join, the introduction prefixes `<device>/32=intro` and `<device>/32=hint` (`LinkHints::dial`, `ndn_invite::introduction_prefixes`, invite.md §2.3), so Interests for the one exchange go over the link and no other name of `device` does. A code naming a device of a namespace this device already holds must not steer that namespace's Interests to whoever holds the key. **What the party may send in is bounded too** (a scope, §8.3): the link receives Data and Nacks only under `routes` (the answers to what this device asked) and Interests only under this device's own device names (the inviter fetches the joiner's seal key there); every other Interest the party sends is dropped and Nacked back to it, never handed to the forwarder, so it cannot reach this device's other links under this device's identity. This device sends Interests under `routes` and answers under its own device names, nothing else. The receive rate limit is `ENROLLMENT_ANSWERS` (burst 512, 128/s: a hint record, an offer and an answer arrive in fragments). The scope is the data of the peer entry: `unidentified_routes` names what is asked, this device's certificate names its own devices; it ends with the identification, when the link is made again.
4. **Made again once.** When this device adopts a trust context, each link to a device dialed by its key alone (no identity of it admitted) whose device name the keyring now covers is closed with **0x03** and dialed once more (§8.5), whatever enrollment verdict the party sent (the party chose it, and this dial was never for an enrollment): its hello is judged by what this side holds now, and the device is identified, so the link carries the identity's routes and the namespace's sync group (§10). The entry is removed once its link ends, and is not dialed again (§13.1: not persistent).
   **A device of a namespace this device holds shows a certificate of it when the link is made again.** On the link made again because this device now holds the namespace of `device`, a party whose hello shows no certificate this device holds is not that device: admission refuses it with **0x10** (`expected-device-unconfirmed`), saying that this device dialled `device` from an introduction code and holds its namespace, that the party shows none, that the link is closed and its routes removed, and to join again with a new code and check the address. It is not admitted again as an unidentified party with the introduction's routes. The first link of the dial is admitted unidentified as rule 3 says, and the join judges it by the hint record. A peer entry that carries no `unidentified_routes` (a host's own entry for a key) is not judged by this rule.
5. **Taken down when the join fails, or when the party is not the one the record names.** `Links::undial_by_key(key, why)`, called by the host when the join that dialled fails, or when the verified record names another key than the link's (invite.md §8.2 step 0, §8.3 S6 and S8, `Host::undial`), closes the link and removes the entry, but only if the entry is one `dial_by_key` (or `dial_first`, §13.3A) added and its link has shown **no certificate this device holds** (an enrollment verdict the party sent does not make it identified). A link that was up before the dial, or that has been identified since, is kept.

A dial sends only what every link sends: the handshake and the hello (§5). The secret of a code never passes through it: the secret travels only inside the sealed ask (invite.md §8.2, §4.1), over the link or any other path.

A device with no listening socket dials from a socket the system picks; a device that listens dials from its link socket, so the other device sees one address for it. Addresses to dial are bounded and tried once per join; a dial that fails leaves nothing behind.

### 13.3A Dialing a first contact: no key to expect

A **short** introduction code (invite.md §6.3) carries no link key: its first contact is one address, or a relay's name (which is no dial: the join's Interests go by that name through a relay this device already reaches). For the address, a joiner calls `Links::dial_first(device, addr, within, routes) -> Result<KeyFingerprint, LinkDetail>`, where `device` is the inviter's device name the code gives and `routes` the introduction prefixes of §13.3 rule 3 (`LinkHints::dial_first`, which the host's `Host::dial_first` forwards to, gives them and returns the 32 octets of the key). **The hello of a first contact is empty** (§5.2: no certificate, no membership), as a device-side enrollment link's is (§8.5): nothing of this device is shown to a party no key vouches for. This device's full hello is sent on the link made again once it holds the namespace of `device` (rule 4 of §13.3), to the party the join judged.

1. **Guards, before any datagram.** An offline device (§17D.1) makes no dial: the error is the `offline` detail. A device reaches **one** address: no race; the bound `CANDIDATES_MAX` of §13.3 is not reached by a short code's single first contact.
2. **The handshake expects no key** (§3.4): the dial accepts whichever key the party at `addr` proves, from the host's link socket when it has that address family, else a dial-only socket (§13.1), within `within`. When no handshake succeeds in that time the dial fails saying the address, and why; nothing was added.
3. **The proved key.** A key that is this device's own is refused: the connection is closed with **0x14** and the dial fails, no entry added. A key this device already links with is not linked twice: the connection is closed with **0x01** and the key is returned, the first link untouched.
4. **Then as §13.3.** The peer entry `{key: the proved key, device, unidentified_routes: routes}` is added — not persistent, direct paths off, its one path `addr` — and the link is established expecting that key, admitted as a dialed peer entry's link (§7.3 rule 7), with an **empty hello**. From here §13.3 rules 3, 4 and 5 hold unchanged: the link routes only `routes` at cost 0 and carries only what rule 3 says until the party shows a certificate this device holds, is made again once when this device adopts the namespace of `device` (with this device's full hello, then), is refused once that namespace is held and the party shows no certificate of it, and is taken down by `Links::undial_by_key(key, why)` with the key the dial returned. When admission or the exchange fails the entry is removed and the dial fails with the party's own words: a failed dial leaves no peer, route or link.
5. **Returns the key.** The key names the link and nothing more: it is no statement that the party is the inviter. The join fetches the hint record over this link and verifies it against the code (invite.md §8.3 S4–S6). When the record names this key the join goes on over this same link. **When it names another key, the join takes this link down at once** with `undial_by_key` for the key this dial returned — before the offer is fetched or the ask is sent, whether or not the record offers an address — and then dials the record's key (`Links::dial_by_key`, §13.3), else goes by relays, else by name; it never uses this link's routes. A join that fails after the dial takes this link down the same way, and a join that succeeds keeps it only when its key is the record's.

Threat notes:

- **A stranger answers.** Whoever holds the address is linked as an unidentified party: its link routes the introduction prefixes of `device` and no other name, whatever `device` claims, and whichever namespace the stranger itself shows certificates of (a test asserts the FIB, and that names outside the prefixes have no route and no answer). A device of a namespace this device already holds is not routed any of its names either. What it serves under those prefixes is verified by the invitations against the code (the anchor fingerprint, the signer, the offer) before anything is dialled or adopted.
- **The party at the address sees nothing of this device.** The hello of a first contact is empty (above): a hostile code, an address reassigned after the inviter moved, an address typo the checksum misses, and any party on the network path (no key is pinned) learn neither this device's certificate chain nor the namespaces it belongs to. The inviter needs none to answer: it gives an introduction link to a device with no certificate while an offer is open (§8.6), and the ask carries the joiner's credentials sealed to the inviter's seal key. An inviter that also admits enrollment links takes the empty hello for an enrollment link, and that link then carries the open offer's introduction too (§8.6). Namespace-level refusals (the device's namespace is this device's own or a held one of another anchor) are made by the invitations before the dial where the code names the namespace or the device name holds it (invite.md §8.1); only a short code's named-namespace judgement waits for the hint record (invite.md §8.3 S2, S5).
- **What the party sends in is bounded.** An Interest the party sends for a name outside this device's own device names is dropped at the link and Nacked, so a first contact cannot make this device's forwarder ask its other links for anything under this device's identity (rule 3 of §13.3; a test asserts an Interest for another name reaches no other face while one under the device's own name is delivered).
- **The link does not outlive a wrong party.** A party that relays the genuine hint record and blocks the record's key gets neither the offer fetch nor the ask (rule 5), and no link or route to it remains after the join, whether the record offers an address or not; a link made again to it once the namespace is held is refused (rule 4 of §13.3).

### 13.4 Grants: threat notes

A grant (§8.7) is host-supplied authority to *link*, not to read: the link carries only the names of the offered folder, of the person's own devices and of the introduction (§8.7 rule 10), and within those the layer's own gating (the folder's members record, the epoch keys) still decides what is answered. Before round 6 the link carried every name, so an unsealed collection of the inviter's namespace outside the folder, which the layer answers to whoever asks by name, was open to a person invited into one folder; that is closed at the link. Since round 7 a person holds **one entry per folder**, and what the link carries and what the person may push are judged **at every packet** against the entries live at that packet (§8.7 rules 5 and 10); the notes of the departure and of the co-writers' roots are §13.5. Since round 9 the person's own device holds the **mirror** of the grant (§8.7 rule 16) and routes the other writers' namespaces over the inviter's link (rule 18): the last four notes of this section are the mirror's, and the last two of §13.5 are the routes'.

- **No address, no name.** A grant is made for a key and consulted only against a key the handshake proved and a certificate that validates in a held namespace (offline, revocations and the namespace's link policy judged first, §7.1, §7.4). A stale or hostile address in a code's link hint (§13.3), a device name a code claims, or a name an Interest carries decides nothing: the worst such an address does is a failed dial.
- **One key, its namespaces.** A person's other keys are not granted: a stolen second device does not link. The same key showing another namespace than the granted one (a membership, §5.8) links for the granted one only, and its other memberships' routes, presence and sync groups are not added. A device of a namespace this side does not hold, whose chain ends in a root its own hello carries, is never served by a grant: nothing proves that root.
- **Never wider than the policy and the quotas.** A grant is consulted only where the policy declines the whole link, never under `open` (which already serves any held namespace, under quotas), and its links count against the quotas of the policy (or the defaults, §15.3): it cannot lift a quota, a revocation or a namespace's link policy. The reader's scope (§8.7 rule 5) is as narrow as the layer lets it be, not narrower: a reader's Interests, and the answers under its own device names; **a person's push scope is the union of the writer entries' carried names only**, so a folder in which the person only reads, however many, widens nothing, and a demotion takes effect at the next packet. The names a grant link carries are the union of the live entries' folders (rule 10): the person cannot use this device's forwarder to ask other peers' names either, and what stays public by the layer's model (the folder's sync group) is named there.
- **Ended grants close links, entry by entry.** An entry outliving the person's removal is ended by (a) the invitations' check on every held members entry, which revokes the entry **of that entry's space** ([invite.md](invite.md) §10 rule 7; the host's `revoke_grant(key, folder)` is called before the note is made durable), (b) its expiry, judged on this side's clock at every admission and by one task that wakes at the earliest `until` of any entry and at least once a minute while a dated entry is in force (a suspend or a clock step is seen within a minute), and (c) `revoke_grant` or, for the person, `revoke_grants`. **A link closes only when the key's last entry ends**, and an ended entry carries nothing from that instant (rule 10), so the folder that was ended is out at the next packet while another still syncs. A link whose handshake straddles the end is closed once it is registered (rule 11). A link whose only admission was the grant is closed with **0x19**, the sentence saying which entry ended last and what to do; a link another rule admits is not; when a record ended the last entry the link narrows to the departure first (§8.8, §13.5). A redial of a remembered peer that first dialled in carries the grants too (rule 12).
- **A leaked offer secret** gives the thief one use of the offer, and with it the grant for the thief's key and the person's namespace; the grant adds only the link, and ends with the membership.
- **The host that calls `Links::grant` is trusted** as it is for a `PeerSpec`: the key it names links. A host with a link key other than the device's key (§8.7 rule 8) calls it itself.
- **Memory is bounded.** The table holds the grants the host made, and the last 64 that ended (to name them in refusals); a refusal that names an ended grant says only what the grant's key already knows.
- **Can the inviter's link (the mirror grant, seen from the joiner) be used by a different key?** No. The entry holds one key, the digest of the key that signed the answer the join verified to belong to the offering device under the anchor the code named, and the link is admitted only when the handshake proves that key **and** an identity that validates in the inviter's namespace (§8.7 rule 3: by key and by namespace, both). Another key of the inviter's person gets nothing; a key that signed nothing the join verified has no entry; a key that holds none is refused and told how to get one (§8.7 rule 7). The MAC of the note keeps a writer of the store from adding an entry (the mirror note, below).
- **Can a hostile inviter use the mirror grant to make the joiner serve more than the folder?** No more than the folder, the public names and her own devices' names. The grant is for the inviter's own key and the folder; the link carries (§8.7 rule 16) the folder's names (live, from the joiner's own fold in force), the public names of the inviter's namespace and of the folder's other writers, and the names under the inviter's own devices; her pushes pass only under her own devices unless the fold lists her namespace as a writer. A hostile inviter who also **signs an entry** that lists other writers makes the joiner carry those writers' public names (trust context, key and certificate names, sync group) toward her: nothing of the joiner's own collections outside the folder. Two checks of the invitations bound what an *offer* can name. (a) `keep_mirror` keeps a note only when the folder lies **under the inviter's own namespace** (invite.md §11 rule 17): an offer that names a folder of the joiner's own namespace, whose fold lists the joiner, would otherwise grant the inviter a link into it; no note is kept, `join` still returns, and a warning says so and to join a folder of the inviter's namespace. (b) No note is kept, and a warning says to ask for a new offer, when the fold in force no longer lists this device's person. **The limit, stated plainly: a public space.** A public space (heap.md §6.1) has no epochs and anyone reads it, so an entry that no longer names this device as a writer does not end the entry there: it stands, as a reader's, while the fold lists the person (a sealed space's entry that leaves the person out of its audience ends it). Through it the folder's owner is carried the folder's names, and the layer answers a public space's entries by name to whoever asks anyway: the entry grants her no more than the reader's scope over her own link, and nothing outside the folder.
- **The mirror note.** It is MAC'd under a key derived (HKDF) from the device's recipient secret, which lives in the key store, with labels of its own (`ndn-invite/mirror-note/mac-key/1`, `…/mac/1`), so a mirror note is never read as an inviter's note nor the reverse; it is kept in the node's store under `/localhost/ndn-invite/` (invite.md §15), never served, never on the wire. A party who writes to the store and changes it makes it **unread** (a warning that says why and to join again with a new offer): the device then admits no one on its account. A party who plants one has no MAC. Rolling back to an older genuine copy cannot widen anything: the entry exists only while the fold in force lists this device's person, its role is re-derived from the fold at every judgement, and an ended entry that is rolled back is judged against the fold again. A party who can write the key store already holds the device (§17C.6).
- **Can an accepted link overwrite another peer's record?** No (§17C.6, §17C.2 rule 7). The record is keyed by the key the handshake proved; a link of another key makes or updates **that** key's record and no other; the address it brings is a hint, and a redial of it admits only the holder of the key.

### 13.5 The departure and the co-writers: threat notes

The departure (§8.8) gives a person who was let go one signed record, on a link that carries nothing else; the live co-writer names (§8.7 rule 13) let a member walk to the other writers; the joiner's routes (§8.7 rule 18) let the member's forwarder send the Interest at all. Each widens what a link carries or where this device sends, so each is bounded here.

- **The departure link as an oracle.** It answers one question: *fetch this record.* It is offered only to a key whose handshake proved the key, whose identity validates in a held namespace of the mark, and for which this device holds a mark; the marks come only from grant notes whose MAC checks (invite.md §11 rule 14), so **a key that never held a grant has no mark** and gets the refusal it got before (and the introduction link only while an offer is open). A key whose mark expired or was used up gets the refusal of a key whose grant ended with no mark, the same `grant-ended` text (§8.7 rule 7): the mark's existence is not told to a key that never had a note, and a key that had one already knows it was let go. The mark is looked up **by the key the handshake proved**, so a prober can ask only about its own key and learns of no one else's departure; this spec makes no claim of equal timing between the refusals. Nothing is learned from the link that the person did not know except the record's name, which `Departure` hands them. The record is signed data: the layer does not seal members entries (only a Put is sealed, heap.md §3.5, §6.4), so it carries the list of the space's writers and readers as that entry states it, which the person could read as a member until the entry removed them, and which the layer answers by name to whoever asks.
- **The departure link as a way back in.** It carries the record's entry, its pieces and its manifest nodes (a prefix of one log entry), and the key and certificate names of the folder's namespace and of the record's signer (so the record validates): **no sync group, no trust context, no other log entry, no other folder, no introduction; no route, no presence, no quota slot beyond the enrollment links' slots.** Interests only toward this device, answers only toward the peer, at the `ENROLLMENT_INTERESTS` rate. It is bounded in time (`hold`, 30 s), in attempts (`attempts` = 3 per key per mark), in marks (`marks_max` = 256, the oldest evicted) and by the mark's own expiry (`departure_for`, 7 days by default). A removed member who dials again until the mark expires gets at most `attempts` short links per mark; the counts live in memory and start again when this device restarts or the mark is replaced, so a removed member costs at most `attempts` links of at most `hold` seconds per mark and per restart of the inviter. A narrowed link whose key is granted again before it closes is widened by the new entry (the person was invited again), never by the mark.
- **A hostile inviter cannot make a person fetch an arbitrary name.** A `Departure` is a hint with no authority (§5.9): the person's sink takes it only for a space the person has open, told by a device of the space's owner namespace, a record that is a log entry of that space whose device lies under a namespace the person holds (invite.md §11 rule 15), and what is fetched is judged as any entry, by its signatures and its chain. A hint that is none of these is refused with a reason and logged. Hints are bounded per link (`DEPARTURES_MAX` = 16 folders told, `TAKEN_PER_LINK_MAX` = 32 taken over the link's life), one take of a folder is in flight, and the invitations begin at most six a minute. A hostile inviter can make a person fetch **a members entry of a space the person belongs to** from its own link, and nothing else. A person never needs the hint: the space is judged by the entries it holds, told or not.
- **Writers' names widening the grant.** The names added for each other writer are those of namespaces **the space's fold in force lists as writers of this folder**, derived at every packet with no cache: a writer the fold no longer lists is out at the next packet. They are the writer's namespace **sync group, trust context and key and certificate names**, and the seal keys and grant asks of her devices (§8.7 rules 10 and 13). A name of such a writer **outside the folder and outside these** (an entry of her other spaces, any other name under her namespace) stays refused. The sync group carries "device D moved" and no data, and the trust context and the key and certificate names are **public by design**, as a hello already carries the chain: they are what a member needs to validate the other writer's certificate. All are bounded to namespaces that the fold of this space lists as writers. A reader entry gets them as any person admitted to the folder does and gains no push scope.
- **Ann relays, bounded, between two grant links.** A grant link is routed by its person's device name and by the person's public names (§10, §8.7 rule 19), so Ann's forwarder has a route for Carol's device name, and for Carol's trust context and key and certificate names, over Carol's link. When Bob's forwarder routes Carol's namespace over his link to Ann (the joiner's route of §8.7 rule 18, which Bob's own link layer installs from Bob's own record in force; or a `[[peer]]` entry for Carol reached through Ann; Ann's grant installs no route on Bob's side), his Interest for a name of Carol's that his link carries (her log entries of the folder, public by the folder's rule) reaches Ann's forwarder and is forwarded to Carol's link, which carries it (names under her own device), and the Data comes back and is judged against Bob's entries again. So Ann **does** fetch for Bob, names under a writer's device name between two links; it is not the case that only what Ann's own device holds crosses. The relay is bounded: the names are the ones both links already carry (rule 10: never the writer's other collections, nor any name outside the folder and the public names of §8.7 rule 13), the Interests count against Bob's per-key and per-namespace receive rates and the Data against Carol's link's, every packet is judged against the entries and the members record live at that packet in both directions, so a writer the record drops loses her link, and her route with it, and a Data that returns for an Interest already pending is dropped at Bob's link when his entries no longer carry its name. It is a bounded relay, with no amplification beyond a fetch by a person the folder admits of what the folder's writers wrote.
- **Roles are the record's, per packet.** The role of an entry is re-derived from the members record in force and the link filters follow at the next packet: an inviter that demotes a writer drops the writer's push scope at once, with no close to race. A person who is a writer in one folder and a reader in another has the push scope of the first only.
- **No way to hold the link open.** A narrowed link is closed at `hold` whether or not the record crossed; a person who never asks for the record does not keep it, and the narrowed link carries no more than a fresh departure link would. A link that stays up for another entry (§8.8 rule 10) is the other entry's: the departure adds to it only the names of one signed record and the key and certificate names that validate it, for as long as the mark lives, and it takes no slot or rate and widens no push scope.
- **Can a writer of a folder make the joiner route a name it should not?** Only the inviter's fold names the routes, and a writer cannot change the fold: only the owner's devices sign a space's members entries (heap.md §5), and the device derives `writers` from the fold in force, whose entries it verified. But the owner (Ann) can list any writer namespace, and **a route is not safe because its cost is high**: a forwarder takes the longest matching prefix first and uses cost only among routes of one prefix, so a route Ann's fold makes at a name wins the names under it over any shorter route of the joiner's. Round 9's first filter (drop only the joiner's own namespace and what lies above or below it) let a record list `/com`, `/user`, `/localhop`, `/localhost` or `/dave/member`, and the joiner's Interests for those names would have gone to Ann's face and nowhere else (dropped at the joiner's own grant filter under the default `own` policy, or seen, dropped or answered by Ann under another). The device now lists a name only when it **names itself** and cannot take a name from a better route (§8.7 rule 18 item 3, invite.md §11 rule 18): not refused by `IntroPolicy::refuses` (the reserved names, the broad shared names, too few components), the namespace of a trust context held here or a self-certifying person's, and neither above nor below a namespace held here or adopted for a folder (except an exact match). So `/com`, `/user`, `/localhop`, `/localhost` and an unheld `/dave/member` are never routed, and nothing is routed that the joiner could not already validate by a context or a name it holds; the link layer adds, as defence in depth, that no prefix over, under or equal to `/localhost` or `/localhop` is routed, and that each inviter has an equal share of the bounds. The routes are installed only over the inviter's identified full link (§8.7 rule 18 item 4), at most 64 namespaces in all (each with its sync group for a writer-role joiner), and never over a link of another key, a served identity or a link made only to introduce. A route is a path and not a right: a reader-role joiner is routed `<W>` only and not the sync group (rule 18 item 2), and the inviter's filter still drops what a reader may not fetch or push. **The limit, stated plainly:** a hostile inviter can still list a writer that is a namespace the joiner holds (or a self-certifying person) and so make the joiner send Interests for it, and for the names under it, toward her; she can blackhole them, or answer with data the joiner validates by that namespace's own trust (held, so nothing she answers there is believed unless it verifies). She cannot divert the joiner's own names, a name no context of the joiner's covers, a reserved or broad name, or a name over or under a namespace the joiner holds, and she routes nothing the fold does not list.
- **The route installation as a trust surface.** It is the one place where the link layer writes into the forwarder's FIB on the strength of data it did not make. The data is the device's (signed records, verified, derived at every call from durable data and the MAC'd note, nothing cached); the link is the inviter's identified full link (handshake key, an identity of the owner's namespace validating in a held namespace); the prefixes are namespaces that name themselves and cannot take a name from a better route (rule 18 item 3; and, for a writer-role joiner, their sync groups), bounded (16 writers a folder, 64 namespaces, 16 folders, each inviter an equal share) and costed above every real path to the same prefix; a route a real path already makes is never overwritten (item 8); and a route is removed with the entry, with the record's writer and with the link, and logged at info (the face and the prefixes; the folders with their inviters and writers when they change). The forwarder is told while the link table is locked, which orders the routes after the face and never gives them to a face that is gone (item 7). The host that calls `Links::set_joined_routes` is trusted as it is for `Links::grant` (§13.4). The grant link's own routes for the person's public names (rule 19) are of the same kind and no wider: derived from a live entry and the identities that link was admitted by, only for held identities in a namespace the entry lists, never for a policy-admitted, served, enrollment, introduction or departure link, at the same cost, and gone with the face; they route only names that rule 10 already carries.

### 13.6 Follows: threat notes

A device that links to a relay tells it which space groups it follows (§5.10) and the relay routes exactly those groups over the link (§10). The claim is the claimant's word.

- **What a false claim gets.** The Sync Interests of the public groups it names, delivered to the claimant at the link's own rates: the claimant names `/x/32=sync/doc` and the relay routes `/x/32=sync/doc` toward it. Nothing else: no Data of the space (the layer's own gating decides what an Interest of its names is answered), no name outside the named groups, **no other space of `/x`** (the claim names the group of one space, never `/x/32=sync`, which every space of `/x` lies under, and a hello that names it is refused, §5.10), no trust context, no entry, no change of the link's scope, rates or quota (they are those of the identity that admitted it). The route is added only to a full link whose peer an identity admitted; an enrollment, introduction, departure or grant link takes none, and a grant link keeps the groups of its granted spaces only (§8.7 rule 20; the `routes_for` test `a_claim_of_following_routes_nothing_on_an_enrollment_departure_grant_or_unidentified_link`).
- **The privacy residual.** The group is public by design (§8.7 rule 10: the group carries no data; a Sync Interest names devices and counts), so a claimant hears the state vector of the space it names: the names of its devices and how many entries each wrote. A claim shows **no more than the claimant could ask for**: it names the exact group, so the claimant must already know the space's name (a group is `<owner>/32=sync/<space>`), and a claim cannot enumerate the owner's other spaces, private ones included, as a claim of the namespace's group did (a namespace's whole group was the prefix of every space of its owner: [Decision 43](#20-decisions)). **Space names are not secret and can be guessed and probed.** People choose them (`notes`, `photos`), and a claim costs a peer nothing the link does not already bound (`FOLLOWS_MAX` per link, the link's rates): an identified peer that names `<owner>/32=sync/notes` learns whether a space of that name exists and, if it does, hears its devices and how many entries each wrote, which is all the group says (no entry, no member list, no role, no Data). The layer does not hide that a space exists, who writes in it or how often from a peer that guesses its owner's name and the space's; an owner for whom that matters gives the space a name that cannot be guessed (a random component), and a probe of such a name finds nothing. It is what any device linked to a relay that carries the space already sees by sending an Interest there, and what the space's members announce to everyone. The claim tells the relay **which spaces this device follows**, which is why a device tells only a relay it uses (the route it needs) and a hello for enrollment, a first contact or a direct path names none.
- **Why no proof.** Following a space is knowing its name, and a space's group is public: a proof would prove nothing the claimant could not copy. A revocation of a device's membership in `/x` still takes `/x/32=sync` from the link (§12), even when the device also claimed a group of `/x`: the claimed group's route is the claim's, the namespace group's route the membership's, and the next link of that device claims the group again and gets, again, only that public group's Interests.
- **Cost, bounded.** At most `FOLLOWS_MAX` = 32 routes on its own link (the first 32 names are used and the rest ignored; each is a space group of at most `FOLLOW_DEPTH_MAX` = 13 components), none kept after the link. Across links the cost is 32 per link: under `open` with the default `links_total` = 256 (§15.3), at most 8,192 next hops, in entries shared by prefix. A device naming 32 groups is held to its link's frame and Interest buckets (§15.3: a stranger's `interests_per_key` is 100 a second, burst 200). A Sync Interest multicast to a claimant costs the relay one more copy of an Interest it already received over a bounded link, sent over the claimant's own link. The limits count spaces, not namespaces: a group is longer than a namespace by the keyword and the space's name, so the depth limit is the old namespace depth (8) plus 5, and the count was raised from 16 to 32 because a person follows several spaces of one owner where a namespace named them all with one name; a host that follows more spaces than that is refused when it gives them (§5.10), not truncated.
- **What the relay learns.** The space groups a device follows, told in its hello over the link's TLS. A device that wants none known follows nothing the relay carries, or uses no relay for it; the relay learns of no space the host does not name, and holding a namespace's trust context tells it nothing.

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

A candidate is a kind and a UDP address (§5.5 encoding). Kinds: 0 host (an interface address on the link socket's port; loopback and link-local skipped unless the host keeps them, for devices on one machine; a socket bound to one address offers that address), 1 reflexive (an address a full link's other side reports, §5.5, for the same socket), 2 advertised (configured, e.g. a port forward; ndn-fwd `[[face]] kind = "quic" advertise`), 3 mapped (a port-mapping protocol). A sender lists its candidates best first (next) and sends at most `CANDIDATES_MAX` = 8; a receiver uses at most 8 and ignores candidates of an unknown kind. The punch uses the socket of the link to the relay, so the reflexive candidate is the NAT mapping the relay saw.

**The order a device lists its candidates in.** A device lists its own candidates (what the punch signs, and what a link hint offers: `Links::hint_candidates`) best first, so that the first is one another computer can reach, and keeps at most `CANDIDATES_MAX` of the best. Each candidate has a rank; candidates of a rank keep the order they were gathered in (reflexive first, then each source's, a source's own addresses in the system's order):

| Rank | Candidates |
|---|---|
| 0 | a reflexive, advertised or mapped address, and a host address of an interface that is not one of the next: a global or private-LAN address of a physical interface, and of a tunnel (WireGuard, Tailscale: it reaches other computers) |
| 1 | a host address only of a bridge or container interface, which reaches this machine's guests: an interface whose name begins `docker`, `veth`, `br-`, `virbr`, `cni`, `flannel`, `cali`, `lxc`, `lxdbr`, `podman`, `vboxnet`, `vmnet`, `vmenet`, `bridge`, `kube-`, `cilium_` or `weave` (a plain `br0` is not: a host with bridged networking has its LAN address on it) |
| 2 | a loopback, link-local or unspecified address of any kind (kept only with `HostCandidates::include_local`, devices on one machine) |

Why: a short code carries one first contact, the first of this order whose line fits (invite.md §6.3), and a joiner that dials a loopback or a bridge address dials its own machine. The order is `candidates.rs`'s, applied by `HostCandidates` to the interface addresses it lists and again by a device's gathering to everything merged, so a source of another kind can list its addresses in any order. A host address is told to belong to a bridge or container interface by looking it up among the device's own interfaces at the time; an address no interface of the device has (a source's own) is rank 0 unless it is loopback or link-local.

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

ndn-rs reports per device (`Links::report`): its paths (kind `link`, `direct` or `relay` — the relay's link face —, face, remote address, RTT, age) and the direct-path state: `none`, `off`, `trying`, `up`, `not-possible` or `refused`, with a detail and when the next punch is due; for a configured device, its link mode and, when it is not linked, why (a detail); for a relay this device uses, its source, preference and state (`linked`, `trying`, `down`, `standby` or `off`, §15.6) with a detail; on a relay, for a device asleep here, how long, the Interests held for it, whether it asked to be held for and to be woken, and the wakes sent (§17). For the device itself: its key, the probes it sent, the punches it refused, its serving policy (a detail, §15.2), the Interests it holds for sleeping devices, and the wakes it sent.

Whatever the report says in words is a **detail** (`LinkDetail`, ndn-mgmt-wire): a stable code (`link_code`, catalogued with its parameters in [mgmt-trust.md, "Links"](mgmt-trust.md#links)), named parameters, a neutral default sentence and the details that sentence quotes (its causes, each cause's sentence verbatim in its parent's, in order). The library takes no host's words: its sentences name no host command or configuration key. A client words the codes it knows (`LinkDetail::render`; `LinkWords` gives a client's sentence for the six codes whose neutral sentence stands in for a host's peer entries, certificate renewal and expected keys) and shows the neutral sentence, its known causes worded in place, for the others. The sentence of a refusal is also the Reason Phrase this side closes with (§6.1), and the text of a punch refusal (§14.4): the other device gets the neutral sentence.

ndn-fwd serves this as the management dataset `/localhost/nfd/links/list` (local operators only), and `ndn-ctl link list` prints it ([reference/links.md](../wiki/src/reference/links.md)). Its TLVs are those of ndn-mgmt-wire `link_status` (`link_tlv`), all even and so skippable by an older decoder: 0x04A0–0x04BE for keys, paths and direct-path state, and

| TLV-TYPE | Field | In | Value |
|---|---|---|---|
| 0x04C0 | mode | LINK | `always`, `on-demand` or `off` |
| 0x04C2 | idle_secs | LINK, mode `on-demand` | NonNegativeInteger: the idle close (s) |
| 0x04C4 | relay | LINK | nested: the device is a relay this device uses |
| 0x04C6 | source | relay | `user` or `namespace:<namespace>` |
| 0x04C8 | preference | relay | NonNegativeInteger, lower preferred |
| 0x04CA | state | relay | `linked`, `trying`, `down`, `standby` or `off` |
| 0x04CE | asleep | LINK (relay side) | nested: the device is asleep here |
| 0x04D0 | since_secs | asleep | NonNegativeInteger (s) |
| 0x04D2 | held | asleep; top level | NonNegativeInteger: Interests held for that device; top level: `held_total`, for all |
| 0x04D4 | hold | asleep | empty: it asked for its Interests to be held |
| 0x04D6 | wake | asleep | empty: it registered a wake token |
| 0x04D8 | wakes | asleep; top level | NonNegativeInteger: wakes sent to that device; top level: `wakes_sent`, to all |
| 0x04E0 | code | detail | UTF-8: the detail's code |
| 0x04E2 | param | detail | nested, one per parameter: name (0x04E4), value (0x04E6), both UTF-8 |
| 0x04E8 | text | detail | UTF-8: the neutral sentence |
| 0x04EA | cause | detail | nested detail, one per cause, in the order their sentences appear |
| 0x04EC | direct | LINK | nested detail: why the direct path is in its state, and what to do if anything |
| 0x04EE | detail | relay | nested detail: why the relay is in its state |
| 0x04F0 | down | LINK | nested detail: why a configured device is not linked now |
| 0x04F2 | serve | top level | nested detail: this device's serving policy |
| 0x050C | fault_injection | top level | nested, optional: present exactly when the daemon was built with the test-only fault layer (§17B.6) |
| 0x050E | profile | fault_injection | UTF-8: the installed profile's text form; absent while no plan is installed |
| 0x0510 | met | fault_injection | NonNegativeInteger: packets that met the profile |
| 0x0512 | dropped | fault_injection | NonNegativeInteger: of those, dropped |
| 0x0514 | duplicated | fault_injection | NonNegativeInteger: of those, delivered twice |
| 0x0516 | forged | fault_injection | NonNegativeInteger: of those, Data packets forged |
| 0x0518 | delayed | fault_injection | NonNegativeInteger: of those, held back |
| 0x051A | passed | fault_injection | NonNegativeInteger: packets the plan's predicate left alone |
| 0x051C | predicate_panics | fault_injection | NonNegativeInteger: times the plan's predicate panicked |

A detail without a code is malformed. 0x04BC, 0x04CC, 0x04DA and 0x04DC carried sentences before details replaced them; they are retired and not reused.

Strings are UTF-8. The link commands, also for local operators only, name a configured link by its label (as `link list` shows it) in `ControlParameters` Uri, and change only the running daemon:

- `/localhost/nfd/links/connect` — `Links::connect`: the link is wanted now, whatever its mode, and dialled at once (§16.1);
- `/localhost/nfd/links/disconnect` — `Links::disconnect`: the link is no longer asked for; an `off` link closes now, an `on-demand` link once idle, an `always` link stays (set its mode to `off` to close it);
- `/localhost/nfd/links/mode` — `Links::set_mode`: the mode in `ControlParameters` LocalUri, `always`, `on-demand`, `on-demand:<idle seconds>` (10–86 400; without seconds the link's current idle time, else 60 s) or `off`.

A device that linked in without a peer entry has no mode and cannot be named by these commands. A command answers its detail as JSON in the ControlResponse status text (codes `linking`, `link-released`, `link-mode-set`); a refusal is a structured refusal (the `links` codes of [mgmt-trust.md](mgmt-trust.md#links)). Presentation is not normative.

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
- **`open`** (quotas): devices of any namespace whose hello chain ends in a self-signed root certificate that validates the device's certificate (§7.1 R1–R7), under the quotas of §15.3. The relay's own namespaces are never under quota. A device of a namespace the relay holds the trust context of but holds no certificate in is served too, checked as any device of that namespace (revocations, link policy, §7.1 steps 1–11) and under the quotas, the namespace bound to the held context's anchor with the smallest fingerprint (§15.3): holding a namespace's context is what an inviter does for the person it introduced (§8.6), and `open` must not stop serving a person once it follows them.

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
| `interests_per_key` | packets one served **stranger** sends over its link: a per-link bucket on received frames (§8.3) | the Interest is dropped with a **Congestion** Nack (bounded, §8.3 rule 7); other frames silently |
| `interests_per_namespace` | packets all served strangers of one root key send together: a bucket the links of that root share (§8.3) | the same |

The two rates count every received packet (Interests, Data and Nacks), as the scope's bucket does; Ack-only frames are free. Otherwise a served link under quotas is a full link: its scope carries Interests and answers in both directions with any name.

**The rate of a link is by its kind.** The link counts above (`links_total`, `links_per_namespace`) bind every served link, grant links included (§8.7 rule 4); the **rates** are these:

| Link | Frames, per link | Bytes, per link | The namespace's links together | Over it |
|---|---|---|---|---|
| a link of this device's **own** namespace (§7.3 rule 5), role `admin`, `member` or `node` | never limited | never limited | not shared | nothing to meet |
| a link of this device's own namespace, role **`guest`** (round 12, L2: "a friend's device, short-lived"; it ends when its certificate lapses) | the grant link's, below | the grant link's | its own shared bucket of the namespace's guests, the grant links' numbers | as a grant link; the names it carries are unchanged (every name) |
| a **grant link** (§8.7): a member the owner let in by invitation | burst 65,536, 32,768 a second (`GRANT_FRAMES`); **Interests alone** burst 16,384, 4,096 a second (`GRANT_INTERESTS`) | burst 64 MiB, 32 MiB a second (`GRANT_BYTES`) received; **answered** burst 64 MiB, 16 MiB a second (`GRANT_ANSWERED`) sent | frames burst 262,144, 131,072 a second (`GRANTS_FRAMES`); bytes burst 256 MiB, 128 MiB a second (`GRANTS_BYTES`) | an Interest: Congestion Nack, bounded; else silent; **an Interest that comes when less than a 32nd of the answered budget's burst (2 MiB) is left is Nacked Congestion** (§8.3 rule 7: its answer would not fit). The data layer's `32=grant` asks 256 at once, 16 a second together (`DATA_ASKS`), silent; an answer over `GRANT_ANSWERED` (of an Interest admitted before) dropped silently |
| a **stranger** served under `open` or `listed` with quotas (§15.2) | `interests_per_key`: 100 a second, burst 200 | none (a frame is at most a datagram: 100 frames of ≤ 1.35 KB ≈ 135 KB a second) | `interests_per_namespace`: 400 a second, burst 800 | an Interest: Congestion Nack, bounded; else silent |
| an **introduction**, enrollment or departure link (§8.1, §8.6, §8.8) | `ENROLLMENT_INTERESTS`: burst 32, 4 a second | none | not shared | an Interest: Congestion Nack, bounded; else silent |

**Round 12 numbers, and why** (`policy.rs`). *`GRANT_INTERESTS`* (16,384 burst, 4,096 a second): one 1 MiB pull is 256 piece Interests, up to `Config::window` in flight (heap.md §7.4, §10.2), so the burst is 64 pulls at once and the refill 16 pulls a second (16 MiB a second of 4 KiB pieces asked); an ordinary pull never meets it (case `a_members_1_mib_transfer_over_a_grant_link_meets_no_quota`: 0 frames over a rate, 0 Congestion Nacks). *`GRANT_ANSWERED`* (64 MiB burst, 16 MiB a second): one honest pull is 1.2 MiB on the wire, so the burst is some 50 pulls back to back and the refill matches `GRANT_INTERESTS` of 4 KiB pieces; it bounds what one key can make this device send, however many Interests it sends (before: 32,768 Interests a second, some 128 MiB a second of 4 KiB Data or more with 8,800-byte Data). *`DATA_ASKS`* (256 burst, 16 a second): an honest member asks a grant per collection and epoch it reads; its device never has more than 256 asks in flight (its fetch slots), so the burst covers all it can have outstanding, and 16 a second stays well under the 128 a second the owner's data layer drains asks it cannot answer, which the 32,768 a second of the frame bucket did not.

**Open item: a per-writer storage quota.** A granted writer's pushes are bounded in *rate* only: at most one burst of 64 MiB and then 32 MiB a second received over its link (`GRANT_BYTES`), 128 MiB a second for a namespace's members, until the grant ends. There is **no bound on the total stored per writer**: it needs a data-layer concept (per-writer accounting of stored bytes, a limit stated in signed data such as the writer's entry of the members fold, and a refusal at accept time saying which limit was met and what to do) that neither the link layer nor `ndn-heap` has (heap.md §1.7 states none), and a per-link cumulative cap would reset on reconnect and so bound nothing. It is left open; the owner's recourse until then is revoking the grant.

**A certificate that lapses ends the link** (round 12, L2). The hello checks the validity of the leaf and its issuers once; a link that stands past the earliest NotAfter of an identity's chain would keep an identity it no longer has. Each identity records, at admission, the certificate of its chain that lapses first and its NotAfter; a task sleeps until the earliest of them over the live links (a minute at most at a time, the wall clock read again at each wake; woken when a link is admitted) and takes each lapsed identity from its link as a revocation does (§12): a link left with no identity closes with **0x10** (Unrecognized: the key has no valid certificate now) saying which certificate lapsed, when, and to renew it (or enroll again if the device was offline across its NotAfter) and link again; a link another membership still admits stays, losing that identity's routes.
The grant link's rates are not the strangers' and are not read from the quotas: a `listed` policy's `Quotas` bound how many grant links there are and how fast its strangers go, never how fast a member the owner invited does. They are policy constants of the link layer (`policy.rs`), stated here with their reasons.

*Why a member's link is that high.* A member is authenticated (its key proved the handshake), named by a signed grant, and revocable (the link closes at the grant's end, §8.7 rule 6); an ordinary transfer must never meet its limit. What a transfer costs the owner to receive: the data layer cuts a payload into pieces of 4096 bytes (heap.md §8.2) and asks up to `Config::window` at a time (heap.md §10.2). **1 MiB asked by a member** is 256 piece Interests of about 100 bytes (26 KB); **1 MiB pushed by a writer** is 256 Data of about 4.4 KB, each fragmented into 4 or 5 frames of 1,100 bytes or more: about 1,300 frames and 1.2 MiB. Sync traffic is a few dozen small frames per update. The old default (200 frames burst, 100 a second) was met by one 1 MiB transfer: with it, the case `a_members_1_mib_transfer_over_a_grant_link_meets_no_quota` (`tests/quotas.rs`) loses 54 of the 256 piece Interests, and the ndf-rs ladder counted 9,966 drops over 100 runs of 1 MiB, each dropped Interest waiting for its asker's timer (250 ms, doubling). The new burst of 65,536 frames and 64 MiB covers 50 such transfers back to back; the sustained 32,768 frames and 32 MiB a second (256 Mbit/s) is the frames of 32 MiB at the datagram size, which is the rate of Data and fragments a writer may push. The **Interests** among those frames have a bucket of their own, because an Interest of 100 bytes asks for a piece of 4 KiB and so each one makes this device send about 40 times its size: burst 16,384 and 4,096 a second (`GRANT_INTERESTS`), which is 64 one-MiB pulls at once and 16 MiB a second of pieces asked, more than a forwarder answers from a store. A transfer larger than the burst at a speed larger than the sustained rate (more than 64 MiB at over 32 MiB/s) meets the limit; the asker then gets Congestion Nacks and backs off, and a Data pushed over it is lost like any lost Data (the asker's timer).

*What a granted member that misbehaves can do.* The buckets are the protection. **Received:** from one key this device receives, judges and passes to its forwarder at most **32 MiB and 32,768 frames a second** (and one burst of 64 MiB), from all the members of one namespace at most **128 MiB and 131,072 frames a second**; of those frames the **Interests** are held to **4,096 a second** (burst 16,384, `GRANT_INTERESTS`: one 1 MiB pull is 256 piece Interests, so a member may pull 16 MiB a second for as long as it likes and 64 pulls at once, and no more), and the data layer's own asks (`32=grant`) to **16 a second** (burst 256, `DATA_ASKS`), each of which costs this device a fetch back to the asker. The rest is dropped at the link, before the forwarder, and an Interest among it costs one Nack of the size of the Interest, itself bounded (§8.3 rule 7). **Sent:** what this device answers over a grant link is bounded by `GRANT_ANSWERED` (burst 64 MiB, **16 MiB a second**, counted in `sending()` on Data, Nacks and later fragments of one link); an answer over it is dropped silently, and an honest 1 MiB pull is 1.2 MiB on the wire, so the burst covers about 50 of them. **Relayed:** the names it carries are those of the folders it is granted (§8.7 rule 5), and a grant ask crosses only to a granter the folder can have (the owner's own devices and the listed writers' devices, `folder_carries`, `writer_carries`, invite.md §13.2, §13.3), so the owner's forwarder does not relay a member's asks to arbitrary devices. **Stored:** a writer's Data that the owner fetches is stored; there is **no per-writer quota of what is kept** (it needs per-writer accounting and a limit in signed data, which the link layer has not and `ndn-heap` has not either): the bound is the received-bytes bucket above, 64 MiB at once and then 32 MiB a second per link (128 MiB a second per namespace), until the grant is revoked, and the owner sees the writer's key on the stored packets. It is bounded in time (revoking the grant closes the link at once), and its misbehaviour is named: the report counts the drops (`LinkReport::frames_over_rate`), the log names the link and the reason.

*Why a stranger's and an introduction link keep theirs.* A stranger has proved a key and a certificate chain and nothing else: no grant names it, nobody can revoke it, and what it asks the relay serves from its store: 100 Interests a second is what a household's devices browsing and syncing through a small server need, and no more. An introduction link serves one exchange (an offer's record, an ask) to a party the owner has not admitted: a burst of 32 and 4 a second is a handful of Interests (§8.1).

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

**Which of the device's namespaces a relay is used for.** A device in several namespaces uses relays for each: a relay its person added is used for every namespace it holds a certificate in; a relay a namespace advertises, for each of the device's namespaces whose held trust context advertises it (by device name or key), however many of them do (`relay_namespaces_of`). A device in none counts all its relays together. The choice (§15.6) counts these namespaces only.

**Which namespaces a relay's link path routes.** A device *follows* a namespace when it holds that namespace's trust context (non-empty namespace) but no certificate in it. The link path to a relay routes the namespaces the relay is used for, then each namespace the device follows, at the relay's rank (`relay_routed_namespaces`), whether its person added the relay or a namespace advertises it. A person's devices thus reach the people they follow through the relay their namespace advertises, with no `[[relay]]`. Following a namespace never makes the device link more relays. The routes follow what the device follows while the link path is up: when it adopts a trust context, when a membership begins or ends, and when the host forgets a context (`Links::followed_changed`, which `ndn-link` runs on every adoption and identity change itself), every relay link path up MUST route each namespace it now routes over the relay and MUST take the route of each it no longer does — unless another of the path's routes has the same prefix — at the rank it came up with; an on-demand relay that is down routes them to the waiting face (§16.3). A namespace followed later is therefore routed at once, without the link being made again. These are the device's own Interests, which name a namespace it needs; what the **relay** is told it follows is another set, the space groups the host gives (`Links::set_followed_groups`, §5.10), not derived from the contexts held.

**Reaching a device not followed yet.** A device that holds no trust context of a namespace routes nothing of it, yet may need to reach one of its devices once — to ask for an introduction ([invite.md](invite.md) §8.2, §12.1). It names, in a ForwardingHint, a relay that reaches that device (the ones the other namespace's trust context advertises, as a code carries them, else the relays its own namespace advertises): its relay link path routes the relay's own name (§10), so the Interest goes to the relay. A host MUST give its forwarder its own device names — every device name of a certificate it holds, of its link key or of a membership — kept current as they change, and its forwarder MUST strip the hint from an Interest one of whose hint's delegations is one of those names or a name under one (as NFD strips a hint that reached a producer region): the hinted relay then forwards the Interest by name, over the link of the linked device its name routes (§10), and that device's forwarder delivers it by name too. A delegation naming an *ancestor* of the device's names has **not** reached the device: it names whatever serves that namespace elsewhere — as the hint `<ns>` of an enrollment's, a renewal's or an approval's certificate fetch names the namespace's CA (the fetch is named under the device's own key name, which a relay may route back to the device) — and the forwarder MUST forward the Interest toward that delegation with its hint. The device names are therefore not NFD producer regions: NFD's `NetworkRegionTable` counts a region as reached by any delegation that is the region or an ancestor of it (a network the forwarder is part of), which for a device name would take every hint naming its namespace as arrived at each of its devices. The ndn-rs engine keeps both: regions (`EngineConfig::network_region`, `NetworkRegionTable::add_region`) under NFD's rule, own names (`NetworkRegionTable::add_own_name`, `remove_own_name`) under this one. Nothing in the forwarder knows the names asked for. The hint is not authenticated: a wrong one costs only reachability, as any route does; whatever answers is checked end to end by the asker. A relay serves the asking device exactly as any other served device (§15.2), and the Data returns over the pending entries.

**What the relay needs.** Nothing per person. A relay carries the people it serves without their trust contexts: it serves their devices offline against their roots (§7.1, `open` or `listed`), routes each served device's name, its issuers' key names and its namespace's sync group over its link (§10), runs that group with the multicast strategy while the namespace is in transit, and carries their Data in transit (§15.7). Their devices validate it end to end, fetching the chain from the device that signed it. A device that follows another person's space tells the relay the space's exact group in its hello (§5.10), and the relay routes that group to it too, and no other space of the same owner (§10, [Decision 42](#20-decisions), [Decision 43](#20-decisions)): the people of two spaces reach each other through the relay, still with nothing configured per person.

### 15.6 Choosing relays, failover and failback

**Order.** Relays are ordered by preference (lower first); of equal preference, a `user` relay comes before a `namespace` one, then they keep the order in which they were added. `count` relays are linked at once for each namespace the device uses relays for (`RelayOptions::count`, default 1; ndn-fwd `[relays] count`, 1–8).

**Choice.** Walking the order, a relay is considered while at least one of the namespaces it is used for has fewer than `count` relays chosen:

- an `off` relay that the host does not ask for and that is not linked is skipped;
- a relay that is linked, or whose last dial did not fail, is **chosen**;
- a relay whose last dial failed, or that closed its link with **0x00** (Shutdown), is **retried**: dialled again with its backoff (§13.1) while the next one in the order stands in.

Relays not considered stand by, undialled. Chosen and retried relays are dialled as their mode says (§16.1). A chosen relay counts for each namespace it is used for; a retried one for none. The choice is made again whenever a relay's link comes up or ends, a dial of a relay fails, or a peer is added, removed, connected, disconnected or changes mode.

**Routes.** The link path to a relay routes the namespaces it carries (§15.5) at a cost equal to the relay's rank in the whole order (0 for the first, 1 for the next, …), and the routes of the peers reached through it at that rank + 10 (§10). Traffic of each namespace therefore takes the most preferred linked relay that routes it.

**Failover.** When the link to a relay drops, its face and routes go, and traffic takes the next linked relay at once (with `count` > 1). A relay that closed the link with 0x00 (Shutdown) said it is going away: it is retried at once, so the next relay in the order is chosen and dialled without waiting for a dial of the first to fail. A link that dropped otherwise (timed out, replaced, …) may be a relay restarting or a short outage: the relay stays chosen and is dialled again after `BACKOFF_FIRST`; once a dial of it fails, it is retried and the next relay in the order is chosen and dialled.

**Failback.** When a retried relay links again, it is chosen again, and a relay that no longer fits within `count` is **released**: the device closes its link with **0x06** (Released), saying it uses a more preferred relay now and will use this one again if that one is lost. A device also closes with 0x06 the link to a relay its host removed or its namespace no longer advertises.

An Interest waiting for an on-demand relay that is not chosen is answered with a Nack NoRoute (§16.3). Status reports each relay as `linked`, `trying` (chosen; being dialled, or on demand and waiting for traffic), `down` (its last dial failed, or it shut down), `standby` or `off` (§14.10).

### 15.7 Transit: Data of a namespace the relay does not hold

A forwarder validates the Data it forwards against the trust contexts it holds. A relay serving the devices of a namespace it does not hold (`listed` without its trust context, or `open`) cannot: it holds neither that namespace's trust context nor its certificates. While at least one device served for such a namespace is linked, the relay carries the namespace's Data **in transit**:

- it forwards that Data to the Interests pending for it **without validating it**: the Data is still signed, and the devices that asked for it validate it end to end;
- it caches none of it: Data in transit never enters the Content Store;
- unsolicited Data is still dropped, as for any Data that answers no pending Interest;
- Data under a namespace the relay holds is always validated, whatever is in transit.
- it runs the namespace's sync group `<ns>/32=sync` with the multicast strategy, so a Sync Interest from one served device goes over the group route of every other one linked (§10). When the namespace leaves transit the group's strategy goes, unless the relay holds the namespace: a held namespace's group keeps the strategy its trust-context library gave it.

The namespace leaves transit when the last link of a device served for it ends. Host interface: `ndn-link` calls `FaceSink::transit(namespace, true)` when a path of a served device comes up — once for each namespace a served identity of the link is in (§7.3) — and `FaceSink::transit(namespace, false)` when it ends; the calls pair up, so the host counts them per namespace ([Decision 30](#20-decisions)). The ndn-rs engine keeps the counts in `TransitPrefixes`; its first `add` and last `remove` of a namespace run the host's action under the count's lock. `EngineFaces` carries the group there (`ndn_namespace::sync_group::carry`) and releases it (`release`). A forwarder that validates nothing carries no Data in transit, but still runs the group so ([Decision 33](#20-decisions)).

`security/transit` ([mgmt-trust.md](mgmt-trust.md#transit)), from a local operator or a member of a transit group, adds reasons of its own to the same count, one per mark, for a local app that adopted a person's self-certifying namespace for one scope of its own ([heap.md](heap.md) §9.4); management counts its marks apart, each owned by the management face that asked and released when that face closes, so a release never takes a link's reason, and a namespace an app still marks stays in transit when its served devices' last link ends.

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

A device checks each link it keeps: an on-demand link every `idle` / 4, clamped to 250 ms – 30 s; other links every 60 s; and at once when the host changes something. *Activity* is the NDN datagrams and the channel datagrams sent or received on the link (QUIC DATAGRAM frames), and the octets of channel frames on its stream in either direction (ndn-rs `LinkHandle::side_stats`, §9 item 7); keep-alive PINGs and control-stream messages are not activity, so keep-alives do not hold an idle link open. A link another device dialled here with no activity for `quiet_close` is closed with **0x02** (Idle), unless the host's forwarder routes to its face — an NDN route, or a *side route* (`FaceSink::side_routes`: the routes the forwarder holds for channel frames; zero for a forwarder that has none) — or the link carries a namespace in transit (§15.7); a link this device dialled is its mode's own. The device closes the link:
- with **0x05** (Asleep), when an `on-demand` link is not asked for, the host is not active, and the link carried no datagram for `idle` (the close comes within one check after that);
- with **0x05**, when an `off` link is no longer asked for;
- with **0x06** (Released), when a relay is no longer chosen (§15.6) or the peer was removed.

**Channel stream bytes and the quiet close.** For the quiet-close rule of a link another device dialled here, the octets of channel frames on its stream are activity **only while the forwarder holds a side route to its face**: a peer that sends channel frames the forwarder would drop (nothing routes them) does not keep an unrouted link open by it, and once the route goes the quiet period runs from the last such octet. (For the on-demand idle rule of a link this device dials they count always.) Channel datagrams count with every datagram, as an NDN datagram the scope drops does: the rule asks whether the link carried anything, and `datagrams()` is not told what became of it.

A host going inactive (`set_active(false)`) closes nothing at once: its on-demand links close once idle. After closing a link itself, the device dials again as soon as the link is wanted again (§13.1). A relay that sees a device's link end may count it asleep (§17.2).

### 16.3 The waiting face

While an on-demand peer has a path to dial, the routes its link will get — its `routes`; else, for a relay this device uses, the namespaces its link path routes (§15.5); else its `device` — lead to the waiting face at `WAITING_COST` = 1000, above any link's cost. An Interest the forwarder sends there:

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

## 17A. Link status

*(Numbered 17A while the sections of round 6 are placed: SHAPES-R6 calls it §17, and §17–§18 are Reachability and Constants above. Nothing in it is on the wire.)*

A host that shows its links (a status screen, a log) needs the state of each peer **as it changes**, not a poll of `Links::report` (§14.10, unchanged). `Links::watch()` gives it a `LinkWatch`: the state of every peer now, then each change.

### 17A.1 The shape

```rust
pub enum Direction { Dialed, Accepted }                      // who made the link
pub enum Next { Redialling { within: Duration }, WaitingForAddress, WhenWanted, WhenOnline, Gone }
pub enum LinkState {
    Up   { direction: Direction, since: SystemTime },
    Down { direction: Option<Direction>, why: LinkDetail, next: Next },
}
pub struct PeerLink { pub key: KeyFingerprint, pub device: Option<Name>, pub state: LinkState }
impl Links     { pub fn watch(&self) -> LinkWatch }
impl LinkWatch {
    pub fn current(&self) -> Vec<PeerLink>;                  // the table now
    pub async fn changed(&mut self) -> Option<Vec<PeerLink>>;
}
pub const LINK_STATES_MAX: usize = 256;
```

1. **Keyed by key.** A peer is its link key's fingerprint (§3.3). A peer is keyed when its key is known: a configured peer with an expected `key` from its first dial (a failed first dial is a `Down` state of that key); any other peer when its handshake shows the key. A dial that fails for a peer with no key known yet has no state to show. `device` is the device name of the identity the peer's certificates proved (§7.1), kept once known; a name only claimed (a code's link hint, a configured `device` the peer has not proved) is not shown.
2. **Up.** An entry is `Up` from the moment a path of its link is admitted (§7.3), whichever side dialled it and whichever path (a link, or a direct path that is the only path). A direct path joining a link that is up changes nothing; a link that replaces another (§11) is `Up` again, with a new `since`, and never shows `Down` between.
3. **Down.** An entry is `Down` when the last path of its link ended. `direction` is the lost link's (`None`: no link of the key was ever up here, as after a refused first dial). `why` is a `LinkDetail` (§14.10) of the close or of the failed dial, in plain words. The state is decided in one place per event and never overwrites a link that came up again meanwhile.
4. **Next.** What this device does about a `Down` peer, as the decision is made where the device redials (§13.1):
   - `Redialling { within }`: it dials again, within `within` (the backoff: `BACKOFF_FIRST` after a drop; the doubled wait after a failure; `BACKOFF_REFUSED` after a refusal, §13.1; zero when a link it closed must be made again at once);
   - `WaitingForAddress`: the peer has no path to dial (it links in; the host or a relay gives an address later);
   - `WhenWanted`: the peer is dialled when the link is wanted — the host asks, traffic waits for it, the relay is needed (§16.1, §16.2, §15.6) — and the link was closed here for that reason;
   - `WhenOnline`: this device is offline (`Links::set_online(false)`, §17D.1) and makes no attempt of any kind; it dials the peer again, at once and in its turn (§17C.2 rule 2), when it is back online;
   - `Gone`: this device does not dial it again: a peer entry that is not `persistent` and links `always` is dialled once (§13.1), a peer dialled by a code's key (§13.3) once, and a link no peer entry of this device expected is never dialled from this table.
5. **Reasons.** `why` carries the codes of §14.10: `link-closed-by-peer` with the words the other device closed with (including its shutdown, "refused" and the reason it gave for a refusal, and an ended grant it closed for), `link-closed-here` with the words this device closed with (the mode turned the link off or to sleep, the host removed it, a more preferred relay, a grant ended or a member left), `link-timeout` or `link-connect` for a link or dial that went unanswered, `link-unexpected-key` for a dial that met another key, and the refusals of §7.3 as causes of those. A link that a departure closed carries a **`let-go`** cause (facts `folder` and `record`, §8.8 rule 8) on both sides: on the inviter's from the reason it closed with, on the person's from the `Departure` it heard. A reason says what happened and what to do, in terms of no host.
6. **Offline and no path.** Two codes (registered in the table of `mgmt-trust.md`, "Why a link did not come up, or ended") belong to `why` beside those of item 5. `offline`: the link, or the wait, is down because this device is offline (§17D.1); every `Down` entry then carries it with `Next::WhenOnline`, whatever closed the link (the other device sees `link-closed-by-peer` with the words "this device went offline; it links again when it is back", not a grant that ended). It stays until the peer's next outcome (up, or a failed dial) replaces it. `no-path`: a remembered peer whose kept addresses all failed while no relay both devices use is linked (§17D.2); its entry is `Down` with `Next::WaitingForAddress`, and its sentence says what to do (the other device reaches this one when it dials this device's current address, or when both link to a relay). Neither names an address: the words of §17A.4 hold.

### 17A.2 Bounded, coalesced, no queue

1. The table holds at most `LINK_STATES_MAX` = 256 peers. A peer beyond it takes the place of the entry longest unchanged among those that are `Down` with `next = Gone`; if none, among those `Down` for any other `next`; if none, among those `Up`. An entry given up this way is not reported.
2. A watcher holds a **cursor**: the table's version when it last looked (a counter that grows with each change). It holds no queue of changes, so a watcher that never reads costs no memory and a slow watcher cannot grow it; wake-ups carry no data (a notification that something changed).
3. The first `changed()` returns the whole table now, at once, even when empty: a watcher started late is told the state first. Each later call waits until a peer changed since the watcher last looked and returns exactly those peers, **one entry per peer, in its newest state**, the longest unchanged first. A peer that went down and up between two looks shows once, `Up`. A change that does not alter a peer's state (the same failure again with the same reason and `next`) is no change.
4. `changed()` returns `None` once the `Links` are dropped or cancelled. `current()` is the table now, in the same order.

### 17A.3 Hooks (non-normative)

The state is written at four places and nowhere else: a link or direct path coming up (`establish`), the end of the last path of a link (the task that unregisters it), the dial loop's decision (`next`; a failed dial), and the dial by key's failure. An internal observer hook (`Links::observe`, crate-private) tells the link memory (SHAPES-R6 item 2) of each admitted path (key, device, the address it came from, direction, whether an identity admitted it) and of each loss; it is inline, not a queue, and persists nothing.

### 17A.4 Threat notes

- A watcher is the host's own code. It sees keys (public), device names (those the peer's certificates proved), directions, times and `why` texts. It never sees an address: socket addresses, IP addresses and `host:port` endpoints in a reason or in its facts are replaced by "an address" before the reason is recorded. Reasons are the sentences the link layer already writes for logs and reports (§14.10): they hold no key material, no token, no certificate and no secret.
- The words of a peer's close are the peer's: a hostile peer chooses the text of its own `link-closed-by-peer` reason, and it can put anything in it: line breaks and escape sequences that forge a log line or repaint a terminal, bidirectional controls that reorder what a screen shows, zero-width characters that hide words, a page of persuasion. Two layers make it safe to show, and a host still MUST show it as text, never as markup or a command. (1) `ndn-face-quic` hands up no raw close text: the text of a close (`LinkError::Refused`) and of a transport close (the sentence of `LinkError::Connect`) have gone through `sanitize_peer_text` — every control character (C0, DEL, C1) and invisible character (the bidirectional controls U+061C, U+200E–200F, U+202A–202E, U+2066–2069, the zero-width characters U+200B–200D, U+2060–206F, U+FEFF, U+00AD, U+180E, the interlinear annotation marks and the tag characters) removed, every run of whitespace (the line and paragraph separators included) collapsed to one space, the ends trimmed, and the whole at most `PEER_TEXT_MAX` = 512 characters, a longer text ending in `…` within that bound — so the log lines and details built from it carry one bounded line of printable text. (2) A watcher does the same to every sentence and parameter of a reason, whatever its source, **before** it scrubs addresses (an address with an invisible character in it is still an address), and bounds each at `WATCH_TEXT_MAX` = 1024 characters, again ending in `…`.
- The table is bounded (§17A.2), so peers cannot grow it by dialling with many keys, a code's hint naming many keys, or flapping; a flood of keys evicts the entries of dead peers before those of live links, and a live peer that was evicted is shown again by its next change.
- No wire TLV is added or changed (the registry of §5.1 is unchanged).

### 17A.5 The side path's counters

`Links::report()` gives each device's link a `LinkStatus` (§14.10); it carries `side: SideStats`, the counters of the channel frames (§9 item 7) of the link's paths together (those of a path that is gone are gone with it; a device that is not linked has zeros). Counters only: no address, no key, no name. Nothing on the wire changes for it (the field `ChannelCaps` of §5.2 is the only addition of the channel carrier).

| Field | Counts |
|---|---|
| `datagram_tx_frames`, `datagram_tx_bytes` | channel datagrams sent, and their octets |
| `datagram_rx_frames`, `datagram_rx_bytes` | channel datagrams received and delivered, and their octets |
| `stream_tx_frames`, `stream_tx_bytes` | channel frames written to the stream, and their octets (without the record's 4-octet prefix) |
| `stream_rx_frames`, `stream_rx_bytes` | channel frames read from the stream, and their octets |
| `coalesced` | stream frames written in the same write as an earlier one |
| `dropped_over_quota` | received datagrams dropped, and frames `forward_side` refused as `Full`, for the link's fair share (§9 item 9) |
| `dropped_malformed` | stream records of no octets, over 1 MiB, or not starting with 0x00 (§9 item 7) |
| `stream_blocked` | stream writes that found no flow-control credit and waited |
| `sink_full` | frames `forward_side` refused because the send buffer or the stream's queue had no room |
| `refused` | frames refused because the link does not carry channel frames or the peer lacks the capability: those sent, and those received and dropped |
| `queued_peak` | the most octets that waited in the connection's datagram send buffer when a channel datagram was handed to it (always under the headroom then in force, so under `QUEUE_CAP`, §9 item 7) |

## 17B. The fault layer

*(Numbered 17B while the sections of round 6 are placed: SHAPES-R6 calls it §18, and §18 is Constants above. Its one wire addition is the optional `links/list` notice of §17B.6.)*

The conformance's `--faulty` profile (drop, duplicate, forge, delay, reorder, block loss) is the network a host's faulty test suite must meet on its **real** links too. ndn-link carries a **test-only** fault layer for it: a wrapper on each link's face that applies a seeded profile to the packets arriving on it. **It is for tests only.** A build that has it says so (§17B.6), and it is kept out of shipped binaries (§17B.7).

### 17B.1 The feature

1. The layer MUST be compiled only with the cargo feature `fault-injection` of `ndn-link`. The feature MUST NOT be in `default`, MUST NOT be enabled by the default features of any other crate, and MUST be documented *for tests only*. A crate that needs it for a test asks for it as a dev-dependency feature or on the cargo command line (`cargo test -p ndn-link --features fault-injection`).
2. Without the feature nothing of the layer exists in the build: no wrapper, no counters, no dependency (its one dependency, `ndn-faults`, is optional and pulled by the feature). `LinkReport::fault_injection: Option<FaultReport>` and the type `FaultReport` are in **every** build, so that a host's code does not change with the feature; the field is `None` without it.
3. API (feature on): `FaultPlan { profile: Faults, verdict: Option<FaultJudge> }` (`FaultPlan::new(profile)`, `.verdict(f)` with `f: Fn(&FaultFrame) -> FaultVerdict + Send + Sync`), `FaultVerdict { Profile, Drop, Pass }`, `FaultFrame`, `FaultKind`, `Links::inject_faults(&self, FaultPlan)`, `Links::clear_faults(&self)`, and the profile type re-exported (`ndn_link::Faults`, `ndn_link::FAULTY`). `FaultPlan::verdict` replaces the `FaultPlan::only(Fn -> bool)` predicate of the first build of the layer: there is no alias, and `only(p)` is `verdict(|f| if p(f) { Profile } else { Pass })`.

### 17B.2 The profile, and its one definition

1. The profile is `Faults`: `drop`, `dup`, `forge` (probabilities 0–1), `delay` (ms, a uniform hold of 0..=`delay`), `reorder` (probability of a further hold of `max(delay, 50)` ms), `blocks` (ms: a Data is held a further 0..=`blocks`), and `seed`. Its text form is comma-separated `key=value` pairs (`drop=0.2,dup=0.1,…`); `FAULTY` is the conformance's `drop=0.2,dup=0.1,forge=0.05,delay=400,reorder=0.1,blocks=1500`. A **Data** for `forge` and `blocks` is a frame carrying a whole Data, bare or as the fragment of an NDNLPv2 packet; a fragment of a larger Data, an Interest, a Nack and a link-service frame are not. A forged Data has one byte of its signature value flipped.
2. The draws are a xorshift64 sequence per **link direction**, seeded from the profile's `seed` and the direction's two ends; each packet draws, in this order: drop; delay; reorder; (a Data) block hold; duplicate; (a Data) forgery. The same seed and the same packets on the same direction give the same fates.
3. **One definition (result of the sharing check).** The profile, the draws, the text form, `FAULTY` and the frame reading live in the crate `ndn-faults` of ndn-rs (`crates/core/ndn-faults`; scope `extension`; its only runtime dependency is `bytes`; no tokio). The dependency-direction guard (`testbed/dep-direction-guard.py`) allows it — it constrains only what `spec` crates depend on, and no `spec` crate depends on `ndn-faults` — and `ndn-sim` (which re-exports it: `ndn_sim::Faults`, `ndn_sim::faults::…` are unchanged and bit-identical) and `ndn-link` (optionally, behind the feature) depend on it. So `--faulty` and the face wrapper share every draw; the sequence of `FAULTY` at seed 3 on the direction 1 → 2 is pinned in `ndn-faults` and, through the re-export, in `ndn-sim`. A `spec` crate that came to depend on `ndn-faults` would be refused by the guard (a spec crate may not depend on an `extension` crate): the profile is test support and MUST NOT enter the library closure.

### 17B.3 Where, and when

1. **On arrival, once.** The wrapper sits on the receive side of the face of each link (a link, or a direct path), between the QUIC datagram and the forwarder. Each packet the face yields meets the plan's verdict once (§17B.4): it is discarded, or delivered untouched, or it meets the profile and is dropped, or delivered once or twice, after its delay, as the profile says. What this device sends is not faulted here: the other device's layer faults it when it arrives there, as the simulator faults what a node receives.
2. **Only what crosses links.** The layer sees only link faces. The host's local faces (its applications, its management socket, the signalling and waiting faces of the library) are never wrapped. The link's own handshake and control messages (hello, verdict, presence, reachability; §4, §5) travel on the QUIC control stream, not through the face, and are never faulted.
3. **Ends and determinism.** The draws of an arrival direction are `profile.stream(from, to)` with `from` = the first eight bytes, big-endian, of the sending device's key fingerprint (§3.3) and `to` = those of the receiving device's, so a device pair with fixed keys draws the same sequence in every run, and each direction its own. A link made again after a loss starts the sequence again.
4. **Links already up and links made later.** `inject_faults` applies to **every** link of the `Links`, those already up included, from the next packet that arrives, and to every link made afterwards; every link's wrapper reads the plan the `Links` holds. It replaces an earlier plan, starts its counters at zero and its draws again; `clear_faults` ends it (packets already held are delivered at their time). Delays use tokio timers, so held packets overtake each other as the profile says. A link that ends delivers what the layer holds before the face reports the end.

### 17B.4 The verdict

1. A plan's `verdict` is `Fn(&FaultFrame) -> FaultVerdict + Send + Sync`, asked once of every packet that arrives on a link (default, no function: `Profile` for every packet). `FaultVerdict::Profile` applies the profile to the packet (it meets the draws of §17B.2 and §17B.3.3: counted in `met`, and in `dropped`, `duplicated`, `forged`, `delayed` by what the profile did). `FaultVerdict::Pass` delivers it at once and untouched, counted in `passed`. `FaultVerdict::Drop` discards it, counted in `dropped`: **`dropped` is the one counter the verdict's drops and the profile's drops share**, so a Drop is never counted in `met` and `dropped` can exceed `met`.
   **Determinism rule.** A packet the verdict drops or passes **draws nothing** from the link direction's stream (§17B.3.3): the fates of the packets that meet the profile, in the order they meet it, are the draws of the stream for those packets alone, whatever number of others were dropped or passed between them. The same seed gives the same fates with or without them; a host that adds a packet to the traffic that it drops does not change what the profile does to the rest. (This is what lets a host drop one collection's versions and keep the faulty network on for the others: ndf's scenario K1.)
2. `FaultFrame { direction, peer, kind, name, len }`: `direction` is which side opened the link (`Dialed` when this device did); `peer` the key of the device the packet came from; `kind` is `Interest`, `Data`, `Nack` or `Other` (a link-service frame with no network packet, a later fragment, bytes that are no packet); `name` the packet's name for the first three (of a fragmented packet, the first fragment's; a Nack carries its Interest's); `len` the frame's length as it crossed the link. A host that wants "the versions of the first collection, while a file exists" says it here; ndn-link knows no file.
3. The verdict runs on the link's receive path: it SHOULD be short and MUST NOT block. A verdict that **panics** does not end the link's receive task: the panic is caught, the packet is delivered untouched (as `Pass` does, but counted only in `predicate_panics`, not in `passed`), and the report counts it — the layer fails open and says so.

### 17B.5 A forged packet is still refused

The layer only flips a byte of a Data's signature value; it never signs, never adds a certificate and never touches a name or content. A consumer that validates (an `ndn-heap` node, `Unverified::verify`) MUST refuse the packet it forged, and a forwarder that validates drops it. The conformance case demonstrates it through a real link, with a consumer that does not validate as the control that the packet really was forged.

### 17B.6 The notice and the report

1. `Links::start` of a build with the feature MUST log, at `warn`, once: "ndn-link was built with `fault-injection`: it can drop, duplicate, forge and delay packets; this is for tests and must not be in a production build"; `inject_faults` logs a `warn` with the profile.
2. `LinkReport::fault_injection` is `Some(FaultReport)` in a build with the feature (even with no plan installed: `profile: None`), `None` otherwise. `FaultReport { profile (the text form), met, dropped, duplicated, forged, delayed, passed, predicate_panics }`: `met` counts the packets that arrived and met the profile (no verdict function, or the verdict was `Profile`), and `duplicated`, `forged`, `delayed` count what the profile did to them; `dropped` counts the packets the profile dropped **and** those the verdict dropped (§17B.4); `passed` counts those the verdict let pass; `predicate_panics` counts verdicts that panicked. The counters are those of the installed plan, over all links.
3. **The shipped hosts carry it.** The management dataset `links/list` (§14.10) carries `fault_injection` as the optional nested TLV 0x050C (`FaultReport` as `LinkFaultReport` of ndn-mgmt-wire: the profile in 0x050E, absent while no plan is installed, and the counters 0x0510–0x051C), present exactly when the daemon was built with the feature, and `ndn-ctl link list` prints the counters and a `WARNING` line that says what the build is and what to do; the terminal UI shows a "Test build" pane on its connections screen. The mobile library's `NdnLinkReport::fault_injection` (`NdnFaultReport`) carries the same fields to the app, `None` in every shipped build.

### 17B.7 Keeping it out of production

`tools/check-shipped-features.sh` (workspace root) lists `fault-injection` among the **forbidden features** and fails when (1) any `Cargo.toml` but ndn-link's own declares or enables it outside `[dev-dependencies]`, or (2) the resolved feature graph of a shipped package (the forwarder binary `ndn-fwd`, the mobile library `ndn-boltffi`), by default features or `--all-features`, with no dev edges, holds it. (`--forbidden-only` runs just these checks; they need no build.) The script's `ndn-ext: all-features` build does turn the feature on, as a compile check of the crate, not as a shipped artifact.

The `ndn-fwd` daemon refuses to start with the layer, before it opens anything: `ndn_link::FaultReport::compiled_in()` (true exactly when ndn-link has the feature) with `[links] allow_fault_injection` unset (its default, `false`) ends the start with an error that says the build has the test-only fault layer, that it will not start with it, and the two ways out: rebuild without the feature (a shipped daemon never has it), or, for a test run, set `allow_fault_injection = true` under `[links]`. The setting does nothing to a daemon without the layer. The mobile library has no start to refuse (it has no operator); it forwards the notice (§17B.6) and a host app MAY refuse to run when it is set.

### 17B.8 Threat notes

- **In a production binary by accident.** The feature is off by default, no crate default-features it, a build that has it logs a warning at every start and says so in `Links::report()`, in the `links/list` dataset and in `ndn-ctl link list` (§17B.6), the `ndn-fwd` daemon refuses to start with it unless `[links] allow_fault_injection = true` (§17B.7), and the guard of §17B.7 fails a shipped graph that holds it. A plan still has to be installed by host code: the compiled-in layer touches nothing until `inject_faults`.
- **A verdict that panics or is slow.** A panic is caught and fails open (§17B.4); a slow verdict delays that link's receive path (and so its packets): it is the host's test code, bounded by its own discipline, and no part of the layer waits for it elsewhere.
- **Only what crosses links.** The layer wraps link faces only: it cannot fault a host's local faces, the control stream or the handshake, so it cannot make a link admit a device it would refuse, nor change who a link's peer is (admission is §7 and is unchanged); it only perturbs the NDN packets that arrive after admission.
- **It adds no capability.** A forged Data is refused by validation (§17B.5); a dropped, duplicated or delayed packet is what the network already does, and `Drop` is what the network already does: a verdict that discards a packet gives the host nothing a lossy link would not (it can make a test fail, never make a link admit or accept what it would refuse), and a packet it drops or passes draws nothing, so it cannot steer the profile's draws either. Held packets are bounded by the profile's delay, not unbounded: a profile with a large `delay` or `blocks` and a fast sender holds memory in proportion; test profiles keep them small.
- The only wire change is the optional `links/list` notice of §17B.6 (TLVs 0x050C–0x051C, registered in the specs README); a decoder that predates it skips them (all even), and nothing outside `links/list` carries it.

## 17C. Link memory

*(Numbered 17C like §17A and §17B: SHAPES-R6 calls it §16, which is Link modes above. Nothing in it is on the wire: no TLV is registered or changed, and the registry of §5.1 is unchanged. Every record here is local to a device.)*

A device that restarts has lost what it learned of its peers: who they were, and where they were reached. A host that wants them back keeps a list, or a relay brings them. **Link memory** keeps, in a store the host gives, what the links themselves learned — each peer's key, its device and the addresses that worked — and dials the peers again from it: no peer entry, no relay, no list of the host's. It is **a hint to dial, never a reason to admit**: what a record says is checked again by the handshake and by admission (§7) at every dial, and nothing in the store admits anyone.

### 17C.1 The shape

```rust
pub trait LinkMemory: Send + Sync {
    fn load(&self) -> Result<Vec<PeerRecord>, String>;                                   // sync, at start
    fn save<'a>(&'a self, r: &'a PeerRecord) -> MemoryFuture<'a, Result<(), String>>;    // returns once durable
    fn remove<'a>(&'a self, k: &'a KeyFingerprint) -> MemoryFuture<'a, Result<(), String>>;
    fn load_listen_port(&self) -> Result<Option<u16>, String>;                           // sync, at start (§17D.2)
    fn save_listen_port<'a>(&'a self, p: Option<u16>) -> MemoryFuture<'a, Result<(), String>>;  // None removes; returns once durable
}
pub struct PeerRecord {
    pub key: KeyFingerprint,        // the key the peer proves in the handshake
    pub device: Name,               // the device it proved to be, in a namespace this device held
    pub addresses: Vec<SocketAddr>, // most recent first, at most addresses_max: hints
    pub last_contact: SystemTime,
    pub origin: Direction,          // who FIRST made the link: Dialed | Accepted (§17A.1)
    pub port: Option<u16>,          // the listening port of the peer's last contact (§17D.2): a hint
}
pub struct MemoryOptions {
    pub peers_max: usize,           // 64: one more evicts the peer least recently in contact
    pub addresses_max: usize,       // 4
    pub expires: Duration,          // 30 days without contact
    pub redial: Backoff,            // the dial backoff (§13.1) by default
    pub dials_at_once: usize,       // 4: peers redialled at the same time (§17C.2 rule 2)
    pub include_local: bool,        // false: loopback and link-local addresses are not kept or dialled (rule 1)
    pub persist_addresses: bool,    // true: false writes records without addresses (§17C.6)
    pub save_interval: Duration,    // 60 s: a record is written at most once in this long (rule 6)
}
impl Links {
    pub fn remember(self: &Arc<Self>, memory: Arc<dyn LinkMemory>, options: MemoryOptions);
    pub async fn forget(&self, key: &KeyFingerprint);
}
pub struct MemoryReport { pub peers: Vec<RememberedPeer>, pub store_error: Option<String> }   // LinkReport::memory
```

`MemoryFuture` is a boxed, `Send` future (the crate takes no async-trait or futures dependency). `PeerSpec` gains one field, `remembered: bool` (false by default), which only the link memory sets (§17C.4). `Links::remember` is called once; a second call is ignored and logs that it was.

### 17C.2 The rules

1. **The key is authenticated and an address is a hint.** A record is made only for a link that an **identity validated in a namespace this device holds** admitted (§7.3): not an enrollment link or an introduction link (§8), not a link admitted by the expected key alone, not a direct path, not a peer the host's `LinkSetup` or `add_peer` lists, not a relay a namespace advertises (§15.5). The record keeps what worked: the address this device **dialled**. For a link the peer opened, the address it came from is the peer's source address, whose port is the peer's own choice and changes at each reconnect of a device that dials from a socket of its own: rule 7 says what is kept of it (the IP, with the port the record holds; **never the source port**; the whole source address only for a record that holds no address and no port yet), so a peer that reconnects a hundred times from a hundred ports changes nothing. An address a dial would not use is **never kept, read from the store or dialled**: unspecified, multicast and broadcast ones, port 0, and — unless `include_local` — loopback (`127.0.0.0/8`, `::1`) and link-local (`169.254.0.0/16`, `fe80::/10`) ones, the rule a link hint of a code has (invite.md §6.1): a store or a peer must not make this device send datagrams to services on itself or on its link (169.254.169.254, say). A host that links devices on one machine or one link sets `include_local`. A redial pins the key in the handshake (§3.4, §13.3: it accepts only the holder of the key): an address answered by another key is no link and costs a failed dial.
2. **Redial in the background**, at `remember` and after each loss, with `MemoryOptions::redial`: the handshakes to every address of the record at once (at most `addresses_max`), as §13.3. **Staggered:** at most `dials_at_once` peers (default 4, so at most 16 handshakes) are dialled at the same time; the others wait for a turn, each wait ending at once when its loop is stopped, and a peer is looked at again when its turn comes (forgotten, linked or no longer admitted while it waited: it is not dialled). A store with 64 peers of 4 addresses each is not 256 QUIC Initials at one moment. A peer with **no address** is *waiting for a new address* (`RememberedState::WaitingForAddress`, `Next::WaitingForAddress`, §17A.1); it learns one at the next contact — the peer dials in, a relay reports it — and dials it then. A peer that is linked is not dialled; when its link ends, the loop waits the first backoff and dials again. A dial that fails waits the doubling backoff; the refusal wait of §13.1 is not distinguished (a record's dial is bounded by the backoff either way).
3. **Not redialled when no held context admits it.** A record's peer is dialled, and a contact is remembered, only when **both** hold:
   - the record's **device is under a namespace this device holds** (`Keyring::held_for`, §7.1);
   - and this device may link with the peer by its own rules: a peer it dialled itself (`origin = Dialed`) in a held namespace; or a peer that dialled in (`origin = Accepted`) that is a device of a namespace this device holds a certificate in (the serving policy `own` serves it, §15.2), **or** a person this device introduced, **or** the inviter of a folder this device joined (the mirror grant, §8.7 rule 16), **only while a live grant covers its key** (§8.7: `Links::grants`).

   A record that fails this is **not dialled and not admitted**: it says why in the report (`RememberedState::NotDialled { why }`, in words that say what to do), is looked at again when a trust context is adopted or a grant is made, and is dropped at expiry (rule 5). The `origin` is that of the **first** contact and is never changed by a later one, so a peer that dialled in cannot become a peer this device dialled. **A peer whose `origin` is `Accepted` is judged when this device redials it exactly as a stranger that dials in is** — by the serving policy and the grants, its link carrying the grant, the quota and the reader's scope — so the end of a grant closes the redialled link too, and a redial never has fewer limits than the same peer arriving (§8.7 rule 12).
4. **A remembered peer is never admitted by its key alone.** The expected-key path of a `PeerSpec` (§7.3 rule 7) is for hosts that list peers. The entry the redial dials as has `remembered = true`, and then: (a) its `key` pins the dial and a different key is refused (`not-expected-key`); (b) it is admitted **only as an identified device** — a certificate that validates in a namespace this device holds, proves the record's `device` (else `not-expected-device`) and passes that namespace's link policy and any revocation; a hello with no usable certificate, or one whose namespace is not held, is refused (`expected-device-unconfirmed`, saying so and what to do), never admitted by the key, and never as an enrollment link; (c) it is a peer entry **only for the dial this device made**: a link that came in with the same key is judged as any stranger's, by the serving policy and the grants (§15.2, §8.7), so a record never makes the serving policy more permissive. A member who was removed and still holds its key is therefore refused by the rules of rule 3, and by the other device's rules when the removal is the other device's.
5. **Bounds and expiry are `MemoryOptions`.** At most `peers_max` records (a new peer past it evicts the one least recently in contact, and removes it from the store) and `addresses_max` addresses each (most recent first; an address already held moves to the front). A record with no contact for `expires` is removed at the next prune, which runs at start (a record already expired is never dialled) and after each write; **a peer whose link is up is in contact**, and is never pruned. `Links::forget(key)` is how a host says a member left: the record is removed from memory and **from the store before it returns** (`LinkMemory::remove` returned), its redial stops, its addresses are dropped; a link already up **stays up** while a held context admits it (the layer, not this call, ends the links of removed members: §8.7, §12). A peer that links in again is remembered again.
6. **Durability.** A record is saved after a contact **once something the store should hold changed**: a new peer, another address list (an address this device dialled, rule 1, or the new front address of a peer that opened a link, rule 7) or device name, or a `last_contact` that the store's is a quarter of `expires` behind (so a peer that is always in contact does not expire at a restart, and the store is not written at every link). **A record is written at most once in `save_interval`** (60 s by default; the first write of a record is not delayed): what changes in between stays in memory and is written when the time is up, and at `Links::shutdown`, so a peer that reconnects again and again is a few writes (flash wear, an fsync each), not one per reconnect. Saves are written **in the background, one store operation at a time** (a save never lands after the removal that follows it, and a save reads the record when the store is its turn, so a removal that came first is never undone); **nothing waits on the store**, and `Links::shutdown` writes what is owed first. A store that fails (on load, save or remove) is logged and shown in `LinkReport::memory.store_error` in words; the links work without it, and what is learned stays in memory until the store works again.
7. **A link an identified peer opens brings the record's address up to date.** When a peer opens a link to this device and the memory takes the contact (§17C.3: the key is the one the handshake proved, an identity validated in a held namespace admitted the link, `LinkEvent::Up { identified: true, kind: Link }`, and rule 3 holds), `Book::learn` for `Direction::Accepted` keeps **the address it came from with the port the record holds**: `record.port`, else the port of the record's first address. That candidate `(source IP, held port)` moves to the front of the list when its IP is usable (rule 1's filter, `include_local`) and differs from the front address (an address already held moves to the front and is never listed twice); the list stays within `addresses_max`, so the oldest goes. **The source port is never recorded** (round 6): it is the peer's own choice and changes at each reconnect, and `record.port` is changed only by a link this device dialled, a direct path or `set_port` (§17D.2 rule 3). A record with **no address and no port** (a first contact) takes the source address and port as before, as the one to try. A port that changed as well as the address is learned as before (a dial, a direct path, a reported IP: §17D.2 rules 3 and 4). The record is keyed by the proven key: **a link of another key makes or updates that key's own record and no other**. With `persist_addresses` off the new front address lives in the run's memory and marks no write; with it on, a new front address is a change to save, under rule 6's `save_interval`. *Why:* a device that moved was told to its peers only through a live link, and the IP the peer reported was kept in memory only (§17D.2 rule 4's reported IPs): after the peer restarted, its record still held the old address, and neither side could start the link again (round 9, F4). The record's address is the one a restart reads, so it is the one that is kept up to date; the IPs §17D.2 rule 4 keeps "in memory only" are those no kept address is at (a direct path's far end), and the source IP of an accepted link is no longer among them, since the record holds it. *The story (F4):* Ann is at 10.1.0.1 and moves to 10.2.0.1; Bob restarts after the move; Ann's redial of Bob is admitted by Bob's mirror grant (§8.7 rule 16) as a link for her folder; Bob's record of her becomes `[10.2.0.1:P, 10.1.0.1:P]` with the same port `P`, written (rule 6), and Bob dials `10.2.0.1:P` after his next restart whether or not a link is up.

### 17C.3 What a contact is

The memory subscribes to the links' events (§17A.3). **An address is learned** when a path of a link is admitted (`Up`) with these all true: it is a link, not a direct path; an identity admitted it; the peer's device is known from that identity; the peer is not one the host lists or a namespace relay (a peer this device dialled by a code's hint, §13.3, and the memory's own redials are *not* host-listed: the join's identified link is how a joiner learns its inviter); and rule 3 holds for the contact (with the record's `origin`, else the link's direction). What is kept of the address is rules 1 and 7: the address of a link this device dialled, or, for a link the peer opened, the IP it came from with the port the record holds (the whole source address only for a record with neither address nor port). A contact is also noted when a link **ends** (`last_contact`), and while a link is up every `expires / 8`. Addresses are IPv4-mapped IPv6 addresses shown as IPv4, and an address with port 0, unspecified, multicast or broadcast (and, unless `include_local`, loopback or link-local) is not kept. A record loaded from the store is cleaned the same way, its addresses cut to `addresses_max`, the newest of two records of one key kept, and the records beyond `peers_max` (the least recent) and those expired are dropped and removed from the store. With `persist_addresses` off the addresses a store holds are not read (a record is read without them and rewritten without them), and a record is written without them: a peer is then redialled in the run that learned its address, and after a restart waits for its next contact.

### 17C.4 The node's store (`DeviceMemory`)

With the cargo feature `introductions`, `DeviceMemory::new(store)` keeps one record per key as one **note** in the `DataStore` of an `ndn-heap` node (`Node::store()`, heap.md §10.2): the value of the name `/localhost/ndn-link/memory/<key>`, a prefix no device serves, `<key>` the peer's key fingerprint in 64 lowercase hex digits. The value, version 2 (a version 1 value, which has no last row, is read too, with no port), big-endian:

| octets | |
|---|---|
| 1 | version `2` |
| 1 | origin: `0` this device dialled, `1` the peer dialled in |
| 8 | last contact, seconds since the Unix epoch |
| 32 | the key fingerprint |
| 2 + *n* | the device name as a Name TLV, *n* octets |
| 1 + … | address count (≤ 255), then each: `4` or `6`, the address (4 or 16 octets), the port (2) |
| 2 | the peer's last-known listening port, `0` for none (version 2 only) |

A reader MUST refuse, without panicking, a value that is another version, ends short, has octets after the last address, has a bad origin or address family, a time that does not fit, or a name that is not a Name; the record is **dropped**, and so is a record whose key is not the one its note is named by (a record is only ever read as the key it names). The notes that cannot be read are removed from the store, behind. A note is written behind the store's barrier (`DataStore::sync`: `save` and `remove` return once it passed, on a blocking thread unless the store says its barrier is immediate), so a record saved survives a power loss; it lives in the node's own store and is never served, announced or trusted. A key of a note is 1 to 64 octets with no `/` and no control character, a value is at most 4,096 octets, and the memory holds at most 1,024 notes: a `save` that breaks one of these, or would add a 1,025th, is refused saying which rule and what to do, and writes nothing.

`LinkMemory::load_listen_port` and `save_listen_port` are kept by `DeviceMemory` as one more note of the same prefix, key `listen-port`, value the port in 2 octets, big-endian (never served): `save_listen_port(None)` removes it, and it is written and removed under the same durability and the same `persist_addresses` option as the records (§17D.2). `load` skips that note (it is no record); a `listen-port` note that is not 2 octets is dropped as an unreadable record is, and reads as no port.

### 17C.5 The report

`LinkReport::memory` is `None` until `remember` is called, then `Some(MemoryReport { peers, store_error })`: each remembered peer's record and what this device does about it (`Linked`, `Dialling`, `Redialling { within }`, `WaitingForAddress`, `NotDialled { why }`, `NoPath { why }` (§17D.2), `Offline` (§17D.1)), most recently in contact first. The entries the redials keep as peers (rule 4) also appear among `links` like any peer entry, labelled with the device name.

### 17C.6 Threat notes

- **Stale or hostile addresses.** An address in a record is where to try, nothing more. The handshake accepts only the holder of the key (§3.4), so an address that another key answers at costs **a failed dial and no link**, and that device learns of this device only the TLS handshake of a dial it cannot complete. The cost is bounded: at most `addresses_max` dials per peer per attempt, in one race of `MESSAGE_DEADLINE`, at most `dials_at_once` peers at a time, under the backoff of `MemoryOptions::redial` (default 500 ms doubling to 30 s). A peer that opened a link chooses the **IP** a record keeps for it (rule 7), but only a peer whose key the handshake proved, that an identity of a held namespace admitted and that rule 3 lets this device dial; only for **its own** record, at the port that record already holds, never at a port of its choosing; and within `addresses_max` (its oldest address goes), under rule 1's filter. So a hostile peer of that kind can put an IP of its choosing at the front of its own record, which costs this device one failed dial per attempt if the IP is not the peer's (the handshake expects the peer's own key, and whoever answers there holds another), and it moves no other key's record. A source address forged on a datagram cannot reach `learn`: QUIC validates the path before the handshake finishes, and the key is proven by the handshake before anything is learned. **A store that someone can write** can plant up to `peers_max` × `addresses_max` addresses: none that is loopback, link-local, unspecified, multicast or broadcast is read (rule 1; 169.254.169.254, the cloud metadata address, is link-local), and the rest are dialled `dials_at_once` peers at a time, never 256 Initials at once. A planted address that is public or private costs a failed handshake, bounded as above.
- **Persistence of a removed peer.** A record outlives the peer's membership: a removed member's key is still in the store. It cannot link it back: rule 3 refuses to dial it once no held context or live grant covers it (a grant ends with the members record, §8.7), and rule 4 refuses to admit it by its key whoever dials. The record is dropped at expiry, or at once by `forget`; a host that removes a member SHOULD call `forget`.
- **A tampered store.** The store holds keys (public), device names and addresses: nothing secret. A party with write access to a device's local store already holds the device. What it can do: add addresses (failed dials, bounded as above, and none of the kinds rule 1 refuses), add or change keys and devices — the handshake then proves the key and rules 3 and 4 decide, so a planted record admits no one and dials only a device a held context admits; change `origin` from `Accepted` to `Dialed` — which lets this device dial a peer in a held namespace that dialled it first: a dial, still admitted only as an identified device. Garbage is dropped (§17C.4). The store is not integrity-protected by this crate; a host that needs that gives a `LinkMemory` that is.
- **The store is in the clear.** A record names each peer's key, its device name and the addresses it was last reached at, and anyone who can read the store reads who this device talks to and where: the **permissions of the file or database the store lives in belong to the host** (the device's user only; `DeviceMemory`'s notes are in the node's own store). Nothing in it is a secret, but it is not nothing. A host that does not want the addresses on disk sets `MemoryOptions::persist_addresses = false`: the records then hold the key, the device and the last contact only, and the addresses a store held before are rewritten out of it.
- **A flapping peer.** An authenticated peer that reconnects again and again from the same IP (honest, or one that dials from a new port each time) changes nothing the store holds: the source port is never recorded and an IP already at the front is no change (rule 7). One that comes from a new IP each time changes the front address, and the record is written at most once per `save_interval` (rule 6), with the oldest address leaving at `addresses_max`: flash wear and one fsync per reconnect are not on offer.
- **Address freshness is a hint, and costs at most a failed dial.** A new front address that is wrong costs one failed dial within the bounds above (the handshake still proves the key); it moves **only the proven key's own record**; it is the IP and never the port; the store is written at most once per `save_interval`; and under `persist_addresses = false` nothing of it reaches the store.
- **An accepted link and another peer's record.** A link another key opens makes or updates that key's record and touches no other: the record is keyed by the key the handshake proved (rule 1), and an unidentified or unproven peer is never learned (the gate is `LinkEvent::Up { identified: true, kind: Link }`: a refused link emits no `Up`, so a stranger leaves no record in memory or in the store).
- **A flood of peers.** `peers_max` bounds the records, and a record is made only for a peer a held namespace's identity admitted *and* that rule 3 lets this device dial (an open relay does not fill its memory with strangers: a device of a held namespace it is not in, with no grant, is not remembered).
- **Redial storms.** One loop per record, so at most `peers_max` loops, of which at most `dials_at_once` dial at the same time (rule 2); each waits its backoff; a link that comes up and is gone at once waits too.

### 17C.7 Conformance cases

`tests/memory.rs` (real QUIC, real forwarders, real data-layer devices): two hosts joined by a code restart over their stores and keyrings and link and sync again with no relay, no peer entry and no list (Bob redials Ann from his device's notes; Ann accepts him by the grant her device re-derives); a fresh record is dialled at start and linked as an identified device; an expired record is not dialled and is removed; `forget` removes durably and ends the redial; a record whose namespace is not held is not dialled until it is; an address another key answers at is a failed dial and no link; a peer with no address waits and learns one when the peer dials in; a remembered peer whose grant was revoked is refused saying so and the inviter does not dial it; a removed member's remembered key is refused, also after a restart; notes that are not records are dropped; a store with 64 peers of 4 loopback addresses each is dialled not at all by default, and with `include_local` four peers at a time (the planted addresses are 256 UDP sockets that count the Initials they receive). Unit tests of admission (`a_remembered_peer_is_never_admitted_by_its_key_alone`, and its siblings) pin rule 4 against the same entry listed by a host, which is admitted by its key; those of `memory.rs` pin rule 1's address filter and rule 7's accepted-link rule (`loopback_and_link_local_addresses_are_not_kept`, `an_accepted_link_brings_the_address_up_to_date_with_the_held_port`, `a_record_with_no_port_uses_the_port_of_its_first_address`, `an_accepted_address_is_held_within_the_bound`, `an_accepted_address_asks_for_no_write_when_addresses_are_not_persisted`, `a_loopback_source_is_kept_only_where_the_host_says_so`, `a_link_another_key_opened_leaves_this_record_untouched`, `the_source_port_of_an_accepted_link_is_never_recorded`, `an_accepted_link_from_a_held_ip_changes_nothing_whatever_its_source_port`), rule 6's write interval (`a_peer_that_links_a_hundred_times_costs_few_writes`) and `persist_addresses`; `peer.rs` pins that a remembered peer's entry in a lower slot never hides the entry a host listed for the same device. The real-link cases of rule 7 (F4, clean and faulty; the source port; the peer a key refuses; a link of another key) are `tests/mirror.rs` (§8.9).

## 17D. Online, the listening port, and a change of address

*(Numbered 17D like §17A–§17C. Nothing in it is on the wire: no TLV is registered or changed, and the registry of §5.1 is unchanged. Everything here is local to a device.)*

An embedded host (a desktop program, a phone) goes offline, restarts, and moves between networks. It MUST NOT have to stop and restart its links, keep a port, or poll its interfaces for this: the state is held in `Links`.

### 17D.1 Offline and online

```rust
impl Links {
    pub fn set_online(self: &Arc<Self>, online: bool);   // default: online
    pub fn is_online(&self) -> bool;
}
```

1. `set_online(false)` MUST close every link and every direct path now, with `CloseReason::Shutdown` and the words "this device went offline; it links again when it is back". The other device therefore sees `link-closed-by-peer` with those words, never `grant-ended`.
2. While offline a device MUST take no inbound attempt: each is dropped before its handshake and unanswered (`LinkEndpoint::set_accepting(false)`, quinn's `Incoming::ignore`: not a refusal; the dialling device's handshake times out); a handshake that began before and ends after is refused, or closed once registered. It MUST make no attempt of any kind: no dial (`dial_loop`, the memory's redials, `dial_by_key`, `dial_first`), no punch and no answer to a punch, whatever the host asks (`connect`, `network_changed`) and whatever the backoff says. No datagram leaves for a link (a test counts QUIC Initials on a UDP socket every dial would hit: zero).
3. `watch()` MUST show every peer that is down with `Next::WhenOnline` and the `offline` code (§17A.1 item 6); a remembered peer's state is `RememberedState::Offline`.
4. `set_online(true)` MUST wake every loop at once: each peer, remembered and configured, is dialled with no backoff, and the dials take their turns at `dials_at_once` (§17C.2 rule 2; a configured peer's first dial after waking takes a turn at the same limit); punches are made again and candidates are gathered again (a gather reads the sockets as they are). A cycle repeated with the same memory leaves no state in the host: the same peers, records and link faces.
5. A watcher of a device that is offline MUST NOT be told a peer is `Gone` because its link closed: a one-shot peer is dialled when the device is online again.
6. A handshake already begun when the device went offline ends by its own handshake timeout (its Initial may be retransmitted until then); none begins after.

### 17D.2 The listening port

1. `LinkMemory` keeps the port the host's link socket listens on (`load_listen_port`, `save_listen_port`; **required**: a store that cannot keep it says so by an error, and the report says the port is not remembered). `DeviceMemory` keeps it in its local notes (§17C.4). It is kept under the same durability and the same `persist_addresses` option as the records: with the option off no port is written, none kept before is read, and one written before is removed at `remember`.
2. At `Links::remember`, before any redial, when the host's socket listens and its port differs from the kept one, `Links` MUST bind the kept port again when it is free (a socket on the same IP and port, `LinkEndpoint::rebind`) and otherwise keep the port it has and **keep that** (write it). A kept port that is 0 or below `LISTEN_PORT_MIN` (1024) MUST NOT be a bind target. When the port in use is not the one the peers knew, `Links` announces (presence) and punches again, and the candidates of the next punch carry the port in use.
3. `PeerRecord::port` is the listening port of the peer's last contact: the port of a link this device dialled or of a direct path; the source port of a link the peer opened only fills a record that holds neither a port nor an address (a first contact: it is the peer's own choice, §17C.2 rules 1 and 7). It is kept in `DeviceMemory` (record version 2) and dropped under `persist_addresses = false`.
4. A contact that reports an IP address for a remembered peer that no kept address is at (the far end of a direct path; the source IP of an accepted link is, in practice, no longer one of them: §17C.2 rule 7 puts it into the record itself, at the front with the record's port, where a restart finds it) makes the redial also dial that IP at the record's port, before the kept addresses; at most `REPORTED_MAX` (2) such IPs are kept per peer, **in memory only** (they are the run's, never written to the store), never loopback or link-local unless `include_local`. Two devices that both restart on new ports find each other through a relay both use (their links to it carry the new addresses; the punch by membership is made even for a device only the memory has an entry for, and its direct path teaches each record the other's port), or by the other's next dial.
5. **No path.** When every address kept for a remembered peer failed and no relay that both devices use is linked (a relay that lists the peer in its presence, §14.9, and whose link is up), the report says so: `RememberedState::NoPath { why }` and, in `watch()`, `no-path` with `Next::WaitingForAddress`. The words say what to do: the peer reaches this device when it dials this device's current address, or when both link to a relay. It is a statement, not a retry loop: the redial backoff is unchanged.

### 17D.3 A change of address

```rust
pub struct AddressWatch { pub poll: Duration /* 5 s */, pub enabled: bool /* true */, pub removal_persists: Duration /* 3 s */ }
pub trait AddressSource: Send + Sync + 'static { fn addresses(&self) -> Vec<IpAddr>; }
impl Links {
    pub fn watch_addresses(self: &Arc<Self>, watch: AddressWatch);                       // reads the interfaces
    pub fn watch_addresses_from(self: &Arc<Self>, watch: AddressWatch, source: Arc<dyn AddressSource>);
}
```

1. `Links::start` MUST start a watcher with the defaults. It reads the device's address set (`AddressSource`; by default the interfaces that are up, loopback and link-local excluded, and on Linux the IPv6 addresses the kernel marks **deprecated, temporary, tentative or failed duplicate detection** excluded too, read from `/proc/net/if_inet6`: addresses nothing lasting is bound to; where the platform says no such flag, every address is in) every `poll` (at least `ADDRESS_POLL_MIN`), and, on Linux, when a netlink subscription (`NETLINK_ROUTE`, `RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR`) says an address changed. The subscription is read by the runtime (`AsyncFd`) and not by a thread of its own, which could not be stopped; the poll is the backstop. The interfaces are read **at most once per `ADDRESS_COALESCE`**, however many notices came (a flood of notices costs a read a window); a subscription that breaks is logged with its error, the poll reads alone, and the subscription is opened again at a poll; a read of the set that fails is logged and tried again at the next poll, so the watcher never stops of its own. The watcher reads the interface list only: it makes no network I/O and never blocks the links.
2. A change of the set MUST do what `network_changed(None)` does (§14.7): dial-only sockets move, every remembered and configured peer is dialled again at once (staggered, §17D.1 item 4), punches are made again, presence is announced. The links this device **accepted** are closed too, but **only those accepted at an address that went** (the local address the peer's packets arrived at, `LinkHandle::accepted_ip`: the destination address the system reports, else the socket's own address when it is a specific one), saying which address is gone (a QUIC server cannot follow its address, RFC 9000 §9: such a link is lost to both sides until an idle timeout). A link accepted at an address that stays is not touched, nor is one whose address is not known (a socket on every address on a system that reports no destination address): it ends at the idle timeout or by the other device's dial, as any lost link does. An address only added closes none. The host's `network_changed` says only that the network changed, not what, and closes the accepted links always; a platform callback and the watcher together are one change.
3. A change is acted on `ADDRESS_COALESCE` (500 ms) after it was noticed (those that follow are the same), at most `ADDRESS_BURSTS_PER_MINUTE` (6) times in a minute (the rest merge into the next), and not while offline (the set is noted; going online redials from where the device is). **A removal is acted on only once the address has stayed gone for `AddressWatch::removal_persists`** (`ADDRESS_REMOVAL_PERSISTS`, 3 s by default; zero acts at the first read that finds it gone): an address back within the window is no change, and the window runs from the first read that found it gone. An address added is acted on at once and does not wait for a removal that is still waiting; the removal then follows as a change of its own.
4. A new link of a device that this device already holds a link to, registered more than `DIAL_RACE_WINDOW` after the old one, replaces it whichever side dialled (§6.3 keeps the link of the smaller fingerprint only for dials that raced): the old link is one the other device lost, which is what a moved device's redial meets.

### 17D.4 Threat notes

- **The port memory.** One `u16` in the device's store and each peer's last-known port: no secret, in the clear like the addresses and under the same `persist_addresses` option. A tampered store changes only where to *try*: the handshake still proves the key. A port below 1024 or 0 is refused as a bind target.
- **Reported IPs.** A contact's IP that no kept address is at (a direct path's far end) makes this device dial that IP at the peer's port: at most `REPORTED_MAX` per peer, only for peers rule 3 of §17C.2 lets this device dial, after a completed handshake that proved the key (the IP cannot be spoofed past it), and a failed dial costs no link. The source IP of an accepted link is the record's own front address (§17C.2 rule 7, with the same bounds).
- **The redial storm.** One burst per change, coalesced, at most 6 a minute, behind `dials_at_once` and the dial backoff; a hostile local actor that flaps interfaces costs a bounded number of handshakes a minute, which it could by dialling ahead.
- **Address churn from the network** (a router advertisement that makes the host create and expire short-lived SLAAC addresses, a VPN that flaps, privacy addresses that rotate). Three things bound what it costs, in this order: the addresses the kernel marks deprecated or temporary are no part of the set (rule 1); an address that is gone and back within `removal_persists` is no change (rule 3); and what a removal closes is the links accepted **at that address**, never the others (rule 2), so churn of addresses no link uses leaves every link up. What it can still do is the redial of rule 2, bounded as above. Where the platform tells no flag (not Linux), the first protection is absent and the other two stand.
- **Offline.** An offline device is not a participant: no attempt, no answer, no packet for a link.
- **Replacing an older link.** The new link is proven by the same key as the old one; replacing it lets no one in, and a flood of dials is bounded by the handshake limits (§13.2).

### 17D.5 Conformance cases

`tests/online.rs` (real QUIC, real devices): offline closes every link, makes no attempt even when asked, answers no inbound attempt, and online links the remembered and configured peers again from the same memory; five cycles keep no state in the host; online redials a few peers at a time; the kept port is bound again when free, another is used and kept when it is taken, none is kept under `persist_addresses = false`, 0 and below 1024 are not bind targets; a reported IP is dialled at the record's port; no path is reported; words typed after a laptop moved cross within a redial (F4: a controlled address source, and in a user and network namespace with real interface addresses and netlink); an address that no accepted link was accepted at goes and the accepted link stays (the first link is the same face after, none was made); the address a link was accepted at goes and the link closes; an address that is gone and back inside the persistence window changes nothing; a read of the addresses that fails (the source panics) does not stop the watcher; in a network namespace, 300 netlink notices in a burst cost at most a handful of reads of the interfaces, and a deprecated IPv6 address is no address of the default source. `tests/memory.rs`, `memory`/`device_memory` unit tests: the port round trip, a version 1 record, the option. Unit tests of the watcher: what is due and when (an address added at once, one removed only after the window, one that returns never), the flags of `/proc/net/if_inet6`.

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
| `LINK_SOCKET_BUFFER` | 4 MiB asked of the kernel for each link socket's receive buffer and send buffer (granted up to its `rmem_max` / `wmem_max`) | §5.4 |
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
| `ChannelCaps` | TLV-TYPE 0x044E, one byte; bit 0 = channel frames v1 | §5.2 |
| channel marker | first octet `0x00` | §9 item 7 |
| `QUEUE_FLOOR` / `QUEUE_CAP` / `DATAGRAM_SEND_BUFFER` | 128 KiB least and 512 KiB most of channel-datagram headroom (a millisecond of the send rate between them) / the connection's 1 MiB datagram send buffer | §9 item 7 |
| `STREAM_FRAME_MAX` / `STREAM_QUEUE_MAX` | 1 MiB per channel stream frame / 4 MiB queued in front of the stream's writer (and 4 MiB held for a face's reader) | §9 item 7 |
| `FAIR_CAPACITY` / `FAIR_FLOOR` / `FAIR_INTERVAL` | 128 MiB/s least pool contending links divide, each way (not a ceiling: a lone link takes no bucket and a pool whose links carried more divides that, `carried`) / 256 KiB/s least for an active contending link / 1 s window (activity, rates, the `carried` mark measured and decayed by 0.9 per window) | §9 item 9 |
| fragment overhead reserve | 50 bytes | §9 |
| `max_datagram_frame_size` advertised | 65 535 | §3.1 |
| handshake limits | 64 / 4 per IP / 8 refusals within 60 s → 60 s | §13.2 |
| shutdown grace | 1 s | §6.1 |
| `WAKE_TOKEN_MAX` | 1024 bytes | §5.6 |
| `PRESENCE_MAX` | 256 devices per Presence | §5.7 |
| presence namespaces kept per link | 256 | §5.7 |
| `DEPARTURES_MAX` | 16 folders told to, and heard from, a peer on one link | §5.9 |
| departure `hold` / `settle` | 30 s / 2 s (`DepartureOptions`) | §8.8 |
| departure `attempts` / `marks_max` | 3 departure links per key per mark / 256 marks (`DepartureOptions`) | §8.8 |
| `TAKEN_PER_LINK_MAX` | 32 departures a link's sink takes over the link's life | §8.8 |
| ended grant entries remembered | 64, one per (key, folder) | §8.7 |
| `departure_for` (`ndn-invite`, `IntroPolicy`) | 7 days by default; zero makes no mark | §8.8, invite.md §11 rule 14 |
| `MEMBERSHIPS_MAX` | 8 memberships sent and used per hello (one per namespace); 1 per punch message | §5.2, §5.8, §14.3 |
| `FOLLOWS_MAX` | 32 space groups named, and used, per hello | §5.2, §5.10, §13.6 |
| `FOLLOW_DEPTH_MAX` | 13 components of a followed group's name: an owner namespace of at most 8, `32=sync`, the space's at most 4 | §5.10 |
| `FOLLOW_SPACE_MAX` | 4 components after `32=sync` in a followed group (a space's name under its owner) | §5.10 |
| membership exporter | label `EXPORTER-ndn-link/1 membership`, empty context, 32 bytes | §5.8 |
| binding transcript | `ndn-link/1 membership` 0x00 ‖ link key fingerprint ‖ channel binding ‖ SHA-256(certificate): 118 bytes | §5.8 |
| punch channel binding | SHA-256(`ndn-link/1 punch` ‖ session) | §5.8, §14.3 |
| `Quotas` default (strangers) | 256 links, 32 per namespace, 100/s (burst 200) per key, 400/s (burst 800) per namespace | §15.3 |
| `GRANT_FRAMES` / `GRANT_BYTES` / `GRANT_INTERESTS` / `GRANT_ANSWERED` / `DATA_ASKS` (per grant link) | frames burst 65,536, 32,768 a second; bytes burst 64 MiB, 32 MiB a second; Interests burst 16,384, 4,096 a second; answered bytes burst 64 MiB, 16 MiB a second; `32=grant` asks burst 256, 16 a second | §15.3 |
| `GRANTS_FRAMES` / `GRANTS_BYTES` (all grant links of a namespace) | frames burst 262,144, 131,072 a second; bytes burst 256 MiB, 128 MiB a second | §15.3 |
| `CONGESTION_NACKS` (per link) | burst 256, 128 a second | §8.3 rule 7 |
| `RelayOptions` default | count 1, namespace relays on, mode `always`, no hold | §15.5, §15.6 |
| `DirectOptions` default | membership on, `max_paths` 8 | §14.8, §14.9 |
| member / bounded punch recheck | 5 s | §14.1, §14.9 |
| on-demand idle check | `idle` / 4, within 250 ms – 30 s (other links: 60 s) | §16.2 |
| `DEMAND_PER_PEER` / `DEMAND_TOTAL` | 64 / 1024 | §16.3 |
| default InterestLifetime at the waiting face | 4 s | §16.3, §17.3 |
| `HoldLimits` default | 64 per device, 4096 in total, 60 s | §17.3 |
| `asleep_max` default | 24 h | §17.2 |
| `WAKE_INTERVAL` | 30 s | §17.4 |
| `LINK_STATES_MAX` | 256 peers in the status table | §17A.2 |
| `MemoryOptions` default | 64 peers, 4 addresses each, expire after 30 days without contact, redial with the dial backoff, 4 peers dialled at once, no loopback or link-local address, addresses persisted, a record written at most once in 60 s | §17C.1 |
| link memory record | version 2 (version 1 is read), 32-octet key, ≤ 255 addresses, a 2-octet port | §17C.4 |
| `ADDRESS_POLL` / `ADDRESS_POLL_MIN` | 5 s default / 1 s least, the interval at which the device's addresses are read | §17D.3 |
| `ADDRESS_COALESCE` | 500 ms: changes of the addresses within it are one change | §17D.3 |
| `ADDRESS_BURSTS_PER_MINUTE` | 6: the most changes of the addresses acted on in a minute | §17D.3 |
| `ADDRESS_REMOVAL_PERSISTS` | 3 s: an address must stay gone this long before its removal is acted on (`AddressWatch::removal_persists`) | §17D.3 |
| `LISTEN_PORT_MIN` | 1024: a kept port below it (or 0) is never a bind target | §17D.2 |
| `REPORTED_MAX` | 2 IP addresses reported by contacts, kept per remembered peer | §17D.2 |
| `DIAL_RACE_WINDOW` | 10 s (= `MESSAGE_DEADLINE`): a link registered longer ago than this is not the other half of a simultaneous dial | §6.3, §17D.3 |
| `JOINED_ROUTE_COST` | `VIA_RELAY_COST` + 1000 = 1010: the cost of a joiner's route, above every route of a real path **to the same prefix** (cost decides only among routes of one prefix; the filter of rule 18 item 3 is what keeps a joiner's route from taking a name from a better one) | §8.7 rule 18, §10 |
| `JOINED_ROUTES_MAX` / `JOINED_FOLDERS_MAX` | 64 distinct namespaces (each with its sync group for a writer-role joiner: at most 128 routes) / 16 folders routed over inviters' links (`Links::set_joined_routes`), each inviter key an equal share of both | §8.7 rule 18 |
| `JOINED_WRITERS_MAX` (`ndn-invite`) | 16 other writers' namespaces per joined folder (`JoinedFolder::writers`) | §8.7 rule 18, invite.md §11 rule 18 |

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

### 19.4 LinkHello with no certificate (14 B)

```
fd0450 0a        LinkHello, length 10
  fd0451 01 01   LinkVersion = 1
  fd044e 01 01   ChannelCaps = bit 0 (channel frames v1)
```
`fd04500afd04510101fd044e0101`

### 19.5 LinkHello with leaf and root (564 B)

```
fd0450 fd022e    LinkHello, length 558
  fd0451 01 01   LinkVersion = 1
  <leaf, 283 B, 19.3>
  <root, 265 B, 19.3>
```

The wire is `fd0450fd022efd04510101` ‖ leaf ‖ root ‖ `fd044e0101` (5 + 283 + 265 + 5 = 558). A receiver whose key is the TLS key of 19.1 passes step 3 of §7.1: the leaf's Content SPKI reduces to the raw key `8a88…6f5c`. The chain ends in the namespace's self-signed root, the form §5.2 asks for. The hello ends with ChannelCaps (19.4); a hello without it (a sender that predates the field) is read as no capability.

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
| scope Nack, Congestion (§8.3 rule 7) | `6424fd032005fd0321013250190517070f0804686f6d650802434108034e45570a0401020304` |
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

### 19.13 LinkHello of a direct-path dialer with no certificate, session 01…08 (26 B)

```
fd0450 16              LinkHello, length 22
  fd0451 01 01         LinkVersion = 1
  fd045a 08 0102030405060708   DirectPath
  fd044e 01 01         ChannelCaps
```
`fd045016fd04510101fd045a080102030405060708fd044e0101`

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

### 19.20 Departure

A `Departure` (§5.9) for the folder `/a/32=data/n` and the members record `/a/d/32=log/n/seq=3` (a SequenceNum component, type 0x3A), 37 bytes: the 4-byte header (`fd 04 4c`, TLV-LENGTH 33), the 14-byte Name of the folder, the 19-byte Name of the record:

```
fd044c21
070c 0801 61 2004 64617461 0801 6e
0711 0801 61 0801 64 2003 6c6f67 0801 6e 3a01 03
```

Line breaks and spaces carry no meaning. The hex is the encoder's output, asserted literally by `departure_matches_the_spec_vector_round_trips_and_is_read_strictly` (Q/message.rs), which also asserts the header, the length and that the value is the two Names' encodings in that order, and that a value of fewer than two Names, of a third Name, of an unknown odd type (`fd 04 4f 00`) or of a malformed Name is refused while an unknown even type above 31 (`fd 04 4e 00`) is skipped.

### 19.21 LinkHello with Follows

A hello with no certificate that follows the groups `/a/32=sync/x` and `/b/c/32=sync/y/z`, 52 bytes: the header (`fd 04 50`, TLV-LENGTH 48), LinkVersion, then Follows (`fd 04 56`, TLV-LENGTH 34) with the 14-byte Name `/a/32=sync/x` (components `08 01 61`, the keyword `20 04 73 79 6e 63`, `08 01 78`) and the 20-byte Name `/b/c/32=sync/y/z`, then ChannelCaps:

```
fd045030
  fd04510101
  fd045622
    070c 0801 61 2004 73796e63 0801 78
    0712 0801 62 0801 63 2004 73796e63 0801 79 0801 7a
  fd044e0101
```

Without the breaks: `fd045030fd04510101fd045622070c080161200473796e630801780712080162080163200473796e6308017908017afd044e0101`. The hex is the encoder's output, asserted literally by `a_hello_follows_is_even_names_and_an_older_receiver_skips_it` (Q/message.rs); `a_hello_carries_channel_caps_and_an_older_hello_has_none` asserts 19.4, that a hello of an older sender (no field) reads as no capability, that bits this side does not know are kept, and that a field of any length but one is malformed. `a_hello_follows_is_bounded` asserts that a Follows of more than 32 Names is read as its first 32 and that a sender names no more. `a_hello_follows_names_exact_groups_and_refuses_what_is_not_one` asserts that a namespace (`/a`), the owner's whole group (`/a/32=sync`), a group with an empty owner, with more than 4 components after the keyword, with another keyword or a non-generic component in it, and one of more than 13 components are refused (0x15), as are the root, a value with no Name and a TLV that is not a Name inside it, that an unknown even type above 31 beside it is skipped, and that a sender leaves such names out rather than make its own hello malformed.

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
24. **Idle is measured in datagrams and channel stream bytes** (§16.2). Keep-alives and control messages do not count, so an on-demand link closes when its traffic stops, whatever its keep-alive; the NDN datagrams, the channel datagrams and the octets of channel frames on the stream do. The close is 0x05, so the other side's log says the device went to sleep by choice; a relay counts the device asleep after any end of its last path, a broken one included (§17.2).
25. **Waiting Interests go out past the forwarder** (§16.3, §17.3). The forwarder already sent them to the waiting face and keeps their pending entries; sending them over the link's face directly needs no second forwarding decision, and the Data that comes back matches the pending entries by name.
26. **Held Interests and wakes live in memory, bounded** (§17). A relay keeps no state for sleeping devices across restarts; devices register on every link, so a restart costs one relink. The notifier gets the device's name, key and token and a count, never Interest names, and at most one wake per 30 s per device, so a stream of Interests cannot become a stream of pushes.
27. **Presence travels on the control stream** (§14.8), not as signed records or in a sync group: the stream is authenticated by the link's handshake and admission, reaches only the members the relay admitted, filtered per role, says who is linked now, and costs nothing while nothing changes. Presence never carries addresses.
28. **The smaller fingerprint punches members; direct paths are bounded** (§14.8, §14.9). The same order as the dial (Decision 17) means two members never punch each other at once. `max_paths` bounds the state and keep-alives of direct paths; recent traffic only breaks ties among members membership already qualifies, and an answerer at its bound refuses with 0x16 so the punching side backs off.
29. **Control messages after the verdict** (§5.6, §5.7, §5.9) use the even types 0x0440–0x044C, so receivers that predate them skip them. The latest of each (per namespace for Presence, per folder for Departure) replaces what was sent before, at the receiver and in the sender's queue, so a slow reader costs no memory.
30. **Served namespaces are carried in transit, unvalidated and uncached** (§15.7). A relay cannot validate the Data of a namespace whose trust context and certificates it does not hold, and fetching them would make serving depend on that namespace's infrastructure. Dropping that Data would make serving useless. Its consumers validate it end to end; the relay answers only pending Interests and caches nothing it could not validate, so it never serves unvalidated Data from its cache to a later requester. Validation is skipped only while a served link of that namespace is up, and never under a namespace the relay holds.
31. **A link carries every membership** (§5.8, §7.1, §7.3, §12). A device takes part in many namespaces, with a key in each. A link keeps one key per device (the node key, in TLS); each other namespace is shown as a Membership: that key's chain and its signature binding the link key to this connection. Alternatives were one link per namespace key (a second handshake and connection per namespace and peer, and two links between the same two devices, which the duplicate-link rule forbids) and the same key certified in each namespace (the roles layout gives each namespace its own key, and a key compromised in one would be in all). The binding covers the link key fingerprint, so a membership cannot be moved to another device's link, and the TLS exporter, so it cannot be replayed onto another connection; the receiver recomputes both from its own view of the connection. A forged or replayed membership refuses the link with a code of its own (0x1A), since an honest device never sends one. The peer is admitted by any identity the local policy accepts, and routes, presence, transit and revocation follow each identity: a revocation in A takes A from the link and keeps it up by C. Revocations are per namespace at admission too: a revoked leaf or membership refuses the link only when nothing else identifies the peer. Relays are chosen per namespace (`count` for each), so a device of A and C is reachable through a relay of each. Punch messages carry the membership of the namespace the punch is in, bound to the punch's session, while the PunchKey stays the link key that the direct path's handshake proves. The Membership is an even TLV-TYPE above 31, so a receiver that predates it ignores it and admits the device by its link key's certificate, as before; a device's hello without memberships is the hello of ndn-link/1 before them.
32. **A relay also routes the namespaces the device follows** (§10, §15.5). Two people's devices, each the root of its own namespace and each holding the other's trust context, reach each other through a relay both use without operator routes: the relay routes each linked device and its sync group, and each device routes the other's namespace (its devices and, by CHILD-INHERIT, its sync group) to the relay. A relay the namespace advertises does this as well as one the person added: the namespace's root chose it for the person's devices, so following someone needs no `[[relay]]`. The choice still counts certificate namespaces only, so following a namespace dials no more relays.
33. **A relay carries a served namespace's sync group and chain** (§10, §15.7). A community relay needs nothing per person: holding the trust contexts of the people it carries would be a setup step for each of them. So a served device's link routes its namespace's group like a held one's, and while the namespace is in transit the relay runs the group with the multicast strategy, as a forwarder holding it would. The strategy is an ordinary choice made by the host's library that knows the namespace is carried; the forwarder treats no name specially. It stays for a namespace the relay holds, whose trust-context library chose it. A relay holding a namespace validates its Data, fetching and caching the chain; a relay carrying it in transit does neither, so the served device's link routes the key names of the issuers its hello showed, and consumers fetch the chain from the device. A namespace-wide route was the alternative; it would send every Interest under the namespace to whichever served device the strategy picks.
34. **A followed namespace is routed at once; a relay is reachable by its name** (§10, §15.5). Two people who meet by an introduction code adopt each other's trust context while linked: routing a namespace followed later only from the next link path to the relay left them unreachable until a relink nobody asks for. The routes of a link path therefore follow the keyring on every adoption, as revocations already did (§12). Before adopting, a device reaches the other only by naming a relay both use, in a ForwardingHint: the generic NDN mechanism, with the relay's own name routed over its link and each forwarder stripping a hint that names one of its own device names or a name under one; the alternative — a route per namespace announced by the relay — would make a community relay keep state per person (§15.5 "What the relay needs"). The device names are not NFD producer regions: under NFD's rule a hint naming an ancestor of a region has reached it, so a hint `<ns>` toward the namespace's CA (a renewal's certificate fetch) was stripped at the renewing device itself, which then had no route for its own new certificate.
35. **A stranger gets an introduction link, and the dial is by key** (§7.3 rule 8, §8.6, §13.3). An embedded device with no daemon has no relay and no route to a stranger, yet an introduction needs a path to the inviter's device before either side trusts the other. The alternative — a peer entry for every possible joiner, or an unauthenticated listener — would make the inviter either unreachable or open: the introduction link is open to the one exchange only, within the enrollment links' slots and rates, and carries nothing a stranger could not ask of the device by name. The key in the code authenticates the inviter (the handshake proves it); the addresses are only where to try (invite.md §18). Every address is tried at once so one dead address costs no more than the handshake timeout, and the first link whose handshake proved the key wins.
36. **The grant is the tighter choice, and it is consulted only where the policy declines** (§8.7). An inviter keeping `own` still links with the one person it introduced: the grant names a key and the namespaces it may link as, ends with its date, a revocation or the person's removal, and never widens the policy, the quotas, a revocation or a namespace's link policy; under `open` it changes nothing. The round-4 advice to choose `open` or `listed` is withdrawn. A reader's link carries Interests and the answers under its own device names, not Interests alone: the layer fetches a reader's certificates and its seal by name (§8.7 rule 5).
37. **A person let go is told on a narrow link, by a hint with no authority** (§5.9, §8.7, §8.8, §13.5). A device that was removed from a folder saw only a closed link, and one that was offline when the record was written had nothing to go on. The alternatives were to keep the link open (a removed member would keep a path to the inviter) or to close it and say nothing in the link (the host would need a side channel). The link instead narrows in place, or a returning device is admitted on a departure link, to carry **one signed record** and the names that validate it, within the enrollment links' slots and rate, for at most `hold`, `attempts` times per mark and until the mark expires. The `Departure` message only names the record: the person's data layer fetches it and judges it by its signatures, so a hostile inviter makes a person fetch nothing but a members record of a folder it belongs to. A grant became a set of entries per key so that letting a person go of one folder does not close the link of another, and the pushes and the names a link carries are judged per packet against the live entries, so a role change or an entry's end takes effect at the next packet with no close.
38. **A grant is built at both ends, and the joiner routes its own forwarder** (§8.7 rules 16–19, §8.8 rule 13, §13.4–§13.5, §17C.2 rule 7). A grant that admitted the person at the inviter and nothing at the joiner left two things broken: the inviter's redial of a person who had restarted was refused by the person's `own` policy, and the person's forwarder had no route toward the other writers' namespaces the inviter's link carries. The joiner now holds the **mirror** of the grant, an ordinary entry of the inviter's key for the folder (no new admission rule, no wire change; it stands while the record in force lists the joiner, with the role the record gives the inviter), and its link layer installs the routes itself, over the inviter's identified full link only, from the folders its device joined. The alternatives were to admit the inviter by key alone (§17C.2 rule 4 forbids it) and to have the host forward routes (only the link layer knows both the link's face and the record, and a host keeps no link state). The routes are the writers' **namespaces**, at a cost above every real path so that a path to the writer's own devices wins; for a writer-role joiner also each writer's **sync group**, because the data layer registers that group with its own forwarder and the longest-prefix match would shadow a route at the namespace. The group is the writer-push route (notices and pushes), so a reader is routed the namespace only; a route is a path and never a right, and the inviter's filter decides. The other half of the relay is on the writer's side: a grant link also routes the person's public names (trust context, key and certificate names) when a live entry admitted it (rule 19), because the inviter's forwarder could not otherwise send the joiner's Interest for them toward the writer. A mirror never makes a departure mark: the inviter is the folder's owner and signs its records, and the person let go is told by her. The same round's address freshness (§17C.2 rule 7) lets a link an identified peer opens bring the record's IP up to date with the port it holds and never records the source port, so that a device that moved and a peer that restarted find each other.
39. **A first contact is dialled by address with no key, and the proved key only names the link** (§3.4, §13.3A). A short code has no key to put in the handshake. The alternatives were to put the key back in the code (32 octets: 24 words, the cost the short code exists to avoid) or to dial the address and trust the party. The dial instead accepts the key the handshake proves, adds the peer entry with *that* key and the introduction's routes only, and the join verifies everything the party serves against the code; the worst a wrong party at the address gets is a link that routes the introduction's three prefixes, taken down when the join fails.
40. **A wrong party at a first contact does no more than fail the join** (§8.6, §13.3 rules 3–5, §13.3A). Decision 39 left three things open that a party at the address with no key to prove could use. **The hello is empty** (no certificate, no membership): nothing vouches for the party, and the inviter answers a device with no certificate while an offer is open; an inviter that also admits enrollment links carries both errands on one link rather than preferring one, so enrollment through it keeps working while an offer is open. **What the party sends in is bounded**: answers under the routes and Interests under the joiner's own device names (a scope with `interests_in`, the mirror of `answers_in`), because the link is unvouched while the joiner's forwarder, which would ask the joiner's other links under the joiner's identity, is not. **The link is taken down when the verified record names another key**, not only when the join fails, and a link made again to a party that still shows no certificate of a namespace now held is refused: the link of a party no key vouches for must not outlive the join that proved it was not the inviter. The alternative for the first, preferring the introduction scope to the enrollment scope while an offer is open, would have stopped enrollment through an inviter for the hours an offer is open.
41. **A link's rate is by its kind, and an Interest dropped for rate is told so** (§8.3 rule 7, §15.3, round 12). One 1 MiB transfer over a grant link (256 piece Interests, 32 in flight) met the strangers' default quota (burst 200, 100 a second) and lost Interests silently, each waiting for its asker's timer (250 ms, doubling; 9,966 drops over 100 runs). The alternatives were to raise `Quotas::default` for everyone, which loosens what a stranger may send, or to give a grant link the strangers' numbers scaled up. The rates now follow what each link is: a link of the device's own namespace is never limited; a **grant link** (a member authenticated by its key, named by a signed grant, revocable) takes frame and byte buckets that an ordinary transfer never meets (65,536 frames and 64 MiB at once, then 32,768 frames and 32 MiB a second; the namespace's links together four times that), with the byte and frame buckets as the bound on a member that misbehaves; a **stranger** and an **introduction** link keep the tight ones. The grant link's numbers are constants of the link layer, not the `Quotas` the operator sets for strangers. An Interest dropped for a rate is answered with a **Congestion** Nack at once (not NoRoute, which says the route is missing), so the asker retries soon with a backoff instead of waiting for its timer; the Nacks of one link are themselves bounded (256, then 128 a second), so a flood is not answered with a flood. The link layer counts the frames it dropped for a rate and the Nacks it sent (`LinkReport`), which no host could read before. No wire change: the Nack is an LpPacket Nack with another reason code.
42. **A device tells its relay what it follows, and the relay routes the groups** (§5.10, §10, §13.6, §15.5). The re-founded data layer has one sync group for a space, `<O>/32=sync/<rest>` under the space owner's namespace; the old layer published into the group of every member's namespace as well. Two people through a community relay that holds neither namespace then lost one direction: Bob (who follows `/sa`) routes `/sa` to the relay and reaches Alice, but Alice's Sync Interests of her group leave her relay face and the relay had no route for `/sa/32=sync` over Bob's link (its routes there were Bob's device, his issuers' key names and `/sb`'s group). The alternatives were a route per namespace announced by the relay (the relay holds no context to announce from), a route the relay makes from every group it has ever seen (a table a stranger fills), or a route made by Bob's Interest (a state kept for a timer, which correctness must not depend on). The claim is told by the device, in its hello, once, to the relay it uses: a hello field costs no new message or state machine, binds the claim to a link the way memberships are, and goes with the link. It is not proved, because following is public (§13.6); what it buys is a route for a public group on a full link whose peer an identity admitted ([Decision 43](#20-decisions) narrows what it names to a space's exact group), at most 32 of them. The set changing relinks (as memberships do, §8.5): a short blip at a following or an unfollowing, which is rare, against a second message and its ordering rules; a later round may send the change on the control stream if devices are seen to follow and unfollow often. A grant link keeps rule 20's groups only, because the claim is the claimant's word and a grant is the owner's.
43. **A claim names a space's exact group, and the host says which spaces the device follows** (§5.10, §10, §13.6, §15.5; the stage-7 review's L2). Decision 42's first form named the followed *namespaces* and the relay routed `<ns>/32=sync`, the prefix of the groups of every space of the namespace: any identified peer of the relay that claimed `/x` received the Sync Interests of every space of `/x`, private ones included, with their devices and activity, though asking for one needs the space's name. The hello now names `<owner>/32=sync/<space>` for each space the device follows, and the relay routes exactly that prefix; a namespace and an owner's whole group are no group and make the hello malformed, so the claim cannot be widened by a sender, and a claim shows no more than the claimant could ask for. `ndn-link` knows no spaces, so it cannot derive the set from the trust contexts it holds (a context names a namespace); the layer that knows the spaces says: `Links::set_followed_groups(groups)` takes the whole set, refuses it whole when a name is no group or more than `FOLLOWS_MAX` are given (a silent truncation would leave a space unrouted with nothing saying so), and relinks the relays whose hello told another set. The data layer's group of a space is `ndn_heap::wire::sync_group_of`. A daemon runs the links and a data host runs the layer, in two processes, so the host says it over management: a mark of the group on `security/transit` (mgmt-trust.md "Transit"), which is owned by the connection that gave it and gone when it closes, as the transit marks are, carries nothing in transit, and is gated as they are (a local operator or a member of a transit group): the groups all faces mark are what the daemon's links set. The alternative of a verb of its own (`links/follow`) would have needed a gate, a release rule and a client of its own for what a mark already is. The device's own routes for a followed namespace (§15.5) stay namespace-wide: they are its Interests. The alternatives for the relay were to keep the namespace and let a filter drop the other spaces (the relay holds no names of the spaces to drop by: it would carry them to the claimant's face first), and to correct §13.6 to state the enumeration (a privacy loss with a cheap fix). Limits: a group is longer than a namespace by the keyword and the space's name, so `FOLLOW_DEPTH_MAX` is the old 8 plus 5 = 13, and `FOLLOWS_MAX` counts spaces, 32, because a person follows several spaces of one owner. The route is a more specific prefix than the owner's group routes of the relay; every route is installed with CHILD_INHERIT, so the forwarder gives the exact group the nexthops of `<owner>/32=sync` too and the devices of the namespace still hear the claimant, and the strategy of `<owner>/32=sync` (multicast) is found by longest prefix (`a_relay_routes_the_group_of_the_space_its_device_follows_and_no_other_space_of_the_namespace`).

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
| `Departure` 0x044C: encode, strict decode (exactly two Names, even types above 31 skipped), `DEPARTURES_MAX` | Q/message.rs:412–469 (`Departure`), :64–68; test `departure_matches_the_spec_vector_round_trips_and_is_read_strictly` |
| `Follows` 0x0456 in the hello: encode (at most 32 valid groups), strict decode (first 32 used; a namespace, an owner's whole group and over-deep names refused, even types above 31 skipped), `FOLLOWS_MAX`, `FOLLOW_DEPTH_MAX`, `FOLLOW_SPACE_MAX` | Q/message.rs (`LinkHello::follows`, `check_followed_group`); tests `a_hello_follows_is_even_names_and_an_older_receiver_skips_it`, `a_hello_follows_is_bounded`, `a_hello_follows_names_exact_groups_and_refuses_what_is_not_one` |
| followed group routes (`routes_for`: full identified link, no grant; exactly the groups named), what a device tells a relay (`Judge::told_follows`: the groups the host gave `Links::set_followed_groups`), relink when it changes (`LinkTable::relink_followed`) | N/routes.rs, N/relays.rs, N/table.rs; tests `a_full_link_routes_the_groups_its_peer_follows_once`, `a_claim_of_following_routes_nothing_on_an_enrollment_departure_grant_or_unidentified_link`, `a_served_devices_follows_are_carried_and_route_their_groups_only`, `a_relay_also_routes_the_followed_namespaces` (N/admission.rs: a namespace followed tells nothing); real QUIC and forwarders: `tests/follows.rs` (`a_relay_routes_the_group_of_the_space_its_device_follows_and_no_other_space_of_the_namespace`, `a_space_followed_later_is_routed_by_the_relay_once_the_link_is_made_again`, `a_space_no_longer_followed_loses_the_relays_route_when_the_link_is_made_again`, `the_hosts_followed_groups_name_exact_spaces_or_are_refused_whole`) |
| a host's followed groups reach the links: marks of a group on `security/transit` (counted per face, released with the face, no transit effect), refusals of a name that is no group, of too many and of a node with no links; the groups a host marks (`ndn-heap` tool: spaces open or carried of another owner; `ndn-repo follow`: spaces carried of another owner) | ndn-fwd `transit_marks.rs` (`Marked::Group`, `Inner::follow`); ndn-tools `host.rs` (`followed_group`, `FollowedGroups`); ndn-repo `follow.rs` (`followed_groups`); tests `a_followed_space_group_is_told_to_the_links_and_nothing_else_is`, `a_closed_face_stops_following_what_only_it_followed`, `only_a_space_of_another_owner_is_followed_by_its_own_group`, `the_daemon_is_told_the_groups_of_the_spaces_followed_and_no_more`, `a_follower_follows_the_groups_of_the_spaces_of_other_owners_only` |
| `Departure` queued per folder (latest replaces, at most 16 folders told), written after the verdict; heard per folder (17th closes 0x15); `send_departure`, `departures` | Q/link.rs:485–502 (`put_departure`), :565–587 (`Heard::take`), :811–844 |
| narrowing scope (`LinkScope::narrowing`, asked per packet) | Q/scope.rs:104–124 (`Narrowing`) |
| grants as a set of entries per key; `grant`, `revoke_grant(key, folder)`, `revoke_grants`; per-packet `grant_names` / `grant_pushes`; ended entries (64) | N/grants.rs (`Grants`, `Links::grant`, `Links::revoke_grant`, `Judge::grant_names`, `Judge::grant_pushes`) |
| departure marks, `DepartureOptions`, `DepartureSink`, narrowing and closing (`narrow_granted`, `spawn_finish`), departure link admission, the person's half (`hear_departures`), `let-go` detail | N/departures.rs (`Departures`, `Links::depart`, `Links::set_departure_options`, `Links::set_departure_sink`); N/grants.rs (`GrantOutcome::Departing`); N/admission.rs (`Enrollment::Departure`) |
| the joiner's routes (`JoinedRoutes` with `push`, `Links::set_joined_routes`, the set and its bounds, one route set per full link path, applied under the table lock); `LinkHints::serve` follows `Invites::joined_changes`; the mirror grant is an ordinary `Links::grant` entry; a grant link's routes for the person's public names (`grant_public_routes`); address freshness of an accepted link (`Book::learn`) | N/joined.rs; N/table.rs (`LinkTable::reroute_joined`); N/links.rs (`Links::set_joined_routes`); N/routes.rs (`grant_public_routes`); N/policy.rs (`JOINED_ROUTE_COST`, `JOINED_ROUTES_MAX`, `JOINED_FOLDERS_MAX`); N/hints.rs (`LinkHints::serve`); N/memory.rs (`Book::learn`) |
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
| routes and VIA_RELAY_COST; routes per identity; relay routes at rank for the namespaces the relay is used for, and followed namespaces over a relay the person added; namespace route only for a node this side dials | N/routes.rs:26–96; N/links.rs:617–624; N/relays.rs (`relay_namespaces_of`, `relay_routed_namespaces`); N/serving.rs (`followed_namespaces`) (test `a_user_relay_also_routes_the_followed_namespaces` in N/admission.rs) |
| route origin static, CHILD_INHERIT; remove_routes | N/engine.rs:32–58 |
| establish: channel binding, hello (link key chain and memberships), decide, slot, admit, reliability choice, register (identities, namespaces shown), routes, transit per served identity, idle close; on end: asleep, presence per identity, relay choice | N/links.rs:451–745 |
| link up: awake, waiting Interests sent, Reachability sent, presence followed (relays, and peers one of whose roles may relay) and announced per identity | N/links.rs:751–783 |
| duplicate-link rule `keeps_existing`; register | N/table.rs:32, :172–222 (test :544) |
| revocation while linked: per identity; routes and presence of a revoked membership taken; close when none is left | N/links.rs:155–159, :237 (`revoked`); N/table.rs:482 (`close_revoked`) (test `revoking_one_membership_keeps_the_link_by_another_and_the_last_closes_it` in ndn-link/tests/memberships.rs) |
| relink after enrollment and when memberships change, 0x03 | N/links.rs:201 (`identities_changed`), :219 (`shown_namespaces`); N/table.rs:411, :430, :446; F/links.rs:502 |
| dial loop, `Backoff` (500 ms doubling to 30 s; refused 60 s), persistence for `always` only | N/links.rs:991–; N/policy.rs:87 |
| link wanted by mode and relay choice; keep: idle by datagrams, 0x05 / 0x06 closes | N/links.rs:876–947; N/control.rs:357–365 |
| dial over path candidates and resolved addresses | N/links.rs:840 (`dial_once`); N/host.rs:114–137 |
| dialling by a code's key (`dial_by_key`, `undial_by_key`) and with no key to expect (`dial_first`, the key it proved, §13.3A); `LinkHints::dial`, `LinkHints::dial_first`, `LinkHints::undial` | N/introduce.rs (`Links::dial_by_key`, `Links::dial_first`, `Links::undial_by_key`; tests in the module and in ndn-link/tests/introductions.rs); N/hints.rs |
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
| `links/list` TLVs 0x04A0–0x04F2; `link_code`, `LinkDetail`, `LinkWords`; `LinkModeArg` | ndn-rs/crates/core/ndn-mgmt-wire/src/link_status.rs:30, :120, :406, :536, :713 |
| `links/connect`, `links/disconnect`, `links/mode` | ndn-rs/crates/core/ndn-mgmt-wire/src/nfd_command.rs:70–79; F/links_mgmt.rs:67–230 |
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
