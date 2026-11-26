# ndn-rs specifications

Normative specs are written so that an independent implementation (NDNts,
python-ndn, ndnd, …) can interoperate with ndn-rs. Design documents explain
why. Notes record a decision or describe a historical design.

## Personal namespace: wire specifications (normative)

The design is in [personal-namespace.md](personal-namespace.md). These specs
define the bytes on the wire:

| Spec | Covers |
|---|---|
| [ndn-link.md](ndn-link.md) | QUIC links: ALPN `ndn-link/1`, RFC 7250 raw public keys, key fingerprint, hello/verdict TLVs (incl. enrollment link), datagram framing, timeouts, close reasons, admission, duplicate-link rule |
| [trust-context.md](trust-context.md) | Trust context TLVs (anchors, revocations and revocation cuts, KeyRole, LinkPolicy, EnrollmentHint, schema), versions, continuity, catch-up, RDR publication, context sync group, how Data is judged against revocations without clocks, self-certifying namespaces `/user/<h>` (§4.5) |
| [ndncert-extensions.md](ndncert-extensions.md) | NDNCERT extensions: approval (CA/APPROVAL, CA/PENDING, CA/STATUS, verification code), renewal challenge, invite tokens |
| [trust-envelope.md](trust-envelope.md) | `ndn-trust://` envelopes: kinds, TLV 0x0470–0x049F, carriage forms incl. QR |
| [recovery-kit.md](recovery-kit.md) | Recovery kits: BIP39 → Ed25519 recovery key, key naming, file kit (PBES2), hardware kit |
| [local-refusal.md](local-refusal.md) | NackReason 170–176 for local faces |
| [mgmt-trust.md](mgmt-trust.md) | Trust management outcomes: refusal codes, next-step classes, details, per-verb catalogues (trust-admin, approvals, links, side routes, invites, root-device operations, notifications) |

## Other specifications

| Spec | Covers |
|---|---|
| [heap.md](heap.md) | Heap (`ndn-heap`, the data layer; the specification of the former `ndn-data` crate is kept in [history/](history/)): a signed hash-chained log per writer and space, entries and their TLVs, names, membership as an operation fold in which removal wins, epoch seals and grants, durability by sequence reservation with recovery from peers and a signed gap statement, the TLV registry 0x0600–0x063F |
| [channel.md](channel.md) | Channel (`ndn-heap` `chan`): ephemeral live data of a space, which replaced the former signals (kept in [history/signals.md](history/signals.md)); set up by signed NDN (ask, session, wrapped key, judging, renewal, re-keying), the sealed frame and its messages, the receiver and sender, the forwarder's side table that fans frames out (the `SideRoute` LP header 0x0370, routes, `UP`, the bar), signed checkpoints (the record, evidence, `Trust::Verified`, the stated window), residuals, threat notes; the TLV registry 0x0660–0x06BF |
| [invite.md](invite.md) | Invite (`ndn-invite`, introductions on top of heap.md; the introductions of the former data layer carried over to the `ndn-heap` space): a one-use offer as a signed packet `<D>/32=intro/32=offer/<id>` served by an extension (not a log entry), the code (link, words, short code with its hint record), the sealed ask and the answer that names the one members entry that admitted the joiner, wrong-try counters and the use mark, grants and mirror grants that follow the members, departures, the host trait, the introduction surface and folder-scope predicates, policy, refusals and threat notes; the TLV numbers of §16 (kept from the former data layer) |
| [did-ndn-spec.md](did-ndn-spec.md) | `did:ndn` method |
| [service-layer.md](service-layer.md) | Service layer |
| [ndnsf-invariants.md](ndnsf-invariants.md) | NDNSF security-invariant witnesses |
| [subscription-request-sub-tlv.md](subscription-request-sub-tlv.md) | SubscriptionRequest sub-TLV |
| [trace-context-lp-tlv.md](trace-context-lp-tlv.md) | TraceContext LP TLV |

## Notes

- [f28-non-minimal-varnum-decode.md](f28-non-minimal-varnum-decode.md): ruling on non-minimal VAR-NUMBER on the SVS wire
- [named-time.md](named-time.md): historical design, superseded by the crates
- [history/](history/): superseded specifications, kept for history and not normative: the former data layer (`ndn-data`, removed from the workspace; its remainder is [history/data-layer-remainder.md](history/data-layer-remainder.md)) and the families cut out of it. Each file begins with a banner that names what superseded it

## Conventions

### TLV-TYPE numbers

Application TLV-TYPEs of these specs are allocated from 0x0400–0x06FF in
blocks, one owner each. Allocate a new block from the free space and add it
here before using it.

| Block | Owner |
|---|---|
| 0x0403 | free |
| 0x0404 | [trust-context.md](trust-context.md) §3.3.12: `CutTip` (a sub-TLV of RevocationCut) |
| 0x0405 | free |
| 0x0406 | [trust-context.md](trust-context.md) §3.3.12: `CutTipDigest` (in CutTip) |
| 0x0407–0x040F | free (left below the trust-context block) |
| 0x0410–0x043E | [trust-context.md](trust-context.md) |
| 0x0440–0x046C | [ndn-link.md](ndn-link.md) (hello/verdict, the control messages after the verdict — Reachability 0x0440, Presence 0x0446, ObservedAddress 0x0458 and, since round 7, `Departure` 0x044C, §5.9 — the hello's even fields `Follows` 0x0456 and, since the channel carrier, `ChannelCaps` 0x044E (§5.2: one byte, bit 0 = channel frames), and the punch messages) |
| 0x0470–0x049F | [trust-envelope.md](trust-envelope.md) (the `intro` kind's offer, relay hint and secret: 0x0475–0x0477; its link hint, the octets of invite.md §6.1's hint: 0x0478; since round 10 the compact form, names as wire relative to the namespace instead of text: `IntroNamespaceWire` 0x0490, `IntroOfferWire` 0x0492, `IntroRelayWire` 0x0494, all even; the text tags 0x0489, 0x0475, 0x0476 are still read, never written) |
| 0x04A0–0x04F2 | `links/list` and management outcome details ([ndn-link.md](ndn-link.md), [mgmt-trust.md](mgmt-trust.md)) |
| 0x0500–0x0509 | `cs/list` (`ndn-mgmt-wire`) |
| 0x050C–0x051E | `links/list` fault-layer notice, the optional `fault_injection` entry (0x050C–0x051C used; [ndn-link.md](ndn-link.md) §14.10, §17B.6) |
| 0x0520–0x057F | [invite.md](invite.md) §16.1, only the numbers it lists: 0x0561, 0x0563, 0x0565, 0x0567, 0x0569, 0x056B, 0x056D and 0x056F (the offer, use mark, ask and answer records, role, tries, refusal and credentials), 0x052A (`ADMITTED`, a nested entry id) with 0x0526 (`SEQ`, only inside `ADMITTED`), and 0x052E, 0x0531, 0x053B, 0x053F, 0x055E, 0x0568, 0x0574, 0x0576 and 0x057C, kept from the former data layer, none renumbered. **The rest of the block is retired and MUST NOT be reused**: it carried the former `ndn-data` records (versions, summaries, cuts, custody, streams, merge, groups; the old specifications are kept in [history/](history/)), and a reused number would let a stale packet of that crate decode as a record of another meaning |
| 0x0580–0x05AF | **retired and MUST NOT be reused**: the TLV numbers of the former signals (replaced by the channel, [channel.md](channel.md); the specification is kept in [history/signals.md](history/signals.md)); a reused number would let a stale signal packet decode as a record of another meaning |
| 0x05B0–0x05BF | [invite.md](invite.md) §6.1, §7.1, §16.2 (even numbers: an introduction code's link hint, carried as the value of the intro envelope's `LinkHint` 0x0478 — `LinkKey` 0x05B0, `LinkCandidate` 0x05B2; the hint record a short code names, the Content of the Data `<device>/32=hint/<token>` — `IntroHint` 0x05B4 holding `HintOffer` 0x05B6 (a Name), `LinkKey`, `LinkCandidate`s, `HintRelay` 0x05B8 (a Name, repeatable), `HintUntil` 0x05BC and `Credentials` 0x056F, or `HintGone` 0x05BA (3 expired, 4 closed) with `Credentials`, the whole of a gone mark); the other numbers of the block are unallocated and invite.md's to assign |
| 0x0600–0x063F | [heap.md](heap.md) §15 (the data layer's log entry and its parts: `ENTRY` 0x0601, `KIND` 0x0603, `PREV` 0x0605, `PREV_SEQ` 0x0607, `ENTRY_REF` 0x0609, `PATH` 0x060F, `INLINE` 0x0611, `BLOB` 0x0613, `SEALED` 0x0619, `MEMBERS` 0x0621, `EPOCH_BODY` 0x062F, `GRANT_ASK` 0x0635, `SEAL_KEY` 0x0637, `GRANT` 0x0639, `SEAL_KEY_PACKET` 0x063B, `ASKER_CERT` 0x063D and their fields, §3; odd numbers critical, even numbers skippable and reserved for additive fields; 0x063F free) |
| 0x0640–0x0653 | `ndn-security` custodian remote signer (`ndn-security/src/custodian/custodian/remote_signer.rs:149-159`: sign request and response, request id, region, status, signature, pairing offer, dashboard public key, transport hint, nonce) |
| 0x0660–0x06BF | [channel.md](channel.md) §7 (the channel setup: `CHAN_ASK` 0x0661 and its `ASK_*` fields 0x0663–0x0672, `CHAN_SESSION` 0x0673 and its `S_*` fields 0x0675–0x0697, `CHAN_REFUSAL` 0x0699 with `R_CODE` 0x069B, `R_TEXT` 0x069D, `R_RETRY` 0x069F, `CHAN_ANNOUNCE` 0x06A1, `B_ID` 0x06A3, `B_NAME` 0x06A5, `W_MESSAGES` 0x06A7, `W_BYTES` 0x06A9, `W_MS` 0x06AB; odd numbers critical, even numbers skippable and reserved for additive fields) |

The blocks 0x05C0–0x05DF and 0x05E0–0x05FE are unallocated: their numbers were retired when answers and device events were removed from the former data layer (the old specifications are kept in [history/answers.md](history/answers.md) and [history/data-layer-events.md](history/data-layer-events.md)), and they MUST NOT be reused. The block 0x0580–0x05AF is retired the same way, since the signals it served were replaced by the channel ([history/signals.md](history/signals.md)).

### NDNLPv2 header numbers

NDNLPv2 headers are TLV-TYPEs of their own, below the application blocks above and ordered by number inside an LpPacket. Odd numbers are critical, even numbers are skipped by a decoder that does not know them. The base set is NDNLPv2's own (Fragment 0x50, PitToken 0x62, Nack 0x0320 and NackReason 0x0321 (see [local-refusal.md](local-refusal.md)), IncomingFaceId 0x032C, NextHopFaceId 0x0330, CachePolicy 0x0334, CongestionMark 0x0340, Ack 0x0344, TxSequence 0x0348, NonDiscovery 0x034C, PrefixAnnouncement 0x0350). The headers ndn-rs adds, and where each is specified:

| Type | Name | Owner |
|---|---|---|
| 0x0334 | `CachePolicy`, `NoCache` (1) | NDNLPv2; the channel's setup Data carries it ([channel.md](channel.md) §3.2) |
| 0x0360, 0x0362, 0x0364 | A-LAL `Presence`, previous-hop location, data location (even, non-critical, ndn-rs experimental) | `ndn-packet` `lp/al_lal.rs` |
| 0x0370 | `SideRoute`: the route id (8 octets) and a TTL in seconds (2), exactly 10 octets, on a channel session Data (even: a forwarder that predates it skips it) | [channel.md](channel.md) §14.3 (`ndn_packet::tlv_type::LP_SIDE_ROUTE`) |
| 0x0520 | `TraceContext` | [trace-context-lp-tlv.md](trace-context-lp-tlv.md) |

0x0370 was free. Before `SideRoute` no spec and no code of `ndn-rs`, `ndn-ext`, `ndn-radio` or `ndn-fwd` named it (`grep` for `0x0370` and `LP_SIDE_ROUTE`, build directories excluded, finds only `ndn-packet`'s definition and codec and the doc comments of `ndn-engine`), and this registry had no NDNLPv2 table.

### Name-component types

NDN name components carry a TLV-TYPE of their own. The NDN packet format
assigns 1 (ImplicitSha256Digest), 2 (ParametersSha256Digest), 8 (Generic),
32 (Keyword), 50 (Segment), 52 (ByteOffset), 54 (Version), 56 (Timestamp)
and 58 (SequenceNum), and leaves 128–252 to applications
([NDN packet format, name component types](https://docs.named-data.net/NDN-packet-spec/current/types.html)).
These specs use the assigned types and allocate application types here,
each with one owner. Allocate from 128–252 and add it here before using it.

| Type | Name | URI form | Owner |
|---|---|---|---|
| 161 (`0xA1`) | SelfCertifying: SHA-256 of a namespace's genesis root, an Ed25519 public key (32 octets), only as the second component of `/user/<h>` (`ndn_packet::tlv_type::SELF_CERTIFYING`; the type ndf-rs uses for the same names) | `161=%xx…` | [trust-context.md](trust-context.md) §4.5 |
