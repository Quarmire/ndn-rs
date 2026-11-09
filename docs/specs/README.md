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
| [trust-envelope.md](trust-envelope.md) | `ndn-trust://` envelopes: kinds, TLV 0x0470–0x048F, carriage forms incl. QR |
| [recovery-kit.md](recovery-kit.md) | Recovery kits: BIP39 → Ed25519 recovery key, key naming, file kit (PBES2), hardware kit |
| [local-refusal.md](local-refusal.md) | NackReason 170–176 for local faces |
| [mgmt-trust.md](mgmt-trust.md) | Trust management outcomes: refusal codes, next-step classes, details, per-verb catalogues (trust-admin, approvals, links, invites, root-device operations, notifications) |

## Other specifications

| Spec | Covers |
|---|---|
| [data-layer.md](data-layer.md) | Data layer: versions, collections, members, summaries, cuts, snapshots, custody, prune, seals and types and the seven verbs; slices 1–6 normative (versions, members, merge rule `/merge/yrs`, nested summaries, snapshots, sync notice, seals, large payloads, custody leases and audits, prune; signed blocks, the one-key rule's head and freshness bound, retention by expiry with summary keep bounds, range reads; revocation cuts; merge rules by versioned name, operations the application builds, checkpoints, merge pieces, groups of versions, folder members records, introductions (joining a folder by a code); TLV 0x0520–0x057F), later slices skeleton |
| [signals.md](signals.md) | Signals: ephemeral live data (presence, cursors, live edits) between the members of a folder; run keys and run headers, packets signed by the run key and sealed under the folder epoch's signal key, the push into the namespaces' sync groups, the local leg over shared-memory rings, receiver checks, limits, threat notes; TLV 0x0580–0x05AF |
| [did-ndn-spec.md](did-ndn-spec.md) | `did:ndn` method |
| [service-layer.md](service-layer.md) | Service layer |
| [ndnsf-invariants.md](ndnsf-invariants.md) | NDNSF security-invariant witnesses |
| [subscription-request-sub-tlv.md](subscription-request-sub-tlv.md) | SubscriptionRequest sub-TLV |
| [trace-context-lp-tlv.md](trace-context-lp-tlv.md) | TraceContext LP TLV |

## Notes

- [f28-non-minimal-varnum-decode.md](f28-non-minimal-varnum-decode.md): ruling on non-minimal VAR-NUMBER on the SVS wire
- [named-time.md](named-time.md): historical design, superseded by the crates

## Conventions

### TLV-TYPE numbers

Application TLV-TYPEs of these specs are allocated from 0x0400–0x05FF in
blocks, one owner each. Allocate a new block from the free space and add it
here before using it.

| Block | Owner |
|---|---|
| 0x0403–0x040F | free (left below the trust-context block) |
| 0x0410–0x042F | [trust-context.md](trust-context.md) |
| 0x0440–0x046C | [ndn-link.md](ndn-link.md) (hello/verdict, punch) |
| 0x0470–0x048F | [trust-envelope.md](trust-envelope.md) (the `intro` kind's offer, relay hint and secret: 0x0475–0x0477) |
| 0x04A0–0x04F2 | `links/list` and management outcome details ([ndn-link.md](ndn-link.md), [mgmt-trust.md](mgmt-trust.md)) |
| 0x0500–0x0509 | `cs/list` (`ndn-mgmt-wire`) |
| 0x0520–0x057F | [data-layer.md](data-layer.md) (even numbers; odd ones for critical additions: slice 3's chunks, hold, lease, prune and audit records, 0x0521–0x0537, and its custody fields — holders, asker, whole, proof, pruned-by, refused-by — 0x0539–0x0543; slice 4's block, block entry, offset, head record, freshness, time range, the expired audit answer and a summary node's expiry runs, 0x0545–0x0553; slice 6's folder flag of a members record, a version's group and its count, 0x0555–0x0559, a removal cut's binding of what it keeps to its bytes (CutBytes, the full name of its cut manifest), 0x055B, and a folder cut's list per collection (CutIn), 0x055F; slice 6 reuses, in a version record, FrontierEntry 0x0524 with Digest 0x055E — each parent bound to its tip's packet — and Rule 0x0548, the merge rule an operation was made for; the introduction's offer and use-mark records, ask, answer, role, tries, refusal and credentials, 0x0561–0x056F, §19) |
| 0x0580–0x05AF | [signals.md](signals.md) (even numbers) |

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
