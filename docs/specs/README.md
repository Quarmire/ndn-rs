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
| [trust-context.md](trust-context.md) | Trust context TLVs (anchors, revocations, KeyRole, LinkPolicy, EnrollmentHint, schema), versions, continuity, catch-up, RDR publication, context sync group |
| [ndncert-extensions.md](ndncert-extensions.md) | NDNCERT extensions: approval (CA/APPROVAL, CA/PENDING, CA/STATUS, verification code), renewal challenge, invite tokens |
| [trust-envelope.md](trust-envelope.md) | `ndn-trust://` envelopes: kinds, TLV 0x0470–0x048F, carriage forms incl. QR |
| [recovery-kit.md](recovery-kit.md) | Recovery kits: BIP39 → Ed25519 recovery key, key naming, file kit (PBES2), hardware kit |
| [local-refusal.md](local-refusal.md) | NackReason 170–176 for local faces |
| [mgmt-trust.md](mgmt-trust.md) | Trust management outcomes: refusal codes, next-step classes, details, per-verb catalogues (trust-admin, approvals, links, invites, root-device operations, notifications) |

## Other specifications

| Spec | Covers |
|---|---|
| [data-layer.md](data-layer.md) | Data layer: versions, collections, members, summaries, cuts, snapshots, custody, prune, seals, types and the seven verbs; slice 1 normative (versions, members, merge rule `/merge/yrs`, nested summaries, snapshots, sync notice, TLV 0x0520–0x057F), later slices skeleton |
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
| 0x0470–0x048F | [trust-envelope.md](trust-envelope.md) |
| 0x04A0–0x04F2 | `links/list` and management outcome details ([ndn-link.md](ndn-link.md), [mgmt-trust.md](mgmt-trust.md)) |
| 0x0500–0x0509 | `cs/list` (`ndn-mgmt-wire`) |
| 0x0520–0x057F | [data-layer.md](data-layer.md) (even numbers; odd ones reserved for critical additions) |
