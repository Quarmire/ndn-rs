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

## Other specifications

| Spec | Covers |
|---|---|
| [did-ndn-spec.md](did-ndn-spec.md) | `did:ndn` method |
| [service-layer.md](service-layer.md) | Service layer |
| [ndnsf-invariants.md](ndnsf-invariants.md) | NDNSF security-invariant witnesses |
| [subscription-request-sub-tlv.md](subscription-request-sub-tlv.md) | SubscriptionRequest sub-TLV |
| [trace-context-lp-tlv.md](trace-context-lp-tlv.md) | TraceContext LP TLV |

## Notes

- [f28-non-minimal-varnum-decode.md](f28-non-minimal-varnum-decode.md): ruling on non-minimal VAR-NUMBER on the SVS wire
- [named-time.md](named-time.md): historical design, superseded by the crates
