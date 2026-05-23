# NDN overview

Named Data Networking is a content-centric network architecture. A
packet carries a *name*, not an address. There are two packet types:
the **Interest** (a request for content) and the **Data** (the
content itself, signed by its producer). Routers forward Interests
toward producers and Data back to consumers along the reverse path.

This page covers the four ideas you need to read the rest of the
wiki: names, the Interest/Data pair, signing, and trust.

## Names

A name is an ordered sequence of components. Components are
arbitrary bytes; conventionally they are written as URI segments.

```text
/example/blog/post/2026-05-20/v=42/seg=3
```

Each component carries a TLV *type* (regular, sequence number,
version, segment, timestamp, keyword, parameters-sha256-digest,
implicit-sha256-digest, etc.). The type system is documented in
the NDN Packet Specification; ndn-rs's coverage is tracked in the
[spec-compliance summary](../reference/spec-compliance.md).

Component types in ndn-rs are `ndn_packet::NameComponent` variants;
naming a `Data` packet under `/example/blog/post/seg=0` parses to
five components.

## Interest and Data

An Interest names what the consumer wants. A Data carries the
content, the producer's signature, and metadata (freshness,
content type, signature info).

| Packet | Fields | Built by |
|---|---|---|
| Interest | name, nonce, lifetime, optional `MustBeFresh`, optional `ForwardingHint`, optional signed-Interest fields | `InterestBuilder` |
| Data | name, content, content-type, freshness, signature-info, signature-value | `DataBuilder` |

A consumer expresses the Interest; some producer signs and returns
the Data. The flow through the forwarder — the PIT, the FIB, the
Content Store — is in
[Interest and Data lifecycle](./interest-data-lifecycle.md).

## Signing

Every `Data` packet is signed. The signature covers the name, the
content, and the signature info (which carries the key locator).

ndn-rs ships these signature types:

| SigType | Algorithm | Use |
|---|---|---|
| 0 | DigestSha256 | Content addressing; no producer identity. |
| 1 | SignatureSha256WithRsa | Legacy RSA producers. |
| 3 | SignatureSha256WithEcdsa | ECDSA P-256; common producer choice. |
| 4 | SignatureHmacWithSha256 | Symmetric HMAC (controlled deployments). |
| 5 | SignatureEd25519 | Ed25519; preferred for new deployments. |
| 6 | SignatureBlake3 | Content addressing with BLAKE3. |
| 7 | SignatureKeyedBlake3 | Keyed BLAKE3. |

Codes 6 and 7 are registered in the NDN TLV registry. The signing
entry point is `KeyChain::sign`; see
[Identity and keys](./identity-and-keys.md).

## Trust

A signature is not a verdict. A verifier consults a *trust policy*
to decide whether the signing key is allowed to sign the requested
name.

ndn-rs models this as two traits:

- `TrustPolicy` — "should this key be trusted for this name?" Returns
  yes / no / chain-up-to-cert-X.
- `ValidationPolicy` — composition of `TrustPolicy` decisions into a
  full validator (allow custom override rules, chained policies).

Concrete policies that ship in-tree: `InsecureTrust` (anything goes;
tests only), `StaticTrust` (allowlist of keys), `LvsTrust`
(Light Versatile Schema rules), `HierarchicalPolicy` (parent-name
key signs child-name data). Tabular catalog: [Trust policies](../reference/trust-policies.md).

## Cache and content store

Routers cache Data they have forwarded. A subsequent Interest with
the same name may be answered from the cache rather than reaching
the original producer. This makes NDN naturally multicast: ten
consumers asking for the same name hit one Data exchange and nine
cache responses.

ndn-rs's Content Store is `crates/ndn-store/`. It implements
the `ContentStore` trait; the default is an LRU with policy hooks
for freshness and Must-Be-Fresh handling.

## Forwarding strategy

How an Interest is forwarded toward a producer (which face out, when
to retransmit, how to react to NACKs) is the *strategy*'s call.
ndn-rs ships `BestRouteStrategy` (default), `MulticastStrategy`, and
`ComposedStrategy`. The trait is `Strategy` in
[Extend tier](../api/extend.md#strategy); the default is what runs
under any prefix the operator has not pinned.

## Faces

A *face* is a logical link between two NDN nodes. It is not a
TCP/UDP/IP socket: it is an NDN-layer object that owns a transport
(byte send/recv) and a link service (NDNLPv2 framing). One face per
peer, one face type per transport — UDP, TCP, Unix, WebTransport,
WebRTC, BLE, Ethernet, shared memory, in-process. The catalog is in
[Face transports](../reference/face-transports.md).

## Reading further

- The packet lifecycle: [Interest and Data lifecycle](./interest-data-lifecycle.md).
- Identities, certs, key chains: [Identity and keys](./identity-and-keys.md).
- One-page jargon reference: [Glossary](./glossary.md).
- Wire format details: the
  [spec-compliance summary](../reference/spec-compliance.md).
