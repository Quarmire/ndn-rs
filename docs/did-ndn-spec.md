# did:ndn Method Specification

**Method name:** `ndn`
**Status:** Draft
**Editor:** ndn-rs contributors
**Repository:** https://github.com/ndn-rs/ndn-rs
**Latest version:** This document

---

## Abstract

The `did:ndn` DID method identifies Named Data Networking (NDN) namespaces as W3C Decentralized Identifiers (DIDs). Each `did:ndn` identifier resolves to a DID Document by fetching the corresponding NDN certificate over NDN — using any NDN transport (UDP, Ethernet, Bluetooth, LoRa, serial, satellite, or mesh). No HTTP infrastructure is required. The method enables full DID ecosystem interoperability — Verifiable Credentials, DIDComm, Universal Resolver — for participants in NDN networks, including resource-constrained IoT devices, mobile applications, and offline swarms.

---

## 1. Introduction

### 1.1 NDN Names as Identifiers

Named Data Networking is a content-centric networking architecture in which every packet is named. Names are hierarchical, human-meaningful paths such as `/edu/ucla/remap/sensor/node1`. Unlike IP addresses, NDN names are not tied to network topology — the same name is routable regardless of where in the network the data resides.

This naming model already provides exactly what a DID method needs: a globally scoped, self-describing identifier. The NDN certificate published at `<identity-name>/KEY/<key-id>` is an authoritative statement binding that public key to that identity name. Nothing else is needed to define a DID: the name is the identifier, and the certificate is the DID Document.

### 1.2 Relationship to W3C DID Core

This specification defines how NDN names and certificates satisfy the requirements of the W3C Decentralized Identifiers (DIDs) v1.0 specification (https://www.w3.org/TR/did-core/):

- **DID Syntax:** NDN names are encoded as `did:ndn:...` URIs (Section 3).
- **DID Document:** NDN certificates are converted to DID Documents on resolution (Section 5).
- **DID Operations:** Create, Read, Update, and Deactivate are all defined in terms of NDN operations (Section 4).

### 1.3 Design Goals

- **Transport independence.** Resolution uses NDN Interests, which work on any NDN transport. No HTTP required.
- **No registry.** There is no central registry of `did:ndn` identifiers. Anyone with an NDN identity can create a `did:ndn` DID.
- **Namespace-hierarchical trust.** Certificate chains follow the namespace hierarchy, enabling organizational delegation.
- **Interoperability.** DID Documents use standard `JsonWebKey2020` verification methods, compatible with existing DID tooling.

---

## 2. Terminology

| Term | Definition |
|------|-----------|
| NDN | Named Data Networking — a content-centric networking architecture |
| NDN Name | A hierarchical sequence of name components, e.g., `/com/acme/alice` |
| Interest | An NDN request packet; carries a name and optional parameters |
| Data | An NDN response packet; carries a name, content, and signature |
| Certificate | An NDN Data packet containing a public key, identity name, and validity period, signed by an issuer |
| KEY component | The literal name component `KEY` that marks the start of a key locator suffix |
| Identity name | The portion of a key name before the `KEY` component: `<identity>/KEY/<key-id>` |
| NDNCERT | NDN Certificate Management Protocol — automated certificate issuance over NDN |
| Trust anchor | A certificate that is trusted unconditionally (no further chain verification required) |

---

## 3. Method Syntax

### 3.1 DID Scheme

A `did:ndn` DID has the following structure:

```abnf
did-ndn        = "did:ndn:" ndn-identifier
ndn-identifier = simple-form / v1-form

simple-form    = first-component *(":" component)
first-component = 1*name-char
component      = 1*name-char
name-char      = ALPHA / DIGIT / "-" / "." / "_"

v1-form        = "v1:" base64url
base64url      = 1*(ALPHA / DIGIT / "-" / "_") *("=")
```

The `v1:` prefix signals that the identifier is a base64url-encoded TLV representation of the full NDN name, including any binary or parameterized components.

### 3.2 Simple Form

For NDN names whose components consist entirely of ASCII letters, digits, hyphens, periods, and underscores, the identifier is formed by replacing each `/` separator with `:` and omitting the leading `/`:

```
NDN name:   /com/acme/alice
DID:        did:ndn:com:acme:alice

NDN name:   /edu/ucla/remap/sensor-array
DID:        did:ndn:edu:ucla:remap:sensor-array

NDN name:   /fleet/vehicle/vin-1HGBH41JXMN109186
DID:        did:ndn:fleet:vehicle:vin-1HGBH41JXMN109186
```

The simple form is preferred for human-readable identifiers.

### 3.3 v1 Form

NDN names may contain components with arbitrary binary content, implicit digest components, parameterized components, or non-ASCII characters. These cannot be represented in the simple form. The `v1:` prefix signals that the remainder is a base64url-encoded NDN TLV name:

```
NDN name (with binary component):
    /sensor/<0x00 0x01 0x02 0x03>

DID (v1 form):
    did:ndn:v1:BgNzZW5zb3IEBB8AAQID
    (where the value is base64url(TLV-encode("/sensor/<binary>")) )
```

Implementations MUST support both forms in resolution. When generating a DID from an NDN name, implementations SHOULD use the simple form if all components satisfy the `name-char` grammar, and MUST use the `v1:` form otherwise.

### 3.4 Relationship Between DID and Key Name

Given a DID `did:ndn:<identifier>`, the corresponding NDN Interest for resolution targets:

```
<identity-name>/KEY
```

with `CanBePrefix = true`, where `<identity-name>` is the NDN name recovered from the identifier by reversing the encoding in Sections 3.2 or 3.3. The `CanBePrefix` flag matches any specific key ID under the `/KEY` component.

---

## 4. DID Operations

### 4.1 Create

**Creating a `did:ndn` DID** means generating a key pair and publishing the corresponding certificate in the NDN network.

**Procedure:**

1. Generate an Ed25519 key pair `(sk, pk)`.
2. Choose an identity name `N` (e.g., `/com/acme/alice`).
3. Choose a key ID `k` (typically the current Unix timestamp in microseconds, encoded as an NDN name component).
4. Construct the certificate name: `N/KEY/k`.
5. Build a self-signed NDN Data packet with:
   - Name: `N/KEY/k`
   - Content: TLV-encoded public key `pk`
   - SignatureInfo: Ed25519, key locator = `N/KEY/k` (self-signed)
   - ValidityPeriod: desired lifetime
   - Signature: `sign(sk, signed_region_of_packet)`
6. Publish the certificate packet so that NDN Interests for `N/KEY` (with `CanBePrefix`) will receive it.

The DID is `name_to_did(N)`.

In practice, `NdnIdentity::open_or_create` or `NdnIdentity::provision` perform all of these steps automatically:

```rust
use std::path::PathBuf;
use ndn_identity::NdnIdentity;

// Create: generates key, self-signs cert, publishes via the router
let identity = NdnIdentity::open_or_create(
    &PathBuf::from("/var/lib/ndn/alice-id"),
    "/com/acme/alice",
).await?;

println!("Created DID: {}", identity.did());
// → did:ndn:com:acme:alice
```

For certificates issued by an NDNCERT CA rather than self-signed, the certificate content is the same structure; only the issuer differs.

### 4.2 Read (Resolve)

**Resolving a `did:ndn` DID** means fetching the certificate from the NDN network and converting it to a DID Document.

**Procedure:**

1. Parse the DID to recover the identity name `N` (reverse the encoding in Section 3.2 or 3.3).
2. Construct an NDN Interest:
   - Name: `N/KEY`
   - CanBePrefix: true
   - MustBeFresh: true (to avoid stale cached certificates)
   - InterestLifetime: 4000ms (or caller-configured)
3. Send the Interest over NDN. The Interest routes to the identity holder (or to a cache that holds the certificate).
4. Receive the NDN Data packet (the certificate).
5. Optionally: validate the certificate signature against a trust anchor.
6. Convert the certificate to a DID Document (Section 5).

```rust
use ndn_did::UniversalResolver;

let resolver = UniversalResolver::new();
let doc = resolver.resolve("did:ndn:com:acme:alice").await?;

println!("id: {}", doc.id);
println!("key type: {}", doc.verification_method[0].type_);
```

**Resolution over multiple transports:** Because step 2 sends a standard NDN Interest, resolution works over any NDN transport the local node has configured: UDP unicast, UDP multicast, Ethernet, Bluetooth, LoRa, WifibroadcastNG, or any other face type supported by the NDN forwarder. No HTTP reachability is required.

**Resolution failure:** If the Interest times out (no Data received within the Interest lifetime), resolution returns `DidError::NotFound`. If the received Data fails certificate signature validation, resolution returns `DidError::InvalidCertificate`.

### 4.3 Update

**Updating a `did:ndn` DID Document** means issuing a new certificate version.

NDN certificate names include a version component: `N/KEY/k/v=<timestamp>`. To update the public key or validity period:

1. Generate a new key pair (or reuse the existing key with a new validity period).
2. Issue a new certificate at `N/KEY/k2` (new key ID) or `N/KEY/k/v=<new-timestamp>`.
3. Publish the new certificate.
4. The old certificate naturally expires when its validity period ends.

There is no explicit "replace" operation. The DID Document at any point in time is the result of resolving `N/KEY` with `CanBePrefix`, which returns the most recent (freshest) certificate. Old versions are not served once they expire from the Content Store.

**Key rotation** is handled by issuing a new key ID. The DID URI remains the same (`did:ndn:com:acme:alice`); only the verification method changes.

### 4.4 Deactivate

**Deactivating a `did:ndn` DID** means ceasing to publish the certificate.

If the certificate holder stops producing the certificate Data packet in response to resolution Interests, and the existing certificate expires from all caches, the DID becomes unresolvable. There is no explicit deactivation message.

For time-sensitive deactivation (e.g., key compromise), the DID controller can push a trust schema update to validators that explicitly distrusts the identity name. This propagates to all validators via NDN sync within seconds.

---

## 5. DID Document

The DID Document for a `did:ndn` identifier is derived from the NDN certificate as follows.

### 5.1 Context and Identifier

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/jws-2020/v1"
  ],
  "id": "did:ndn:<identifier>"
}
```

The `id` is `name_to_did(certificate.identity_name())`.

### 5.2 Verification Method

The certificate's public key is represented as a `JsonWebKey2020` verification method:

```json
{
  "verificationMethod": [{
    "id": "did:ndn:<identifier>#key-0",
    "type": "JsonWebKey2020",
    "controller": "did:ndn:<identifier>",
    "publicKeyJwk": {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "<base64url-encoded 32-byte public key>"
    }
  }]
}
```

For Ed25519 keys (the default in ndn-rs), the JWK uses `"kty": "OKP"` and `"crv": "Ed25519"` per RFC 8037.

### 5.3 Verification Relationships

By default, the single verification method is referenced in `authentication` and `assertionMethod`:

```json
{
  "authentication": ["did:ndn:<identifier>#key-0"],
  "assertionMethod": ["did:ndn:<identifier>#key-0"]
}
```

If the certificate includes additional key purposes in its content TLV (e.g., key agreement), those are reflected in `keyAgreement` or `capabilityDelegation` as appropriate.

### 5.4 Service Endpoints

NDNCERT certificates may carry service endpoint extensions (application-specific TLV content types). If present, these are converted to DID Document `service` entries:

```json
{
  "service": [{
    "id": "did:ndn:<identifier>#ndn-face",
    "type": "NdnFace",
    "serviceEndpoint": "/ndn/neighbor/192.0.2.1"
  }]
}
```

Service endpoints are optional. Most certificates do not include them.

### 5.5 Complete Example

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/jws-2020/v1"
  ],
  "id": "did:ndn:com:acme:alice",
  "verificationMethod": [{
    "id": "did:ndn:com:acme:alice#key-0",
    "type": "JsonWebKey2020",
    "controller": "did:ndn:com:acme:alice",
    "publicKeyJwk": {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
    }
  }],
  "authentication": ["did:ndn:com:acme:alice#key-0"],
  "assertionMethod": ["did:ndn:com:acme:alice#key-0"]
}
```

---

## 6. DID Resolution Metadata

The `did:ndn` resolver returns the following resolution metadata alongside the DID Document:

| Field | Value |
|-------|-------|
| `contentType` | `application/did+ld+json` |
| `retrieved` | ISO 8601 timestamp of resolution |
| `certName` | Full NDN name of the certificate that was fetched |
| `issuer` | `did:ndn` URI of the certificate issuer (if not self-signed) |

---

## 7. Privacy Considerations

### 7.1 Name Reveals Organizational Hierarchy

NDN names in `did:ndn` identifiers are hierarchical and human-meaningful. The identifier `did:ndn:com:acme:hr:employee:alice` reveals that Alice is an employee of acme.com's HR department. Organizations with privacy requirements should use opaque component values:

```
did:ndn:com:acme:devices:a3f9b2e1d4c507f8
```

The component `a3f9b2e1d4c507f8` is an opaque device ID. It reveals that the device is associated with acme.com's devices namespace but nothing more.

### 7.2 Resolution Traffic Reveals Identity Lookups

Sending an NDN Interest for `<identity>/KEY` reveals to nearby network nodes that you are looking up this identity. In sensitive contexts, consider fetching certificates via NDN's default multicast face (so the lookup is not unicast-routed to the identity holder) or using cached certificates where possible.

### 7.3 Correlation via Name Prefix

Multiple `did:ndn` identifiers under the same prefix (e.g., `did:ndn:com:acme:fleet:vehicle:*`) are obviously correlated by prefix. This is the intended behavior for organizational namespaces. For identifiers that should not be linkable to an organization, use top-level opaque names.

---

## 8. Security Considerations

### 8.1 Trust Anchor Distribution

A `did:ndn` DID Document is only meaningful if the verifier has a trust anchor that chains to the certificate's issuer. Without a trust anchor, a resolved DID Document is cryptographically valid but not trusted.

Trust anchors for `did:ndn` are distributed the same way as NDN trust anchors: configured in firmware, distributed via authenticated NDN sync, or established via NDNCERT enrollment. The `UniversalResolver` accepts a trust anchor configuration:

```rust
let resolver = UniversalResolver::new()
    .with_trust_anchor(load_root_cert()?);
```

### 8.2 Replay Attacks

NDN Interests carry a nonce and optionally a timestamp. NDNCERT certificates include a `ValidityPeriod` TLV with `notBefore` and `notAfter` timestamps. A verifier MUST check that the current time falls within the certificate's validity period. Expired certificates MUST NOT be accepted as valid DID Documents.

The `cert_to_did_document` function propagates the validity period into DID Document metadata. Callers that cache DID Documents should honor the `notAfter` timestamp and re-resolve after expiry.

### 8.3 Key Rotation and Revocation

Key rotation is handled by issuing a new certificate (new key ID under the same identity name). The old certificate expires naturally. There is no revocation mechanism for individual certificates; instead, operators rely on short certificate lifetimes (default 24h via NDNCERT) to bound the exposure window.

For immediate revocation, a trust schema update that explicitly distrusts the identity name propagates to validators via NDN sync. This is faster than waiting for cert expiry but requires validators to be subscribed to the trust schema sync group.

### 8.4 Namespace Squatting

Because `did:ndn` requires no central registry, anyone can create a DID for any namespace. The security of `did:ndn` relies on the NDN routing infrastructure: if your network's FIB only routes `/com/acme/...` to the legitimate Acme servers (as enforced by network operators or the NDN trust schema), then only the legitimate identity holder can respond to resolution Interests for `did:ndn:com:acme:*`.

For globally routed NDN names (in the global NDN testbed or future deployments), namespace assignment is managed by namespace authorities similar to domain registrars. For private or enterprise deployments, the enterprise controls its own namespace.

### 8.5 Interaction with did:web Cross-Anchoring

When cross-anchoring `did:ndn` with `did:web` (Section 9), verifiers SHOULD require that both documents reference the same public key material. A mismatch indicates either a misconfiguration or an active attack on one of the resolution paths.

---

## 9. Cross-Method Interoperability

### 9.1 Cross-Anchoring with did:web

`did:web` resolves via HTTPS to a `.well-known/did.json` endpoint. To cross-anchor `did:ndn:com:acme:alice` with `did:web:alice.acme.com`:

1. Create a `did:ndn:com:acme:alice` identity (this specification).
2. Publish the same DID Document JSON at `https://alice.acme.com/.well-known/did.json` (the `did:web` document).
3. Add `"alsoKnownAs": ["did:ndn:com:acme:alice"]` to the `did:web` document.
4. Optionally add `"alsoKnownAs": ["did:web:alice.acme.com"]` to the `did:ndn` document (via certificate extension).

Both documents reference the same `publicKeyJwk`. A verifier that can reach `alice.acme.com` via HTTPS can verify signatures without NDN. A verifier inside an NDN network without HTTPS can resolve `did:ndn:com:acme:alice` without HTTP.

### 9.2 did:key for Offline Bootstrapping

`did:key` encodes the public key directly in the DID URI — no resolution required. For factory-provisioned devices that need a stable identifier before network connectivity:

1. At manufacture, generate an Ed25519 key pair and derive the `did:key`.
2. Burn the `did:key` into firmware as a `FactoryCredential::DidKey(...)`.
3. On first network boot, the device enrolls with an NDNCERT CA using the `did:key` as proof of identity.
4. After enrollment, the device's identity transitions to `did:ndn`.

The `UniversalResolver` resolves `did:key` identifiers locally without any network call:

```rust
let resolver = UniversalResolver::new();
// Resolves entirely in-process — the key is in the URI
let doc = resolver.resolve(
    "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
).await?;
```

---

## 10. DIF Universal Resolver Driver

The `did-ndn-driver` binary (in the `crates/did-ndn-driver` directory of this repository) implements the DIF Universal Resolver HTTP driver interface.

### 10.1 Running the Driver

```bash
# Build the driver
cargo build --release -p did-ndn-driver

# Run it (listens on port 8080 by default)
./target/release/did-ndn-driver --port 8080 --ndn-socket /run/nfd/nfd.sock
```

### 10.2 Driver API

The driver exposes the standard Universal Resolver endpoint:

```
GET /1.0/identifiers/{did}
```

For example:

```bash
curl http://localhost:8080/1.0/identifiers/did:ndn:com:acme:alice
```

Response:

```json
{
  "didDocument": {
    "@context": ["https://www.w3.org/ns/did/v1", "..."],
    "id": "did:ndn:com:acme:alice",
    "verificationMethod": [{ "..." }],
    "authentication": ["did:ndn:com:acme:alice#key-0"]
  },
  "didResolutionMetadata": {
    "contentType": "application/did+ld+json",
    "retrieved": "2026-04-07T03:00:00Z"
  },
  "didDocumentMetadata": {
    "certName": "/com/acme/alice/KEY/v=1712400000000"
  }
}
```

### 10.3 Docker Container

```dockerfile
FROM scratch
COPY did-ndn-driver /did-ndn-driver
EXPOSE 8080
ENTRYPOINT ["/did-ndn-driver"]
```

```bash
docker build -t did-ndn-driver .
docker run -p 8080:8080 \
  -v /run/nfd/nfd.sock:/run/nfd/nfd.sock \
  did-ndn-driver
```

### 10.4 Submitting to the DIF Universal Resolver

To add `did:ndn` to the DIF Universal Resolver (https://dev.uniresolver.io/):

1. Build and publish the Docker image to a public registry.
2. Submit a pull request to https://github.com/decentralized-identity/universal-resolver adding a driver entry for `ndn`.
3. The driver configuration references the Docker image and maps the `did:ndn` method to the driver's port.

---

## 11. Reference Implementation

The reference implementation of the `did:ndn` method is the `ndn-did` crate in this repository:

- **Crate:** `crates/protocols/ndn-did`
- **Repository:** https://github.com/ndn-rs/ndn-rs
- **Key types:** `UniversalResolver`, `DidDocument`, `DidError`
- **Key functions:** `name_to_did`, `did_to_name`, `cert_to_did_document`

The implementation is written in Rust and licensed under MIT OR Apache-2.0 (same as the ndn-rs workspace).

### 11.1 Conformance

An implementation of this specification MUST:

- Accept `did:ndn:<simple-form>` identifiers and recover the NDN name by splitting on `:`.
- Accept `did:ndn:v1:<base64url>` identifiers and recover the NDN name by decoding and TLV-parsing.
- Send an NDN Interest for `<identity-name>/KEY` with `CanBePrefix = true` during resolution.
- Convert the received certificate to a DID Document with at least one `JsonWebKey2020` verification method.
- Return `DidError::NotFound` if the Interest times out.
- Return `DidError::InvalidCertificate` if the certificate fails signature validation.

An implementation SHOULD:

- Support `did:key` resolution locally without network calls.
- Support `did:web` resolution via HTTPS for cross-anchoring scenarios.
- Cache resolved DID Documents up to the certificate's `notAfter` timestamp.

---

## 12. Appendix: ABNF Summary

```abnf
did-ndn        = "did:ndn:" ndn-identifier
ndn-identifier = simple-form / v1-form
simple-form    = first-component *(":" component)
first-component = 1*name-char
component      = 1*name-char
name-char      = ALPHA / DIGIT / "-" / "." / "_"
v1-form        = "v1:" base64url
base64url      = 1*(ALPHA / DIGIT / "-" / "_") *("=")
```

---

## 13. References

- W3C Decentralized Identifiers (DIDs) v1.0: https://www.w3.org/TR/did-core/
- W3C DID Use Cases: https://www.w3.org/TR/did-use-cases/
- JsonWebKey2020: https://w3c.github.io/vc-jws-2020/
- RFC 8037 (CFRG Elliptic Curves for JOSE, Ed25519): https://www.rfc-editor.org/rfc/rfc8037
- NDN Packet Format Specification: https://docs.named-data.net/NDN-packet-spec/current/
- NDNCERT Protocol: https://github.com/named-data/ndncert/blob/master/docs/NDNCERT-protocol-0.3.pdf
- DIF Universal Resolver: https://github.com/decentralized-identity/universal-resolver
- ndn-rs (reference implementation): https://github.com/ndn-rs/ndn-rs
