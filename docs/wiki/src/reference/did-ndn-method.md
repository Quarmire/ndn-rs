# did:ndn DID Method Specification

**Method Name:** `ndn`  
**Status:** Draft  
**Authors:** ndn-rs contributors  
**Specification:** This document follows the [W3C DID Method Registry](https://www.w3.org/TR/did-spec-registries/) template.

---

## Abstract

The `did:ndn` DID method binds W3C Decentralized Identifiers to Named Data Networking (NDN) names. It supports two resolution strategies:

- **CA-anchored DIDs** — rooted in a certificate authority hierarchy, resolved by fetching an NDNCERT certificate
- **Zone DIDs** — self-certifying, resolved by fetching a signed DID Document Data packet at the zone root name

Both strategies use NDN Interest/Data exchange for resolution; no DNS, HTTP, or blockchain infrastructure is required.

---

## 1. Method-Specific Identifier Syntax

The ABNF for `did:ndn` identifiers is:

```abnf
did-ndn   = "did:ndn:" base64url
base64url = 1*(ALPHA / DIGIT / "-" / "_")
```

The method-specific identifier is the **base64url-encoded (no padding) complete NDN Name TLV wire format**, including the outer `Name-Type` (`0x07`) and `TLV-Length` octets.

```
did:ndn:<base64url(Name TLV)>
```

This single form handles all NDN names — GenericNameComponents, BLAKE3_DIGEST zone roots, versioned components, sequence numbers, and any future typed components — without type-specific special cases or dual-form ambiguity.

### 1.1 Encoding Examples

```
NDN name:              /com/acme/alice
Name TLV (hex):        07 11 08 03 com 08 04 acme 08 05 alice
did:ndn:               did:ndn:<base64url of above>

NDN name:              /<blake3_digest(pubkey)>   (zone root, type 0x03)
Name TLV (hex):        07 22 03 20 <32 bytes>
did:ndn:               did:ndn:<base64url of above>
```

The method-specific identifier contains no colons (`:` is not in the base64url alphabet), which unambiguously distinguishes the current encoding from the deprecated dual-form encoding described in §1.2.

### 1.2 Deprecated Encoding (Backward Compatibility)

Earlier drafts of this spec defined two forms that are now deprecated:

| Form | Syntax | Problem |
|------|--------|---------|
| Simple | `did:ndn:com:acme:alice` | Ambiguous when first component equals `v1` |
| v1 binary | `did:ndn:v1:<base64url>` | `v1:` sentinel collides with a name whose first component is literally `v1` |

**Ambiguity example:** Both of the following produced `did:ndn:v1:BwEA` under the old scheme:
- The binary encoding of a name with a single zero-byte GenericNameComponent
- The simple encoding of the name `/v1/BwEA` (two ASCII components)

The unified binary form eliminates this: every NDN name maps to exactly one DID string.

Implementations **must** still accept the deprecated forms in `did_to_name` for backward compatibility, but **must not** produce them. The presence of a `:` in the method-specific identifier identifies a deprecated DID; the presence of `v1:` as the first two characters identifies the deprecated binary form specifically.

---

## 2. DID Document Structure

A `did:ndn` DID Document conforms to the [W3C DID Core](https://www.w3.org/TR/did-core/) data model and is serialised as JSON-LD.

### 2.1 CA-Anchored DID Document

Derived from the NDNCERT certificate at `<identity-name>/KEY`:

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
      "x": "<base64url(pubkey)>"
    }
  }],
  "authentication": ["did:ndn:com:acme:alice#key-0"],
  "assertionMethod": ["did:ndn:com:acme:alice#key-0"],
  "capabilityInvocation": ["did:ndn:com:acme:alice#key-0"],
  "capabilityDelegation": ["did:ndn:com:acme:alice#key-0"]
}
```

### 2.2 Zone DID Document

Published as a signed NDN Data packet at the zone root name. Zone owners **must** publish this document for resolvers to find it. The document:

- **Must** include an Ed25519 `verificationMethod` whose public key satisfies `blake3(pubkey) == zone_root_component`
- **May** include an X25519 `keyAgreement` method for encrypted content (derived from the Ed25519 seed or generated independently)
- **May** include `service` endpoints (e.g., sync group prefixes, router prefixes)

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/jws-2020/v1"
  ],
  "id": "did:ndn:<base64url(zone-root-Name-TLV)>",
  "verificationMethod": [
    {
      "id": "did:ndn:<base64url>...#key-0",
      "type": "JsonWebKey2020",
      "controller": "did:ndn:<base64url>...",
      "publicKeyJwk": { "kty": "OKP", "crv": "Ed25519", "x": "..." }
    },
    {
      "id": "did:ndn:<base64url>...#key-agreement-0",
      "type": "JsonWebKey2020",
      "controller": "did:ndn:<base64url>...",
      "publicKeyJwk": { "kty": "OKP", "crv": "X25519", "x": "..." }
    }
  ],
  "authentication": ["did:ndn:<base64url>...#key-0"],
  "assertionMethod": ["did:ndn:<base64url>...#key-0"],
  "keyAgreement": ["did:ndn:<base64url>...#key-agreement-0"],
  "capabilityInvocation": ["did:ndn:<base64url>...#key-0"],
  "capabilityDelegation": ["did:ndn:<base64url>...#key-0"],
  "service": []
}
```

---

## 3. CRUD Operations

### 3.1 Create

**CA-anchored:** Enroll with an NDNCERT CA. The CA issues a certificate at `<identity-name>/KEY/<version>/<issuer>`. The DID is derived from the identity name.

**Zone:** Generate an Ed25519 keypair. Compute `zone_root = blake3(public_key)`. Construct the zone root name as a single `BLAKE3_DIGEST` component. Sign and publish the DID Document as an NDN Data packet at the zone root name.

```rust
use ndn_security::{ZoneKey, build_zone_did_document};

let zone_key = ZoneKey::from_seed(&seed);
let doc = build_zone_did_document(&zone_key, x25519_key, services);
// Publish doc as a signed Data packet at zone_key.zone_root_name()
```

### 3.2 Read (Resolution)

Resolution is performed by an `NdnDidResolver` wired with an NDN fetch function.

**CA-anchored:** The resolver sends an Interest for `<identity-name>/KEY`. The Data response contains a certificate in NDNCERT TLV format. The DID Document is derived from the certificate's public key.

**Zone:** The resolver sends an Interest for the zone root name. The Data response contains a JSON-LD DID Document. After parsing, the resolver verifies:

1. `doc.id == requested_did`
2. `blake3(doc.ed25519_public_key) == zone_root_name_component`

If either check fails, `invalidDidDocument` is returned.

### 3.3 Update

**CA-anchored:** Certificate renewal via NDNCERT. The identity prefix and DID are unchanged.

**Zone:** Publish a new signed DID Document at the same zone root name with updated keys, services, or metadata. The zone root name is immutable — it is derived from the original public key. To rotate the Ed25519 signing key, use [zone succession](#zone-succession).

### 3.4 Deactivate (Zone Succession)

A zone owner signals deactivation by publishing a succession document at the old zone root name:

```rust
use ndn_security::build_zone_succession_document;

let doc = build_zone_succession_document(&old_zone_key, "did:ndn:<base64url-of-new-zone>");
// Publish doc at old_zone_key.zone_root_name()
```

The succession document:
- Has `alsoKnownAs: ["did:ndn:v1:<new-zone>"]`
- Has empty `assertionMethod`, `capabilityInvocation`, `capabilityDelegation`
- Still carries the old Ed25519 key so verifiers can authenticate the succession claim

Resolvers that receive a succession document should:
1. Set `deactivated: true` in `DidDocumentMetadata`
2. Expose the successor DID via `alsoKnownAs` for the caller to follow

---

## 4. Security Considerations

### 4.1 Zone DID Binding

The cryptographic binding of a zone DID to its public key is enforced at resolution time by verifying `blake3(pubkey) == zone_root_component`. This check is mandatory and must not be skipped, even when the document is fetched over a trusted channel.

### 4.2 Data Packet Authentication

Zone DID Documents **must** be signed as NDN Data packets with the zone's Ed25519 key. Resolvers **must** validate the Data packet signature before extracting document bytes. If the NDN-layer signature is invalid, the resolution result is `internalError`.

### 4.3 CA-Anchored Trust

CA-anchored DID resolution trusts the NDNCERT CA hierarchy. The CA's identity and signing policy are out of scope for this specification; see [NDNCERT: Automated Certificate Issuance](../deep-dive/ndncert.md) for the CA protocol.

### 4.4 Succession Attacks

An attacker who compromises the old zone private key could publish a fraudulent succession document. Zone owners should retire old keys promptly after succession and distribute the new zone DID via authenticated out-of-band channels.

### 4.5 Replay

NDN Interest/Data exchange uses nonce-based deduplication. DID Document Data packets should include a freshness period so that resolvers prefer fresh copies over cached stale documents.

---

## 5. Privacy Considerations

### 5.1 Name Correlation

`did:ndn:com:acme:alice` directly encodes the NDN identity namespace prefix. This leaks organizational hierarchy to any observer. Zone DIDs (`did:ndn:v1:…`) are pseudonymous — the base64url blob reveals nothing about the owner's identity beyond the public key.

### 5.2 Resolution Traffic

Sending an NDN Interest for `<identity-name>/KEY` reveals to network nodes along the path that the requester is resolving that DID. Interest aggregation in NDN routers limits this to one forwarded Interest per prefix per time window.

### 5.3 Key Agreement

Zone DID Documents may include an X25519 `keyAgreement` key. This key **must** be generated independently from the Ed25519 signing key (or derived via a one-way function) so that compromise of the signing key does not imply compromise of encrypted content.

---

## 6. Rust API Reference

| Type / Function | Description |
|---|---|
| `ZoneKey::from_seed(&[u8; 32])` | Derive Ed25519 key and zone root name from a 32-byte seed |
| `ZoneKey::zone_root_name()` | The `/<blake3_digest>` NDN name |
| `ZoneKey::zone_root_did()` | `did:ndn:v1:<base64url>` string |
| `build_zone_did_document(&ZoneKey, x25519, services)` | Construct a zone DID Document |
| `build_zone_succession_document(&ZoneKey, successor_did)` | Construct a succession document |
| `cert_to_did_document(&Certificate, x25519)` | Derive a DID Document from an NDNCERT certificate |
| `NdnDidResolver::with_fetcher(fn)` | Wire a CA-anchored cert fetch function |
| `NdnDidResolver::with_did_doc_fetcher(fn)` | Wire a zone DID Document fetch function |
| `UniversalResolver::resolve(did)` | Resolve a DID, returns `DidResolutionResult` |
| `UniversalResolver::resolve_document(did)` | Resolve and return just the `DidDocument` |
| `name_to_did(&Name)` | Encode an NDN name as a `did:ndn` string |
| `did_to_name(&str)` | Decode a `did:ndn` string back to an NDN name |

---

## 7. Conformance

This method is intended to be registered with the [W3C DID Method Registry](https://www.w3.org/TR/did-spec-registries/). Until registered, the method name `ndn` is used informally by ndn-rs and associated projects.
