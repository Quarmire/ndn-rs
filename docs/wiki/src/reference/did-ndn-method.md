# did:ndn DID Method Specification

**Method Name:** `ndn`  
**Status:** Draft  
**Authors:** ndn-rs contributors  
**Specification:** This document follows the [W3C DID Method Registry](https://www.w3.org/TR/did-spec-registries/) template.

---

## Abstract

The `did:ndn` DID method binds W3C Decentralized Identifiers to Named Data Networking (NDN) names. DIDs are resolved by fetching a certificate at the corresponding NDN identity prefix and converting it into a DID Document. No DNS, HTTP, or blockchain infrastructure is required — only NDN Interest/Data exchange.

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

This single form handles all NDN names — GenericNameComponents, ImplicitSha256DigestComponent, ParametersSha256DigestComponent, KeywordNameComponent, versioned components, sequence numbers, and any future typed components — without type-specific special cases or dual-form ambiguity.

### 1.1 Encoding Examples

```
NDN name:              /com/acme/alice
Name TLV (hex):        07 11 08 03 com 08 04 acme 08 05 alice
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

A `did:ndn` DID Document conforms to the [W3C DID Core](https://www.w3.org/TR/did-core/) data model and is serialised as JSON-LD. The document is derived from the NDNCERT certificate at `<identity-name>/KEY`:

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

If the certificate carries an X25519 key (e.g. for encrypted content), the DID Document includes a second `verificationMethod` of type `JsonWebKey2020` with `crv: X25519`, referenced from `keyAgreement`.

---

## 3. CRUD Operations

### 3.1 Create

Enroll with an NDNCERT CA. The CA issues a certificate at `<identity-name>/KEY/<version>/<issuer>`. The DID is derived from the identity name.

### 3.2 Read (Resolution)

Resolution is performed by an `NdnDidResolver` wired with an NDN fetch function. The resolver sends an Interest for `<identity-name>/KEY`. The Data response contains a certificate in NDNCERT TLV format. The DID Document is derived from the certificate's public key.

### 3.3 Update

Certificate renewal via NDNCERT. The identity prefix and DID are unchanged.

### 3.4 Deactivate

NDNCERT certificate revocation. Resolvers receiving a revoked certificate set `deactivated: true` in `DidDocumentMetadata`.

---

## 4. Security Considerations

### 4.1 Data Packet Authentication

Certificate Data packets **must** be signed by an NDNCERT-trusted issuer. Resolvers **must** validate the Data packet signature against the trust schema before deriving a DID Document.

### 4.2 CA-Anchored Trust

`did:ndn` resolution trusts the NDNCERT CA hierarchy. The CA's identity and signing policy are out of scope for this specification; see [NDNCERT: Automated Certificate Issuance](../deep-dive/ndncert.md) for the CA protocol.

### 4.3 Replay

NDN Interest/Data exchange uses nonce-based deduplication. Certificate Data packets should include a freshness period so that resolvers prefer fresh copies over cached stale certificates.

---

## 5. Privacy Considerations

### 5.1 Name Correlation

`did:ndn:com:acme:alice` directly encodes the NDN identity namespace prefix. This leaks organizational hierarchy to any observer. Applications that need pseudonymous DIDs should use a different DID method (`did:key`, etc.) layered alongside `did:ndn`.

### 5.2 Resolution Traffic

Sending an NDN Interest for `<identity-name>/KEY` reveals to network nodes along the path that the requester is resolving that DID. Interest aggregation in NDN routers limits this to one forwarded Interest per prefix per time window.

### 5.3 Key Agreement

If the certificate carries an X25519 key for encrypted content, that key **must** be generated independently from the Ed25519 signing key (or derived via a one-way function) so that compromise of the signing key does not imply compromise of encrypted content.

---

## 6. Rust API Reference

| Type / Function | Description |
|---|---|
| `cert_to_did_document(&Certificate, x25519)` | Derive a DID Document from an NDNCERT certificate |
| `did_document_to_trust_anchor(&DidDocument, name)` | Reconstruct a trust-anchor `Certificate` from a DID Document |
| `NdnDidResolver::with_fetcher(fn)` | Wire a certificate fetch function |
| `KeyDidResolver` | Resolver for `did:key` (a self-contained method) |
| `UniversalResolver::resolve(did)` | Resolve a DID, returns `DidResolutionResult` |
| `UniversalResolver::resolve_document(did)` | Resolve and return just the `DidDocument` |
| `name_to_did(&Name)` | Encode an NDN name as a `did:ndn` string |
| `did_to_name(&str)` | Decode a `did:ndn` string back to an NDN name |

---

## 7. Conformance

This method is intended to be registered with the [W3C DID Method Registry](https://www.w3.org/TR/did-spec-registries/). Until registered, the method name `ndn` is used informally by ndn-rs and associated projects.
