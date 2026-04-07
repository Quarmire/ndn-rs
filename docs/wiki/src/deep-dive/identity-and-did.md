# Identity and Decentralized Identifiers

## The Bootstrap Problem

NDN's security model is cryptographically sound. Every packet is signed, every signature can be verified against a certificate chain, and the trust schema enforces that only authorized keys can sign data in a given namespace. But there is a quiet question lurking at the foundation of all of this: where does the first trust anchor come from?

When a newly deployed sensor wakes up and says "trust /sensor/factory/KEY/root", you have to ask: who told you to trust that? If the answer is "it was burned into the firmware at manufacture time", you are already doing identity management. You just haven't given it a name yet.

This is the bootstrap problem, and it is not unique to NDN. The web solved it with browser-bundled root CA lists — a pragmatic but deeply centralized answer. PKI solved it with the same idea. NDN's architecture gives us a much better tool.

## NDN Names Are Already Identifiers

Here is the insight that changes everything: NDN names are not just routing labels. They are *identifiers* in the full sense of the word.

Consider `/com/acme/alice`. In IP terms, this looks like a path — something you might GET over HTTP. But in NDN, this name has a richer meaning. There is no IP address behind it. No server to connect to. The name *is* the identity. The certificate published at `/com/acme/alice/KEY/...` is the authoritative statement: "here is the public key that belongs to this identity."

This is not a novel idea — it is just explicit about what NDN names actually are. The NDN architecture already specifies that key names have the form `<identity>/KEY/<key-id>`, and that certificates are signed Data packets. What we are doing with `did:ndn` is giving that existing structure a standard representation that the broader identity ecosystem can interoperate with.

The W3C Decentralized Identifiers (DID) specification defines exactly what NDN names already provide: a string identifier, a way to resolve it to a public key, and a mechanism for service discovery — all without depending on any central registry.

## What W3C DIDs Are

A DID is a URI of the form `did:<method>:<method-specific-id>`. The method identifies how to resolve the identifier; the method-specific ID is opaque to the generic DID layer. Resolution yields a **DID Document** — a JSON-LD object containing:

- The DID itself (the `id` field)
- One or more **verification methods** (public keys, in JsonWebKey2020 or other formats)
- References to those keys for specific **relationships**: `authentication`, `assertionMethod`, `keyAgreement`, `capabilityDelegation`
- Optional **service endpoints** (URLs, NDN prefixes, or anything else the controller wants to advertise)

The critical property is that resolution does not require a central lookup service. Each DID method defines its own resolution mechanism — DNS for `did:web`, the Ethereum blockchain for `did:ethr`, content-addressed storage for `did:key`. For `did:ndn`, resolution is an NDN Interest.

Here is a minimal DID Document for Alice:

```json
{
  "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"],
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

This document says: Alice can authenticate with this Ed25519 key, and data she asserts is signed with the same key. Nothing here requires a server, a certificate authority, or a blockchain.

## The did:ndn Method

The `did:ndn` method maps NDN names to DIDs with a straightforward encoding. For names composed entirely of printable ASCII components with no special characters, the mapping is a simple colon-substitution: slashes become colons.

```
NDN name:   /com/acme/alice
did:ndn:    did:ndn:com:acme:alice

NDN name:   /edu/ucla/remap/sensor-array
did:ndn:    did:ndn:edu:ucla:remap:sensor-array
```

For names containing arbitrary binary components, parameterized components, or non-ASCII characters — common in sensor networks and embedded systems — the `v1:` prefix signals a base64url-encoded TLV representation of the full name:

```
NDN name (with binary component):  /sensor/<binary-id>
did:ndn:    did:ndn:v1:BgNkYXRh...  (base64url of TLV-encoded name)
```

The `v1:` form is lossless and handles any valid NDN name. The simple colon form is preferred for human-readable identifiers because it is legible in logs, configuration files, and UIs.

### Converting Between Forms

`ndn-did` provides the conversion utilities:

```rust
use ndn_did::{name_to_did, did_to_name};

let name: Name = "/com/acme/alice".parse()?;

// Name → DID (simple form for ASCII names)
let did = name_to_did(&name);
assert_eq!(did, "did:ndn:com:acme:alice");

// DID → Name (works for both simple and v1: forms)
let recovered = did_to_name("did:ndn:com:acme:alice")?;
assert_eq!(recovered, name);

// Binary component: v1: encoding is used automatically
let sensor_name: Name = "/sensor".parse()?;
// (imagine a binary component appended)
let did = name_to_did(&sensor_name);
// If any component is not clean ASCII, result is "did:ndn:v1:<base64>"
```

### Resolution: an NDN Interest

Resolving `did:ndn:com:acme:alice` means fetching the certificate at `/com/acme/alice/KEY`. The resolver sends an NDN Interest with `CanBePrefix = true` (to match any key ID under the `/KEY` component) and `MustBeFresh = true` (to avoid stale cached keys). The responding Data packet is the certificate.

The certificate is then converted to a DID Document:

```rust
use ndn_did::{UniversalResolver, cert_to_did_document};
use ndn_security::Certificate;

// High-level: resolve a did:ndn directly
let resolver = UniversalResolver::new();
let doc: DidDocument = resolver.resolve("did:ndn:com:acme:alice").await?;

// Low-level: convert an already-fetched certificate
let cert: Certificate = /* fetched from network or cache */;
let doc = cert_to_did_document(&cert);
```

The `UniversalResolver` handles multiple DID methods — `did:ndn`, `did:web`, `did:key` — under a single interface. Which method is used is determined by parsing the `did:` prefix. An application that consumes DIDs from multiple sources can use `UniversalResolver` without branching on method type.

## Transport Independence

One of `did:ndn`'s most important properties is that it inherits NDN's transport independence. Resolution sends an NDN Interest. Interests travel over any NDN face:

- UDP unicast or multicast
- Raw Ethernet (named Ethernet, IEEE 802 mac48 addressing)
- Bluetooth
- LoRa (long-range radio)
- Satellite links
- Serial / CAN bus
- WiFi in infrastructure or ad-hoc mode
- WifibroadcastNG (used in drone swarms)

There is no HTTP server to reach. There is no DNS record to look up. If the identity holder's name is reachable over any NDN topology — even one that has no connection to the internet — the DID resolves.

This matters enormously for embedded and IoT deployments. A factory floor with no internet connection can still maintain a full DID-based identity infrastructure as long as NDN routing is configured internally. A swarm of drones with an ad-hoc mesh network between them can resolve each other's DIDs over that mesh without any external infrastructure.

## Cross-Anchoring with did:web

For systems that need to interoperate with web-based identity infrastructure — human-facing logins, OAuth clients, services that only speak HTTPS — `did:ndn` can be cross-anchored with `did:web`.

The idea is simple: publish the same public key at both a `did:web` endpoint and a `did:ndn` name, then include each as a `sameAs` or `alsoKnownAs` relation in both documents.

```
Alice controls:
  did:ndn:com:acme:alice     (resolves via NDN Interest)
  did:web:alice.acme.com     (resolves via HTTPS + well-known URL)
```

Both DID Documents refer to the same Ed25519 public key. A verifier that speaks `did:web` can verify Alice's signatures without knowing anything about NDN. A verifier inside an NDN network can resolve `did:ndn:com:acme:alice` without HTTP.

Setting this up requires:
1. Creating an `NdnIdentity` for `/com/acme/alice` (see below)
2. Serving the DID Document JSON at `https://alice.acme.com/.well-known/did.json` (standard `did:web` resolution path)
3. Including `"alsoKnownAs": ["did:ndn:com:acme:alice"]` in the `did:web` document

The key material is the same on both sides. There is no duplication of trust — just two resolution paths to the same cryptographic identity.

## did:key for Offline and Embedded Devices

`did:key` is the simplest DID method: the public key itself *is* the identifier. There is no document to fetch. The DID encodes the public key bytes directly in the URI.

```
did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
```

This is ideal for factory-provisioned devices that need a stable identity before they have network connectivity. A device's Ed25519 public key is generated at manufacture time, and the `did:key` derived from it is the device's identifier — no registration step, no CA, no network required to establish the identity.

`ndn-did` can resolve `did:key` identifiers locally without any network call:

```rust
let resolver = UniversalResolver::new();

// Resolves instantly — the key is encoded in the DID itself
let doc = resolver.resolve(
    "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
).await?;

// Extract the verification method (the public key)
let vm = &doc.verification_method[0];
println!("key type: {}", vm.type_);
```

Once a `did:key` device enrolls with an NDNCERT CA and gets a proper namespace certificate, it transitions from `did:key` (offline bootstrapping) to `did:ndn` (full network identity). The factory credential that authorizes this transition can be a `FactoryCredential::DidKey(did_key_string)`, which the CA verifies by checking that the enrollment request was signed with the key encoded in the DID.

## Integration with ndn-security

`ndn-security`'s `Certificate` type and `did:ndn` are two representations of the same thing. A `Certificate` is an NDN Data packet containing a public key, an identity name, a validity period, and a signature from the issuer. A DID Document is a JSON-LD object containing a public key, an identity URI, and optionally a chain of trust. The mapping is direct.

`cert_to_did_document` performs this conversion:

```rust
use ndn_did::cert_to_did_document;
use ndn_security::Certificate;

let cert: Certificate = identity.security_manager().get_certificate()?;
let doc = cert_to_did_document(&cert);

// The DID in the document matches what name_to_did() would produce
assert_eq!(doc.id, name_to_did(cert.identity_name()));
```

The `UniversalResolver`, when resolving a `did:ndn`, uses `ndn-security`'s `CertFetcher` internally to retrieve the certificate over the network and then calls `cert_to_did_document`. This means DID resolution automatically benefits from the certificate cache, the trust schema, and the full certificate chain validation machinery.

The bridge between DID resolution and the `Validator` is equally clean. A resolved `DidDocument` can supply the trust anchor for a `Validator`:

```rust
use ndn_did::UniversalResolver;
use ndn_security::Validator;

let resolver = UniversalResolver::new();
let doc = resolver.resolve("did:ndn:com:acme:sensor-ca").await?;

// Build a Validator that trusts this DID's key as a trust anchor
let validator = Validator::builder()
    .trust_anchor_from_did_document(&doc)?
    .hierarchical_schema()
    .build();
```

This closes the loop on the bootstrap problem. Instead of burning a raw certificate into firmware, you burn a DID. The device resolves that DID on first boot to obtain the CA's public key, then uses that key as the trust anchor for all future certificate validation.

## See Also

- [NDNCERT: Automated Certificate Issuance](./ndncert.md) — how devices obtain namespace certificates using NDNCERT, building on the identity foundation described here
- [Security Model](./security-model.md) — the full certificate chain validation, trust schema, and `SafeData` typestate
- [Fleet and Swarm Security](../guides/fleet-security.md) — end-to-end walkthrough of identity management for 10,000 autonomous vehicles
- [did:ndn Method Specification](../../../did-ndn-spec.md) — the formal W3C DID method spec
