# Security Model

## The Problem: Bolted-On vs. Built-In Security

In IP networking, security is an afterthought. TLS secures the *channel* between two endpoints, but the data itself has no inherent protection. Once a TLS session terminates at a CDN or cache, the original security guarantee evaporates. You trust the server, not the data.

NDN flips this entirely. Every Data packet is signed at birth, and the signature travels with the data forever. A cached copy served by a router three hops away is exactly as trustworthy as one delivered directly by the producer -- the signature is over the content, not the channel. This is a profound architectural advantage, but it creates challenges that don't exist in IP security:

- **Key discovery is a networking problem.** A Data packet says "I was signed by key `/sensor/node1/KEY/k1`" -- but that key's certificate is itself an NDN Data packet that must be fetched over the network.
- **Trust is not transitive by default.** Just because a signature is cryptographically valid doesn't mean you should trust it. Which keys are authorized to sign which data? The answer requires *policy*, not just cryptography.
- **Verification has a cost.** Ed25519 verification is fast, but doing it for every packet on a high-throughput forwarder adds up. Local applications on the same machine shouldn't pay that cost.

ndn-rs addresses all three challenges through a layered design: trust schemas define policy, certificate chain validation handles key discovery, and the `SafeData` typestate makes the compiler enforce that unverified data never reaches code that expects verified data.

```mermaid
flowchart LR
    subgraph Producer
        App["Application"] --> Sign["Sign with<br/>Ed25519 / HMAC"]
        Sign --> Data["Signed Data Packet<br/>(signature is part of the wire format)"]
    end

    Data --> Network

    subgraph Network["Network (routers, caches)"]
        R1["Router"] -->|"forward + cache"| R2["Router"]
    end

    Network --> Validate

    subgraph Consumer["Consumer / Forwarder"]
        Validate["Validate signature"] --> Schema["Check trust schema"]
        Schema --> Chain["Walk certificate chain"]
        Chain --> Safe["SafeData"]
    end

    style Safe fill:#2d7a3a,color:#fff
```

The signature is embedded in the packet's wire format. Routers can cache and forward the packet without breaking it. Any consumer, anywhere in the network, can independently verify the signature without contacting the original producer.

## The Journey of a Data Packet

To understand how these pieces fit together, follow a Data packet arriving at a forwarder with `profile = "default"` (forwarder-level validation opted in).

**A temperature reading arrives.** The packet's name is `/sensor/node1/temp/1712400000`, and its SignatureInfo field says it was signed by key `/sensor/node1/KEY/k1`. The raw bytes are sitting in a buffer. At this point, it's just a `Data` -- an unverified blob.

**First question: does the policy allow this?** Before touching any cryptography, the forwarder consults its trust schema. The schema has a rule saying data under `/sensor/<node>/<type>` must be signed by `/sensor/<node>/KEY/<id>`. The forwarder pattern-matches: `<node>` captures `node1` in both the data name and the key name. The captures are consistent, so the schema allows this combination. If the key name had been `/other-org/KEY/k1`, the schema would reject immediately -- no crypto needed.

**Next: find the certificate.** The key name `/sensor/node1/KEY/k1` points to a certificate, which in NDN is just another Data packet containing the signer's public key. The forwarder checks its `CertCache` first. On a cache hit, it already has the public key bytes and can proceed. On a miss, it sends a normal Interest for `/sensor/node1/KEY/k1` -- the certificate flows through the same Interest/Data machinery as any other content, and gets cached in the Content Store for future lookups.

**Verify the signature.** With the public key in hand, the forwarder runs Ed25519 verification over the packet's signed region (everything from the Name through the SignatureInfo). If the signature doesn't check out, the packet is rejected.

**But who signed the certificate?** The certificate for `/sensor/node1/KEY/k1` is itself a signed Data packet. Maybe it was signed by `/sensor/KEY/root`. The forwarder walks up the chain: fetch that certificate, verify its signature, check *its* issuer, and so on -- until it reaches a trust anchor (a self-signed certificate the forwarder was configured to trust at startup). If the chain exceeds a configurable maximum depth, or if a cycle is detected, validation fails.

**The packet becomes `SafeData`.** If the entire chain checks out, the `Data` is wrapped in a `SafeData` struct. From this point forward, the type system guarantees that this data has been verified. Code that expects `SafeData` literally cannot receive unverified data -- it won't compile.

```mermaid
flowchart LR
    Data["Data Packet\n/sensor/node1/temp\nSigned by /sensor/node1/KEY/k1"]
    --> SchemaCheck{"Trust schema\nallows\n(data, key)?"}

    SchemaCheck -->|No| Reject["REJECT\nSchemaMismatch"]
    SchemaCheck -->|Yes| CacheHit{"In\nCertCache?"}

    CacheHit -->|Yes| VerifySig1["Verify signature\nwith cert pubkey"]
    CacheHit -->|No| Fetch["Fetch cert\nvia Interest"]
    Fetch -->|"Not found"| Pending["PENDING\n(retry later)"]
    Fetch -->|Found| VerifySig1

    VerifySig1 -->|Invalid| RejectSig["REJECT\nBadSignature"]
    VerifySig1 -->|Valid| IsAnchor{"Issuer is\ntrust anchor?"}

    IsAnchor -->|Yes| VerifyAnchor["Verify cert\nwith anchor key"]
    IsAnchor -->|No| DepthCheck{"depth <\nmax_chain?"}

    DepthCheck -->|No| RejectDeep["REJECT\nChainTooDeep"]
    DepthCheck -->|Yes| CacheHit2{"Fetch issuer\ncert (cached?)"}
    CacheHit2 -->|Yes| VerifySig1
    CacheHit2 -->|No| FetchIssuer["Fetch issuer\nvia Interest"]
    FetchIssuer --> VerifySig1

    VerifyAnchor -->|Valid| Accept["ACCEPT\nSafeData ✓"]
    VerifyAnchor -->|Invalid| RejectAnchor["REJECT\nBadSignature"]

    style Accept fill:#2d7a3a,color:#fff
    style Reject fill:#8c2d2d,color:#fff
    style RejectSig fill:#8c2d2d,color:#fff
    style RejectDeep fill:#8c2d2d,color:#fff
    style RejectAnchor fill:#8c2d2d,color:#fff
    style Pending fill:#8c6d2d,color:#fff
```

The result of validation is one of three outcomes:

```rust
pub enum ValidationResult {
    /// Signature valid, chain terminates at a trust anchor.
    Valid(Box<SafeData>),
    /// Signature invalid or trust schema violated.
    Invalid(TrustError),
    /// Missing certificate -- needs fetching.
    Pending,
}
```

The `Pending` state is important: because certificates are fetched over the network, validation can be asynchronous. A forwarder may need to pause validation, send an Interest for a missing certificate, and resume when the certificate arrives.

## How Producers Sign Data

On the other side of the equation, a producer needs to create a cryptographic identity and attach signatures to outgoing Data packets.

`KeyChain` in `ndn-security` is the single entry point for NDN security in both applications and the forwarder:

```rust
use ndn_security::KeyChain;

// Ephemeral identity (tests, short-lived producers) — in-memory only
let keychain = KeyChain::ephemeral("/sensor/node1")?;
let signer = keychain.signer()?;

// Persistent identity — generates on first run, reloads on subsequent runs
let keychain = KeyChain::open_or_create(
    std::path::Path::new("/var/lib/ndn/sensor-id"),
    "/sensor/node1",
)?;
let signer = keychain.signer()?;
```

`ndn-app` re-exports `KeyChain` from `ndn-security`, so `use ndn_app::KeyChain` works too.

The `SignWith` extension trait provides a synchronous one-liner for signing a packet builder without spawning an async task — useful in closures and non-async contexts:

```rust
use ndn_security::SignWith;
use ndn_packet::encode::DataBuilder;

let wire = DataBuilder::new("/sensor/node1/temp".parse()?, b"23.5°C")
    .sign_with_sync(&*signer)?;  // returns Bytes directly
```

Under the hood, signing is handled by the `Signer` trait. Both traits in the security layer (`Signer` and `Verifier`) use `BoxFuture` for dyn-compatibility, so they can be stored as `Arc<dyn Signer>` in the key store and swapped at runtime:

```rust
pub trait Signer: Send + Sync + 'static {
    fn sig_type(&self) -> SignatureType;
    fn key_name(&self) -> &Name;
    fn cert_name(&self) -> Option<&Name> { None }
    fn public_key(&self) -> Option<Bytes> { None }

    fn sign<'a>(&'a self, region: &'a [u8])
        -> BoxFuture<'a, Result<Bytes, TrustError>>;

    /// CPU-only signers (Ed25519, HMAC) override this to
    /// avoid async overhead.
    fn sign_sync(&self, region: &[u8]) -> Result<Bytes, TrustError>;
}
```

ndn-rs ships two signer implementations:

| Algorithm | Signer | Signature Size | Use Case |
|-----------|--------|---------------|----------|
| Ed25519 | `Ed25519Signer` | 64 bytes | Default for all Data packets |
| HMAC-SHA256 | `HmacSh256Signer` | 32 bytes | Pre-shared key authentication (~10x faster) |
| BLAKE3 | `Blake3Signer` | 32 bytes | High-throughput; experimental type code 6 (not yet in NDN Packet Format spec) |

Both implement `sign_sync` for a CPU-only fast path -- no async state machine overhead when the operation is pure computation.

## DataBuilder Signing Methods

`DataBuilder` exposes several signing methods with different performance and conformance characteristics:

| Method | Allocations | Crypto | NDN conformant | When to use |
|--------|-------------|--------|----------------|-------------|
| `sign_digest_sha256()` | **1** | SHA-256 in-place | Yes | Default for all high-throughput production |
| `sign_sync(type, kl, fn)` | 2 | caller-supplied | Yes | Ed25519 / HMAC — synchronous callers |
| `sign(type, kl, fn).await` | 3+ | caller-supplied | Yes | Ed25519 / HMAC — async callers |
| `sign_none()` | **1** | None | **No** | Benchmarking raw engine throughput only |
| `build()` | ~4 | None (zeroed SigValue) | Partial | Tests / non-validating consumers |

### `sign_digest_sha256` fast-path details

The fast path achieves its performance by pre-computing all TLV sizes before any allocation, writing every field directly into a single `BytesMut`, and hashing `&buf[signed_start..]` in-place:

```
1 BytesMut::with_capacity(total_size)
  ├─ Data TLV header
  ├─ Name TLV           ┐
  ├─ MetaInfo TLV       │  signed region — hashed in-place, no copy
  ├─ Content TLV        │
  ├─ SignatureInfo (5B) ─┘
  └─ SignatureValue (34B = type+len+SHA256)
```

#### Known limitations (not currently addressable)

1. **No `no_std` support.** The fast path uses `ring` for SHA-256, which requires the standard library.  `no_std` callers must use `build()` and sign the packet externally.  Tracking: if a `ring`-compatible `no_std` SHA-256 is adopted in future, the `#[cfg(feature = "std")]` gate can be lifted.

2. **No KeyLocator in DigestSha256.** The SignatureInfo bytes are hardcoded to `[0x16, 0x03, 0x1B, 0x01, 0x00]` — type, length, SignatureType=0 (DigestSha256) — with no room for a KeyLocator TLV.  This covers the vast majority of uses; self-signed certificates that carry DigestSha256 + KeyLocator must use `sign_sync` instead.

3. **`debug_assert` guards only.** The size pre-computation is verified by `debug_assert_eq!` guards that are compiled out in release builds.  The math is fully deterministic (depends only on the name and content sizes, which don't change between the compute and write phases), so this is safe — the guards exist to catch bugs during development, not to handle runtime variability.

4. **Duplicated encoding logic.** Name/MetaInfo/Content encoding is shared via private helpers (`FastPathSizes`, `write_fields`, `put_vu`) between `sign_digest_sha256` and `sign_none`.  The `sign_sync`/`sign`/`build` paths use `TlvWriter`-based helpers (`write_name`, `write_nni`) instead.  If a new optional field is added to MetaInfo (e.g., `ContentType`), it must be added in both the `TlvWriter` path and the fast-path helpers.

### `sign_none` — benchmarking only

`sign_none()` produces a packet with no `SignatureInfo` or `SignatureValue` TLVs.  It uses the same single-buffer fast path as `sign_digest_sha256` (1 allocation, no crypto), making it the ceiling for producer throughput.

**Validators will reject `sign_none` packets.**  It is only safe to use in pipelines where validation is explicitly disabled — currently, only `FlowSignMode::None` in `ndn-iperf` (selected by passing `--sign none`).  Do not use in any production data plane.

## Trust Schemas in Depth

Trust schemas are the *policy layer* that sits between raw cryptographic verification and actual trust. A valid signature from a stranger is meaningless; what matters is whether the signer was *authorized* to sign that particular data.

A schema is a collection of rules, each pairing a data name pattern with a key name pattern. Patterns use three component types:

```rust
pub enum PatternComponent {
    Literal(NameComponent),   // must match exactly
    Capture(Arc<str>),        // binds one component to a named variable
    MultiCapture(Arc<str>),   // binds one or more trailing components
}
```

The key insight is that **capture variables must be consistent across both patterns**. Consider a sensor network where temperature readings under `/sensor/<node>/temp` must be signed by that node's own key:

```rust
SchemaRule {
    data_pattern: NamePattern(vec![
        Literal(comp("sensor")),
        Capture("node"),
        Capture("type"),
    ]),
    key_pattern: NamePattern(vec![
        Literal(comp("sensor")),
        Capture("node"),    // must match the same value as above
        Literal(comp("KEY")),
        Capture("id"),
    ]),
}
```

When a Data packet named `/sensor/node1/temp` arrives signed by `/sensor/node1/KEY/k1`, the schema matches: `node` captures `node1` in both patterns. But if `node2` tried to sign data for `node1`, the captures would conflict and the schema would reject the packet before any cryptographic verification occurs.

This is a lightweight but powerful mechanism. A few well-chosen rules can express policies like:

- **Hierarchical trust**: data and key must share the same organizational prefix
- **Scope restriction**: a department key can only sign data within its department
- **Role-based signing**: only keys under `/admin/KEY/` can sign configuration updates

ndn-rs provides three built-in schemas for common cases:

- `TrustSchema::new()` -- empty, rejects everything (for strict configurations where you add rules explicitly)
- `TrustSchema::accept_all()` -- wildcard, accepts any signed packet (for testing or trusted environments)
- `TrustSchema::hierarchical()` -- data and key must share the same first name component; the actual hierarchy is enforced by the certificate chain walk

### Text pattern format

Patterns can be written and parsed as human-readable strings. Components are
`/`-separated:

| Syntax | Meaning |
|---|---|
| `/literal` | Matches exactly the component `literal` |
| `/<var>` | Captures one component into `var` |
| `/<**var>` | Captures all remaining components into `var` (must be last) |

A rule is written as `<data_pattern> => <key_pattern>`:

```text
/sensor/<node>/<type> => /sensor/<node>/KEY/<id>
```

Parse and serialise in code:

```rust
use ndn_security::SchemaRule;

let rule = SchemaRule::parse("/sensor/<node>/<type> => /sensor/<node>/KEY/<id>")?;
println!("{}", rule.to_string());
```

### Configuring rules in the router TOML

Add `[[security.rule]]` sections to `ndn-fwd.toml`. Rules are loaded at
startup and added to the active schema on top of whatever the `profile` setting
implies:

```toml
[security]
# "disabled" is the default — no validation, matching NFD's forwarder behaviour.
# Switch to "default" or "accept-signed" once trust anchors and keys are ready.
profile = "disabled"
trust_anchor = "/etc/ndn/ta.cert"

# Rules are appended on top of whatever the profile implies.
[[security.rule]]
data = "/sensor/<node>/<type>"
key  = "/sensor/<node>/KEY/<id>"

[[security.rule]]
data = "/admin/<**rest>"
key  = "/admin/KEY/<id>"
```

**Profile defaults summary:**

| Profile | Behaviour |
|---|---|
| `"disabled"` | No validation — Data is cached and forwarded as-is **(default)** |
| `"accept-signed"` | Verify signatures but skip certificate chain walking |
| `"default"` | Full hierarchical chain validation with trust schema |

The default is `"disabled"` to match NFD's behaviour: in NDN, Data validation is a
*consumer-side* concern. The producer signs; routers forward; consumers verify.
Enabling forwarder-level validation is an opt-in hardening measure that requires
all trust anchors and certificates to be provisioned first.

Additional `[[security.rule]]` entries are always appended regardless of profile.

> **Comparison with NFD/ndn-cxx:** NFD's *forwarder* does not validate Data at
> all — `ValidatorConfig` is part of the `ndn-cxx` *application library*, not
> the NFD daemon. ndn-rs matches this default (`profile = "disabled"`) but
> additionally lets you opt in to forwarder-level validation, and supports
> *runtime modification* of rules without restarting — NFD's `ValidatorConfig`
> requires a process restart to change its rules.

### Runtime trust schema management API

The trust schema can be modified at runtime via NDN management commands sent to
`/localhost/nfd/security/`:

| Command | What it does |
|---|---|
| `schema-list` | List all active rules with their indices |
| `schema-rule-add` | Append one rule (pass `Uri` = rule string) |
| `schema-rule-remove` | Remove rule at index (pass `Count` = index) |
| `schema-set` | Replace entire schema (pass `Uri` = newline-separated rules) |

Using `ndn-ctl` (or any NFD-compatible management client):

```sh
# List the current rules
ndn-ctl security schema-list

# Add a new rule
ndn-ctl security schema-rule-add "/dept/<team>/<**rest> => /dept/<team>/KEY/<id>"

# Remove rule at index 0
ndn-ctl security schema-rule-remove 0

# Replace the whole schema (empty string rejects everything)
ndn-ctl security schema-set "/org/<**rest> => /org/KEY/<id>"
```

Using the Rust `MgmtClient` API:

```rust
use ndn_ipc::MgmtClient;

let client = MgmtClient::connect("/tmp/ndn.sock").await?;

// List rules
let resp = client.security_schema_list().await?;
println!("{}", resp.status_text);

// Add a rule
client.security_schema_rule_add("/sensor/<node>/<type> => /sensor/<node>/KEY/<id>").await?;

// Remove rule at index 0
client.security_schema_rule_remove(0).await?;

// Replace all rules at once
client.security_schema_set(
    "/sensor/<node>/<type> => /sensor/<node>/KEY/<id>\n\
     /admin/<**rest> => /admin/KEY/<id>"
).await?;
```

Changes take effect immediately for all subsequent validations. In-flight
validations that have already passed the schema check are not affected.

### Mutability design

The schema inside `Validator` is stored behind an `Arc<RwLock<TrustSchema>>`.
Reads (the hot validation path) acquire a shared lock for the duration of the
`allows()` call — typically a few microseconds for small schemas. Writes
(management API) acquire an exclusive lock, which blocks new reads momentarily
but does not affect already-in-progress pipeline tasks.

This design means the management API never requires rebuilding the validator or
draining the pending queue — rules take effect atomically from the perspective
of the validation path.

## The Local Trust Escape Hatch

Not every Data packet needs cryptographic verification. Applications running on the same machine as the forwarder -- connected via shared memory (SHM) or Unix sockets -- are already authenticated by the operating system.

On Unix systems, `SO_PEERCRED` on a Unix socket provides the connecting process's UID. If the forwarder trusts that UID, Data from that face skips the entire certificate chain walk:

```rust
SafeData::from_local_trusted(data, uid)
```

The resulting `SafeData` carries a `TrustPath::LocalFace { uid }` instead of `TrustPath::CertChain(...)`, recording *how* trust was established. This matters for two reasons:

1. **Performance.** Ed25519 verification, while fast, is not free. On a forwarder handling millions of local application packets per second, skipping crypto for trusted local faces is significant.
2. **Bootstrapping.** A newly started application doesn't have certificates yet. Local trust lets it communicate with the forwarder immediately, even before setting up its cryptographic identity.

The critical point is that the `SafeData` type is the same in both paths. Downstream code doesn't need to know (or care) whether trust was established cryptographically or locally -- it just receives a `SafeData` and knows the data has been through a trust check.

## SafeData: The Compiler as Security Auditor

All of the mechanisms above converge on a single type: `SafeData`. This is a Data packet whose signature has been verified -- either through the full certificate chain or via local trust.

```rust
pub struct SafeData {
    pub(crate) inner: Data,
    pub(crate) trust_path: TrustPath,
    pub(crate) verified_at: u64,    // nanoseconds since epoch
}

pub enum TrustPath {
    /// Validated via full certificate chain.
    CertChain(Vec<Name>),
    /// Trusted because it arrived on a local face.
    LocalFace { uid: u32 },
}
```

The `pub(crate)` fields are the key detail. Application code cannot construct a `SafeData` -- only `Validator::validate_chain()` and `SafeData::from_local_trusted()` (both inside the `ndn-security` crate) can create one. This is the typestate pattern: the type itself encodes a security invariant.

Any API that accepts `SafeData` instead of `Data` is making a compile-time assertion: "this function only operates on verified data." If a developer accidentally tries to pass an unverified `Data` packet to such a function, the code won't compile. There's no runtime check to forget, no boolean flag to misread, no error to swallow. The compiler is the security auditor, and it never takes a day off.

This is especially powerful in the forwarding pipeline. The Content Store insertion stage, for example, can require `SafeData` -- guaranteeing that the cache will never serve unverified content, even if a bug elsewhere in the pipeline skips validation. The guarantee is structural, not procedural.

## Identity and DID Integration

The security primitives described above — certificates, trust schemas, `SafeData` — are the foundation. But they answer *how* to verify data, not *who* to trust in the first place. Two higher-level layers sit above `ndn-security` to close that gap.

### From Certificate to DID Document

`ndn-security`'s `Certificate` type is an NDN Data packet containing a public key, an identity name, a validity period, and an issuer signature. This maps directly onto a W3C DID Document: the identity name becomes the DID URI, the public key becomes a `JsonWebKey2020` verification method, and the issuer signature establishes the chain of trust.

The `ndn-did` crate provides `cert_to_did_document` to perform this conversion explicitly, and `name_to_did` / `did_to_name` to translate between NDN name and DID URI forms. A `Certificate` issued by NDNCERT is simultaneously a valid DID Document with no additional encoding step. This means that any system in the W3C DID ecosystem — a DIF Universal Resolver driver, a Verifiable Credential verifier, a DIDComm messaging layer — can interoperate with NDN identities directly.

See [Identity and Decentralized Identifiers](./identity-and-did.md) for the full treatment: how `did:ndn` names are encoded, how resolution works over NDN transports, how to cross-anchor with `did:web` for web interoperability, and how `did:key` enables offline bootstrapping for factory-provisioned devices.

### NdnIdentity: Identity Lifecycle Above KeyChain

`ndn-security` provides the low-level building blocks (`KeyChain`, `Signer`, `Validator`, `CertCache`). `ndn-identity` wraps `KeyChain` in an `NdnIdentity` type that adds certificate lifecycle management on top.

`NdnIdentity` implements `Deref<Target = KeyChain>`, so every `KeyChain` method (`signer()`, `validator()`, `add_trust_anchor()`, `manager_arc()`) is available directly on `NdnIdentity` without any bridging:

```rust
let identity = NdnIdentity::open_or_create(path, "/sensor/node1").await?;

// These call KeyChain methods via Deref — no indirection required
let signer  = identity.signer()?;
let anchor  = Certificate::decode(anchor_bytes)?;
identity.add_trust_anchor(anchor);
let validator = identity.validator();
```

Beyond `KeyChain`, `NdnIdentity` adds:

- **Persistent storage** — keys and certificates survive reboots via `NdnIdentity::open_or_create`
- **Ephemeral identities** — `NdnIdentity::ephemeral` creates a throw-away in-memory identity for tests
- **Automated NDNCERT enrollment** — `NdnIdentity::provision` runs the full NDNCERT client exchange, handling token and possession challenges
- **Background renewal** — configurable `RenewalPolicy` automatically renews certificates before they expire
- **DID access** — `identity.did()` returns the `did:ndn` URI for the identity's name without any conversion boilerplate

For most applications, `NdnIdentity` is the only security API they need. Direct use of `Validator` or `CertCache` is reserved for advanced scenarios like custom trust schema configuration or building a CA. When framework code needs the underlying `Arc<SecurityManager>`, call `identity.manager_arc()`.

See [NDNCERT: Automated Certificate Issuance](./ndncert.md) for how certificate issuance works end-to-end, including the CA hierarchy, challenge types, and short-lived certificate renewal.
