# Identity and keys

An NDN identity is a name plus a key pair, signed by a certificate.
The `KeyChain` is the single object that holds identities, their
keys, and the policies that govern signing and validation. This
page covers the three things an application author needs to know:
identities, signing info, and trust policies.

## KeyChain

```rust,ignore
use ndn::prelude::*;
use ndn::KeyChain;

# async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
let keychain = KeyChain::open_default().await?;
# Ok(()) }
```

`KeyChain::open_default()` opens the operating-system PIB (Personal
Information Base) at `~/.ndn/pib.db` on native targets and an
IndexedDB-backed PIB in the browser. The opened keychain knows the
host's identities, their keys, and any certificates that have been
imported.

`KeyChain` lives at `crates/spec/ndn-security/src/keychain.rs`. The
Develop tier re-exports it as `ndn::KeyChain`.

## Identities

An identity is a name. Each identity owns one or more keys; one of
those keys is the *default* and is used for signing unless an
explicit selector overrides it.

```rust,ignore
# use ndn::prelude::*;
# use ndn::KeyChain;
# async fn run(keychain: &mut KeyChain) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
let identity = keychain.create_identity("/alice").await?;
let key = identity.default_key();
let cert = identity.self_signed_cert();
# Ok(()) }
```

The on-disk shape: each identity gets a directory under the PIB;
keys are stored as Ed25519 / ECDSA private keys; certificates are
stored as `Data` packets under the standard NDN cert naming
convention (`/<identity>/KEY/<key-id>/<issuer-id>/<version>`).

## Certificates

A certificate is a signed `Data` packet whose content is the
identity's public key. Certificates carry a validity period and a
key locator pointing to the issuer's key.

| Verb | Where |
|---|---|
| Create a self-signed cert | `identity.self_signed_cert()` |
| Import a cert (e.g. from NDNCERT enrollment) | `keychain.import_cert(&cert).await?` |
| Issue a cert for another identity | `keychain.issue_cert(&other_key, ...).await?` |
| Enroll via NDNCERT | See [NDNCERT setup](../guides/ndncert-setup.md). |

## SigningInfo

`SigningInfo` is the "sign me with X" descriptor. The `KeyChain`
takes it; the producer takes it; the Responder takes it.

```rust,ignore
use ndn::SigningInfo;

// Sign with /alice's default key:
let info = SigningInfo::by_identity("/alice");

// Sign with a specific key under /alice:
let info = SigningInfo::by_key("/alice/KEY/...");

// Sign with an explicit cert (key + cert metadata):
let info = SigningInfo::by_cert(cert.name().clone());

// SHA-256 digest only (no producer identity):
let info = SigningInfo::sha256_digest();
```

A `SigningInfo` resolves to a `SignerSelection` inside the
`KeyChain`. That extra step exists so `TrustPolicy` decisions are
applied before the bytes are signed. See `crates/spec/ndn-security/src/keychain.rs:143`
for the resolution path.

## Trust policies

When you fetch a `Data`, the Consumer's `ValidationPolicy` decides
whether to accept it. Both the policy and its building blocks are
re-exported from the Develop umbrella:

```rust,ignore
use ndn::{InsecureTrust, StaticTrust, LvsTrust, HierarchicalPolicy, ValidationPolicy};
```

| Policy | What it accepts |
|---|---|
| `InsecureTrust` | Any signature. Tests only. |
| `StaticTrust` | Signatures from an explicit allowlist of keys. |
| `LvsTrust` | Light Versatile Schema rules (LVS) — pattern-based. |
| `HierarchicalPolicy` | Parent-name key signs child-name data. |
| `AcceptAllPolicy` | Skips validation entirely (degraded mode). |

For a tabular catalog with rule examples: [Trust policies](../reference/trust-policies.md).

## PIB backends

| Backend | Where it lives | Used by |
|---|---|---|
| `SqlitePib` | SQLite database at `~/.ndn/pib.db` | Native targets (Linux/macOS/Windows). |
| `IdbPib` | IndexedDB origin store | Browser (`wasm32-unknown-unknown`). |
| `MemPib` | In-process map | Tests; the `KeyChain::open_memory()` constructor. |

The default constructor picks the right backend for the build
target. To override the path:

```rust,ignore
use ndn::KeyChain;
# async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
let keychain = KeyChain::open_at("/var/lib/myapp/pib.db").await?;
# Ok(()) }
```

## SafeBag — exporting identities

A `SafeBag` is a passphrase-encrypted bundle of an identity, its
keys, and its certificates. The format is interoperable with
ndnsec; the operator workflow is in
[NDNCERT setup → invite tokens](../guides/ndncert-setup.md).

```rust,ignore
use ndn::KeyChain;
# async fn run(keychain: &KeyChain) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
let bytes = keychain.export_safebag("/alice", b"passphrase").await?;
std::fs::write("alice.safebag", &bytes)?;
# Ok(()) }
```

The receiving side calls `keychain.import_safebag(&bytes, passphrase)`.

## See also

- [NDNCERT setup](../guides/ndncert-setup.md) — operator and joiner
  workflow for automated certificate issuance.
- [Trust policies](../reference/trust-policies.md) — concrete policy
  catalog with rule shapes.
- [Develop tier → KeyChain](../api/develop.md#keychain) — full API
  surface.
- `crates/spec/ndn-security/` — implementation; the trait surfaces
  are in `trust.rs`, `validation_policy.rs`, `keychain.rs`.
