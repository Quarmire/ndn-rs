# ndn-identity

High-level NDN identity management: `NdnIdentity` lifecycle, NDNCERT certificate
enrollment, and fleet zero-touch provisioning. Wraps `ndn-security` and `ndn-cert`
with a single ergonomic handle that covers creation, persistent storage, background
certificate renewal, and DID derivation.

## Key types

| Type | Description |
|------|-------------|
| `NdnIdentity` | Unified signing identity handle with `signer()`, `name()`, `did()` accessors |
| `DeviceConfig` | Fleet provisioning configuration: namespace, CA prefix, factory credential, renewal policy |
| `FactoryCredential` | Credential presented to the CA at first enrollment (token, voucher, etc.) |
| `RenewalPolicy` | When to auto-renew: `WhenPercentRemaining(u8)`, `WhenExpiry(Duration)`, `Manual` |
| `NdncertCa` / `NdncertCaBuilder` | Embedded NDNCERT CA for issuing certificates to devices |
| `EnrollConfig` | Challenge parameters for NDNCERT enrollment |
| `IdentityError` | Error type covering storage, network, and crypto failures |

## Usage

```toml
[dependencies]
ndn-identity = { version = "*" }
```

```rust
use ndn_identity::NdnIdentity;

// Ephemeral (tests, quick prototypes)
let id = NdnIdentity::ephemeral("/com/example/alice")?;

// Persistent — load or create from disk
let id = NdnIdentity::open_or_create(
    Path::new("/var/lib/ndn/identity"),
    "/com/example/alice",
)?;

let signer = id.signer()?;
println!("DID: {}", id.did());
```
