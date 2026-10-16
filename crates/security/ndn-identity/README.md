# ndn-identity

High-level NDN identity management: the `Identity` lifecycle (create, rotate,
recover, delegate), NDNCERT certificate enrollment, and fleet zero-touch
provisioning. Wraps `ndn-security` and `ndn-cert` with a single handle over a
`KeyChain` that covers creation, persistent storage, background certificate
renewal, and DID derivation.

## Key types

| Type | Description |
|------|-------------|
| `Identity` | Managed identity over a `KeyChain` (derefs to it): `signer()`, `name()`, `did()`, plus rotation, recovery, and device delegation |
| `DeviceConfig` | Fleet provisioning configuration: namespace, CA prefix, factory credential, renewal policy |
| `FactoryCredential` | Credential presented to the CA at first enrollment (token, voucher, etc.) |
| `RenewalPolicy` | When to auto-renew: `WhenPercentRemaining(u8)`, `WhenExpiry(Duration)`, `Manual` |
| `NdncertCa` / `NdncertCaBuilder` | Embedded NDNCERT CA for issuing certificates to devices; `serve_with_feed` adds the validator-checked device-approval `ApprovalFeed` |
| `NdncertClient` / `ChallengeParams` | Consumer-backed NDNCERT client over the shared `ndn_cert::client::enroll` driver |
| `IdentityError` | Error type covering storage, network, and crypto failures |

## Usage

```toml
[dependencies]
ndn-identity = { version = "*" }
```

```rust
use ndn_identity::Identity;

// Ephemeral (tests, quick prototypes)
let id = Identity::ephemeral("/com/example/alice")?;

// Persistent — load or create from disk
let id = Identity::open_or_create(
    Path::new("/var/lib/ndn/identity"),
    "/com/example/alice",
)?;

let signer = id.signer()?;
println!("DID: {}", id.did());
```
