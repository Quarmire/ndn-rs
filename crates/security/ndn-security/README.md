# ndn-security

Cryptographic signing, verification, and trust-policy enforcement for NDN packets. The type system enforces security: only packets wrapped in `SafeData` (produced by `Validator`) are considered verified, making it a compile-time error to forward unvalidated data. `SecurityManager` provides a high-level facade over the lower-level primitives.

## Key Types

| Type / Trait | Role |
|---|---|
| `Signer` | Trait for signing NDN packets |
| `Ed25519Signer` / `HmacSha256Signer` | Concrete signers |
| `Verifier` / `Ed25519Verifier` | Signature verification trait and Ed25519 implementation |
| `Validator` | Chains signature verification with trust schema lookup |
| `TrustSchema` | Name-pattern rules for trust decisions |
| `NamePattern` / `PatternComponent` | Regex-like name components for trust rules |
| `SafeData` | Newtype proving a Data packet has passed validation |
| `KeyStore` / `MemKeyStore` | In-memory key storage; implement `KeyStore` for persistent backends |
| `CertCache` / `Certificate` | Certificate lookup cache |
| `CertFetcher` | Async certificate retrieval via the NDN network |
| `FilePib` | File-system Public Information Base |
| `SecurityManager` | High-level facade combining signer, verifier, validator, and PIB |
| `SecurityProfile` | Named security configuration preset |

## Feature Flags

| Flag | Default | Description |
|---|---|---|
| `yubikey-piv` | no | Hardware key storage via YubiKey PIV (requires pcscd) |

## Usage

```rust
use ndn_security::{Ed25519Signer, Validator, TrustSchema};

let signer = Ed25519Signer::generate()?;
// sign a packet
let signed_data = data_builder.sign_with(&signer)?;

// validate before forwarding
let safe = validator.validate(signed_data).await?; // returns SafeData
```

Part of the [ndn-rs](../../README.md) workspace.
