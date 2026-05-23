# ndn-cert

NDNCERT — NDN Certificate Management Protocol. Implements automated certificate issuance over NDN using a CA/client exchange with pluggable challenge handlers (email, PIN, token, YubiKey HOTP, possession). Transport-agnostic: all protocol messages are serialized as JSON bytes carried in NDN ApplicationParameters/Content fields, with Phase 1C adding full NDN TLV encoding for interop with the reference C++ implementation.

## Key Types

| Type / Trait | Role |
|---|---|
| `EnrollmentSession` | Client-side NDNCERT session: INFO → PROBE → NEW → CHALLENGE flow |
| `CaConfig` / `CaState` | CA configuration and runtime state |
| `ChallengeHandler` | Trait for implementing custom challenge methods |
| `PinChallenge` | Built-in PIN-based challenge |
| `EmailChallenge` | Built-in email OTP challenge |
| `TokenChallenge` / `TokenStore` | Pre-shared token challenge |
| `YubikeyHotpChallenge` | YubiKey HOTP hardware challenge |
| `PossessionChallenge` | Prove possession of an existing certificate |
| `CaProfile` | CA metadata returned by the INFO endpoint |
| `CertRequest` / `NewResponse` | NEW phase messages |
| `ChallengeRequest` / `ChallengeResponse` | CHALLENGE phase messages |
| `EcdhKeypair` / `SessionKey` | ECDH key agreement for channel encryption (Phase 1C) |
| `NamespacePolicy` / `HierarchicalPolicy` | CA issuance policy — controls which names a CA may certify |
| `CertError` | Unified error type |

## Usage

```rust
use ndn_cert::EnrollmentSession;

let session = EnrollmentSession::new(ca_prefix, key_pair);
let cert = session.run(&mut consumer, challenge_response_fn).await?;
```

Part of the [ndn-rs](../../README.md) workspace.
