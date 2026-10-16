# ndn-cert

NDNCERT — NDN Certificate Management Protocol. Implements automated certificate issuance over NDN using a CA/client exchange with pluggable challenge handlers (email, PIN, token, YubiKey HOTP, possession). Transport-agnostic: all protocol messages are serialized as JSON bytes carried in NDN ApplicationParameters/Content fields, with Phase 1C adding full NDN TLV encoding for interop with the reference C++ implementation.

## Key Types

| Type / Trait | Role |
|---|---|
| `client::enroll` / `CaExchange` | The one client driver: NEW → CHALLENGE rounds over any `CaExchange` transport (Interest wire in, Data out); `client::fetch_issued_cert` fetches the result |
| `EnrollmentSession` | Client-side NDNCERT state machine the driver runs |
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
use ndn_cert::client::{enroll, fetch_issued_cert};

// `exchange: impl CaExchange` — e.g. `ndn_identity::NdncertClient` over a Consumer.
let cert_name = enroll(&mut exchange, &ca_prefix, signer, 86_400, "token", |_round| {
    std::future::ready(Ok(params.take()))  // `None` stops after round 0
})
.await?;
let cert_data = fetch_issued_cert(&mut exchange, &cert_name).await?;
```

Part of the [ndn-rs](../../README.md) workspace.
