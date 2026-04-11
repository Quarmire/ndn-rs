# Setting Up an NDNCERT CA

This guide walks through standing up an NDNCERT certificate authority from scratch. By the end you will have a running CA that accepts enrollment requests, issues 24-hour certificates, and handles both factory token provisioning and renewal via possession proof.

If you are deploying a fleet of devices and want the full architectural context, read [Fleet and Swarm Security](./fleet-security.md) first. This guide focuses on the mechanics.

## Prerequisites

- A running NDN router (`ndn-fwd` on the same host, or reachable via UDP/Ethernet)
- Rust toolchain and the ndn-rs workspace checked out
- An identity for the CA (either self-signed or issued by a higher-level CA)

The CA uses `ndn-identity`, `ndn-cert`, and `ndn-app`. Add them to your `Cargo.toml`:

```toml
[dependencies]
ndn-identity = { path = "crates/ndn-identity" }
ndn-cert     = { path = "crates/ndn-cert" }
ndn-app      = { path = "crates/ndn-app" }
tokio        = { version = "1", features = ["full"] }
anyhow       = "1"
```

## Step 1: Create the CA Identity

The CA needs its own NDN identity — a key pair and a self-signed certificate (for a root CA) or a certificate issued by a higher authority (for a sub-CA). Use `NdnIdentity::open_or_create` so the identity persists across restarts.

```rust
use std::path::PathBuf;
use ndn_identity::NdnIdentity;

// Create (or load from disk) the CA's identity
let ca_identity = NdnIdentity::open_or_create(
    &PathBuf::from("/var/lib/ndn/ca-identity"),
    "/example/ca",
).await?;

println!("CA identity: {}", ca_identity.name());
println!("CA DID:      {}", ca_identity.did());
```

If `/var/lib/ndn/ca-identity` is empty, `open_or_create` generates a new Ed25519 key pair and creates a self-signed certificate. On subsequent runs, it loads the existing key and certificate from disk. The identity directory should be on a persistent, access-controlled volume — it contains the CA's private key.

For a **sub-CA** whose certificate was issued by a root CA, you would provision it with `NdnIdentity::provision` (see Step 5 of the [Fleet Security](./fleet-security.md#factory-provisioning-zero-human-steps) guide) and then load it with `open_or_create` for subsequent CA operations.

## Step 2: Configure Challenge Handlers

Challenges are how the CA verifies that an applicant is authorized to receive a certificate. You can configure multiple challenge types on a single CA; the CA advertises them all in its INFO response and the applicant picks the one it supports.

### Token Challenge

Best for factory provisioning (ZTP). Pre-generate tokens and burn them into firmware.

```rust
use ndn_cert::{TokenStore, TokenChallenge};

let mut store = TokenStore::new();

// Add individual tokens
store.add("tok-a3f9b2e1d4c5".to_string());
store.add("tok-7e8f1a2b3c4d".to_string());

// Or add a batch
let tokens: Vec<String> = generate_tokens(1000);
store.add_many(tokens);

let token_challenge = TokenChallenge::new(store);
```

Tokens are single-use and permanently consumed when presented. There is no way to "reset" a token — generate new ones if needed.

### Possession Challenge

Best for renewal and sub-namespace enrollment. The applicant proves it holds a certificate that the CA already trusts.

```rust
use ndn_cert::PossessionChallenge;
use ndn_security::Certificate;

// Trust anything signed by our own CA cert (for renewals)
let ca_cert = ca_identity.security_manager().get_certificate()?;
let possession_challenge = PossessionChallenge::new(vec![ca_cert]);

// Or trust a set of root-of-trust certificates (for ECU enrollment)
let ecu_roots: Vec<Certificate> = load_hardware_root_certs()?;
let ecu_challenge = PossessionChallenge::new(ecu_roots);
```

## Step 3: Configure Namespace Policy

The namespace policy controls which certificate requests the CA will accept. The two main options are `HierarchicalPolicy` (default, recommended for most deployments) and `DelegationPolicy` (for custom rules).

```rust
use ndn_cert::HierarchicalPolicy;

// HierarchicalPolicy: only accept namespaces that are suffixes of the CA's own name.
// CA name: /example/ca
// Accepted: /example/ca/devices/sensor-001
//           /example/ca/users/alice
// Rejected: /other-org/device/001  (different prefix)
//           /example               (CA's own name — not issued to applicants)
let policy = HierarchicalPolicy;
```

For a CA named `/fleet/ca`, this means it only issues certificates under `/fleet/ca/...`. If you want the CA to issue for `/fleet/...` (dropping the `ca` component), use a `DelegationPolicy` with explicit rules.

## Step 4: Build and Start the CA

```rust
use std::time::Duration;
use ndn_cert::NdncertCa;
use ndn_app::Producer;

let ca = NdncertCa::builder()
    .name("/example/ca")
    .signing_identity(&ca_identity)
    .challenge(token_challenge)
    .challenge(possession_challenge)
    .policy(HierarchicalPolicy)
    .cert_lifetime(Duration::from_secs(24 * 3600)) // 24 hours
    .build()?;

// Register the CA prefix with the router and start serving
let producer = Producer::connect("/tmp/ndn.sock", "/example/ca").await?;

println!("NDNCERT CA running on /example/ca");
ca.serve(producer).await?;
```

`ca.serve(producer)` drives the CA's event loop — it processes incoming INFO, NEW, and CHALLENGE Interests until the producer is shut down. This call does not return until the producer is dropped or the router disconnects.

## Step 5: Provision a Device

On the device side, `NdnIdentity::provision` handles the full NDNCERT client exchange:

```rust
use std::path::PathBuf;
use ndn_identity::{NdnIdentity, DeviceConfig, FactoryCredential, RenewalPolicy};

let config = DeviceConfig {
    namespace: "/example/ca/devices/sensor-001".to_string(),
    storage: PathBuf::from("/var/lib/ndn/sensor-identity"),
    factory_credential: FactoryCredential::Token("tok-a3f9b2e1d4c5".to_string()),
    ca_prefix: "/example/ca".parse()?,
    renewal: RenewalPolicy::WhenPercentRemaining(20),
    delegate: None,
};

let identity = NdnIdentity::provision(config).await?;
println!("Provisioned: {}", identity.did());
// → did:ndn:example:ca:devices:sensor-001
```

## Step 6: Verify the Certificate Chain

After provisioning, verify the full chain from the device cert back to the trust anchor:

```rust
use ndn_security::{Validator, TrustSchema};

// Load the CA's certificate as a trust anchor
let ca_cert = ca_identity.security_manager().get_certificate()?;

// Build a validator that trusts the CA cert
let validator = Validator::builder()
    .trust_anchor(ca_cert)
    .schema(TrustSchema::hierarchical())
    .build();

// Fetch a Data packet signed by the device
let data: Data = /* ... */;

match validator.validate_chain(&data).await {
    ValidationResult::Valid(safe_data) => println!("valid: chain verified"),
    ValidationResult::Invalid(e) => eprintln!("invalid: {e}"),
    ValidationResult::Pending => println!("cert not yet fetched"),
}
```

## Generating Provisioning Tokens

For factory-scale deployments, generate tokens programmatically and hand them to the manufacturing system:

```rust
use ndn_cert::TokenStore;

fn generate_tokens(count: usize) -> Vec<String> {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..count)
        .map(|_| {
            let bytes: [u8; 16] = rng.gen();
            format!("tok-{}", hex::encode(bytes))
        })
        .collect()
}

// Generate 10,000 tokens for a production run
let tokens = generate_tokens(10_000);

// Write them to a file for the manufacturing system
let csv = tokens.join("\n");
std::fs::write("factory-tokens.csv", csv)?;

// Load them into the CA's token store
let mut store = TokenStore::new();
store.add_many(tokens);
```

Keep the token list in a secure location. A leaked token list allows unauthorized enrollment under your CA's namespace.

## Running Multiple CA Replicas

To run a second CA replica for high availability, point it at the same identity storage (read-only — the key material is the same on all replicas) and the same distributed token store. Register all replicas under the same prefix in the FIB.

```
FIB entry:  /example/ca → face-1 (CA replica A)
                          face-2 (CA replica B)
                          face-3 (CA replica C)
```

The forwarder distributes Interests across all registered faces. If one replica is unreachable, Interests naturally route to the others (with a brief delay for the forwarder's dead face detection).

For possession challenges, there is no shared state — each replica independently verifies the proof. For token challenges, the `TokenStore` backend must be shared (e.g., backed by Redis or etcd) so a token consumed at one replica is not reusable at another.

```rust
// Replica A and Replica B both use the same distributed token store
let store = TokenStore::from_redis("redis://ca-token-store:6379")?;
```

## Rotating the CA Certificate

CA certificate rotation is a planned operation. The procedure:

1. **Offline ceremony**: On the machine holding the root (or parent) CA, issue a new sub-CA certificate with a later validity period. This is done with the same NDNCERT exchange, with the root CA as the issuer.

2. **Update trust anchors**: Distribute the new CA certificate to all validators in your fleet. This can be done via NDN sync (SVS) — validators subscribe to a trust anchor sync group and pick up the new cert automatically.

3. **Transition period**: Run the old and new CA certificates simultaneously. Devices renewing during the transition may receive either. Both are valid because both chain to the same root.

4. **Retire old cert**: Once the old CA cert's validity period expires, it is automatically invalid. No explicit retirement step needed — short-lived certs handle this naturally.

The root CA offline ceremony is the most sensitive step. Use an air-gapped machine, record the ceremony, and rotate root CA certs infrequently (once every few years is typical).

## Full Working Example

Here is a complete, self-contained CA and client example you can run directly:

```rust
use std::path::PathBuf;
use std::time::Duration;
use ndn_identity::{NdnIdentity, DeviceConfig, FactoryCredential, RenewalPolicy};
use ndn_cert::{NdncertCa, TokenStore, TokenChallenge, PossessionChallenge, HierarchicalPolicy};
use ndn_app::Producer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // --- CA setup ---

    let ca_identity = NdnIdentity::open_or_create(
        &PathBuf::from("/tmp/demo-ca-identity"),
        "/demo/ca",
    ).await?;

    let mut token_store = TokenStore::new();
    token_store.add("demo-token-abc123".to_string());

    let ca_cert = ca_identity.security_manager().get_certificate()?;
    let possession = PossessionChallenge::new(vec![ca_cert]);

    let ca = NdncertCa::builder()
        .name("/demo/ca")
        .signing_identity(&ca_identity)
        .challenge(TokenChallenge::new(token_store))
        .challenge(possession)
        .policy(HierarchicalPolicy)
        .cert_lifetime(Duration::from_secs(24 * 3600))
        .build()?;

    let producer = Producer::connect("/tmp/ndn.sock", "/demo/ca").await?;

    // Spawn the CA in the background
    tokio::spawn(async move {
        ca.serve(producer).await.expect("CA failed");
    });

    // --- Device provisioning ---

    let device_config = DeviceConfig {
        namespace: "/demo/ca/device/001".to_string(),
        storage: PathBuf::from("/tmp/demo-device-identity"),
        factory_credential: FactoryCredential::Token("demo-token-abc123".to_string()),
        ca_prefix: "/demo/ca".parse()?,
        renewal: RenewalPolicy::WhenPercentRemaining(20),
        delegate: None,
    };

    let device_identity = NdnIdentity::provision(device_config).await?;

    println!("Device enrolled!");
    println!("  Name: {}", device_identity.name());
    println!("  DID:  {}", device_identity.did());

    // Use the device signer to sign Data packets
    let signer = device_identity.signer()?;
    println!("  Key name: {}", signer.key_name());

    Ok(())
}
```

## See Also

- [NDNCERT Protocol Deep Dive](../deep-dive/ndncert.md) — how the protocol works internally
- [Fleet and Swarm Security](./fleet-security.md) — large-scale deployment patterns
- [Identity and DIDs](../deep-dive/identity-and-did.md) — how NDNCERT-issued certs map to W3C DIDs
- [Building NDN Applications](./building-ndn-apps.md) — using `NdnIdentity` in your application
