# Fleet and Swarm Security

## The Scene

It is 3 AM in a logistics hub. Somewhere on a production line, vehicle number 7,432 rolls off the assembly and is loaded onto a transport truck before sunrise. By noon it will be in a distribution center three states away. By next week it will be making autonomous deliveries in a city it has never visited.

That vehicle needs a cryptographic identity. Every sensor reading it produces, every route update it broadcasts, every command it receives — all of it needs to be signed and verifiable. Not because of a compliance checkbox, but because in an autonomous vehicle network, an unsigned packet is an unsigned check: you have no idea who wrote it or whether it has been tampered with.

You have 10,000 vehicles. Managing 10,000 keys manually is not an option. Neither is shipping them all to a central server for enrollment — that server becomes a single point of failure for your entire fleet. You need a system that:

- Provisions each vehicle automatically, with no human steps per vehicle
- Works even when individual vehicles are temporarily offline
- Allows each vehicle to bootstrap its own sub-systems without internet access
- Makes "revoke this vehicle" as simple as pressing a button, with no CRL distribution
- Scales to sub-systems: a vehicle has 40+ ECUs, each of which also needs a verifiable identity

This guide walks through exactly that system, built on NDNCERT and ndn-security.

## The Trust Hierarchy

Before touching any code, it helps to visualize the chain of trust you are building:

```
Manufacturer root CA
(offline, air-gapped, ceremony once per year)
    │
    └── Fleet operations CA    ← online, runs NDNCERT, issues 24h vehicle certs
    │   /fleet/ca
    │       │
    │       └── Vehicle identity    ← auto-renewed every ~19h
    │           /fleet/vehicle/<vin>
    │               │
    │               └── ECU certs    ← issued by the vehicle itself, offline
    │                   /fleet/vehicle/<vin>/ecu/brake
    │                   /fleet/vehicle/<vin>/ecu/lidar
    │                   /fleet/vehicle/<vin>/ecu/camera-front
    │                   /fleet/vehicle/<vin>/ecu/gps
    │                   ...
```

Each arrow represents a certificate signature. The root CA signs the fleet operations CA cert. The fleet CA signs each vehicle cert. Each vehicle signs its ECU certs. A remote verifier who holds the root CA cert as a trust anchor can walk this chain and verify the authenticity of a sensor reading from a front camera three levels deep — without contacting any CA at verification time.

The offline root CA is critical. If the fleet operations CA is compromised, you can revoke it from the offline root and reissue a new operations CA cert without changing the trust anchor burned into your systems. The blast radius of a CA compromise is bounded by the namespace scope of that CA.

## Factory Provisioning: Zero Human Steps

At manufacture time, the factory generates a unique one-time token for each vehicle and burns it into the firmware alongside the fleet CA prefix. This is the *only* provisioning step that requires access to the factory system. Everything else happens automatically.

On first boot, the vehicle calls `NdnIdentity::provision`. This is a single async call that handles the entire NDNCERT exchange:

```rust
use std::path::PathBuf;
use ndn_identity::{NdnIdentity, DeviceConfig, FactoryCredential, RenewalPolicy};

let vin = read_vin_from_hardware(); // e.g. "1HGBH41JXMN109186"
let token = read_factory_token_from_firmware(); // burned in at manufacture

let config = DeviceConfig {
    // The namespace this vehicle will own
    namespace: format!("/fleet/vehicle/{vin}"),
    // Where to persist the identity (survives reboots)
    storage: PathBuf::from("/var/lib/ndn/identity"),
    // The pre-provisioned token from the factory
    factory_credential: FactoryCredential::Token(token),
    // Where to find the fleet CA
    ca_prefix: "/fleet/ca".parse()?,
    // Renew when 20% lifetime remains (~19h for 24h certs)
    renewal: RenewalPolicy::WhenPercentRemaining(20),
    // No additional delegation needed
    delegate: None,
};

let identity = NdnIdentity::provision(config).await?;

println!("enrolled as: {}", identity.did());
// → did:ndn:fleet:vehicle:1HGBH41JXMN109186
```

Under the hood, `provision` does the following:
1. Generates an Ed25519 key pair (or loads an existing one from `storage` if this is a restart after partial provisioning)
2. Sends an INFO Interest to `/fleet/ca/INFO` to get the CA's certificate and challenge type
3. Sends a NEW Interest with the vehicle's public key and desired namespace
4. Responds to the token challenge with the factory token
5. Receives the signed certificate from the CA
6. Saves the certificate and private key to `storage`
7. Starts the background renewal task

From this point on, `NdnIdentity::open_or_create` will load the existing identity without re-enrolling:

```rust
// Subsequent boots: loads from disk, no NDNCERT exchange needed
let identity = NdnIdentity::open_or_create(
    &PathBuf::from("/var/lib/ndn/identity"),
    &format!("/fleet/vehicle/{vin}")
).await?;
```

The provisioning token is single-use. If someone intercepts the provisioning exchange and tries to replay the token, the CA rejects it — the token is already marked consumed. An attacker would need to intercept the token *before* the vehicle uses it, which requires access to the firmware at manufacture time.

## ECU Delegation: The Vehicle as a Mini-CA

After the vehicle is enrolled, it starts its own NDNCERT CA for its sub-systems. This happens before any internet-facing communication — the ECU enrollment runs over the vehicle's internal network (CAN bus, automotive Ethernet, or internal WiFi).

```rust
use ndn_cert::{NdncertCa, PossessionChallenge, HierarchicalPolicy};
use ndn_app::Producer;

// The vehicle's identity (just enrolled above)
let vehicle_identity = NdnIdentity::open_or_create(/* ... */).await?;

// Start a CA that issues certs under the vehicle's namespace
let ca = NdncertCa::builder()
    .name(format!("/fleet/vehicle/{vin}/ca"))
    .signing_identity(&vehicle_identity)
    // ECUs prove ownership by signing with a hardware root-of-trust key
    // (burned into the ECU at manufacture and stored in the vehicle's manifest)
    .challenge(PossessionChallenge::new(load_ecu_root_certs()?))
    // Only allow namespaces under /fleet/vehicle/<vin>/ecu/
    .policy(HierarchicalPolicy)
    .cert_lifetime(Duration::from_secs(7 * 24 * 3600)) // 1 week for ECUs
    .build()?;

// Serve over the internal network face
let producer = Producer::connect("/var/run/ndn-internal.sock", "/fleet/vehicle").await?;
ca.serve(producer).await?;
```

Each ECU's firmware knows its own role name (e.g., `brake`, `lidar`, `camera-front`) and runs a matching provisioning sequence using `FactoryCredential::Existing`, which presents the ECU's hardware-bound root-of-trust certificate as a possession proof:

```rust
// On the brake ECU:
let ecu_config = DeviceConfig {
    namespace: format!("/fleet/vehicle/{vin}/ecu/brake"),
    storage: PathBuf::from("/var/lib/ndn/ecu-identity"),
    factory_credential: FactoryCredential::Existing {
        cert_name: load_hardware_cert_name()?,
        key_seed: load_hardware_key_seed()?,
    },
    ca_prefix: format!("/fleet/vehicle/{vin}/ca").parse()?,
    renewal: RenewalPolicy::WhenPercentRemaining(10),
    delegate: None,
};

let ecu_identity = NdnIdentity::provision(ecu_config).await?;
```

This entire ECU enrollment happens on the vehicle's internal bus. The vehicle does not need internet connectivity. The fleet CA does not need to know that ECUs exist. The vehicle is the trust authority for its own sub-systems.

## Renewal: 24 Hours Without Drama

Vehicle certs have a 24-hour lifetime. Renewal is fully automatic. The background renewal task in `NdnIdentity` watches the certificate's validity period and, when the remaining lifetime falls below the configured threshold (20% by default, i.e., about 19h into a 24h cert), initiates a new NDNCERT exchange using the possession challenge — the vehicle's current valid certificate is the proof of identity.

```
Time 0h:    Vehicle enrolls, receives 24h cert
Time 19h:   Renewal threshold reached (80% used)
            Background task sends CHALLENGE Interest to /fleet/ca
            using possession of current cert as proof
            Fleet CA issues new 24h cert
Time 24h:   Old cert expires (renewal already done at 19h)
```

If the fleet CA is unreachable when renewal is attempted, the background task retries with exponential backoff. The vehicle continues operating on its current certificate. As long as the vehicle reconnects to the CA within the remaining 5 hours of validity, renewal succeeds before expiry.

For a vehicle that is completely offline for more than 24 hours — say, in an underground facility with no network coverage — the cert expires. When the vehicle reconnects, it re-enrolls using the possession challenge with its recently-expired cert. The CA can be configured to accept certs that expired within a grace period (configurable per CA policy), or it can require a new token (which the fleet operator provisions through the management interface). Either way, the human burden is minimal.

## Revocation Without CRL

Short-lived certs make revocation simple enough that it barely deserves the word "revocation". Here is the entire process for decommissioning a compromised vehicle:

1. An operator opens the fleet management console and marks VIN-1234 as revoked.
2. The console calls the CA's management API: `ca.policy().block_namespace("/fleet/vehicle/vin-1234")`.
3. The next time VIN-1234 tries to renew (within 5 hours), the CA rejects the renewal request.
4. The vehicle's certificate expires within 24 hours of the compromise being detected.

No CRL file to publish. No OCSP responder to query. No list of revoked serials to distribute to 10,000 other vehicles. The network does not need to know anything. Each vehicle's cert either renews successfully or it does not, and within 24 hours of a failed renewal, the cert is gone.

For emergency situations where you cannot wait 24 hours, push a trust schema update that explicitly rejects the compromised namespace. This update propagates through NDN sync (SVS) to all validators in the fleet within seconds. But in practice, operators rarely need this — 24 hours is a small window for most threat scenarios.

## Drone Swarms: The Same Model, No Infrastructure

The same architecture applies to a swarm of 500 drones. The key difference: there may be no internet connection at all. The swarm operates as an ad-hoc NDN mesh.

The swarm includes one or more CA nodes — designated drones (or a ground station) that run the fleet CA. The CA nodes run NDNCERT. Other drones in the swarm enroll by sending Interests that route through the mesh to the nearest CA node.

Because NDN routing is name-based, a drone doesn't need to know *which* CA node handles its request. It just sends an Interest for `/swarm/ca/INFO`, and the forwarder routes it to whichever CA node has a FIB entry for that prefix. If one CA node crashes or flies out of range, the FIB re-converges and requests route to the next nearest CA.

```rust
// A drone in the swarm — same provisioning code as a vehicle
let drone_config = DeviceConfig {
    namespace: format!("/swarm/drone/{serial}"),
    storage: PathBuf::from("/data/ndn-identity"),
    factory_credential: FactoryCredential::Token(firmware_token),
    ca_prefix: "/swarm/ca".parse()?,
    renewal: RenewalPolicy::WhenPercentRemaining(20),
    delegate: None,
};

// This Interest routes through the ad-hoc mesh to the nearest CA node
// No IP, no DNS, no internet required
let identity = NdnIdentity::provision(drone_config).await?;
```

A nearby drone can relay the enrollment Interest through NDN's normal forwarding. If the direct link to the CA is down, the Interest travels through intermediate nodes. This works because NDN routing is hop-by-hop and content-centric: any node with a FIB route to `/swarm/ca` will forward the Interest toward the CA.

## Setting Up the Fleet CA

The fleet operations CA runs on a server (or a cluster of servers for high availability). Here is its complete setup:

```rust
use std::path::PathBuf;
use std::time::Duration;
use ndn_identity::{NdnIdentity, DeviceConfig, FactoryCredential, RenewalPolicy};
use ndn_cert::{NdncertCa, TokenStore, TokenChallenge, PossessionChallenge, HierarchicalPolicy};
use ndn_app::Producer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // The fleet CA's own identity — issued by the root CA during an offline ceremony
    // Stored on disk; load it (or create it if this is the first run)
    let ca_identity = NdnIdentity::open_or_create(
        &PathBuf::from("/var/lib/ndn/fleet-ca-identity"),
        "/fleet/ca",
    ).await?;

    println!("Fleet CA running as: {}", ca_identity.did());

    // Token store: pre-loaded with factory tokens for all vehicles
    // (this list comes from the manufacturing system)
    let mut token_store = TokenStore::new();
    for token in load_factory_tokens_from_manufacturing_db()? {
        token_store.add(token);
    }

    // Possession challenge: allows renewal using an existing /fleet cert
    let fleet_root_cert = ca_identity.security_manager().get_certificate()?;
    let possession = PossessionChallenge::new(vec![fleet_root_cert]);

    // Build the CA
    let ca = NdncertCa::builder()
        .name("/fleet/ca")
        .signing_identity(&ca_identity)
        // Support both challenges: token for first enrollment, possession for renewal
        .challenge(TokenChallenge::new(token_store))
        .challenge(possession)
        // Only issue for /fleet/ namespace
        .policy(HierarchicalPolicy)
        // 24-hour certs
        .cert_lifetime(Duration::from_secs(24 * 3600))
        .build()?;

    // Connect to the router and register the CA prefix
    let producer = Producer::connect("/tmp/ndn-faces.sock", "/fleet/ca").await?;

    println!("Fleet CA accepting enrollment requests...");
    ca.serve(producer).await?;

    Ok(())
}
```

For high availability, run two or three instances of this process, all pointing to the same (distributed) token store. Register all of them under the `/fleet/ca` prefix in the FIB. The forwarder load-balances across them.

## What You Have Built

At the end of this setup:

- 10,000 vehicles each have a cryptographically verifiable identity, issued automatically with no human steps per vehicle.
- Each vehicle's sub-systems have their own identities, issued by the vehicle without internet access.
- Every packet in the fleet is signed. Every signature can be traced back to the root CA that you control.
- Compromised vehicles are effectively decommissioned within 24 hours of detection, with no infrastructure changes.
- The entire trust infrastructure runs over NDN — it works on UDP, Ethernet, internal CAN bus, or a drone swarm mesh network with no internet connection.

## See Also

- [NDNCERT: Automated Certificate Issuance](../deep-dive/ndncert.md) — the protocol details behind `NdnIdentity::provision`
- [Identity and Decentralized Identifiers](../deep-dive/identity-and-did.md) — how vehicle identities map to W3C DIDs
- [Setting Up an NDNCERT CA](./ndncert-setup.md) — step-by-step CA configuration reference
- [Security Model](../deep-dive/security-model.md) — the certificate chain validation that makes all of this work
