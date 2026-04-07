//! Fleet and device provisioning — zero-touch provisioning (ZTP) for NDN devices.

use std::{path::PathBuf, sync::Arc, time::Duration};

use ndn_packet::Name;
use ndn_security::SecurityManager;

use crate::{
    enroll::{ChallengeParams, NdncertClient},
    error::IdentityError,
    identity::NdnIdentity,
    renewal::start_renewal,
};

/// Factory-installed credential used to bootstrap device enrollment.
#[derive(Debug, Clone)]
pub enum FactoryCredential {
    /// A pre-provisioned one-time token (most common for fleet devices).
    Token(String),
    /// A `did:key` string embedded in firmware for possession-based enrollment.
    DidKey(String),
    /// An existing certificate name + signing key seed for renewal-style enrollment.
    Existing {
        cert_name: String,
        key_seed: [u8; 32],
    },
}

/// When to automatically renew a certificate.
#[derive(Debug, Clone)]
pub enum RenewalPolicy {
    /// Renew when N% of the certificate lifetime remains. Default: 20.
    WhenPercentRemaining(u8),
    /// Renew on a fixed interval regardless of cert expiry.
    Every(Duration),
    /// Never auto-renew.
    Manual,
}

impl Default for RenewalPolicy {
    fn default() -> Self {
        RenewalPolicy::WhenPercentRemaining(20)
    }
}

/// Configuration for zero-touch device provisioning.
pub struct DeviceConfig {
    /// The NDN namespace this device should claim
    /// (e.g. `/com/acme/fleet/VIN-123456`).
    pub namespace: Name,
    /// Persistent storage for keys and certificates. `None` = in-memory only.
    pub storage: Option<PathBuf>,
    /// Factory credential used for the first enrollment.
    pub factory_credential: FactoryCredential,
    /// CA prefix. `None` = derive from namespace (drop last component, append `/CA`).
    pub ca_prefix: Option<Name>,
    /// Auto-renewal policy.
    pub renewal: RenewalPolicy,
    /// Sub-namespaces to delegate after enrollment
    /// (e.g. ECU names under a vehicle namespace).
    pub delegate: Vec<Name>,
}

/// Run the zero-touch provisioning flow.
pub async fn run_provisioning(config: DeviceConfig) -> Result<NdnIdentity, IdentityError> {
    let ca_prefix = config
        .ca_prefix
        .clone()
        .unwrap_or_else(|| derive_ca_prefix(&config.namespace));

    // Set up security manager.
    let manager = if let Some(ref path) = config.storage {
        let (mgr, _) = SecurityManager::auto_init(&config.namespace, path)?;
        mgr
    } else {
        SecurityManager::new()
    };

    // Generate enrollment key.
    let key_name = config
        .namespace
        .clone()
        .append("KEY")
        .append_version(now_ms());
    manager.generate_ed25519(key_name.clone())?;
    let signer = manager.get_signer_sync(&key_name)?;
    let pubkey_bytes = signer
        .public_key()
        .ok_or_else(|| IdentityError::Enrollment("signer has no public key".to_string()))?;

    let manager = Arc::new(manager);

    // Build challenge from factory credential.
    let challenge = build_challenge(&config.factory_credential, &key_name);

    // We need a Consumer to talk to the CA. In the ZTP scenario the device
    // must have a face to the CA already configured. We expect a Consumer
    // to be available via the socket path conventionally at /run/ndn/router.sock.
    // If not available we return a clear error asking the caller to provide one.
    //
    // For embedded/mobile scenarios, the caller should use NdncertClient directly.
    let socket = std::path::Path::new("/run/ndn/router.sock");
    if !socket.exists() {
        return Err(IdentityError::Enrollment(
            "ZTP requires a running NDN router at /run/ndn/router.sock; \
             use NdncertClient directly for custom connectivity"
                .to_string(),
        ));
    }

    let consumer = ndn_app::Consumer::connect(socket).await?;
    let mut client = NdncertClient::new(consumer, ca_prefix);

    let cert = client
        .enroll(
            key_name.clone(),
            pubkey_bytes.to_vec(),
            86400, // 24h default
            challenge,
        )
        .await?;

    manager.add_trust_anchor(cert);

    // Start renewal if requested.
    let renewal = match &config.renewal {
        RenewalPolicy::Manual => None,
        policy => Some(start_renewal(
            manager.clone(),
            key_name.clone(),
            config.namespace.clone(),
            &policy.clone(),
            config.storage.clone(),
        )),
    };

    Ok(NdnIdentity {
        name: config.namespace,
        manager,
        key_name,
        renewal,
    })
}

fn build_challenge(credential: &FactoryCredential, _key_name: &Name) -> ChallengeParams {
    match credential {
        FactoryCredential::Token(token) => ChallengeParams::Token {
            token: token.clone(),
        },
        FactoryCredential::DidKey(did) => {
            // For did:key credentials, we use a raw challenge carrying the DID key.
            // In a full implementation, we'd sign the request with the DID key.
            ChallengeParams::Raw({
                let mut m = serde_json::Map::new();
                m.insert("did_key".to_string(), did.clone().into());
                m
            })
        }
        FactoryCredential::Existing { cert_name, key_seed } => {
            // Sign the cert name (used as nonce by possession challenge).
            use ndn_security::{Ed25519Signer, Signer};
            let signer = Ed25519Signer::from_seed(
                key_seed,
                cert_name
                    .parse()
                    .unwrap_or_else(|_| ndn_packet::Name::root()),
            );
            let sig = signer
                .sign_sync(cert_name.as_bytes())
                .unwrap_or_default();
            ChallengeParams::Possession {
                cert_name: cert_name.clone(),
                signature: sig.to_vec(),
            }
        }
    }
}

fn derive_ca_prefix(namespace: &Name) -> Name {
    // Heuristic: drop the last component (device ID) and append /CA.
    let comps = namespace.components();
    if comps.len() > 1 {
        Name::from_components(comps[..comps.len() - 1].iter().cloned()).append("CA")
    } else {
        namespace.clone().append("CA")
    }
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
