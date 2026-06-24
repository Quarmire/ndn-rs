//! Zero-touch device provisioning over NDNCERT.

use std::{path::PathBuf, sync::Arc, time::Duration};

use ndn_packet::Name;
use ndn_security::{KeyChain, SecurityManager};

use crate::{
    enroll::{ChallengeParams, NdncertClient},
    error::IdentityError,
    facade::Identity,
    renewal::{CertRenewer, NdncertRenewer, start_renewal},
};

#[derive(Debug, Clone)]
pub enum FactoryCredential {
    /// One-time enrollment token (most common for fleet devices).
    Token(String),
    /// `did:key` embedded in firmware (possession-style enrollment).
    DidKey(String),
    /// Pre-existing cert + key seed (renewal-style enrollment).
    Existing {
        cert_name: String,
        key_seed: [u8; 32],
    },
}

#[derive(Debug, Clone)]
pub enum RenewalPolicy {
    WhenPercentRemaining(u8),
    Every(Duration),
    Manual,
}

impl Default for RenewalPolicy {
    fn default() -> Self {
        RenewalPolicy::WhenPercentRemaining(20)
    }
}

pub struct DeviceConfig {
    pub namespace: Name,
    /// `None` keeps keys in memory only.
    pub storage: Option<PathBuf>,
    pub factory_credential: FactoryCredential,
    /// `None` derives `<namespace minus last>/CA`.
    pub ca_prefix: Option<Name>,
    pub renewal: RenewalPolicy,
    /// Sub-namespaces to delegate after enrollment.
    pub delegate: Vec<Name>,
}

pub async fn run_provisioning(config: DeviceConfig) -> Result<Identity, IdentityError> {
    let ca_prefix = config
        .ca_prefix
        .clone()
        .unwrap_or_else(|| derive_ca_prefix(&config.namespace));

    let manager = if let Some(ref path) = config.storage {
        let (mgr, _) = SecurityManager::auto_init(&config.namespace, path)?;
        mgr
    } else {
        SecurityManager::new()
    };

    let key_name = config
        .namespace
        .clone()
        .append("KEY")
        .append_version(now_ms());
    manager.generate_ed25519(key_name.clone())?;
    let signer = manager.get_signer_sync(&key_name)?;

    let manager = Arc::new(manager);

    let challenge = build_challenge(&config.factory_credential, &key_name);

    // ZTP path assumes a system NDN router. Custom transports should call
    // `NdncertClient` directly.
    let socket = std::path::Path::new("/run/ndn/router.sock");
    if !socket.exists() {
        return Err(IdentityError::Enrollment(
            "ZTP requires a running NDN router at /run/ndn/router.sock; \
             use NdncertClient directly for custom connectivity"
                .to_string(),
        ));
    }

    let consumer = ndn_app::Consumer::connect(socket).await?;
    let mut client = NdncertClient::new(consumer, ca_prefix.clone());

    let cert = client
        .enroll(key_name.clone(), Arc::clone(&signer), 86400, challenge)
        .await?;

    manager.add_trust_anchor(cert);

    // Auto-renewal re-runs the NDNCERT flow against the same CA over a fresh router
    // connection. (For a single-use factory token the CA may reject the re-used challenge;
    // a possession challenge is the production renewal path — see `NdncertRenewer`.)
    let renewer: Arc<dyn CertRenewer> = Arc::new(NdncertRenewer {
        ca_prefix,
        validity_secs: 86400,
        challenge: build_challenge(&config.factory_credential, &key_name),
        connect: Arc::new(|| {
            Box::pin(async {
                ndn_app::Consumer::connect(std::path::Path::new("/run/ndn/router.sock")).await
            })
        }),
    });

    let renewal = match &config.renewal {
        RenewalPolicy::Manual => None,
        policy => Some(start_renewal(
            manager.clone(),
            key_name.clone(),
            config.namespace.clone(),
            &policy.clone(),
            Some(renewer),
        )),
    };

    let keychain = KeyChain::from_parts(manager, config.namespace.clone(), key_name);
    Ok(Identity::from_keychain(keychain, renewal))
}

fn build_challenge(credential: &FactoryCredential, _key_name: &Name) -> ChallengeParams {
    match credential {
        FactoryCredential::Token(token) => ChallengeParams::Token {
            token: token.clone(),
        },
        FactoryCredential::DidKey(did) => {
            // Carries the DID key as a raw parameter; a future revision
            // should sign the request with the DID key.
            ChallengeParams::Raw({
                let mut m = serde_json::Map::new();
                m.insert("did_key".to_string(), did.clone().into());
                m
            })
        }
        FactoryCredential::Existing {
            cert_name,
            key_seed,
        } => {
            use ndn_security::{Ed25519Signer, Signer};
            let signer = Ed25519Signer::from_seed(
                key_seed,
                cert_name
                    .parse()
                    .unwrap_or_else(|_| ndn_packet::Name::root()),
            );
            let sig = signer.sign_sync(cert_name.as_bytes()).unwrap_or_default();
            ChallengeParams::Possession {
                cert_name: cert_name.clone(),
                signature: sig.to_vec(),
            }
        }
    }
}

fn derive_ca_prefix(namespace: &Name) -> Name {
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
