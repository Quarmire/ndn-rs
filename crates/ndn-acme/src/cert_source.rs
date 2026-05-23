//! Operator-facing cert source enum (`Pem` / `Acme` / `SelfSignedDev`).

use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::cache::CertCache;
use crate::client::{AcmeClient, AcmeError};
use crate::dns::DnsProvider;

#[derive(Clone)]
pub struct CertMaterial {
    pub cert_chain_pem: Vec<u8>,
    pub private_key_pem: Vec<u8>,
}

/// Localhost-only dev cert; never for production.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct SelfSignedDev {
    #[serde(default = "default_hostnames")]
    pub hostnames: Vec<String>,
}

fn default_hostnames() -> Vec<String> {
    vec!["localhost".into()]
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AcmeConfig {
    /// e.g. `https://acme-v02.api.letsencrypt.org/directory`.
    pub directory_url: String,
    /// `mailto:` is implied if the scheme is omitted.
    pub email: String,
    pub domain: String,
    /// Selects a registered `DnsProvider` impl (e.g. `"cloudflare"`).
    pub dns_provider: String,
    /// Provider-specific (API token, zone id, ...).
    #[serde(default)]
    pub params: serde_json::Value,
    pub cache_dir: PathBuf,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CertSource {
    Pem { cert_pem: PathBuf, key_pem: PathBuf },
    Acme(AcmeConfig),
    SelfSignedDev(SelfSignedDev),
}

impl CertSource {
    /// Runs an ACME order if the cached cert is missing or stale.
    pub async fn resolve(
        &self,
        provider: Option<Arc<dyn DnsProvider>>,
    ) -> Result<CertMaterial, AcmeError> {
        match self {
            CertSource::Pem { cert_pem, key_pem } => {
                let cert_chain_pem = tokio::fs::read(cert_pem).await?;
                let private_key_pem = tokio::fs::read(key_pem).await?;
                Ok(CertMaterial {
                    cert_chain_pem,
                    private_key_pem,
                })
            }
            CertSource::Acme(cfg) => {
                let cache = CertCache::open(&cfg.cache_dir).await?;
                if let Some((cert, key)) = cache.load(&cfg.domain).await
                    && !crate::renewal::needs_renewal(&cert).unwrap_or(true)
                {
                    return Ok(CertMaterial {
                        cert_chain_pem: cert,
                        private_key_pem: key,
                    });
                }
                let provider = provider.ok_or(AcmeError::NoDnsProvider)?;
                let client = AcmeClient::new(cfg, provider).await?;
                let mat = client.issue().await?;
                cache
                    .store(&cfg.domain, &mat.cert_chain_pem, &mat.private_key_pem)
                    .await?;
                Ok(mat)
            }
            CertSource::SelfSignedDev(s) => {
                // Chrome's WebTransport `serverCertificateHashes` rejects
                // certs valid for more than 14 days; cap at 13 to be safe.
                let mut params = rcgen::CertificateParams::new(s.hostnames.clone())
                    .map_err(|e| AcmeError::Other(e.to_string()))?;
                let now = time::OffsetDateTime::now_utc();
                params.not_before = now - time::Duration::hours(1);
                params.not_after = now + time::Duration::days(13);
                let key_pair =
                    rcgen::KeyPair::generate().map_err(|e| AcmeError::Other(e.to_string()))?;
                let cert = params
                    .self_signed(&key_pair)
                    .map_err(|e| AcmeError::Other(e.to_string()))?;
                let cert_chain_pem = cert.pem().into_bytes();
                let private_key_pem = key_pair.serialize_pem().into_bytes();
                Ok(CertMaterial {
                    cert_chain_pem,
                    private_key_pem,
                })
            }
        }
    }
}
