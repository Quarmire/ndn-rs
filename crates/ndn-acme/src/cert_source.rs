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

impl CertMaterial {
    /// SHA-256 of the leaf (first) certificate in the chain.
    ///
    /// This is the value a *pinning* dialer trusts — `CertHashes` on a
    /// forwarder-to-forwarder face, or a browser's `serverCertificateHashes`.
    /// Returns `None` if the PEM holds no parseable certificate.
    pub fn leaf_sha256(&self) -> Option<[u8; 32]> {
        use sha2::{Digest, Sha256};
        let leaf = rustls_pemfile::certs(&mut self.cert_chain_pem.as_slice())
            .next()?
            .ok()?;
        let mut out = [0u8; 32];
        out.copy_from_slice(&Sha256::digest(&leaf));
        Some(out)
    }
}

/// Validity window applied when minting a *self-signed* cert.
///
/// Only [`CertSource::SelfSignedDev`] consults this — `Pem` and `Acme` get
/// their validity from the file or the CA. It lets one shared cert source serve
/// both a browser-facing transport and a backbone link without compromising
/// either (the user asked for "no tradeoffs"):
///
/// - WebTransport must stay browser-pinnable, and Chrome rejects a
///   `serverCertificateHashes` cert valid for more than 14 days.
/// - A raw-QUIC backbone peer pins the *leaf hash*, not the expiry, so a 13-day
///   window there only forces needless regeneration across restarts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SelfSignedProfile {
    /// Cap validity at 13 days so the cert is usable with Chrome's WebTransport
    /// `serverCertificateHashes`. The safe default.
    #[default]
    BrowserPinnable,
    /// Long-lived (10 years) — for a pinned backbone/raw-QUIC link where the
    /// dialer trusts the leaf hash and ignores expiry.
    Backbone,
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
    ///
    /// `profile` only affects the [`SelfSignedDev`](Self::SelfSignedDev) arm —
    /// it picks the self-signed validity window (see [`SelfSignedProfile`]).
    /// `Pem` and `Acme` ignore it.
    pub async fn resolve(
        &self,
        provider: Option<Arc<dyn DnsProvider>>,
        profile: SelfSignedProfile,
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
                let mut params = rcgen::CertificateParams::new(s.hostnames.clone())
                    .map_err(|e| AcmeError::Other(e.to_string()))?;
                let now = time::OffsetDateTime::now_utc();
                params.not_before = now - time::Duration::hours(1);
                params.not_after = now
                    + match profile {
                        // Chrome's WebTransport `serverCertificateHashes`
                        // rejects certs valid for more than 14 days.
                        SelfSignedProfile::BrowserPinnable => time::Duration::days(13),
                        // A pinned backbone peer trusts the leaf hash, not the
                        // expiry — a long window avoids restart-time regen.
                        SelfSignedProfile::Backbone => time::Duration::days(3650),
                    };
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
