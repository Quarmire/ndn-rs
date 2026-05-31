//! Background ACME renewal loop (24h tick, 30-day renewal window).

use std::sync::Arc;
use std::time::Duration;

use tracing::{error, info, warn};

use crate::cache::CertCache;
use crate::cert_source::AcmeConfig;
use crate::client::AcmeClient;
use crate::dns::DnsProvider;

const CHECK_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
const RENEW_THRESHOLD_DAYS: i64 = 30;

/// Read-only status of a provisioned leaf certificate, for operability
/// surfaces (logs, management introspection).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CertStatus {
    /// `notAfter`, seconds since the Unix epoch.
    pub not_after_unix: i64,
    /// Whole days until `notAfter` (negative if already expired).
    pub days_remaining: i64,
    /// Whether the cert is within the renewal window (or unparseable).
    pub needs_renewal: bool,
}

/// Conservative: returns true when the cert cannot be parsed, so the loop
/// re-orders on the next tick.
pub fn needs_renewal(cert_pem: &[u8]) -> Result<bool, String> {
    Ok(check_expiry_days(cert_pem)
        .map(|d| d <= RENEW_THRESHOLD_DAYS)
        .unwrap_or(true))
}

/// Parse the leaf certificate's status (notAfter / days remaining / renewal).
/// Returns `None` when the PEM has no parseable leaf certificate.
pub fn cert_status(cert_pem: &[u8]) -> Option<CertStatus> {
    let not_after_unix = leaf_not_after_unix(cert_pem)?;
    let days_remaining = (not_after_unix - now_unix()) / 86_400;
    Some(CertStatus {
        not_after_unix,
        days_remaining,
        needs_renewal: days_remaining <= RENEW_THRESHOLD_DAYS,
    })
}

/// Whole days until the leaf cert's `notAfter`; `None` if unparseable.
fn check_expiry_days(cert_pem: &[u8]) -> Option<i64> {
    Some((leaf_not_after_unix(cert_pem)? - now_unix()) / 86_400)
}

fn leaf_not_after_unix(cert_pem: &[u8]) -> Option<i64> {
    use x509_parser::prelude::*;
    let mut reader = std::io::BufReader::new(cert_pem);
    let der = rustls_pemfile::certs(&mut reader).next()?.ok()?;
    let (_, cert) = X509Certificate::from_der(der.as_ref()).ok()?;
    Some(cert.validity().not_after.timestamp())
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Loops until `cancel` fires; renews on the next tick when the cached cert
/// is within [`RENEW_THRESHOLD_DAYS`].
pub async fn renewal_loop(
    cfg: AcmeConfig,
    provider: Arc<dyn DnsProvider>,
    cancel: tokio_util::sync::CancellationToken,
) {
    let cache = match CertCache::open(&cfg.cache_dir).await {
        Ok(c) => c,
        Err(e) => {
            error!(target: "ndn_acme", %e, "renewal: cache open failed");
            return;
        }
    };

    loop {
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep(CHECK_INTERVAL) => {}
        }

        let stale = cache
            .load(&cfg.domain)
            .await
            .map(|(c, _)| needs_renewal(&c).unwrap_or(true))
            .unwrap_or(true);
        if !stale {
            continue;
        }

        match AcmeClient::new(&cfg, provider.clone()).await {
            Ok(client) => match client.issue().await {
                Ok(mat) => {
                    if let Err(e) = cache
                        .store(&cfg.domain, &mat.cert_chain_pem, &mat.private_key_pem)
                        .await
                    {
                        error!(target: "ndn_acme", %e, "renewal: cache store failed");
                    } else {
                        info!(target: "ndn_acme", domain = %cfg.domain, "cert renewed");
                    }
                }
                Err(e) => warn!(target: "ndn_acme", %e, "renewal: order failed"),
            },
            Err(e) => warn!(target: "ndn_acme", %e, "renewal: account create failed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cert_status_parses_self_signed() {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let pem = ck.cert.pem();
        let st = cert_status(pem.as_bytes()).expect("status");
        // rcgen's default validity is well over the 30-day renewal window.
        assert!(
            st.days_remaining > 30,
            "days_remaining={}",
            st.days_remaining
        );
        assert!(!st.needs_renewal);
        assert!(!needs_renewal(pem.as_bytes()).unwrap());
    }

    #[test]
    fn cert_status_none_for_garbage() {
        assert!(cert_status(b"not a pem").is_none());
        // Unparseable cert is conservatively treated as needing renewal.
        assert!(needs_renewal(b"not a pem").unwrap());
    }
}
