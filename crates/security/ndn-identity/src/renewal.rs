//! Background certificate-renewal task (G10).
//!
//! The task watches a cert's remaining validity and, when it crosses the policy threshold,
//! drives a pluggable [`CertRenewer`] to obtain + install a fresh certificate — no manual
//! re-enrollment. [`NdncertRenewer`] is the built-in renewer: it re-runs the NDNCERT
//! enrollment flow against the CA. A `None` renewer keeps the old behavior (log + ask the
//! operator to re-enroll), so the seam is opt-in.

use std::future::Future;
use std::pin::Pin;
use std::{path::PathBuf, sync::Arc, time::Duration};

use async_trait::async_trait;
use ndn_packet::Name;
use ndn_security::SecurityManager;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::device::RenewalPolicy;
use crate::enroll::{ChallengeParams, NdncertClient};

/// Obtains + installs a fresh certificate for an identity whose current cert is nearing
/// expiry. The renewal task calls this; implementations talk to whatever issuer the
/// deployment uses (NDNCERT via [`NdncertRenewer`], an internal CA, a test stub).
#[async_trait]
pub trait CertRenewer: Send + Sync {
    /// Renew the certificate for `key_name` under `namespace`, installing it into
    /// `manager`. Returns the issued cert's name on success.
    async fn renew(
        &self,
        manager: &SecurityManager,
        key_name: &Name,
        namespace: &Name,
    ) -> Result<Name, RenewalError>;
}

/// Why an automatic renewal attempt failed (the task logs it and retries next interval).
#[derive(Debug, thiserror::Error)]
pub enum RenewalError {
    #[error("connecting to the router/CA: {0}")]
    Connect(String),
    #[error("no signer for key {0}")]
    NoSigner(Box<Name>),
    #[error("NDNCERT enrollment: {0}")]
    Enrollment(Box<crate::IdentityError>),
    #[error("{0}")]
    Other(String),
}

/// Factory for a fresh [`Consumer`](ndn_app::Consumer) to reach the CA — a new connection
/// per attempt, since enrollment consumes the consumer.
pub type ConsumerConnect = Arc<
    dyn Fn() -> Pin<Box<dyn Future<Output = Result<ndn_app::Consumer, ndn_app::AppError>> + Send>>
        + Send
        + Sync,
>;

/// The built-in renewer: re-runs the NDNCERT flow (INFO → NEW → CHALLENGE → cert-fetch)
/// against `ca_prefix` and installs the issued cert as a trust anchor.
///
/// It re-uses the enrollment `challenge`; for production, renewal should present a
/// **possession** challenge (re-proving with the current cert) rather than re-using a
/// single-use factory token — supply a possession [`ChallengeParams`] here for that.
pub struct NdncertRenewer {
    pub ca_prefix: Name,
    pub validity_secs: u64,
    pub challenge: ChallengeParams,
    pub connect: ConsumerConnect,
}

#[async_trait]
impl CertRenewer for NdncertRenewer {
    async fn renew(
        &self,
        manager: &SecurityManager,
        key_name: &Name,
        _namespace: &Name,
    ) -> Result<Name, RenewalError> {
        let signer = manager
            .get_signer_sync(key_name)
            .map_err(|_| RenewalError::NoSigner(Box::new(key_name.clone())))?;
        let consumer = (self.connect)()
            .await
            .map_err(|e| RenewalError::Connect(e.to_string()))?;
        let mut client = NdncertClient::new(consumer, self.ca_prefix.clone());
        let cert = client
            .enroll(
                key_name.clone(),
                signer,
                self.validity_secs,
                self.challenge.clone(),
            )
            .await
            .map_err(|e| RenewalError::Enrollment(Box::new(e)))?;
        let cert_name = (*cert.name).clone();
        // Install the renewed leaf into the validation cert cache — NOT as a trust anchor.
        // `add_trust_anchor` would promote every renewed end-entity cert to a
        // chain-terminating root (and, since anchors are keyed by cert name and each
        // renewal mints a new name, grow the anchor set unboundedly). The renewed cert
        // chains to the CA that issued it; the node's anchors (the CA) are unchanged.
        manager.cert_cache().insert(cert);
        Ok(cert_name)
    }
}

pub struct RenewalHandle {
    task: JoinHandle<()>,
}

impl Drop for RenewalHandle {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub fn start_renewal(
    manager: Arc<SecurityManager>,
    key_name: Name,
    namespace: Name,
    policy: &RenewalPolicy,
    renewer: Option<Arc<dyn CertRenewer>>,
    _storage: Option<PathBuf>,
) -> RenewalHandle {
    let check_interval = match policy {
        RenewalPolicy::WhenPercentRemaining(_pct) => Duration::from_secs(600),
        RenewalPolicy::Every(d) => *d,
        RenewalPolicy::Manual => {
            return RenewalHandle {
                task: tokio::spawn(async {}),
            };
        }
    };

    let percent = match policy {
        RenewalPolicy::WhenPercentRemaining(p) => *p as u64,
        _ => 20,
    };

    let task = tokio::spawn(async move {
        let mut failures: u32 = 0;
        loop {
            tokio::time::sleep(check_interval).await;

            if !check_renewal_needed(&manager, &key_name, percent) {
                failures = 0;
                continue;
            }
            info!(identity = %namespace, "certificate approaching expiry, initiating renewal");
            match &renewer {
                Some(r) => match r.renew(&manager, &key_name, &namespace).await {
                    Ok(cert) => {
                        failures = 0;
                        info!(identity = %namespace, %cert, "certificate renewed");
                    }
                    Err(e) => {
                        failures = failures.saturating_add(1);
                        // Exponential backoff with jitter so a fleet that crosses the
                        // threshold together doesn't retry against the CA in lockstep.
                        let backoff = backoff_delay(check_interval, failures);
                        warn!(
                            identity = %namespace,
                            error = %e,
                            backoff_ms = backoff.as_millis() as u64,
                            "automatic renewal failed; backing off before retry"
                        );
                        tokio::time::sleep(backoff).await;
                    }
                },
                None => warn!(
                    identity = %namespace,
                    "no CertRenewer configured; re-enroll manually or supply one"
                ),
            }
        }
    });

    RenewalHandle { task }
}

/// Backoff before the next renewal attempt after `failures` consecutive failures:
/// exponential in `base` (capped at 1 h) plus up to ±50% jitter (decorrelates a fleet).
fn backoff_delay(base: Duration, failures: u32) -> Duration {
    use std::time::{SystemTime, UNIX_EPOCH};
    const CAP: Duration = Duration::from_secs(3600);
    let exp = base.saturating_mul(1u32 << failures.min(6)); // base·2^min(failures,6)
    let capped = exp.min(CAP);
    // Cheap jitter from the wall clock (no RNG dep): ±50% of the capped delay.
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0);
    let half = capped / 2;
    let jitter = if half.is_zero() {
        Duration::ZERO
    } else {
        Duration::from_nanos(nanos % (half.as_nanos().max(1) as u64))
    };
    capped.saturating_sub(half).saturating_add(jitter)
}

fn check_renewal_needed(manager: &SecurityManager, key_name: &Name, threshold_pct: u64) -> bool {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;

    if let Some(cert) = manager
        .cert_cache()
        .get(&std::sync::Arc::new(key_name.clone()))
    {
        let total = cert.valid_until.saturating_sub(cert.valid_from);
        let remaining = cert.valid_until.saturating_sub(now_ns);
        if total == 0 {
            return false;
        }
        let remaining_pct = (remaining * 100) / total;
        return remaining_pct < threshold_pct;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_packet::{NameComponent, SignatureType};
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Records how many times it was asked to renew (no real CA needed).
    struct CountingRenewer {
        calls: Arc<AtomicU64>,
    }

    #[async_trait]
    impl CertRenewer for CountingRenewer {
        async fn renew(
            &self,
            _m: &SecurityManager,
            key_name: &Name,
            _ns: &Name,
        ) -> Result<Name, RenewalError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(key_name.clone())
        }
    }

    fn near_expiry_cert(key_name: &Name) -> ndn_security::Certificate {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        ndn_security::Certificate {
            name: Arc::new(key_name.clone()),
            public_key: bytes::Bytes::from_static(&[0u8; 32]),
            // 99% elapsed: well under any sane threshold.
            valid_from: now.saturating_sub(99),
            valid_until: now.saturating_add(1),
            issuer: None,
            signed_region: None,
            sig_value: None,
            sig_type: SignatureType::SignatureEd25519,
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn renewer_is_invoked_when_cert_nears_expiry() {
        let manager = Arc::new(SecurityManager::new());
        let key_name =
            Name::from_components([NameComponent::generic(bytes::Bytes::from_static(b"k"))]);
        manager.cert_cache().insert(near_expiry_cert(&key_name));

        let calls = Arc::new(AtomicU64::new(0));
        let renewer = Arc::new(CountingRenewer { calls: Arc::clone(&calls) });
        let _handle = start_renewal(
            manager,
            key_name,
            Name::from_components([NameComponent::generic(bytes::Bytes::from_static(b"id"))]),
            &RenewalPolicy::Every(Duration::from_millis(30)),
            Some(renewer),
            None,
        );

        // A few check intervals: the near-expiry cert trips renewal each time.
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert!(
            calls.load(Ordering::Relaxed) >= 1,
            "the renewer must be invoked for a near-expiry cert"
        );
    }
}
