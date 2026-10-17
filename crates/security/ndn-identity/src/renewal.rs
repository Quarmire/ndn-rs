//! Certificate renewal (F10) on the device side.
//!
//! - [`renew_via_engine`] renews a certificate through an engine: the one call
//!   the `ndn-fwd` daemon (`ndn-fwd renew`, its renewal timer) and an app's
//!   embedded engine (ndn-mobile) make. The protocol is
//!   [`ndn_cert::renew_certificate`]: NDNCERT with the CA's built-in
//!   `renewal` challenge, proving possession of the current certificate's
//!   key — no invite, same key.
//! - [`RenewBefore`] says when a certificate is due; [`backoff_delay`] how
//!   long to wait after failed attempts. Both are shared by every renewal
//!   schedule.
//! - [`start_renewal`] runs a background task for an identity held by a
//!   [`SecurityManager`], driving a pluggable [`CertRenewer`];
//!   [`NdncertRenewer`] renews over a `Consumer` connection. A `None` renewer
//!   only logs, asking the operator to re-enroll.

use std::future::Future;
use std::pin::Pin;
use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use ndn_app::ForwarderEngine;
use ndn_cert::IssuedCertificate;
use ndn_packet::{Data, Name};
use ndn_security::{Certificate, Keyring, SecurityManager, Signer};
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::device::RenewalPolicy;
use crate::engine_exchange::EngineExchange;
use crate::enroll::NdncertClient;

/// The longest [`renew_via_engine`] can take: every exchange it may make
/// ([`ndn_cert::renewal::RENEWAL_MAX_EXCHANGES`]) timing out at the engine
/// consumer's per-Interest timeout.
pub fn renew_via_engine_budget() -> Duration {
    ndn_app::DEFAULT_TIMEOUT * ndn_cert::renewal::RENEWAL_MAX_EXCHANGES
}

/// Renew `current` (a certificate Data for `device_key`) at the CA that
/// issued it, through `engine`: Interests go out on a short-lived in-process
/// consumer face, so the engine's FIB forwards them toward the CA. The new
/// certificate is for the same key, checked to chain to the root of a trust
/// context in `keyring`. Storing and serving it is the caller's. See
/// [`ndn_cert::renew_certificate`].
pub async fn renew_via_engine(
    engine: &ForwarderEngine,
    keyring: &Arc<Keyring>,
    current: &Data,
    device_key: Arc<dyn Signer>,
) -> Result<IssuedCertificate, ndn_cert::RenewalError> {
    let mut exchange = EngineExchange::new(engine);
    ndn_cert::renew_certificate(keyring, &mut exchange, current, device_key).await
}

/// When a certificate is due for renewal: once its remaining validity falls
/// below a threshold.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RenewBefore {
    /// A fraction (`0..1`) of the certificate's lifetime: `1/3` renews a
    /// 90-day certificate 30 days before it expires.
    Fraction(f64),
    /// A fixed time before expiry (capped at the certificate's lifetime).
    Remaining(Duration),
}

impl RenewBefore {
    /// Renew once a third of the lifetime remains.
    pub const ONE_THIRD: Self = Self::Fraction(1.0 / 3.0);

    /// When (nanoseconds since the Unix epoch) a certificate valid from
    /// `valid_from` until `valid_until` (likewise) is due: `valid_until`
    /// minus the threshold, never before `valid_from`.
    pub fn renew_at(&self, valid_from: u64, valid_until: u64) -> u64 {
        let lifetime = valid_until.saturating_sub(valid_from);
        let before = match *self {
            Self::Fraction(f) => (lifetime as f64 * f.clamp(0.0, 1.0)) as u64,
            Self::Remaining(d) => u64::try_from(d.as_nanos()).unwrap_or(u64::MAX),
        };
        valid_until.saturating_sub(before).max(valid_from)
    }
}

/// The certificate `manager` holds for `key_name`: the newest currently
/// valid one cached under the key name (a renewed key has several), else
/// the newest valid one cached for the public key of `key_name`'s signer.
/// An expired certificate is not current: it cannot be renewed.
pub fn current_certificate(manager: &SecurityManager, key_name: &Name) -> Option<Certificate> {
    use sha2::{Digest, Sha256};
    if let Some(cert) = manager.cert_cache().get_valid(key_name) {
        return Some(cert);
    }
    let public_key = manager.get_signer_sync(key_name).ok()?.public_key()?;
    manager
        .cert_cache()
        .get_by_key_digest(&Sha256::digest(&public_key)[..])
        .filter(Certificate::is_valid_now)
}

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

/// Why an automatic renewal attempt failed (the task logs it and retries after a backoff).
#[derive(Debug, thiserror::Error)]
pub enum RenewalError {
    #[error("connecting to the router/CA: {0}")]
    Connect(String),
    #[error("no signer for key {0}")]
    NoSigner(Box<Name>),
    #[error("no certificate held for key {0}")]
    NoCertificate(Box<Name>),
    #[error(transparent)]
    Renewal(#[from] ndn_cert::RenewalError),
    #[error("{0}")]
    Other(String),
}

/// Factory for a fresh `Consumer`(ndn_app::Consumer) to reach the CA — a new connection
/// per attempt, since enrollment consumes the consumer.
pub type ConsumerConnect = Arc<
    dyn Fn() -> Pin<Box<dyn Future<Output = Result<ndn_app::Consumer, ndn_app::AppError>> + Send>>
        + Send
        + Sync,
>;

/// The built-in renewer: renews the key's current certificate
/// ([`current_certificate`]) at the CA that issued it with
/// [`ndn_cert::renew_certificate`] over a fresh `connect`ion, and installs
/// the new certificate into the validation cache. The manager's keyring must
/// hold the namespace's trust context: the new certificate is checked to
/// chain to its root.
pub struct NdncertRenewer {
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
        let current = current_certificate(manager, key_name)
            .ok_or_else(|| RenewalError::NoCertificate(Box::new(key_name.clone())))?;
        let data = Data::decode(bytes::Bytes::from(ndn_cert::ca::serialize_cert(&current)))
            .map_err(|e| RenewalError::Other(format!("current certificate: {e}")))?;
        let ca_prefix = ndn_cert::issuing_ca_prefix(&current).unwrap_or_else(Name::root);
        let consumer = (self.connect)()
            .await
            .map_err(|e| RenewalError::Connect(e.to_string()))?;
        let mut client = NdncertClient::new(consumer, ca_prefix);
        let issued =
            ndn_cert::renew_certificate(manager.keyring(), &mut client, &data, signer).await?;
        let cert_name = (*issued.cert.name).clone();
        // Install the renewed leaf into the validation cert cache — NOT as a trust anchor.
        // `add_trust_anchor` would promote every renewed end-entity cert to a
        // chain-terminating root (and, since anchors are keyed by cert name and each
        // renewal mints a new name, grow the anchor set unboundedly). The renewed cert
        // chains to the CA that issued it; the node's anchors (the CA) are unchanged.
        manager.cert_cache().insert(issued.cert);
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

/// How often a `WhenPercentRemaining` policy re-checks the cert's remaining validity.
const PERCENT_POLICY_CHECK_INTERVAL: Duration = Duration::from_secs(600);
/// Default remaining-validity threshold (percent) that triggers renewal when a policy
/// doesn't specify one.
const DEFAULT_RENEW_THRESHOLD_PCT: u64 = 20;

pub fn start_renewal(
    manager: Arc<SecurityManager>,
    key_name: Name,
    namespace: Name,
    policy: &RenewalPolicy,
    renewer: Option<Arc<dyn CertRenewer>>,
) -> RenewalHandle {
    let check_interval = match policy {
        RenewalPolicy::WhenPercentRemaining(_pct) => PERCENT_POLICY_CHECK_INTERVAL,
        RenewalPolicy::Every(d) => *d,
        RenewalPolicy::Manual => {
            return RenewalHandle {
                task: tokio::spawn(async {}),
            };
        }
    };

    let percent = match policy {
        RenewalPolicy::WhenPercentRemaining(p) => *p as u64,
        _ => DEFAULT_RENEW_THRESHOLD_PCT,
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
pub fn backoff_delay(base: Duration, failures: u32) -> Duration {
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
    current_certificate(manager, key_name).is_some_and(|cert| {
        cert.valid_until > cert.valid_from
            && RenewBefore::Fraction(threshold_pct as f64 / 100.0)
                .renew_at(cert.valid_from, cert.valid_until)
                <= now_ns
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_packet::{NameComponent, SignatureType};
    use portable_atomic::AtomicU64;
    use std::sync::atomic::Ordering;

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
            // 99% elapsed, still valid for the test's duration: well under
            // any sane threshold.
            valid_from: now.saturating_sub(99_000_000_000),
            valid_until: now.saturating_add(1_000_000_000),
            issuer: None,
            signed_region: None,
            sig_value: None,
            sig_type: SignatureType::SignatureEd25519,
        }
    }

    /// A fraction renews with that share of the lifetime left; a fixed
    /// time, that long before expiry; never before the certificate starts.
    #[test]
    fn renew_at_leaves_the_threshold_before_expiry() {
        const DAY: u64 = 86_400_000_000_000;
        let (from, until) = (10 * DAY, 100 * DAY);
        let third = RenewBefore::ONE_THIRD.renew_at(from, until);
        assert!(third.abs_diff(70 * DAY) < 1_000_000, "{third}");
        assert_eq!(
            RenewBefore::Remaining(Duration::from_secs(5 * 86_400)).renew_at(from, until),
            95 * DAY
        );
        assert_eq!(
            RenewBefore::Remaining(Duration::from_secs(500 * 86_400)).renew_at(from, until),
            from
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn renewer_is_invoked_when_cert_nears_expiry() {
        let manager = Arc::new(SecurityManager::new());
        let key_name =
            Name::from_components([NameComponent::generic(bytes::Bytes::from_static(b"k"))]);
        manager.cert_cache().insert(near_expiry_cert(&key_name));

        let calls = Arc::new(AtomicU64::new(0));
        let renewer = Arc::new(CountingRenewer {
            calls: Arc::clone(&calls),
        });
        let _handle = start_renewal(
            manager,
            key_name,
            Name::from_components([NameComponent::generic(bytes::Bytes::from_static(b"id"))]),
            &RenewalPolicy::Every(Duration::from_millis(30)),
            Some(renewer),
        );

        // A few check intervals: the near-expiry cert trips renewal each time.
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert!(
            calls.load(Ordering::Relaxed) >= 1,
            "the renewer must be invoked for a near-expiry cert"
        );
    }
}
