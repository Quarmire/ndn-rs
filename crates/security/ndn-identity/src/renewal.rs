//! Certificate renewal (F10) on the device side.
//!
//! - [`renew_via_engine`] renews a certificate through an engine: the one call
//!   the `ndn-fwd` daemon (`ndn-fwd renew`, its renewal timer) and an app's
//!   embedded engine (ndn-mobile) make. The protocol is
//!   [`ndn_cert::renew_certificate`]: NDNCERT with the CA's built-in
//!   `renewal` challenge, proving possession of the current certificate's
//!   key — no invite, same key.
//! - [`RenewBefore`] says when a certificate is due; [`backoff_delay`] how
//!   long to wait after failed attempts.
//! - [`RenewalSchedule`] is the one renewal schedule: per certificate, when
//!   it is due, the backoff after a failed attempt (longer after a refusal),
//!   the key just renewed not renewed again before its new certificate is
//!   due, and which conditions to report once (an expired certificate, a
//!   threshold longer than the lifetime). It decides; its driver renews and
//!   logs. `ndn_namespace::renewal::spawn_periodic` (a forwarder, an app)
//!   and [`start_renewal`] both drive it.
//! - [`start_renewal`] runs a background task for an identity held by a
//!   [`SecurityManager`], driving a pluggable [`CertRenewer`];
//!   [`NdncertRenewer`] renews over a `Consumer` connection. A `None` renewer
//!   fails each due attempt, asking the operator to re-enroll.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::time::Instant;
use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use ndn_app::ForwarderEngine;
use ndn_cert::IssuedCertificate;
use ndn_packet::{Data, Name};
use ndn_security::{Certificate, Keyring, SecurityManager, Signer};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::device::RenewalPolicy;
use crate::engine_exchange::EngineExchange;
use crate::enroll::NdncertClient;

/// The longest [`renew_via_engine`] can take: every exchange it may make
/// ([`ndn_cert::renewal::RENEWAL_MAX_EXCHANGES`]) timing out at the engine
/// consumer's per-Interest timeout.
pub fn renew_via_engine_budget() -> Duration {
    ndn_app::DEFAULT_TIMEOUT * ndn_cert::renewal::RENEWAL_MAX_EXCHANGES
}

/// Renew `current` (a certificate Data for `device_key`) at its namespace's
/// CA, through `engine`: Interests go out on a short-lived in-process
/// consumer face, so the engine's FIB forwards them toward the CA. After the
/// namespace's root device is replaced through a recovery kit, that CA signs
/// with a later key of the same CA identity and accepts `current` with its
/// chain, walked from `issuers` — the issuer certificates the device kept
/// ([`IssuedCertificate::issuers`]) — before the network. The new
/// certificate is for the same key, checked to chain to the root of a trust
/// context in `keyring`. Storing and serving it (and its
/// [`IssuedCertificate::issuers`]) is the caller's. See
/// [`ndn_cert::renew_certificate`].
pub async fn renew_via_engine(
    engine: &ForwarderEngine,
    keyring: &Arc<Keyring>,
    current: &Data,
    issuers: &[Data],
    device_key: Arc<dyn Signer>,
) -> Result<IssuedCertificate, ndn_cert::RenewalError> {
    let mut exchange = EngineExchange::new(engine);
    ndn_cert::renew_certificate(keyring, &mut exchange, current, issuers, device_key).await
}

/// When a certificate is due for renewal: once its remaining validity falls
/// below a threshold.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RenewBefore {
    /// A fraction (`0..1`) of the certificate's lifetime: `1/3` renews a
    /// 90-day certificate 30 days before it expires.
    Fraction(f64),
    /// A fixed time before expiry. A certificate whose lifetime is no longer
    /// than this would be due the moment it is issued (and its renewal due
    /// again at once): it is renewed at [`ONE_THIRD`](Self::ONE_THIRD) instead
    /// — see [`exceeds_lifetime`](Self::exceeds_lifetime).
    Remaining(Duration),
}

impl RenewBefore {
    /// Renew once a third of the lifetime remains.
    pub const ONE_THIRD: Self = Self::Fraction(1.0 / 3.0);

    /// When (nanoseconds since the Unix epoch) a certificate valid from
    /// `valid_from` until `valid_until` (likewise) is due: `valid_until`
    /// minus the threshold, never before `valid_from`. A threshold that
    /// [exceeds the lifetime](Self::exceeds_lifetime) uses
    /// [`ONE_THIRD`](Self::ONE_THIRD).
    pub fn renew_at(&self, valid_from: u64, valid_until: u64) -> u64 {
        let lifetime = valid_until.saturating_sub(valid_from);
        let before = match *self {
            Self::Fraction(f) => (lifetime as f64 * f.clamp(0.0, 1.0)) as u64,
            Self::Remaining(_) if self.exceeds_lifetime(valid_from, valid_until) => {
                return Self::ONE_THIRD.renew_at(valid_from, valid_until);
            }
            Self::Remaining(d) => u64::try_from(d.as_nanos()).unwrap_or(u64::MAX),
        };
        valid_until.saturating_sub(before).max(valid_from)
    }

    /// Whether this is a [`Remaining`](Self::Remaining) threshold at least
    /// as long as the lifetime of a certificate valid from `valid_from`
    /// until `valid_until`: the CA issues certificates shorter than the
    /// threshold, so [`renew_at`](Self::renew_at) falls back to a third of
    /// the lifetime.
    pub fn exceeds_lifetime(&self, valid_from: u64, valid_until: u64) -> bool {
        let lifetime = valid_until.saturating_sub(valid_from);
        matches!(*self, Self::Remaining(d) if d.as_nanos() >= u128::from(lifetime))
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
/// ([`current_certificate`]) at its namespace's CA with
/// [`ndn_cert::renew_certificate`] over a fresh `connect`ion — after a
/// recovery a later CA key of the same CA identity, which accepts an earlier
/// CA's certificate with its chain (the issuer certificates the manager's
/// cert cache holds) — and installs the new certificate into the validation
/// cache. The manager's keyring must hold the namespace's trust context: the
/// new certificate is checked to chain to its root.
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
        let issuers = cached_issuers(manager, &current);
        let issued =
            ndn_cert::renew_certificate(manager.keyring(), &mut client, &data, &issuers, signer)
                .await?;
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

/// The issuer certificates of `cert`'s chain that `manager`'s cert cache
/// holds, in walk order, up to the first it does not hold. The renewal's
/// chain walk verifies each one; none is trusted by itself.
fn cached_issuers(manager: &SecurityManager, cert: &Certificate) -> Vec<Data> {
    const MAX_CHAIN: usize = 8;
    let mut issuers: Vec<Data> = Vec::new();
    let mut locator = cert.issuer.clone();
    while let Some(key) = locator.take() {
        let Some(issuer) = manager.cert_cache().get_valid(&key) else {
            break;
        };
        let Some(data) = issuer.data_wire().and_then(|wire| Data::decode(wire).ok()) else {
            break;
        };
        // A self-signed anchor or a cycle ends the walk.
        if issuers.len() == MAX_CHAIN || issuers.iter().any(|kept| kept.name == data.name) {
            break;
        }
        locator = issuer.issuer.clone();
        issuers.push(data);
    }
    issuers
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
const DEFAULT_RENEW_THRESHOLD_PCT: u8 = 20;

/// Renew the certificate `manager` holds for `key_name` (of identity
/// `namespace`) with `renewer`, on the [`RenewalSchedule`]:
///
/// - `WhenPercentRemaining(p)`: due once `p`% of its lifetime is left,
///   checked at least every 10 minutes;
/// - `Every(d)`: due once 20% is left, checked at least every `d` (no
///   oftener than [`RenewalSchedule::MIN_WAIT`]);
/// - `Manual`: never.
///
/// The first check runs one interval after the start. A failed attempt is
/// retried after the schedule's backoff (30–60 s, doubling up to 30–60 min;
/// 30–60 min after the CA refused); an expired certificate is reported once,
/// as an ERROR: the device needs a new invite.
pub fn start_renewal(
    manager: Arc<SecurityManager>,
    key_name: Name,
    namespace: Name,
    policy: &RenewalPolicy,
    renewer: Option<Arc<dyn CertRenewer>>,
) -> RenewalHandle {
    let pct = |p: u8| RenewBefore::Fraction(f64::from(p) / 100.0);
    let (before, interval) = match policy {
        RenewalPolicy::WhenPercentRemaining(p) => (pct(*p), PERCENT_POLICY_CHECK_INTERVAL),
        RenewalPolicy::Every(d) => (pct(DEFAULT_RENEW_THRESHOLD_PCT), *d),
        RenewalPolicy::Manual => {
            return RenewalHandle {
                task: tokio::spawn(async {}),
            };
        }
    };

    let task = tokio::spawn(async move {
        let mut schedule = RenewalSchedule::new(before).with_max_wait(interval);
        let mut wait = interval;
        loop {
            tokio::time::sleep(wait).await;
            let held = held_certificate(&manager, &key_name);
            schedule.begin_scan(held.as_ref().map(|cert| (&key_name, &*cert.name)));
            if let Some(cert) = held
                && schedule.check(&key_name, &cert, Now::current()) == Due::Now
            {
                info!(identity = %namespace, "certificate approaching expiry, initiating renewal");
                let result = match &renewer {
                    Some(r) => r
                        .renew(&manager, &key_name, &namespace)
                        .await
                        .map_err(|e| (e.is_final(), e.to_string())),
                    None => Err((
                        false,
                        "no CertRenewer configured; re-enroll manually or supply one".to_owned(),
                    )),
                };
                match result {
                    Ok(issued) => {
                        info!(identity = %namespace, cert = %issued, "certificate renewed");
                        let current = current_certificate(&manager, &key_name);
                        schedule.renewed(&key_name, &cert, current.as_ref().unwrap_or(&cert));
                    }
                    Err((refused, why)) => match schedule.failed(&cert, refused, Now::current()) {
                        Failed::Expired => error!(
                            identity = %namespace,
                            certificate = %cert.name,
                            expired_secs_ago = now_ns().saturating_sub(cert.valid_until) / 1_000_000_000,
                            "certificate expired and was not renewed in time: renewal needs a \
                             current certificate, so this device needs a new invite to enroll again"
                        ),
                        Failed::Retry {
                            attempts,
                            delay,
                            days_left,
                        } => warn!(
                            identity = %namespace,
                            certificate = %cert.name,
                            error = %why,
                            attempts,
                            days_left = %format!("{days_left:.1}"),
                            retry_in_secs = delay.as_secs(),
                            "automatic renewal failed; the certificate works until it expires"
                        ),
                    },
                }
            }
            wait = schedule.wait();
        }
    });

    RenewalHandle { task }
}

/// The certificate `manager` holds for `key_name`: the
/// [current](current_certificate) one, else the newest cached under the key
/// name (an expired one, which the schedule reports).
fn held_certificate(manager: &SecurityManager, key_name: &Name) -> Option<Certificate> {
    current_certificate(manager, key_name)
        .or_else(|| manager.cert_cache().get(&Arc::new(key_name.clone())))
}

impl RenewalError {
    /// Whether the CA refused (retrying soon cannot help) rather than the
    /// attempt failing.
    pub fn is_final(&self) -> bool {
        matches!(self, Self::Renewal(e) if e.is_final())
    }
}

/// Backoff before the next renewal attempt after `failures` consecutive failures:
/// `base`·2^min(failures, 6), capped at 1 h, then cut to a random 50–100% of
/// that (decorrelates a fleet).
pub fn backoff_delay(base: Duration, failures: u32) -> Duration {
    use std::time::{SystemTime, UNIX_EPOCH};
    const CAP: Duration = Duration::from_secs(3600);
    let exp = base.saturating_mul(1u32 << failures.min(6)); // base·2^min(failures,6)
    let capped = exp.min(CAP);
    // Cheap jitter from the wall clock (no RNG dep): 50–100% of the capped delay.
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

fn now_ns() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

/// A moment on both clocks the schedule reads: the wall clock (certificate
/// validity is in nanoseconds since the Unix epoch) and the monotonic one
/// (backoffs).
#[derive(Debug, Clone, Copy)]
pub struct Now {
    pub wall_ns: u64,
    pub instant: Instant,
}

impl Now {
    pub fn current() -> Self {
        Self {
            wall_ns: now_ns(),
            instant: Instant::now(),
        }
    }
}

/// What to do with one certificate now ([`RenewalSchedule::check`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Due {
    /// Not due yet, or the backoff after a failed attempt runs: check again
    /// after this.
    Later(Duration),
    /// It expired, and that was reported: renewal cannot help it (the
    /// device needs a new invite).
    Expired,
    /// Renew it now.
    Now,
}

/// What follows a failed attempt ([`RenewalSchedule::failed`]).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Failed {
    /// The certificate expired: report it, as an ERROR. It is reported
    /// once; the schedule does not try it again.
    Expired,
    /// Try again after `delay`.
    Retry {
        /// Consecutive failed attempts for this certificate, this one
        /// included.
        attempts: u32,
        delay: Duration,
        /// The days of validity the certificate has left.
        days_left: f64,
    },
}

/// The renewal schedule of a device's certificates: when each is due, and
/// what follows an attempt. It holds no certificate and makes no exchange;
/// its driver scans the certificates it holds, renews those this says are
/// due, reports each outcome back, and sleeps for [`wait`](Self::wait).
///
/// - A certificate is due once its remaining validity falls below
///   [`RenewBefore`]. A threshold at least the certificate's lifetime would
///   make each one due as it is issued: it renews at a third of the
///   lifetime, and [`first_short_lived`](Self::first_short_lived) says when
///   to warn about it (once per key).
/// - A key just renewed is not renewed again before the certificate that
///   renewal issued is due, whichever certificate the store reports as the
///   key's current one.
/// - A failed attempt is retried after [`backoff_delay`] from
///   [`RETRY_BASE`](Self::RETRY_BASE), doubling per consecutive failure; a
///   refusal waits the longest backoff ([`REFUSED_BACKOFF`](Self::REFUSED_BACKOFF)).
/// - A failed attempt on an expired certificate is reported once and not
///   retried: renewal needs a current certificate.
/// - A store that cannot be read is scanned again after a growing backoff
///   ([`unreadable`](Self::unreadable)).
#[derive(Debug)]
pub struct RenewalSchedule {
    before: RenewBefore,
    max_wait: Duration,
    /// Per certificate: consecutive failures and when to try again.
    retry: HashMap<Name, (u32, Instant)>,
    /// Per key: when the certificate its last renewal issued is due.
    renewed: HashMap<Name, u64>,
    /// Expired certificates, reported once.
    expired: HashSet<Name>,
    /// Keys whose certificates are shorter than the threshold, reported once.
    short_lived: HashSet<Name>,
    /// Consecutive scans that could not read the store.
    unreadable: u32,
    /// The soonest check this scan asks for.
    next: Duration,
}

impl RenewalSchedule {
    /// The longest a driver sleeps between scans by default.
    pub const MAX_WAIT: Duration = Duration::from_secs(3_600);
    /// The shortest a driver sleeps between scans.
    pub const MIN_WAIT: Duration = Duration::from_secs(1);
    /// Backoff base after a failed attempt.
    pub const RETRY_BASE: Duration = Duration::from_secs(60);
    /// Backoff exponent after a refusal: the cap (an hour).
    pub const REFUSED_BACKOFF: u32 = 6;

    pub fn new(before: RenewBefore) -> Self {
        Self {
            before,
            max_wait: Self::MAX_WAIT,
            retry: HashMap::new(),
            renewed: HashMap::new(),
            expired: HashSet::new(),
            short_lived: HashSet::new(),
            unreadable: 0,
            next: Self::MAX_WAIT,
        }
    }

    /// Sleep at most `max_wait` between scans (at least
    /// [`MIN_WAIT`](Self::MIN_WAIT)).
    pub fn with_max_wait(mut self, max_wait: Duration) -> Self {
        self.max_wait = max_wait.max(Self::MIN_WAIT);
        self.next = self.max_wait;
        self
    }

    pub fn before(&self) -> RenewBefore {
        self.before
    }

    /// Start a scan of the certificates held now, as (key, certificate
    /// name): what the schedule kept for any other is forgotten.
    pub fn begin_scan<'a>(&mut self, held: impl IntoIterator<Item = (&'a Name, &'a Name)>) {
        let (keys, certs): (HashSet<&Name>, HashSet<&Name>) = held.into_iter().unzip();
        self.retry.retain(|cert, _| certs.contains(cert));
        self.renewed.retain(|key, _| keys.contains(key));
        self.unreadable = 0;
        self.next = self.max_wait;
    }

    /// The store holding the certificates cannot be read: how long to wait
    /// before scanning again (a growing backoff).
    pub fn unreadable(&mut self) -> Duration {
        self.unreadable += 1;
        backoff_delay(Self::RETRY_BASE, self.unreadable - 1)
    }

    /// Whether `cert` of `key` is shorter than the threshold and this is
    /// the first time that is seen for `key`: warn that it renews at a third
    /// of its lifetime instead.
    pub fn first_short_lived(&mut self, key: &Name, cert: &Certificate) -> bool {
        self.before
            .exceeds_lifetime(cert.valid_from, cert.valid_until)
            && self.short_lived.insert(key.clone())
    }

    /// What to do with `cert`, the current certificate of `key`, now.
    pub fn check(&mut self, key: &Name, cert: &Certificate, now: Now) -> Due {
        let due_at = self
            .before
            .renew_at(cert.valid_from, cert.valid_until)
            .max(self.renewed.get(key).copied().unwrap_or(0));
        if now.wall_ns < due_at {
            return self.later(Duration::from_nanos(due_at - now.wall_ns));
        }
        if self.expired.contains(&*cert.name) {
            return Due::Expired;
        }
        if let Some((_, at)) = self.retry.get(&*cert.name) {
            let left = at.saturating_duration_since(now.instant);
            if !left.is_zero() {
                return self.later(left);
            }
        }
        Due::Now
    }

    /// `previous`, the certificate of `key`, was renewed: the CA issued
    /// `issued`.
    pub fn renewed(&mut self, key: &Name, previous: &Certificate, issued: &Certificate) {
        self.retry.remove(&*previous.name);
        self.renewed.insert(
            key.clone(),
            self.before.renew_at(issued.valid_from, issued.valid_until),
        );
    }

    /// An attempt to renew `cert` failed at `now`; `refused`: the CA
    /// refused it (retrying soon cannot help).
    pub fn failed(&mut self, cert: &Certificate, refused: bool, now: Now) -> Failed {
        let days_left = (cert.valid_until as f64 - now.wall_ns as f64) / 86_400e9;
        if days_left <= 0.0 {
            self.expired.insert((*cert.name).clone());
            return Failed::Expired;
        }
        let attempts = self.retry.get(&*cert.name).map_or(0, |(n, _)| *n) + 1;
        let exponent = if refused {
            Self::REFUSED_BACKOFF
        } else {
            attempts - 1
        };
        let delay = backoff_delay(Self::RETRY_BASE, exponent);
        self.retry
            .insert((*cert.name).clone(), (attempts, now.instant + delay));
        self.next = self.next.min(delay);
        Failed::Retry {
            attempts,
            delay,
            days_left,
        }
    }

    /// How long to sleep before the next scan: until the soonest check this
    /// scan asked for, within [`MIN_WAIT`](Self::MIN_WAIT) and the maximum.
    pub fn wait(&self) -> Duration {
        self.next.clamp(Self::MIN_WAIT, self.max_wait)
    }

    fn later(&mut self, after: Duration) -> Due {
        self.next = self.next.min(after);
        Due::Later(after)
    }
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
    /// time, that long before expiry. A fixed time at least the lifetime
    /// never makes a certificate due as it is issued (it would be renewed in
    /// a loop): it renews at a third of the lifetime.
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
        for days in [90, 500] {
            let before = RenewBefore::Remaining(Duration::from_secs(days * 86_400));
            assert!(before.exceeds_lifetime(from, until));
            assert_eq!(before.renew_at(from, until), third);
        }
    }

    /// An expired certificate is told apart from a missing one: renewal
    /// cannot help it, and the task reports that the device must enroll
    /// again instead of falling silent.
    #[test]
    fn an_expired_certificate_is_not_mistaken_for_none() {
        let manager = SecurityManager::new();
        let key_name =
            Name::from_components([NameComponent::generic(bytes::Bytes::from_static(b"k"))]);
        assert!(held_certificate(&manager, &key_name).is_none());
        let mut cert = near_expiry_cert(&key_name);
        cert.valid_until = now_ns() - 1_000_000_000;
        manager.cert_cache().insert(cert);
        let held = held_certificate(&manager, &key_name).expect("the expired one is held");
        let mut schedule = RenewalSchedule::new(RenewBefore::ONE_THIRD);
        assert_eq!(schedule.check(&key_name, &held, Now::current()), Due::Now);
        assert_eq!(
            schedule.failed(&held, false, Now::current()),
            Failed::Expired
        );
        assert_eq!(
            schedule.check(&key_name, &held, Now::current()),
            Due::Expired
        );
    }

    const DAY: u64 = 86_400_000_000_000;

    fn name(uri: &str) -> Name {
        uri.parse().unwrap()
    }

    /// A certificate named `name`, valid from day `from` until day `until`.
    fn cert(name_uri: &str, from: u64, until: u64) -> Certificate {
        let mut c = near_expiry_cert(&name(name_uri));
        c.valid_from = from * DAY;
        c.valid_until = until * DAY;
        c
    }

    fn at(day: u64, instant: Instant) -> Now {
        Now {
            wall_ns: day * DAY,
            instant,
        }
    }

    fn between(d: Duration, low: u64, high: u64) -> bool {
        (Duration::from_secs(low)..=Duration::from_secs(high)).contains(&d)
    }

    /// A certificate is due once a third of its lifetime is left; before
    /// that, the schedule waits until then, at most an hour per sleep.
    #[test]
    fn a_certificate_is_due_at_the_threshold() {
        let key = name("/ns/member/laptop/KEY/k");
        let c = cert("/ns/member/laptop/KEY/k/NDNCERT/v1", 0, 90);
        let mut s = RenewalSchedule::new(RenewBefore::ONE_THIRD);
        let t = Instant::now();
        s.begin_scan([(&key, &*c.name)]);
        let Due::Later(after) = s.check(&key, &c, at(10, t)) else {
            panic!("not due yet")
        };
        assert!(after.as_nanos().abs_diff(u128::from(50 * DAY)) < 1_000_000);
        assert_eq!(s.wait(), RenewalSchedule::MAX_WAIT);
        assert_eq!(s.check(&key, &c, at(61, t)), Due::Now);
    }

    /// A failed attempt is retried after a doubling backoff from a minute;
    /// a refusal after the longest; a renewal clears the backoff.
    #[test]
    fn a_failed_attempt_backs_off_and_a_refusal_longest() {
        let key = name("/ns/member/laptop/KEY/k");
        let c = cert("/ns/member/laptop/KEY/k/NDNCERT/v1", 0, 90);
        let mut s = RenewalSchedule::new(RenewBefore::ONE_THIRD);
        let t = Instant::now();
        s.begin_scan([(&key, &*c.name)]);
        let Failed::Retry {
            attempts: 1,
            delay,
            days_left,
        } = s.failed(&c, false, at(80, t))
        else {
            panic!("a current certificate is retried")
        };
        assert!(between(delay, 30, 60), "{delay:?}");
        assert!((days_left - 10.0).abs() < 1e-6);
        assert_eq!(s.wait(), delay.max(RenewalSchedule::MIN_WAIT));
        assert!(matches!(s.check(&key, &c, at(80, t)), Due::Later(left) if left <= delay));
        assert_eq!(s.check(&key, &c, at(80, t + delay)), Due::Now);
        let Failed::Retry {
            attempts: 2, delay, ..
        } = s.failed(&c, false, at(80, t + delay))
        else {
            panic!("retried again")
        };
        assert!(between(delay, 60, 120), "{delay:?}");
        let Failed::Retry {
            attempts: 3, delay, ..
        } = s.failed(&c, true, at(80, t))
        else {
            panic!("a refusal is retried too")
        };
        assert!(between(delay, 1_800, 3_600), "{delay:?}");

        let renewed = cert("/ns/member/laptop/KEY/k/NDNCERT/v2", 80, 170);
        s.renewed(&key, &c, &renewed);
        let Failed::Retry { attempts: 1, .. } = s.failed(&c, false, at(80, t)) else {
            panic!("the renewal cleared the backoff")
        };
    }

    /// After a renewal the key is not renewed again before the new
    /// certificate is due, even while the store still reports the old one.
    #[test]
    fn a_renewed_key_waits_for_its_new_certificate() {
        let key = name("/ns/member/laptop/KEY/k");
        let old = cert("/ns/member/laptop/KEY/k/NDNCERT/v1", 0, 90);
        let new = cert("/ns/member/laptop/KEY/k/NDNCERT/v2", 61, 151);
        let mut s = RenewalSchedule::new(RenewBefore::ONE_THIRD);
        let t = Instant::now();
        s.begin_scan([(&key, &*old.name)]);
        assert_eq!(s.check(&key, &old, at(61, t)), Due::Now);
        s.renewed(&key, &old, &new);
        s.begin_scan([(&key, &*old.name)]);
        assert!(matches!(s.check(&key, &old, at(62, t)), Due::Later(_)));
        assert_eq!(s.check(&key, &new, at(122, t)), Due::Now);
        // A key no longer held is forgotten.
        s.begin_scan(std::iter::empty());
        assert_eq!(s.check(&key, &old, at(62, t)), Due::Now);
    }

    /// A failed attempt on an expired certificate is reported once and not
    /// retried.
    #[test]
    fn an_expired_certificate_is_reported_once() {
        let key = name("/ns/member/laptop/KEY/k");
        let c = cert("/ns/member/laptop/KEY/k/NDNCERT/v1", 0, 90);
        let mut s = RenewalSchedule::new(RenewBefore::ONE_THIRD);
        let t = Instant::now();
        s.begin_scan([(&key, &*c.name)]);
        assert_eq!(s.check(&key, &c, at(91, t)), Due::Now);
        assert_eq!(s.failed(&c, false, at(91, t)), Failed::Expired);
        assert_eq!(s.check(&key, &c, at(92, t)), Due::Expired);
        assert_eq!(s.wait(), RenewalSchedule::MAX_WAIT);
    }

    /// A threshold at least the lifetime renews at a third of it, and says
    /// so once per key.
    #[test]
    fn a_threshold_longer_than_the_lifetime_is_reported_once() {
        let key = name("/ns/member/laptop/KEY/k");
        let c = cert("/ns/member/laptop/KEY/k/NDNCERT/v1", 0, 90);
        let mut s = RenewalSchedule::new(RenewBefore::Remaining(Duration::from_secs(500 * 86_400)));
        let t = Instant::now();
        assert!(s.first_short_lived(&key, &c));
        assert!(!s.first_short_lived(&key, &c));
        assert!(matches!(s.check(&key, &c, at(59, t)), Due::Later(_)));
        assert_eq!(s.check(&key, &c, at(61, t)), Due::Now);
        let mut fraction = RenewalSchedule::new(RenewBefore::ONE_THIRD);
        assert!(!fraction.first_short_lived(&key, &c));
    }

    /// An unreadable store is scanned again after a growing backoff, reset
    /// by a scan that reads it.
    #[test]
    fn an_unreadable_store_backs_off() {
        let mut s = RenewalSchedule::new(RenewBefore::ONE_THIRD);
        assert!(between(s.unreadable(), 30, 60));
        assert!(between(s.unreadable(), 60, 120));
        s.begin_scan(std::iter::empty());
        assert!(between(s.unreadable(), 30, 60));
    }

    /// The wait between scans stays within the bounds.
    #[test]
    fn the_wait_is_bounded() {
        let s =
            RenewalSchedule::new(RenewBefore::ONE_THIRD).with_max_wait(Duration::from_millis(30));
        assert_eq!(s.wait(), RenewalSchedule::MIN_WAIT);
        let s =
            RenewalSchedule::new(RenewBefore::ONE_THIRD).with_max_wait(Duration::from_secs(600));
        assert_eq!(s.wait(), Duration::from_secs(600));
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
