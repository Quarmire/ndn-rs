//! Asynchronous certificate fetcher for NDN trust chain resolution.
//!
//! `CertFetcher` retrieves certificates over NDN by expressing Interests
//! for certificate names. It deduplicates concurrent requests for the same
//! certificate, caches results in the shared `CertCache`, and remembers
//! recent failures (a negative cache) so a stream of Data signed by an
//! unfetchable key costs one cert Interest per backoff window rather than one
//! per packet.
//!
//! A fetcher may also ask the neighbour that delivered the Data being
//! validated ([`CertFetcher::with_direct_fetch`], [`CertFetcher::fetch_from`]),
//! as ndn-cxx's `CertificateFetcherDirectFetch` does: a producer serves its
//! own issuer chain, which matters when nobody the routes lead to holds it
//! any more (an earlier CA whose root device was replaced). Where a
//! certificate came from never makes it trusted: the chain walk verifies
//! every hop up to an anchor.
//!
//! A fetch the forwarder answers with a refusal ([`FetchMiss::Refused`]: it
//! refused the certificate Data itself) ends at once with that reason: the
//! validator remembers the refused certificate for its key, so asking the
//! neighbour too could not change the verdict on the Data waiting on it.
//!
//! A fetch every source it asked answered definitively — none to be had
//! there ([`FetchMiss::Absent`], a NoRoute Nack), or a refusal — leaves the
//! certificate known absent ([`CertFetcher::known_absent`]) for as long as
//! the fetcher would not ask again: Data waiting on it can be given a final
//! verdict. A fetch that timed out never does; the network may only be slow.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use ndn_packet::{Data, Name};
use tokio::sync::broadcast;

use crate::TrustError;
use crate::cert_cache::{CertCache, Certificate};

/// Why a [`FetchFn`] or [`DirectFetchFn`] brought no certificate Data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FetchMiss {
    /// Nothing usable answered in time: a timeout, or a Nack that may not
    /// hold for long (congestion, a duplicate).
    Unanswered,
    /// Answered that the certificate cannot be had where it was asked: a
    /// NoRoute Nack.
    Absent,
    /// This host's forwarder refused the Data that answered: a final verdict
    /// on that certificate.
    Refused(ndn_packet::Refusal),
    /// A [`DirectFetchFn`] that asked nobody, because the routed fetch already
    /// goes to that face: the routed fetch's answer stands for both.
    NotAsked,
}

impl FetchMiss {
    /// What two sources that both brought no certificate add up to: absent
    /// only when each said so (one that asked nobody defers to the other).
    fn and(self, other: FetchMiss) -> FetchMiss {
        match (self, other) {
            (FetchMiss::NotAsked, miss) | (miss, FetchMiss::NotAsked) => miss,
            (FetchMiss::Absent, FetchMiss::Absent) => FetchMiss::Absent,
            _ => FetchMiss::Unanswered,
        }
    }
}

pub type FetchFn = Arc<
    dyn Fn(Name) -> Pin<Box<dyn Future<Output = Result<Data, FetchMiss>> + Send>> + Send + Sync,
>;

/// Fetch a certificate name out of one face (a forwarder face id), bypassing
/// the FIB.
pub type DirectFetchFn = Arc<
    dyn Fn(Name, u64) -> Pin<Box<dyn Future<Output = Result<Data, FetchMiss>> + Send>>
        + Send
        + Sync,
>;

/// What a fetch is deduplicated and backed off by: the certificate name and
/// the delivering face asked directly (`None`: routes only). A fetch that
/// asks face A neither answers for nor suppresses one that would ask face B —
/// B may be the one neighbour holding the chain.
type FetchKey = (Arc<Name>, Option<u64>);

pub struct CertFetcher {
    cert_cache: Arc<CertCache>,
    fetch_fn: FetchFn,
    direct_fn: Option<DirectFetchFn>,
    in_flight: DashMap<FetchKey, broadcast::Sender<Option<Certificate>>>,
    /// Fetches whose last attempt failed: until when re-fetching is
    /// suppressed, and whether the certificate is known absent. Bounded:
    /// pruned of expired entries once it exceeds [`NEGATIVE_CACHE_PRUNE_AT`].
    failed: DashMap<FetchKey, Failed>,
    timeout: Duration,
    negative_ttl: Duration,
}

/// A fetch that brought no certificate.
#[derive(Clone, Copy)]
struct Failed {
    /// The key is not fetched again before this.
    retry_at: tokio::time::Instant,
    /// Every source the fetch asked answered definitively (none to be had
    /// there, or a refusal), rather than not answering in time.
    absent: bool,
}

/// Why [`CertFetcher::do_fetch`] brought no certificate.
struct Miss {
    error: TrustError,
    absent: bool,
}

impl From<TrustError> for Miss {
    fn from(error: TrustError) -> Self {
        Self {
            error,
            absent: false,
        }
    }
}

/// Size at which expired negative-cache entries are swept.
const NEGATIVE_CACHE_PRUNE_AT: usize = 1024;

/// How long a routed fetch has to answer before the neighbour that delivered
/// the packet is asked too ([`CertFetcher::fetch_from`]). Well above a
/// forwarder's retransmission-suppression window (NFD and ndn-rs: 10 ms), so
/// the second Interest is forwarded rather than aggregated.
const DIRECT_FETCH_AFTER: Duration = Duration::from_millis(50);

impl CertFetcher {
    /// `timeout` bounds each fetch; a failed fetch suppresses re-fetching the
    /// same name for `timeout` as well (see [`Self::with_negative_ttl`]).
    pub fn new(cert_cache: Arc<CertCache>, fetch_fn: FetchFn, timeout: Duration) -> Self {
        Self {
            cert_cache,
            fetch_fn,
            direct_fn: None,
            in_flight: DashMap::new(),
            failed: DashMap::new(),
            timeout,
            negative_ttl: timeout,
        }
    }

    /// Override how long a failed fetch suppresses re-fetching the same name
    /// (`Duration::ZERO` disables the negative cache).
    pub fn with_negative_ttl(mut self, ttl: Duration) -> Self {
        self.negative_ttl = ttl;
        self
    }

    /// Also ask the face a validated packet arrived on, in parallel with the
    /// routed fetch, when [`Self::fetch_from`] names one.
    pub fn with_direct_fetch(mut self, direct_fn: DirectFetchFn) -> Self {
        self.direct_fn = Some(direct_fn);
        self
    }

    /// How long after a fetch of a name begins that name may next be fetched
    /// when the fetch fails: the fetch timeout plus the failure back-off.
    pub fn retry_after(&self) -> Duration {
        self.timeout + self.negative_ttl
    }

    /// Whether `cert_name` is known absent where [`Self::fetch_from`] asks
    /// for it (with `face` asked too): its last fetch ended with every source
    /// it asked answering that none is to be had there (a NoRoute Nack), or
    /// with this host's forwarder refusing what answered — not merely without
    /// an answer in time, which the network's slowness can explain. Holds for
    /// as long as the fetcher would not ask again.
    pub fn known_absent(&self, cert_name: &Arc<Name>, face: Option<u64>) -> bool {
        let face = face.filter(|_| self.direct_fn.is_some());
        self.failed
            .get(&(Arc::clone(cert_name), face))
            .is_some_and(|f| f.absent && tokio::time::Instant::now() < f.retry_at)
    }

    /// Fetch the certificate `cert_name` resolves to (a key name — the
    /// newest certificate of that key — or a full certificate name),
    /// deduplicating concurrent requests. A cached certificate answers only
    /// while it is valid: once the cached one expires, a fresh one is fetched
    /// (the fetch function asks with `CanBePrefix` and `MustBeFresh`, so a
    /// renewed certificate is found rather than a cached copy of the old).
    ///
    /// Panic-safe: if the leader's `do_fetch` panics, `InFlightGuard`
    /// removes the in-flight entry on unwind, all `Sender` clones drop, and
    /// any follower awaiting `rx.recv()` unblocks with `RecvError::Closed`
    /// mapped to `CertNotFound` instead of hanging.
    pub async fn fetch(&self, cert_name: &Arc<Name>) -> Result<Certificate, TrustError> {
        self.fetch_from(cert_name, None).await
    }

    /// [`Self::fetch`], also asking the neighbour on `face` (the face the
    /// packet being validated arrived on) when a direct fetch is configured:
    /// both are asked at once and the first certificate under `cert_name`
    /// answers. Deduplication and the failure back-off are per name *and*
    /// face, so a fetch for Data from one neighbour never stands in for
    /// asking another.
    pub async fn fetch_from(
        &self,
        cert_name: &Arc<Name>,
        face: Option<u64>,
    ) -> Result<Certificate, TrustError> {
        if let Some(cert) = self.cert_cache.get_valid(cert_name) {
            return Ok(cert);
        }
        let face = face.filter(|_| self.direct_fn.is_some());
        let key: FetchKey = (Arc::clone(cert_name), face);

        // Negative cache: a recent failure for this name short-circuits, so
        // Data signed by an unreachable key cannot drive a fetch per packet.
        let failed = self.failed.get(&key).map(|e| *e.value());
        if let Some(failed) = failed {
            if tokio::time::Instant::now() < failed.retry_at {
                let why = if failed.absent { "known absent" } else { "recently failed" };
                return Err(TrustError::CertNotFound {
                    name: format!("{why}: {cert_name}"),
                });
            }
            self.failed.remove(&key);
        }

        // Atomic leader election: exactly one caller per key issues the fetch.
        let tx = match self.in_flight.entry(key.clone()) {
            dashmap::mapref::entry::Entry::Occupied(entry) => {
                let mut rx = entry.get().subscribe();
                drop(entry);
                return match rx.recv().await {
                    Ok(Some(cert)) => Ok(cert),
                    // Closed before we subscribed in time: the leader may still
                    // have succeeded (it caches before publishing).
                    _ => self
                        .cert_cache
                        .get_valid(cert_name)
                        .ok_or_else(|| TrustError::CertNotFound {
                            name: cert_name.to_string(),
                        }),
                };
            }
            dashmap::mapref::entry::Entry::Vacant(entry) => {
                let (tx, _) = broadcast::channel(1);
                entry.insert(tx.clone());
                tx
            }
        };
        let guard = InFlightGuard {
            in_flight: &self.in_flight,
            key: key.clone(),
        };

        let result = self.do_fetch(cert_name, face).await;

        if let Err(miss) = &result
            && !self.negative_ttl.is_zero()
        {
            let now = tokio::time::Instant::now();
            if self.failed.len() >= NEGATIVE_CACHE_PRUNE_AT {
                self.failed.retain(|_, f| f.retry_at > now);
            }
            self.failed.insert(
                key,
                Failed {
                    retry_at: now + self.negative_ttl,
                    absent: miss.absent,
                },
            );
        }

        let cert = result.as_ref().ok().cloned();
        let _ = tx.send(cert);
        drop(guard);

        result.map_err(|miss| miss.error)
    }

    async fn do_fetch(&self, cert_name: &Arc<Name>, face: Option<u64>) -> Result<Certificate, Miss> {
        let name = cert_name.as_ref().clone();
        let routed = (self.fetch_fn)(name.clone());
        let answer = async {
            let (Some(face), Some(direct)) = (face, &self.direct_fn) else {
                return routed.await;
            };
            // The neighbour is asked only when the routed fetch has not
            // answered within `DIRECT_FETCH_AFTER`, and never sooner: the
            // same Interest arriving at the forwarder twice within its
            // retransmission-suppression window aggregates into one PIT
            // entry, so the later of the two would never be sent.
            let started = tokio::time::Instant::now();
            tokio::pin!(routed);
            match tokio::time::timeout(DIRECT_FETCH_AFTER, &mut routed).await {
                // Data, or a refusal: the verdict on the certificate.
                Ok(answered @ (Ok(_) | Err(FetchMiss::Refused(_)))) => answered,
                Ok(Err(miss)) => {
                    tokio::time::sleep_until(started + DIRECT_FETCH_AFTER).await;
                    then_ask(miss, direct(name, face)).await
                }
                Err(_) => first_answer(routed, direct(name, face)).await,
            }
        };

        let data = match tokio::time::timeout(self.timeout, answer).await {
            Err(_) => {
                return Err(TrustError::CertNotFound {
                    name: format!("timeout fetching {}", cert_name),
                }
                .into());
            }
            Ok(Err(FetchMiss::Unanswered | FetchMiss::NotAsked)) => {
                return Err(TrustError::CertNotFound {
                    name: cert_name.to_string(),
                }
                .into());
            }
            Ok(Err(FetchMiss::Absent)) => {
                return Err(Miss {
                    error: TrustError::CertNotFound {
                        name: format!("{cert_name}: none to be had where it was asked"),
                    },
                    absent: true,
                });
            }
            Ok(Err(FetchMiss::Refused(refusal))) => {
                return Err(Miss {
                    error: TrustError::CertNotFound {
                        name: format!(
                            "{cert_name}: the forwarder refused the certificate that answered \
                             ({refusal})"
                        ),
                    },
                    absent: true,
                });
            }
            Ok(Ok(data)) => data,
        };

        // The answer to a prefix Interest must be a certificate of the
        // requested key under the requested name — not other Data under it
        // (another key's certificate, an NDNCERT approval `<key>/ndncert-approve/<id>`,
        // anything a producer publishes there), which would be cached and
        // then resolve the KeyLocator to a key it does not name.
        if !crate::cert_cache::resolves_to(cert_name, &data.name)
            || crate::cert_name::is_reserved_non_cert(&data.name)
        {
            return Err(TrustError::CertNotFound {
                name: format!(
                    "{} answered the fetch for {cert_name} but is no certificate of that key",
                    data.name
                ),
            }
            .into());
        }
        let cert = Certificate::decode(&data)?;
        self.cert_cache.insert(cert.clone());
        Ok(cert)
    }
}

/// The first of `a` and `b` to answer with Data or a refusal; once neither
/// did, what their misses add up to ([`FetchMiss::and`]).
async fn first_answer<A, B>(a: A, b: B) -> Result<Data, FetchMiss>
where
    A: Future<Output = Result<Data, FetchMiss>>,
    B: Future<Output = Result<Data, FetchMiss>>,
{
    tokio::pin!(a, b);
    tokio::select! {
        found = &mut a => match found {
            Err(miss) if !matches!(miss, FetchMiss::Refused(_)) => then_ask(miss, b).await,
            answered => answered,
        },
        found = &mut b => match found {
            Err(miss) if !matches!(miss, FetchMiss::Refused(_)) => then_ask(miss, a).await,
            answered => answered,
        },
    }
}

/// `other`'s answer (Data, or a refusal) after a source that brought `miss`;
/// if it misses too, what the two misses add up to.
async fn then_ask<F>(miss: FetchMiss, other: F) -> Result<Data, FetchMiss>
where
    F: Future<Output = Result<Data, FetchMiss>>,
{
    match other.await {
        Err(other) if !matches!(other, FetchMiss::Refused(_)) => Err(miss.and(other)),
        answered => answered,
    }
}

/// Drop-driven cleanup for `CertFetcher::in_flight`. Removes the per-key
/// broadcast `Sender` on either normal exit or a panic during `do_fetch`,
/// ensuring waiting followers see `RecvError::Closed` rather than hanging.
struct InFlightGuard<'a> {
    in_flight: &'a DashMap<FetchKey, broadcast::Sender<Option<Certificate>>>,
    key: FetchKey,
}

impl Drop for InFlightGuard<'_> {
    fn drop(&mut self) {
        self.in_flight.remove(&self.key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use ndn_packet::NameComponent;
    use ndn_tlv::TlvWriter;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn make_cert_name(id: &str) -> Arc<Name> {
        Arc::new(Name::from_components([
            NameComponent::generic(Bytes::copy_from_slice(id.as_bytes())),
            NameComponent::generic(Bytes::from_static(b"KEY")),
            NameComponent::generic(Bytes::from_static(b"k1")),
        ]))
    }

    fn make_cert_data(name: &Name, pk: &[u8]) -> Data {
        // Certificate Format v2 wire: Content is raw SPKI bytes for
        // Ed25519, SignatureInfo carries no ValidityPeriod (defaults to
        // 0..MAX), matching the wide-open setup the fetcher tests need.
        let mut signed = TlvWriter::new();
        signed.write_nested(0x07, |w| {
            for comp in name.components() {
                w.write_tlv(comp.typ, &comp.value);
            }
        });
        let spki: Vec<u8> = if pk.len() == crate::spki::ED25519_KEY_LEN {
            let mut k = [0u8; crate::spki::ED25519_KEY_LEN];
            k.copy_from_slice(pk);
            crate::spki::wrap_ed25519(&k).to_vec()
        } else {
            pk.to_vec()
        };
        signed.write_tlv(0x15, &spki);
        signed.write_nested(0x16, |w| {
            w.write_tlv(0x1b, &[5u8]);
            // Ed25519 decode requires a KeyLocator; self-locator pointing
            // at the cert's own name is the simplest satisfying fixture.
            w.write_nested(ndn_packet::tlv_type::KEY_LOCATOR, |w| {
                w.write_nested(0x07, |w| {
                    for comp in name.components() {
                        w.write_tlv(comp.typ, &comp.value);
                    }
                });
            });
        });
        let region = signed.finish();
        let mut inner = region.to_vec();
        {
            let mut sw = TlvWriter::new();
            sw.write_tlv(0x17, &[0u8; 64]);
            inner.extend_from_slice(&sw.finish());
        }
        let mut outer = TlvWriter::new();
        outer.write_tlv(0x06, &inner);
        Data::decode(outer.finish()).unwrap()
    }

    #[tokio::test]
    async fn cache_hit_skips_fetch() {
        let cache = Arc::new(CertCache::new());
        let cert_name = make_cert_name("alice");
        cache.insert(Certificate {
            name: Arc::clone(&cert_name),
            public_key: Bytes::from_static(&[1; 32]),
            valid_from: 0,
            valid_until: u64::MAX,
            issuer: None,
            signed_region: None,
            sig_value: None,
            sig_type: ndn_packet::SignatureType::SignatureEd25519,
        });

        let fetch_count = Arc::new(AtomicUsize::new(0));
        let fc = Arc::clone(&fetch_count);
        let fetch_fn: FetchFn = Arc::new(move |_| {
            fc.fetch_add(1, Ordering::Relaxed);
            Box::pin(async { Err(FetchMiss::Unanswered) })
        });

        let fetcher = CertFetcher::new(cache, fetch_fn, Duration::from_secs(1));
        let cert = fetcher.fetch(&cert_name).await.unwrap();
        assert_eq!(cert.public_key.as_ref(), &[1; 32]);
        assert_eq!(fetch_count.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn successful_fetch_caches_result() {
        let cache = Arc::new(CertCache::new());
        let cert_name = make_cert_name("bob");

        let cn = Arc::clone(&cert_name);
        let fetch_fn: FetchFn = Arc::new(move |_| {
            let data = make_cert_data(&cn, &[2; 32]);
            Box::pin(async move { Ok(data) })
        });

        let fetcher = CertFetcher::new(Arc::clone(&cache), fetch_fn, Duration::from_secs(1));
        let cert = fetcher.fetch(&cert_name).await.unwrap();
        assert_eq!(cert.public_key.as_ref(), &[2; 32]);

        assert!(cache.get(&cert_name).is_some());
    }

    #[tokio::test]
    async fn fetch_timeout_returns_error() {
        let cache = Arc::new(CertCache::new());
        let cert_name = make_cert_name("slow");

        let fetch_fn: FetchFn = Arc::new(|_| {
            Box::pin(async {
                tokio::time::sleep(Duration::from_secs(10)).await;
                Err(FetchMiss::Unanswered)
            })
        });

        let fetcher = CertFetcher::new(cache, fetch_fn, Duration::from_millis(50));
        let result = fetcher.fetch(&cert_name).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn deduplication_sends_one_interest() {
        let cache = Arc::new(CertCache::new());
        let cert_name = make_cert_name("carol");

        let fetch_count = Arc::new(AtomicUsize::new(0));
        let fc = Arc::clone(&fetch_count);
        let cn = Arc::clone(&cert_name);
        let fetch_fn: FetchFn = Arc::new(move |_| {
            fc.fetch_add(1, Ordering::Relaxed);
            let data = make_cert_data(&cn, &[3; 32]);
            Box::pin(async move {
                tokio::time::sleep(Duration::from_millis(50)).await;
                Ok(data)
            })
        });

        let fetcher = Arc::new(CertFetcher::new(cache, fetch_fn, Duration::from_secs(1)));

        let f1 = {
            let fetcher = Arc::clone(&fetcher);
            let name = Arc::clone(&cert_name);
            tokio::spawn(async move { fetcher.fetch(&name).await })
        };
        let f2 = {
            let fetcher = Arc::clone(&fetcher);
            let name = Arc::clone(&cert_name);
            tokio::spawn(async move { fetcher.fetch(&name).await })
        };

        let (r1, r2) = tokio::join!(f1, f2);
        assert!(r1.unwrap().is_ok());
        assert!(r2.unwrap().is_ok());
        assert_eq!(fetch_count.load(Ordering::Relaxed), 1);
    }

    /// When the leader's `do_fetch` panics, the follower must not hang
    /// on the broadcast channel. `InFlightGuard`'s `Drop` removes the
    /// dashmap entry on unwind, dropping the `Sender` clones so the
    /// follower's `rx.recv()` resolves to `CertNotFound`.
    #[tokio::test]
    async fn leader_panic_unblocks_follower_via_drop_guard() {
        let cache = Arc::new(CertCache::new());
        let cert_name = make_cert_name("panicker");

        // Panic *inside* the future after a small delay so the
        // follower has time to observe the leader's `in_flight`
        // entry and subscribe to the broadcast. Without this delay
        // the leader's panic runs synchronously on first poll, its
        // guard drops, the dashmap entry vanishes, and the follower
        // races to re-create the entry as a new leader — which
        // would then *also* panic. The 50 ms / 25 ms split below
        // pins the test on the dedup path (follower as actual
        // follower, not as next-leader).
        let fetch_fn: FetchFn = Arc::new(|_name| {
            Box::pin(async {
                tokio::time::sleep(Duration::from_millis(50)).await;
                panic!("simulated leader panic mid-fetch");
            })
        });

        let fetcher = Arc::new(CertFetcher::new(cache, fetch_fn, Duration::from_secs(5)));

        let leader = {
            let f = Arc::clone(&fetcher);
            let n = Arc::clone(&cert_name);
            tokio::spawn(async move { f.fetch(&n).await })
        };
        tokio::time::sleep(Duration::from_millis(25)).await;
        let follower = {
            let f = Arc::clone(&fetcher);
            let n = Arc::clone(&cert_name);
            tokio::spawn(async move { f.fetch(&n).await })
        };

        // Wrap the join in a 2 s timeout so any regression manifests as
        // a test timeout rather than a workspace-test hang.
        let joined = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(leader, follower)
        })
        .await
        .expect("leader panic must not deadlock follower");

        // Leader's task panicked → JoinResult is Err. Follower's
        // task completed normally with Err(CertNotFound) once the
        // dashmap entry was dropped.
        assert!(joined.0.is_err(), "leader task should report panic");
        let follower_result = joined.1.unwrap();
        assert!(
            matches!(follower_result, Err(TrustError::CertNotFound { .. })),
            "follower should resolve to CertNotFound, got {follower_result:?}",
        );

        // `in_flight` is empty after the guard's `Drop` ran.
        assert_eq!(fetcher.in_flight.len(), 0);
    }

    fn counting_miss_fetch_fn() -> (FetchFn, Arc<AtomicUsize>) {
        let count = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&count);
        let fetch_fn: FetchFn = Arc::new(move |_| {
            c.fetch_add(1, Ordering::Relaxed);
            Box::pin(async { Err(FetchMiss::Unanswered) })
        });
        (fetch_fn, count)
    }

    /// A cert that fails to fetch (no route / Nack resolve instantly) must not
    /// be re-fetched for every Data that names it: the negative cache holds the
    /// failure for the backoff window, so N lookups cost one Interest.
    #[tokio::test]
    async fn failed_fetch_is_not_retried_within_backoff() {
        let (fetch_fn, count) = counting_miss_fetch_fn();
        let fetcher = CertFetcher::new(
            Arc::new(CertCache::new()),
            fetch_fn,
            Duration::from_secs(30),
        );
        let name = make_cert_name("gone");
        for _ in 0..50 {
            assert!(fetcher.fetch(&name).await.is_err());
        }
        assert_eq!(count.load(Ordering::Relaxed), 1, "one Interest per backoff window");
        // A different name is unaffected.
        assert!(fetcher.fetch(&make_cert_name("other")).await.is_err());
        assert_eq!(count.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn failed_fetch_is_retried_after_backoff() {
        let (fetch_fn, count) = counting_miss_fetch_fn();
        let fetcher = CertFetcher::new(
            Arc::new(CertCache::new()),
            fetch_fn,
            Duration::from_secs(1),
        )
        .with_negative_ttl(Duration::from_millis(30));
        let name = make_cert_name("later");
        assert!(fetcher.fetch(&name).await.is_err());
        assert!(fetcher.fetch(&name).await.is_err());
        assert_eq!(count.load(Ordering::Relaxed), 1);
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(fetcher.fetch(&name).await.is_err());
        assert_eq!(count.load(Ordering::Relaxed), 2, "backoff expired → refetch");
    }

    #[tokio::test]
    async fn zero_negative_ttl_disables_backoff() {
        let (fetch_fn, count) = counting_miss_fetch_fn();
        let fetcher = CertFetcher::new(
            Arc::new(CertCache::new()),
            fetch_fn,
            Duration::from_secs(1),
        )
        .with_negative_ttl(Duration::ZERO);
        let name = make_cert_name("nocache");
        for _ in 0..3 {
            assert!(fetcher.fetch(&name).await.is_err());
        }
        assert_eq!(count.load(Ordering::Relaxed), 3);
    }

    /// A routed fetch that never answers (the routes lead to a node that no
    /// longer holds the certificate: an earlier CA after its root device was
    /// replaced) is rescued by the neighbour that delivered the packet,
    /// asked on its face no sooner than `DIRECT_FETCH_AFTER` — so the two
    /// Interests are not aggregated into one PIT entry.
    #[tokio::test]
    async fn the_delivering_face_answers_when_the_routed_fetch_cannot() {
        let cert_name = make_cert_name("earlier-ca");
        let routed: FetchFn = Arc::new(|_| Box::pin(std::future::pending()));
        let asked = Arc::new(std::sync::OnceLock::new());
        let count = Arc::new(AtomicUsize::new(0));
        let (cn, log, n) = (Arc::clone(&cert_name), Arc::clone(&asked), Arc::clone(&count));
        let started = tokio::time::Instant::now();
        let direct: DirectFetchFn = Arc::new(move |_, face| {
            n.fetch_add(1, Ordering::Relaxed);
            let _ = log.set((face, started.elapsed()));
            let data = make_cert_data(&cn, &[7; 32]);
            Box::pin(async move { Ok(data) })
        });
        let fetcher = CertFetcher::new(Arc::new(CertCache::new()), routed, Duration::from_secs(1))
            .with_direct_fetch(direct);

        let cert = fetcher.fetch_from(&cert_name, Some(9)).await.unwrap();
        assert_eq!(cert.public_key.as_ref(), &[7; 32]);
        assert_eq!(count.load(Ordering::Relaxed), 1);
        let (face, after) = *asked.get().unwrap();
        assert_eq!(face, 9, "asked on the face the packet arrived on");
        assert!(after >= DIRECT_FETCH_AFTER, "asked too soon: {after:?}");
    }

    /// A routed fetch that answers in time is all that is sent; without a
    /// face, or without a direct fetch configured, the neighbour is never
    /// asked.
    #[tokio::test]
    async fn the_delivering_face_is_not_asked_when_the_routes_answer() {
        let cert_name = make_cert_name("current-ca");
        let cn = Arc::clone(&cert_name);
        let routed: FetchFn = Arc::new(move |_| {
            let data = make_cert_data(&cn, &[8; 32]);
            Box::pin(async move { Ok(data) })
        });
        let direct_count = Arc::new(AtomicUsize::new(0));
        let dc = Arc::clone(&direct_count);
        let direct: DirectFetchFn = Arc::new(move |_, _| {
            dc.fetch_add(1, Ordering::Relaxed);
            Box::pin(async { Err(FetchMiss::Unanswered) })
        });
        let fetcher = CertFetcher::new(Arc::new(CertCache::new()), routed, Duration::from_secs(1))
            .with_direct_fetch(direct);
        assert!(fetcher.fetch_from(&cert_name, Some(9)).await.is_ok());
        assert_eq!(direct_count.load(Ordering::Relaxed), 0);

        let unrouted = make_cert_name("unrouted");
        assert!(fetcher.fetch(&unrouted).await.is_err());
        assert_eq!(direct_count.load(Ordering::Relaxed), 0, "no face named, none asked");
    }

    /// A routed fetch the forwarder answers with a refusal ends at once with
    /// that reason, and the neighbour is not asked: the verdict on the
    /// certificate stands whoever serves it.
    #[tokio::test]
    async fn a_refused_certificate_ends_the_fetch_at_once() {
        let cert_name = make_cert_name("revoked");
        let routed: FetchFn = Arc::new(|_| {
            Box::pin(async { Err(FetchMiss::Refused(ndn_packet::Refusal::Revoked)) })
        });
        let direct_count = Arc::new(AtomicUsize::new(0));
        let dc = Arc::clone(&direct_count);
        let direct: DirectFetchFn = Arc::new(move |_, _| {
            dc.fetch_add(1, Ordering::Relaxed);
            Box::pin(async { Err(FetchMiss::Unanswered) })
        });
        let fetcher = CertFetcher::new(Arc::new(CertCache::new()), routed, Duration::from_secs(5))
            .with_direct_fetch(direct);
        let started = tokio::time::Instant::now();
        let err = fetcher.fetch_from(&cert_name, Some(9)).await.unwrap_err();
        assert!(err.to_string().contains("refused"), "{err}");
        assert!(started.elapsed() < DIRECT_FETCH_AFTER, "waited: {:?}", started.elapsed());
        tokio::time::sleep(DIRECT_FETCH_AFTER * 2).await;
        assert_eq!(direct_count.load(Ordering::Relaxed), 0, "the neighbour was asked");
    }

    /// Only a certificate of the requested key answers its fetch: other Data
    /// under the requested name (another key's certificate, an NDNCERT
    /// approval, a producer's ordinary Data) is refused and never cached.
    #[tokio::test]
    async fn only_a_certificate_of_the_requested_key_answers() {
        let cases = [
            ("/home/bob", "/home/bob/eve/p"),
            ("/home/bob", "/home/bob/eve/KEY/e/NDNCERT/v=1"),
            ("/a/KEY/k", "/a/KEY/k/ndncert-approve/7"),
            ("/a/KEY/k", "/a/KEY/k/extra"),
            ("/a/KEY/k/NDNCERT", "/a/KEY/k/NDNCERT/v=1/extra"),
        ];
        for (asked, answered) in cases {
            let asked: Arc<Name> = Arc::new(asked.parse().unwrap());
            let answered: Name = answered.parse().unwrap();
            let cache = Arc::new(CertCache::new());
            let fetch_fn: FetchFn = Arc::new(move |_| {
                let data = make_cert_data(&answered, &[5; 32]);
                Box::pin(async move { Ok(data) })
            });
            let fetcher = CertFetcher::new(Arc::clone(&cache), fetch_fn, Duration::from_secs(1));
            assert!(fetcher.fetch(&asked).await.is_err(), "{asked} accepted a foreign answer");
            assert!(cache.get(&asked).is_none());
        }
        // A certificate of the key, and a legacy key-named one, do answer.
        for (asked, answered) in [("/a/KEY/k", "/a/KEY/k/NDNCERT/v=1"), ("/a/KEY/k", "/a/KEY/k")] {
            let asked: Arc<Name> = Arc::new(asked.parse().unwrap());
            let answered: Name = answered.parse().unwrap();
            let fetch_fn: FetchFn = Arc::new(move |_| {
                let data = make_cert_data(&answered, &[5; 32]);
                Box::pin(async move { Ok(data) })
            });
            let fetcher =
                CertFetcher::new(Arc::new(CertCache::new()), fetch_fn, Duration::from_secs(1));
            assert!(fetcher.fetch(&asked).await.is_ok());
        }
    }

    /// A fetch that asked one neighbour, in flight or failed, never stands
    /// in for asking another: the neighbour holding the chain is asked
    /// whatever order the packets arrived in.
    #[tokio::test]
    async fn each_delivering_face_is_asked_for_its_own_packet() {
        let cert_name = make_cert_name("earlier-ca");
        let routed: FetchFn = Arc::new(|_| Box::pin(async { Err(FetchMiss::Unanswered) }));
        let cn = Arc::clone(&cert_name);
        // Only face 2 holds the certificate; face 1 answers late, with nothing.
        let direct: DirectFetchFn = Arc::new(move |_, face| {
            let data = make_cert_data(&cn, &[6; 32]);
            Box::pin(async move {
                if face == 2 {
                    Ok(data)
                } else {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    Err(FetchMiss::Unanswered)
                }
            })
        });
        let fetcher = Arc::new(
            CertFetcher::new(Arc::new(CertCache::new()), routed, Duration::from_secs(5))
                .with_direct_fetch(direct),
        );

        // Face 1's fetch is in flight when face 2's packet asks.
        let first = {
            let (f, n) = (Arc::clone(&fetcher), Arc::clone(&cert_name));
            tokio::spawn(async move { f.fetch_from(&n, Some(1)).await })
        };
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(fetcher.fetch_from(&cert_name, Some(2)).await.is_ok());
        let _ = first.await;

        // Face 1's fetch failed and is backed off; face 2 is still asked.
        let fetcher = CertFetcher::new(
            Arc::new(CertCache::new()),
            Arc::new(|_| Box::pin(async { Err(FetchMiss::Unanswered) })),
            Duration::from_secs(5),
        )
        .with_direct_fetch({
            let cn = Arc::clone(&cert_name);
            Arc::new(move |_, face| {
                let data = make_cert_data(&cn, &[6; 32]);
                Box::pin(async move { (face == 2).then_some(data).ok_or(FetchMiss::Unanswered) })
            })
        });
        assert!(fetcher.fetch_from(&cert_name, Some(1)).await.is_err());
        assert!(fetcher.fetch_from(&cert_name, Some(2)).await.is_ok());
    }

    fn answering(miss: FetchMiss) -> (FetchFn, Arc<AtomicUsize>) {
        let count = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&count);
        let fetch_fn: FetchFn = Arc::new(move |_| {
            c.fetch_add(1, Ordering::Relaxed);
            Box::pin(async move { Err(miss) })
        });
        (fetch_fn, count)
    }

    fn direct_answering(miss: FetchMiss) -> DirectFetchFn {
        Arc::new(move |_, _| Box::pin(async move { Err(miss) }))
    }

    /// A fetch every source answered "none here" (NoRoute) — the routes and
    /// the delivering face — leaves the certificate known absent for that
    /// face while the back-off lasts, and the back-off still holds: no
    /// second Interest. Another face's packet is not answered by it.
    #[tokio::test]
    async fn a_certificate_every_source_says_is_absent_is_known_absent() {
        let name = make_cert_name("unenrolled");
        let (routed, count) = answering(FetchMiss::Absent);
        let fetcher = CertFetcher::new(Arc::new(CertCache::new()), routed, Duration::from_secs(1))
            .with_negative_ttl(Duration::from_millis(100))
            .with_direct_fetch(direct_answering(FetchMiss::Absent));

        assert!(!fetcher.known_absent(&name, Some(9)), "not before it was asked");
        assert!(fetcher.fetch_from(&name, Some(9)).await.is_err());
        assert!(fetcher.known_absent(&name, Some(9)));
        assert!(!fetcher.known_absent(&name, Some(4)), "only for the face asked");
        assert!(fetcher.fetch_from(&name, Some(9)).await.is_err());
        assert_eq!(count.load(Ordering::Relaxed), 1, "backed off as before");
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            !fetcher.known_absent(&name, Some(9)),
            "once it may be asked again, it is no longer known"
        );

        // A routes-only fetch: the one source asked decides.
        let (routed, _) = answering(FetchMiss::Absent);
        let fetcher = CertFetcher::new(Arc::new(CertCache::new()), routed, Duration::from_secs(1));
        assert!(fetcher.fetch(&name).await.is_err());
        assert!(fetcher.known_absent(&name, None));
    }

    /// Absent is final only when every source asked answered definitively:
    /// a source that did not answer in time (or answered a transient Nack)
    /// leaves it unknown — the network may only be slow. A direct fetch that
    /// asked nobody (the routes already lead to that face) defers to the
    /// routed answer.
    #[tokio::test]
    async fn absence_needs_every_source_asked_to_answer_it() {
        let name = make_cert_name("maybe");
        let cases = [
            (FetchMiss::Absent, FetchMiss::Unanswered, false),
            (FetchMiss::Unanswered, FetchMiss::Absent, false),
            (FetchMiss::Absent, FetchMiss::NotAsked, true),
            (FetchMiss::Unanswered, FetchMiss::NotAsked, false),
        ];
        for (routed, direct, absent) in cases {
            let (routed_fn, _) = answering(routed);
            let fetcher =
                CertFetcher::new(Arc::new(CertCache::new()), routed_fn, Duration::from_secs(1))
                    .with_direct_fetch(direct_answering(direct));
            assert!(fetcher.fetch_from(&name, Some(9)).await.is_err());
            assert_eq!(fetcher.known_absent(&name, Some(9)), absent, "{routed:?} + {direct:?}");
        }

        // The routes say none, the neighbour never answers: the fetch times
        // out, and nothing is known.
        let (routed, _) = answering(FetchMiss::Absent);
        let fetcher =
            CertFetcher::new(Arc::new(CertCache::new()), routed, Duration::from_millis(200))
                .with_direct_fetch(Arc::new(|_, _| Box::pin(std::future::pending())));
        assert!(fetcher.fetch_from(&name, Some(9)).await.is_err());
        assert!(!fetcher.known_absent(&name, Some(9)));

        // The routes say none, the neighbour holds it: found.
        let (routed, _) = answering(FetchMiss::Absent);
        let cn = Arc::clone(&name);
        let fetcher = CertFetcher::new(Arc::new(CertCache::new()), routed, Duration::from_secs(1))
            .with_direct_fetch(Arc::new(move |_, _| {
                let data = make_cert_data(&cn, &[3; 32]);
                Box::pin(async move { Ok(data) })
            }));
        assert!(fetcher.fetch_from(&name, Some(9)).await.is_ok());
        assert!(!fetcher.known_absent(&name, Some(9)));
    }

    /// A refusal of what answered is a definitive answer too.
    #[tokio::test]
    async fn a_refused_certificate_is_known_absent() {
        let name = make_cert_name("refused");
        let (routed, _) = answering(FetchMiss::Refused(ndn_packet::Refusal::Revoked));
        let fetcher = CertFetcher::new(Arc::new(CertCache::new()), routed, Duration::from_secs(1))
            .with_direct_fetch(direct_answering(FetchMiss::Unanswered));
        assert!(fetcher.fetch_from(&name, Some(9)).await.is_err());
        assert!(fetcher.known_absent(&name, Some(9)));
    }
}
