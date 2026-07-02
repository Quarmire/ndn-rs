//! Asynchronous certificate fetcher for NDN trust chain resolution.
//!
//! `CertFetcher` retrieves certificates over NDN by expressing Interests
//! for certificate names. It deduplicates concurrent requests for the same
//! certificate and caches results in the shared `CertCache`.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use ndn_packet::{Data, Name};
use tokio::sync::broadcast;

use crate::TrustError;
use crate::cert_cache::{CertCache, Certificate};

pub type FetchFn =
    Arc<dyn Fn(Name) -> Pin<Box<dyn Future<Output = Option<Data>> + Send>> + Send + Sync>;

pub struct CertFetcher {
    cert_cache: Arc<CertCache>,
    fetch_fn: FetchFn,
    in_flight: DashMap<Arc<Name>, broadcast::Sender<Option<Certificate>>>,
    timeout: Duration,
}

impl CertFetcher {
    pub fn new(cert_cache: Arc<CertCache>, fetch_fn: FetchFn, timeout: Duration) -> Self {
        Self {
            cert_cache,
            fetch_fn,
            in_flight: DashMap::new(),
            timeout,
        }
    }

    /// Fetch a certificate by name, deduplicating concurrent requests.
    ///
    /// Panic-safe: if the leader's `do_fetch` panics, `InFlightGuard`
    /// removes the in-flight entry on unwind, all `Sender` clones drop, and
    /// any follower awaiting `rx.recv()` unblocks with `RecvError::Closed`
    /// mapped to `CertNotFound` instead of hanging.
    pub async fn fetch(&self, cert_name: &Arc<Name>) -> Result<Certificate, TrustError> {
        if let Some(cert) = self.cert_cache.get(cert_name) {
            return Ok(cert);
        }

        if let Some(entry) = self.in_flight.get(cert_name) {
            let mut rx = entry.subscribe();
            drop(entry);
            return match rx.recv().await {
                Ok(Some(cert)) => Ok(cert),
                _ => Err(TrustError::CertNotFound {
                    name: cert_name.to_string(),
                }),
            };
        }

        let (tx, _) = broadcast::channel(1);
        self.in_flight.insert(Arc::clone(cert_name), tx.clone());
        let guard = InFlightGuard {
            in_flight: &self.in_flight,
            cert_name: Arc::clone(cert_name),
        };

        let result = self.do_fetch(cert_name).await;

        let cert = result.as_ref().ok().cloned();
        let _ = tx.send(cert);
        drop(guard);

        result
    }

    async fn do_fetch(&self, cert_name: &Arc<Name>) -> Result<Certificate, TrustError> {
        let name = cert_name.as_ref().clone();

        let data = tokio::time::timeout(self.timeout, (self.fetch_fn)(name))
            .await
            .map_err(|_| TrustError::CertNotFound {
                name: format!("timeout fetching {}", cert_name),
            })?
            .ok_or_else(|| TrustError::CertNotFound {
                name: cert_name.to_string(),
            })?;

        let cert = Certificate::decode(&data)?;
        self.cert_cache.insert(cert.clone());
        Ok(cert)
    }
}

/// Drop-driven cleanup for `CertFetcher::in_flight`. Removes the per-name
/// broadcast `Sender` on either normal exit or a panic during `do_fetch`,
/// ensuring waiting followers see `RecvError::Closed` rather than hanging.
struct InFlightGuard<'a> {
    in_flight: &'a DashMap<Arc<Name>, broadcast::Sender<Option<Certificate>>>,
    cert_name: Arc<Name>,
}

impl Drop for InFlightGuard<'_> {
    fn drop(&mut self) {
        self.in_flight.remove(&self.cert_name);
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
            Box::pin(async { None })
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
            Box::pin(async move { Some(data) })
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
                None
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
                Some(data)
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
}
