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

/// Type alias for the async fetch callback.
///
/// The callback takes a certificate Name and returns `Option<Data>`.
/// `None` means the fetch failed (timeout, no route, etc.).
pub type FetchFn =
    Arc<dyn Fn(Name) -> Pin<Box<dyn Future<Output = Option<Data>> + Send>> + Send + Sync>;

/// Fetches certificates over NDN with deduplication and caching.
pub struct CertFetcher {
    cert_cache: Arc<CertCache>,
    fetch_fn: FetchFn,
    /// In-flight fetch deduplication.
    /// When a cert is being fetched, subsequent requests wait on a broadcast.
    in_flight: DashMap<Arc<Name>, broadcast::Sender<Option<Certificate>>>,
    timeout: Duration,
}

impl CertFetcher {
    /// Create a new fetcher.
    ///
    /// `fetch_fn` is called to express an Interest and return the Data response.
    /// It is typically wired to an `AppHandle` in the engine.
    pub fn new(cert_cache: Arc<CertCache>, fetch_fn: FetchFn, timeout: Duration) -> Self {
        Self {
            cert_cache,
            fetch_fn,
            in_flight: DashMap::new(),
            timeout,
        }
    }

    /// Fetch a certificate by name.
    ///
    /// Returns immediately if the cert is already cached. Otherwise, expresses
    /// an Interest, decodes the response, and caches it. Concurrent requests
    /// for the same name are deduplicated (only one Interest is sent).
    pub async fn fetch(&self, cert_name: &Arc<Name>) -> Result<Certificate, TrustError> {
        // Fast path: already cached.
        if let Some(cert) = self.cert_cache.get(cert_name) {
            return Ok(cert);
        }

        // Check if someone is already fetching this cert.
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

        // We're the first — initiate the fetch.
        let (tx, _) = broadcast::channel(1);
        self.in_flight.insert(Arc::clone(cert_name), tx.clone());

        let result = self.do_fetch(cert_name).await;

        // Notify waiters and clean up.
        let cert = result.as_ref().ok().cloned();
        let _ = tx.send(cert);
        self.in_flight.remove(cert_name);

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

    /// Build a minimal cert Data packet for testing.
    fn make_cert_data(name: &Name, pk: &[u8]) -> Data {
        let mut signed = TlvWriter::new();
        // Name
        signed.write_nested(0x07, |w| {
            for comp in name.components() {
                w.write_tlv(comp.typ as u64, &comp.value);
            }
        });
        // Content with public key
        signed.write_nested(0x15, |w| {
            w.write_tlv(0x00, pk);
        });
        // SignatureInfo (minimal Ed25519)
        signed.write_nested(0x16, |w| {
            w.write_tlv(0x1b, &[5u8]);
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

        // Should be in cache now.
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

        // Launch two concurrent fetches for the same cert.
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
        // Only one actual fetch should have been made.
        assert_eq!(fetch_count.load(Ordering::Relaxed), 1);
    }
}
