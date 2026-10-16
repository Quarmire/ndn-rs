//! Engine-backed certificate fetching.
//!
//! A [`Validator`] resolves a signing cert it has not cached through its
//! [`CertFetcher`]. On an embedded engine the natural fetch path is the engine
//! itself: express the cert Interest on an in-process app face and let the
//! forwarder route it to whoever serves the cert (the producer, the CA that
//! issued it, a neighbour's CS). The engine cannot build that fetcher during
//! `EngineBuilder::build` — app faces live above `ndn-engine` — so it is
//! attached afterwards with [`install_engine_cert_fetcher`].
//!
//! Loop/amplification bounds: the fetcher dedups concurrent requests per name
//! and backs off after a failure (one Interest per name per
//! [`CERT_FETCH_TIMEOUT`]); the engine's validation stage never awaits a fetch
//! on the pipeline and drops a waiting Data at its original deadline; a cert's
//! own Data is validated like any other, so resolving a chain costs at most one
//! fetch per missing hop, bounded by the validator's max chain depth.

use std::sync::Arc;
use std::time::Duration;

use ndn_engine::ForwarderEngine;
use ndn_packet::Name;
use ndn_security::{CertCache, CertFetcher, FetchFn};
use tokio_util::sync::CancellationToken;

use crate::EngineAppExt;

/// Upper bound on one certificate fetch, and the back-off before a failed
/// name is fetched again.
pub const CERT_FETCH_TIMEOUT: Duration = Duration::from_secs(4);

/// A [`FetchFn`] that expresses each cert Interest through `engine` on one
/// in-process app face (tied to `cancel`). Concurrent fetches share the face;
/// replies are demultiplexed by name.
pub fn engine_fetch_fn(engine: &ForwarderEngine, cancel: CancellationToken) -> FetchFn {
    let node = Arc::new(engine.app_node(cancel));
    Arc::new(move |name: Name| {
        let node = Arc::clone(&node);
        Box::pin(async move { node.fetch(name).await.ok() })
    })
}

/// A [`CertFetcher`] over `engine` that fills `cache` (normally the cache of
/// the validator it will be attached to).
pub fn engine_cert_fetcher(
    engine: &ForwarderEngine,
    cache: Arc<CertCache>,
    cancel: CancellationToken,
) -> Arc<CertFetcher> {
    Arc::new(CertFetcher::new(
        cache,
        engine_fetch_fn(engine, cancel),
        CERT_FETCH_TIMEOUT,
    ))
}

/// Attach an engine-backed [`CertFetcher`] to the engine's own data-path
/// validator, so Data signed by a cert the node has not seen (e.g. a newly
/// enrolled device) is validated after fetching that cert instead of being
/// dropped. Call once after `EngineBuilder::build`.
///
/// Returns `false` (and allocates nothing) when the engine has no validator
/// (`SecurityProfile::Disabled`) or its validator already has a fetcher.
pub fn install_engine_cert_fetcher(engine: &ForwarderEngine, cancel: CancellationToken) -> bool {
    let Some(validator) = engine.validator() else {
        return false;
    };
    if validator.has_cert_fetcher() {
        return false;
    }
    let fetcher = engine_cert_fetcher(engine, validator.cert_cache_arc(), cancel);
    let installed = validator.set_cert_fetcher(fetcher).is_ok();
    if installed {
        tracing::info!(
            target: "security",
            "engine validator: engine-backed certificate fetcher attached"
        );
    }
    installed
}
