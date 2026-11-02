//! Certificate fetching over an engine or a forwarder connection.
//!
//! A [`Validator`](ndn_security::Validator) resolves a signing cert it has not cached through its
//! [`CertFetcher`]. On an embedded engine the natural fetch path is the engine
//! itself: express the cert Interest on an in-process app face and let the
//! forwarder route it to whoever serves the cert (the producer, the CA that
//! issued it, a neighbour's CS). The engine cannot build that fetcher during
//! `EngineBuilder::build` — app faces live above `ndn-engine` — so it is
//! attached afterwards with [`install_engine_cert_fetcher`]. An app on a
//! forwarder connection fetches the same way over its connection:
//! [`demux_cert_fetcher`] over a [`Node`](crate::Node)'s demultiplexer.
//!
//! Loop/amplification bounds: the fetcher dedups concurrent requests per name
//! and backs off after a failure (one Interest per name per
//! [`CERT_FETCH_TIMEOUT`]); the engine's validation stage never awaits a fetch
//! on the pipeline and drops a waiting Data at its original deadline; a cert's
//! own Data is validated like any other, so resolving a chain costs at most one
//! fetch per missing hop, bounded by the validator's max chain depth.
//!
//! Resolving a chain keeps several fetches in flight on the one face at once:
//! the leaf cert's Data is itself parked until its issuer's cert is fetched.
//! The face is always a [`DemuxConnection`] (the types demand it), over which every
//! [`Consumer`] fetch receives exactly the reply that answers its own
//! Interest; a shared receive queue would hand the issuer's cert to the leaf
//! fetch, which discards it as a straggler, and both fetches time out.

use std::sync::Arc;
use std::time::Duration;

use ndn_engine::ForwarderEngine;
use ndn_face::local::InProcFace;
use ndn_packet::Name;
use ndn_packet::encode::InterestBuilder;
use ndn_security::{CertCache, CertFetcher, DirectFetchFn, FetchFn, FetchMiss};
use ndn_transport::FaceId;
use tokio_util::sync::CancellationToken;

use crate::connection::{Connection, InProcConnection};
use crate::{AppError, Consumer, DemuxConnection, EngineAppExt};

/// In-process face buffer depth of the direct-fetch face (as an app face's).
const DIRECT_FACE_BUFFER: usize = 256;

/// Upper bound on one certificate fetch, and the back-off before a failed
/// name is fetched again.
pub const CERT_FETCH_TIMEOUT: Duration = Duration::from_secs(4);

/// The cert Interest every fetch path expresses: see [`demux_fetch_fn`].
fn cert_interest(name: Name) -> InterestBuilder {
    InterestBuilder::new(name)
        .can_be_prefix()
        .must_be_fresh()
        .lifetime(CERT_FETCH_TIMEOUT)
}

/// A fetch's error as the [`CertFetcher`] reads it: the forwarder refused
/// what this source served, or a NoRoute Nack says none is to be had where it
/// was asked — both definitive for this source only — while anything else (a
/// timeout, a transient Nack) is no answer.
fn miss(e: AppError) -> FetchMiss {
    match e {
        AppError::Refused { reason } => FetchMiss::Refused(reason),
        AppError::Nacked {
            reason: Some(ndn_packet::NackReason::NoRoute),
        } => FetchMiss::Absent,
        _ => FetchMiss::Unanswered,
    }
}

/// A [`FetchFn`] that expresses each cert Interest on `demux` — a
/// [`Node`](crate::Node)'s ([`Node::demux`](crate::Node::demux)), or
/// [`DemuxConnection::new`] over any [`Connection`] — so concurrent fetches
/// share it and each gets the reply (Data or Nack) to its own Interest.
///
/// The Interest names a key (or one certificate) and carries `CanBePrefix`,
/// so it is answered by a certificate `<key>/<issuer-id>/<version>` (NDN
/// Certificate Format v2), and `MustBeFresh`, so a content store holding a
/// stale copy of an older certificate of the key does not answer it — after a
/// renewal the new certificate comes from its producer.
pub fn demux_fetch_fn(demux: Arc<DemuxConnection>) -> FetchFn {
    let conn: Arc<dyn Connection> = demux;
    Arc::new(move |name: Name| {
        let mut consumer = Consumer::new(Arc::clone(&conn));
        Box::pin(async move {
            let wire = cert_interest(name).build();
            consumer
                .fetch_wire(wire, CERT_FETCH_TIMEOUT)
                .await
                .map_err(miss)
        })
    })
}

/// A [`CertFetcher`] over `demux` (see [`demux_fetch_fn`]) that fills
/// `cache` (normally the cache of the validator it will be attached to) —
/// for an app on a forwarder connection, such as a [`Node`](crate::Node)'s.
pub fn demux_cert_fetcher(demux: Arc<DemuxConnection>, cache: Arc<CertCache>) -> Arc<CertFetcher> {
    Arc::new(CertFetcher::new(
        cache,
        demux_fetch_fn(demux),
        CERT_FETCH_TIMEOUT,
    ))
}

/// A [`FetchFn`] that expresses each cert Interest through `engine` on one
/// in-process app face (tied to `cancel`): [`demux_fetch_fn`] over it.
pub fn engine_fetch_fn(engine: &ForwarderEngine, cancel: CancellationToken) -> FetchFn {
    demux_fetch_fn(DemuxConnection::new(engine.app_face(cancel)))
}

/// A [`DirectFetchFn`]: the same cert Interest, expressed through `engine`
/// out of one given face (NDNLPv2 `NextHopFaceId`, bypassing the FIB) — the
/// face the Data being validated arrived on, whose producer serves its own
/// issuer chain. The in-process face it is sent from opts into LocalFields,
/// without which the forwarder ignores `NextHopFaceId`. A face the FIB
/// already routes the name to is not asked again
/// ([`FetchMiss::NotAsked`]): the routed fetch went there.
pub fn engine_direct_fetch_fn(
    engine: &ForwarderEngine,
    cancel: CancellationToken,
) -> DirectFetchFn {
    let face_id = engine.faces().alloc_id();
    let (face, handle) = InProcFace::new(face_id, DIRECT_FACE_BUFFER);
    engine.add_face(face, cancel);
    engine.set_local_fields(face_id, true);
    let conn: Arc<dyn Connection> = DemuxConnection::new(Arc::new(InProcConnection::new(handle)));
    let fib = engine.fib();
    Arc::new(move |name: Name, face: u64| {
        let face = FaceId(face);
        let routed_there = fib
            .lpm(&name)
            .is_some_and(|entry| entry.nexthops.iter().any(|hop| hop.face_id == face));
        let mut consumer = Consumer::new(Arc::clone(&conn));
        Box::pin(async move {
            if routed_there {
                return Err(FetchMiss::NotAsked);
            }
            consumer
                .fetch_with_on(face, cert_interest(name))
                .await
                .map_err(miss)
        })
    })
}

/// A [`CertFetcher`] over `engine` that fills `cache` (normally the cache of
/// the validator it will be attached to).
pub fn engine_cert_fetcher(
    engine: &ForwarderEngine,
    cache: Arc<CertCache>,
    cancel: CancellationToken,
) -> Arc<CertFetcher> {
    Arc::new(
        CertFetcher::new(
            cache,
            engine_fetch_fn(engine, cancel.clone()),
            CERT_FETCH_TIMEOUT,
        )
        .with_direct_fetch(engine_direct_fetch_fn(engine, cancel)),
    )
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
