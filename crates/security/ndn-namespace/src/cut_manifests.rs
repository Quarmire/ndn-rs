//! Keeping and serving the cut manifests of the trust contexts a device
//! keeps.
//!
//! A revocation cut with ranges names its manifest by the full name of its
//! root packet (CutManifest): a self-certifying tree of Data
//! (`<ns>/32=trust-context/32=cut/<h>/seg=<i>`, DigestSha256) listing the
//! sequence number and implicit digest of every entry the ranges accept. A
//! reader accepts an in-range packet only if the manifest lists its exact
//! bytes, so the manifest must be reachable wherever the context is: every
//! device that keeps a namespace's contexts keeps and serves the manifest
//! packets of every cut they hold, beside the versions
//! ([`crate::publish::PublishedContexts::publish_cut_manifests`]).
//!
//! When a version is kept ([`crate::keep`]), the packets the store holds
//! already (the root device stores those of the cut file it signed before
//! handing the version over) are served at once; the missing ones are
//! fetched by full name through the engine, from the forwarders that serve
//! the namespace (not from this device's own publisher), each checked
//! against the digest that names it, then stored and served. A fetch that
//! fails is tried again a few times; a reader that needs a packet not held
//! here fetches it like a missing certificate in any case.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_app::EngineAppExt;
use ndn_engine::ForwarderEngine;
use ndn_packet::Name;
use ndn_security::SignedTrustContext;
use ndn_security::cut_manifest::CutManifests;
use tokio_util::sync::CancellationToken;

use crate::ContextStore;
use crate::publish::PublishedContexts;

/// At most this many manifest packets are held for one cut: a manifest
/// listing more entries than any device log holds is refused rather than
/// kept.
pub const MAX_MANIFEST_PACKETS: usize = 4096;

/// How many times the missing packets of a version's cuts are asked for
/// before the device gives up until the next version is kept.
const ATTEMPTS: u32 = 5;
/// The wait before the first retry, doubled each time.
const FIRST_RETRY: Duration = Duration::from_secs(2);

/// What a device keeps of the manifests of one version's cuts.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct KeptManifests {
    /// Packets fetched and stored now.
    pub fetched: usize,
    /// Manifest packets (full names) still missing, with why.
    pub missing: Vec<(Name, String)>,
}

/// Serve the manifest packets of `ctx`'s cuts that `store` holds, and fetch,
/// store and serve the missing ones through `engine`, in the background
/// when a runtime runs (else only the stored ones are served).
pub(crate) fn keep(
    engine: &ForwarderEngine,
    store: &Arc<dyn ContextStore>,
    publisher: Option<&PublishedContexts>,
    ctx: &SignedTrustContext,
) {
    if roots(ctx).is_empty() {
        return;
    }
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        serve_stored(store.as_ref(), publisher, ctx);
        return;
    };
    // The task works on its own copy of the version.
    let Ok(ctx) = SignedTrustContext::decode_content(&ctx.encode_content(), ctx.version()) else {
        serve_stored(store.as_ref(), publisher, ctx);
        return;
    };
    let (engine, store, publisher) = (engine.clone(), Arc::clone(store), publisher.cloned());
    runtime.spawn(async move {
        let mut wait = FIRST_RETRY;
        for attempt in 1..=ATTEMPTS {
            let kept = fetch_missing(&engine, store.as_ref(), publisher.as_ref(), &ctx).await;
            if kept.missing.is_empty() {
                return;
            }
            let missing: Vec<String> = kept
                .missing
                .iter()
                .map(|(name, why)| format!("{name} ({why})"))
                .collect();
            tracing::warn!(
                target: "security",
                namespace = %ctx.namespace(),
                version = ctx.version(),
                attempt,
                missing = %missing.join(", "),
                "cut manifest packets not held yet; readers fetch them from other nodes"
            );
            tokio::time::sleep(wait).await;
            wait *= 2;
        }
    });
}

/// The full names of the manifest root packets `ctx`'s cuts name.
fn roots(ctx: &SignedTrustContext) -> Vec<Name> {
    ctx.revocation_cuts()
        .iter()
        .filter_map(|c| c.manifest().cloned())
        .collect()
}

/// The manifest packets of `ctx`'s namespace `store` holds, served by
/// `publisher`; returns them as a set to walk.
fn serve_stored(
    store: &dyn ContextStore,
    publisher: Option<&PublishedContexts>,
    ctx: &SignedTrustContext,
) -> CutManifests {
    let namespace = ctx.namespace();
    let stored = store.stored_cut_manifests(namespace).unwrap_or_else(|e| {
        tracing::warn!(
            target: "security",
            namespace = %namespace,
            error = %e,
            "cannot read the stored cut manifest packets"
        );
        Vec::new()
    });
    let held = CutManifests::new(MAX_MANIFEST_PACKETS * roots(ctx).len().max(1));
    let mut served: Vec<Bytes> = Vec::with_capacity(stored.len());
    for wire in stored {
        let Ok(data) = ndn_packet::Data::decode(wire.clone()) else {
            continue;
        };
        if held.insert(&data).is_ok() {
            served.push(wire);
        }
    }
    if let Some(publisher) = publisher {
        publisher.publish_cut_manifests(namespace, &served);
    }
    held
}

/// Serve the stored manifest packets of `ctx`'s cuts, then fetch every
/// missing one by full name through `engine` — not from this device's own
/// publisher — checking each against the digest that names it, store it in
/// `store` and serve it, until every manifest is whole or a fetch fails.
pub async fn fetch_missing(
    engine: &ForwarderEngine,
    store: &dyn ContextStore,
    publisher: Option<&PublishedContexts>,
    ctx: &SignedTrustContext,
) -> KeptManifests {
    let namespace = ctx.namespace();
    let held = serve_stored(store, publisher, ctx);
    let mut kept = KeptManifests::default();
    let mut wanted: Vec<Name> = roots(ctx)
        .iter()
        .flat_map(|root| held.missing(root))
        .collect();
    if wanted.is_empty() {
        return kept;
    }
    let _bypass = publisher.map(|p| p.bypass(namespace));
    let cancel = CancellationToken::new();
    let _face = cancel.clone().drop_guard();
    let mut consumer = engine.app_consumer(cancel);
    while let Some(full) = wanted.pop() {
        let Some((_, digest)) = ndn_cert::split_full_name(&full) else {
            kept.missing
                .push((full, "not a full name ending in a digest".to_owned()));
            continue;
        };
        let data = match consumer.fetch(full.clone()).await {
            Ok(data) => data,
            Err(e) => {
                kept.missing.push((full, e.to_string()));
                continue;
            }
        };
        if data.implicit_digest() != digest {
            kept.missing.push((
                full,
                "the answer's bytes do not hash to its name".to_owned(),
            ));
            continue;
        }
        if let Err(e) = held.insert(&data) {
            kept.missing.push((full, e.to_string()));
            continue;
        }
        let wire = data.raw().clone();
        if let Err(e) = store.persist_cut_manifest(namespace, &wire) {
            tracing::warn!(
                target: "security",
                packet = %full,
                error = %e,
                "cut manifest packet served but not stored"
            );
        }
        if let Some(publisher) = publisher {
            publisher.publish_cut_manifests(namespace, std::slice::from_ref(&wire));
        }
        kept.fetched += 1;
        // Its children, if it is an inner node.
        for root in roots(ctx) {
            for name in held.missing(&root) {
                if !wanted.contains(&name) && !kept.missing.iter().any(|(m, _)| *m == name) {
                    wanted.push(name);
                }
            }
        }
    }
    kept
}
