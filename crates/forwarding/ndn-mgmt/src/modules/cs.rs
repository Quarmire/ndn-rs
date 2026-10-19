//! `/localhost/nfd/cs/{config, info, erase, list}` — content store.

use async_trait::async_trait;
use ndn_engine::ForwarderEngine;
use ndn_mgmt_wire::{
    ControlParameters, ControlResponse, CsEntry, CsListing,
    control_response::status,
    nfd_command::{module, verb},
};
use ndn_packet::Name;

use crate::MgmtResponse;
use crate::module::{MgmtContext, MgmtModule};
use crate::wire::MAX_DATASET_PAYLOAD_LEN;

async fn handle_cs(
    verb_name: &[u8],
    params: ControlParameters,
    engine: &ForwarderEngine,
) -> MgmtResponse {
    match verb_name {
        v if v == verb::CONFIG => cs_config(params, engine).into(),
        v if v == verb::INFO => cs_info(engine).into(),
        v if v == verb::ERASE => cs_erase(params, engine).await.into(),
        v if v == verb::LIST => MgmtResponse::Dataset(cs_list_dataset(params, engine).await),
        _ => ControlResponse::error(status::NOT_FOUND, "unknown cs verb").into(),
    }
}

/// `cs/list` lists this many entries when the command carries no Count.
const CS_LIST_DEFAULT_COUNT: u64 = 100;

/// `cs/list`: the entries the CS holds under the Name parameter (absent: all
/// of them), the first Count (default [`CS_LIST_DEFAULT_COUNT`]) in canonical
/// name order, each judged fresh at the engine's now, and the total held
/// there. The answer fits one dataset segment — clients read only the first
/// — so it may list fewer than Count; the total still counts every entry.
async fn cs_list_dataset(params: ControlParameters, engine: &ForwarderEngine) -> bytes::Bytes {
    let prefix = params.name.unwrap_or_else(Name::root);
    let limit = params.count.unwrap_or(CS_LIST_DEFAULT_COUNT);
    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
    let now_ns = engine.runtime().unix_nanos();
    let held = engine.cs().list_erased(&prefix, limit, now_ns).await;
    let listing = CsListing {
        entries: held
            .entries
            .into_iter()
            .map(|e| CsEntry {
                name: (*e.name).clone(),
                bytes: e.bytes as u64,
                fresh: e.fresh,
            })
            .collect(),
        total: held.total as u64,
    };
    listing.encode_within(MAX_DATASET_PAYLOAD_LEN)
}

// NFD `CsFlagBit` (ndn-cxx nfd-constants.hpp): admit gates insertion, serve
// gates satisfying Interests from cache.
const BIT_CS_ENABLE_ADMIT: u64 = 1 << 0;
const BIT_CS_ENABLE_SERVE: u64 = 1 << 1;

fn cs_config(params: ControlParameters, engine: &ForwarderEngine) -> ControlResponse {
    let cs = engine.cs();

    if let Some(new_cap) = params.capacity {
        cs.set_capacity(new_cap as usize);
        tracing::info!(target: "mgmt.cs", capacity = new_cap, "cs capacity updated");
    }

    // Admit/Serve flags, Flags+Mask shaped like faces/update (NFD CsManager).
    if let (Some(flags), Some(mask)) = (params.flags, params.mask) {
        if mask & BIT_CS_ENABLE_ADMIT != 0 {
            cs.set_admit(flags & BIT_CS_ENABLE_ADMIT != 0);
        }
        if mask & BIT_CS_ENABLE_SERVE != 0 {
            cs.set_serve(flags & BIT_CS_ENABLE_SERVE != 0);
        }
    }

    let cap = cs.capacity();
    let mut flags = 0u64;
    if cs.admit_enabled() {
        flags |= BIT_CS_ENABLE_ADMIT;
    }
    if cs.serve_enabled() {
        flags |= BIT_CS_ENABLE_SERVE;
    }
    let echo = ControlParameters {
        capacity: Some(cap.max_bytes as u64),
        flags: Some(flags),
        ..Default::default()
    };
    ControlResponse::ok("OK", echo)
}

fn cs_info(engine: &ForwarderEngine) -> ControlResponse {
    let cs = engine.cs();
    let cap = cs.capacity();
    let n_entries = cs.len();
    let current = cs.current_bytes();
    let stats = cs.stats();
    let variant = cs.variant_name();

    let text = format!(
        "capacity={}B entries={} used={}B hits={} misses={} variant={}",
        cap.max_bytes, n_entries, current, stats.hits, stats.misses, variant,
    );
    ControlResponse::ok_empty(text)
}

async fn cs_erase(params: ControlParameters, engine: &ForwarderEngine) -> ControlResponse {
    let Some(ref name) = params.name else {
        return ControlResponse::error(status::BAD_PARAMS, "missing Name parameter");
    };
    let cs = engine.cs();
    let limit = params.count.map(|c| c as usize);
    let erased = cs.evict_prefix_erased(name, limit).await;

    let echo = ControlParameters {
        name: params.name,
        count: Some(erased as u64),
        ..Default::default()
    };
    ControlResponse::ok("OK", echo)
}

pub(crate) struct CsModule;

#[async_trait]
impl MgmtModule for CsModule {
    fn name(&self) -> &'static [u8] {
        module::CS
    }

    async fn dispatch(
        &self,
        verb: &[u8],
        params: ControlParameters,
        ctx: &MgmtContext<'_>,
    ) -> MgmtResponse {
        handle_cs(verb, params, ctx.engine).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use ndn_engine::{EngineBuilder, EngineConfig};
    use ndn_store::CsMeta;
    use std::sync::Arc;

    async fn insert(engine: &ForwarderEngine, uri: &str, data: &'static [u8], fresh: bool) {
        let meta = CsMeta {
            stale_at: if fresh { u64::MAX } else { 0 },
            revocation_epoch: None,
        };
        engine
            .cs()
            .insert_erased(
                Bytes::from_static(data),
                Arc::new(uri.parse().unwrap()),
                meta,
            )
            .await;
    }

    async fn list(engine: &ForwarderEngine, params: ControlParameters) -> (usize, CsListing) {
        match handle_cs(verb::LIST, params, engine).await {
            MgmtResponse::Dataset(body) => (body.len(), CsListing::decode(&body)),
            _ => panic!("cs/list answers a dataset"),
        }
    }

    #[tokio::test]
    async fn list_answers_what_the_cs_holds_under_the_prefix() {
        let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
            .build()
            .await
            .unwrap();
        insert(&engine, "/a/3", b"ccc", true).await;
        insert(&engine, "/a/1", b"a", false).await;
        insert(&engine, "/a/2", b"bb", true).await;
        insert(&engine, "/b/1", b"d", true).await;

        let (_, capped) = list(
            &engine,
            ControlParameters {
                name: Some("/a".parse().unwrap()),
                count: Some(2),
                ..Default::default()
            },
        )
        .await;
        assert_eq!(capped.total, 3);
        let entry = |uri: &str, bytes: u64, fresh: bool| CsEntry {
            name: uri.parse().unwrap(),
            bytes,
            fresh,
        };
        assert_eq!(
            capped.entries,
            vec![entry("/a/1", 1, false), entry("/a/2", 2, true)]
        );

        let (_, all) = list(&engine, ControlParameters::default()).await;
        assert_eq!(all.total, 4, "no Name: the whole CS");
        assert_eq!(all.entries.len(), 4, "no Count: a default cap above 4");

        shutdown.shutdown().await;
    }

    #[tokio::test]
    async fn list_fits_one_dataset_segment_and_still_counts_everything() {
        let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
            .build()
            .await
            .unwrap();
        const HELD: usize = 400;
        for i in 0..HELD {
            let uri = format!("/many/{i:040}");
            engine
                .cs()
                .insert_erased(
                    Bytes::from_static(b"x"),
                    Arc::new(uri.parse().unwrap()),
                    CsMeta {
                        stale_at: u64::MAX,
                        revocation_epoch: None,
                    },
                )
                .await;
        }
        let (len, listing) = list(
            &engine,
            ControlParameters {
                count: Some(HELD as u64),
                ..Default::default()
            },
        )
        .await;
        assert!(len <= MAX_DATASET_PAYLOAD_LEN, "one segment: {len} bytes");
        assert_eq!(listing.total, HELD as u64);
        assert!(!listing.entries.is_empty() && listing.entries.len() < HELD);
        assert!(
            listing.entries.windows(2).all(|w| w[0].name < w[1].name),
            "the first ones in name order"
        );

        shutdown.shutdown().await;
    }
}
