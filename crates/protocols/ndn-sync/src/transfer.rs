//! Shared segmented transfer for SVS and PSync: split a blob into
//! `…/seg=i` Data carrying a `FinalBlockId`, and fetch a segment range
//! through a windowed, transport-agnostic pipeline.
//!
//! Both sync protocols emit replies/publications that can exceed an MTU
//! (a large SVS-PS blob; a PSync full-state dump). The producer side uses
//! `segment_blob` to chunk + name + finalize; the consumer side uses
//! `windowed_fetch` over an `Express` closure the caller supplies
//! (SVS wires it to its data-plane correlator, PSync to its own). The
//! `mpsc<Bytes>` boundary stays the caller's, so this runs natively, in
//! the browser, or against real faces.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use ndn_packet::{Data, Name};
use tokio::sync::{Semaphore, mpsc};

use crate::rt;

/// A spawnable "express one Interest, return its Data wire" future.
#[cfg(not(target_arch = "wasm32"))]
pub type ExpressFut = Pin<Box<dyn Future<Output = Option<Bytes>> + Send>>;
// wasm32 is single-threaded; gloo timers are !Send, so drop the Send bound.
#[cfg(target_arch = "wasm32")]
pub type ExpressFut = Pin<Box<dyn Future<Output = Option<Bytes>>>>;

/// Caller-supplied fetch primitive: given a segment name, return the Data
/// wire (or `None` on timeout/failure). The caller owns retry/correlation.
#[cfg(not(target_arch = "wasm32"))]
pub type Express = Arc<dyn Fn(Name) -> ExpressFut + Send + Sync>;
#[cfg(target_arch = "wasm32")]
pub type Express = Arc<dyn Fn(Name) -> ExpressFut>;

/// The `FinalBlockId` segment number of a Data, if it carries one.
pub fn final_block_segment(data: &Data) -> Option<u64> {
    data.meta_info()
        .and_then(|m| m.final_block_component())
        .and_then(|r| r.ok())
        .and_then(|c| c.as_segment())
}

/// Upper bound on segments a consumer will fetch from a peer-advertised
/// `FinalBlockId` (audit PSYNC-3). A malicious or buggy producer advertising a
/// huge `FinalBlockId` would otherwise drive the consumer to issue up to ~2⁶⁴
/// segment Interests. ~1M segments (≈ multi-GiB objects at typical chunk sizes)
/// is far above any legitimate sync publication.
pub const MAX_FETCH_SEGMENTS: u64 = 1 << 20;

/// Like [`final_block_segment`] but clamped to [`MAX_FETCH_SEGMENTS`], for the
/// consumer fetch-loop bound.
pub fn final_block_segment_clamped(data: &Data) -> Option<u64> {
    final_block_segment(data).map(|last| last.min(MAX_FETCH_SEGMENTS))
}

/// Split `content` into ≤ `max_segment`-byte chunks named `base/seg=i`,
/// each stamped with the last segment as `FinalBlockId` via `build`. The
/// caller's `build(name, chunk, last_seg)` controls content-type +
/// signing and returns the segment's Data wire. Always yields at least
/// one segment (`seg=0`), even for empty `content`.
pub fn segment_blob<F>(
    base: &Name,
    content: &[u8],
    max_segment: usize,
    build: F,
) -> Vec<(Name, Bytes)>
where
    F: Fn(&Name, &[u8], u64) -> Bytes,
{
    let max = max_segment.max(1);
    let chunks: Vec<&[u8]> = if content.is_empty() {
        vec![&[][..]]
    } else {
        content.chunks(max).collect()
    };
    let last = (chunks.len() - 1) as u64;
    chunks
        .iter()
        .enumerate()
        .map(|(i, chunk)| {
            let name = base.clone().append_segment(i as u64);
            let wire = build(&name, chunk, last);
            (name, wire)
        })
        .collect()
}

/// Fetch `base/seg=lo ..= hi` with up to `window` Interests in flight,
/// returning each segment's Data **content** in segment order (`None` =
/// that segment couldn't be fetched). Concurrency is bounded by a
/// semaphore — pass 100 segments and only `window` run at once.
pub async fn windowed_fetch(
    base: &Name,
    lo: u64,
    hi: u64,
    window: usize,
    express: Express,
) -> Vec<Option<Bytes>> {
    if hi < lo {
        return Vec::new();
    }
    let sem = Arc::new(Semaphore::new(window.max(1)));
    let (tx, mut rx) = mpsc::channel::<(u64, Option<Bytes>)>((hi - lo + 1) as usize);
    for s in lo..=hi {
        // Acquire before spawning → at most `window` in flight.
        let permit = Arc::clone(&sem).acquire_owned().await.expect("semaphore");
        let name = base.clone().append_segment(s);
        let express = Arc::clone(&express);
        let tx = tx.clone();
        rt::spawn(async move {
            let _permit = permit;
            let content = express(name).await.and_then(|wire| {
                Data::decode(wire)
                    .ok()
                    .map(|d| d.content().cloned().unwrap_or_default())
            });
            let _ = tx.send((s, content)).await;
        });
    }
    drop(tx);
    let mut out: Vec<(u64, Option<Bytes>)> = Vec::new();
    while let Some(item) = rx.recv().await {
        out.push(item);
    }
    out.sort_by_key(|(s, _)| *s);
    out.into_iter().map(|(_, p)| p).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_packet::encode::DataBuilder;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    #[test]
    fn segment_blob_chunks_and_finalizes() {
        let base = n("/a/b");
        let content: Vec<u8> = (0..25u8).collect();
        let segs = segment_blob(&base, &content, 10, |name, chunk, last| {
            DataBuilder::new(name.clone(), chunk)
                .final_block_id_typed_seg(last)
                .build()
        });
        assert_eq!(segs.len(), 3, "25 bytes / 10 → 3 segments");
        assert_eq!(segs[0].0, base.clone().append_segment(0));
        assert_eq!(segs[2].0, base.clone().append_segment(2));
        // Reassembled content matches; FinalBlockId = seg=2 on each.
        let mut reassembled = Vec::new();
        for (_, wire) in &segs {
            let d = Data::decode(wire.clone()).unwrap();
            assert_eq!(final_block_segment(&d), Some(2));
            reassembled.extend_from_slice(d.content().unwrap());
        }
        assert_eq!(reassembled, content);
    }

    #[test]
    fn segment_blob_empty_yields_one_segment() {
        let segs = segment_blob(&n("/x"), &[], 100, |name, chunk, last| {
            DataBuilder::new(name.clone(), chunk)
                .final_block_id_typed_seg(last)
                .build()
        });
        assert_eq!(segs.len(), 1);
    }

    #[tokio::test]
    async fn windowed_fetch_orders_and_handles_misses() {
        let base = n("/svc/5");
        // express returns a Data for even segments, None for odd.
        let express: Express = Arc::new(|name: Name| {
            Box::pin(async move {
                let seg = name.components().last().unwrap().as_segment().unwrap();
                if seg.is_multiple_of(2) {
                    Some(DataBuilder::new(name, format!("seg{seg}").as_bytes()).build())
                } else {
                    None
                }
            })
        });
        let out = windowed_fetch(&base, 0, 3, 4, express).await;
        assert_eq!(out.len(), 4);
        assert_eq!(out[0].as_deref(), Some(&b"seg0"[..]));
        assert!(out[1].is_none());
        assert_eq!(out[2].as_deref(), Some(&b"seg2"[..]));
        assert!(out[3].is_none());
    }
}
