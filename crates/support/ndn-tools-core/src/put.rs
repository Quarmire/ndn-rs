//! Embeddable NDN put tool logic — publish a chunked object as named Data segments.
//!
//! Always uses ndn-cxx compatible naming:
//! Segments are served under `/<prefix>/v=<µs-timestamp>/<seg>` using
//! VersionNameComponent (TLV 0x36) and SegmentNameComponent (TLV 0x32).
//! Compatible with `ndnpeekdata --pipeline` and `ndngetfile` consumers.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use bytes::Bytes;
use tokio::sync::mpsc;

use ndn_app::KeyChain;
use ndn_ipc::ForwarderClient;
use ndn_ipc::chunked::{ChunkedProducer, NDN_DEFAULT_SEGMENT_SIZE};
use ndn_packet::encode::DataBuilder;
use ndn_packet::{Interest, Name, NameComponent};
use ndn_security::Signer;

use crate::common::{ConnectConfig, ToolEvent};

// ── Parameter type ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PutParams {
    pub conn: ConnectConfig,
    /// Base name prefix. Segments will be served under `/<prefix>/v=<ts>/<seg>`.
    pub name: String,
    /// Content to publish (already in memory).
    pub data: Bytes,
    /// Segment size in bytes.
    pub chunk_size: usize,
    /// Sign each Data segment with Ed25519.
    pub sign: bool,
    /// Sign each Data segment with HMAC-SHA256.
    pub hmac: bool,
    /// Data freshness period in milliseconds (0 = omit).
    pub freshness_ms: u64,
    /// Stop serving after this many seconds (0 = serve until cancelled/disconnected).
    pub timeout_secs: u64,
    /// Suppress per-Interest log lines.
    pub quiet: bool,
}

impl PutParams {
    pub fn chunk_size_or_default(mut self) -> Self {
        if self.chunk_size == 0 {
            self.chunk_size = NDN_DEFAULT_SEGMENT_SIZE;
        }
        self
    }
}

// ── Run ───────────────────────────────────────────────────────────────────────

/// Publish `params.data` as segmented ndn-cxx compatible Data.
///
/// Registers the base name, creates a versioned prefix, and responds to every
/// incoming Interest for that prefix until cancelled or the timeout is reached.
/// Emits [`ToolEvent`]s to `tx` as Interests are served.
pub async fn run_producer(params: PutParams, tx: mpsc::Sender<ToolEvent>) -> Result<()> {
    let name: Name = params.name.parse().map_err(|e| anyhow::anyhow!("{e}"))?;
    let total_bytes = params.data.len();
    let chunk_size = if params.chunk_size == 0 {
        NDN_DEFAULT_SEGMENT_SIZE
    } else {
        params.chunk_size
    };
    let producer = Arc::new(ChunkedProducer::new(name.clone(), params.data, chunk_size));
    let seg_count = producer.segment_count();
    let last_seg = seg_count.saturating_sub(1);

    // Build the versioned prefix: /<name>/v=<µs-timestamp>
    let ts_us = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0);
    let served_prefix = name.clone().append_component(NameComponent::version(ts_us));

    // Size the SHM ring for the largest Data we'll emit: chunk_size
    // plus signature/name overhead (handled inside the SHM face). Let
    // the caller override via ConnectConfig.mtu; otherwise derive from
    // chunk_size so producers emitting large segments don't silently
    // exceed the default ~266 KiB slot.
    let mtu_hint = params.conn.mtu.or(Some(chunk_size));
    let client = if params.conn.use_shm {
        ForwarderClient::connect_with_mtu(&params.conn.face_socket, mtu_hint).await?
    } else {
        ForwarderClient::connect_unix_only(&params.conn.face_socket).await?
    };
    // Register the base name so the router delivers Interests for any version.
    client.register_prefix(&name).await?;

    let transport = if client.is_shm() { "SHM" } else { "Unix" };
    let _ = tx.send(ToolEvent::info(format!(
        "ndn-put: registered {name}  [{transport}]  (ndn-cxx mode, serving under {served_prefix})"
    ))).await;
    let _ = tx
        .send(ToolEvent::info(format!(
            "ndn-put: {total_bytes} bytes → {seg_count} segment(s) of {chunk_size} B"
        )))
        .await;

    let signer: Option<Arc<dyn Signer>> = if params.sign {
        let keychain = KeyChain::ephemeral(name.to_string().as_str())?;
        let s = keychain.signer()?;
        let _ = tx
            .send(ToolEvent::info(format!(
                "ndn-put: signing with {} ({:?})",
                s.key_name(),
                s.sig_type()
            )))
            .await;
        Some(s)
    } else if params.hmac {
        let key_name = Name::from_components([
            NameComponent::generic(Bytes::from_static(b"ndn-put")),
            NameComponent::generic(Bytes::from_static(b"hmac-key")),
        ]);
        Some(Arc::new(ndn_security::HmacSha256Signer::new(
            b"ndn-put-bench-key",
            key_name,
        )))
    } else {
        None
    };

    let freshness = (params.freshness_ms > 0).then(|| Duration::from_millis(params.freshness_ms));

    let _ = tx
        .send(ToolEvent::info(
            "ndn-put: waiting for Interests... (Ctrl-C to stop)",
        ))
        .await;

    let start = Instant::now();
    let deadline =
        (params.timeout_secs > 0).then(|| start + Duration::from_secs(params.timeout_secs));

    let mut served: u64 = 0;
    let mut unknown: u64 = 0;

    loop {
        if tx.is_closed() {
            break;
        }

        if let Some(dl) = deadline
            && Instant::now() >= dl
        {
            let _ = tx
                .send(ToolEvent::info("ndn-put: timeout reached, shutting down"))
                .await;
            break;
        }

        let raw = match client.recv().await {
            Some(b) => b,
            None => {
                let _ = tx
                    .send(ToolEvent::info(format!(
                        "ndn-put: connection closed after {served} Interests served"
                    )))
                    .await;
                break;
            }
        };

        let interest = match Interest::decode(raw) {
            Ok(i) => i,
            Err(_) => continue,
        };

        // Extract SegmentNameComponent (TLV 0x32) from the last name component.
        let last_is_seg = interest
            .name
            .components()
            .last()
            .and_then(|c| c.as_segment());

        let seg_idx: usize = match last_is_seg {
            Some(i) if (i as usize) < seg_count => i as usize,
            Some(_) => {
                // Segment number out of range — skip.
                unknown += 1;
                if !params.quiet {
                    let _ = tx
                        .send(ToolEvent::info(format!(
                            "ndn-put: segment out of range: {}",
                            interest.name
                        )))
                        .await;
                }
                continue;
            }
            None => {
                // CanBePrefix discovery Interest (no SegmentNameComponent).
                // Respond with segment 0 under the versioned prefix — compatible
                // with ndn-cxx ndnputchunks behaviour and with `ndn-peek --can-be-prefix`.
                0
            }
        };

        let seg_bytes = match producer.segment(seg_idx) {
            Some(b) => b,
            None => continue,
        };

        // Build the Data name.  For explicit-segment Interests use the Interest
        // name as-is.  For CanBePrefix discovery Interests (no SegmentNameComponent
        // in the name) append segment 0 under the versioned prefix, matching
        // ndn-cxx ndnputchunks behaviour.  NDNts get-segmented --ver=cbp then
        // finds the VersionNameComponent at name[-2] (before the segment).
        let data_name = if last_is_seg.is_some() {
            (*interest.name).clone()
        } else {
            served_prefix.clone().append_segment(seg_idx as u64)
        };
        let data_name_str = data_name.to_string();

        let mut builder =
            DataBuilder::new(data_name, seg_bytes).final_block_id_typed_seg(last_seg as u64);
        if let Some(f) = freshness {
            builder = builder.freshness(f);
        }

        let data_wire = if let Some(ref signer) = signer {
            let sig_type = signer.sig_type();
            let key_name = signer.key_name().clone();
            builder.sign_sync(sig_type, Some(&key_name), |region| {
                signer.sign_sync(region).expect("signing failed")
            })
        } else {
            builder.sign_digest_sha256()
        };

        if let Err(e) = client.send(data_wire).await {
            let _ = tx
                .send(ToolEvent::error(format!("ndn-put: send error: {e}")))
                .await;
            break;
        }
        served += 1;
        if !params.quiet {
            let _ = tx
                .send(ToolEvent::info(format!(
                    "ndn-put: served segment {seg_idx}/{last_seg}  {}",
                    data_name_str
                )))
                .await;
        }
    }

    let elapsed = start.elapsed();
    let _ = tx.send(ToolEvent::summary(String::new())).await;
    let _ = tx.send(ToolEvent::summary("--- ndn-put summary ---")).await;
    let _ = tx
        .send(ToolEvent::summary(format!(
            "  uptime:   {:.1}s",
            elapsed.as_secs_f64()
        )))
        .await;
    let _ = tx
        .send(ToolEvent::summary(format!("  served:   {served}")))
        .await;
    if unknown > 0 {
        let _ = tx
            .send(ToolEvent::summary(format!("  unknown:  {unknown}")))
            .await;
    }

    Ok(())
}
