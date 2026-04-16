//! Embeddable NDN peek tool logic — single and segmented fetch.
//!
//! Always uses ndn-cxx compatible naming:
//! - Segmented fetch sends the initial Interest with CanBePrefix, discovers the
//!   versioned prefix from the response, and fetches subsequent segments using
//!   SegmentNameComponent (TLV 0x32). Compatible with `ndnputchunks` producers.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use anyhow::Result;
use bytes::{Bytes, BytesMut};
use tokio::sync::mpsc;

use ndn_ipc::ForwarderClient;
use ndn_packet::encode::InterestBuilder;
use ndn_packet::{Data, Name};

use crate::common::{ConnectConfig, ToolData, ToolEvent};

// ── Parameter type ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PeekParams {
    pub conn: ConnectConfig,
    /// Name to fetch (or versioned prefix for segmented mode).
    pub name: String,
    /// Interest lifetime in milliseconds.
    pub lifetime_ms: u64,
    /// File path to write assembled content. `None` → emit as ToolEvent text.
    pub output: Option<String>,
    /// Segmented pipeline depth. `None` → single-packet fetch.
    pub pipeline: Option<usize>,
    /// Emit content as hex instead of UTF-8 text.
    pub hex: bool,
    /// Emit metadata only (name, content size, sig type).
    pub meta_only: bool,
    /// Emit per-segment progress events.
    pub verbose: bool,
    /// Set CanBePrefix on the Interest (single-fetch mode).
    pub can_be_prefix: bool,
}

// ── Single fetch ──────────────────────────────────────────────────────────────

async fn fetch_one(
    client: &ForwarderClient,
    name: &Name,
    lifetime: Duration,
    can_be_prefix: bool,
) -> Result<Data> {
    let mut b = InterestBuilder::new(name.clone()).lifetime(lifetime);
    if can_be_prefix {
        b = b.can_be_prefix();
    }
    client.send(b.build()).await?;
    let timeout = lifetime + Duration::from_millis(500);
    let raw = tokio::time::timeout(timeout, client.recv())
        .await
        .map_err(|_| anyhow::anyhow!("timeout waiting for {name}"))?
        .ok_or_else(|| anyhow::anyhow!("connection closed"))?;
    Data::decode(raw).map_err(|e| anyhow::anyhow!("decode: {e}"))
}

// ── Segmented fetch (ndn-cxx) ─────────────────────────────────────────────────

/// Segmented fetch using SegmentNameComponent (TLV 0x32), compatible with
/// ndnputchunks producers. Sends the initial Interest with CanBePrefix to
/// discover the versioned name, then fetches all segments.
async fn fetch_segmented(
    client: &ForwarderClient,
    prefix: &Name,
    pipeline: usize,
    lifetime: Duration,
    verbose: bool,
    tx: &mpsc::Sender<ToolEvent>,
) -> Result<Bytes> {
    // Discovery: CanBePrefix so we match any version.
    let wire = InterestBuilder::new(prefix.clone())
        .lifetime(lifetime)
        .can_be_prefix()
        .build();
    client.send(wire).await?;

    let timeout = lifetime + Duration::from_millis(500);
    let raw = tokio::time::timeout(timeout, client.recv())
        .await
        .map_err(|_| anyhow::anyhow!("timeout: no response from {prefix}"))?
        .ok_or_else(|| anyhow::anyhow!("connection closed"))?;
    let first = Data::decode(raw).map_err(|e| anyhow::anyhow!("decode: {e}"))?;

    if verbose {
        let _ = tx
            .send(ToolEvent::info(format!(
                "ndn-peek: discovered name: {}",
                first.name
            )))
            .await;
    }

    // The response name should end with a SegmentNameComponent (type 0x32).
    let comps = first.name.components();
    let versioned_prefix = if comps.last().map(|c| c.typ) == Some(ndn_packet::tlv_type::SEGMENT) {
        Name::from_components(comps[..comps.len() - 1].iter().cloned())
    } else {
        // Not a segmented response — treat as single packet.
        return Ok(first.content().cloned().unwrap_or_else(Bytes::new));
    };

    let seg0_idx = comps.last().and_then(|c| c.as_segment()).unwrap_or(0) as usize;

    let total_segs: usize = first
        .meta_info()
        .and_then(|mi| mi.final_block_id.as_ref())
        .and_then(|fb| decode_final_block_id_segment(fb))
        .map(|last| last + 1)
        .unwrap_or(1);

    if verbose {
        let _ = tx
            .send(ToolEvent::info(format!(
                "ndn-peek: versioned prefix: {versioned_prefix}  total segments: {total_segs}"
            )))
            .await;
        let _ = tx
            .send(
                ToolEvent::info(format!("ndn-peek: {total_segs} segment(s) to fetch")).with_data(
                    ToolData::FetchProgress {
                        received: 1,
                        total: total_segs,
                    },
                ),
            )
            .await;
    }

    let seg0_content = first.content().cloned().unwrap_or_else(Bytes::new);
    if total_segs == 1 {
        return Ok(seg0_content);
    }

    let make_interest = |seg: usize| {
        let name = versioned_prefix.clone().append_segment(seg as u64);
        InterestBuilder::new(name).lifetime(lifetime).build()
    };

    let mut segments: Vec<Option<Bytes>> = vec![None; total_segs];
    segments[seg0_idx] = Some(seg0_content);
    let mut in_flight: HashMap<u64, (usize, Instant)> = HashMap::new();
    let mut next_seg: usize = if seg0_idx == 0 { 1 } else { 0 };
    let mut received: usize = 1;
    let mut seq: u64 = 0;

    loop {
        // Fill the pipeline window. When multiple slots are open (the
        // common case at window-fill time and after processing a burst
        // of Data responses), batch them into a single SHM ring
        // transition. For the steady-state single-slot refill (one Data
        // in → one Interest out), skip the Vec allocation overhead and
        // send directly. This avoids the regression observed in small-
        // segment cells where 98% of sends are single-Interest refills
        // and the batch path's Vec alloc was more expensive than the old
        // per-send() call.
        {
            let mut batch: Vec<(usize, Bytes)> = Vec::new();
            while in_flight.len() + batch.len() < pipeline && next_seg < total_segs {
                if next_seg == seg0_idx {
                    next_seg += 1;
                    continue;
                }
                batch.push((next_seg, make_interest(next_seg)));
                next_seg += 1;
            }
            let now = Instant::now();
            if batch.len() > 1 {
                let wires: Vec<Bytes> = batch.iter().map(|(_, w)| w.clone()).collect();
                client.send_batch(&wires).await?;
            } else if batch.len() == 1 {
                client.send(batch[0].1.clone()).await?;
            }
            for (seg, _) in batch {
                in_flight.insert(seq, (seg, now));
                seq += 1;
            }
        }
        if received == total_segs {
            break;
        }

        let drain = lifetime + Duration::from_millis(500);
        match tokio::time::timeout(drain, client.recv()).await {
            Ok(Some(raw)) => {
                if let Ok(data) = Data::decode(raw) {
                    let seg_idx = data
                        .name
                        .components()
                        .last()
                        .and_then(|c| c.as_segment())
                        .map(|s| s as usize);
                    if let Some(idx) = seg_idx.filter(|&i| i < total_segs && segments[i].is_none())
                    {
                        segments[idx] = Some(data.content().cloned().unwrap_or_else(Bytes::new));
                        received += 1;
                        if verbose {
                            let _ = tx
                                .send(
                                    ToolEvent::info(format!(
                                        "ndn-peek: {received}/{total_segs} segments"
                                    ))
                                    .with_data(
                                        ToolData::FetchProgress {
                                            received,
                                            total: total_segs,
                                        },
                                    ),
                                )
                                .await;
                        }
                        in_flight.retain(|_, (s, _)| *s != idx);
                    }
                }
            }
            Ok(None) => anyhow::bail!("connection closed during segmented fetch"),
            Err(_) => {
                let stale: Vec<(usize, u64)> = in_flight
                    .iter()
                    .filter(|(_, (_, t0))| t0.elapsed() >= lifetime)
                    .map(|(&sq, &(idx, _))| (idx, sq))
                    .collect();
                if !stale.is_empty() {
                    let now = Instant::now();
                    let wires: Vec<Bytes> =
                        stale.iter().map(|&(idx, _)| make_interest(idx)).collect();
                    for (_, old_seq) in &stale {
                        in_flight.remove(old_seq);
                    }
                    client.send_batch(&wires).await?;
                    for (idx, _) in stale {
                        in_flight.insert(seq, (idx, now));
                        seq += 1;
                    }
                }
            }
        }
    }

    reassemble(segments)
}

/// Decode FinalBlockId as a SegmentNameComponent (TLV 0x32, big-endian integer).
fn decode_final_block_id_segment(fb: &[u8]) -> Option<usize> {
    if fb.len() < 2 {
        return None;
    }
    // Expect TLV type 0x32 (SegmentNameComponent).
    if fb[0] != 0x32 {
        return None;
    }
    let len = fb[1] as usize;
    if fb.len() < 2 + len {
        return None;
    }
    let value = &fb[2..2 + len];
    let mut n = 0usize;
    for &b in value {
        n = n.checked_shl(8)?.checked_add(b as usize)?;
    }
    Some(n)
}

fn reassemble(segments: Vec<Option<Bytes>>) -> Result<Bytes> {
    let total: usize = segments
        .iter()
        .filter_map(|s| s.as_ref())
        .map(|s| s.len())
        .sum();
    let mut out = BytesMut::with_capacity(total);
    for seg in &segments {
        match seg {
            Some(b) => out.extend_from_slice(b),
            None => anyhow::bail!("incomplete transfer: missing segment(s)"),
        }
    }
    Ok(out.freeze())
}

// ── Main entry points ─────────────────────────────────────────────────────────

/// Fetch a named Data packet (single) or segmented object, emitting events to `tx`.
pub async fn run_peek(params: PeekParams, tx: mpsc::Sender<ToolEvent>) -> Result<()> {
    let name = params
        .name
        .parse::<Name>()
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let lifetime = Duration::from_millis(params.lifetime_ms);
    let client = if params.conn.use_shm {
        ForwarderClient::connect_with_mtu(&params.conn.face_socket, params.conn.mtu).await?
    } else {
        ForwarderClient::connect_unix_only(&params.conn.face_socket).await?
    };

    let transport = if client.is_shm() { "SHM" } else { "Unix" };
    let _ = tx
        .send(ToolEvent::info(format!(
            "ndn-peek: fetching {name}  [{transport}]  lifetime={}ms",
            params.lifetime_ms
        )))
        .await;

    if let Some(pipeline) = params.pipeline {
        let pipeline = pipeline.max(1);
        let _ = tx
            .send(ToolEvent::info(format!(
                "ndn-peek: segmented pipeline={pipeline}  mode=ndn-cxx"
            )))
            .await;
        let t0 = Instant::now();
        let assembled =
            fetch_segmented(&client, &name, pipeline, lifetime, params.verbose, &tx).await?;
        let elapsed = t0.elapsed();
        let rate = if elapsed.as_secs_f64() > 0.0 {
            assembled.len() as f64 / elapsed.as_secs_f64() / 1024.0
        } else {
            0.0
        };
        let _ = tx
            .send(ToolEvent::info(format!(
                "ndn-peek: {} bytes in {:.2}s ({:.1} KB/s)",
                assembled.len(),
                elapsed.as_secs_f64(),
                rate
            )))
            .await;
        emit_content(&assembled, &name, &params, &tx).await?;
    } else {
        let data = fetch_one(&client, &name, lifetime, params.can_be_prefix).await?;
        if params.meta_only {
            emit_meta(&data, &tx).await;
        } else {
            let content = data.content().map(|b| b.as_ref()).unwrap_or(&[]);
            emit_content(content, &data.name, &params, &tx).await?;
        }
    }

    Ok(())
}

async fn emit_content(
    data: &[u8],
    name: &Name,
    params: &PeekParams,
    tx: &mpsc::Sender<ToolEvent>,
) -> Result<()> {
    let saved_to;
    if let Some(ref path) = params.output {
        tokio::fs::write(path, data).await?;
        let _ = tx
            .send(ToolEvent::info(format!(
                "ndn-peek: saved {} bytes to {path}",
                data.len()
            )))
            .await;
        saved_to = Some(path.clone());
    } else if params.hex {
        let hex: String = data.iter().map(|b| format!("{b:02x}")).collect();
        let _ = tx.send(ToolEvent::info(hex)).await;
        saved_to = None;
    } else {
        match std::str::from_utf8(data) {
            Ok(s) => {
                let _ = tx.send(ToolEvent::info(s.trim_end())).await;
            }
            Err(_) => {
                let _ = tx
                    .send(ToolEvent::warn(format!(
                        "ndn-peek: binary content ({} bytes); use output path or hex mode",
                        data.len()
                    )))
                    .await;
            }
        }
        saved_to = None;
    }

    let _ = tx
        .send(
            ToolEvent::info(String::new()).with_data(ToolData::PeekResult {
                name: name.to_string(),
                bytes_received: data.len() as u64,
                saved_to,
            }),
        )
        .await;

    Ok(())
}

async fn emit_meta(data: &Data, tx: &mpsc::Sender<ToolEvent>) {
    let _ = tx
        .send(ToolEvent::info(format!("  name:     {}", data.name)))
        .await;
    if let Some(mi) = data.meta_info() {
        if let Some(fp) = mi.freshness_period {
            let _ = tx
                .send(ToolEvent::info(format!(
                    "  freshness: {}ms",
                    fp.as_millis()
                )))
                .await;
        }
        if let Some(ref fb) = mi.final_block_id {
            let last = decode_final_block_id_segment(fb);
            let _ = tx
                .send(ToolEvent::info(format!("  final-block-id: {last:?}")))
                .await;
        }
    }
    let content_len = data.content().map(|b| b.len()).unwrap_or(0);
    let _ = tx
        .send(ToolEvent::info(format!("  content:  {content_len} bytes")))
        .await;
    if let Some(si) = data.sig_info() {
        let _ = tx
            .send(ToolEvent::info(format!("  sig-type: {:?}", si.sig_type)))
            .await;
        if let Some(ref kl) = si.key_locator {
            let _ = tx.send(ToolEvent::info(format!("  key:      {kl}"))).await;
        }
    }
}
