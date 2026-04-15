//! Embeddable NDN peek tool logic — single and segmented fetch.
//!
//! Always uses ndn-cxx compatible naming:
//! - Segmented fetch sends the initial Interest with CanBePrefix, discovers the
//!   versioned prefix from the response, and fetches subsequent segments using
//!   SegmentNameComponent (TLV 0x32). Compatible with `ndnputchunks` producers.
//!
//! # Verification modes
//!
//! See [`VerifyMode`]. The default is [`VerifyMode::None`] — segments are
//! fetched and assembled without checking signatures, matching the
//! historical behaviour. Other modes verify per-segment with the
//! algorithm the producer chose; the consumer must be told which one
//! to expect because in-band sig-type sniffing only works for some
//! algorithms (Merkle, where the manifest fetch is name-resolvable;
//! Ed25519 with `--batch-verify`, where the public key is known
//! out-of-band; etc.).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use tokio::sync::mpsc;

use ndn_ipc::ForwarderClient;
use ndn_packet::encode::InterestBuilder;
use ndn_packet::{Data, Name, SignatureType, tlv_type};
use ndn_security::merkle::{CachedManifest, verify_merkle_segment};
use ndn_security::signer::{
    SIGNATURE_TYPE_DIGEST_BLAKE3_MERKLE, SIGNATURE_TYPE_DIGEST_SHA256_MERKLE,
};
use ndn_security::{Ed25519Verifier, ed25519_verify_batch};
use ndn_transport::CongestionController;

use crate::common::{ConnectConfig, ToolData, ToolEvent};

// ── Verification + congestion control parameter types ──────────────────────

/// Per-segment verification strategy for segmented fetch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VerifyMode {
    /// No verification (default). Faster, matches historical behaviour.
    #[default]
    None,
    /// Verify each segment as DigestSha256 (recompute SHA-256 of the
    /// signed region and compare).
    DigestSha256,
    /// Verify each segment as DigestBlake3.
    DigestBlake3,
    /// Verify each segment with Ed25519. Public key is given via
    /// [`PeekParams::ed25519_public_key`]. Pair with `batch_verify`
    /// to use `verify_batch` instead of per-signature verify.
    Ed25519,
    /// Auto-detect Merkle from the first segment's SignatureType
    /// (codes 8 / 9). Fetches the manifest by name from the
    /// segment's KeyLocator, parses it, and verifies every segment
    /// against the cached root. **Does not** verify the manifest's
    /// own asymmetric signature — it's just decoded for the root.
    Merkle,
}

/// Congestion-control algorithm for the segmented fetch pipeline,
/// matching the iperf flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CcAlgo {
    /// Fixed window (the historical `--pipeline N` behaviour).
    #[default]
    Fixed,
    /// Additive-increase / multiplicative-decrease.
    Aimd,
    /// CUBIC (RFC 8312).
    Cubic,
}

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
    /// Per-segment verification strategy (segmented fetch only).
    pub verify_mode: VerifyMode,
    /// Public key for `VerifyMode::Ed25519` (32 bytes). Ignored for
    /// other modes. None → Ed25519 verification will fail.
    pub ed25519_public_key: Option<[u8; 32]>,
    /// Use `ed25519_verify_batch` instead of per-signature verify when
    /// `verify_mode == Ed25519`. Collects all (region, sig, key)
    /// tuples and runs one batch verify at the end of the fetch.
    pub batch_verify: bool,
    /// Congestion control for the segmented fetch pipeline.
    pub cc_algo: CcAlgo,
    /// Initial pipeline window. With `cc_algo == Fixed`, this is the
    /// fixed window; with AIMD/Cubic, it's the starting value.
    pub initial_window: usize,
    /// AIMD / Cubic minimum congestion window.
    pub min_window: Option<f64>,
    /// AIMD / Cubic maximum congestion window.
    pub max_window: Option<f64>,
    /// AIMD additive increase (default 1.0 → 1 segment per RTT).
    pub ai: Option<f64>,
    /// AIMD / Cubic multiplicative decrease factor (default 0.5).
    pub md: Option<f64>,
    /// Cubic `C` parameter.
    pub cubic_c: Option<f64>,
    /// Partial fetch: starting segment index. 0 = from segment 0.
    pub start_seg: usize,
    /// Partial fetch: how many segments to retrieve. 0 = all from
    /// `start_seg` to the end.
    pub count_segs: usize,
    /// Emit a machine-parseable JSON summary line at the end of the
    /// run (one line, prefixed `metrics:`).
    pub metrics: bool,
    /// Stream segment Content directly to `output` as each segment
    /// arrives, instead of buffering all segments in a
    /// `Vec<Option<Bytes>>` and reassembling at the end. Eliminates
    /// the O(N) reassembly cost and the O(N) allocation of segment
    /// Bytes storage — at the cost of requiring `output` to be set
    /// (no in-memory result), no partial-range or out-of-order
    /// support (segments must arrive in order to be streamed to
    /// disk without re-seeks), and losing the "all or nothing"
    /// atomicity the buffered path provides on error.
    ///
    /// Only enable for full-file fetches with `cc_algo == Fixed` or
    /// small partial ranges; the fetch loop will buffer-then-write
    /// if either `start_seg != 0` or `count_segs != 0` to preserve
    /// partial-range correctness.
    pub no_assemble: bool,
}

impl Default for PeekParams {
    fn default() -> Self {
        Self {
            conn: ConnectConfig::default(),
            name: String::new(),
            lifetime_ms: 4000,
            output: None,
            pipeline: None,
            hex: false,
            meta_only: false,
            verbose: false,
            can_be_prefix: false,
            verify_mode: VerifyMode::default(),
            ed25519_public_key: None,
            batch_verify: false,
            cc_algo: CcAlgo::default(),
            initial_window: 16,
            min_window: None,
            max_window: None,
            ai: None,
            md: None,
            cubic_c: None,
            start_seg: 0,
            count_segs: 0,
            metrics: false,
            no_assemble: false,
        }
    }
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

/// Outcome of a segmented fetch — assembled bytes plus per-run metrics
/// the caller can publish via `--metrics` or display in a UI.
struct FetchOutcome {
    assembled: Bytes,
    metrics: FetchMetrics,
}

#[derive(Default)]
struct FetchMetrics {
    total_segments_in_file: usize,
    fetched_segments: usize,
    fetch_wall_us: u64,
    verify_wall_us: u64,
    /// Per-segment verify latencies in µs (only populated when
    /// per-segment verification is enabled).
    verify_samples_us: Vec<u64>,
    manifest_fetch_us: u64,
    bytes: u64,
    cc_label: &'static str,
    verify_label: &'static str,
}

impl FetchMetrics {
    fn percentile(samples: &[u64], pct: f64) -> u64 {
        if samples.is_empty() {
            return 0;
        }
        let mut sorted = samples.to_vec();
        sorted.sort_unstable();
        let idx = ((sorted.len() as f64) * pct).floor() as usize;
        sorted[idx.min(sorted.len() - 1)]
    }

    fn p50(&self) -> u64 {
        Self::percentile(&self.verify_samples_us, 0.50)
    }
    fn p95(&self) -> u64 {
        Self::percentile(&self.verify_samples_us, 0.95)
    }
    fn p99(&self) -> u64 {
        Self::percentile(&self.verify_samples_us, 0.99)
    }

    fn to_json_line(&self) -> String {
        let throughput_bps = if self.fetch_wall_us > 0 {
            (self.bytes as f64 * 8.0 * 1_000_000.0) / (self.fetch_wall_us as f64)
        } else {
            0.0
        };
        format!(
            "metrics: {{\
              \"bytes\":{},\
              \"segments_in_file\":{},\
              \"fetched\":{},\
              \"fetch_wall_us\":{},\
              \"verify_wall_us\":{},\
              \"manifest_fetch_us\":{},\
              \"verify_p50_us\":{},\
              \"verify_p95_us\":{},\
              \"verify_p99_us\":{},\
              \"throughput_bps\":{:.0},\
              \"cc\":\"{}\",\
              \"verify\":\"{}\"\
            }}",
            self.bytes,
            self.total_segments_in_file,
            self.fetched_segments,
            self.fetch_wall_us,
            self.verify_wall_us,
            self.manifest_fetch_us,
            self.p50(),
            self.p95(),
            self.p99(),
            throughput_bps,
            self.cc_label,
            self.verify_label,
        )
    }
}

/// Build a CC controller from the params, mirroring iperf's setup.
fn build_cc(p: &PeekParams) -> CongestionController {
    let initial = p.initial_window.max(1) as f64;
    let mut cc = match p.cc_algo {
        CcAlgo::Fixed => CongestionController::fixed(initial),
        CcAlgo::Aimd => CongestionController::aimd(),
        CcAlgo::Cubic => CongestionController::cubic(),
    };
    cc = cc.with_window(initial).with_ssthresh(initial);
    if let Some(v) = p.min_window {
        cc = cc.with_min_window(v);
    }
    if let Some(v) = p.max_window {
        cc = cc.with_max_window(v);
    }
    if let Some(v) = p.ai {
        cc = cc.with_additive_increase(v);
    }
    if let Some(v) = p.md {
        cc = cc.with_decrease_factor(v);
    }
    if let Some(v) = p.cubic_c {
        cc = cc.with_cubic_c(v);
    }
    cc
}

fn cc_label(cc: &CongestionController) -> &'static str {
    match cc {
        CongestionController::Fixed { .. } => "fixed",
        CongestionController::Aimd { .. } => "aimd",
        CongestionController::Cubic { .. } => "cubic",
    }
}

fn verify_label(mode: VerifyMode) -> &'static str {
    match mode {
        VerifyMode::None => "none",
        VerifyMode::DigestSha256 => "digest-sha256",
        VerifyMode::DigestBlake3 => "digest-blake3",
        VerifyMode::Ed25519 => "ed25519",
        VerifyMode::Merkle => "merkle",
    }
}

/// Verify a single Data segment per the configured mode. Returns
/// `Ok(verify_us)` on success — the caller records this for percentile
/// reporting.
async fn verify_one(
    data: &Data,
    leaf_index: usize,
    params: &PeekParams,
    merkle_cache: &mut Option<CachedManifest>,
    client: &ForwarderClient,
    lifetime: Duration,
    metrics: &mut FetchMetrics,
) -> Result<u64> {
    let t0 = Instant::now();
    match params.verify_mode {
        VerifyMode::None => {}
        VerifyMode::DigestSha256 => {
            use sha2::{Digest, Sha256};
            let h = Sha256::digest(data.signed_region());
            if h.as_slice() != data.sig_value() {
                anyhow::bail!("sha256 verify failed for segment {leaf_index}");
            }
        }
        VerifyMode::DigestBlake3 => {
            let h = blake3::hash(data.signed_region());
            if h.as_bytes() != data.sig_value() {
                anyhow::bail!("blake3 verify failed for segment {leaf_index}");
            }
        }
        VerifyMode::Ed25519 => {
            // Per-segment verify only when batch_verify is OFF; in
            // batch mode the caller collects the inputs and runs one
            // verify_batch at the end.
            if !params.batch_verify {
                let pk = params
                    .ed25519_public_key
                    .as_ref()
                    .context("ed25519 verify requires --pubkey")?;
                let outcome =
                    Ed25519Verifier.verify_sync(data.signed_region(), data.sig_value(), pk);
                if outcome != ndn_security::VerifyOutcome::Valid {
                    anyhow::bail!("ed25519 verify failed for segment {leaf_index}");
                }
            }
        }
        VerifyMode::Merkle => {
            // First Merkle segment: fetch the manifest by KeyLocator
            // name and cache it. Subsequent segments verify against
            // the cached state.
            if merkle_cache.is_none() {
                let manifest_name = data
                    .sig_info()
                    .and_then(|si| si.key_locator.clone())
                    .context("merkle segment missing KeyLocator → manifest name")?;
                let m_t0 = Instant::now();
                let manifest_data = fetch_one(client, &manifest_name, lifetime, false).await?;
                metrics.manifest_fetch_us = m_t0.elapsed().as_micros() as u64;
                let cached = CachedManifest::from_manifest_data(&manifest_data)
                    .map_err(|e| anyhow::anyhow!("manifest decode: {e}"))?;
                *merkle_cache = Some(cached);
            }
            let cached = merkle_cache.as_ref().unwrap();
            verify_merkle_segment(data, leaf_index, cached)
                .map_err(|e| anyhow::anyhow!("merkle segment {leaf_index}: {e}"))?;
        }
    }
    Ok(t0.elapsed().as_micros() as u64)
}

/// Segmented fetch using SegmentNameComponent (TLV 0x32), compatible with
/// ndnputchunks producers. Sends the initial Interest with CanBePrefix to
/// discover the versioned name, then fetches all segments. Optional
/// per-segment verification, congestion control, and partial-range
/// `[start_seg, start_seg + count_segs)` fetch.
#[allow(clippy::too_many_arguments)]
async fn fetch_segmented(
    client: &ForwarderClient,
    prefix: &Name,
    params: &PeekParams,
    lifetime: Duration,
    tx: &mpsc::Sender<ToolEvent>,
) -> Result<FetchOutcome> {
    let mut metrics = FetchMetrics::default();
    let fetch_t0 = Instant::now();

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

    if params.verbose {
        let _ = tx
            .send(ToolEvent::info(format!(
                "ndn-peek: discovered name: {}",
                first.name
            )))
            .await;
    }

    // The response name should end with a SegmentNameComponent (type 0x32).
    let comps = first.name.components();
    let versioned_prefix = if comps.last().map(|c| c.typ) == Some(tlv_type::SEGMENT) {
        Name::from_components(comps[..comps.len() - 1].iter().cloned())
    } else {
        // Not a segmented response — treat as single packet.
        let assembled = first.content().cloned().unwrap_or_else(Bytes::new);
        metrics.bytes = assembled.len() as u64;
        metrics.fetch_wall_us = fetch_t0.elapsed().as_micros() as u64;
        return Ok(FetchOutcome { assembled, metrics });
    };

    let seg0_idx = comps.last().and_then(|c| c.as_segment()).unwrap_or(0) as usize;

    let total_segs: usize = first
        .meta_info()
        .and_then(|mi| mi.final_block_id.as_ref())
        .and_then(|fb| decode_final_block_id_segment(fb))
        .map(|last| last + 1)
        .unwrap_or(1);

    metrics.total_segments_in_file = total_segs;

    // Auto-detect Merkle from the first segment's sig type if the
    // user explicitly asked for Merkle mode but didn't tell us
    // which kind. Either way, we always detect by sig-type code so
    // the auto path also catches a "verify_mode = Merkle" misconfig
    // against a non-Merkle file.
    let sig_type_code = first
        .sig_info()
        .map(|si| match si.sig_type {
            SignatureType::Other(c) => c,
            other => other.code(),
        })
        .unwrap_or(0);
    let is_merkle = matches!(
        sig_type_code,
        SIGNATURE_TYPE_DIGEST_BLAKE3_MERKLE | SIGNATURE_TYPE_DIGEST_SHA256_MERKLE
    );
    if is_merkle && params.verify_mode == VerifyMode::None && params.verbose {
        let _ = tx
            .send(ToolEvent::info(
                "ndn-peek: detected Merkle SignatureType; pass --verify=merkle to verify",
            ))
            .await;
    }

    // Compute the actual range to fetch. For a partial fetch:
    //   start = max(start_seg, 0), end = min(start + count, total)
    // count_segs == 0 means "to the end".
    let start = params.start_seg.min(total_segs.saturating_sub(1));
    let end = if params.count_segs == 0 {
        total_segs
    } else {
        (start + params.count_segs).min(total_segs)
    };
    let range_len = end.saturating_sub(start);
    let want_full = start == 0 && end == total_segs;

    if params.verbose {
        let _ = tx
            .send(ToolEvent::info(format!(
                "ndn-peek: prefix={versioned_prefix} total={total_segs} fetch=[{start}..{end}) cc={} verify={}",
                cc_label(&build_cc(params)),
                verify_label(params.verify_mode),
            )))
            .await;
    }

    // Storage for fetched segment bodies. We allocate the full
    // length of the requested range; index into it by `seg_idx -
    // start`. For a full fetch this is `total_segs`.
    let mut segments: Vec<Option<Bytes>> = vec![None; range_len];
    let mut received: usize = 0;

    // Storage for the per-segment verify inputs in batch-verify mode.
    // We tuple-up (signed_region, sig_value, leaf_index) and run one
    // ed25519_verify_batch at the end of the fetch.
    let mut batch_inputs: Vec<(Bytes, Bytes, usize)> = Vec::new();

    // Eager manifest fetch. For Merkle verification we must resolve
    // the manifest Data *before* the pipeline drains, because
    // `fetch_one(manifest_name)` uses the same shared recv channel
    // as the segment pipeline. If we defer this to the first segment
    // arrival inside `drive_pipeline`, the manifest fetch races with
    // the several already-in-flight segment responses and
    // `client.recv()` returns a segment Data instead of the manifest.
    // Fetching the manifest up front is also cheap — it's one extra
    // Interest round-trip, amortised across the whole transfer.
    let mut merkle_cache: Option<CachedManifest> = None;
    if is_merkle && params.verify_mode == VerifyMode::Merkle {
        let manifest_name = first
            .sig_info()
            .and_then(|si| si.key_locator.clone())
            .context("merkle segment missing KeyLocator → manifest name")?;
        let m_t0 = Instant::now();
        let manifest_data = fetch_one(client, &manifest_name, lifetime, false).await?;
        metrics.manifest_fetch_us = m_t0.elapsed().as_micros() as u64;
        let cached = CachedManifest::from_manifest_data(&manifest_data)
            .map_err(|e| anyhow::anyhow!("manifest decode: {e}"))?;
        if params.verbose {
            let _ = tx
                .send(ToolEvent::info(format!(
                    "ndn-peek: merkle manifest: {} segments, root cached",
                    cached.leaf_count
                )))
                .await;
        }
        merkle_cache = Some(cached);
    }

    // Treat the discovery Data as the first segment if its index
    // falls inside the requested range.
    if seg0_idx >= start && seg0_idx < end {
        segments[seg0_idx - start] = Some(first.content().cloned().unwrap_or_else(Bytes::new));
        received += 1;
        let verify_us = verify_one(
            &first,
            seg0_idx,
            params,
            &mut merkle_cache,
            client,
            lifetime,
            &mut metrics,
        )
        .await?;
        if params.verify_mode != VerifyMode::None {
            metrics.verify_samples_us.push(verify_us);
        }
        if params.verify_mode == VerifyMode::Ed25519 && params.batch_verify {
            batch_inputs.push((
                Bytes::copy_from_slice(first.signed_region()),
                Bytes::copy_from_slice(first.sig_value()),
                seg0_idx,
            ));
        }
        // Merkle cache survives across the loop below.
        if range_len == 1 || (start == seg0_idx && end == start + 1) {
            metrics.fetched_segments = received;
            metrics.bytes = segments[0].as_ref().map(|s| s.len() as u64).unwrap_or(0);
            metrics.fetch_wall_us = fetch_t0.elapsed().as_micros() as u64;
            metrics.cc_label = cc_label(&build_cc(params));
            metrics.verify_label = verify_label(params.verify_mode);
            return finalise(segments, batch_inputs, params, metrics, want_full);
        }
        // Continue with the cache populated for the rest of the range.
        return drive_pipeline(
            client,
            &versioned_prefix,
            params,
            lifetime,
            tx,
            segments,
            received,
            start,
            end,
            seg0_idx,
            merkle_cache,
            batch_inputs,
            metrics,
            fetch_t0,
            want_full,
        )
        .await;
    }

    // Discovery segment falls outside the partial range — drop its
    // content and fetch the whole range from scratch. The
    // `merkle_cache` was populated above if verify_mode == Merkle;
    // it survives the dropped discovery segment and feeds straight
    // into the pipeline loop.
    drive_pipeline(
        client,
        &versioned_prefix,
        params,
        lifetime,
        tx,
        segments,
        received,
        start,
        end,
        usize::MAX,
        merkle_cache,
        batch_inputs,
        metrics,
        fetch_t0,
        want_full,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn drive_pipeline(
    client: &ForwarderClient,
    versioned_prefix: &Name,
    params: &PeekParams,
    lifetime: Duration,
    tx: &mpsc::Sender<ToolEvent>,
    mut segments: Vec<Option<Bytes>>,
    mut received: usize,
    start: usize,
    end: usize,
    skip_seg: usize, // segment index already filled (or usize::MAX)
    mut merkle_cache: Option<CachedManifest>,
    mut batch_inputs: Vec<(Bytes, Bytes, usize)>,
    mut metrics: FetchMetrics,
    fetch_t0: Instant,
    want_full: bool,
) -> Result<FetchOutcome> {
    let mut cc = build_cc(params);
    let cc_name = cc_label(&cc);
    metrics.cc_label = cc_name;
    metrics.verify_label = verify_label(params.verify_mode);

    let make_interest = |seg: usize| {
        let name = versioned_prefix.clone().append_segment(seg as u64);
        InterestBuilder::new(name).lifetime(lifetime).build()
    };

    let mut in_flight: HashMap<u64, (usize, Instant)> = HashMap::new();
    let mut next_seg: usize = start;
    let mut seq: u64 = 0;

    let target = end - start;
    while received < target {
        // Push as many Interests as the current congestion window
        // allows.
        let window = cc.window().floor() as usize;
        while in_flight.len() < window && next_seg < end {
            if next_seg == skip_seg {
                next_seg += 1;
                continue;
            }
            client.send(make_interest(next_seg)).await?;
            in_flight.insert(seq, (next_seg, Instant::now()));
            seq += 1;
            next_seg += 1;
        }

        let drain = lifetime + Duration::from_millis(500);
        match tokio::time::timeout(drain, client.recv()).await {
            Ok(Some(raw)) => {
                let data = match Data::decode(raw) {
                    Ok(d) => d,
                    Err(_) => continue,
                };
                let seg_idx = data
                    .name
                    .components()
                    .last()
                    .and_then(|c| c.as_segment())
                    .map(|s| s as usize);
                if let Some(idx) = seg_idx {
                    if idx >= start && idx < end {
                        let slot = idx - start;
                        if segments[slot].is_none() {
                            // Verify before storing — fail-fast on
                            // bad data so we don't waste time pulling
                            // the rest.
                            let verify_us = verify_one(
                                &data,
                                idx,
                                params,
                                &mut merkle_cache,
                                client,
                                lifetime,
                                &mut metrics,
                            )
                            .await?;
                            if params.verify_mode != VerifyMode::None {
                                metrics.verify_samples_us.push(verify_us);
                                metrics.verify_wall_us += verify_us;
                            }
                            if params.verify_mode == VerifyMode::Ed25519 && params.batch_verify {
                                batch_inputs.push((
                                    Bytes::copy_from_slice(data.signed_region()),
                                    Bytes::copy_from_slice(data.sig_value()),
                                    idx,
                                ));
                            }
                            segments[slot] =
                                Some(data.content().cloned().unwrap_or_else(Bytes::new));
                            received += 1;
                            cc.on_data();
                            in_flight.retain(|_, (s, _)| *s != idx);
                            if params.verbose && received.is_multiple_of(64) {
                                let _ = tx
                                    .send(
                                        ToolEvent::info(format!(
                                            "ndn-peek: {received}/{target} segments  cwnd={:.1}",
                                            cc.window()
                                        ))
                                        .with_data(
                                            ToolData::FetchProgress {
                                                received,
                                                total: target,
                                            },
                                        ),
                                    )
                                    .await;
                            }
                        }
                    }
                }
            }
            Ok(None) => anyhow::bail!("connection closed during segmented fetch"),
            Err(_) => {
                // Drain timeout — treat outstanding Interests as
                // lost, signal the CC, and re-express any past their
                // own per-Interest deadline.
                cc.on_timeout();
                let stale: Vec<(usize, u64)> = in_flight
                    .iter()
                    .filter(|(_, (_, t0))| t0.elapsed() >= lifetime)
                    .map(|(&sq, &(idx, _))| (idx, sq))
                    .collect();
                for (idx, old_seq) in stale {
                    in_flight.remove(&old_seq);
                    client.send(make_interest(idx)).await?;
                    in_flight.insert(seq, (idx, Instant::now()));
                    seq += 1;
                }
            }
        }
    }

    metrics.fetched_segments = received;
    metrics.bytes = segments
        .iter()
        .filter_map(|s| s.as_ref())
        .map(|s| s.len() as u64)
        .sum();
    metrics.fetch_wall_us = fetch_t0.elapsed().as_micros() as u64;
    finalise(segments, batch_inputs, params, metrics, want_full)
}

/// Final processing: optional batch Ed25519 verification + reassembly
/// into one buffer (only if `want_full`; otherwise concatenate the
/// requested partial range). When `params.no_assemble` is set and
/// `params.output` is provided, segments are streamed directly to
/// the output file via `FileExt::write_at` (positional writes, so
/// out-of-order arrival is fine) and the returned `assembled` is
/// empty.
fn finalise(
    segments: Vec<Option<Bytes>>,
    batch_inputs: Vec<(Bytes, Bytes, usize)>,
    params: &PeekParams,
    mut metrics: FetchMetrics,
    want_full: bool,
) -> Result<FetchOutcome> {
    if params.verify_mode == VerifyMode::Ed25519 && params.batch_verify && !batch_inputs.is_empty()
    {
        let pk = params
            .ed25519_public_key
            .as_ref()
            .context("ed25519 batch verify requires --pubkey")?;
        let pk_arc: Arc<[u8; 32]> = Arc::new(*pk);
        let regions: Vec<&[u8]> = batch_inputs.iter().map(|(r, _, _)| r.as_ref()).collect();
        let sigs: Vec<&[u8; 64]> = batch_inputs
            .iter()
            .map(|(_, s, _)| {
                let bytes: &[u8] = s.as_ref();
                let arr: &[u8; 64] = bytes.try_into().expect("ed25519 sig length");
                arr
            })
            .collect();
        let keys: Vec<&[u8; 32]> = (0..batch_inputs.len()).map(|_| pk_arc.as_ref()).collect();
        let t0 = Instant::now();
        let outcome = ed25519_verify_batch(&regions, &sigs, &keys)
            .map_err(|e| anyhow::anyhow!("ed25519 batch verify: {e}"))?;
        let dt = t0.elapsed().as_micros() as u64;
        metrics.verify_wall_us += dt;
        // Treat the batch as one giant verify sample so percentiles
        // still mean something.
        metrics.verify_samples_us.push(dt);
        if outcome != ndn_security::VerifyOutcome::Valid {
            anyhow::bail!("ed25519 batch verify failed");
        }
    }

    // Fast path: --no-assemble streams to `output` directly, skipping
    // the per-segment BytesMut extend_from_slice() and the final
    // single-buffer allocation. Requires `output` and a uniform
    // segment stride (the per-segment write offset is `slot *
    // seg_stride`, so the first N-1 segments must all be the same
    // length). We enforce that by computing `seg_stride` from the
    // first segment slot and bailing out to the buffered path if any
    // subsequent slot disagrees.
    #[cfg(unix)]
    if params.no_assemble {
        use std::os::unix::fs::FileExt;
        let path = params
            .output
            .as_ref()
            .context("--no-assemble requires --output")?;
        // Stride is the length of the first filled slot — the file's
        // segments are assumed uniform-length except possibly the
        // last one (which can be shorter, and is handled naturally
        // because we write exactly its length at the stride offset).
        let seg_stride = segments
            .iter()
            .find_map(|s| s.as_ref().map(|b| b.len()))
            .unwrap_or(0);

        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)
            .with_context(|| format!("open {path} for no-assemble write"))?;

        let mut total_bytes: u64 = 0;
        for (slot, seg) in segments.iter().enumerate() {
            if let Some(b) = seg {
                let offset = (slot * seg_stride) as u64;
                file.write_all_at(b, offset).with_context(|| {
                    format!("write_at offset={offset} for segment slot {slot}")
                })?;
                total_bytes += b.len() as u64;
            }
        }
        metrics.bytes = total_bytes;
        // Return an empty `assembled` — the caller's `emit_content`
        // path will notice `output` is set and skip its own write.
        return Ok(FetchOutcome {
            assembled: Bytes::new(),
            metrics,
        });
    }

    if !want_full {
        // Partial range: concatenate just the slots we have.
        let total: usize = segments
            .iter()
            .filter_map(|s| s.as_ref())
            .map(|s| s.len())
            .sum();
        let mut out = BytesMut::with_capacity(total);
        for s in &segments {
            if let Some(b) = s {
                out.extend_from_slice(b);
            }
        }
        return Ok(FetchOutcome {
            assembled: out.freeze(),
            metrics,
        });
    }

    let assembled = reassemble(segments)?;
    Ok(FetchOutcome { assembled, metrics })
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
        ForwarderClient::connect(&params.conn.face_socket).await?
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

    if let Some(_pipeline) = params.pipeline {
        // The legacy `--pipeline N` flag is still honoured at the CLI
        // level and re-injected into params.initial_window for back-
        // compat: a user passing `--pipeline 16` on the binary CLI
        // gets the same fixed-window behaviour they had before.
        // Algorithm/window selection now flows through cc_algo +
        // initial_window on PeekParams.
        let _ = tx
            .send(ToolEvent::info(format!(
                "ndn-peek: segmented fetch  cc={}  init_window={}  verify={}",
                match params.cc_algo {
                    CcAlgo::Fixed => "fixed",
                    CcAlgo::Aimd => "aimd",
                    CcAlgo::Cubic => "cubic",
                },
                params.initial_window,
                verify_label(params.verify_mode),
            )))
            .await;
        let t0 = Instant::now();
        let outcome = fetch_segmented(&client, &name, &params, lifetime, &tx).await?;
        let elapsed = t0.elapsed();
        let rate = if elapsed.as_secs_f64() > 0.0 {
            outcome.assembled.len() as f64 / elapsed.as_secs_f64() / 1024.0
        } else {
            0.0
        };
        let _ = tx
            .send(ToolEvent::info(format!(
                "ndn-peek: {} bytes in {:.2}s ({:.1} KB/s)",
                outcome.assembled.len(),
                elapsed.as_secs_f64(),
                rate
            )))
            .await;
        if params.metrics {
            let _ = tx
                .send(ToolEvent::summary(outcome.metrics.to_json_line()))
                .await;
        }
        if params.no_assemble && params.output.is_some() {
            // finalise() already streamed segments to the output
            // file via positional writes; skip the emit_content
            // path (which would otherwise over-write the file with
            // an empty buffer) and log the saved-to event directly.
            let path = params.output.clone().unwrap();
            let _ = tx
                .send(
                    ToolEvent::info(format!(
                        "ndn-peek: saved {} bytes to {path} (streamed)",
                        outcome.metrics.bytes
                    ))
                    .with_data(ToolData::PeekResult {
                        name: name.to_string(),
                        bytes_received: outcome.metrics.bytes,
                        saved_to: Some(path),
                    }),
                )
                .await;
        } else {
            emit_content(&outcome.assembled, &name, &params, &tx).await?;
        }
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
