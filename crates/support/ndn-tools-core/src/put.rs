//! Embeddable NDN put tool logic — publish a chunked object as named Data segments.
//!
//! Always uses ndn-cxx compatible naming:
//! Segments are served under `/<prefix>/v=<µs-timestamp>/<seg>` using
//! VersionNameComponent (TLV 0x36) and SegmentNameComponent (TLV 0x32).
//! Compatible with `ndnpeekdata --pipeline` and `ndngetfile` consumers.
//!
//! # Signing modes
//!
//! [`SignMode`] selects the signature algorithm; [`HashAlgo`] selects
//! the hash function (only meaningful for [`SignMode::Merkle`] today).
//! The split is deliberately extensible: future algorithms can pick a
//! sign mode without re-using a "blake3-merkle" composite name.
//!
//! - **`SignMode::None`**: no SignatureValue (debug only).
//! - **`SignMode::DigestSha256`**: NDN spec type 0, SHA-256 of the
//!   signed region. ndn-cxx interoperable.
//! - **`SignMode::DigestBlake3`**: ndn-rs experimental type 6.
//! - **`SignMode::HmacSha256`**: NDN spec type 4, ephemeral key.
//! - **`SignMode::Blake3Keyed`**: ndn-rs experimental type 7,
//!   ephemeral 32-byte key.
//! - **`SignMode::Ed25519`**: NDN spec type 5, ephemeral keypair.
//! - **`SignMode::Merkle`**: ndn-rs experimental Merkle-tree segment
//!   signing. The producer builds the tree once at startup,
//!   publishes a manifest Data at `/<prefix>/v=<ts>/_root` signed
//!   with an ephemeral Ed25519 key, and serves each segment with
//!   leaf-hash-plus-proof as its SignatureValue. Interoperable with
//!   `ndn-peek` Merkle verification only — ndn-cxx tools can't
//!   consume the new signature type yet.

use std::collections::HashMap;
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
use ndn_security::merkle::{
    Blake3Merkle, MerkleKind, MerkleSegmentedPublication, Sha256Merkle, publish_segmented_merkle,
};

use crate::common::{ConnectConfig, ToolEvent};

// ── Sign mode + hash algo ────────────────────────────────────────────────────

/// Signing algorithm for ndn-put. See module docs for the full list
/// and what each one interoperates with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SignMode {
    /// Default: NDN spec DigestSha256 (type 0). Bit-for-bit
    /// interoperable with ndn-cxx and NDNts.
    #[default]
    DigestSha256,
    /// No signature value at all. For debugging only — many
    /// consumers will refuse the resulting packet.
    None,
    /// ndn-rs experimental DigestBlake3 (type 6).
    DigestBlake3,
    /// NDN spec HmacWithSha256 (type 4). Ephemeral key.
    HmacSha256,
    /// ndn-rs experimental Blake3Keyed (type 7). Ephemeral 32-byte key.
    Blake3Keyed,
    /// NDN spec SignatureSha256WithEd25519 (type 5). Ephemeral keypair.
    Ed25519,
    /// ndn-rs experimental Merkle-tree segment signing. The hash
    /// algorithm is picked by [`HashAlgo`] on the same params struct.
    Merkle,
}

/// Hash algorithm for sign modes that take one. Only meaningful for
/// [`SignMode::Merkle`] today.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HashAlgo {
    #[default]
    Sha256,
    Blake3,
}

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
    /// Signing algorithm. See [`SignMode`].
    pub sign_mode: SignMode,
    /// Hash algorithm — only consulted for [`SignMode::Merkle`].
    pub hash_algo: HashAlgo,
    /// Data freshness period in milliseconds (0 = omit).
    pub freshness_ms: u64,
    /// Stop serving after this many seconds (0 = serve until cancelled/disconnected).
    pub timeout_secs: u64,
    /// Suppress per-Interest log lines.
    pub quiet: bool,
    /// Pre-sign every segment at startup into a name → wire lookup
    /// table. The recv loop then serves by HashMap lookup with no
    /// DataBuilder / hash work in the hot path. Always on for
    /// `SignMode::Merkle` (the Merkle primitive requires the tree
    /// to be built up front); opt-in for other modes. Trades startup
    /// latency and memory (roughly one extra Bytes-size allocation
    /// per segment) for steady-state throughput.
    pub pre_sign: bool,
}

impl Default for PutParams {
    fn default() -> Self {
        Self {
            conn: ConnectConfig::default(),
            name: String::new(),
            data: Bytes::new(),
            chunk_size: 0,
            sign_mode: SignMode::default(),
            hash_algo: HashAlgo::default(),
            freshness_ms: 10_000,
            timeout_secs: 0,
            quiet: false,
            pre_sign: false,
        }
    }
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

/// Internal: how a particular sign mode produces a Data wire for a given
/// segment index.
///
/// Two shapes:
/// - **Lazy** (`None`, `DigestSha256`, `DigestBlake3`, `Signer`): the
///   recv loop builds and signs each Data on demand as Interests
///   arrive. Low startup cost, higher per-Interest cost.
/// - **Prebuilt** (`PreSigned`, `Merkle`): every segment Data wire
///   is signed once at startup into a `HashMap<Name, Bytes>` and the
///   recv loop is a lookup. Higher startup cost, near-zero per-
///   Interest cost. Merkle *requires* this shape because the tree
///   depends on the full segment set; other modes enable it with
///   `PutParams::pre_sign = true`.
enum SignerSlate {
    /// No signature value (debug only).
    None,
    /// DigestSha256 (NDN spec type 0). Lazy.
    DigestSha256,
    /// DigestBlake3 (ndn-rs experimental type 6). Lazy.
    DigestBlake3,
    /// Boxed `Signer` for HMAC-SHA256, Blake3-keyed, and Ed25519.
    /// Lazy.
    Signer(Arc<dyn Signer>),
    /// Pre-signed segment wires for any non-Merkle mode. Built once
    /// at startup when `PutParams::pre_sign` is set.
    PreSigned { wires: HashMap<Name, Bytes> },
    /// Pre-built Merkle publication. `wires` includes both the N
    /// segments and the manifest Data, all keyed by Name. The recv
    /// loop treats this identically to `PreSigned` (same name-lookup
    /// path); the variant is kept distinct only so log lines can
    /// say "merkle" vs "prebuilt" and so future Merkle-specific
    /// bookkeeping has a place to live.
    Merkle { wires: HashMap<Name, Bytes> },
}

impl SignerSlate {
    /// True if this slate serves segments from a pre-built
    /// HashMap<Name, Bytes> lookup (Merkle or explicit pre-sign).
    fn is_prebuilt(&self) -> bool {
        matches!(self, SignerSlate::PreSigned { .. } | SignerSlate::Merkle { .. })
    }

    /// Look up a pre-built wire by name. Returns `None` for lazy
    /// slates and for names not in the map.
    fn lookup(&self, name: &Name) -> Option<&Bytes> {
        match self {
            SignerSlate::PreSigned { wires } => wires.get(name),
            SignerSlate::Merkle { wires, .. } => wires.get(name),
            _ => None,
        }
    }
}

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
    let producer = Arc::new(ChunkedProducer::new(
        name.clone(),
        params.data.clone(),
        chunk_size,
    ));
    let seg_count = producer.segment_count();
    let last_seg = seg_count.saturating_sub(1);

    // Build the versioned prefix: /<name>/v=<µs-timestamp>
    let ts_us = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0);
    let served_prefix = name.clone().append_component(NameComponent::version(ts_us));

    let client = if params.conn.use_shm {
        ForwarderClient::connect(&params.conn.face_socket).await?
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

    let slate: SignerSlate = build_signer_slate(&params, &served_prefix, &tx).await?;

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

        // Prebuilt slate: pre-signed map keyed by Data name. Applies
        // to both `SignMode::Merkle` (always prebuilt, required by
        // the tree) and any other mode with `pre_sign = true`. The
        // recv loop is just an index + send with no DataBuilder or
        // hash work in the hot path.
        if slate.is_prebuilt() {
            // Resolve the requested name. Three cases:
            //   1. Explicit segment Interest: use interest.name.
            //   2. Manifest Interest (Merkle only): use interest.name
            //      (which matches `<served_prefix>/_root`).
            //   3. CanBePrefix discovery: respond with segment 0 wire.
            let last_is_seg = interest
                .name
                .components()
                .last()
                .and_then(|c| c.as_segment());
            let lookup_name: Name = if last_is_seg.is_some() {
                (*interest.name).clone()
            } else if slate.lookup(interest.name.as_ref()).is_some() {
                // Non-segment name that happens to hit the table —
                // e.g. the Merkle manifest at `<served_prefix>/_root`.
                (*interest.name).clone()
            } else {
                // CanBePrefix discovery fallback: segment 0.
                served_prefix.clone().append_segment(0)
            };
            let data_wire = match slate.lookup(&lookup_name) {
                Some(w) => w.clone(),
                None => {
                    // Unknown name — could be an out-of-range segment,
                    // a name from a different version, or noise.
                    unknown += 1;
                    if !params.quiet {
                        let _ = tx
                            .send(ToolEvent::info(format!(
                                "ndn-put: unknown segment name: {}",
                                interest.name
                            )))
                            .await;
                    }
                    continue;
                }
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
                        "ndn-put: served (prebuilt) {}",
                        lookup_name
                    )))
                    .await;
            }
            continue;
        }

        // Non-Merkle: extract SegmentNameComponent (TLV 0x32) from the
        // last name component and lazy-sign per Interest.
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

        let data_wire = match &slate {
            SignerSlate::None => builder.sign_none(),
            SignerSlate::DigestSha256 => builder.sign_digest_sha256(),
            SignerSlate::DigestBlake3 => builder.sign_digest_blake3(),
            SignerSlate::Signer(s) => {
                let sig_type = s.sig_type();
                let kn = s.key_name().clone();
                builder.sign_sync(sig_type, Some(&kn), |region| {
                    s.sign_sync(region).expect("signing failed")
                })
            }
            SignerSlate::PreSigned { .. } | SignerSlate::Merkle { .. } => {
                unreachable!("prebuilt slates are served via the is_prebuilt() branch above")
            }
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

/// Build the per-mode `SignerSlate` once at startup. For
/// `SignMode::Merkle` (always) and any non-Merkle mode with
/// `params.pre_sign = true`, the full segment set is pre-signed
/// into a `HashMap<Name, Bytes>` and the recv loop serves by
/// lookup. For other non-Merkle modes the slate is a "lazy"
/// variant and the recv loop signs per Interest.
async fn build_signer_slate(
    params: &PutParams,
    served_prefix: &Name,
    tx: &mpsc::Sender<ToolEvent>,
) -> Result<SignerSlate> {
    // Merkle is its own thing — construct the publication via the
    // security primitive and wrap it.
    if params.sign_mode == SignMode::Merkle {
        return build_merkle_slate(params, served_prefix, tx).await;
    }

    // Build a lazy slate first; the recv loop uses this directly
    // when `pre_sign = false`.
    let lazy: SignerSlate = match params.sign_mode {
        SignMode::None => {
            let _ = tx
                .send(ToolEvent::warn(
                    "ndn-put: --sign=none → no SignatureValue (debug only)",
                ))
                .await;
            SignerSlate::None
        }
        SignMode::DigestSha256 => {
            let _ = tx
                .send(ToolEvent::info(
                    "ndn-put: signing with DigestSha256 (NDN spec type 0)",
                ))
                .await;
            SignerSlate::DigestSha256
        }
        SignMode::DigestBlake3 => {
            let _ = tx
                .send(ToolEvent::info(
                    "ndn-put: signing with DigestBlake3 (ndn-rs experimental type 6)",
                ))
                .await;
            SignerSlate::DigestBlake3
        }
        SignMode::HmacSha256 => {
            let key_name = Name::from_components([
                NameComponent::generic(Bytes::from_static(b"ndn-put")),
                NameComponent::generic(Bytes::from_static(b"hmac-key")),
            ]);
            let s: Arc<dyn Signer> = Arc::new(ndn_security::HmacSha256Signer::new(
                b"ndn-put-bench-key",
                key_name,
            ));
            let _ = tx
                .send(ToolEvent::info(format!(
                    "ndn-put: signing with HmacSha256 ({})",
                    s.key_name()
                )))
                .await;
            SignerSlate::Signer(s)
        }
        SignMode::Blake3Keyed => {
            let key_name = Name::from_components([
                NameComponent::generic(Bytes::from_static(b"ndn-put")),
                NameComponent::generic(Bytes::from_static(b"blake3-key")),
            ]);
            let s: Arc<dyn Signer> = Arc::new(ndn_security::Blake3KeyedSigner::new(
                *b"ndn-put-blake3-key-padded-32-byt",
                key_name,
            ));
            let _ = tx
                .send(ToolEvent::info(format!(
                    "ndn-put: signing with Blake3Keyed ({})",
                    s.key_name()
                )))
                .await;
            SignerSlate::Signer(s)
        }
        SignMode::Ed25519 => {
            let keychain = KeyChain::ephemeral(params.name.as_str())?;
            let s = keychain.signer()?;
            let _ = tx
                .send(ToolEvent::info(format!(
                    "ndn-put: signing with Ed25519 ({})",
                    s.key_name()
                )))
                .await;
            SignerSlate::Signer(s)
        }
        SignMode::Merkle => unreachable!("handled above"),
    };

    if !params.pre_sign {
        return Ok(lazy);
    }

    // Pre-sign every segment into a name → wire table using the same
    // DataBuilder path the recv loop would take lazily. The Interest
    // matching in the recv loop still consults `served_prefix` to
    // resolve CanBePrefix discovery and explicit segment Interests
    // to the same names we populate here.
    let chunk_size = if params.chunk_size == 0 {
        NDN_DEFAULT_SEGMENT_SIZE
    } else {
        params.chunk_size
    };
    let n_segs = params.data.len().div_ceil(chunk_size).max(1);
    let last_seg = n_segs.saturating_sub(1);
    let freshness = (params.freshness_ms > 0).then(|| Duration::from_millis(params.freshness_ms));

    let mut wires: HashMap<Name, Bytes> = HashMap::with_capacity(n_segs);
    for (i, seg_body) in params.data.chunks(chunk_size).enumerate() {
        let data_name = served_prefix.clone().append_segment(i as u64);
        let mut builder = DataBuilder::new(data_name.clone(), seg_body)
            .final_block_id_typed_seg(last_seg as u64);
        if let Some(f) = freshness {
            builder = builder.freshness(f);
        }
        let wire = match &lazy {
            SignerSlate::None => builder.sign_none(),
            SignerSlate::DigestSha256 => builder.sign_digest_sha256(),
            SignerSlate::DigestBlake3 => builder.sign_digest_blake3(),
            SignerSlate::Signer(s) => {
                let sig_type = s.sig_type();
                let kn = s.key_name().clone();
                builder.sign_sync(sig_type, Some(&kn), |region| {
                    s.sign_sync(region).expect("pre-sign failed")
                })
            }
            SignerSlate::PreSigned { .. } | SignerSlate::Merkle { .. } => {
                unreachable!("lazy slate can't be prebuilt at this point")
            }
        };
        wires.insert(data_name, wire);
    }
    if params.data.is_empty() {
        // Zero-byte input still produces one empty segment.
        let data_name = served_prefix.clone().append_segment(0);
        let builder =
            DataBuilder::new(data_name.clone(), &[][..]).final_block_id_typed_seg(0);
        let builder = match freshness {
            Some(f) => builder.freshness(f),
            None => builder,
        };
        let wire = match &lazy {
            SignerSlate::None => builder.sign_none(),
            SignerSlate::DigestSha256 => builder.sign_digest_sha256(),
            SignerSlate::DigestBlake3 => builder.sign_digest_blake3(),
            SignerSlate::Signer(s) => {
                let sig_type = s.sig_type();
                let kn = s.key_name().clone();
                builder.sign_sync(sig_type, Some(&kn), |region| {
                    s.sign_sync(region).expect("pre-sign failed")
                })
            }
            _ => unreachable!(),
        };
        wires.insert(data_name, wire);
    }

    let _ = tx
        .send(ToolEvent::info(format!(
            "ndn-put: pre-signed {} segment(s) at startup",
            wires.len()
        )))
        .await;

    Ok(SignerSlate::PreSigned { wires })
}

/// Build the Merkle slate. Always prebuilt — the tree depends on
/// every segment body.
async fn build_merkle_slate(
    params: &PutParams,
    served_prefix: &Name,
    tx: &mpsc::Sender<ToolEvent>,
) -> Result<SignerSlate> {
    let kind = match params.hash_algo {
        HashAlgo::Sha256 => MerkleKind::Sha256,
        HashAlgo::Blake3 => MerkleKind::Blake3,
    };
    let manifest_signer = KeyChain::ephemeral(params.name.as_str())?
        .signer()
        .map_err(|e| anyhow::anyhow!("merkle manifest signer: {e}"))?;
    let chunk_size = if params.chunk_size == 0 {
        NDN_DEFAULT_SEGMENT_SIZE
    } else {
        params.chunk_size
    };
    let pub_: MerkleSegmentedPublication = match kind {
        MerkleKind::Sha256 => publish_segmented_merkle::<Sha256Merkle>(
            served_prefix,
            &params.data,
            chunk_size,
            kind,
            manifest_signer.as_ref(),
        ),
        MerkleKind::Blake3 => publish_segmented_merkle::<Blake3Merkle>(
            served_prefix,
            &params.data,
            chunk_size,
            kind,
            manifest_signer.as_ref(),
        ),
    }
    .map_err(|e| anyhow::anyhow!("merkle publish: {e}"))?;

    let mut wires: HashMap<Name, Bytes> = HashMap::with_capacity(pub_.segments.len() + 1);
    for w in &pub_.segments {
        let d = ndn_packet::Data::decode(w.clone())
            .map_err(|e| anyhow::anyhow!("decode merkle segment: {e}"))?;
        wires.insert(d.name.as_ref().clone(), w.clone());
    }
    wires.insert(pub_.manifest_name.clone(), pub_.manifest.clone());

    let kind_label = match kind {
        MerkleKind::Sha256 => "sha256",
        MerkleKind::Blake3 => "blake3",
    };
    let _ = tx
        .send(ToolEvent::info(format!(
            "ndn-put: signing with Merkle/{} ({} segments + manifest at {})",
            kind_label,
            pub_.segments.len(),
            pub_.manifest_name
        )))
        .await;
    let _ = pub_.manifest_name; // silences unused-field warning
    Ok(SignerSlate::Merkle { wires })
}
