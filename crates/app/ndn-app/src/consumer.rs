#[cfg(not(target_arch = "wasm32"))]
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;

#[cfg(not(target_arch = "wasm32"))]
use ndn_face::local::InProcHandle;
#[cfg(target_arch = "wasm32")]
use ndn_face_local::InProcHandle;
#[cfg(not(target_arch = "wasm32"))]
use ndn_ipc::ForwarderClient;
use ndn_packet::encode::InterestBuilder;
use ndn_packet::lp::{LpPacket, is_lp_packet};
use ndn_packet::{
    Data, Interest, MAX_PERSISTENT_LIFETIME_SECS, Name, PacketError, SubscriptionRequest,
};
use ndn_security::{SafeData, Unverified, Validator};

use crate::AppError;
use crate::rdr::sha256;

/// Verify a fetched `Data` against `validator` (when present) and return its
/// content bytes. With a validator the Data must authenticate (signature checked
/// against the pinned anchor) or this errors; without one, content is taken
/// as-is (integrity only). `None` when the Data carries no Content. The single
/// choke point both the unverified and verified RDR object paths route through.
/// Build and send one segment Interest for `versioned/seg=<seg>` (carrying the
/// forwarding hint, if any) directly on the connection — used by the windowed
/// segment-fetch pipeline.
async fn send_segment_interest(
    conn: &dyn Connection,
    versioned: &Name,
    seg: u64,
    forwarding_hint: &[Name],
) -> Result<(), AppError> {
    let mut b = InterestBuilder::new(versioned.clone().append_segment(seg))
        .lifetime(DEFAULT_INTEREST_LIFETIME);
    if !forwarding_hint.is_empty() {
        b = b.forwarding_hint(forwarding_hint.to_vec());
    }
    conn.send(b.build()).await
}

async fn accept_content(
    data: Data,
    validator: Option<Arc<Validator>>,
) -> Result<Option<Bytes>, AppError> {
    match validator {
        Some(v) => {
            let safe = Unverified::new(data)
                .verify(&v)
                .await
                .map_err(|e| AppError::Unverified(e.to_string()))?;
            Ok(safe.data().content().map(|b| Bytes::copy_from_slice(b)))
        }
        None => Ok(data.content().map(|b| Bytes::copy_from_slice(b))),
    }
}
#[cfg(not(target_arch = "wasm32"))]
use crate::connection::IpcConnection;
use crate::connection::{Connection, InProcConnection, LpInfo};

pub const DEFAULT_INTEREST_LIFETIME: Duration = Duration::from_millis(4000);

/// Local safety-net timeout for `fetch_*`. Set slightly above the
/// Interest lifetime to absorb forwarding and processing delay.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_millis(4500);

/// Per-Interest attempts for whole-object (RDR) fetches. Each metadata-discovery
/// and segment Interest is re-expressed up to this many times with back-off
/// before the fetch fails. Lossy/high-latency faces (connectionless named-radio
/// bearers — Wi-Fi Aware, BLE advertising) drop fragments and have multi-second
/// round-trips; a single one-shot Interest fails far too easily there. On a
/// healthy link the first attempt succeeds, so this costs nothing.
const OBJECT_FETCH_ATTEMPTS: u32 = 4;
/// Initial back-off between object-fetch retries (doubles each attempt).
const OBJECT_FETCH_BACKOFF: Duration = Duration::from_millis(300);

/// Consecutive *no-progress* stalls (each [`SEG_RECV_TIMEOUT`] long) before a
/// windowed fetch gives up. Counts only stalls with zero new segments delivered
/// — any arriving segment resets it — so a large transfer survives per-segment
/// loss (a single stuck segment retransmits each stall but doesn't abort the
/// whole object while others keep flowing), and only genuine silence
/// (~`SEG_MAX_STALLS` × 1.5s) ends it. (Previously a per-segment retransmit cap
/// aborted the whole object when ONE segment hit the cap — fatal for big files
/// over a lossy radio where an 8 KB Data is several NDNLP fragments.)
// Give-up budget = SEG_MAX_STALLS × SEG_RECV_TIMEOUT of *consecutive* no-progress
// time (any arriving segment resets it). Kept at ~18 s of tolerance so a brief
// Wi-Fi hiccup mid-transfer is ridden out, not aborted: when the per-stall
// timeout dropped 1500 ms → 400 ms (faster retransmit), this rose 12 → 45 to hold
// the same wall-clock tolerance (45 × 400 ms ≈ 18 s).
const SEG_MAX_STALLS: u32 = 45;
/// How long to wait for *any* segment Data before retransmitting the in-flight
/// window. Shorter than the Interest lifetime so a dropped segment is re-sent
/// promptly without stalling the whole transfer; on a healthy link Data arrives
/// far sooner, so this never fires spuriously.
// Loss-recovery floor: how long with NO segment arriving before the in-flight
// set is retransmitted. 1500 ms made each loss event cost a full 1.5 s of dead
// air (measured: 31 stalls ≈ 46 s of a 59 s transfer). Wi-Fi RTT (even with the
// producer-side seam round-trip) is tens of ms, so a far tighter floor recovers
// loss promptly; the bounded window keeps any spurious retransmit cheap.
const SEG_RECV_TIMEOUT: Duration = Duration::from_millis(400);

/// Which congestion-control strategy the object-fetch pipeline runs — the shared
/// [`ndn_transport::CongestionController`] variants. Default AIMD.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CongestionStrategy {
    /// AIMD with slow-start (the ndncatchunks `aimd` model).
    #[default]
    Aimd,
    /// CUBIC — more aggressive window growth on high bandwidth-delay paths.
    Cubic,
}

impl CongestionStrategy {
    /// Parse `"aimd"` / `"cubic"` (case-insensitive); `None` if unrecognized.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "aimd" => Some(Self::Aimd),
            "cubic" => Some(Self::Cubic),
            _ => None,
        }
    }

    fn controller(self) -> ndn_transport::CongestionController {
        // Window sizing for the bulk fetch over the InfraTunnel UDP face. History:
        // unbounded slow-start (ssthresh=f64::MAX) overshot to ~214 segments and
        // burst-lost on 2.4 GHz with a serial per-segment producer (the old
        // RemoteSigner serve), so it was clamped hard to 32. That regime is gone —
        // bulk is now served off-seam from the engine CS (engine-signed, no
        // per-segment round-trip), the UDP socket has a 4 MB SO_RCVBUF, and the
        // path is a real Wi-Fi link. So the small clamp was the throughput ceiling
        // (window/RTT). Open it up: a higher ceiling with a slow-start threshold
        // partway, so AIMD ramps to ~128 quickly then grows gently in congestion
        // avoidance toward the cap and backs off multiplicatively on real loss —
        // adapting to the path instead of a fixed small window. `max_window`
        // (256×8 KB = 2 MB in flight) stays within the engine CS that buffers the
        // relay's ahead-of-demand segments.
        const MAX_WINDOW: f64 = 48.0;
        const SLOW_START_THRESH: f64 = 48.0;
        match self {
            Self::Aimd => ndn_transport::CongestionController::aimd()
                .with_max_window(MAX_WINDOW)
                .with_ssthresh(SLOW_START_THRESH),
            Self::Cubic => ndn_transport::CongestionController::cubic()
                .with_max_window(MAX_WINDOW)
                .with_ssthresh(SLOW_START_THRESH),
        }
    }
}

/// Express Interests and fetch `Data`. Most apps use [`Node`](crate::Node)
/// (`node.fetch` / `node.object`); reach for `Consumer` for a custom connection
/// or congestion strategy.
pub struct Consumer {
    conn: Arc<dyn Connection>,
    cc_strategy: CongestionStrategy,
}

impl Consumer {
    /// Use the `connect` / `from_handle` shortcuts when the connection
    /// shape is fixed; reach for this when wrapping a custom transport.
    pub fn new(conn: Arc<dyn Connection>) -> Self {
        Self {
            conn,
            cc_strategy: CongestionStrategy::default(),
        }
    }

    /// Begin a composable object fetch — the fluent replacement for the
    /// `fetch_object*` family. Chain `.verify()` / `.hint()` / `.progress()` then
    /// a terminal `.fetch()` / `.stream()` / `.to_file()`.
    pub fn object(self, name: impl Into<Name>) -> crate::object::ObjectFetch {
        crate::object::ObjectFetch::new(self, name.into())
    }

    /// Choose the congestion-control strategy for object fetches (default AIMD).
    pub fn with_congestion_strategy(mut self, strategy: CongestionStrategy) -> Self {
        self.cc_strategy = strategy;
        self
    }

    /// Set the congestion-control strategy on an existing consumer.
    pub fn set_congestion_strategy(&mut self, strategy: CongestionStrategy) {
        self.cc_strategy = strategy;
    }

    pub fn congestion_strategy(&self) -> CongestionStrategy {
        self.cc_strategy
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub async fn connect(socket: impl AsRef<Path>) -> Result<Self, AppError> {
        let client = ForwarderClient::connect(socket)
            .await
            .map_err(AppError::Connection)?;
        Ok(Self::new(Arc::new(IpcConnection::new(client))))
    }

    /// In-process handle for an embedded engine.
    pub fn from_handle(handle: InProcHandle) -> Self {
        Self::new(Arc::new(InProcConnection::new(handle)))
    }

    /// The low-level fetch: returns raw, **unverified** `Data`. It is the
    /// primitive the verified surfaces and segment reassembly build on — in
    /// application code reach for those instead:
    /// [`fetch_verified`](Self::fetch_verified) (validates → `SafeData`) when you
    /// have a `Validator`, or [`fetch_unverified`](Self::fetch_unverified) to make
    /// the lack of verification explicit and force a choice. For hop limit, app
    /// parameters, or forwarding hints use [`Self::fetch_with`].
    pub async fn fetch(&mut self, name: impl Into<Name>) -> Result<Data, AppError> {
        let wire = InterestBuilder::new(name)
            .lifetime(DEFAULT_INTEREST_LIFETIME)
            .build();
        self.fetch_wire(wire, DEFAULT_TIMEOUT).await
    }

    /// Sends an LP `NextHopFaceId` header so the forwarder skips FIB
    /// lookup and uses `face_id` directly. Caller keeps `face_id`
    /// valid — an unknown id is dropped.
    pub async fn fetch_on(
        &mut self,
        face_id: ndn_transport::FaceId,
        name: impl Into<Name>,
    ) -> Result<Data, AppError> {
        let wire = InterestBuilder::new(name)
            .lifetime(DEFAULT_INTEREST_LIFETIME)
            .pin_face(face_id.0)
            .build();
        self.fetch_wire(wire, DEFAULT_TIMEOUT).await
    }

    /// Full [`InterestBuilder`] control plus face pin; see
    /// [`Self::fetch_on`] for the common case.
    pub async fn fetch_with_on(
        &mut self,
        face_id: ndn_transport::FaceId,
        builder: InterestBuilder,
    ) -> Result<Data, AppError> {
        let (wire, timeout) = builder.pin_face(face_id.0).build_with_timeout();
        self.fetch_wire(wire, timeout).await
    }

    /// Local wait derives from the builder's Interest lifetime + 500 ms.
    pub async fn fetch_with(&mut self, builder: InterestBuilder) -> Result<Data, AppError> {
        let (wire, timeout) = builder.build_with_timeout();
        self.fetch_wire(wire, timeout).await
    }

    /// `timeout` should be at least the Interest lifetime encoded in
    /// `wire`. Returns [`AppError::Nacked`] on a forwarder Nack **for this
    /// Interest**.
    ///
    /// ## Pairing contract (NS-6a)
    ///
    /// One outstanding Interest per `Consumer`: `&mut self` keeps fetches serial. The reply is
    /// paired to the sent Interest **by name** — exact, `CanBePrefix` descendant,
    /// implicit-digest, or parameters-digest, the Content-Store match rules — never by arrival
    /// order. Anything else landing on the face while waiting (typically a straggler reply to
    /// an earlier fetch that timed out client-side while its Interest was still pending in the
    /// PIT) is **discarded**, not mis-delivered: a late reply must never become the answer to
    /// the next question. (The NS-6 field bug: arrival-order pairing let one reordered reply
    /// silently shift every subsequent fetch by one, and downstream a stale reply acked a
    /// fresh seq — a permanent hole.) Nacks are paired the same way, by the name of their
    /// enclosed Interest. For multiple Interests in flight on one connection use a
    /// name-correlated pump ([`DemuxConnection::fetch_correlated`](crate::DemuxConnection) or
    /// the windowed object pipeline) rather than interleaving `fetch_wire` calls.
    pub async fn fetch_wire(&mut self, wire: Bytes, timeout: Duration) -> Result<Data, AppError> {
        // The sent Interest's matching identity (name + CanBePrefix), decoded up front so a
        // malformed wire fails loudly here instead of mispairing later.
        //
        // **Look inside an LP wrapper first.** `InterestBuilder::pin_face` — what
        // [`fetch_with_on`](Self::fetch_with_on) calls to steer an Interest out one face — encodes
        // NextHopFaceId, an NDNLPv2 field, so the wire it builds is an `LpPacket` (0x64) carrying
        // the Interest as its fragment. Decoding that as a bare Interest fails with
        // `UnknownPacketType(0x64)`, and because this runs *before* `conn.send`, the `?` returned
        // early and **nothing was ever transmitted** — `fetch_with_on` could not work for any
        // caller. Found through NLSR's Hello tests, whose neighbours stayed Inactive because every
        // Hello Interest died on this line.
        //
        // Only the pairing identity is unwrapped; `wire` is sent unchanged, because the LP header
        // is exactly what tells the forwarder which face to use.
        let interest = interest_identity(&wire).map_err(|e| AppError::Protocol(e.to_string()))?;
        let expected = (*interest.name).clone();
        let can_be_prefix = interest.selectors().can_be_prefix;

        self.conn.send(wire).await?;

        crate::rt::timeout(timeout, async {
            loop {
                let Some(reply) = self.conn.recv().await else {
                    return Err(AppError::Closed);
                };
                match judge_reply(&expected, can_be_prefix, reply) {
                    ReplyVerdict::Ours(data) => return Ok(*data),
                    ReplyVerdict::Nacked(reason) => return Err(AppError::Nacked { reason }),
                    ReplyVerdict::Straggler => continue,
                }
            }
        })
        .await
        .map_err(|_| AppError::Timeout)?
    }

    /// Like [`fetch`](Self::fetch) but also returns the received Data's
    /// NDNLPv2 local fields ([`LpInfo`]) — the `getTag<IncomingFaceIdTag>()`
    /// equivalent. `incoming_face_id` is populated when the consumer face has
    /// LocalFields enabled (or, for an embedded app, always — via the in-proc
    /// source tag-bag).
    pub async fn fetch_with_meta(
        &mut self,
        name: impl Into<Name>,
    ) -> Result<(Data, LpInfo), AppError> {
        let expected = name.into();
        let wire = InterestBuilder::new(expected.clone())
            .lifetime(DEFAULT_INTEREST_LIFETIME)
            .build();
        self.conn.send(wire).await?;
        // Same name-paired loop as `fetch_wire` (see its pairing contract): stragglers from
        // earlier timed-out fetches are discarded, never returned as this fetch's answer.
        crate::rt::timeout(DEFAULT_TIMEOUT, async {
            loop {
                let Some((reply, lp)) = self.conn.recv_with_meta().await else {
                    return Err(AppError::Closed);
                };
                match judge_reply(&expected, false, reply) {
                    ReplyVerdict::Ours(data) => return Ok((*data, lp)),
                    ReplyVerdict::Nacked(reason) => return Err(AppError::Nacked { reason }),
                    ReplyVerdict::Straggler => continue,
                }
            }
        })
        .await
        .map_err(|_| AppError::Timeout)?
    }

    /// Send without awaiting a reply; pairs with [`Self::recv_data`]
    /// for subscription-style flows where one Interest yields many
    /// Data packets. For one-shot fetches use [`Self::fetch_wire`].
    pub async fn send_raw(&self, wire: Bytes) -> Result<(), AppError> {
        self.conn.send(wire).await
    }

    /// Receive the next packet, LP-unwrapped and decoded as `Data`.
    /// Pairs with [`Self::send_raw`].
    pub async fn recv_data(&self) -> Result<Data, AppError> {
        let reply = self.conn.recv().await.ok_or(AppError::Closed)?;
        decode_data_lp(reply)
    }

    /// Receive the next packet as raw wire bytes, without LP-unwrapping or
    /// decoding. Used by [reflexive](crate::reflexive) flows that must tell a
    /// reverse Interest from the forward Data on the same face.
    pub async fn recv_raw(&self) -> Option<Bytes> {
        self.conn.recv().await
    }

    /// Subscribe to `prefix` with a **persistent Interest** — one Interest
    /// satisfied by many Data (`SubscriptionRequest` sub-TLV). Idle-cheap: the
    /// Interest pends in the PIT with no re-expression until its data-count /
    /// lifetime budget is spent, at which point [`Subscription::recv`]
    /// transparently re-expresses. The Zenoh-style streaming-downlink
    /// primitive; pair with a producer that streams Data under `prefix`.
    ///
    /// Borrows the consumer; the app face is dedicated to this stream while the
    /// `Subscription` lives — don't interleave `fetch`/`recv_data` on the same
    /// consumer. Re-subscribing (e.g. after the peer producer was down) reuses
    /// the same face: call `subscribe` again on the same consumer.
    pub async fn subscribe(
        &self,
        prefix: impl Into<Name>,
        opts: SubscribeOptions,
    ) -> Result<Subscription, AppError> {
        let mut sub = Subscription {
            conn: Arc::clone(&self.conn),
            prefix: prefix.into(),
            opts,
            remaining: 0,
            subscription_id: fresh_subscription_id(),
        };
        sub.express().await?;
        Ok(sub)
    }

    /// **The safe fetch.** Fetches and validates against `validator`, returning
    /// [`SafeData`] only for an *authenticated* packet. The recommended default
    /// whenever a trust schema applies.
    ///
    /// A `DigestSha256`-only packet (integrity, not identity) is rejected — a
    /// valid digest is not authentication. To accept integrity-only data on
    /// purpose, use `fetch_unverified(name).await?.verify_allowing_digest(...)`.
    pub async fn fetch_verified(
        &mut self,
        name: impl Into<Name>,
        validator: &Validator,
    ) -> Result<SafeData, AppError> {
        self.fetch_unverified(name)
            .await?
            .verify(validator)
            .await
            .map_err(|e| AppError::Unverified(e.to_string()))
    }

    /// Fetch a Data wrapped in [`Unverified<Data>`], forcing the caller to
    /// explicitly resolve it — `.verify(&validator)` for [`SafeData`] (the safe
    /// path), or `.trust_unchecked()` to accept it without verification on
    /// purpose (loud and greppable). The honest form of a raw [`fetch`](Self::fetch):
    /// you can't accidentally use unauthenticated data.
    pub async fn fetch_unverified(
        &mut self,
        name: impl Into<Name>,
    ) -> Result<Unverified<Data>, AppError> {
        Ok(Unverified::new(self.fetch(name).await?))
    }

    pub async fn get(&mut self, name: impl Into<Name>) -> Result<Bytes, AppError> {
        let data = self.fetch(name).await?;
        data.content()
            .map(|b| Bytes::copy_from_slice(b))
            .ok_or_else(|| AppError::Protocol("Data has no content".into()))
    }

    /// Sequential — a single [`Connection`] cannot correlate
    /// concurrent Interests to responses without PIT tokens. For true
    /// concurrency, use multiple `Consumer` instances and
    /// `tokio::join!`. Result order matches input.
    pub async fn fetch_all(&mut self, names: &[Name]) -> Vec<Result<Data, AppError>> {
        let mut results = Vec::with_capacity(names.len());
        for name in names {
            results.push(self.fetch(name.clone()).await);
        }
        results
    }

    /// Exponential back-off: `base_delay`, `2×base_delay`, … up to
    /// `max_attempts` total tries.
    pub async fn fetch_with_retry(
        &mut self,
        name: impl Into<Name>,
        max_attempts: u32,
        base_delay: std::time::Duration,
    ) -> Result<Data, AppError> {
        let name = name.into();
        let mut delay = base_delay;
        let attempts = max_attempts.max(1);
        let mut last_err = AppError::Timeout;
        for attempt in 0..attempts {
            match self.fetch(name.clone()).await {
                Ok(data) => return Ok(data),
                Err(e) => {
                    last_err = e;
                    if attempt + 1 < attempts {
                        crate::rt::sleep(delay).await;
                        delay *= 2;
                    }
                }
            }
        }
        Err(last_err)
    }

    /// RDR-style whole-object fetch. Issues `<name>/32=metadata` with
    /// `CanBePrefix` + `MustBeFresh`, decodes the resulting
    /// [`rdr::MetaData`](crate::rdr::MetaData) for the versioned
    /// prefix and `FinalBlockID`, then concatenates segments. Mirrors
    /// ndnd `std/object/client_consume.go:22`; pair with
    /// [`Producer::publish_object`](crate::Producer::publish_object).
    pub async fn fetch_object(&mut self, name: impl Into<Name>) -> Result<Bytes, AppError> {
        self.fetch_object_inner(name.into(), None, &[], |_, _| {})
            .await
    }

    /// Verified whole-object fetch — the **secure** RDR path: like
    /// [`fetch_object`](Self::fetch_object) but the metadata discovery Data AND
    /// every segment are verified against `validator` before their bytes are
    /// accepted, so the entire reassembled object is *authenticated*, not merely
    /// integrity-checked. Prefer [`VerifiedConsumer::fetch_object`] (the
    /// least-resistance safe verb); this exists so the raw consumer can do a
    /// verified object fetch too.
    #[deprecated(
        since = "0.1.0",
        note = "use `consumer.object(name).verify(v).fetch()`"
    )]
    pub async fn fetch_object_verified(
        &mut self,
        name: impl Into<Name>,
        validator: Arc<Validator>,
    ) -> Result<Bytes, AppError> {
        self.fetch_object_inner(name.into(), Some(validator), &[], |_, _| {})
            .await
    }

    /// Verified whole-object fetch steered by an NDNLPv2 **ForwardingHint** —
    /// like [`fetch_object_verified`](Self::fetch_object_verified) but every
    /// Interest (metadata discovery + each segment) carries `forwarding_hint`,
    /// so content named under a non-routable producer prefix is forwarded toward
    /// a routable delegation (e.g. `/ndn/node/<peerId>`) until it reaches the
    /// producer's region, where the hint is stripped and the Interest forwarded
    /// by name. The cross-peer fetch primitive for tap-to-share.
    #[deprecated(
        since = "0.1.0",
        note = "use `consumer.object(name).verify(v).hint([...]).fetch()`"
    )]
    pub async fn fetch_object_verified_hinted(
        &mut self,
        name: impl Into<Name>,
        validator: Arc<Validator>,
        forwarding_hint: &[Name],
    ) -> Result<Bytes, AppError> {
        self.fetch_object_inner(name.into(), Some(validator), forwarding_hint, |_, _| {})
            .await
    }

    /// Whole-object fetch with progress: `on_progress(received, total)` is
    /// called once with `(0, total)` as soon as the segment count is known, then
    /// after each segment lands. Drives a download progress bar.
    #[deprecated(
        since = "0.1.0",
        note = "use `consumer.object(name).verify(v).hint([...]).progress(cb).fetch()`"
    )]
    pub async fn fetch_object_verified_hinted_progress(
        &mut self,
        name: impl Into<Name>,
        validator: Arc<Validator>,
        forwarding_hint: &[Name],
        on_progress: impl FnMut(u64, u64),
    ) -> Result<Bytes, AppError> {
        self.fetch_object_inner(name.into(), Some(validator), forwarding_hint, on_progress)
            .await
    }

    async fn fetch_object_inner(
        &mut self,
        name: Name,
        validator: Option<Arc<Validator>>,
        forwarding_hint: &[Name],
        on_progress: impl FnMut(u64, u64),
    ) -> Result<Bytes, AppError> {
        let meta = self
            .fetch_metadata(&name, validator.clone(), forwarding_hint)
            .await?;
        let last_seg = meta
            .last_segment()
            .ok_or_else(|| AppError::Protocol("metadata FinalBlockID unparseable".into()))?;

        // In-memory reassembly: the sink stashes each segment into `chunks`,
        // joined in order once the window completes.
        let total = last_seg + 1;
        let mut chunks: Vec<Option<Bytes>> = (0..total).map(|_| None).collect();

        // FLIC manifest path: the (validated) metadata IS the signed manifest
        // root, so segments are served plain and authenticated by hash-match
        // against the listed SHA-256 — not by a per-segment signature. Pass no
        // per-segment validator; the manifest's one signature is the anchor.
        if let Some(hashes) = meta.segment_hashes.clone() {
            if hashes.len() as u64 != total {
                return Err(AppError::Protocol(format!(
                    "manifest lists {} hashes but object has {} segments",
                    hashes.len(),
                    total
                )));
            }
            self.fetch_segments_windowed(
                &meta.versioned_name,
                last_seg,
                None,
                forwarding_hint,
                |_| false,
                on_progress,
                |seg, bytes| {
                    let got = sha256(&bytes);
                    if got != hashes[seg as usize] {
                        return Err(AppError::Unverified(format!(
                            "segment {seg} hash does not match manifest"
                        )));
                    }
                    chunks[seg as usize] = Some(bytes);
                    Ok(())
                },
            )
            .await?;
            let mut out = bytes::BytesMut::new();
            for c in chunks {
                out.extend_from_slice(&c.unwrap_or_default());
            }
            return Ok(out.freeze());
        }

        self.fetch_segments_windowed(
            &meta.versioned_name,
            last_seg,
            validator,
            forwarding_hint,
            |_| false,
            on_progress,
            |seg, bytes| {
                chunks[seg as usize] = Some(bytes);
                Ok(())
            },
        )
        .await?;
        let mut out = bytes::BytesMut::new();
        for c in chunks {
            out.extend_from_slice(&c.unwrap_or_default());
        }
        Ok(out.freeze())
    }

    /// Streaming whole-object fetch: each segment's bytes are handed to
    /// `on_segment(seg_index, bytes)` as they arrive over the
    /// congestion-controlled windowed pipeline, so memory stays flat
    /// regardless of object size — the consumer counterpart to the producer's
    /// [`publish_object_from_file`](crate::Producer::publish_object_from_file).
    /// Cross-platform (no file/unix requirement).
    ///
    /// **Resume:** `already_have(seg)` returning `true` skips that segment (it
    /// is neither re-requested nor delivered to `on_segment`), so a transfer
    /// interrupted after persisting N segments continues from where it stopped
    /// instead of restarting at segment 0. Pass `|_| false` for a fresh fetch.
    ///
    /// `validator` authenticates every segment when present (the verified
    /// streaming path). Returns the object's producer-declared size in bytes
    /// (0 if unadvertised).
    pub async fn fetch_object_streaming(
        &mut self,
        name: impl Into<Name>,
        validator: Option<Arc<Validator>>,
        forwarding_hint: &[Name],
        already_have: impl Fn(u64) -> bool,
        on_progress: impl FnMut(u64, u64),
        on_segment: impl FnMut(u64, Bytes) -> Result<(), AppError>,
    ) -> Result<u64, AppError> {
        let name = name.into();
        let meta = self
            .fetch_metadata(&name, validator.clone(), forwarding_hint)
            .await?;
        let last_seg = meta
            .last_segment()
            .ok_or_else(|| AppError::Protocol("metadata FinalBlockID unparseable".into()))?;
        self.fetch_segments_windowed(
            &meta.versioned_name,
            last_seg,
            validator,
            forwarding_hint,
            already_have,
            on_progress,
            on_segment,
        )
        .await?;
        Ok(meta.size.unwrap_or(0))
    }

    /// Simplest streaming fetch: hand each segment to `on_segment` as it
    /// arrives — no validation, no resume. See
    /// [`fetch_object_streaming`](Self::fetch_object_streaming) for the
    /// verified / resumable form.
    #[deprecated(
        since = "0.1.0",
        note = "use `consumer.object(name).stream(|_| false, on_segment)`"
    )]
    pub async fn fetch_object_into(
        &mut self,
        name: impl Into<Name>,
        on_segment: impl FnMut(u64, Bytes) -> Result<(), AppError>,
    ) -> Result<u64, AppError> {
        self.fetch_object_streaming(name, None, &[], |_| false, |_, _| {}, on_segment)
            .await
    }

    /// Fetch + decode the object's RDR `<name>/32=metadata` (generous lifetime +
    /// retries — the first and most failure-prone round-trip over a lossy radio).
    async fn fetch_metadata(
        &mut self,
        name: &Name,
        validator: Option<Arc<Validator>>,
        forwarding_hint: &[Name],
    ) -> Result<crate::rdr::MetaData, AppError> {
        let meta_data = self
            .fetch_object_with_retry(|| {
                let mut b = InterestBuilder::new(crate::rdr::metadata_name(name))
                    .can_be_prefix()
                    .must_be_fresh()
                    .lifetime(DEFAULT_INTEREST_LIFETIME);
                if !forwarding_hint.is_empty() {
                    b = b.forwarding_hint(forwarding_hint.to_vec());
                }
                b
            })
            .await?;
        let meta_content = accept_content(meta_data, validator)
            .await?
            .ok_or_else(|| AppError::Protocol("metadata Data has no Content".into()))?;
        crate::rdr::MetaData::decode(meta_content)
    }

    /// Like [`fetch_object_verified_hinted`](Self::fetch_object_verified_hinted)
    /// but **streams** each verified segment to `file` at its byte offset
    /// (positioned writes) as it arrives, so an arbitrarily large object is
    /// received without ever holding it in memory. Returns the total bytes
    /// written. `on_progress(received, total)` drives a download bar.
    #[cfg(unix)]
    #[deprecated(
        since = "0.1.0",
        note = "use `consumer.object(name).verify(v).hint([...]).progress(cb).to_file(&file)`"
    )]
    pub async fn fetch_object_to_file_hinted_progress(
        &mut self,
        name: impl Into<Name>,
        validator: Arc<Validator>,
        forwarding_hint: &[Name],
        file: &std::fs::File,
        on_progress: impl FnMut(u64, u64),
    ) -> Result<u64, AppError> {
        use std::os::unix::fs::FileExt;
        let name = name.into();
        let meta = self
            .fetch_metadata(&name, Some(validator.clone()), forwarding_hint)
            .await?;
        let last_seg = meta
            .last_segment()
            .ok_or_else(|| AppError::Protocol("metadata FinalBlockID unparseable".into()))?;
        let seg_size = meta.segment_size.unwrap_or(8192);
        self.fetch_segments_windowed(
            &meta.versioned_name,
            last_seg,
            Some(validator),
            forwarding_hint,
            |_| false,
            on_progress,
            |seg, bytes| {
                file.write_all_at(&bytes, seg * seg_size)
                    .map_err(|e| AppError::Protocol(format!("write segment {seg}: {e}")))
            },
        )
        .await?;
        Ok(meta.size.unwrap_or(0))
    }

    /// Fetch segments `0..=last_seg` of `versioned` over a
    /// **congestion-controlled** pipeline driven by the shared
    /// [`ndn_transport::CongestionController`] (AIMD; the same controller
    /// ndn-iperf uses): the in-flight window grows on each acked segment and
    /// shrinks on a congestion signal (a stall/timeout or an NDNLPv2
    /// `CongestionMark`), so it self-tunes to the path instead of a fixed window. Each verified segment is
    /// handed to `sink` (reassemble in memory or stream to disk); out-of-order
    /// arrival is tolerated and a stall retransmits the in-flight set. The loop
    /// itself holds no payloads — only a per-segment `done` bitmap — so a
    /// streaming `sink` keeps memory flat regardless of object size.
    #[allow(clippy::too_many_arguments)]
    async fn fetch_segments_windowed(
        &self,
        versioned: &Name,
        last_seg: u64,
        validator: Option<Arc<Validator>>,
        forwarding_hint: &[Name],
        already_have: impl Fn(u64) -> bool,
        mut on_progress: impl FnMut(u64, u64),
        mut sink: impl FnMut(u64, Bytes) -> Result<(), AppError>,
    ) -> Result<(), AppError> {
        use std::collections::{HashMap, HashSet};
        let conn = Arc::clone(&self.conn);
        let total = last_seg + 1;
        // Resume support: segments the caller already has are pre-marked done
        // and never re-fetched, so an interrupted transfer continues instead of
        // restarting at segment 0.
        let mut done: Vec<bool> = (0..total).map(already_have).collect();
        let mut received: u64 = done.iter().filter(|&&d| d).count() as u64;
        on_progress(received, total);
        let mut stalls: u32 = 0; // consecutive no-progress stalls; reset on any new segment
        // Diagnostics: distinguish loss (high retransmits) from a stuck window.
        let mut retransmits: u64 = 0;
        let mut total_stalls: u64 = 0;
        let mut max_window: usize = 0;
        // Per-step wall-clock accumulators. `verify` was the serial bottleneck on
        // this recv loop — Ed25519 verification is CPU-bound and ran inline, so the
        // loop couldn't drain the socket while verifying. We now offload each
        // segment's verify to the runtime (across cores natively / concurrently on
        // wasm) and only `sink` + the `done`/congestion bookkeeping stay on the
        // loop. `recv_wait` is then the path floor; `sink` is the disk write.
        let mut recv_wait = std::time::Duration::ZERO;
        let mut sink_t = std::time::Duration::ZERO;
        let mut max_outstanding: usize = 0;
        let fetch_start = std::time::Instant::now();
        let mut next_send: u64 = 0;
        let mut inflight: HashMap<u64, u32> = HashMap::new(); // seg -> attempts
        let mut verifying: HashSet<u64> = HashSet::new(); // recv'd, verify in flight
        let mut outstanding: usize = 0;
        // Cap the verify backlog (≈ held Data) regardless of how far recv races
        // ahead of verify. In practice never hit — parallel verify outruns the
        // radio — but it bounds memory if the path ever bursts.
        const MAX_OUTSTANDING_VERIFY: usize = 256;
        // Completed verifies report (seg, congestion_marked, verified-content).
        type VerifyDone = (u64, bool, Result<Option<Bytes>, AppError>);
        let (vtx, mut vrx) = tokio::sync::mpsc::unbounded_channel::<VerifyDone>();
        // Self-tuning pipeline depth — the shared congestion controller (also
        // used by ndn-iperf), per the consumer's chosen strategy, so the fetch
        // adapts to the path instead of a fixed window.
        let mut cc = self.cc_strategy.controller();
        let limit = |cc: &ndn_transport::CongestionController| (cc.window() as usize).max(1);

        // Prime the window to the initial cwnd, skipping already-have segments.
        while next_send < total && inflight.len() < limit(&cc) {
            if done[next_send as usize] {
                next_send += 1;
                continue;
            }
            send_segment_interest(conn.as_ref(), versioned, next_send, forwarding_hint).await?;
            inflight.insert(next_send, 1);
            next_send += 1;
        }

        // Apply one completed verify: write the bytes, mark done, advance the
        // congestion window. A verify *failure* fails the whole fetch — authenticity
        // is not optional. (Macro, not a closure, so it can borrow the loop's locals
        // mutably and `?`-return from the function.)
        macro_rules! apply_verified {
            ($seg:expr, $marked:expr, $res:expr) => {{
                outstanding -= 1;
                verifying.remove(&$seg);
                let bytes = $res?.unwrap_or_default();
                if !done[$seg as usize] {
                    let s0 = std::time::Instant::now();
                    sink($seg, bytes)?;
                    sink_t += s0.elapsed();
                    done[$seg as usize] = true;
                    received += 1;
                    stalls = 0; // progress — reset the no-progress stall budget
                    if $marked {
                        cc.on_congestion_mark();
                    } else {
                        cc.on_data();
                    }
                    on_progress(received, total);
                }
            }};
        }

        while received < total {
            // Apply verifies that finished since the last turn (non-blocking), so
            // `done`/`received` and the window advance promptly.
            while let Ok((seg, marked, res)) = vrx.try_recv() {
                apply_verified!(seg, marked, res);
            }
            if received >= total {
                break;
            }
            // Refill the window. A segment in flight on the wire OR in verify is
            // not re-requested (tracked by `inflight` / `verifying`).
            max_window = max_window.max(limit(&cc));
            while next_send < total && inflight.len() < limit(&cc) {
                if done[next_send as usize] || verifying.contains(&next_send) {
                    next_send += 1;
                    continue;
                }
                send_segment_interest(conn.as_ref(), versioned, next_send, forwarding_hint).await?;
                inflight.insert(next_send, 1);
                next_send += 1;
            }

            let recv_t0 = std::time::Instant::now();
            let recv_res = crate::rt::timeout(SEG_RECV_TIMEOUT, conn.recv()).await;
            recv_wait += recv_t0.elapsed();
            match recv_res {
                Ok(Some(wire)) => {
                    // Peek the NDNLPv2 CongestionMark (early congestion signal)
                    // before unwrapping. Non-segment / Nack packets are ignored;
                    // the retransmit path recovers any real loss.
                    let marked = is_lp_packet(&wire)
                        && LpPacket::decode(wire.clone())
                            .is_ok_and(|lp| lp.congestion_mark.is_some());
                    let Ok(data) = decode_data_lp(wire) else {
                        continue;
                    };
                    let Some(seg) = data.name.components().last().and_then(|c| c.as_segment())
                    else {
                        continue;
                    };
                    // A fresh, in-range segment is off the wire: take it out of the
                    // in-flight set and hand verification to the runtime so the loop
                    // can keep draining the socket. Duplicates (already done, or a
                    // verify already in flight) are dropped.
                    if seg < total && !done[seg as usize] && !verifying.contains(&seg) {
                        inflight.remove(&seg);
                        // Back-pressure: if the verify backlog is full, block on one
                        // completion before queueing more, bounding held memory.
                        if outstanding >= MAX_OUTSTANDING_VERIFY
                            && let Some((s, m, r)) = vrx.recv().await
                        {
                            apply_verified!(s, m, r);
                        }
                        verifying.insert(seg);
                        outstanding += 1;
                        max_outstanding = max_outstanding.max(outstanding);
                        let v = validator.clone();
                        let tx = vtx.clone();
                        crate::rt::spawn(async move {
                            let res = accept_content(data, v).await;
                            let _ = tx.send((seg, marked, res));
                        });
                    }
                }
                Ok(None) => return Err(AppError::Closed),
                Err(_elapsed) => {
                    // Nothing arrived this interval. If verifies are still in flight,
                    // that's progress, not a stall — wait for the next completion
                    // instead of retransmitting.
                    if outstanding > 0 {
                        if let Some((seg, marked, res)) = vrx.recv().await {
                            apply_verified!(seg, marked, res);
                        }
                        continue;
                    }
                    // Genuine stall = loss: back off, then retransmit everything in
                    // flight (deduped by the forwarder/CS; a late duplicate Data is
                    // dropped above). Give up only after SEG_MAX_STALLS *consecutive*
                    // no-progress stalls — any arriving segment resets `stalls` — so a
                    // big transfer survives per-segment loss and the tail keeps being
                    // retried as long as it makes headway.
                    cc.on_timeout();
                    if inflight.is_empty() {
                        return Err(AppError::Timeout);
                    }
                    stalls += 1;
                    total_stalls += 1;
                    if stalls >= SEG_MAX_STALLS {
                        return Err(AppError::Timeout);
                    }
                    for seg in inflight.keys().copied().collect::<Vec<_>>() {
                        *inflight.get_mut(&seg).expect("seg in inflight") += 1;
                        retransmits += 1;
                        send_segment_interest(conn.as_ref(), versioned, seg, forwarding_hint)
                            .await?;
                    }
                }
            }
        }
        let elapsed_ms = fetch_start.elapsed().as_millis() as u64;
        tracing::debug!(
            target: "ndn_app::fetch",
            total, retransmits, total_stalls, max_window, max_outstanding,
            elapsed_ms,
            recv_wait_ms = recv_wait.as_millis() as u64,
            sink_ms = sink_t.as_millis() as u64,
            "windowed fetch done (verify off-loop across cores; recv_wait≈path floor)"
        );
        Ok(())
    }

    /// Issue an Interest built by `make` (rebuilt with a fresh nonce each try),
    /// re-expressing on timeout/Nack up to [`OBJECT_FETCH_ATTEMPTS`] times with
    /// exponential back-off. Resilience for the RDR fetch over lossy radios.
    async fn fetch_object_with_retry(
        &mut self,
        mut make: impl FnMut() -> InterestBuilder,
    ) -> Result<Data, AppError> {
        let mut delay = OBJECT_FETCH_BACKOFF;
        let mut last_err = AppError::Timeout;
        for attempt in 0..OBJECT_FETCH_ATTEMPTS {
            let (wire, timeout) = make().build_with_timeout();
            match self.fetch_wire(wire, timeout).await {
                Ok(data) => return Ok(data),
                Err(e) => {
                    last_err = e;
                    if attempt + 1 < OBJECT_FETCH_ATTEMPTS {
                        crate::rt::sleep(delay).await;
                        delay *= 2;
                    }
                }
            }
        }
        Err(last_err)
    }

    /// Companion to `Producer::publish_large`. Segment names are
    /// generic NameComponents holding ASCII-decimal indices
    /// (`/prefix/0`, `/prefix/1`, …); `/prefix/0`'s `FinalBlockId`
    /// fixes the total count.
    pub async fn fetch_segmented(&mut self, prefix: impl Into<Name>) -> Result<Bytes, AppError> {
        let prefix = prefix.into();

        let seg0_name = prefix.clone().append("0");
        let seg0 = self.fetch(seg0_name).await?;

        let last_seg = parse_final_block_id_seg(&seg0).unwrap_or(0);

        let seg0_content = seg0
            .content()
            .map(|b| Bytes::copy_from_slice(b))
            .unwrap_or_default();

        if last_seg == 0 {
            return Ok(seg0_content);
        }

        let mut chunks: Vec<Bytes> = Vec::with_capacity(last_seg + 1);
        chunks.push(seg0_content);
        for i in 1..=last_seg {
            let name = prefix.clone().append(i.to_string());
            let data = self.fetch(name).await?;
            chunks.push(
                data.content()
                    .map(|b| Bytes::copy_from_slice(b))
                    .unwrap_or_default(),
            );
        }

        let total: usize = chunks.iter().map(|c| c.len()).sum();
        let mut out = bytes::BytesMut::with_capacity(total);
        for chunk in chunks {
            out.extend_from_slice(&chunk);
        }
        Ok(out.freeze())
    }

    /// Alias for [`Self::fetch_verified`].
    pub async fn get_verified(
        &mut self,
        name: impl Into<Name>,
        validator: &ndn_security::Validator,
    ) -> Result<ndn_security::SafeData, AppError> {
        self.fetch_verified(name, validator).await
    }

    /// Decide trust **once** and get a consumer whose ordinary verbs are safe:
    /// [`VerifiedConsumer::fetch`] returns [`SafeData`], not raw `Data`. This is
    /// the recommended shape — configure a [`Validator`] up front (e.g.
    /// `keychain.validator()`) and you cannot then accidentally use unverified
    /// data. Drop back to the raw primitives with
    /// [`VerifiedConsumer::unverified`] when you mean to.
    pub fn verifying(self, validator: Validator) -> VerifiedConsumer {
        VerifiedConsumer {
            inner: self,
            validator: Arc::new(validator),
        }
    }
}

/// A `Consumer` that verifies every fetch against a pinned [`Validator`], so
/// the short verbs (`fetch`, `get`) return [`SafeData`] instead of raw `Data`.
/// Build one with [`Consumer::verifying`].
///
/// This is the safe path of least resistance: the obvious call is the verified
/// one. The unverified primitives remain reachable via [`unverified`](Self::unverified)
/// for the cases that genuinely need them (segment reassembly, deliberate
/// integrity-only acceptance).
pub struct VerifiedConsumer {
    inner: Consumer,
    validator: Arc<Validator>,
}

impl VerifiedConsumer {
    /// Fetch and verify against the pinned validator. Verification is not
    /// optional here — you get [`SafeData`] or an error.
    pub async fn fetch(&mut self, name: impl Into<Name>) -> Result<SafeData, AppError> {
        self.inner.fetch_verified(name, &self.validator).await
    }

    /// The pinned validator as a shared handle (cheap to clone).
    pub fn validator_arc(&self) -> Arc<Validator> {
        Arc::clone(&self.validator)
    }

    /// Verified content bytes (the [`fetch`](Self::fetch) payload).
    pub async fn get(&mut self, name: impl Into<Name>) -> Result<Bytes, AppError> {
        let safe = self.fetch(name).await?;
        safe.data()
            .content()
            .map(|b| Bytes::copy_from_slice(b))
            .ok_or_else(|| AppError::Protocol("Data has no content".into()))
    }

    /// Verified whole-object fetch — the secure RDR path. The metadata discovery
    /// Data and every segment are verified against the pinned validator before
    /// reassembly, so you get the object's bytes only if the *whole* object
    /// authenticates. The safe counterpart to [`Consumer::fetch_object`].
    pub async fn fetch_object(&mut self, name: impl Into<Name>) -> Result<Bytes, AppError> {
        #[allow(deprecated)] // the builder consumes Consumer by value; &mut self here
        self.inner
            .fetch_object_verified(name, Arc::clone(&self.validator))
            .await
    }

    /// The validator this consumer verifies against.
    pub fn validator(&self) -> &Validator {
        self.validator.as_ref()
    }

    /// Borrow the underlying raw `Consumer` for the unverified primitives
    /// (`fetch_object`, `fetch_unverified`, …). Reaching for this is the
    /// explicit "I am handling trust myself here" signal.
    pub fn unverified(&mut self) -> &mut Consumer {
        &mut self.inner
    }

    /// Drop the validator and recover the raw `Consumer`.
    pub fn into_inner(self) -> Consumer {
        self.inner
    }
}

/// LP-unwrap a received packet and decode it as `Data`, surfacing a Nack.
/// What one received frame is, relative to the Interest a fetch is waiting on.
enum ReplyVerdict {
    /// The Data that satisfies OUR Interest (name-matched).
    Ours(Box<Data>),
    /// A Nack whose enclosed Interest is OURS.
    Nacked(Option<ndn_packet::NackReason>),
    /// Not ours: a reply/Nack for some earlier, already-abandoned Interest (its client-side
    /// wait expired while the PIT entry lived on), or junk. Discarded — mis-delivering it is
    /// the NS-6 off-by-one.
    Straggler,
}

/// The Interest identity of an outbound wire, whether it is bare or LP-wrapped.
///
/// The mirror of [`judge_reply`]'s LP handling on the send side. A builder that sets any NDNLPv2
/// local field — today `pin_face` (NextHopFaceId), and anything added later — emits an `LpPacket`
/// whose fragment is the Interest, so a bare `Interest::decode` on the built wire is wrong for a
/// growing set of perfectly valid Interests. Unwrapping here keeps that a detail of encoding rather
/// than something every caller of `fetch_wire` has to know.
///
/// An LP frame that carries no fragment is a protocol error for this path: there is no Interest to
/// pair a reply against, so failing here beats sending something that can never be answered.
fn interest_identity(wire: &Bytes) -> Result<Interest, PacketError> {
    if is_lp_packet(wire) {
        let lp = LpPacket::decode(wire.clone())?;
        // 0x64 = LpPacket, per `ndn_packet::lp::is_lp_packet`; there is no exported constant.
        let fragment = lp.fragment.ok_or(PacketError::UnknownPacketType(0x64))?;
        return Interest::decode(fragment);
    }
    Interest::decode(wire.clone())
}

/// Classify one frame off the consumer face against the Interest identified by
/// `expected` (+ `can_be_prefix`). Nacks match by their enclosed Interest's name; an
/// unattributable Nack (no decodable enclosed Interest) is treated as a straggler — failing
/// slow (timeout) beats failing wrong.
fn judge_reply(expected: &Name, can_be_prefix: bool, reply: Bytes) -> ReplyVerdict {
    if is_lp_packet(&reply) {
        let Ok(lp) = LpPacket::decode(reply) else {
            return ReplyVerdict::Straggler;
        };
        if let Some(header) = lp.nack {
            let ours = lp
                .fragment
                .and_then(|f| Interest::decode(f).ok())
                .is_some_and(|i| *i.name == *expected);
            return if ours {
                ReplyVerdict::Nacked(header.reason)
            } else {
                tracing::debug!(%expected, "consumer: discarding straggler Nack");
                ReplyVerdict::Straggler
            };
        }
        let Some(fragment) = lp.fragment else {
            return ReplyVerdict::Straggler; // an idle/ack-only LP frame
        };
        return judge_data(expected, can_be_prefix, fragment);
    }
    judge_data(expected, can_be_prefix, reply)
}

fn judge_data(expected: &Name, can_be_prefix: bool, wire: Bytes) -> ReplyVerdict {
    let Ok(data) = Data::decode(wire) else {
        return ReplyVerdict::Straggler;
    };
    if data_matches(expected, can_be_prefix, &data) {
        ReplyVerdict::Ours(Box::new(data))
    } else {
        tracing::debug!(%expected, got = %data.name, "consumer: discarding straggler reply");
        ReplyVerdict::Straggler
    }
}

/// Does `data` satisfy an Interest for `expected` (+ `can_be_prefix`)? Mirrors the
/// Content-Store match rules (`LruCs::lookup`): a trailing `ImplicitSha256Digest` component
/// must verify against the Data wire; a trailing `ParametersSha256Digest` matches whether the
/// responder echoed it into the Data name or answered the bare name; `CanBePrefix` accepts any
/// descendant (or the name itself); otherwise exact equality.
fn data_matches(expected: &Name, can_be_prefix: bool, data: &Data) -> bool {
    let dname: &Name = &data.name;
    let comps = expected.components();
    let last_typ = comps.last().map(|c| c.typ);
    if last_typ == Some(ndn_packet::tlv_type::IMPLICIT_SHA256) {
        let bare = Name::from_components(comps[..comps.len() - 1].iter().cloned());
        return *dname == bare
            && comps.last().unwrap().value.as_ref() == data.implicit_digest().as_slice();
    }
    if last_typ == Some(ndn_packet::tlv_type::PARAMETERS_SHA256) {
        if dname == expected {
            return true;
        }
        let bare = Name::from_components(comps[..comps.len() - 1].iter().cloned());
        return *dname == bare;
    }
    if can_be_prefix {
        return dname.has_prefix(expected);
    }
    dname == expected
}

pub(crate) fn decode_data_lp(reply: Bytes) -> Result<Data, AppError> {
    if is_lp_packet(&reply)
        && let Ok(lp) = LpPacket::decode(reply.clone())
    {
        if let Some(header) = lp.nack {
            return Err(AppError::Nacked {
                reason: header.reason,
            });
        }
        if let Some(fragment) = lp.fragment {
            return Data::decode(fragment).map_err(|e| AppError::Protocol(e.to_string()));
        }
    }
    Data::decode(reply).map_err(|e| AppError::Protocol(e.to_string()))
}

/// Options for [`Consumer::subscribe`].
#[derive(Clone, Debug)]
pub struct SubscribeOptions {
    /// Data packets one persistent Interest may satisfy before the consumer
    /// re-expresses (the forwarder reaps the PIT entry once this is hit).
    pub max_data_count: u32,
    /// Persistent PIT lifetime; capped at [`MAX_PERSISTENT_LIFETIME_SECS`].
    pub lifetime: Duration,
    /// If no Data arrives within this window, the subscription re-expresses
    /// itself (fresh signature, same [`SubscriptionId`]). This is the trigger
    /// that recovers an upstream face flap the consumer cannot otherwise see
    /// (F15): the re-express re-establishes the broken upstream leg and splices
    /// the surviving budget. `None` disables it (re-express only on budget
    /// exhaustion).
    ///
    /// [`SubscriptionId`]: ndn_packet::SubscriptionRequest
    pub staleness: Option<Duration>,
}

impl Default for SubscribeOptions {
    fn default() -> Self {
        Self {
            max_data_count: 1024,
            lifetime: Duration::from_secs(600),
            staleness: Some(Duration::from_secs(30)),
        }
    }
}

/// A persistent-Interest subscription: one Interest satisfied by many Data.
/// Created by [`Consumer::subscribe`].
pub struct Subscription {
    conn: Arc<dyn Connection>,
    prefix: Name,
    opts: SubscribeOptions,
    /// Data packets the current persistent Interest may still satisfy.
    remaining: u32,
    /// Stable correlation handle reused on every re-expression so the
    /// forwarder can splice surviving budget after a face flap (F15).
    subscription_id: Bytes,
}

/// Mint a process-unique, stable SubscriptionId (16 bytes: start-timestamp ‖
/// monotonic counter). It is a correlation handle, not a secret — uniqueness,
/// not unpredictability, is what matters, so no CSPRNG dependency is needed.
fn fresh_subscription_id() -> Bytes {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let t = web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let mut id = [0u8; 16];
    id[0..8].copy_from_slice(&t.to_be_bytes());
    id[8..16].copy_from_slice(&n.to_be_bytes());
    Bytes::copy_from_slice(&id)
}

/// Build the persistent Interest wire for `prefix` carrying a
/// `SubscriptionRequest` in ApplicationParameters (CanBePrefix + MustBeFresh).
///
/// **Signed** (`DigestSha256`, with anti-replay `SignatureNonce`/`SignatureTime`):
/// the forwarder only installs *true* persistence (one Interest → many Data) for
/// a validated, signed subscription Interest — an unsigned one degrades to
/// one-shot (`ndn-engine` `check_persistent`). DigestSha256 keys no identity; a
/// trust-schema-bearing deployment can swap in a real signer.
fn build_persistent_interest(
    prefix: &Name,
    opts: &SubscribeOptions,
    subscription_id: &Bytes,
) -> Bytes {
    let secs = (opts.lifetime.as_secs() as u32).min(MAX_PERSISTENT_LIFETIME_SECS);
    let sr = SubscriptionRequest {
        version: 1,
        max_data_count: opts.max_data_count,
        max_lifetime_secs: secs,
        subscription_id: Some(subscription_id.clone()),
    };
    InterestBuilder::new(prefix.clone())
        .can_be_prefix()
        .must_be_fresh()
        .lifetime(opts.lifetime)
        .app_parameters(sr.encode().to_vec())
        .sign_digest_sha256()
}

impl Subscription {
    async fn express(&mut self) -> Result<(), AppError> {
        self.conn
            .send(build_persistent_interest(
                &self.prefix,
                &self.opts,
                &self.subscription_id,
            ))
            .await?;
        self.remaining = self.opts.max_data_count.max(1);
        Ok(())
    }

    /// Next streamed Data. Re-expresses the persistent Interest automatically
    /// once the data-count budget is exhausted, and — when `opts.staleness` is
    /// set — also if no Data arrives within that window, so the subscription
    /// recovers an upstream face flap by re-establishing the broken leg with a
    /// fresh re-express carrying the same SubscriptionId (F15).
    pub async fn recv(&mut self) -> Result<Data, AppError> {
        loop {
            if self.remaining == 0 {
                self.express().await?;
            }
            let reply = match self.opts.staleness {
                Some(window) => match crate::rt::timeout(window, self.conn.recv()).await {
                    Ok(r) => r,
                    // Silence past the staleness window: re-express (fresh
                    // signature, same SubscriptionId) and keep waiting.
                    Err(_elapsed) => {
                        self.express().await?;
                        continue;
                    }
                },
                None => self.conn.recv().await,
            };
            let reply = reply.ok_or(AppError::Closed)?;
            self.remaining = self.remaining.saturating_sub(1);
            return decode_data_lp(reply);
        }
    }

    pub fn prefix(&self) -> &Name {
        &self.prefix
    }
}

/// Decode `FinalBlockId` as a generic NameComponent (TLV type 0x08)
/// holding an ASCII-decimal segment index. Returns `None` on absence
/// or parse failure. Assumes short components (type + length both
/// single-byte).
fn parse_final_block_id_seg(data: &Data) -> Option<usize> {
    let meta = data.meta_info()?;
    let fbi = meta.final_block_id.as_ref()?;

    if fbi.len() < 2 {
        return None;
    }
    let len = fbi[1] as usize;
    let value_start = 2;
    if fbi.len() < value_start + len {
        return None;
    }
    let value = &fbi[value_start..value_start + len];
    std::str::from_utf8(value).ok()?.parse::<usize>().ok()
}

#[cfg(test)]
mod subscription_tests {
    use super::*;
    use ndn_packet::Interest;

    /// A digest-only (no trusted identity) Data verified against a validator
    /// must surface as `AppError::Unverified`, NOT `AppError::Protocol` — the
    /// taxonomy distinction apps branch on (trust event vs malformed bytes).
    #[tokio::test]
    async fn verification_failure_is_unverified_not_protocol() {
        use ndn_packet::encode::DataBuilder;
        use ndn_security::{TrustSchema, Validator};

        let wire = DataBuilder::new("/x/y".parse::<Name>().unwrap(), b"hi").build();
        let data = Data::decode(wire).unwrap();
        let validator = Arc::new(Validator::new(TrustSchema::new()));

        let err = accept_content(data, Some(validator)).await.unwrap_err();
        assert!(
            matches!(err, AppError::Unverified(_)),
            "expected Unverified, got {err:?}"
        );
    }

    /// **A face-pinned Interest must actually reach the wire.** `pin_face` sets NextHopFaceId, an
    /// NDNLPv2 field, so the built wire is an `LpPacket` (0x64) wrapping the Interest. `fetch_wire`
    /// decoded that as a bare Interest *before* `conn.send`, so every `fetch_with_on` call returned
    /// `Protocol("unknown packet type 0x64")` having transmitted **nothing** — the method was inert
    /// for every caller. It surfaced three layers away, as NLSR Hello neighbours stuck `Inactive`.
    ///
    /// This asserts on the seam — that the connection was handed a frame and that a reply pairs —
    /// not on the helper that unwraps the LP. A first draft of this test called `interest_identity`
    /// directly and **passed against the defect**, because the bug is which decode `fetch_wire`
    /// calls, not whether a correct decode exists.
    #[tokio::test]
    async fn fetch_with_on_transmits_a_face_pinned_interest() {
        use crate::Connection;
        use ndn_packet::encode::DataBuilder;
        use std::sync::Mutex as StdMutex;

        /// Records what it was asked to send, and answers with a Data under the sent name.
        struct SpyConn {
            sent: StdMutex<Vec<Bytes>>,
            inbox: StdMutex<Vec<Bytes>>,
        }

        #[async_trait::async_trait]
        impl Connection for SpyConn {
            async fn send(&self, wire: Bytes) -> Result<(), AppError> {
                self.sent.lock().unwrap().push(wire.clone());
                // Reply as a forwarder would: unwrap LP, answer the enclosed Interest.
                let inner = if is_lp_packet(&wire) {
                    LpPacket::decode(wire.clone())
                        .ok()
                        .and_then(|lp| lp.fragment)
                        .unwrap_or(wire)
                } else {
                    wire
                };
                if let Ok(i) = Interest::decode(inner) {
                    let reply = DataBuilder::new((*i.name).clone(), b"INFO").build();
                    self.inbox.lock().unwrap().push(reply);
                }
                Ok(())
            }
            async fn recv(&self) -> Option<Bytes> {
                loop {
                    if let Some(b) = self.inbox.lock().unwrap().pop() {
                        return Some(b);
                    }
                    crate::rt::sleep(Duration::from_millis(1)).await;
                }
            }
            async fn register_prefix(&self, _prefix: &Name) -> Result<(), AppError> {
                Ok(())
            }
        }

        let conn = Arc::new(SpyConn {
            sent: StdMutex::new(Vec::new()),
            inbox: StdMutex::new(Vec::new()),
        });
        let mut consumer = Consumer::new(conn.clone() as Arc<dyn Connection>);
        let name: Name = "/ndn/test/B/nlsr/INFO".parse().unwrap();

        let got = consumer
            .fetch_with_on(
                ndn_transport::FaceId(42),
                InterestBuilder::new(name.clone())
                    .lifetime(Duration::from_secs(1))
                    .must_be_fresh()
                    .can_be_prefix(),
            )
            .await;

        let sent = conn.sent.lock().unwrap().clone();
        assert_eq!(
            sent.len(),
            1,
            "fetch_with_on must transmit; sending nothing at all was the defect (result: {:?})",
            got.as_ref().map(|_| "Ok").map_err(|e| e.to_string())
        );
        assert!(
            is_lp_packet(&sent[0]),
            "and it must go out still LP-wrapped — the header is what pins the face"
        );
        assert_eq!(
            *got.expect("a matching Data must pair back").name,
            name,
            "the reply pairs against the name inside the wrapper"
        );
    }

    #[test]
    fn persistent_interest_carries_subscription_request() {
        let prefix = Name::from("/vpn/downlink");
        let opts = SubscribeOptions {
            max_data_count: 256,
            lifetime: Duration::from_secs(120),
            ..SubscribeOptions::default()
        };
        let id = fresh_subscription_id();
        let wire = build_persistent_interest(&prefix, &opts, &id);
        let interest = Interest::decode(wire).expect("valid interest");

        assert!(interest.name.has_prefix(&prefix));

        let params = interest.app_parameters().expect("has app parameters");
        let sr = SubscriptionRequest::find_in(params).expect("carries SubscriptionRequest");
        assert_eq!(sr.version, 1);
        assert_eq!(sr.max_data_count, 256);
        assert_eq!(sr.max_lifetime_secs, 120);
        assert_eq!(sr.subscription_id.as_ref(), Some(&id), "id rides the wire");
    }

    #[test]
    fn subscription_id_is_stable_across_re_expression() {
        // The same Subscription reuses one id on every express() so the
        // forwarder can correlate a re-attach after a face flap (F15).
        let id = fresh_subscription_id();
        let opts = SubscribeOptions::default();
        let a = build_persistent_interest(&Name::from("/s"), &opts, &id);
        let b = build_persistent_interest(&Name::from("/s"), &opts, &id);
        let ida =
            SubscriptionRequest::find_in(Interest::decode(a).unwrap().app_parameters().unwrap())
                .unwrap()
                .subscription_id;
        let idb =
            SubscriptionRequest::find_in(Interest::decode(b).unwrap().app_parameters().unwrap())
                .unwrap()
                .subscription_id;
        assert_eq!(ida, idb);
        assert_eq!(ida, Some(id));
    }

    #[test]
    fn fresh_subscription_ids_are_unique() {
        assert_ne!(fresh_subscription_id(), fresh_subscription_id());
    }

    /// A `Connection` that swallows the first subscription Interest (recv hangs)
    /// and only delivers Data once it has seen a *second* send — i.e. after the
    /// subscription re-expresses on staleness.
    struct StaleConn {
        sends: std::sync::atomic::AtomicUsize,
        data: Bytes,
    }

    #[async_trait::async_trait]
    impl Connection for StaleConn {
        async fn send(&self, _wire: Bytes) -> Result<(), AppError> {
            self.sends.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
        async fn recv(&self) -> Option<Bytes> {
            if self.sends.load(std::sync::atomic::Ordering::SeqCst) >= 2 {
                Some(self.data.clone())
            } else {
                // No Data on the first express → forces the staleness timeout.
                std::future::pending().await
            }
        }
        async fn register_prefix(&self, _prefix: &Name) -> Result<(), AppError> {
            Ok(())
        }
    }

    fn make_data_wire() -> Bytes {
        use ndn_tlv::TlvWriter;
        let nc = {
            let mut w = TlvWriter::new();
            w.write_tlv(0x08, b"s");
            w.finish()
        };
        let name = {
            let mut w = TlvWriter::new();
            w.write_tlv(0x07, &nc);
            w.finish()
        };
        let mut w = TlvWriter::new();
        w.write_tlv(0x06, &name);
        w.finish()
    }

    /// F15 B2 trigger: when no Data arrives within the staleness window, the
    /// subscription re-expresses itself (re-establishing a flapped upstream
    /// leg). One re-express is enough here to unblock delivery.
    #[tokio::test]
    async fn recv_reexpresses_on_staleness() {
        let conn = Arc::new(StaleConn {
            sends: std::sync::atomic::AtomicUsize::new(0),
            data: make_data_wire(),
        });
        let mut sub = Subscription {
            conn: conn.clone(),
            prefix: Name::from("/s"),
            opts: SubscribeOptions {
                staleness: Some(Duration::from_millis(20)),
                ..SubscribeOptions::default()
            },
            remaining: 0,
            subscription_id: fresh_subscription_id(),
        };
        let data = sub.recv().await.expect("Data delivered after re-express");
        assert!(data.name.to_string().contains('s'));
        assert_eq!(
            conn.sends.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "subscription must re-express exactly once on staleness"
        );
    }

    /// A `Connection` that answers a metadata Interest with an RDR `MetaData`
    /// and each segment Interest with `[seg; 10]`, so a windowed fetch can be
    /// driven without a real engine. Out-of-order tolerance is exercised by the
    /// pipeline issuing many Interests before draining replies.
    struct SegServer {
        versioned: Name,
        last_seg: u64,
        metadata_name: Name,
        q: std::sync::Mutex<std::collections::VecDeque<Bytes>>,
    }

    #[async_trait::async_trait]
    impl Connection for SegServer {
        async fn send(&self, wire: Bytes) -> Result<(), AppError> {
            use ndn_packet::encode::DataBuilder;
            let interest = Interest::decode(wire).map_err(|e| AppError::Protocol(e.to_string()))?;
            let Some(last) = interest.name.components().last().cloned() else {
                return Ok(());
            };
            if last.typ == 0x20 && last.value.as_ref() == b"metadata" {
                let nni = crate::rdr::encode_nni_be(self.last_seg);
                let mut fbi = vec![0x32u8, nni.len() as u8];
                fbi.extend_from_slice(&nni);
                let meta = crate::rdr::MetaData {
                    versioned_name: self.versioned.clone(),
                    final_block_id: Bytes::from(fbi),
                    segment_size: Some(10),
                    size: Some((self.last_seg + 1) * 10),
                    segment_hashes: None,
                };
                let data = DataBuilder::new(self.metadata_name.clone(), &meta.encode()).build();
                self.q.lock().unwrap().push_back(data);
            } else if let Some(seg) = last.as_segment()
                && seg <= self.last_seg
            {
                let data =
                    DataBuilder::new(self.versioned.clone().append_segment(seg), &[seg as u8; 10])
                        .build();
                self.q.lock().unwrap().push_back(data);
            }
            Ok(())
        }
        async fn recv(&self) -> Option<Bytes> {
            loop {
                if let Some(d) = self.q.lock().unwrap().pop_front() {
                    return Some(d);
                }
                tokio::task::yield_now().await;
            }
        }
        async fn register_prefix(&self, _: &Name) -> Result<(), AppError> {
            Ok(())
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn windowed_fetch_streams_to_file_at_offsets() {
        use std::os::unix::fs::FileExt;
        // 50 segments of 10 bytes, segment i = [i; 10]; stream them to a file at
        // offset i*10 and verify the file is byte-correct (no in-memory buffer).
        let object: Name = "/peer/file/f2".parse().unwrap();
        let versioned = object.clone().append_version(9);
        let server = Arc::new(SegServer {
            versioned: versioned.clone(),
            last_seg: 49,
            metadata_name: crate::rdr::metadata_name(&object),
            q: std::sync::Mutex::new(std::collections::VecDeque::new()),
        });
        let consumer = Consumer::new(server);

        let path = std::env::temp_dir().join("ndn_recv_stream_test.bin");
        let out = std::fs::File::create(&path).unwrap();
        consumer
            .fetch_segments_windowed(
                &versioned,
                49,
                None,
                &[],
                |_| false,
                |_, _| {},
                |seg, bytes| {
                    out.write_all_at(&bytes, seg * 10)
                        .map_err(|e| AppError::Protocol(e.to_string()))
                },
            )
            .await
            .expect("streamed fetch");

        let mut buf = vec![0u8; 500];
        std::fs::File::open(&path)
            .unwrap()
            .read_exact_at(&mut buf, 0)
            .unwrap();
        for i in 0..50u64 {
            let s = i as usize * 10;
            assert_eq!(
                &buf[s..s + 10],
                &vec![i as u8; 10][..],
                "segment {i} at offset"
            );
        }
        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn windowed_fetch_reassembles_multi_segment_object() {
        let object: Name = "/peer/file/f1".parse().unwrap();
        let versioned = object.clone().append_version(7);
        // 100 segments > FETCH_WINDOW, so the pipeline must slide and refill.
        let server = Arc::new(SegServer {
            versioned,
            last_seg: 99,
            metadata_name: crate::rdr::metadata_name(&object),
            q: std::sync::Mutex::new(std::collections::VecDeque::new()),
        });
        let mut consumer = Consumer::new(server);
        let bytes = consumer.fetch_object(object).await.expect("windowed fetch");
        assert_eq!(bytes.len(), 1000, "100 segments x 10 bytes reassembled");
        for i in 0..100u64 {
            let s = i as usize * 10;
            assert_eq!(
                &bytes[s..s + 10],
                &vec![i as u8; 10][..],
                "segment {i} must land at the right offset (in-order reassembly)"
            );
        }
    }

    #[tokio::test]
    #[allow(deprecated)] // exercises the deprecated fetch_object_into compat path
    async fn fetch_object_into_streams_every_segment() {
        let object: Name = "/peer/file/stream".parse().unwrap();
        let versioned = object.clone().append_version(3);
        let server = Arc::new(SegServer {
            versioned,
            last_seg: 49,
            metadata_name: crate::rdr::metadata_name(&object),
            q: std::sync::Mutex::new(std::collections::VecDeque::new()),
        });
        let mut consumer = Consumer::new(server);

        type Collected = Arc<std::sync::Mutex<Vec<(u64, Vec<u8>)>>>;
        let got: Collected = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = Arc::clone(&got);
        let size = consumer
            .fetch_object_into(object, move |seg, bytes| {
                sink.lock().unwrap().push((seg, bytes.to_vec()));
                Ok(())
            })
            .await
            .expect("streaming fetch");
        assert_eq!(size, 500, "declared size = 50 segments x 10 bytes");

        let mut got = got.lock().unwrap().clone();
        got.sort_by_key(|(s, _)| *s);
        assert_eq!(got.len(), 50);
        for (i, (seg, bytes)) in got.iter().enumerate() {
            assert_eq!(*seg, i as u64);
            assert_eq!(bytes, &vec![i as u8; 10]);
        }
    }

    #[tokio::test]
    async fn fetch_object_streaming_resumes_skipping_have_segments() {
        let object: Name = "/peer/file/resume".parse().unwrap();
        let versioned = object.clone().append_version(5);
        let server = Arc::new(SegServer {
            versioned,
            last_seg: 49,
            metadata_name: crate::rdr::metadata_name(&object),
            q: std::sync::Mutex::new(std::collections::VecDeque::new()),
        });
        let mut consumer = Consumer::new(server);

        // Pretend segments 0..25 were already persisted by an interrupted run.
        let delivered: Arc<std::sync::Mutex<Vec<u64>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = Arc::clone(&delivered);
        consumer
            .fetch_object_streaming(
                object,
                None,
                &[],
                |seg| seg < 25,
                |_, _| {},
                move |seg, _bytes| {
                    sink.lock().unwrap().push(seg);
                    Ok(())
                },
            )
            .await
            .expect("resumed fetch");

        let delivered = delivered.lock().unwrap().clone();
        assert_eq!(delivered.len(), 25, "only the missing tail is fetched");
        assert!(
            delivered.iter().all(|&s| (25..50).contains(&s)),
            "no already-have segment should be re-delivered: {delivered:?}"
        );
    }

    #[test]
    fn lifetime_capped_at_max() {
        let opts = SubscribeOptions {
            max_data_count: 1,
            lifetime: Duration::from_secs(100_000),
            ..SubscribeOptions::default()
        };
        let wire = build_persistent_interest(&Name::from("/x"), &opts, &fresh_subscription_id());
        let interest = Interest::decode(wire).unwrap();
        let sr = SubscriptionRequest::find_in(interest.app_parameters().unwrap()).unwrap();
        assert_eq!(sr.max_lifetime_secs, MAX_PERSISTENT_LIFETIME_SECS);
    }
}

#[cfg(test)]
mod fetch_pairing_tests {
    //! NS-6a: `fetch_wire` pairs request→response BY NAME, never by arrival order. The field
    //! bug: a late reply to an earlier client-side-timed-out fetch (its Interest still pending
    //! in the PIT) landed as the next `recv()` and was returned as the answer to the NEXT
    //! fetch — shifting every subsequent pairing by one, silently. These tests drive the
    //! straggler cases directly; the end-to-end gate (a real held reply over a real fabric) is
    //! ndn-sim's `tests/field_faults.rs::held_reply_shifts_arrival_order_pairing_by_one`.

    use super::*;
    use ndn_packet::encode::DataBuilder;
    use ndn_packet::lp::encode_lp_nack;
    use std::collections::VecDeque;

    /// A `Connection` that replays a fixed inbound script, then pends forever.
    struct ScriptedConn {
        q: std::sync::Mutex<VecDeque<Bytes>>,
    }

    impl ScriptedConn {
        fn new(frames: impl IntoIterator<Item = Bytes>) -> Arc<Self> {
            Arc::new(Self {
                q: std::sync::Mutex::new(frames.into_iter().collect()),
            })
        }
    }

    #[async_trait::async_trait]
    impl Connection for ScriptedConn {
        async fn send(&self, _wire: Bytes) -> Result<(), AppError> {
            Ok(())
        }
        async fn recv(&self) -> Option<Bytes> {
            let next = self.q.lock().unwrap().pop_front();
            match next {
                Some(f) => Some(f),
                None => std::future::pending().await,
            }
        }
        async fn register_prefix(&self, _prefix: &Name) -> Result<(), AppError> {
            Ok(())
        }
    }

    fn data(name: &str) -> Bytes {
        DataBuilder::new(name.parse::<Name>().unwrap(), name.as_bytes()).build()
    }

    fn interest(name: &str) -> Bytes {
        InterestBuilder::new(name.parse::<Name>().unwrap())
            .lifetime(Duration::from_secs(4))
            .build()
    }

    /// THE STRAGGLER CASE: a late reply to a previous fetch arrives first; the current fetch
    /// must skip it and return its OWN reply. (Pre-fix, this returned /x/1 as /x/2's answer.)
    #[tokio::test]
    async fn straggler_reply_is_discarded_not_mispaired() {
        let conn = ScriptedConn::new([data("/x/1"), data("/x/2")]);
        let mut c = Consumer::new(conn);
        let got = c
            .fetch_wire(interest("/x/2"), Duration::from_secs(1))
            .await
            .expect("the real reply follows the straggler");
        assert_eq!(got.name.to_string(), "/x/2", "never the straggler");
    }

    /// Only a straggler arrives: the fetch must TIME OUT (fail slow), not return the wrong
    /// packet (fail wrong).
    #[tokio::test]
    async fn straggler_only_times_out() {
        let conn = ScriptedConn::new([data("/x/1")]);
        let mut c = Consumer::new(conn);
        let err = c
            .fetch_wire(interest("/x/2"), Duration::from_millis(200))
            .await
            .expect_err("a mismatched reply is not an answer");
        assert!(matches!(err, AppError::Timeout), "got {err:?}");
    }

    /// A Nack for a DEAD Interest (the straggler's) is discarded; the live fetch still gets
    /// its own Data.
    #[tokio::test]
    async fn nack_for_a_dead_interest_is_discarded() {
        let stale_nack = encode_lp_nack(ndn_packet::NackReason::NoRoute, &interest("/x/1"));
        let conn = ScriptedConn::new([stale_nack, data("/x/2")]);
        let mut c = Consumer::new(conn);
        let got = c
            .fetch_wire(interest("/x/2"), Duration::from_secs(1))
            .await
            .expect("the stale Nack must not kill this fetch");
        assert_eq!(got.name.to_string(), "/x/2");
    }

    /// A Nack for THIS Interest still surfaces as `AppError::Nacked`.
    #[tokio::test]
    async fn nack_for_this_interest_surfaces() {
        let nack = encode_lp_nack(ndn_packet::NackReason::NoRoute, &interest("/x/2"));
        let conn = ScriptedConn::new([nack]);
        let mut c = Consumer::new(conn);
        let err = c
            .fetch_wire(interest("/x/2"), Duration::from_secs(1))
            .await
            .expect_err("our own Nack is an answer");
        assert!(matches!(err, AppError::Nacked { .. }), "got {err:?}");
    }

    /// `CanBePrefix` accepts a descendant (the segmented-publication shape,
    /// `<name>/v=0/seg=0`) — but still discards an unrelated straggler first.
    #[tokio::test]
    async fn can_be_prefix_matches_descendants_only() {
        let conn = ScriptedConn::new([data("/y/9"), data("/x/2/v=0/seg=0")]);
        let mut c = Consumer::new(conn);
        let wire = InterestBuilder::new("/x/2".parse::<Name>().unwrap())
            .lifetime(Duration::from_secs(4))
            .can_be_prefix()
            .build();
        let got = c
            .fetch_wire(wire, Duration::from_secs(1))
            .await
            .expect("descendant satisfies CanBePrefix");
        assert!(got.name.to_string().starts_with("/x/2"), "got {}", got.name);
    }
}
