#[cfg(not(target_arch = "wasm32"))]
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;

#[cfg(target_arch = "wasm32")]
use ndn_face_local::InProcHandle;
#[cfg(not(target_arch = "wasm32"))]
use ndn_face_native::local::InProcHandle;
#[cfg(not(target_arch = "wasm32"))]
use ndn_ipc::ForwarderClient;
use ndn_packet::encode::InterestBuilder;
use ndn_packet::lp::{LpPacket, is_lp_packet};
use ndn_packet::{Data, MAX_PERSISTENT_LIFETIME_SECS, Name, SubscriptionRequest};
use ndn_security::{SafeData, Unverified, Validator};

use crate::AppError;

/// Verify a fetched `Data` against `validator` (when present) and return its
/// content bytes. With a validator the Data must authenticate (signature checked
/// against the pinned anchor) or this errors; without one, content is taken
/// as-is (integrity only). `None` when the Data carries no Content. The single
/// choke point both the unverified and verified RDR object paths route through.
async fn accept_content(
    data: Data,
    validator: Option<&Validator>,
) -> Result<Option<Bytes>, AppError> {
    match validator {
        Some(v) => {
            let safe = Unverified::new(data)
                .verify(v)
                .await
                .map_err(|e| AppError::Protocol(e.to_string()))?;
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

pub struct Consumer {
    conn: Arc<dyn Connection>,
}

impl Consumer {
    /// Use the `connect` / `from_handle` shortcuts when the connection
    /// shape is fixed; reach for this when wrapping a custom transport.
    pub fn new(conn: Arc<dyn Connection>) -> Self {
        Self { conn }
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub async fn connect(socket: impl AsRef<Path>) -> Result<Self, AppError> {
        let client = ForwarderClient::connect(socket)
            .await
            .map_err(AppError::Connection)?;
        Ok(Self {
            conn: Arc::new(IpcConnection::new(client)),
        })
    }

    /// In-process handle for an embedded engine.
    pub fn from_handle(handle: InProcHandle) -> Self {
        Self {
            conn: Arc::new(InProcConnection::new(handle)),
        }
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
    /// `wire`. Returns [`AppError::Nacked`] on a forwarder Nack.
    pub async fn fetch_wire(&mut self, wire: Bytes, timeout: Duration) -> Result<Data, AppError> {
        self.conn.send(wire).await?;

        let reply = crate::rt::timeout(timeout, self.conn.recv())
            .await
            .map_err(|_| AppError::Timeout)?
            .ok_or(AppError::Closed)?;

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

    /// Like [`fetch`](Self::fetch) but also returns the received Data's
    /// NDNLPv2 local fields ([`LpInfo`]) — the `getTag<IncomingFaceIdTag>()`
    /// equivalent. `incoming_face_id` is populated when the consumer face has
    /// LocalFields enabled (or, for an embedded app, always — via the in-proc
    /// source tag-bag).
    pub async fn fetch_with_meta(
        &mut self,
        name: impl Into<Name>,
    ) -> Result<(Data, LpInfo), AppError> {
        let wire = InterestBuilder::new(name)
            .lifetime(DEFAULT_INTEREST_LIFETIME)
            .build();
        self.conn.send(wire).await?;
        let (reply, lp) = crate::rt::timeout(DEFAULT_TIMEOUT, self.conn.recv_with_meta())
            .await
            .map_err(|_| AppError::Timeout)?
            .ok_or(AppError::Closed)?;
        let data = decode_data_lp(reply)?;
        Ok((data, lp))
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
            .map_err(|e| AppError::Protocol(e.to_string()))
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
        self.fetch_object_inner(name.into(), None, &[]).await
    }

    /// Verified whole-object fetch — the **secure** RDR path: like
    /// [`fetch_object`](Self::fetch_object) but the metadata discovery Data AND
    /// every segment are verified against `validator` before their bytes are
    /// accepted, so the entire reassembled object is *authenticated*, not merely
    /// integrity-checked. Prefer [`VerifiedConsumer::fetch_object`] (the
    /// least-resistance safe verb); this exists so the raw consumer can do a
    /// verified object fetch too.
    pub async fn fetch_object_verified(
        &mut self,
        name: impl Into<Name>,
        validator: &Validator,
    ) -> Result<Bytes, AppError> {
        self.fetch_object_inner(name.into(), Some(validator), &[])
            .await
    }

    /// Verified whole-object fetch steered by an NDNLPv2 **ForwardingHint** —
    /// like [`fetch_object_verified`](Self::fetch_object_verified) but every
    /// Interest (metadata discovery + each segment) carries `forwarding_hint`,
    /// so content named under a non-routable producer prefix is forwarded toward
    /// a routable delegation (e.g. `/ndn/node/<peerId>`) until it reaches the
    /// producer's region, where the hint is stripped and the Interest forwarded
    /// by name. The cross-peer fetch primitive for tap-to-share.
    pub async fn fetch_object_verified_hinted(
        &mut self,
        name: impl Into<Name>,
        validator: &Validator,
        forwarding_hint: &[Name],
    ) -> Result<Bytes, AppError> {
        self.fetch_object_inner(name.into(), Some(validator), forwarding_hint)
            .await
    }

    async fn fetch_object_inner(
        &mut self,
        name: Name,
        validator: Option<&Validator>,
        forwarding_hint: &[Name],
    ) -> Result<Bytes, AppError> {
        // Metadata discovery — generous lifetime + retries (it is the first and
        // most failure-prone round-trip over a lossy radio). `CanBePrefix` +
        // `MustBeFresh` rebuilt each attempt with a fresh nonce.
        let meta_data = self
            .fetch_object_with_retry(|| {
                let mut b = InterestBuilder::new(crate::rdr::metadata_name(&name))
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
        let meta = crate::rdr::MetaData::decode(meta_content)?;
        let last_seg = meta
            .last_segment()
            .ok_or_else(|| AppError::Protocol("metadata FinalBlockID unparseable".into()))?;

        let mut out = bytes::BytesMut::new();
        for n in 0..=last_seg {
            let seg_name = meta.versioned_name.clone().append_segment(n);
            let data = self
                .fetch_object_with_retry(|| {
                    let mut b =
                        InterestBuilder::new(seg_name.clone()).lifetime(DEFAULT_INTEREST_LIFETIME);
                    if !forwarding_hint.is_empty() {
                        b = b.forwarding_hint(forwarding_hint.to_vec());
                    }
                    b
                })
                .await?;
            if let Some(chunk) = accept_content(data, validator).await? {
                out.extend_from_slice(&chunk);
            }
        }
        Ok(out.freeze())
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

    /// Companion to [`Producer::publish_large`]. Segment names are
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
            validator,
        }
    }
}

/// A [`Consumer`] that verifies every fetch against a pinned [`Validator`], so
/// the short verbs (`fetch`, `get`) return [`SafeData`] instead of raw `Data`.
/// Build one with [`Consumer::verifying`].
///
/// This is the safe path of least resistance: the obvious call is the verified
/// one. The unverified primitives remain reachable via [`unverified`](Self::unverified)
/// for the cases that genuinely need them (segment reassembly, deliberate
/// integrity-only acceptance).
pub struct VerifiedConsumer {
    inner: Consumer,
    validator: Validator,
}

impl VerifiedConsumer {
    /// Fetch and verify against the pinned validator. Verification is not
    /// optional here — you get [`SafeData`] or an error.
    pub async fn fetch(&mut self, name: impl Into<Name>) -> Result<SafeData, AppError> {
        self.inner.fetch_verified(name, &self.validator).await
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
        self.inner.fetch_object_verified(name, &self.validator).await
    }

    /// The validator this consumer verifies against.
    pub fn validator(&self) -> &Validator {
        &self.validator
    }

    /// Borrow the underlying raw [`Consumer`] for the unverified primitives
    /// (`fetch_object`, `fetch_unverified`, …). Reaching for this is the
    /// explicit "I am handling trust myself here" signal.
    pub fn unverified(&mut self) -> &mut Consumer {
        &mut self.inner
    }

    /// Drop the validator and recover the raw [`Consumer`].
    pub fn into_inner(self) -> Consumer {
        self.inner
    }
}

/// LP-unwrap a received packet and decode it as `Data`, surfacing a Nack.
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
}

impl Default for SubscribeOptions {
    fn default() -> Self {
        Self {
            max_data_count: 1024,
            lifetime: Duration::from_secs(600),
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
}

/// Build the persistent Interest wire for `prefix` carrying a
/// `SubscriptionRequest` in ApplicationParameters (CanBePrefix + MustBeFresh).
///
/// **Signed** (`DigestSha256`, with anti-replay `SignatureNonce`/`SignatureTime`):
/// the forwarder only installs *true* persistence (one Interest → many Data) for
/// a validated, signed subscription Interest — an unsigned one degrades to
/// one-shot (`ndn-engine` `check_persistent`). DigestSha256 keys no identity; a
/// trust-schema-bearing deployment can swap in a real signer.
fn build_persistent_interest(prefix: &Name, opts: &SubscribeOptions) -> Bytes {
    let secs = (opts.lifetime.as_secs() as u32).min(MAX_PERSISTENT_LIFETIME_SECS);
    let sr = SubscriptionRequest {
        version: 1,
        max_data_count: opts.max_data_count,
        max_lifetime_secs: secs,
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
            .send(build_persistent_interest(&self.prefix, &self.opts))
            .await?;
        self.remaining = self.opts.max_data_count.max(1);
        Ok(())
    }

    /// Next streamed Data. Re-expresses the persistent Interest automatically
    /// once the data-count budget is exhausted.
    pub async fn recv(&mut self) -> Result<Data, AppError> {
        if self.remaining == 0 {
            self.express().await?;
        }
        let reply = self.conn.recv().await.ok_or(AppError::Closed)?;
        self.remaining = self.remaining.saturating_sub(1);
        decode_data_lp(reply)
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

    #[test]
    fn persistent_interest_carries_subscription_request() {
        let prefix = Name::from("/vpn/downlink");
        let opts = SubscribeOptions {
            max_data_count: 256,
            lifetime: Duration::from_secs(120),
        };
        let wire = build_persistent_interest(&prefix, &opts);
        let interest = Interest::decode(wire).expect("valid interest");

        assert!(interest.name.has_prefix(&prefix));

        let params = interest.app_parameters().expect("has app parameters");
        let sr = SubscriptionRequest::find_in(params).expect("carries SubscriptionRequest");
        assert_eq!(sr.version, 1);
        assert_eq!(sr.max_data_count, 256);
        assert_eq!(sr.max_lifetime_secs, 120);
    }

    #[test]
    fn lifetime_capped_at_max() {
        let opts = SubscribeOptions {
            max_data_count: 1,
            lifetime: Duration::from_secs(100_000),
        };
        let wire = build_persistent_interest(&Name::from("/x"), &opts);
        let interest = Interest::decode(wire).unwrap();
        let sr = SubscriptionRequest::find_in(interest.app_parameters().unwrap()).unwrap();
        assert_eq!(sr.max_lifetime_secs, MAX_PERSISTENT_LIFETIME_SECS);
    }
}
