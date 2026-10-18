use portable_atomic::AtomicU64;
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use ndn_runtime::Runtime;
use tokio::sync::Mutex;
// `web_time::Instant` proxies to `performance.now()` on wasm; the tokio
// timer wheel panics on `wasm32-unknown-unknown`.
use tracing::{Instrument, debug, field, trace, warn};
use web_time::Instant;

/// Running counts of Data-validation outcomes — the security "status" signal a
/// dashboard or `/status` endpoint reads. Cheap atomics; read via
/// [`ValidationStage::stats`].
#[derive(Default, Debug)]
pub struct ValidationStats {
    pub valid: AtomicU64,
    pub invalid: AtomicU64,
    pub pending: AtomicU64,
    pub dropped_no_key: AtomicU64,
    pub dropped_timeout: AtomicU64,
}

use crate::observability::targets as t;

use crate::pipeline::{Action, DecodedPacket, DropReason, PacketContext};
use ndn_packet::{Name, Refusal};
use ndn_security::{TrustError, ValidationResult, Validator};
use ndn_transport::FaceId;

struct PendingEntry {
    ctx: PacketContext,
    needed_cert: Arc<Name>,
    deadline: Instant,
    byte_size: usize,
}

enum DrainResult {
    /// The awaited cert landed; re-validate. Carries the entry's original
    /// deadline so a re-queue (next missing hop) cannot extend it.
    Ready(Box<PacketContext>, Instant),
    /// The awaited cert is known absent where it was fetched: a final
    /// verdict on the Data.
    Absent(Box<PacketContext>, Arc<Name>),
    Timeout,
}

struct PendingQueue {
    entries: VecDeque<PendingEntry>,
    total_bytes: usize,
    max_entries: usize,
    max_bytes: usize,
    default_timeout: Duration,
}

pub struct PendingQueueConfig {
    pub max_entries: usize,
    pub max_bytes: usize,
    pub timeout: Duration,
}

impl Default for PendingQueueConfig {
    fn default() -> Self {
        Self {
            max_entries: 256,
            max_bytes: 4 * 1024 * 1024,
            timeout: Duration::from_secs(4),
        }
    }
}

impl PendingQueue {
    fn new(config: &PendingQueueConfig) -> Self {
        Self {
            entries: VecDeque::new(),
            total_bytes: 0,
            max_entries: config.max_entries,
            max_bytes: config.max_bytes,
            default_timeout: config.timeout,
        }
    }

    fn deadline_from(&self, now: Instant) -> Instant {
        // Monotonic deadline anchored to the runtime clock (deterministic under a
        // virtual runtime). (ndn-lab slice 0c.)
        now + self.default_timeout
    }

    fn push(&mut self, ctx: PacketContext, needed_cert: Arc<Name>, deadline: Instant) {
        let byte_size = ctx.raw_bytes.len();

        while self.entries.len() >= self.max_entries
            || (self.total_bytes + byte_size > self.max_bytes && !self.entries.is_empty())
        {
            if let Some(evicted) = self.entries.pop_front() {
                self.total_bytes -= evicted.byte_size;
                debug!(target: t::SECURITY, "validation pending queue: evicted oldest entry");
            }
        }

        self.total_bytes += byte_size;
        self.entries.push_back(PendingEntry {
            ctx,
            needed_cert,
            deadline,
            byte_size,
        });
    }

    fn drain_ready(&mut self, validator: &Validator, now: Instant) -> Vec<DrainResult> {
        let mut results = Vec::new();
        let mut i = 0;

        while i < self.entries.len() {
            let entry = &self.entries[i];

            if now >= entry.deadline {
                let entry = self.entries.remove(i).unwrap();
                self.total_bytes -= entry.byte_size;
                debug!(target: t::SECURITY, "validation pending queue: timeout");
                results.push(DrainResult::Timeout);
                continue;
            }

            // The KeyLocator names a key: the Data is ready once a currently
            // valid certificate of it is cached (an expired one cached from
            // before a renewal does not count — the fetch replaces it), or
            // once the validator refused the certificate that answered the
            // fetch (re-validating then yields that verdict, not a timeout).
            if validator.can_resolve(&entry.needed_cert) {
                let entry = self.entries.remove(i).unwrap();
                self.total_bytes -= entry.byte_size;
                results.push(DrainResult::Ready(Box::new(entry.ctx), entry.deadline));
                continue;
            }

            // Every source the cert's fetch asked answered that it is not to
            // be had there (a NoRoute Nack, or a refusal of what it served):
            // the Data cannot be verified now, so it is refused
            // `unverifiable` — not final, the consumer asks again after the
            // back-off — instead of waiting out its deadline. A fetch that
            // timed out never says so; the network may only be slow.
            if validator
                .cert_fetcher()
                .is_some_and(|f| f.known_absent(&entry.needed_cert, Some(entry.ctx.face_id.0)))
            {
                let entry = self.entries.remove(i).unwrap();
                self.total_bytes -= entry.byte_size;
                results.push(DrainResult::Absent(Box::new(entry.ctx), entry.needed_cert));
                continue;
            }

            i += 1;
        }

        results
    }
}

/// Validates inbound Data against the engine [`Validator`].
///
/// Validation on the pipeline is **cache-only** ([`Validator::validate_chain_cached`]):
/// awaiting a network cert fetch inline would stall the very pipeline that
/// must deliver the cert's Data. A missing cert instead parks the Data in a
/// bounded pending queue and spawns a fetch through the validator's
/// [`CertFetcher`](ndn_security::CertFetcher) (attached after engine build, see
/// `ndn_app::install_engine_cert_fetcher`); the drain task re-validates once
/// the cert is cached, walking one missing hop at a time, refuses the Data as
/// `unverifiable` (refused for now, not final: see
/// [`Refusal::is_final`](ndn_packet::Refusal::is_final)) once the fetcher
/// knows the cert absent everywhere it asked
/// ([`CertFetcher::known_absent`](ndn_security::CertFetcher::known_absent)),
/// and drops it when its original deadline passes. The fetcher dedups
/// concurrent requests and backs off after a failure, and every re-queue
/// keeps the original deadline, so a missing cert cannot loop or amplify.
pub struct ValidationStage {
    pub validator: Option<Arc<Validator>>,
    pending: Arc<Mutex<PendingQueue>>,
    pub runtime: Arc<dyn Runtime>,
    stats: Arc<ValidationStats>,
}

impl ValidationStage {
    pub fn new(
        validator: Option<Arc<Validator>>,
        config: PendingQueueConfig,
        runtime: Arc<dyn Runtime>,
    ) -> Self {
        Self {
            validator,
            pending: Arc::new(Mutex::new(PendingQueue::new(&config))),
            runtime,
            stats: Arc::new(ValidationStats::default()),
        }
    }

    pub fn disabled() -> Self {
        Self {
            validator: None,
            pending: Arc::new(Mutex::new(
                PendingQueue::new(&PendingQueueConfig::default()),
            )),
            runtime: ndn_runtime::default_runtime(),
            stats: Arc::new(ValidationStats::default()),
        }
    }

    /// Kick off a background fetch of `cert_name` through the validator's
    /// fetcher, if one is attached: routed by the FIB and, where the fetcher
    /// can, also asked of `in_face`, the neighbour that delivered the Data
    /// waiting on it (a producer serves its own issuer chain). Never awaited
    /// on the pipeline.
    fn request_cert(&self, validator: &Validator, cert_name: &Arc<Name>, in_face: FaceId) {
        if let Some(fetcher) = validator.cert_fetcher() {
            let fetcher = Arc::clone(fetcher);
            let cn = Arc::clone(cert_name);
            self.runtime.spawn(Box::pin(async move {
                let _ = fetcher.fetch_from(&cn, Some(in_face.0)).await;
            }));
        }
    }

    /// The running validation counters (security status / audit dashboard signal).
    pub fn stats(&self) -> Arc<ValidationStats> {
        Arc::clone(&self.stats)
    }

    pub async fn process(&self, mut ctx: PacketContext) -> Action {
        let Some(validator) = &self.validator else {
            // No validator configured: this Data was never SUBJECT to
            // validation, which is not the same as having failed it. Say so
            // explicitly so downstream stages can tell the two apart.
            //
            // `verified` stays false -- nothing checked the signature -- but
            // `CsInsertStage` may still admit, matching NFD: a forwarder does
            // not validate, and the consumer validates for itself (which is
            // exactly what the previous comment here argued, while the code
            // did the opposite). Treating the two as one silently disabled the
            // Content Store whenever `[security] profile = "disabled"`.
            ctx.validation_not_configured = true;
            return Action::Satisfy(ctx);
        };

        let data = match &ctx.packet {
            DecodedPacket::Data(d) => d,
            _ => return Action::Satisfy(ctx),
        };

        // The `validate` span: inputs (name / signature type / signing key) and the
        // verdict + reason + latency. Zero-cost without a subscriber; under the
        // NDN-native OTLP layer it becomes an Interest-able, signed, cached span —
        // both a security trace and a tamper-evident audit record.
        let started = Instant::now();
        let name = data.name.clone();
        let sig_type = data.sig_info().map(|si| si.sig_type);
        let key: Option<Arc<Name>> = data.sig_info().and_then(|si| si.key_locator_name());
        let span = tracing::info_span!(
            target: t::SECURITY, "validate",
            name = %name,
            sig_type = ?sig_type,
            key = ?key.as_deref(),
            outcome = field::Empty,
            reason = field::Empty,
            elapsed_us = field::Empty,
        );

        // ndn-rs validates everything, including /localhost mgmt responses
        // (signed with DigestSha256). NFD reaches the same effect via an
        // explicit `m_localhostValidator` allowlist.
        //
        // The revocation epoch is read BEFORE the context is consulted, so a
        // revoking update that the check below did not see moves it.
        let epoch = validator.keyring().revocation_epoch();
        let (result, missing) = validator
            .validate_chain_cached(data)
            .instrument(span.clone())
            .await;
        span.record("elapsed_us", started.elapsed().as_micros() as u64);
        match result {
            ValidationResult::Valid(_safe) => {
                span.record("outcome", "valid");
                self.stats.valid.fetch_add(1, Ordering::Relaxed);
                trace!(target: t::SECURITY, name=%name, "validation: valid");
                ctx.verified = true;
                ctx.revocation_epoch = Some(epoch);
                Action::Satisfy(ctx)
            }
            ValidationResult::Pending => {
                if let Some(cert_name) = missing {
                    span.record("outcome", "pending");
                    span.record("reason", "awaiting-cert");
                    self.stats.pending.fetch_add(1, Ordering::Relaxed);
                    debug!(target: t::SECURITY, name=%name, cert=%cert_name, "validation: pending, awaiting certificate (queued)");

                    self.request_cert(validator, &cert_name, ctx.face_id);

                    let now = self.runtime.now();
                    let mut pending = self.pending.lock().await;
                    let deadline = pending.deadline_from(now);
                    pending.push(ctx, cert_name, deadline);
                    Action::Drop(DropReason::ValidationPending)
                } else {
                    span.record("outcome", "dropped");
                    span.record("reason", Refusal::Unverifiable.as_str());
                    self.stats.dropped_no_key.fetch_add(1, Ordering::Relaxed);
                    warn!(target: t::SECURITY, name=%name, "validation: DROPPED — unverifiable (no key locator)");
                    Action::Refuse(ctx, Refusal::Unverifiable)
                }
            }
            ValidationResult::Invalid(e) => {
                let (refusal, what) = invalid_reason(&e);
                span.record("outcome", "invalid");
                span.record("reason", refusal.as_str());
                self.stats.invalid.fetch_add(1, Ordering::Relaxed);
                warn!(target: t::SECURITY, name=%name, error=%e, "validation: {what}");
                Action::Refuse(ctx, refusal)
            }
        }
    }

    pub async fn drain_pending(&self) -> Vec<Action> {
        let Some(validator) = &self.validator else {
            return Vec::new();
        };

        let now = self.runtime.now();
        let results = self.pending.lock().await.drain_ready(validator, now);
        let mut actions = Vec::with_capacity(results.len());

        for result in results {
            match result {
                DrainResult::Timeout => {
                    self.stats.dropped_timeout.fetch_add(1, Ordering::Relaxed);
                    warn!(target: t::SECURITY, "validation: DROPPED — cert fetch timed out");
                    actions.push(Action::Drop(DropReason::ValidationTimeout));
                }
                DrainResult::Absent(ctx, cert) => {
                    self.stats.invalid.fetch_add(1, Ordering::Relaxed);
                    warn!(target: t::SECURITY, cert=%cert, "validation: REFUSED for now — unverifiable: every source asked for the signing certificate had none (or served one refused); the consumer may retry after the fetch back-off");
                    actions.push(Action::Refuse(*ctx, Refusal::Unverifiable));
                }
                DrainResult::Ready(ctx, deadline) => {
                    let mut ctx = *ctx;
                    let data = match &ctx.packet {
                        DecodedPacket::Data(d) => d,
                        _ => {
                            actions.push(Action::Satisfy(ctx));
                            continue;
                        }
                    };
                    let epoch = validator.keyring().revocation_epoch();
                    match validator.validate_chain_cached(data).await {
                        (ValidationResult::Valid(_), _) => {
                            self.stats.valid.fetch_add(1, Ordering::Relaxed);
                            trace!(target: t::SECURITY, name=%data.name, "validation: re-validated after cert fetch");
                            ctx.verified = true;
                            ctx.revocation_epoch = Some(epoch);
                            actions.push(Action::Satisfy(ctx));
                        }
                        // The next hop up the chain is missing: fetch it and wait
                        // again, under the entry's ORIGINAL deadline (the walk is
                        // bounded by the validator's max chain depth, and the
                        // deadline bounds the whole resolution).
                        (ValidationResult::Pending, Some(next)) if now < deadline => {
                            debug!(target: t::SECURITY, name=%data.name, cert=%next, "validation: next cert in chain missing, re-queuing");
                            self.request_cert(validator, &next, ctx.face_id);
                            self.pending.lock().await.push(ctx, next, deadline);
                        }
                        (ValidationResult::Pending, _) => {
                            self.stats.dropped_timeout.fetch_add(1, Ordering::Relaxed);
                            warn!(target: t::SECURITY, name=%data.name, "validation: DROPPED — still no cert after fetch");
                            actions.push(Action::Drop(DropReason::ValidationFailed));
                        }
                        (ValidationResult::Invalid(e), _) => {
                            let (refusal, what) = invalid_reason(&e);
                            self.stats.invalid.fetch_add(1, Ordering::Relaxed);
                            warn!(target: t::SECURITY, name=%data.name, error=%e, "validation: {what} (after cert fetch)");
                            actions.push(Action::Refuse(ctx, refusal));
                        }
                    }
                }
            }
        }

        actions
    }
}

/// An `Invalid` verdict as the refusal the local downstreams are told (also
/// the span's `reason`) and the log line's wording: a revoked key or a
/// schema refusal is not a forged signature.
fn invalid_reason(e: &TrustError) -> (Refusal, &'static str) {
    match e {
        TrustError::Revoked { .. } => (
            Refusal::Revoked,
            "REFUSED — certificate revoked in trust context",
        ),
        TrustError::InvalidSignature
        | TrustError::InvalidKey
        | TrustError::NotPublicKeySignature { .. } => (
            Refusal::BadSignature,
            "FAILED — forged/invalid signature",
        ),
        TrustError::SchemaMismatch | TrustError::CertNotAuthorized { .. } => (
            Refusal::Schema,
            "REFUSED — not authorized by the trust schema",
        ),
        TrustError::UntrustedSelfSigned { .. } => (
            Refusal::UntrustedRoot,
            "REFUSED — chain ends at a self-signed certificate that is not a trust anchor",
        ),
        TrustError::ExpectedContextRefused { .. } => (
            Refusal::Context,
            "REFUSED — trust context does not meet the adoption/update expectation",
        ),
        _ => (Refusal::Chain, "FAILED — certificate chain rejected"),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bytes::Bytes;
    use ndn_packet::{Data, SignatureType, encode::DataBuilder};
    use ndn_security::{TrustSchema, Validator};
    use ndn_transport::FaceId;

    use super::*;

    #[tokio::test]
    async fn d13_localhost_data_with_bogus_digest_is_dropped() {
        let validator = Arc::new(Validator::new(TrustSchema::accept_all()));
        let validation = ValidationStage::new(
            Some(validator),
            PendingQueueConfig::default(),
            ndn_runtime::default_runtime(),
        );

        let wire = DataBuilder::new("/localhost/nfd/status/general", b"forged").sign_sync(
            SignatureType::DigestSha256,
            None,
            |_| Bytes::from_static(&[0u8; 32]),
        );
        let data = Data::decode(wire.clone()).unwrap();
        let mut ctx = PacketContext::new(wire, FaceId(1), 0);
        ctx.name = Some(Arc::clone(&data.name));
        ctx.packet = DecodedPacket::Data(Box::new(data));

        let action = validation.process(ctx).await;
        assert!(
            matches!(action, Action::Refuse(_, Refusal::BadSignature)),
            "/localhost Data must go through validation instead of bypassing it"
        );
    }

    use ndn_packet::Name;
    use ndn_security::{CertFetcher, Certificate, Ed25519Signer, FetchFn, Signer};
    use std::collections::HashMap;
    use std::sync::atomic::AtomicUsize;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    fn ctx_for(wire: Bytes) -> PacketContext {
        let data = Data::decode(wire.clone()).unwrap();
        let mut ctx = PacketContext::new(wire, FaceId(1), 0);
        ctx.name = Some(Arc::clone(&data.name));
        ctx.packet = DecodedPacket::Data(Box::new(data));
        ctx
    }

    fn signed_data(name: &str, signer: &Ed25519Signer) -> Bytes {
        DataBuilder::new(n(name), b"payload").sign_sync(
            SignatureType::SignatureEd25519,
            Some(signer.key_name()),
            |region| signer.sign_sync(region).unwrap(),
        )
    }

    /// Validator anchored at `root`, with a fetcher answering from `served`
    /// (name → cert Data wire), `unserved` for any other name, and counting
    /// every fetch attempt.
    fn validator_with_fetcher(
        root: &Ed25519Signer,
        served: HashMap<Name, Bytes>,
        unserved: ndn_security::FetchMiss,
    ) -> (Arc<Validator>, Arc<AtomicUsize>) {
        let validator = Arc::new(Validator::new(TrustSchema::accept_all()));
        validator.add_trust_anchor(Certificate {
            name: Arc::new(root.key_name().clone()),
            public_key: Bytes::copy_from_slice(&root.public_key_bytes()),
            valid_from: 0,
            valid_until: u64::MAX,
            issuer: None,
            signed_region: None,
            sig_value: None,
            sig_type: SignatureType::SignatureEd25519,
        });
        let fetches = Arc::new(AtomicUsize::new(0));
        let f = Arc::clone(&fetches);
        let fetch_fn: FetchFn = Arc::new(move |name: Name| {
            f.fetch_add(1, Ordering::Relaxed);
            let data = served.get(&name).map(|w| Data::decode(w.clone()).unwrap());
            Box::pin(async move { data.ok_or(unserved) })
        });
        let fetcher = Arc::new(CertFetcher::new(
            validator.cert_cache_arc(),
            fetch_fn,
            Duration::from_secs(1),
        ));
        assert!(validator.set_cert_fetcher(fetcher).is_ok());
        (validator, fetches)
    }

    async fn wait_cached(validator: &Validator, name: &Name) {
        let name = Arc::new(name.clone());
        for _ in 0..200 {
            if validator.cert_cache().get(&name).is_some() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("cert {name} never fetched");
    }

    /// Data → leaf cert → mid cert → anchor, with neither cert cached: the
    /// stage fetches the leaf off the hot path, re-queues for the mid cert
    /// (next hop) under the same deadline, then validates — one fetch per cert.
    #[tokio::test]
    async fn pending_data_validates_after_fetching_each_missing_hop() {
        let root = Ed25519Signer::from_seed(&[1; 32], n("/t/KEY/root"));
        let mid = Ed25519Signer::from_seed(&[2; 32], n("/t/mid/KEY/m/root/v1"));
        let leaf = Ed25519Signer::from_seed(&[3; 32], n("/t/leaf/KEY/l/mid/v1"));
        let mid_cert = ndn_security::encode_cert_data(
            mid.key_name(),
            &mid.public_key_bytes(),
            &root,
            0,
            u64::MAX,
        )
        .await
        .unwrap();
        let leaf_cert = ndn_security::encode_cert_data(
            leaf.key_name(),
            &leaf.public_key_bytes(),
            &mid,
            0,
            u64::MAX,
        )
        .await
        .unwrap();
        let served = HashMap::from([
            (mid.key_name().clone(), mid_cert),
            (leaf.key_name().clone(), leaf_cert),
        ]);
        let (validator, fetches) =
            validator_with_fetcher(&root, served, ndn_security::FetchMiss::Unanswered);
        let stage = ValidationStage::new(
            Some(Arc::clone(&validator)),
            PendingQueueConfig::default(),
            ndn_runtime::default_runtime(),
        );

        let action = stage
            .process(ctx_for(signed_data("/t/leaf/photo", &leaf)))
            .await;
        assert!(matches!(action, Action::Drop(DropReason::ValidationPending)));

        wait_cached(&validator, leaf.key_name()).await;
        assert!(
            stage.drain_pending().await.is_empty(),
            "mid cert still missing: re-queued, not resolved"
        );
        wait_cached(&validator, mid.key_name()).await;
        let actions = stage.drain_pending().await;
        assert!(
            matches!(actions.as_slice(), [Action::Satisfy(ctx)] if ctx.verified),
            "Data must validate once its whole chain is fetched"
        );
        assert_eq!(fetches.load(Ordering::Relaxed), 2);
    }

    /// A cert nobody answers for (no answer in time, which says nothing
    /// about whether it exists): every Data naming it is parked, ONE fetch
    /// goes out (dedup + negative cache — no per-packet retry storm), and each
    /// Data is dropped by timeout once its deadline passes, refused to nobody.
    #[tokio::test]
    async fn missing_cert_times_out_without_retry_storm() {
        let root = Ed25519Signer::from_seed(&[1; 32], n("/t/KEY/root"));
        let ghost = Ed25519Signer::from_seed(&[9; 32], n("/t/ghost/KEY/g/root/v1"));
        let (validator, fetches) =
            validator_with_fetcher(&root, HashMap::new(), ndn_security::FetchMiss::Unanswered);
        let stage = ValidationStage::new(
            Some(validator),
            PendingQueueConfig {
                timeout: Duration::from_millis(400),
                ..PendingQueueConfig::default()
            },
            ndn_runtime::default_runtime(),
        );

        for i in 0..20 {
            let action = stage
                .process(ctx_for(signed_data(&format!("/t/ghost/{i}"), &ghost)))
                .await;
            assert!(matches!(action, Action::Drop(DropReason::ValidationPending)));
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        assert!(stage.drain_pending().await.is_empty(), "nothing ready yet");

        tokio::time::sleep(Duration::from_millis(450)).await;
        let actions = stage.drain_pending().await;
        assert_eq!(actions.len(), 20);
        assert!(
            actions
                .iter()
                .all(|a| matches!(a, Action::Drop(DropReason::ValidationTimeout)))
        );
        assert_eq!(stage.stats().dropped_timeout.load(Ordering::Relaxed), 20);
        assert!(stage.drain_pending().await.is_empty(), "no retry after drop");
        assert_eq!(
            fetches.load(Ordering::Relaxed),
            1,
            "20 Data naming one missing cert must cost one fetch"
        );
    }

    /// A cert whose fetch was answered that none is to be had where it was
    /// asked (a NoRoute Nack): the Data waiting on it can never be verified
    /// from there, and is refused `unverifiable` at the next drain rather
    /// than dropped at its deadline.
    #[tokio::test]
    async fn data_whose_certificate_is_known_absent_is_refused_unverifiable() {
        let root = Ed25519Signer::from_seed(&[1; 32], n("/t/KEY/root"));
        let ghost = Ed25519Signer::from_seed(&[9; 32], n("/t/ghost/KEY/g/root/v1"));
        let (validator, fetches) =
            validator_with_fetcher(&root, HashMap::new(), ndn_security::FetchMiss::Absent);
        let stage = ValidationStage::new(
            Some(validator),
            PendingQueueConfig::default(),
            ndn_runtime::default_runtime(),
        );

        let action = stage
            .process(ctx_for(signed_data("/t/ghost/doc", &ghost)))
            .await;
        assert!(matches!(action, Action::Drop(DropReason::ValidationPending)));
        let mut actions = Vec::new();
        for _ in 0..200 {
            actions = stage.drain_pending().await;
            if !actions.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(
            matches!(actions.as_slice(), [Action::Refuse(_, Refusal::Unverifiable)]),
            "the Data is refused unverifiable, well before its deadline"
        );
        assert_eq!(stage.stats().invalid.load(Ordering::Relaxed), 1);
        assert_eq!(fetches.load(Ordering::Relaxed), 1);
    }
}
