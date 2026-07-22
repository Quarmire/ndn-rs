use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
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
use ndn_packet::Name;
use ndn_security::{CertFetcher, ValidationResult, Validator};

struct PendingEntry {
    ctx: PacketContext,
    needed_cert: Arc<Name>,
    deadline: Instant,
    byte_size: usize,
}

enum DrainResult {
    Ready(Box<PacketContext>),
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

    fn push(&mut self, ctx: PacketContext, needed_cert: Arc<Name>, now: Instant) {
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
            // Monotonic deadline anchored to the runtime clock (deterministic under a
            // virtual runtime). (ndn-lab slice 0c.)
            deadline: now + self.default_timeout,
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

            if validator.cert_cache().get(&entry.needed_cert).is_some() {
                let entry = self.entries.remove(i).unwrap();
                self.total_bytes -= entry.byte_size;
                results.push(DrainResult::Ready(Box::new(entry.ctx)));
                continue;
            }

            i += 1;
        }

        results
    }
}

pub struct ValidationStage {
    pub validator: Option<Arc<Validator>>,
    pub cert_fetcher: Option<Arc<CertFetcher>>,
    pending: Arc<Mutex<PendingQueue>>,
    pub runtime: Arc<dyn Runtime>,
    stats: Arc<ValidationStats>,
}

impl ValidationStage {
    pub fn new(
        validator: Option<Arc<Validator>>,
        cert_fetcher: Option<Arc<CertFetcher>>,
        config: PendingQueueConfig,
        runtime: Arc<dyn Runtime>,
    ) -> Self {
        Self {
            validator,
            cert_fetcher,
            pending: Arc::new(Mutex::new(PendingQueue::new(&config))),
            runtime,
            stats: Arc::new(ValidationStats::default()),
        }
    }

    pub fn disabled() -> Self {
        Self {
            validator: None,
            cert_fetcher: None,
            pending: Arc::new(Mutex::new(
                PendingQueue::new(&PendingQueueConfig::default()),
            )),
            runtime: ndn_runtime::default_runtime(),
            stats: Arc::new(ValidationStats::default()),
        }
    }

    /// The running validation counters (security status / audit dashboard signal).
    pub fn stats(&self) -> Arc<ValidationStats> {
        Arc::clone(&self.stats)
    }

    pub async fn process(&self, mut ctx: PacketContext) -> Action {
        let Some(validator) = &self.validator else {
            // No validator: default-deny. Leave `ctx.verified = false` so
            // `CsInsertStage` skips admission; the Data still forwards
            // through PIT-match (downstream consumers validate themselves).
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
        let result = validator.validate_chain(data).instrument(span.clone()).await;
        span.record("elapsed_us", started.elapsed().as_micros() as u64);
        match result {
            ValidationResult::Valid(_safe) => {
                span.record("outcome", "valid");
                self.stats.valid.fetch_add(1, Ordering::Relaxed);
                trace!(target: t::SECURITY, name=%name, "validation: valid");
                ctx.verified = true;
                Action::Satisfy(ctx)
            }
            ValidationResult::Pending => {
                if let Some(cert_name) = key {
                    span.record("outcome", "pending");
                    span.record("reason", "awaiting-cert");
                    self.stats.pending.fetch_add(1, Ordering::Relaxed);
                    debug!(target: t::SECURITY, name=%name, cert=%cert_name, "validation: pending, queuing");

                    if let Some(fetcher) = &self.cert_fetcher {
                        let fetcher = Arc::clone(fetcher);
                        let cn = Arc::clone(&cert_name);
                        self.runtime.spawn(Box::pin(async move {
                            let _ = fetcher.fetch(&cn).await;
                        }));
                    }

                    let now = self.runtime.now();
                    self.pending.lock().await.push(ctx, cert_name, now);
                    Action::Drop(DropReason::ValidationFailed)
                } else {
                    span.record("outcome", "dropped");
                    span.record("reason", "no-key-locator");
                    self.stats.dropped_no_key.fetch_add(1, Ordering::Relaxed);
                    warn!(target: t::SECURITY, name=%name, "validation: DROPPED — unverifiable (no key locator)");
                    Action::Drop(DropReason::ValidationFailed)
                }
            }
            ValidationResult::Invalid(e) => {
                span.record("outcome", "invalid");
                span.record("reason", "bad-signature");
                self.stats.invalid.fetch_add(1, Ordering::Relaxed);
                warn!(target: t::SECURITY, name=%name, error=%e, "validation: FAILED — forged/invalid signature");
                Action::Drop(DropReason::ValidationFailed)
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
                DrainResult::Ready(ctx) => {
                    let mut ctx = *ctx;
                    let data = match &ctx.packet {
                        DecodedPacket::Data(d) => d,
                        _ => {
                            actions.push(Action::Satisfy(ctx));
                            continue;
                        }
                    };
                    match validator.validate_chain(data).await {
                        ValidationResult::Valid(_) => {
                            self.stats.valid.fetch_add(1, Ordering::Relaxed);
                            trace!(target: t::SECURITY, name=%data.name, "validation: re-validated after cert fetch");
                            ctx.verified = true;
                            actions.push(Action::Satisfy(ctx));
                        }
                        ValidationResult::Pending => {
                            self.stats.dropped_timeout.fetch_add(1, Ordering::Relaxed);
                            warn!(target: t::SECURITY, name=%data.name, "validation: DROPPED — still no cert after fetch");
                            actions.push(Action::Drop(DropReason::ValidationFailed));
                        }
                        ValidationResult::Invalid(e) => {
                            self.stats.invalid.fetch_add(1, Ordering::Relaxed);
                            warn!(target: t::SECURITY, name=%data.name, error=%e, "validation: FAILED — forged/invalid after cert fetch");
                            actions.push(Action::Drop(DropReason::ValidationFailed));
                        }
                    }
                }
            }
        }

        actions
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
            None,
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
            matches!(action, Action::Drop(DropReason::ValidationFailed)),
            "/localhost Data must go through validation instead of bypassing it"
        );
    }
}
