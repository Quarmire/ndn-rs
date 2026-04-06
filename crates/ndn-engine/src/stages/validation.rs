use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;
use tokio::time::Instant;
use tracing::{debug, trace};

use ndn_packet::Name;
use ndn_pipeline::{Action, DecodedPacket, DropReason, PacketContext};
use ndn_security::{CertFetcher, ValidationResult, Validator};

/// A queued packet awaiting certificate resolution.
struct PendingEntry {
    ctx: PacketContext,
    needed_cert: Arc<Name>,
    deadline: Instant,
    byte_size: usize,
}

/// Whether a pending entry is ready for action or still waiting.
enum DrainResult {
    /// Certificate arrived — re-validate this packet.
    Ready(PacketContext),
    /// Timed out waiting for the certificate.
    Timeout,
}

/// Bounded pending queue for packets awaiting cert fetch.
struct PendingQueue {
    entries: VecDeque<PendingEntry>,
    total_bytes: usize,
    max_entries: usize,
    max_bytes: usize,
    default_timeout: Duration,
}

/// Configuration for the pending validation queue.
pub struct PendingQueueConfig {
    pub max_entries: usize,
    pub max_bytes: usize,
    pub timeout: Duration,
}

impl Default for PendingQueueConfig {
    fn default() -> Self {
        Self {
            max_entries: 256,
            max_bytes: 4 * 1024 * 1024, // 4 MB
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

    /// Enqueue a packet. If the queue is full, drop the oldest entry.
    fn push(&mut self, ctx: PacketContext, needed_cert: Arc<Name>) {
        let byte_size = ctx.raw_bytes.len();

        while self.entries.len() >= self.max_entries
            || (self.total_bytes + byte_size > self.max_bytes && !self.entries.is_empty())
        {
            if let Some(evicted) = self.entries.pop_front() {
                self.total_bytes -= evicted.byte_size;
                debug!("validation pending queue: evicted oldest entry");
            }
        }

        self.total_bytes += byte_size;
        self.entries.push_back(PendingEntry {
            ctx,
            needed_cert,
            deadline: Instant::now() + self.default_timeout,
            byte_size,
        });
    }

    /// Drain entries that are expired or whose certs are now in cache.
    fn drain_ready(&mut self, validator: &Validator) -> Vec<DrainResult> {
        let mut results = Vec::new();
        let now = Instant::now();
        let mut i = 0;

        while i < self.entries.len() {
            let entry = &self.entries[i];

            if now >= entry.deadline {
                let entry = self.entries.remove(i).unwrap();
                self.total_bytes -= entry.byte_size;
                debug!("validation pending queue: timeout");
                results.push(DrainResult::Timeout);
                continue;
            }

            if validator.cert_cache().get(&entry.needed_cert).is_some() {
                let entry = self.entries.remove(i).unwrap();
                self.total_bytes -= entry.byte_size;
                results.push(DrainResult::Ready(entry.ctx));
                continue;
            }

            i += 1;
        }

        results
    }
}

/// Validates Data packet signatures before caching.
///
/// Sits between `PitMatchStage` and `CsInsertStage` in the data pipeline.
/// When no validator is configured, packets pass through unconditionally.
///
/// When a certificate is not yet cached, the packet is queued in a bounded
/// pending queue. A background drain task periodically re-validates queued
/// packets as certificates arrive.
pub struct ValidationStage {
    pub validator: Option<Arc<Validator>>,
    pub cert_fetcher: Option<Arc<CertFetcher>>,
    pending: Arc<Mutex<PendingQueue>>,
}

impl ValidationStage {
    pub fn new(
        validator: Option<Arc<Validator>>,
        cert_fetcher: Option<Arc<CertFetcher>>,
        config: PendingQueueConfig,
    ) -> Self {
        Self {
            validator,
            cert_fetcher,
            pending: Arc::new(Mutex::new(PendingQueue::new(&config))),
        }
    }

    /// Disabled validation — all packets pass through.
    pub fn disabled() -> Self {
        Self {
            validator: None,
            cert_fetcher: None,
            pending: Arc::new(Mutex::new(
                PendingQueue::new(&PendingQueueConfig::default()),
            )),
        }
    }

    pub async fn process(&self, ctx: PacketContext) -> Action {
        let Some(validator) = &self.validator else {
            return Action::Satisfy(ctx);
        };

        let data = match &ctx.packet {
            DecodedPacket::Data(d) => d,
            _ => return Action::Satisfy(ctx),
        };

        match validator.validate_chain(data).await {
            ValidationResult::Valid(_safe) => {
                trace!(name=%data.name, "validation: valid");
                Action::Satisfy(ctx)
            }
            ValidationResult::Pending => {
                let needed_cert = data
                    .sig_info()
                    .and_then(|si| si.key_locator.as_ref())
                    .cloned();

                if let Some(cert_name) = needed_cert {
                    trace!(name=%data.name, cert=%cert_name, "validation: pending, queuing");

                    // Kick off cert fetch in background.
                    if let Some(fetcher) = &self.cert_fetcher {
                        let fetcher = Arc::clone(fetcher);
                        let cn = Arc::clone(&cert_name);
                        tokio::spawn(async move {
                            let _ = fetcher.fetch(&cn).await;
                        });
                    }

                    self.pending.lock().await.push(ctx, cert_name);
                    // Return Drop so the pipeline doesn't proceed — the packet
                    // will be re-injected after cert fetch via the drain task.
                    Action::Drop(DropReason::ValidationFailed)
                } else {
                    debug!(name=%data.name, "validation: pending but no key locator");
                    Action::Drop(DropReason::ValidationFailed)
                }
            }
            ValidationResult::Invalid(e) => {
                debug!(name=%data.name, error=%e, "validation: FAILED");
                Action::Drop(DropReason::ValidationFailed)
            }
        }
    }

    /// Drain the pending queue and re-validate packets whose certs arrived.
    ///
    /// Called periodically by the drain task spawned in the dispatcher.
    /// Returns actions to inject back into the data pipeline.
    pub async fn drain_pending(&self) -> Vec<Action> {
        let Some(validator) = &self.validator else {
            return Vec::new();
        };

        let results = self.pending.lock().await.drain_ready(validator);
        let mut actions = Vec::with_capacity(results.len());

        for result in results {
            match result {
                DrainResult::Timeout => {
                    actions.push(Action::Drop(DropReason::ValidationTimeout));
                }
                DrainResult::Ready(ctx) => {
                    let data = match &ctx.packet {
                        DecodedPacket::Data(d) => d,
                        _ => {
                            actions.push(Action::Satisfy(ctx));
                            continue;
                        }
                    };
                    // Re-validate now that the cert is cached.
                    match validator.validate_chain(data).await {
                        ValidationResult::Valid(_) => {
                            trace!(name=%data.name, "validation: re-validated after cert fetch");
                            actions.push(Action::Satisfy(ctx));
                        }
                        ValidationResult::Pending => {
                            // Still pending (chain has deeper missing certs).
                            // Re-queue would risk infinite loops; drop instead.
                            debug!(name=%data.name, "validation: still pending after cert fetch, dropping");
                            actions.push(Action::Drop(DropReason::ValidationFailed));
                        }
                        ValidationResult::Invalid(e) => {
                            debug!(name=%data.name, error=%e, "validation: re-validation FAILED");
                            actions.push(Action::Drop(DropReason::ValidationFailed));
                        }
                    }
                }
            }
        }

        actions
    }
}
