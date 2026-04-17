use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;
use tokio::time::Instant;
use tracing::{debug, trace};

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

        // /localhost/ management responses are unsigned by design.
        if data
            .name
            .components()
            .first()
            .map(|c| c.value.as_ref() == b"localhost")
            .unwrap_or(false)
        {
            trace!(name=%data.name, "validation: skipping /localhost/ management data");
            return Action::Satisfy(ctx);
        }

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

                    if let Some(fetcher) = &self.cert_fetcher {
                        let fetcher = Arc::clone(fetcher);
                        let cn = Arc::clone(&cert_name);
                        tokio::spawn(async move {
                            let _ = fetcher.fetch(&cn).await;
                        });
                    }

                    self.pending.lock().await.push(ctx, cert_name);
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
                    let ctx = *ctx;
                    let data = match &ctx.packet {
                        DecodedPacket::Data(d) => d,
                        _ => {
                            actions.push(Action::Satisfy(ctx));
                            continue;
                        }
                    };
                    match validator.validate_chain(data).await {
                        ValidationResult::Valid(_) => {
                            trace!(name=%data.name, "validation: re-validated after cert fetch");
                            actions.push(Action::Satisfy(ctx));
                        }
                        ValidationResult::Pending => {
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
