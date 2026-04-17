//! Record storage, publication, lifecycle management, and helper utilities.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ndn_packet::Name;
use ndn_transport::FaceId;
use tracing::{debug, info};

use crate::config::DiscoveryScope;
use crate::prefix_announce::ServiceRecord;

use super::ServiceDiscoveryProtocol;

pub(crate) struct RecordEntry {
    pub(super) record: ServiceRecord,
    pub(super) published_at_ms: u64,
    pub(super) expires_at: Option<Instant>,
    /// When this face goes down the record is automatically withdrawn.
    pub(super) owner_face: Option<FaceId>,
}

pub(crate) struct ProducerRateLimit {
    pub(super) count: u32,
    pub(super) window_start: Instant,
}

impl ServiceDiscoveryProtocol {
    pub fn publish(&self, record: ServiceRecord) {
        let ts = current_timestamp_ms();
        let mut records = self.local_records.lock().unwrap();
            let existing = records.iter().position(|e| {
            e.record.announced_prefix == record.announced_prefix
                && e.record.node_name == record.node_name
        });
        info!(
            prefix = %record.announced_prefix,
            node   = %record.node_name,
            freshness_ms = record.freshness_ms,
            "service record published",
        );
        let entry = RecordEntry {
            record,
            published_at_ms: ts,
            expires_at: None,
            owner_face: None,
        };
        if let Some(idx) = existing {
            records[idx] = entry;
        } else {
            records.push(entry);
        }
    }

    pub fn publish_with_ttl(&self, record: ServiceRecord, ttl_ms: u64) {
        let ts = current_timestamp_ms();
        let expires_at = Instant::now() + Duration::from_millis(ttl_ms);
        let mut records = self.local_records.lock().unwrap();
        let existing = records.iter().position(|e| {
            e.record.announced_prefix == record.announced_prefix
                && e.record.node_name == record.node_name
        });
        info!(
            prefix       = %record.announced_prefix,
            node         = %record.node_name,
            freshness_ms = record.freshness_ms,
            ttl_ms,
            "service record published (TTL)",
        );
        let entry = RecordEntry {
            record,
            published_at_ms: ts,
            expires_at: Some(expires_at),
            owner_face: None,
        };
        if let Some(idx) = existing {
            records[idx] = entry;
        } else {
            records.push(entry);
        }
    }

    /// Record is automatically withdrawn when `owner_face` goes down.
    pub fn publish_with_owner(&self, record: ServiceRecord, owner_face: FaceId) {
        let ts = current_timestamp_ms();
        let mut records = self.local_records.lock().unwrap();
        let existing = records.iter().position(|e| {
            e.record.announced_prefix == record.announced_prefix
                && e.record.node_name == record.node_name
        });
        info!(
            prefix       = %record.announced_prefix,
            node         = %record.node_name,
            freshness_ms = record.freshness_ms,
            owner_face   = ?owner_face,
            "service record published (owned by face)",
        );
        let entry = RecordEntry {
            record,
            published_at_ms: ts,
            expires_at: None,
            owner_face: Some(owner_face),
        };
        if let Some(idx) = existing {
            records[idx] = entry;
        } else {
            records.push(entry);
        }
    }

    pub fn withdraw(&self, announced_prefix: &Name) {
        let mut records = self.local_records.lock().unwrap();
        let before = records.len();
        records.retain(|e| &e.record.announced_prefix != announced_prefix);
        if records.len() < before {
            info!(prefix = %announced_prefix, "service record withdrawn");
        } else {
            debug!(prefix = %announced_prefix, "service record withdraw: prefix not found (no-op)");
        }
    }

    pub fn local_records(&self) -> Vec<ServiceRecord> {
        self.local_records
            .lock()
            .unwrap()
            .iter()
            .map(|e| e.record.clone())
            .collect()
    }

    /// All known records (local takes precedence over peer on collision).
    pub fn all_records(&self) -> Vec<ServiceRecord> {
        let local = self.local_records.lock().unwrap();
        let peers = self.peer_records.lock().unwrap();

        let mut out: Vec<ServiceRecord> = local.iter().map(|e| e.record.clone()).collect();
        for pr in peers.iter() {
            let already = out
                .iter()
                .any(|r| r.announced_prefix == pr.announced_prefix && r.node_name == pr.node_name);
            if !already {
                out.push(pr.clone());
            }
        }
        out
    }


    pub(super) fn is_in_scope(&self, _prefix: &Name) -> bool {
        match self.config.auto_populate_scope {
            DiscoveryScope::LinkLocal => {
                // Accept anything under /ndn/local/ or /ndn/site/ for backwards compat
                true
            }
            DiscoveryScope::Site => true,
            DiscoveryScope::Global => true,
        }
    }

    pub(super) fn check_rate_limit(&self, producer: &Name, now: Instant) -> bool {
        let key = producer.to_string();
        let window = self.config.max_registrations_window;
        let limit = self.config.max_registrations_per_producer;

        let mut limits = self.rate_limits.lock().unwrap();
        let entry = limits.entry(key).or_insert_with(|| ProducerRateLimit {
            count: 0,
            window_start: now,
        });

        if now.duration_since(entry.window_start) >= window {
            // New window.
            entry.count = 1;
            entry.window_start = now;
            true
        } else if entry.count < limit {
            entry.count += 1;
            true
        } else {
            false
        }
    }
}

pub(super) fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
