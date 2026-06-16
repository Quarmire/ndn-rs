//! Cell keys, bucket specs, overflow actions, and the concurrent
//! table that owns the live `TokenBucket`s.

use std::sync::Arc;

use dashmap::DashMap;
use ndn_foundation_types::Name;
use serde::{Deserialize, Serialize};

use crate::bucket::TokenBucket;
use crate::{RateLimitError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Inbound,
    Outbound,
}

/// Newtype around the engine's `FaceId` so this crate doesn't depend
/// on its concrete shape; `From<ndn_transport::FaceId>` is provided.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FaceRef(pub u64);

impl From<ndn_transport::FaceId> for FaceRef {
    fn from(f: ndn_transport::FaceId) -> Self {
        Self(f.0)
    }
}

/// Either field may be `None` ("any"); `(None, None)` is the global
/// default cell.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Cell {
    pub face: Option<FaceRef>,
    pub prefix: Option<Name>,
    pub direction: Direction,
}

/// At least one limit field must be set.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BucketSpec {
    pub interest_pps: Option<u32>,
    pub interest_burst: Option<u32>,
    pub data_bps: Option<u64>,
    pub data_burst_bytes: Option<u64>,
}

impl BucketSpec {
    pub fn pps(rate: u32, burst: u32) -> Self {
        Self {
            interest_pps: Some(rate),
            interest_burst: Some(burst),
            data_bps: None,
            data_burst_bytes: None,
        }
    }

    pub fn bps(rate: u64, burst_bytes: u64) -> Self {
        Self {
            interest_pps: None,
            interest_burst: None,
            data_bps: Some(rate),
            data_burst_bytes: Some(burst_bytes),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Overflow {
    /// NACK(reason=Congestion); default for inbound Interests.
    Nack,
    /// Silent drop; increment metric. Default for outbound Data.
    Drop,
    /// Bounded FIFO; queue overflow falls back to `Drop`.
    Queue,
}

#[derive(Debug, Clone)]
pub struct RateLimitPolicy {
    pub cell: Cell,
    pub bucket: BucketSpec,
    pub overflow: Overflow,
    /// Required iff `overflow == Queue`.
    pub queue_max: Option<u32>,
}

impl RateLimitPolicy {
    fn validate(&self) -> Result<()> {
        if matches!(self.overflow, Overflow::Queue) && self.queue_max.is_none() {
            return Err(RateLimitError::InvalidCell(
                "overflow = queue requires queue_max",
            ));
        }
        if self.bucket.interest_pps.is_none() && self.bucket.data_bps.is_none() {
            return Err(RateLimitError::InvalidCell(
                "BucketSpec must set at least one limit",
            ));
        }
        Ok(())
    }
}

pub struct CellEntry {
    pub policy: RateLimitPolicy,
    pub bucket: Arc<TokenBucket>,
}

/// Concurrent (DashMap) policy table. Hot-path lookup enumerates the
/// cross product `(face | None) × (lpm-chain(name) | None)`. `set`
/// past `max_cells` returns [`RateLimitError::TableFull`] to bound
/// adversary growth.
#[derive(Default)]
pub struct RateLimitPolicyTable {
    cells: DashMap<Cell, Arc<CellEntry>>,
    max_cells: usize,
}

impl RateLimitPolicyTable {
    pub fn new() -> Self {
        Self::with_capacity_bound(4096)
    }

    pub fn with_capacity_bound(max_cells: usize) -> Self {
        Self {
            cells: DashMap::new(),
            max_cells,
        }
    }

    /// Install or replace a policy; bucket built once and `Arc`-shared.
    /// Capacity is enforced on new keys only — updates always succeed.
    pub fn set(&self, policy: RateLimitPolicy) -> Result<()> {
        policy.validate()?;
        let bucket =
            Arc::new(TokenBucket::from_spec(&policy.bucket).map_err(RateLimitError::InvalidCell)?);
        let key = policy.cell.clone();
        let is_update = self.cells.contains_key(&key);
        if !is_update && self.cells.len() >= self.max_cells {
            return Err(RateLimitError::TableFull);
        }
        self.cells.insert(
            key,
            Arc::new(CellEntry {
                policy: policy.clone(),
                bucket,
            }),
        );
        Ok(())
    }

    /// No-op if absent.
    pub fn unset(&self, cell: &Cell) -> Result<()> {
        self.cells.remove(cell);
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.cells.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cells.is_empty()
    }

    /// Every cell matching `(face, name, direction)`, deepest prefix
    /// first then wildcards. Returned `Arc`s let the hot path drop
    /// the table lock immediately.
    pub fn matches(
        &self,
        face: FaceRef,
        name: Option<&Name>,
        direction: Direction,
    ) -> Vec<Arc<CellEntry>> {
        let mut out = Vec::new();
        for face_key in [Some(face), None] {
            if let Some(name) = name {
                let mut current = Some(name.clone());
                while let Some(p) = current.take() {
                    if let Some(entry) = self.cells.get(&Cell {
                        face: face_key,
                        prefix: Some(p.clone()),
                        direction,
                    }) {
                        out.push(Arc::clone(entry.value()));
                    }
                    if p.is_empty() {
                        break;
                    }
                    let comps = p.components();
                    if comps.is_empty() {
                        break;
                    }
                    current = Some(Name::from_components(comps[..comps.len() - 1].to_vec()));
                }
            }
            if let Some(entry) = self.cells.get(&Cell {
                face: face_key,
                prefix: None,
                direction,
            }) {
                out.push(Arc::clone(entry.value()));
            }
        }
        out
    }

    pub fn entries(&self) -> Vec<Arc<CellEntry>> {
        self.cells.iter().map(|kv| Arc::clone(kv.value())).collect()
    }
}

impl std::fmt::Debug for RateLimitPolicyTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimitPolicyTable")
            .field("cells", &self.cells.len())
            .field("max_cells", &self.max_cells)
            .finish()
    }
}

pub type SharedPolicyTable = Arc<RateLimitPolicyTable>;

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(face: Option<u64>, prefix: Option<&str>, dir: Direction) -> RateLimitPolicy {
        RateLimitPolicy {
            cell: Cell {
                face: face.map(FaceRef),
                prefix: prefix.map(|p| p.parse().unwrap()),
                direction: dir,
            },
            bucket: BucketSpec::pps(100, 200),
            overflow: Overflow::Nack,
            queue_max: None,
        }
    }

    #[test]
    fn rejects_empty_bucket_spec() {
        let mut p = policy(None, Some("/a"), Direction::Inbound);
        p.bucket = BucketSpec {
            interest_pps: None,
            interest_burst: None,
            data_bps: None,
            data_burst_bytes: None,
        };
        let table = RateLimitPolicyTable::new();
        assert!(matches!(table.set(p), Err(RateLimitError::InvalidCell(_))));
    }

    #[test]
    fn rejects_queue_without_max() {
        let mut p = policy(None, Some("/a"), Direction::Inbound);
        p.overflow = Overflow::Queue;
        p.queue_max = None;
        let table = RateLimitPolicyTable::new();
        assert!(matches!(table.set(p), Err(RateLimitError::InvalidCell(_))));
    }

    #[test]
    fn lookup_face_only_cell() {
        let table = RateLimitPolicyTable::new();
        table
            .set(policy(Some(5), None, Direction::Inbound))
            .unwrap();
        let hits = table.matches(FaceRef(5), None, Direction::Inbound);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn lookup_prefix_lpm() {
        let table = RateLimitPolicyTable::new();
        table
            .set(policy(None, Some("/alice"), Direction::Inbound))
            .unwrap();
        table
            .set(policy(None, Some("/alice/video"), Direction::Inbound))
            .unwrap();
        let n: Name = "/alice/video/seg=0".parse().unwrap();
        let hits = table.matches(FaceRef(1), Some(&n), Direction::Inbound);
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn lookup_combines_face_and_prefix_axes() {
        let table = RateLimitPolicyTable::new();
        table
            .set(policy(Some(7), Some("/alice"), Direction::Inbound))
            .unwrap();
        table
            .set(policy(None, Some("/alice"), Direction::Inbound))
            .unwrap();
        table
            .set(policy(Some(7), None, Direction::Inbound))
            .unwrap();
        table.set(policy(None, None, Direction::Inbound)).unwrap();
        let n: Name = "/alice/video".parse().unwrap();
        let hits = table.matches(FaceRef(7), Some(&n), Direction::Inbound);
        assert_eq!(hits.len(), 4);
        let hits = table.matches(FaceRef(99), Some(&n), Direction::Inbound);
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn lookup_respects_direction() {
        let table = RateLimitPolicyTable::new();
        table
            .set(policy(Some(1), None, Direction::Inbound))
            .unwrap();
        assert_eq!(table.matches(FaceRef(1), None, Direction::Inbound).len(), 1);
        assert_eq!(
            table.matches(FaceRef(1), None, Direction::Outbound).len(),
            0
        );
    }

    #[test]
    fn capacity_bound_rejects_new_when_full() {
        let table = RateLimitPolicyTable::with_capacity_bound(2);
        table
            .set(policy(Some(1), None, Direction::Inbound))
            .unwrap();
        table
            .set(policy(Some(2), None, Direction::Inbound))
            .unwrap();
        let third = policy(Some(3), None, Direction::Inbound);
        assert!(matches!(table.set(third), Err(RateLimitError::TableFull)));
        table
            .set(policy(Some(1), None, Direction::Inbound))
            .unwrap();
    }

    #[test]
    fn unset_removes_entry() {
        let table = RateLimitPolicyTable::new();
        let p = policy(Some(1), None, Direction::Inbound);
        table.set(p.clone()).unwrap();
        assert_eq!(table.len(), 1);
        table.unset(&p.cell).unwrap();
        assert_eq!(table.len(), 0);
    }
}
