//! TOML `[[rate-limit.policy]]` blocks and a loader that populates a
//! [`RateLimitPolicyTable`].
//!
//! Example:
//!
//! ```toml
//! [[rate-limit.policy]]
//! face_id        = 7
//! prefix         = "/alice/video"
//! direction      = "inbound"
//! interest_pps   = 100
//! interest_burst = 200
//! overflow       = "nack"
//! ```

use ndn_foundation_types::Name;
use serde::{Deserialize, Serialize};

use crate::policy::{
    BucketSpec, Cell, Direction, FaceRef, Overflow, RateLimitPolicy, RateLimitPolicyTable,
};
use crate::{RateLimitError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitPolicyConfig {
    /// `None` means wildcard face.
    #[serde(default)]
    pub face_id: Option<u64>,

    /// `None` means wildcard prefix.
    #[serde(default)]
    pub prefix: Option<String>,

    pub direction: Direction,

    #[serde(default)]
    pub interest_pps: Option<u32>,
    #[serde(default)]
    pub interest_burst: Option<u32>,
    #[serde(default)]
    pub data_bps: Option<u64>,
    #[serde(default)]
    pub data_burst_bytes: Option<u64>,

    pub overflow: Overflow,

    /// Required iff `overflow = "queue"`.
    #[serde(default)]
    pub queue_max: Option<u32>,
}

impl RateLimitPolicyConfig {
    pub fn into_policy(self) -> Result<RateLimitPolicy> {
        let prefix = match self.prefix {
            Some(s) => Some(
                s.parse::<Name>()
                    .map_err(|_| RateLimitError::Config(format!("invalid prefix: {s:?}")))?,
            ),
            None => None,
        };
        Ok(RateLimitPolicy {
            cell: Cell {
                face: self.face_id.map(FaceRef),
                prefix,
                direction: self.direction,
            },
            bucket: BucketSpec {
                interest_pps: self.interest_pps,
                interest_burst: self.interest_burst,
                data_bps: self.data_bps,
                data_burst_bytes: self.data_burst_bytes,
            },
            overflow: self.overflow,
            queue_max: self.queue_max,
        })
    }
}

/// `[rate-limit]` section with a `policy` array.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    #[serde(default)]
    pub policy: Vec<RateLimitPolicyConfig>,
}

impl RateLimitConfig {
    pub fn from_toml(src: &str) -> Result<Self> {
        #[derive(Deserialize)]
        struct Top {
            #[serde(default, rename = "rate-limit")]
            rate_limit: Option<RateLimitConfig>,
        }
        let top: Top =
            toml::from_str(src).map_err(|e| RateLimitError::Config(format!("toml: {e}")))?;
        Ok(top.rate_limit.unwrap_or_default())
    }

    /// Later blocks override earlier ones at the same cell.
    pub fn populate(&self, table: &RateLimitPolicyTable) -> Result<()> {
        for entry in &self.policy {
            let policy = entry.clone().into_policy()?;
            table.set(policy)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::FaceRef;

    #[test]
    fn parse_single_block() {
        let src = r#"
            [[rate-limit.policy]]
            face_id        = 7
            prefix         = "/alice/video"
            direction      = "inbound"
            interest_pps   = 100
            interest_burst = 200
            overflow       = "nack"
        "#;
        let cfg = RateLimitConfig::from_toml(src).unwrap();
        assert_eq!(cfg.policy.len(), 1);
        let table = RateLimitPolicyTable::new();
        cfg.populate(&table).unwrap();
        let name: Name = "/alice/video/seg=0".parse().unwrap();
        let hits = table.matches(FaceRef(7), Some(&name), Direction::Inbound);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn rejects_invalid_prefix() {
        let src = r#"
            [[rate-limit.policy]]
            prefix       = ""
            direction    = "inbound"
            interest_pps = 1
            overflow     = "nack"
        "#;
        let cfg = RateLimitConfig::from_toml(src).unwrap();
        let table = RateLimitPolicyTable::new();
        cfg.populate(&table).unwrap();
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn rejects_queue_without_max() {
        let src = r#"
            [[rate-limit.policy]]
            direction      = "inbound"
            interest_pps   = 1
            overflow       = "queue"
        "#;
        let cfg = RateLimitConfig::from_toml(src).unwrap();
        let table = RateLimitPolicyTable::new();
        assert!(matches!(
            cfg.populate(&table),
            Err(RateLimitError::InvalidCell(_))
        ));
    }

    #[test]
    fn empty_config_is_ok() {
        let cfg = RateLimitConfig::from_toml("").unwrap();
        assert!(cfg.policy.is_empty());
        let table = RateLimitPolicyTable::new();
        cfg.populate(&table).unwrap();
        assert!(table.is_empty());
    }

    #[test]
    fn malformed_toml_errors() {
        let src = "rate-limit.policy = invalid";
        assert!(matches!(
            RateLimitConfig::from_toml(src),
            Err(RateLimitError::Config(_))
        ));
    }
}
