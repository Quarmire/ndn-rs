//! TOML `[[coding.policy]]` blocks and a loader that populates a
//! [`CodingPolicyTable`]. Programmatic and mgmt-API writes shadow TOML at
//! runtime.
//!
//! ```toml
//! [[coding.policy]]
//! prefix      = "/alice/video"
//! mode        = "fec"
//! k           = 16
//! n           = 20
//! field       = "gf8"
//! applies_to  = "produced"
//! ```

use ndn_foundation_types::Name;
use serde::{Deserialize, Serialize};

use crate::policy::{CodingPolicy, CodingPolicyTable, FecPolicy, Field, PolicyRole};
use crate::{CodingError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodingPolicyConfig {
    pub prefix: String,
    pub mode: String,
    pub k: u16,
    pub n: u16,
    #[serde(default = "default_field")]
    pub field: Field,
    pub applies_to: PolicyRole,
}

fn default_field() -> Field {
    Field::Gf8
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CodingConfig {
    #[serde(default)]
    pub policy: Vec<CodingPolicyConfig>,
}

impl CodingPolicyConfig {
    pub fn into_entry(self) -> Result<(Name, PolicyRole, CodingPolicy)> {
        let prefix = self
            .prefix
            .parse::<Name>()
            .map_err(|_| CodingError::Unimplemented("invalid prefix in config"))?;
        let policy = match self.mode.as_str() {
            "fec" => {
                let p = FecPolicy::systematic(self.k, self.n).ok_or(
                    CodingError::InvalidParameters {
                        k: self.k,
                        n: self.n,
                    },
                )?;
                CodingPolicy::Fec(FecPolicy {
                    field: self.field,
                    ..p
                })
            }
            _ => return Err(CodingError::Unimplemented("unknown coding mode in config")),
        };
        Ok((prefix, self.applies_to, policy))
    }
}

impl CodingConfig {
    pub fn from_toml(src: &str) -> Result<Self> {
        #[derive(Deserialize)]
        struct Top {
            #[serde(default)]
            coding: Option<CodingConfig>,
        }
        let top: Top =
            toml::from_str(src).map_err(|_| CodingError::Unimplemented("toml parse failed"))?;
        Ok(top.coding.unwrap_or_default())
    }

    /// Apply every block to `table`; later blocks shadow earlier ones at
    /// the same `(prefix, role)`.
    pub fn populate(&self, table: &CodingPolicyTable) -> Result<()> {
        for entry in &self.policy {
            let (prefix, role, policy) = entry.clone().into_entry()?;
            table.set(&prefix, role, policy);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_single_block() {
        let toml_src = r#"
            [[coding.policy]]
            prefix      = "/alice/video"
            mode        = "fec"
            k           = 16
            n           = 20
            field       = "gf8"
            applies_to  = "produced"
        "#;
        let cfg = CodingConfig::from_toml(toml_src).unwrap();
        assert_eq!(cfg.policy.len(), 1);
        let table = CodingPolicyTable::new();
        cfg.populate(&table).unwrap();
        let p = table
            .lookup(&"/alice/video".parse().unwrap(), PolicyRole::Produced)
            .unwrap();
        match p {
            CodingPolicy::Fec(fp) => assert_eq!((fp.k, fp.n), (16, 20)),
            #[cfg(feature = "f2-recode")]
            CodingPolicy::Rlnc(_) => unreachable!("config inserts only Fec"),
        }
    }

    #[test]
    fn rejects_bad_k_n() {
        let toml_src = r#"
            [[coding.policy]]
            prefix     = "/x"
            mode       = "fec"
            k          = 5
            n          = 4
            applies_to = "produced"
        "#;
        let cfg = CodingConfig::from_toml(toml_src).unwrap();
        let table = CodingPolicyTable::new();
        assert!(matches!(
            cfg.populate(&table),
            Err(CodingError::InvalidParameters { .. })
        ));
    }

    #[test]
    fn rejects_unknown_mode() {
        let toml_src = r#"
            [[coding.policy]]
            prefix     = "/x"
            mode       = "rlnc"
            k          = 4
            n          = 6
            applies_to = "produced"
        "#;
        let cfg = CodingConfig::from_toml(toml_src).unwrap();
        let table = CodingPolicyTable::new();
        assert!(cfg.populate(&table).is_err());
    }

    #[test]
    fn empty_config_is_ok() {
        let cfg = CodingConfig::from_toml("").unwrap();
        assert!(cfg.policy.is_empty());
        let table = CodingPolicyTable::new();
        cfg.populate(&table).unwrap();
        assert!(table.entries().is_empty());
    }
}
