//! `impl MgmtConfig for ForwarderConfig`.
//!
//! Gated behind the `mgmt` feature. `ndn-mgmt` (spec, the NFD management
//! protocol) defines the [`MgmtConfig`] read surface its command handlers need;
//! this crate (extension, the forwarder TOML) implements it for
//! [`ForwarderConfig`]. The dependency edge therefore runs extension → spec,
//! and consumers that only parse config (without mounting management) never
//! pull the management stack.

use crate::config::ForwarderConfig;
use ndn_mgmt::{CaInfo, MgmtConfig};

impl MgmtConfig for ForwarderConfig {
    fn to_toml_string(&self) -> Result<String, String> {
        ForwarderConfig::to_toml_string(self).map_err(|e| e.to_string())
    }

    fn security_identity(&self) -> Option<&str> {
        self.security.identity.as_deref()
    }

    fn pib_path(&self) -> Option<&str> {
        self.security.pib_path.as_deref()
    }

    fn require_signed_commands(&self) -> bool {
        self.security.mgmt.require_signed_commands
    }

    fn mgmt_trust_anchor_pib(&self) -> Option<&str> {
        self.security.mgmt.trust_anchor_pib.as_deref()
    }

    fn localhop_trust_anchor_pib(&self) -> Option<&str> {
        self.security.mgmt.localhop_trust_anchor_pib.as_deref()
    }

    fn ca_info(&self) -> Option<CaInfo<'_>> {
        let sec = &self.security;
        sec.ca_prefix.as_deref().map(|prefix| CaInfo {
            prefix,
            info: &sec.ca_info,
            max_validity_days: sec.ca_max_validity_days,
            challenges: &sec.ca_challenges,
        })
    }
}
