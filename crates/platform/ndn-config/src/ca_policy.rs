//! What a `[ca]` / `[[ca]]` entry states about its namespace's policies, as
//! the [`PolicyInput`] the namespace's trust context is reconciled with
//! ([`ndn_cert::ca_policy`]): a namespace CA enforces what its context
//! advertises and refuses to start when its entry states another policy;
//! `ndn-fwd init` and a schema update (the CLI's `schema update -c`, an
//! admin screen's) write the stated policy into the next version.

use ndn_cert::PolicyInput;
use ndn_packet::{Name, NameError};
use ndn_security::AdvertisedRelay;

use crate::config::{CaRelayConfig, CaTomlConfig};

/// Why a `[[ca.relay]]` entry cannot be advertised.
#[derive(Debug, thiserror::Error)]
pub enum CaPolicyError {
    /// `device` is not an NDN name.
    #[error("[[ca.relay]] device {device:?} is not an NDN name: {reason}")]
    RelayDevice {
        device: String,
        #[source]
        reason: NameError,
    },
    /// `key` is not 64 hex digits.
    #[error("[[ca.relay]] {device}: key must be 64 hex digits, not {key:?}")]
    RelayKey { device: Name, key: String },
}

impl CaTomlConfig {
    /// What `approval_roles` / `approval_requires_invite` / `link_roles` /
    /// `relay_roles` / `enrollment_links` / `direct_paths` / `direct_pairs`
    /// / `[[ca.relay]]` state; each unset key defers to the trust context
    /// ([`PolicyInput::enforced_policy`] checks them against it).
    pub fn policy_input(&self) -> Result<PolicyInput, CaPolicyError> {
        let relays = self
            .relays
            .as_ref()
            .map(|relays| relays.iter().map(CaRelayConfig::advertised).collect())
            .transpose()?;
        Ok(PolicyInput {
            approval_roles: self.approval_roles.clone(),
            approval_requires_invite: self.approval_requires_invite,
            link_roles: self.link_roles.clone(),
            relay_roles: self.relay_roles.clone(),
            enrollment_links: self.enrollment_links,
            direct_paths: self.direct_paths,
            direct_pairs: self.direct_pairs.clone(),
            relays,
        })
    }
}

impl CaRelayConfig {
    /// This entry as the trust context carries it.
    pub fn advertised(&self) -> Result<AdvertisedRelay, CaPolicyError> {
        let device: Name = self
            .device
            .parse()
            .map_err(|reason| CaPolicyError::RelayDevice {
                device: self.device.clone(),
                reason,
            })?;
        let key = self
            .key
            .as_deref()
            .map(|hex| {
                fingerprint(hex).ok_or_else(|| CaPolicyError::RelayKey {
                    device: device.clone(),
                    key: hex.to_owned(),
                })
            })
            .transpose()?;
        Ok(AdvertisedRelay {
            device,
            key,
            endpoints: self.endpoint.clone(),
            preference: self.preference,
        })
    }
}

/// 64 hex digits as the 32 octets of a fingerprint.
fn fingerprint(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(hex.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relay(key: Option<&str>) -> CaRelayConfig {
        CaRelayConfig {
            device: "/home/node/relay".to_owned(),
            key: key.map(str::to_owned),
            endpoint: vec!["relay.example:6363".to_owned()],
            preference: 1,
        }
    }

    #[test]
    fn a_relay_key_is_exactly_64_hex_digits() {
        let key = "ab".repeat(32);
        assert_eq!(
            relay(Some(&key)).advertised().unwrap().key,
            Some([0xab; 32])
        );
        for bad in ["ab".repeat(31), "zz".repeat(32), format!("{key}00")] {
            assert!(matches!(
                relay(Some(&bad)).advertised(),
                Err(CaPolicyError::RelayKey { .. })
            ));
        }
    }

    #[test]
    fn unset_keys_state_nothing() {
        assert_eq!(
            CaTomlConfig::default().policy_input().unwrap(),
            PolicyInput::default()
        );
    }
}
