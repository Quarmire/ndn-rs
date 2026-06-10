//! Per-face **routing-cost prior** — the static "how good is this link" hint a
//! cost-aware forwarding strategy uses *before* it has any live measurement.
//!
//! This is the static counterpart to the dynamic per-face `LinkSignals` (RSSI,
//! RTT, throughput, congestion) in `ndn-signals-core`: the profile gives a fresh
//! route a sane cost so it prefers the fast link before any traffic has flowed,
//! and the measured signals refine it once traffic is observed.
//!
//! It lives in `ndn-transport` (which owns the face taxonomy) so **every**
//! forwarder — desktop, embedded, mobile, the simulator — can rank its faces by
//! cost, not just the mobile node. Lower cost is preferred.

use crate::face::FaceKind;

/// A per-[`FaceKind`] routing-cost prior. The defaults rank faces by rough
/// throughput/energy (wired < LAN < Wi-Fi Aware < BLE); override any with
/// [`with_cost`](Self::with_cost). Holds only overrides, so it's cheap to clone
/// and the defaults stay in one place.
#[derive(Clone, Debug, Default)]
pub struct LinkProfile {
    overrides: Vec<(FaceKind, u32)>,
}

impl LinkProfile {
    /// The routing cost for `kind` — an override if set, else a sane default.
    pub fn cost(&self, kind: FaceKind) -> u32 {
        if let Some((_, c)) = self.overrides.iter().find(|(k, _)| *k == kind) {
            return *c;
        }
        Self::default_cost(kind)
    }

    /// The built-in cost for a face kind (no overrides applied).
    pub fn default_cost(kind: FaceKind) -> u32 {
        match kind {
            FaceKind::Ethernet => 5,
            FaceKind::Udp => 10, // LAN multicast / unicast
            FaceKind::Tcp => 15, // uplink
            FaceKind::WifiAware => 20, // NAN follow-up: AP-less, mid throughput
            FaceKind::Bluetooth => 50, // BLE advertising: universal but slow
            _ => 30,
        }
    }

    /// Override the cost for a face kind (last write wins).
    pub fn with_cost(mut self, kind: FaceKind, cost: u32) -> Self {
        self.overrides.retain(|(k, _)| *k != kind);
        self.overrides.push((kind, cost));
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_rank_radios_and_overrides_win() {
        let p = LinkProfile::default();
        // wired < LAN < Wi-Fi Aware < BLE
        assert!(p.cost(FaceKind::Ethernet) < p.cost(FaceKind::Udp));
        assert!(p.cost(FaceKind::Udp) < p.cost(FaceKind::WifiAware));
        assert!(p.cost(FaceKind::WifiAware) < p.cost(FaceKind::Bluetooth));

        let tuned = LinkProfile::default().with_cost(FaceKind::Bluetooth, 7);
        assert_eq!(tuned.cost(FaceKind::Bluetooth), 7);
        assert_eq!(tuned.cost(FaceKind::WifiAware), 20); // others unchanged
    }
}
