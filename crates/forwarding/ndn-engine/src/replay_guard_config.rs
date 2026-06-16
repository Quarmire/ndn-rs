//! Replay-guard configuration shared between native [`crate::EngineBuilder`]
//! and wasm [`crate::WasmEngineBuilder`].

/// Default is "enabled, capacity 64, non-monotonic" — the safe baseline for
/// production engines. Callers whose signed-Interest emitters are strictly
/// monotonic (hardened CA setups) can opt into [`ReplayGuardConfig::monotonic`];
/// [`ReplayGuardConfig::disabled`] is a test-only escape hatch.
#[derive(Clone, Copy, Debug)]
pub struct ReplayGuardConfig {
    pub enabled: bool,
    pub per_key_capacity: usize,
    pub monotonic: bool,
}

impl ReplayGuardConfig {
    /// Test-only. Production engines must leave the guard enabled.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            per_key_capacity: 64,
            monotonic: false,
        }
    }

    /// Adds monotonic seq/time enforcement on top of the LRU window. Only
    /// safe when callers emit strictly increasing timestamps / seq numbers;
    /// otherwise legitimate re-attaches after clock skew or restart are
    /// rejected as replays.
    pub fn monotonic() -> Self {
        Self {
            enabled: true,
            per_key_capacity: 64,
            monotonic: true,
        }
    }
}

impl Default for ReplayGuardConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            // 64 records per signer key ≈ 5 KB per active key.
            per_key_capacity: 64,
            // NDNCERT clients and ndn-mgmt callers legitimately re-attach
            // after clock skew, device sleep, or process restart.
            monotonic: false,
        }
    }
}
