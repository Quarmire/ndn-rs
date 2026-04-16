use dioxus::prelude::*;

// Default helpers for serde — called when a field is missing in the JSON file.
// This allows old settings files (saved before a field was added) to load without error.
fn serde_default_ping_prefix() -> String {
    "/ping".to_string()
}
fn serde_default_iperf_prefix() -> String {
    "/iperf".to_string()
}
fn serde_default_iperf_size() -> u32 {
    8192
}
fn serde_default_iperf_face_type() -> String {
    "shm".to_string()
}
fn serde_default_results_max_entries() -> usize {
    100
}

/// Persistent dashboard settings, saved to `~/.config/ndn-dashboard/settings.json`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)] // missing fields fall back to Default::default() …
pub struct DashSettings {
    /// This node's NDN name prefix (e.g. "/alice/home"). Used as base for server names.
    pub node_prefix: String,
    // Ping server
    pub ping_server_auto: bool,
    #[serde(default = "serde_default_ping_prefix")]
    pub ping_prefix: String,
    /// Show a notification when the ping server receives a probe.
    pub ping_notify_connections: bool,
    // Iperf server
    pub iperf_server_auto: bool,
    #[serde(default = "serde_default_iperf_prefix")]
    pub iperf_prefix: String,
    #[serde(default = "serde_default_iperf_size")]
    pub iperf_size: u32,
    /// Transport for the embedded iperf server: "shm" | "unix" | "app".
    #[serde(default = "serde_default_iperf_face_type")]
    pub iperf_face_type: String,
    /// Show a notification when an iperf client connects.
    pub iperf_notify_connections: bool,
    /// Use a fully custom name instead of <node_prefix>/iperf.
    pub iperf_use_custom_name: bool,
    /// Custom full prefix (used when iperf_use_custom_name is true).
    pub iperf_custom_name: String,
    /// Maximum number of tool result entries to keep in the results table.
    #[serde(default = "serde_default_results_max_entries")]
    pub results_max_entries: usize,
    // Experimental
    pub exp_benchmarks: bool,
    pub exp_wasm_strategy: bool,
    pub exp_did: bool,
    pub exp_sync: bool,
    /// Run ndn-ping/ndn-iperf embedded in-process instead of launching subprocesses.
    pub exp_embedded_tools: bool,
}

impl Default for DashSettings {
    fn default() -> Self {
        Self {
            node_prefix: String::new(),
            ping_server_auto: false,
            ping_prefix: "/ping".to_string(),
            ping_notify_connections: false,
            iperf_server_auto: false,
            iperf_prefix: "/iperf".to_string(),
            iperf_size: 8192,
            iperf_face_type: "shm".to_string(),
            iperf_notify_connections: false,
            iperf_use_custom_name: false,
            iperf_custom_name: String::new(),
            results_max_entries: 100,
            exp_benchmarks: false,
            exp_wasm_strategy: false,
            exp_did: false,
            exp_sync: false,
            exp_embedded_tools: false,
        }
    }
}

// ── Desktop: filesystem persistence ──────────────────────────────────────────

#[cfg(feature = "desktop")]
fn settings_path() -> std::path::PathBuf {
    dirs_next::config_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("ndn-dashboard")
        .join("settings.json")
}

#[cfg(feature = "desktop")]
pub fn load_settings() -> DashSettings {
    let path = settings_path();
    if let Ok(content) = std::fs::read_to_string(&path)
        && let Ok(s) = serde_json::from_str(&content)
    {
        return s;
    }
    DashSettings::default()
}

#[cfg(feature = "desktop")]
pub fn save_settings(settings: &DashSettings) -> anyhow::Result<()> {
    let path = settings_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, serde_json::to_string_pretty(settings)?)?;
    Ok(())
}

// ── Web: localStorage persistence ────────────────────────────────────────────

#[cfg(feature = "web")]
pub fn load_settings() -> DashSettings {
    use gloo_storage::{LocalStorage, Storage};
    LocalStorage::get("ndn-dashboard-settings").unwrap_or_default()
}

#[cfg(feature = "web")]
pub fn save_settings(settings: &DashSettings) -> anyhow::Result<()> {
    use gloo_storage::{LocalStorage, Storage};
    LocalStorage::set("ndn-dashboard-settings", settings)
        .map_err(|e| anyhow::anyhow!("localStorage write failed: {:?}", e))
}

// ── Fallback if neither feature is active ────────────────────────────────────

#[cfg(not(any(feature = "desktop", feature = "web")))]
pub fn load_settings() -> DashSettings {
    DashSettings::default()
}

#[cfg(not(any(feature = "desktop", feature = "web")))]
pub fn save_settings(_settings: &DashSettings) -> anyhow::Result<()> {
    Ok(())
}

pub static DASH_SETTINGS: GlobalSignal<DashSettings> = Signal::global(load_settings);
