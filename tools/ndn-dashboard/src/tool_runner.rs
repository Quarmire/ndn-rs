//! Shared tool state, types, and helper functions used by the tools view and
//! the tool-runner coroutine in `app.rs`.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use dioxus::prelude::*;

// ── Persistent tab navigation state ──────────────────────────────────────────

/// Which tab is active in the Tools view — persists across navigation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolTab { Ping, Iperf, Peek, Put }

pub static TOOLS_ACTIVE_TAB: GlobalSignal<ToolTab> = Signal::global(|| ToolTab::Ping);
/// Per-tab panel ID lists — persisted so in-flight runs survive tab switches.
pub static PING_IDS:  GlobalSignal<Vec<u32>> = Signal::global(|| vec![next_tool_instance_id()]);
pub static IPERF_IDS: GlobalSignal<Vec<u32>> = Signal::global(|| vec![next_tool_instance_id()]);
pub static PEEK_IDS:  GlobalSignal<Vec<u32>> = Signal::global(|| vec![next_tool_instance_id()]);
pub static PUT_IDS:   GlobalSignal<Vec<u32>> = Signal::global(|| vec![next_tool_instance_id()]);

// ── Tool result table (shared across all tool cards) ──────────────────────────

/// A summary record stored in the shared results table after a tool run completes.
#[derive(Clone, Debug)]
pub struct ToolResultEntry {
    pub id:             u64,
    pub tool:           &'static str,   // "ping" | "iperf" | "put" | "peek"
    pub ts:             String,
    pub label:          String,
    /// Compact single-line params string shown in the collapsed row.
    pub run_summary:    String,
    pub throughput_bps: Option<f64>,
    pub rtt_avg_us:     Option<u64>,
    pub loss_pct:       Option<f64>,
    pub duration_secs:  Option<f64>,
    pub bytes:          Option<u64>,
    /// Per-interval throughput values for the mini sparkline (iperf).
    pub intervals:      Vec<f64>,
    /// Per-probe RTT values for the mini bar chart (ping).
    pub ping_rtts:      Vec<u64>,
    /// Expanded summary lines: run params first, then measured results.
    pub summary_lines:  Vec<String>,
}

pub static TOOL_RESULTS: GlobalSignal<VecDeque<ToolResultEntry>> =
    Signal::global(VecDeque::new);

static TOOL_RESULT_COUNTER: AtomicU64 = AtomicU64::new(1);
static TOOL_INST_COUNTER:   AtomicU32 = AtomicU32::new(1);

pub fn next_result_id() -> u64 {
    TOOL_RESULT_COUNTER.fetch_add(1, Ordering::Relaxed)
}

pub fn next_tool_instance_id() -> u32 {
    TOOL_INST_COUNTER.fetch_add(1, Ordering::Relaxed)
}

// ── Tool instance state ───────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct ToolInstanceState {
    #[allow(dead_code)]
    pub id:             u32,
    pub kind:           &'static str,   // "ping" | "iperf" | "peek" | "put"
    pub running:        bool,
    /// Per-interval throughput samples (bps) for the live line plot — iperf only.
    pub tp_history:     Vec<f64>,
    /// Most recent RTT in microseconds — ping only.
    pub current_rtt_us: Option<u64>,
    /// Recent output lines (capped at 200).
    pub output:         VecDeque<ndn_tools_core::common::ToolEvent>,
    /// Last received IperfSummary data — used to populate TOOL_RESULTS on completion.
    pub iperf_summary:  Option<ndn_tools_core::common::ToolData>,
    /// Last received PingSummary data.
    pub ping_summary:   Option<ndn_tools_core::common::ToolData>,
    /// Accumulated per-probe RTTs for the result mini chart — ping.
    pub ping_rtts:      Vec<u64>,
    /// Label set when Run is called (the prefix being used).
    pub label:          String,
    /// Elapsed seconds since the run started (updated on intervals).
    pub elapsed_secs:   f64,
    /// Wall-clock start time — used to compute elapsed_secs accurately.
    pub start_time:     std::time::Instant,
    /// Key run parameters captured at start — shown in the result entry.
    pub run_params:     Vec<String>,
}

pub static TOOL_INSTANCES: GlobalSignal<std::collections::HashMap<u32, ToolInstanceState>> =
    Signal::global(std::collections::HashMap::new);

// ── Tool commands ─────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum ToolCmd {
    Run  { id: u32, params: ToolParams },
    Stop { id: u32 },
    /// Start the embedded iperf server using the current DashSettings.
    StartIperfServer,
    StopIperfServer,
    /// Start the embedded ping server using the current DashSettings.
    StartPingServer,
    StopPingServer,
}

#[derive(Debug)]
pub enum ToolParams {
    PingClient {
        prefix:      String,
        count:       u64,
        interval_ms: u64,
        lifetime_ms: u64,
    },
    IperfClient {
        prefix:        String,
        duration_secs: u64,
        window:        usize,
        cc:            String,
        reverse:       bool,
        sign_mode:     String,
        /// "shm" or "unix" — selects which face to connect through.
        face_type:     String,
    },
    PeekClient {
        name:        String,
        output_file: Option<String>,
        pipeline:    Option<usize>,
    },
    PutClient {
        name:         String,
        data:         Vec<u8>,
        sign:         bool,
        freshness_ms: u64,
    },
}

// ── Tool helpers ──────────────────────────────────────────────────────────────

/// Return current local time as HH:MM:SS string.
pub fn chrono_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let h = (secs % 86400) / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    format!("{h:02}:{m:02}:{s:02}")
}

/// Build a [`ToolResultEntry`] from a completed [`ToolInstanceState`].
pub fn build_result_entry(inst: &ToolInstanceState, ts: &str) -> ToolResultEntry {
    use ndn_tools_core::common::ToolData;

    let mut throughput_bps = None;
    let mut rtt_avg_us     = None;
    let mut loss_pct_val   = None;
    let mut duration_secs  = None;
    let mut bytes_count    = None;
    let mut stat_lines     = Vec::new();

    if let Some(ToolData::IperfSummary {
        throughput_bps: tp, rtt_avg_us: rtt,
        loss_pct, duration_secs: dur, transferred_bytes, ..
    }) = &inst.iperf_summary
    {
        throughput_bps = Some(*tp);
        rtt_avg_us     = Some(*rtt);
        loss_pct_val   = Some(*loss_pct);
        duration_secs  = Some(*dur);
        bytes_count    = Some(*transferred_bytes);
        stat_lines.push(format!("Throughput:  {}", fmt_bps(*tp)));
        stat_lines.push(format!("Duration:    {:.1}s", dur));
        stat_lines.push(format!("Transferred: {}", fmt_bytes_short(*transferred_bytes)));
        stat_lines.push(format!("RTT avg:     {} µs", rtt));
        stat_lines.push(format!("Loss:        {loss_pct:.1}%"));
    } else if let Some(ToolData::PingSummary {
        rtt_avg_us: rtt, loss_pct,
        rtt_min_us, rtt_max_us, rtt_p99_us, sent, received, ..
    }) = &inst.ping_summary
    {
        rtt_avg_us   = Some(*rtt);
        loss_pct_val = Some(*loss_pct);
        stat_lines.push(format!("Sent:        {sent}  Received: {received}"));
        stat_lines.push(format!("RTT min/avg/max: {rtt_min_us}/{rtt}/{rtt_max_us} µs"));
        stat_lines.push(format!("RTT p99:     {rtt_p99_us} µs"));
        stat_lines.push(format!("Loss:        {loss_pct:.1}%"));
    }

    // Prepend run params, then a blank line, then stats.
    let run_summary = inst.run_params.join("  ·  ");
    let mut summary_lines = Vec::new();
    if !inst.run_params.is_empty() {
        summary_lines.push("── Run params ──────────────────────────".to_string());
        for p in &inst.run_params {
            summary_lines.push(format!("  {p}"));
        }
        if !stat_lines.is_empty() {
            summary_lines.push(String::new());
            summary_lines.push("── Results ─────────────────────────────".to_string());
        }
    }
    summary_lines.extend(stat_lines);

    ToolResultEntry {
        id: next_result_id(),
        tool: inst.kind,
        ts: ts.to_string(),
        label: inst.label.clone(),
        run_summary,
        throughput_bps,
        rtt_avg_us,
        loss_pct: loss_pct_val,
        duration_secs,
        bytes: bytes_count,
        intervals: smooth_data(&inst.tp_history, 60),
        ping_rtts: smooth_rtts(&inst.ping_rtts, 60),
        summary_lines,
    }
}

/// Downsample a throughput series to at most `target_len` values by averaging buckets.
fn smooth_data(data: &[f64], target_len: usize) -> Vec<f64> {
    if data.len() <= target_len { return data.to_vec(); }
    let ratio = data.len() as f64 / target_len as f64;
    (0..target_len).map(|i| {
        let start = (i as f64 * ratio) as usize;
        let end   = ((i + 1) as f64 * ratio) as usize;
        let slice = &data[start..end.min(data.len())];
        if slice.is_empty() { 0.0 } else { slice.iter().sum::<f64>() / slice.len() as f64 }
    }).collect()
}

/// Downsample RTT data (u64 µs) to at most `target_len` values.
fn smooth_rtts(data: &[u64], target_len: usize) -> Vec<u64> {
    if data.len() <= target_len { return data.to_vec(); }
    let ratio = data.len() as f64 / target_len as f64;
    (0..target_len).map(|i| {
        let start = (i as f64 * ratio) as usize;
        let end   = ((i + 1) as f64 * ratio) as usize;
        let slice = &data[start..end.min(data.len())];
        if slice.is_empty() { 0 }
        else { slice.iter().sum::<u64>() / slice.len() as u64 }
    }).collect()
}

// ── Formatting utilities ──────────────────────────────────────────────────────

/// Format bits-per-second as a human-readable string.
pub fn fmt_bps(bps: f64) -> String {
    if bps >= 1e9      { format!("{:.2} Gbps", bps / 1e9) }
    else if bps >= 1e6 { format!("{:.2} Mbps", bps / 1e6) }
    else if bps >= 1e3 { format!("{:.1} Kbps", bps / 1e3) }
    else               { format!("{:.0} bps", bps) }
}

/// Format byte count with 1 decimal place — suitable for dashboard tables.
pub fn fmt_bytes(b: u64) -> String {
    if b >= 1_073_741_824 { format!("{:.1} GB", b as f64 / 1_073_741_824.0) }
    else if b >= 1_048_576 { format!("{:.1} MB", b as f64 / 1_048_576.0) }
    else if b >= 1024      { format!("{:.1} KB", b as f64 / 1024.0) }
    else                   { format!("{b} B") }
}

/// Format byte count with 2 decimal places — suitable for tool result summaries.
pub fn fmt_bytes_short(b: u64) -> String {
    if b >= 1_073_741_824 { format!("{:.2} GB", b as f64 / 1_073_741_824.0) }
    else if b >= 1_048_576 { format!("{:.2} MB", b as f64 / 1_048_576.0) }
    else if b >= 1024      { format!("{:.2} KB", b as f64 / 1024.0) }
    else                   { format!("{b} B") }
}
