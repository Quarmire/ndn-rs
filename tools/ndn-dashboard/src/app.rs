use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Duration;

use dioxus::prelude::*;
use futures::StreamExt as _;
use ndn_ipc::MgmtClient;

use crate::{
    router_proc,
    settings::DASH_SETTINGS,
    styles::CSS,
    tool_runner::{
        ToolCmd, ToolParams, ToolResultEntry, ToolInstanceState,
        TOOL_RESULTS, TOOL_INSTANCES,
        next_result_id,
        build_result_entry, chrono_now,
    },
    tray,
    types::*,
    views::{
        View,
        config::Config,
        dashboard_config::DashboardConfig,
        fleet::Fleet,
        logs::Logs,
        modals::StartRouterModal,
        onboarding::{is_onboarded, Onboarding},
        overview::Overview,
        radio::Radio,
        security::Security,
        session::Session,
        strategy::Strategy,
        tools::Tools,
    },
};

// ── Global reactive state ────────────────────────────────────────────────────
// GlobalSignal is shared across all windows spawned from this process.

pub static ROUTER_LOG:         GlobalSignal<VecDeque<LogEntry>> = Signal::global(VecDeque::new);
pub static LOG_FILTER:         GlobalSignal<String>             = Signal::global(String::new);
pub static ROUTER_RUNNING:     GlobalSignal<bool>               = Signal::global(|| false);
/// Set by LogPane in any window; polled by the main cmd coroutine each tick.
pub static PENDING_LOG_FILTER: GlobalSignal<Option<String>>     = Signal::global(|| None);
/// Last ring-buffer sequence number received from the router.
/// Reset to 0 on each new connection so that the first poll fetches all buffered lines.
pub static LAST_LOG_SEQ:       GlobalSignal<u64>                = Signal::global(|| 0);
/// Logs tab split layout — persisted as u8 so the Logs view can be remounted
/// without losing the user's split choice. 0=Single, 1=Horizontal, 2=Vertical.
pub static LOG_SPLIT_MODE:     GlobalSignal<u8>                 = Signal::global(|| 0u8);
/// Logs tab split ratio (percent for the first pane, 20–80).
pub static LOG_SPLIT_RATIO:    GlobalSignal<u32>                = Signal::global(|| 50u32);
/// Saved config presets: (name, toml_string).
pub static CONFIG_PRESETS:     GlobalSignal<Vec<(String, String)>> = Signal::global(Vec::new);

/// Currently active view — writable from anywhere (tray, tool shortcuts, etc.).
pub static ACTIVE_VIEW: GlobalSignal<crate::views::View> = Signal::global(|| crate::views::View::Overview);

/// Dark mode toggle — `true` = dark (default), `false` = light.
pub static DARK_MODE: GlobalSignal<bool> = Signal::global(|| true);

// ── Toast notifications ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(dead_code)]
pub enum ToastLevel { Info, Success, Warning, Error }

impl ToastLevel {
    pub fn css_class(self) -> &'static str {
        match self {
            ToastLevel::Info    => "toast-info",
            ToastLevel::Success => "toast-success",
            ToastLevel::Warning => "toast-warning",
            ToastLevel::Error   => "toast-error",
        }
    }
    pub fn icon(self) -> &'static str {
        match self {
            ToastLevel::Info    => "ℹ",
            ToastLevel::Success => "✓",
            ToastLevel::Warning => "⚠",
            ToastLevel::Error   => "✕",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Toast {
    pub id:      u64,
    pub message: String,
    pub level:   ToastLevel,
    pub created: std::time::Instant,
}

pub static TOASTS:  GlobalSignal<std::collections::VecDeque<Toast>> = Signal::global(std::collections::VecDeque::new);
static TOAST_ID:    GlobalSignal<u64>                               = Signal::global(|| 0u64);

pub fn push_toast(msg: impl Into<String>, level: ToastLevel) {
    let mut id = TOAST_ID.write();
    *id += 1;
    TOASTS.write().push_back(Toast { id: *id, message: msg.into(), level, created: std::time::Instant::now() });
}


// ── Commands ─────────────────────────────────────────────────────────────────

/// Operations sent to the background polling coroutine.
#[derive(Debug)]
pub enum DashCmd {
    FaceCreate(String),
    FaceDestroy(u64),
    RouteAdd { prefix: String, face_id: u64, cost: u64 },
    RouteRemove { prefix: String, face_id: u64 },
    StrategySet { prefix: String, strategy: String },
    StrategyUnset(String),
    CsCapacity(u64),
    CsErase(String),
    Shutdown,
    Reconnect,
    RefreshConfig,
    RecordStart,
    RecordStop,
    RecordClear,
    ReplaySession,
    SecurityGenerate(String),
    SecurityKeyDelete(String),
    SecurityEnroll { ca_prefix: String, challenge_type: String, challenge_param: String },
    SecurityTokenAdd(String),
    YubikeyDetect,
    YubikeyGeneratePiv(String),
}

/// Commands sent to the router-management coroutine.
#[derive(Debug)]
pub enum RouterCmd {
    /// Start the router. `None` = use built-in defaults; `Some(path)` = pass `--config <path>`.
    Start(Option<String>),
    Stop,
}


// ── Connection state ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum ConnState {
    Disconnected,
    Connecting,
    Connected,
    Error(String),
}

impl ConnState {
    pub fn badge_class(&self) -> &'static str {
        match self {
            ConnState::Connected    => "badge badge-green",
            ConnState::Connecting   => "badge badge-yellow",
            ConnState::Disconnected => "badge badge-gray",
            ConnState::Error(_)     => "badge badge-red",
        }
    }
    pub fn label(&self) -> String {
        match self {
            ConnState::Connected    => "Connected".into(),
            ConnState::Connecting   => "Connecting…".into(),
            ConnState::Disconnected => "Disconnected".into(),
            ConnState::Error(e)     => format!("Error: {e}"),
        }
    }
}

// ── Shared context ───────────────────────────────────────────────────────────

/// All reactive state exposed to child view components via `use_context`.
#[derive(Clone, Copy)]
pub struct AppCtx {
    #[allow(dead_code)]
    pub conn:              Signal<ConnState>,
    pub status:            Signal<Option<ForwarderStatus>>,
    pub faces:             Signal<Vec<FaceInfo>>,
    pub routes:            Signal<Vec<FibEntry>>,
    pub cs:                Signal<Option<CsInfo>>,
    pub strategies:        Signal<Vec<StrategyEntry>>,
    pub counters:          Signal<Vec<FaceCounter>>,
    pub measurements:      Signal<Vec<MeasurementEntry>>,
    pub config_toml:       Signal<String>,
    pub throughput:        Signal<VecDeque<ThroughputSample>>,
    #[allow(dead_code)]
    pub prev_counters:     Signal<ThroughputSample>,
    pub session_log:       Signal<Vec<SessionEntry>>,
    pub recording:         Signal<bool>,
    pub neighbors:         Signal<Vec<NeighborInfo>>,
    pub security_keys:     Signal<Vec<SecurityKeyInfo>>,
    pub security_anchors:  Signal<Vec<AnchorInfo>>,
    pub ca_info:           Signal<Option<CaInfo>>,
    pub yubikey_status:    Signal<Option<String>>,
    pub cs_hit_history:    Signal<VecDeque<f64>>,
    /// Per-face throughput rate history (60 samples × 3 s = 3 min window).
    pub face_throughput:   Signal<HashMap<u64, VecDeque<ThroughputSample>>>,
    pub router_cmd:        Coroutine<RouterCmd>,
    pub cmd:               Coroutine<DashCmd>,
    pub tool_cmd:          Coroutine<ToolCmd>,
}

// ── Root component ───────────────────────────────────────────────────────────

#[component]
pub fn App() -> Element {
    // Initialise the system tray once (must run on the main thread, after the
    // OS event loop has started — use_hook fires during the first render).
    use_hook(tray::setup);

    let mut conn_state:      Signal<ConnState>                    = use_signal(|| ConnState::Disconnected);
    let mut socket_path:     Signal<String>                       = use_signal(default_socket_path);
    let status:          Signal<Option<ForwarderStatus>>      = use_signal(|| None);
    let faces:           Signal<Vec<FaceInfo>>                = use_signal(Vec::new);
    let routes:          Signal<Vec<FibEntry>>                = use_signal(Vec::new);
    let cs:              Signal<Option<CsInfo>>               = use_signal(|| None);
    let strategies:      Signal<Vec<StrategyEntry>>           = use_signal(Vec::new);
    let counters:        Signal<Vec<FaceCounter>>             = use_signal(Vec::new);
    let measurements:    Signal<Vec<MeasurementEntry>>        = use_signal(Vec::new);
    let config_toml:     Signal<String>                       = use_signal(String::new);
    let throughput:      Signal<VecDeque<ThroughputSample>>   = use_signal(VecDeque::new);
    let prev_counters:   Signal<ThroughputSample>             = use_signal(ThroughputSample::default);
    let session_log:     Signal<Vec<SessionEntry>>            = use_signal(Vec::new);
    let recording:       Signal<bool>                         = use_signal(|| false);
    let neighbors:       Signal<Vec<NeighborInfo>>            = use_signal(Vec::new);
    let security_keys:   Signal<Vec<SecurityKeyInfo>>         = use_signal(Vec::new);
    let security_anchors: Signal<Vec<AnchorInfo>>             = use_signal(Vec::new);
    let ca_info:         Signal<Option<CaInfo>>               = use_signal(|| None);
    let yubikey_status:  Signal<Option<String>>               = use_signal(|| None);
    let cs_hit_history:  Signal<VecDeque<f64>>               = use_signal(VecDeque::new);
    let face_throughput: Signal<HashMap<u64, VecDeque<ThroughputSample>>> = use_signal(HashMap::new);
    let face_prev_ctr:   Signal<HashMap<u64, ThroughputSample>>           = use_signal(HashMap::new);
    let mut error_msg: Signal<Option<String>> = use_signal(|| None);
    let mut show_onboarding: Signal<bool>                     = use_signal(|| !is_onboarded());
    let mut show_start_modal: Signal<bool>                    = use_signal(|| false);
    let mut show_gear_menu:   Signal<bool>                    = use_signal(|| false);

    // Apply initial theme on mount and reactively on change.
    use_effect(move || {
        let dark = *DARK_MODE.read();
        if dark {
            let _ = document::eval("document.documentElement.classList.remove('light-mode')");
        } else {
            let _ = document::eval("document.documentElement.classList.add('light-mode')");
        }
    });

    // Shared channel: router_cmd → tool_cmd server lifecycle commands.
    // Defined before both coroutines so each can capture its end.
    let (srv_cmd_tx, srv_cmd_rx) =
        tokio::sync::mpsc::unbounded_channel::<ToolCmd>();
    // Wrap both ends in Arc so closures (FnMut) can clone the Arc each invocation.
    // The actual sender/receiver is taken from the Option on first (and only) call.
    let srv_cmd_tx_arc = std::sync::Arc::new(srv_cmd_tx);
    let srv_cmd_rx_cell = std::sync::Arc::new(std::sync::Mutex::new(Some(srv_cmd_rx)));

    // ── Router management coroutine ──────────────────────────────────────────
    // Owns the RouterProc, watches for process exit, drains log lines.
    let srv_cmd_tx_arc_r = srv_cmd_tx_arc.clone();
    let router_cmd = use_coroutine(move |mut rx: UnboundedReceiver<RouterCmd>| {
        let srv_cmd_tx = srv_cmd_tx_arc_r.clone();
        async move {
        let mut proc: Option<router_proc::RouterProc> = None;
        let mut check = tokio::time::interval(Duration::from_millis(500));

        loop {
            tokio::select! {
                _ = check.tick() => {
                    if let Some(ref mut p) = proc {
                        if !p.is_running() {
                            proc = None;
                            *ROUTER_RUNNING.write() = false;
                            // Stop in-process tool servers when router dies.
                            let _ = srv_cmd_tx.send(ToolCmd::StopPingServer);
                            let _ = srv_cmd_tx.send(ToolCmd::StopIperfServer);
                        } else {
                            let lines = p.drain_logs();
                            if !lines.is_empty() {
                                let mut log = ROUTER_LOG.write();
                                for entry in lines {
                                    log.push_back(entry);
                                    if log.len() > 2000 { log.pop_front(); }
                                }
                            }
                        }
                    }
                }
                Some(cmd) = rx.next() => {
                    match cmd {
                        RouterCmd::Start(config_path) => {
                            if proc.is_none() {
                                match router_proc::find_binary() {
                                    Some(bin) => {
                                        match router_proc::RouterProc::start(&bin, config_path.as_deref()).await {
                                            Ok(p) => {
                                                *ROUTER_RUNNING.write() = true;
                                                proc = Some(p);

                                                // Give the router a moment to bind its socket.
                                                tokio::time::sleep(Duration::from_millis(800)).await;

                                                // Auto-start in-process servers if configured.
                                                let s = DASH_SETTINGS.peek().clone();
                                                if s.ping_server_auto  { let _ = srv_cmd_tx.send(ToolCmd::StartPingServer);  }
                                                if s.iperf_server_auto { let _ = srv_cmd_tx.send(ToolCmd::StartIperfServer); }
                                            }
                                            Err(e) => tracing::error!("start router: {e}"),
                                        }
                                    }
                                    None => tracing::warn!("ndn-router binary not found in PATH"),
                                }
                            }
                        }
                        RouterCmd::Stop => {
                            // Stop in-process tool servers first.
                            let _ = srv_cmd_tx.send(ToolCmd::StopPingServer);
                            let _ = srv_cmd_tx.send(ToolCmd::StopIperfServer);
                            if let Some(ref mut p) = proc {
                                p.kill().await;
                            }
                            proc = None;
                            *ROUTER_RUNNING.write() = false;
                        }
                    }
                }
            }
        }
        } // close async move
    }); // close FnMut closure + use_coroutine

    // ── Tray polling coroutine ───────────────────────────────────────────────
    // Updates the tray icon colour and forwards menu events.
    use_coroutine(move |_: UnboundedReceiver<()>| async move {
        let mut interval = tokio::time::interval(Duration::from_millis(500));
        loop {
            interval.tick().await;

            // Prune old toasts (older than 5 seconds) — only write if there is
            // actually something to remove, to avoid spurious reactive updates.
            {
                let now = std::time::Instant::now();
                if TOASTS.read().iter().any(|t| now.duration_since(t.created).as_secs() >= 5) {
                    TOASTS.write().retain(|t| now.duration_since(t.created).as_secs() < 5);
                }
            }

            // Sync icon/tooltip with current state.
            let connected = matches!(*conn_state.read(), ConnState::Connected);
            let running   = *ROUTER_RUNNING.read();
            tray::update_state(connected, running);

            // Forward tray-menu events.
            while let Some(tc) = tray::poll_menu_event() {
                match tc {
                    tray::TrayCmd::StartRouter   => router_cmd.send(RouterCmd::Start(None)),
                    tray::TrayCmd::StopRouter    => router_cmd.send(RouterCmd::Stop),
                    tray::TrayCmd::OpenDashboard => { /* window is always open */ }
                    tray::TrayCmd::OpenTools     => { *ACTIVE_VIEW.write() = View::Tools; }
                    tray::TrayCmd::SendFile      => { *ACTIVE_VIEW.write() = View::Tools; }
                    tray::TrayCmd::Quit => {
                        // Kill managed router process before exiting.
                        router_cmd.send(RouterCmd::Stop);
                        std::process::exit(0);
                    }
                }
            }
        }
    });

    // Background coroutine: owns the MgmtClient, polls data, handles commands.
    let cmd = use_coroutine(move |mut rx: UnboundedReceiver<DashCmd>| async move {
        loop {
            conn_state.set(ConnState::Connecting);
            let path = socket_path.peek().clone();

            let client = match MgmtClient::connect(&path).await {
                Ok(c) => c,
                Err(e) => {
                    conn_state.set(ConnState::Error(e.to_string()));
                    // Wait up to 3s before retry; Reconnect command skips the wait.
                    let sleep = tokio::time::sleep(Duration::from_secs(3));
                    tokio::pin!(sleep);
                    loop {
                        tokio::select! {
                            _ = &mut sleep => break,
                            Some(cmd) = rx.next() => {
                                if matches!(cmd, DashCmd::Reconnect) { break }
                                // discard other cmds while disconnected
                            }
                        }
                    }
                    continue;
                }
            };

            conn_state.set(ConnState::Connected);
            error_msg.set(None);
            // Reset the log cursor so the first poll fetches all buffered lines.
            *LAST_LOG_SEQ.write() = 0;

            if let Err(e) = poll_all(&client, status, faces, routes, cs, strategies, counters, measurements, config_toml, throughput, prev_counters, neighbors, security_keys, security_anchors, ca_info, cs_hit_history, face_throughput, face_prev_ctr).await {
                conn_state.set(ConnState::Disconnected);
                error_msg.set(Some(e));
                continue;
            }

            let mut interval = tokio::time::interval(Duration::from_secs(3));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            interval.tick().await; // first tick is immediate; consume it

            'session: loop {
                tokio::select! {
                    _ = interval.tick() => {
                        if let Err(e) = poll_all(&client, status, faces, routes, cs, strategies, counters, measurements, config_toml, throughput, prev_counters, neighbors, security_keys, security_anchors, ca_info, cs_hit_history, face_throughput, face_prev_ctr).await {
                            conn_state.set(ConnState::Disconnected);
                            error_msg.set(Some(e));
                            break 'session;
                        }
                    }
                    Some(cmd_msg) = rx.next() => {
                        if matches!(cmd_msg, DashCmd::Reconnect) {
                            break 'session;
                        }
                        run_cmd(cmd_msg, &client, status, faces, routes, cs, strategies, counters, measurements, error_msg, config_toml, throughput, prev_counters, session_log, recording, neighbors, security_keys, security_anchors, ca_info, yubikey_status, cs_hit_history, face_throughput, face_prev_ctr).await;
                    }
                }
            }
        }
    });

    // ── Embedded tool coroutine ──────────────────────────────────────────────
    // Manages multiple simultaneous tool instances. Each Run creates a new task
    // tracked by its instance ID; Stop cancels a specific instance immediately.
    // All GlobalSignal writes happen here — inside the Dioxus runtime.
    //
    // Reserved IDs: SRV_PING_ID / SRV_IPERF_ID for in-process servers.
    const SRV_PING_ID:  u32 = u32::MAX - 1;
    const SRV_IPERF_ID: u32 = u32::MAX;

    let srv_cmd_rx_cell2 = srv_cmd_rx_cell.clone();
    let tool_cmd = use_coroutine(move |mut rx: UnboundedReceiver<ToolCmd>| {
        let srv_cmd_rx_cell = srv_cmd_rx_cell2.clone();
        async move {
        use ndn_tools_core::common::{ConnectConfig, ToolData};

        // Take srv_cmd_rx out of the Mutex (only happens once on coroutine init).
        let mut srv_rx = srv_cmd_rx_cell
            .lock().unwrap()
            .take()
            .expect("srv_cmd_rx already taken");

        // Channel: (instance_id, Option<ToolEvent>). None = tool completed.
        let (ev_tx, mut ev_rx) =
            tokio::sync::mpsc::unbounded_channel::<(u32, Option<ndn_tools_core::common::ToolEvent>)>();

        // Map of instance_id → abort handle for currently running tools.
        let mut handles: std::collections::HashMap<u32, tokio::task::AbortHandle> =
            std::collections::HashMap::new();

        loop {
            // Merge UI commands and server lifecycle commands into a single Option<ToolCmd>.
            let maybe_cmd: Option<ToolCmd> = tokio::select! {
                Some(cmd) = rx.next() => Some(cmd),
                Some(cmd) = srv_rx.recv() => Some(cmd),
                Some((inst_id, ev_opt)) = ev_rx.recv() => {
                    // ── Tool output / completion events ────────────────────
                    match ev_opt {
                        None => {
                            // Tool completed naturally.
                            handles.remove(&inst_id);
                            // Server IDs don't produce result entries.
                            if inst_id != SRV_PING_ID && inst_id != SRV_IPERF_ID {
                                let ts = chrono_now();
                                let max_results = DASH_SETTINGS.peek().results_max_entries
                                    .max(1); // guard against 0 (corrupt settings)
                                let mut insts = TOOL_INSTANCES.write();
                                if let Some(inst) = insts.get_mut(&inst_id) {
                                    inst.running = false;
                                    // Only save a result if there is meaningful data.
                                    let has_data = inst.iperf_summary.is_some()
                                        || inst.ping_summary.is_some()
                                        || !inst.tp_history.is_empty();
                                    if has_data {
                                        let entry = build_result_entry(inst, &ts);
                                        let mut results = TOOL_RESULTS.write();
                                        results.push_front(entry);
                                        while results.len() > max_results { results.pop_back(); }
                                    }
                                }
                            }
                        }
                        Some(ev) => {
                            if inst_id == SRV_IPERF_ID {
                                // Server connection notification → create result entry.
                                if let Some(ToolData::IperfClientConnected {
                                    flow_id, duration_secs, sign_mode, payload_size, reverse,
                                }) = &ev.structured {
                                    let ts = chrono_now();
                                    let mode = if *reverse { "reverse" } else { "forward" };
                                    let entry = ToolResultEntry {
                                        id:             next_result_id(),
                                        ts,
                                        tool:           "iperf-server",
                                        label:          format!("session {flow_id}"),
                                        run_summary:    format!("{mode}  ·  sign={sign_mode}  ·  size={payload_size}B"),
                                        throughput_bps: None,
                                        bytes:          None,
                                        duration_secs:  Some(*duration_secs as f64),
                                        loss_pct:       None,
                                        rtt_avg_us:     None,
                                        summary_lines:  vec![
                                            format!("mode={mode}"),
                                            format!("sign={sign_mode}"),
                                            format!("size={payload_size}B"),
                                        ],
                                        intervals:  vec![],
                                        ping_rtts:  vec![],
                                    };
                                    let max_results = DASH_SETTINGS.peek().results_max_entries;
                                    let mut results = TOOL_RESULTS.write();
                                    results.push_front(entry);
                                    while results.len() > max_results { results.pop_back(); }
                                }
                            } else if inst_id != SRV_PING_ID {
                                let mut insts = TOOL_INSTANCES.write();
                                if let Some(inst) = insts.get_mut(&inst_id) {
                                    match &ev.structured {
                                        Some(ToolData::IperfInterval { throughput_bps, .. }) => {
                                            inst.tp_history.push(*throughput_bps);
                                            inst.elapsed_secs = inst.start_time.elapsed().as_secs_f64();
                                            if inst.tp_history.len() > 480 { inst.tp_history.remove(0); }
                                        }
                                        Some(ToolData::IperfSummary { .. }) => {
                                            inst.iperf_summary = ev.structured.clone();
                                        }
                                        Some(ToolData::PingResult { rtt_us, .. }) => {
                                            inst.current_rtt_us = Some(*rtt_us);
                                            inst.ping_rtts.push(*rtt_us);
                                            if inst.ping_rtts.len() > 500 { inst.ping_rtts.remove(0); }
                                        }
                                        Some(ToolData::PingSummary { .. }) => {
                                            inst.ping_summary = ev.structured.clone();
                                        }
                                        _ => {}
                                    }
                                    inst.output.push_back(ev);
                                    if inst.output.len() > 200 { inst.output.pop_front(); }
                                }
                            }
                        }
                    }
                    None // no command to process
                }
            };

            let Some(cmd) = maybe_cmd else { continue };

            // ── Dispatch tool command ──────────────────────────────────────
            match cmd {
                ToolCmd::Stop { id } => {
                    if let Some(inst) = TOOL_INSTANCES.write().get_mut(&id) {
                        inst.running = false;
                    }
                    if let Some(h) = handles.remove(&id) { h.abort(); }
                }

                ToolCmd::Run { id, params } => {
                    // Cancel any previous run for this instance slot.
                    if let Some(h) = handles.remove(&id) { h.abort(); }

                    let settings = DASH_SETTINGS.peek().clone();
                    let node_pfx = if settings.node_prefix.is_empty() {
                        None
                    } else {
                        Some(settings.node_prefix.clone())
                    };

                    match &params {
                        ToolParams::PingClient { prefix, count, interval_ms, lifetime_ms } => {
                            TOOL_INSTANCES.write().insert(id, ToolInstanceState {
                                id, kind: "ping", running: true,
                                tp_history: Vec::new(), current_rtt_us: None,
                                output: VecDeque::new(),
                                iperf_summary: None, ping_summary: None,
                                ping_rtts: Vec::new(),
                                label: prefix.clone(), elapsed_secs: 0.0,
                                start_time: std::time::Instant::now(),
                                run_params: vec![
                                    format!("count={count}"),
                                    format!("interval={interval_ms}ms"),
                                    format!("lifetime={lifetime_ms}ms"),
                                ],
                            });
                        }
                        ToolParams::IperfClient { prefix, duration_secs, window, cc, reverse, sign_mode, face_type } => {
                            let mut rp = vec![
                                format!("duration={duration_secs}s"),
                                format!("window={window}"),
                                format!("cc={cc}"),
                                format!("sign={sign_mode}"),
                                format!("face={face_type}"),
                            ];
                            if *reverse { rp.push("reverse".to_string()); }
                            TOOL_INSTANCES.write().insert(id, ToolInstanceState {
                                id, kind: "iperf", running: true,
                                tp_history: Vec::new(), current_rtt_us: None,
                                output: VecDeque::new(),
                                iperf_summary: None, ping_summary: None,
                                ping_rtts: Vec::new(),
                                label: prefix.clone(), elapsed_secs: 0.0,
                                start_time: std::time::Instant::now(),
                                run_params: rp,
                            });
                        }
                        ToolParams::PeekClient { name, pipeline, .. } => {
                            TOOL_INSTANCES.write().insert(id, ToolInstanceState {
                                id, kind: "peek", running: true,
                                tp_history: Vec::new(), current_rtt_us: None,
                                output: VecDeque::new(),
                                iperf_summary: None, ping_summary: None,
                                ping_rtts: Vec::new(),
                                label: name.clone(), elapsed_secs: 0.0,
                                start_time: std::time::Instant::now(),
                                run_params: match pipeline {
                                    Some(p) => vec![format!("pipeline={p}")],
                                    None    => vec![],
                                },
                            });
                        }
                        ToolParams::PutClient { name, sign, freshness_ms, data } => {
                            TOOL_INSTANCES.write().insert(id, ToolInstanceState {
                                id, kind: "put", running: true,
                                tp_history: Vec::new(), current_rtt_us: None,
                                output: VecDeque::new(),
                                iperf_summary: None, ping_summary: None,
                                ping_rtts: Vec::new(),
                                label: name.clone(), elapsed_secs: 0.0,
                                start_time: std::time::Instant::now(),
                                run_params: {
                                    let mut rp = vec![format!("{}B", data.len())];
                                    if *sign { rp.push("signed".to_string()); }
                                    if *freshness_ms > 0 { rp.push(format!("freshness={freshness_ms}ms")); }
                                    rp
                                },
                            });
                        }
                    }

                    // Spawn a single task that joins run_fut + bridge_fut, then
                    // sends the completion signal — no race between bridge and done.
                    // If the tool returns an error (e.g. node_prefix missing for
                    // reverse mode), forward it as an error event so it's visible.
                    let done_tx = ev_tx.clone();
                    let fwd_tx  = ev_tx.clone();
                    let face_socket = socket_path.peek().clone();

                    let h = match params {
                        ToolParams::PingClient { prefix, count, interval_ms, lifetime_ms } => {
                            tokio::spawn(async move {
                                let (ttx, mut trx) = tokio::sync::mpsc::channel(256);
                                let run_fut = ndn_tools_core::ping::run_client(
                                    ndn_tools_core::ping::PingClientParams {
                                        conn: ConnectConfig { face_socket, use_shm: true },
                                        prefix, count, interval_ms, lifetime_ms,
                                    }, ttx);
                                let bridge_fut = async {
                                    while let Some(ev) = trx.recv().await {
                                        let _ = fwd_tx.send((id, Some(ev)));
                                    }
                                };
                                let (res, _) = tokio::join!(run_fut, bridge_fut);
                                if let Err(e) = res {
                                    let _ = fwd_tx.send((id, Some(ndn_tools_core::common::ToolEvent::error(format!("Error: {e}")))));
                                }
                                let _ = done_tx.send((id, None));
                            })
                        }
                        ToolParams::IperfClient { prefix, duration_secs, window, cc, reverse, sign_mode, face_type } => {
                            tokio::spawn(async move {
                                let (ttx, mut trx) = tokio::sync::mpsc::channel(256);
                                let conn = ConnectConfig {
                                    face_socket,
                                    use_shm: face_type == "shm",
                                };
                                let run_fut = ndn_tools_core::iperf::run_client(
                                    ndn_tools_core::iperf::IperfClientParams {
                                        conn,
                                        prefix, duration_secs, initial_window: window, cc,
                                        min_window: None, max_window: None,
                                        ai: None, md: None, cubic_c: None,
                                        lifetime_ms: 4000, quiet: false,
                                        interval_ms: 250, reverse,
                                        node_prefix: node_pfx, sign_mode,
                                    }, ttx);
                                let bridge_fut = async {
                                    while let Some(ev) = trx.recv().await {
                                        let _ = fwd_tx.send((id, Some(ev)));
                                    }
                                };
                                let (res, _) = tokio::join!(run_fut, bridge_fut);
                                if let Err(e) = res {
                                    let _ = fwd_tx.send((id, Some(ndn_tools_core::common::ToolEvent::error(format!("Error: {e}")))));
                                }
                                let _ = done_tx.send((id, None));
                            })
                        }
                        ToolParams::PeekClient { name, output_file, pipeline } => {
                            tokio::spawn(async move {
                                let (ttx, mut trx) = tokio::sync::mpsc::channel(256);
                                let run_fut = ndn_tools_core::peek::run_peek(
                                    ndn_tools_core::peek::PeekParams {
                                        conn: ConnectConfig { face_socket, use_shm: true },
                                        name, lifetime_ms: 4000,
                                        output: output_file, pipeline,
                                        hex: false, meta_only: false,
                                        verbose: false, can_be_prefix: false,
                                    }, ttx);
                                let bridge_fut = async {
                                    while let Some(ev) = trx.recv().await {
                                        let _ = fwd_tx.send((id, Some(ev)));
                                    }
                                };
                                let (res, _) = tokio::join!(run_fut, bridge_fut);
                                if let Err(e) = res {
                                    let _ = fwd_tx.send((id, Some(ndn_tools_core::common::ToolEvent::error(format!("Error: {e}")))));
                                }
                                let _ = done_tx.send((id, None));
                            })
                        }
                        ToolParams::PutClient { name, data, sign, freshness_ms } => {
                            let data_bytes = bytes::Bytes::from(data);
                            tokio::spawn(async move {
                                let (ttx, mut trx) = tokio::sync::mpsc::channel(256);
                                let run_fut = ndn_tools_core::put::run_producer(
                                    ndn_tools_core::put::PutParams {
                                        conn: ConnectConfig { face_socket, use_shm: true },
                                        name, data: data_bytes,
                                        chunk_size: 0, sign, hmac: false,
                                        freshness_ms, timeout_secs: 0, quiet: false,
                                    }, ttx);
                                let bridge_fut = async {
                                    while let Some(ev) = trx.recv().await {
                                        let _ = fwd_tx.send((id, Some(ev)));
                                    }
                                };
                                let (res, _) = tokio::join!(run_fut, bridge_fut);
                                if let Err(e) = res {
                                    let _ = fwd_tx.send((id, Some(ndn_tools_core::common::ToolEvent::error(format!("Error: {e}")))));
                                }
                                let _ = done_tx.send((id, None));
                            })
                        }
                    };
                    handles.insert(id, h.abort_handle());
                }

                ToolCmd::StartIperfServer => {
                    if handles.contains_key(&SRV_IPERF_ID) { continue; }
                    let settings = DASH_SETTINGS.peek().clone();
                    let iperf_prefix = if settings.iperf_use_custom_name && !settings.iperf_custom_name.is_empty() {
                        settings.iperf_custom_name.clone()
                    } else if !settings.node_prefix.is_empty() {
                        format!("{}{}", settings.node_prefix.trim_end_matches('/'), settings.iperf_prefix)
                    } else {
                        settings.iperf_prefix.clone()
                    };
                    let payload_size = settings.iperf_size as usize;
                    let face_socket = socket_path.peek().clone();
                    let fwd_tx = ev_tx.clone();
                    let done_tx = ev_tx.clone();
                    let h = tokio::spawn(async move {
                        let (ttx, mut trx) = tokio::sync::mpsc::channel(256);
                        let run_fut = ndn_tools_core::iperf::run_server(
                            ndn_tools_core::iperf::IperfServerParams {
                                conn: ConnectConfig { face_socket, use_shm: true },
                                prefix: iperf_prefix,
                                payload_size,
                                freshness_ms: 0,
                                quiet: true,
                                interval_ms: 1000,
                            }, ttx);
                        let bridge_fut = async {
                            while let Some(ev) = trx.recv().await {
                                let _ = fwd_tx.send((SRV_IPERF_ID, Some(ev)));
                            }
                        };
                        let _ = tokio::join!(run_fut, bridge_fut);
                        let _ = done_tx.send((SRV_IPERF_ID, None));
                    });
                    handles.insert(SRV_IPERF_ID, h.abort_handle());
                }

                ToolCmd::StopIperfServer => {
                    if let Some(h) = handles.remove(&SRV_IPERF_ID) { h.abort(); }
                }

                ToolCmd::StartPingServer => {
                    if handles.contains_key(&SRV_PING_ID) { continue; }
                    let settings = DASH_SETTINGS.peek().clone();
                    let ping_prefix = if !settings.node_prefix.is_empty() {
                        format!("{}{}", settings.node_prefix.trim_end_matches('/'), settings.ping_prefix)
                    } else {
                        settings.ping_prefix.clone()
                    };
                    let face_socket = socket_path.peek().clone();
                    let fwd_tx = ev_tx.clone();
                    let done_tx = ev_tx.clone();
                    let h = tokio::spawn(async move {
                        let (ttx, mut trx) = tokio::sync::mpsc::channel(256);
                        let run_fut = ndn_tools_core::ping::run_server(
                            ndn_tools_core::ping::PingServerParams {
                                conn: ConnectConfig { face_socket, use_shm: true },
                                prefix: ping_prefix,
                                freshness_ms: 0,
                                sign: false,
                            }, ttx);
                        let bridge_fut = async {
                            while let Some(ev) = trx.recv().await {
                                let _ = fwd_tx.send((SRV_PING_ID, Some(ev)));
                            }
                        };
                        let _ = tokio::join!(run_fut, bridge_fut);
                        let _ = done_tx.send((SRV_PING_ID, None));
                    });
                    handles.insert(SRV_PING_ID, h.abort_handle());
                }

                ToolCmd::StopPingServer => {
                    if let Some(h) = handles.remove(&SRV_PING_ID) { h.abort(); }
                }
            }
        }
        } // close async move
    }); // close FnMut closure + use_coroutine

    let ctx = AppCtx {
        conn: conn_state,
        status,
        faces,
        routes,
        cs,
        strategies,
        counters,
        measurements,
        config_toml,
        throughput,
        prev_counters,
        session_log,
        recording,
        neighbors,
        security_keys,
        security_anchors,
        ca_info,
        yubikey_status,
        cs_hit_history,
        face_throughput,
        router_cmd,
        cmd,
        tool_cmd,
    };
    use_context_provider(move || ctx);

    // Derive security health from keys for the sidebar dot
    let sec_dot_class = {
        let keys = security_keys.read();
        if keys.is_empty() {
            "sec-dot sec-dot-gray"
        } else {
            let (cls, _) = keys[0].expiry_badge();
            match cls {
                "badge badge-green"  => "sec-dot sec-dot-green",
                "badge badge-yellow" => "sec-dot sec-dot-yellow",
                "badge badge-red"    => "sec-dot sec-dot-red",
                _                    => "sec-dot sec-dot-gray",
            }
        }
    };
    let sec_dot_tooltip = {
        let keys = security_keys.read();
        if keys.is_empty() {
            "No identity configured — go to Security tab".to_string()
        } else {
            let k = &keys[0];
            let (_, _expiry_label) = k.expiry_badge();
            let cert_status = if k.has_cert { "issued" } else { "none" };
            let days = k.days_to_expiry()
                .map(|d| if d < 0 { "EXPIRED".to_string() } else if d == 0 { "expires today".to_string() } else { format!("{d}d remaining") })
                .unwrap_or_else(|| "permanent".to_string());
            format!("{}\nCert: {}\nExpiry: {}", k.name, cert_status, days)
        }
    };

    rsx! {
        document::Style { "{CSS}" }

        // First-time onboarding overlay (shown until ~/.ndn/dashboard-onboarded exists).
        if *show_onboarding.read() {
            Onboarding {
                on_complete: move |_| show_onboarding.set(false),
            }
        }

        // StartRouterModal — rendered as a fixed overlay outside the layout
        if *show_start_modal.read() {
            StartRouterModal {
                on_close: move |_| show_start_modal.set(false),
                config_toml,
            }
        }

        ToastOverlay {}

        div { class: "layout",
            // ── Sidebar navigation ─────────────────────────────────────────
            nav { class: "sidebar",
                div { class: "sidebar-logo",
                    style: "display:flex;align-items:center;justify-content:space-between;",
                    span { "NDN Dashboard" }
                    span {
                        class: "{sec_dot_class}",
                        "data-tooltip": "{sec_dot_tooltip}",
                    }
                }
                for view in View::NAV {
                    {
                        let view = *view;
                        let is_active = *ACTIVE_VIEW.read() == view;
                        rsx! {
                            div {
                                class: if is_active { "nav-item active" } else { "nav-item" },
                                onclick: move |_| { *ACTIVE_VIEW.write() = view; },
                                "{view.label()}"
                            }
                        }
                    }
                }

                // Sidebar spacer pushes gear to the bottom
                div { class: "sidebar-spacer" }

                // Gear menu at bottom
                div { class: "sidebar-bottom",
                    if *show_gear_menu.read() {
                        div { class: "gear-menu",
                            div {
                                class: "gear-menu-item",
                                onclick: move |_| {
                                    *ACTIVE_VIEW.write() = View::DashboardConfig;
                                    show_gear_menu.set(false);
                                },
                                "Dashboard Config"
                            }
                            div {
                                class: "gear-menu-item",
                                onclick: move |_| {
                                    *ACTIVE_VIEW.write() = View::RouterConfig;
                                    show_gear_menu.set(false);
                                },
                                "Router Config"
                            }
                        }
                    }
                    button {
                        class: "icon-btn",
                        style: "width:100%;text-align:left;",
                        onclick: move |_| { let v = *show_gear_menu.read(); show_gear_menu.set(!v); },
                        "⚙ Settings"
                    }
                }
            }

            // ── Main area ──────────────────────────────────────────────────
            div { class: "main",
                // Connection bar
                div { class: "conn-bar",
                    span {
                        class: "{conn_state.read().badge_class()}",
                        "{conn_state.read().label()}"
                    }
                    input {
                        r#type: "text",
                        placeholder: "Socket path",
                        value: "{socket_path}",
                        oninput: move |e| socket_path.set(e.value()),
                    }
                    button {
                        class: "btn btn-secondary",
                        onclick: move |_| cmd.send(DashCmd::Reconnect),
                        "Connect"
                    }
                    // Icon buttons
                    button {
                        class: "icon-btn",
                        title: "Refresh",
                        onclick: move |_| cmd.send(DashCmd::Reconnect),
                        "⟳"
                    }
                    // Spacer
                    div { style: "flex:1;" }
                    // Theme toggle
                    button {
                        class: "theme-toggle",
                        title: if *DARK_MODE.read() { "Switch to Light Mode" } else { "Switch to Dark Mode" },
                        onclick: move |_| {
                            let next = !*DARK_MODE.read();
                            *DARK_MODE.write() = next;
                            if next {
                                let _ = document::eval("document.documentElement.classList.remove('light-mode')");
                            } else {
                                let _ = document::eval("document.documentElement.classList.add('light-mode')");
                            }
                        },
                        if *DARK_MODE.read() { "☀" } else { "🌙" }
                    }
                    // Vertical separator
                    div { style: "width:1px;height:20px;background:var(--border);flex-shrink:0;" }
                    // Router process controls (right side)
                    {
                        let running = *ROUTER_RUNNING.read();
                        rsx! {
                            span {
                                class: if running { "badge badge-green" } else { "badge badge-gray" },
                                style: "flex-shrink:0;",
                                if running { "Router Running" } else { "Router Stopped" }
                            }
                            if !running {
                                button {
                                    class: "btn btn-primary btn-sm",
                                    onclick: move |_| show_start_modal.set(true),
                                    "▶ Start"
                                }
                                if *conn_state.read() == ConnState::Connected {
                                    button {
                                        class: "btn btn-danger btn-sm",
                                        onclick: move |_| cmd.send(DashCmd::Shutdown),
                                        "■ Shutdown"
                                    }
                                }
                            } else {
                                button {
                                    class: "btn btn-danger btn-sm",
                                    onclick: move |_| router_cmd.send(RouterCmd::Stop),
                                    "■ Stop"
                                }
                            }
                        }
                    }
                }

                // Content — Logs gets a full-height flex container; other views
                // use the padded scrollable .content div.
                if *ACTIVE_VIEW.read() == View::Logs {
                    div { style: "flex:1;min-height:0;overflow:hidden;display:flex;flex-direction:column;",
                        if let Some(ref err) = *error_msg.read() {
                            div { class: "error-banner", style: "margin:8px 12px 0;",
                                span { "{err}" }
                                button {
                                    class: "btn btn-secondary btn-sm",
                                    onclick: move |_| error_msg.set(None),
                                    "✕"
                                }
                            }
                        }
                        Logs {}
                    }
                } else {
                    div { class: "content",
                        if let Some(ref err) = *error_msg.read() {
                            div { class: "error-banner",
                                span { "{err}" }
                                button {
                                    class: "btn btn-secondary btn-sm",
                                    onclick: move |_| error_msg.set(None),
                                    "✕"
                                }
                            }
                        }
                        {render_view(*ACTIVE_VIEW.read())}
                    }
                }
            }
        }
    }
}

#[component]
fn ToastOverlay() -> Element {
    let toasts = TOASTS.read();
    if toasts.is_empty() { return rsx! {}; }
    rsx! {
        div { class: "toast-container",
            for toast in toasts.iter() {
                {
                    let id = toast.id;
                    let icon = toast.level.icon();
                    let msg = toast.message.clone();
                    let cls = toast.level.css_class();
                    rsx! {
                        div { class: "toast {cls}",
                            div { class: "toast-body",
                                span { class: "toast-icon", "{icon}" }
                                span { class: "toast-msg", "{msg}" }
                            }
                            button {
                                class: "toast-close",
                                onclick: move |_| { TOASTS.write().retain(|t| t.id != id); },
                                "✕"
                            }
                        }
                    }
                }
            }
        }
    }
}

fn render_view(view: View) -> Element {
    match view {
        View::Overview        => rsx! { Overview {} },
        View::Strategy        => rsx! { Strategy {} },
        View::Logs            => rsx! { },  // rendered via full-height branch in App
        View::Session         => rsx! { Session {} },
        View::Security        => rsx! { Security {} },
        View::Fleet           => rsx! { Fleet {} },
        View::Radio           => rsx! { Radio {} },
        View::Tools           => rsx! { Tools {} },
        View::DashboardConfig => rsx! { DashboardConfig {} },
        View::RouterConfig    => rsx! { Config {} },
    }
}


fn default_socket_path() -> String {
    #[cfg(windows)]
    return r"\\.\pipe\ndn".to_string();
    #[cfg(not(windows))]
    "/tmp/ndn.sock".to_string()
}

// ── Polling ───────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn poll_all(
    client:                  &MgmtClient,
    mut status:              Signal<Option<ForwarderStatus>>,
    mut faces:               Signal<Vec<FaceInfo>>,
    mut routes:              Signal<Vec<FibEntry>>,
    mut cs:                  Signal<Option<CsInfo>>,
    mut strategies:          Signal<Vec<StrategyEntry>>,
    mut counters:            Signal<Vec<FaceCounter>>,
    mut measurements:        Signal<Vec<MeasurementEntry>>,
    mut config_toml:         Signal<String>,
    mut throughput:          Signal<VecDeque<ThroughputSample>>,
    mut prev_counters:       Signal<ThroughputSample>,
    mut neighbors:           Signal<Vec<NeighborInfo>>,
    mut security_keys:       Signal<Vec<SecurityKeyInfo>>,
    mut security_anchors:    Signal<Vec<AnchorInfo>>,
    mut ca_info:             Signal<Option<CaInfo>>,
    mut cs_hit_history:      Signal<VecDeque<f64>>,
    mut face_throughput:     Signal<HashMap<u64, VecDeque<ThroughputSample>>>,
    mut face_prev_ctr:       Signal<HashMap<u64, ThroughputSample>>,
) -> Result<(), String> {
    match client.status().await {
        Ok(r)  => status.set(Some(ForwarderStatus::parse(&r.status_text))),
        Err(e) => return Err(e.to_string()),
    }
    match client.face_list().await {
        Ok(r)  => faces.set(FaceInfo::parse_list(&r.status_text)),
        Err(e) => return Err(e.to_string()),
    }
    match client.route_list().await {
        Ok(r)  => routes.set(FibEntry::parse_list(&r.status_text)),
        Err(e) => return Err(e.to_string()),
    }
    match client.cs_info().await {
        Ok(r)  => cs.set(CsInfo::parse(&r.status_text)),
        Err(e) => return Err(e.to_string()),
    }
    match client.strategy_list().await {
        Ok(r)  => strategies.set(StrategyEntry::parse_list(&r.status_text)),
        Err(e) => return Err(e.to_string()),
    }
    // Phase 2 endpoints — best-effort: ignore errors so older routers still work.
    if let Ok(r) = client.face_counters().await {
        counters.set(FaceCounter::parse_list(&r.status_text));
    }
    if let Ok(r) = client.measurements_list().await {
        measurements.set(MeasurementEntry::parse_list(&r.status_text));
    }
    // Config — fetch once on first connect; RefreshConfig command forces re-fetch.
    if config_toml.read().is_empty()
        && let Ok(r) = client.config_get().await
    {
        config_toml.set(r.status_text);
    }
    // Per-face throughput history — compute per-second rates per face.
    {
        let curr_counters = counters.read();
        let active: HashSet<u64> = curr_counters.iter().map(|c| c.face_id).collect();
        let mut fp = face_prev_ctr.write();
        let mut fh = face_throughput.write();
        for c in curr_counters.iter() {
            let fid = c.face_id;
            let curr_snap = ThroughputSample::from_face_counter(c);
            let prev_snap = fp.get(&fid).cloned().unwrap_or_default();
            let rate = ThroughputSample::rate_from_delta(&prev_snap, &curr_snap, 3.0);
            fp.insert(fid, curr_snap);
            let hist = fh.entry(fid).or_insert_with(VecDeque::new);
            hist.push_back(rate);
            if hist.len() > 60 { hist.pop_front(); }
        }
        fh.retain(|k, _| active.contains(k));
        fp.retain(|k, _| active.contains(k));
    }
    // Throughput history — aggregate across all faces.
    {
        let curr = ThroughputSample::from_counters(&counters.read());
        let rate = ThroughputSample::rate_from_delta(&prev_counters.read(), &curr, 3.0);
        prev_counters.set(curr);
        let mut hist = throughput.write();
        hist.push_back(rate);
        if hist.len() > 60 { hist.pop_front(); }
    }
    // Phase 4 endpoints — best-effort.
    if let Ok(r) = client.neighbors_list().await {
        neighbors.set(NeighborInfo::parse_list(&r.status_text));
    }
    if let Ok(r) = client.security_identity_list().await {
        security_keys.set(SecurityKeyInfo::parse_list(&r.status_text));
    }
    if let Ok(r) = client.security_anchor_list().await {
        security_anchors.set(AnchorInfo::parse_list(&r.status_text));
    }
    if let Ok(r) = client.security_ca_info().await {
        ca_info.set(CaInfo::parse(&r.status_text));
    }
    // For external routers (not managed by dashboard), poll the ring buffer.
    // Extract signal values as plain integers before any await — guards must not
    // be held across await points or when writing to the same signal.
    let is_running  = *ROUTER_RUNNING.read();
    let last_seq    = *LAST_LOG_SEQ.read();
    if !is_running && let Ok(r) = client.log_get_recent(last_seq).await {
        let text = r.status_text.trim().to_string();
        let mut lines = text.lines();
        // First line is the max_seq sent by the router.
        if let Some(seq_str) = lines.next()
            && let Ok(max_seq) = seq_str.parse::<u64>()
            && max_seq > last_seq
        {
            // Write LAST_LOG_SEQ before acquiring ROUTER_LOG to avoid
            // any borrow ordering issues.
            *LAST_LOG_SEQ.write() = max_seq;
            {
                let mut log = ROUTER_LOG.write();
                for line in lines {
                    if !line.is_empty() {
                        let entry = crate::types::LogEntry::parse_line(line);
                        log.push_back(entry);
                        if log.len() > 2000 { log.pop_front(); }
                    }
                }
            }
        }
    }
    // Apply any filter queued by pop-out windows or LogPane components.
    // The write guard must be dropped (by binding to a local) before the await —
    // collapsing into `if let ... && .await.is_ok()` would hold the guard across await.
    let pending_filter = PENDING_LOG_FILTER.write().take();
    if let Some(filter) = pending_filter {
        // Intentionally nested: the outer if drops the write guard before the inner await.
        #[allow(clippy::collapsible_if)]
        if client.log_set_filter(&filter).await.is_ok() {
            *LOG_FILTER.write() = filter;
        }
    }
    // Sync the displayed filter badge with what the router is actually running.
    if let Ok(r) = client.log_get_filter().await {
        let fetched = r.status_text.trim().to_string();
        let current = LOG_FILTER.read().clone(); // clone to drop guard before write
        if current != fetched {
            *LOG_FILTER.write() = fetched;
        }
    }
    // CS hit rate sparkline history.
    if let Some(ref info) = *cs.read() {
        let rate = info.hit_rate_pct();
        let mut h = cs_hit_history.write();
        h.push_back(rate);
        if h.len() > 60 { h.pop_front(); }
    }
    Ok(())
}

// ── Command dispatch ──────────────────────────────────────────────────────────

/// Reconstruct a [`DashCmd`] from a recorded [`SessionEntry`] for replay.
fn session_entry_to_cmd(entry: &SessionEntry) -> Option<DashCmd> {
    match entry.kind.as_str() {
        "FaceCreate" => Some(DashCmd::FaceCreate(entry.params.clone())),
        "FaceDestroy" => entry.params.parse::<u64>().ok().map(DashCmd::FaceDestroy),
        "RouteAdd" => {
            let mut prefix = String::new();
            let mut face_id = 0u64;
            let mut cost = 10u64;
            for token in entry.params.split_whitespace() {
                if let Some((k, v)) = token.split_once('=') {
                    match k {
                        "prefix" => prefix   = v.to_string(),
                        "face"   => face_id  = v.parse().unwrap_or(0),
                        "cost"   => cost     = v.parse().unwrap_or(10),
                        _ => {}
                    }
                }
            }
            (!prefix.is_empty()).then_some(DashCmd::RouteAdd { prefix, face_id, cost })
        }
        "RouteRemove" => {
            let mut prefix = String::new();
            let mut face_id = 0u64;
            for token in entry.params.split_whitespace() {
                if let Some((k, v)) = token.split_once('=') {
                    match k {
                        "prefix" => prefix  = v.to_string(),
                        "face"   => face_id = v.parse().unwrap_or(0),
                        _ => {}
                    }
                }
            }
            (!prefix.is_empty()).then_some(DashCmd::RouteRemove { prefix, face_id })
        }
        "StrategySet" => {
            let mut prefix = String::new();
            let mut strategy = String::new();
            for token in entry.params.split_whitespace() {
                if let Some((k, v)) = token.split_once('=') {
                    match k {
                        "prefix"   => prefix   = v.to_string(),
                        "strategy" => strategy = v.to_string(),
                        _ => {}
                    }
                }
            }
            (!prefix.is_empty() && !strategy.is_empty())
                .then_some(DashCmd::StrategySet { prefix, strategy })
        }
        "StrategyUnset" => Some(DashCmd::StrategyUnset(entry.params.clone())),
        "CsCapacity"    => entry.params.parse::<u64>().ok().map(DashCmd::CsCapacity),
        "CsErase"       => Some(DashCmd::CsErase(entry.params.clone())),
        _ => None,
    }
}

fn cmd_to_session_entry(cmd: &DashCmd) -> Option<SessionEntry> {
    match cmd {
        DashCmd::FaceCreate(uri) => Some(SessionEntry { kind: "FaceCreate".into(), params: uri.clone() }),
        DashCmd::FaceDestroy(id) => Some(SessionEntry { kind: "FaceDestroy".into(), params: id.to_string() }),
        DashCmd::RouteAdd { prefix, face_id, cost } => Some(SessionEntry { kind: "RouteAdd".into(), params: format!("prefix={prefix} face={face_id} cost={cost}") }),
        DashCmd::RouteRemove { prefix, face_id } => Some(SessionEntry { kind: "RouteRemove".into(), params: format!("prefix={prefix} face={face_id}") }),
        DashCmd::StrategySet { prefix, strategy } => Some(SessionEntry { kind: "StrategySet".into(), params: format!("prefix={prefix} strategy={strategy}") }),
        DashCmd::StrategyUnset(prefix) => Some(SessionEntry { kind: "StrategyUnset".into(), params: prefix.clone() }),
        DashCmd::CsCapacity(bytes) => Some(SessionEntry { kind: "CsCapacity".into(), params: bytes.to_string() }),
        DashCmd::CsErase(prefix) => Some(SessionEntry { kind: "CsErase".into(), params: prefix.clone() }),
        DashCmd::Shutdown => Some(SessionEntry { kind: "Shutdown".into(), params: String::new() }),
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_cmd(
    cmd:                  DashCmd,
    client:               &MgmtClient,
    status:               Signal<Option<ForwarderStatus>>,
    faces:                Signal<Vec<FaceInfo>>,
    routes:               Signal<Vec<FibEntry>>,
    cs:                   Signal<Option<CsInfo>>,
    strategies:           Signal<Vec<StrategyEntry>>,
    counters:             Signal<Vec<FaceCounter>>,
    measurements:         Signal<Vec<MeasurementEntry>>,
    mut error_msg:        Signal<Option<String>>,
    mut config_toml:      Signal<String>,
    throughput:           Signal<VecDeque<ThroughputSample>>,
    prev_counters:        Signal<ThroughputSample>,
    mut session_log:      Signal<Vec<SessionEntry>>,
    mut recording:        Signal<bool>,
    neighbors:            Signal<Vec<NeighborInfo>>,
    security_keys:        Signal<Vec<SecurityKeyInfo>>,
    security_anchors:     Signal<Vec<AnchorInfo>>,
    ca_info:              Signal<Option<CaInfo>>,
    mut yubikey_status:   Signal<Option<String>>,
    cs_hit_history:       Signal<VecDeque<f64>>,
    face_throughput:      Signal<HashMap<u64, VecDeque<ThroughputSample>>>,
    face_prev_ctr:        Signal<HashMap<u64, ThroughputSample>>,
) {
    // Session recording: log before dispatch.
    if *recording.read()
        && let Some(entry) = cmd_to_session_entry(&cmd)
    {
        session_log.write().push(entry);
    }

    let op_label: Option<&'static str> = match &cmd {
        DashCmd::FaceCreate(_)      => Some("Face created"),
        DashCmd::FaceDestroy(_)     => Some("Face destroyed"),
        DashCmd::RouteAdd { .. }    => Some("Route added"),
        DashCmd::RouteRemove { .. } => Some("Route removed"),
        DashCmd::CsCapacity(_)      => Some("CS capacity updated"),
        DashCmd::CsErase(_)         => Some("CS entries erased"),
        DashCmd::Shutdown            => Some("Router shutdown initiated"),
        DashCmd::StrategySet { .. }  => Some("Strategy updated"),
        DashCmd::StrategyUnset(_)    => Some("Strategy cleared"),
        _ => None,
    };

    let result: Result<(), String> = match cmd {
        DashCmd::FaceCreate(uri) => {
            client.face_create(&uri).await.map(|_| ()).map_err(|e| e.to_string())
        }
        DashCmd::FaceDestroy(id) => {
            client.face_destroy(id).await.map(|_| ()).map_err(|e| e.to_string())
        }
        DashCmd::RouteAdd { prefix, face_id, cost } => {
            match prefix.parse::<ndn_packet::Name>() {
                Ok(n) => client.route_add(&n, Some(face_id), cost).await
                    .map(|_| ()).map_err(|e| e.to_string()),
                Err(e) => Err(e.to_string()),
            }
        }
        DashCmd::RouteRemove { prefix, face_id } => {
            match prefix.parse::<ndn_packet::Name>() {
                Ok(n) => client.route_remove(&n, Some(face_id)).await
                    .map(|_| ()).map_err(|e| e.to_string()),
                Err(e) => Err(e.to_string()),
            }
        }
        DashCmd::StrategySet { prefix, strategy } => {
            match (prefix.parse::<ndn_packet::Name>(), strategy.parse::<ndn_packet::Name>()) {
                (Ok(p), Ok(s)) => client.strategy_set(&p, &s).await
                    .map(|_| ()).map_err(|e| e.to_string()),
                _ => Err("Invalid NDN name".into()),
            }
        }
        DashCmd::StrategyUnset(prefix) => {
            match prefix.parse::<ndn_packet::Name>() {
                Ok(n) => client.strategy_unset(&n).await
                    .map(|_| ()).map_err(|e| e.to_string()),
                Err(e) => Err(e.to_string()),
            }
        }
        DashCmd::CsCapacity(bytes) => {
            client.cs_config(Some(bytes)).await.map(|_| ()).map_err(|e| e.to_string())
        }
        DashCmd::CsErase(prefix) => {
            match prefix.parse::<ndn_packet::Name>() {
                Ok(n) => client.cs_erase(&n, None).await
                    .map(|_| ()).map_err(|e| e.to_string()),
                Err(e) => Err(e.to_string()),
            }
        }
        DashCmd::Shutdown => {
            client.shutdown().await.map(|_| ()).map_err(|e| e.to_string())
        }
        DashCmd::Reconnect => return,
        DashCmd::RefreshConfig => {
            config_toml.set(String::new()); // clear so poll_all re-fetches
            return;
        }
        DashCmd::RecordStart => {
            recording.set(true);
            return;
        }
        DashCmd::RecordStop => {
            recording.set(false);
            return;
        }
        DashCmd::RecordClear => {
            session_log.set(Vec::new());
            return;
        }
        DashCmd::ReplaySession => {
            let entries = session_log.read().clone();
            tracing::info!("ReplaySession: replaying {} commands", entries.len());
            for entry in &entries {
                if let Some(replay_cmd) = session_entry_to_cmd(entry) {
                    // Re-enter run_cmd for each recorded command.
                    // Skip recording the replayed commands to avoid infinite loops.
                    let was_recording = *recording.read();
                    recording.set(false);
                    Box::pin(run_cmd(replay_cmd, client, status, faces, routes, cs, strategies, counters, measurements, error_msg, config_toml, throughput, prev_counters, session_log, recording, neighbors, security_keys, security_anchors, ca_info, yubikey_status, cs_hit_history, face_throughput, face_prev_ctr)).await;
                    recording.set(was_recording);
                    tokio::time::sleep(Duration::from_millis(150)).await;
                }
            }
            return;
        }
        DashCmd::SecurityGenerate(name) => {
            match name.parse::<ndn_packet::Name>() {
                Ok(n) => client.security_identity_generate(&n).await
                    .map(|_| ()).map_err(|e| e.to_string()),
                Err(e) => Err(e.to_string()),
            }
        }
        DashCmd::SecurityKeyDelete(name) => {
            match name.parse::<ndn_packet::Name>() {
                Ok(n) => client.security_key_delete(&n).await
                    .map(|_| ()).map_err(|e| e.to_string()),
                Err(e) => Err(e.to_string()),
            }
        }
        DashCmd::SecurityEnroll { ca_prefix, challenge_type, challenge_param } => {
            match ca_prefix.parse::<ndn_packet::Name>() {
                Ok(n) => client.security_ca_enroll(&n, &challenge_type, &challenge_param).await
                    .map(|_| ()).map_err(|e| e.to_string()),
                Err(e) => Err(e.to_string()),
            }
        }
        DashCmd::SecurityTokenAdd(description) => {
            client.security_ca_token_add(&description).await
                .map(|_| ()).map_err(|e| e.to_string())
        }
        DashCmd::YubikeyDetect => {
            match client.security_yubikey_detect().await {
                Ok(r) => {
                    yubikey_status.set(Some(format!("YubiKey: {}", r.status_text)));
                    Ok(())
                }
                Err(e) => {
                    yubikey_status.set(Some(format!("Not found: {e}")));
                    Ok(()) // Don't propagate as error — just update status
                }
            }
        }
        DashCmd::YubikeyGeneratePiv(name) => {
            match name.parse::<ndn_packet::Name>() {
                Ok(n) => match client.security_yubikey_generate(&n).await {
                    Ok(p) => {
                        let pubkey = p.uri.unwrap_or_else(|| "(no key returned)".to_string());
                        yubikey_status.set(Some(format!("Generated. Public key: {pubkey}")));
                        Ok(())
                    }
                    Err(e) => {
                        yubikey_status.set(Some(format!("Generate failed: {e}")));
                        Ok(())
                    }
                },
                Err(_) => {
                    yubikey_status.set(Some("Invalid NDN name".to_string()));
                    Ok(())
                }
            }
        }
    };

    match result {
        Ok(()) => {
            error_msg.set(None);
            if let Some(label) = op_label { push_toast(label, ToastLevel::Success); }
            let _ = poll_all(client, status, faces, routes, cs, strategies, counters, measurements, config_toml, throughput, prev_counters, neighbors, security_keys, security_anchors, ca_info, cs_hit_history, face_throughput, face_prev_ctr).await;
        }
        Err(e) => {
            push_toast(format!("Command failed: {e}"), ToastLevel::Error);
        }
    }
}
