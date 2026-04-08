use std::collections::VecDeque;
use std::time::Duration;

use dioxus::prelude::*;
use futures::StreamExt as _;
use ndn_ipc::MgmtClient;

use crate::{
    router_proc,
    tray,
    types::*,
    views::{
        View,
        config::Config,
        cs::ContentStore,
        faces::Faces,
        fleet::Fleet,
        logs::Logs,
        onboarding::{is_onboarded, Onboarding},
        overview::Overview,
        radio::Radio,
        routes::Routes,
        security::Security,
        session::Session,
        strategy::Strategy,
        traffic::Traffic,
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

// ── Stylesheet ───────────────────────────────────────────────────────────────

const CSS: &str = "
*{box-sizing:border-box;margin:0;padding:0}
html{height:100%}
body{font-family:system-ui,-apple-system,sans-serif;background:#0d1117;color:#c9d1d9;display:flex;height:100%;overflow:hidden}
/* Dioxus desktop mounts into a bare <div> inside body with no size — override it. */
body>div{height:100%;width:100%;overflow:hidden}
.layout{display:flex;width:100%;height:100%}
.sidebar{width:200px;min-width:200px;background:#161b22;border-right:1px solid #30363d;display:flex;flex-direction:column}
.sidebar-logo{padding:16px;font-size:15px;font-weight:600;color:#58a6ff;border-bottom:1px solid #30363d;letter-spacing:.5px}
.nav-item{padding:10px 16px;cursor:pointer;color:#8b949e;font-size:13px;border-left:3px solid transparent;transition:all .15s}
.nav-item:hover{background:#21262d;color:#c9d1d9}
.nav-item.active{background:#1f6feb22;color:#58a6ff;border-left-color:#58a6ff}
.main{flex:1;display:flex;flex-direction:column;overflow:hidden;min-height:0}
.conn-bar{display:flex;align-items:center;gap:10px;background:#161b22;border-bottom:1px solid #30363d;padding:10px 20px;font-size:13px;flex-shrink:0}
.conn-bar input{background:#0d1117;border:1px solid #30363d;color:#c9d1d9;padding:5px 10px;border-radius:4px;font-size:13px;font-family:monospace;flex:1;max-width:280px;min-width:120px}
.conn-bar input:focus{outline:none;border-color:#58a6ff}
.content{flex:1;overflow-y:auto;padding:24px;min-height:0}
.badge{display:inline-block;padding:2px 9px;border-radius:10px;font-size:11px;font-weight:600}
.badge-green{background:#1a4731;color:#3fb950}
.badge-red{background:#4e1717;color:#f85149}
.badge-yellow{background:#3d3000;color:#d29922}
.badge-blue{background:#0c2d6b;color:#58a6ff}
.badge-gray{background:#21262d;color:#8b949e}
.badge-purple{background:#2a1a4e;color:#a371f7}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;margin-bottom:24px}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px}
.card-label{font-size:11px;color:#8b949e;text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px}
.card-value{font-size:30px;font-weight:600;color:#c9d1d9;line-height:1}
.card-sub{font-size:12px;color:#8b949e;margin-top:6px}
.section{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;margin-bottom:16px}
.section-title{font-size:13px;font-weight:600;color:#8b949e;text-transform:uppercase;letter-spacing:.5px;margin-bottom:14px}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;padding:6px 12px;font-size:11px;color:#8b949e;text-transform:uppercase;letter-spacing:.4px;border-bottom:1px solid #30363d}
td{padding:8px 12px;border-bottom:1px solid #21262d;color:#c9d1d9;vertical-align:middle}
tr:last-child td{border-bottom:none}
tr:hover td{background:#1c2128}
.form-row{display:flex;gap:8px;align-items:flex-end;flex-wrap:wrap;margin-top:14px;padding-top:14px;border-top:1px solid #21262d}
.form-group{display:flex;flex-direction:column;gap:4px}
label{font-size:11px;color:#8b949e}
input,select{background:#0d1117;border:1px solid #30363d;color:#c9d1d9;padding:6px 10px;border-radius:4px;font-size:13px;font-family:inherit}
input:focus,select:focus{outline:none;border-color:#58a6ff}
.btn{padding:7px 14px;border-radius:6px;border:none;cursor:pointer;font-size:13px;font-weight:500;font-family:inherit;transition:background .15s}
.btn-primary{background:#238636;color:#fff}
.btn-primary:hover{background:#2ea043}
.btn-danger{background:#da3633;color:#fff}
.btn-danger:hover{background:#f85149}
.btn-secondary{background:#21262d;color:#c9d1d9;border:1px solid #30363d}
.btn-secondary:hover{background:#30363d}
.btn-sm{padding:4px 10px;font-size:12px}
.error-banner{background:#4e1717;border:1px solid #f85149;border-radius:6px;padding:10px 16px;margin-bottom:16px;color:#f85149;font-size:13px;display:flex;justify-content:space-between;align-items:center}
.mono{font-family:'SF Mono',Consolas,monospace;font-size:12px}
.empty{color:#8b949e;font-size:13px;padding:20px 0;text-align:center}
[data-tooltip]{position:relative;cursor:help}
[data-tooltip]::after{content:attr(data-tooltip);position:absolute;bottom:calc(100% + 6px);left:50%;transform:translateX(-50%);background:#1c2128;border:1px solid #30363d;border-radius:4px;padding:5px 10px;font-size:11px;color:#c9d1d9;white-space:pre-wrap;max-width:280px;pointer-events:none;opacity:0;transition:opacity .15s;z-index:200;line-height:1.5;text-align:left}
[data-tooltip]:hover::after{opacity:1}
.restart-banner{background:#3d3000;border:1px solid #d29922;border-radius:6px;padding:8px 14px;margin-bottom:14px;color:#d29922;font-size:12px;display:flex;align-items:center;gap:8px}
/* ── Onboarding overlay ─────────────────────────────────────────── */
.onboarding-overlay{position:fixed;inset:0;background:rgba(0,0,0,.88);z-index:1000;display:flex;align-items:center;justify-content:center;animation:fade-in .25s ease}
.onboarding-card{background:#161b22;border:1px solid #30363d;border-radius:14px;padding:40px 44px;width:580px;max-width:92vw;position:relative;animation:slide-up .3s ease}
@keyframes slide-up{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}
@keyframes fade-in{from{opacity:0}to{opacity:1}}
.onboarding-step{animation:step-in .25s ease}
@keyframes step-in{from{opacity:0;transform:translateX(18px)}to{opacity:1;transform:translateX(0)}}
.step-dots{display:flex;gap:8px;margin-top:28px;justify-content:center}
.step-dot{width:8px;height:8px;border-radius:50%;background:#30363d;transition:background .25s,transform .25s}
.step-dot.active{background:#58a6ff;transform:scale(1.3)}
.step-dot.done{background:#3fb950}
/* ── Packet flow animation ─────────────────────────────────────── */
@keyframes packet-fly{0%{left:-60px;opacity:0}15%{opacity:1}85%{opacity:1}100%{left:calc(100% + 20px);opacity:0}}
.packet-lane{position:relative;height:28px;overflow:hidden;background:#0d1117;border-radius:4px;margin:6px 0}
.packet-bubble{position:absolute;top:4px;background:#1f6feb;color:#fff;border-radius:3px;padding:2px 8px;font-size:10px;font-family:monospace;white-space:nowrap;animation:packet-fly 2.8s ease-in-out infinite}
.packet-bubble.data{background:#1a4731;animation-delay:.9s}
.packet-bubble.nack{background:#4e1717;animation-delay:1.8s}
/* ── Trust chain ────────────────────────────────────────────────── */
.trust-chain{display:flex;align-items:center;gap:0;margin:16px 0;flex-wrap:wrap}
.chain-node{background:#1c2128;border:1px solid #30363d;border-radius:8px;padding:10px 14px;text-align:center;min-width:110px;transition:border-color .2s}
.chain-node.ok{border-color:#3fb950}
.chain-node.warn{border-color:#d29922}
.chain-node.missing{border-color:#30363d;opacity:.5}
.chain-arrow{font-size:18px;color:#30363d;padding:0 4px;flex-shrink:0}
/* ── Education snippets ────────────────────────────────────────── */
.edu-card{background:linear-gradient(135deg,#0c2d6b1a,#1a472a1a);border:1px solid #1f4f8a44;border-radius:8px;padding:14px 16px;margin-bottom:16px;position:relative;overflow:hidden}
.edu-dismiss{position:absolute;top:8px;right:10px;background:none;border:none;color:#8b949e;cursor:pointer;font-size:16px;padding:0;line-height:1}
.edu-dismiss:hover{color:#c9d1d9}
@keyframes sig-glow{0%,100%{box-shadow:0 0 0 0 transparent}50%{box-shadow:0 0 8px 3px #3fb95044}}
.signed-packet{display:inline-flex;align-items:center;gap:5px;background:#0f2a16;border:1px solid #3fb950;border-radius:4px;padding:3px 9px;font-size:11px;font-family:monospace;animation:sig-glow 2.4s ease infinite}
@keyframes trust-pulse{0%,100%{opacity:.4}50%{opacity:1}}
.trust-link{display:inline-block;width:28px;height:2px;background:#58a6ff;border-radius:1px;animation:trust-pulse 1.8s ease infinite;margin:0 4px;vertical-align:middle}
/* ── Progress steps ────────────────────────────────────────────── */
.enroll-steps{display:flex;align-items:center;gap:0;margin:14px 0;font-size:11px;flex-wrap:wrap}
.enroll-step{display:flex;flex-direction:column;align-items:center;gap:4px;min-width:64px;text-align:center}
.enroll-step-dot{width:11px;height:11px;border-radius:50%;background:#30363d;flex-shrink:0;transition:background .3s}
.enroll-step-dot.done{background:#3fb950}
.enroll-step-dot.active{background:#58a6ff;box-shadow:0 0 0 3px #1f6feb44;animation:ping .9s ease infinite}
@keyframes ping{0%,100%{box-shadow:0 0 0 3px #1f6feb44}50%{box-shadow:0 0 0 6px #1f6feb22}}
.enroll-step-line{flex:1;height:2px;background:#30363d;min-width:24px}
.enroll-step-line.done{background:#3fb950}
/* ── YubiKey ───────────────────────────────────────────────────── */
.yk-seed{background:#0d1117;border:1px solid #30363d;border-radius:4px;padding:10px 12px;font-family:'SF Mono',monospace;font-size:11px;color:#3fb950;word-break:break-all;margin:8px 0;line-height:1.7}
.yk-cmd{background:#0d1117;border:1px solid #30363d;border-radius:4px;padding:8px 12px;font-family:'SF Mono',monospace;font-size:11px;color:#58a6ff;word-break:break-all;margin:6px 0;user-select:all}
/* ── DID ───────────────────────────────────────────────────────── */
.did-value{background:#0d1117;border:1px solid #30363d;border-radius:4px;padding:8px 12px;font-family:'SF Mono',monospace;font-size:12px;color:#a371f7;word-break:break-all;margin:6px 0}
.did-copy-btn{background:none;border:1px solid #30363d;color:#8b949e;border-radius:4px;padding:3px 8px;font-size:11px;cursor:pointer}
.did-copy-btn:hover{border-color:#58a6ff;color:#58a6ff}
/* ── Fleet edu animation ───────────────────────────────────────── */
.edu-flow-row{display:flex;align-items:center;justify-content:center;gap:6px;margin:4px 0}
.edu-flow-label{font-size:8px;color:#8b949e;text-align:center;letter-spacing:.5px}
.edu-router{width:24px;height:20px;background:#1c2128;border:1px solid #30363d;border-radius:3px;display:flex;align-items:center;justify-content:center;font-size:8px;font-weight:600;color:#c9d1d9}
.edu-router-ca{border-color:#1f6feb;color:#58a6ff}
.edu-cert-glow{border-color:#3fb950;color:#3fb950}
@keyframes arrow-pulse{0%,100%{opacity:.3}50%{opacity:1}}
.edu-arrow{font-size:10px;color:#8b949e;animation:arrow-pulse 1.6s ease infinite}
.edu-arrow-right{color:#1f6feb}
.edu-anim-delay1{animation-delay:.4s}
/* ── Overview edu animation ────────────────────────────────────── */
@keyframes drop-packet{0%{transform:translateY(-10px);opacity:0}30%{opacity:1}60%{transform:translateY(0);opacity:1}80%{opacity:0;filter:blur(2px)}100%{opacity:0}}
.drop-packet{font-size:11px;background:#4e1717;border:1px solid #f8514966;border-radius:3px;padding:2px 7px;display:inline-block;animation:drop-packet 2.2s ease infinite;font-family:monospace}
/* ── Log view ──────────────────────────────────────────────────── */
.log-entry{display:flex;align-items:flex-start;gap:8px;padding:3px 4px;border-bottom:1px solid #1c2128;font-size:12px;font-family:'SF Mono',monospace;min-width:0}
.log-entry:last-child{border-bottom:none}
.log-ts{color:#484f58;font-size:10px;white-space:nowrap;flex-shrink:0}
.log-lvl{padding:1px 5px;border-radius:3px;font-size:10px;font-weight:700;min-width:44px;text-align:center;flex-shrink:0;white-space:nowrap}
.log-target{color:#8b949e;flex-shrink:0;white-space:nowrap;max-width:220px;overflow:hidden;text-overflow:ellipsis}
.log-msg{color:#c9d1d9;flex:1;min-width:0;white-space:pre-wrap;word-break:break-word}
.log-list{display:flex;flex-direction:column;overflow-y:auto;overflow-x:hidden;flex:1;min-height:0}
.log-toolbar{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:8px}
.filter-controls-section{background:#0d1117;border:1px solid #21262d;border-radius:6px;padding:12px;margin-bottom:12px}
.col-toggle{padding:2px 7px;border-radius:4px;border:1px solid #30363d;background:#0d1117;color:#8b949e;font-size:10px;cursor:pointer;font-family:inherit;transition:all .15s}
.col-toggle.on{background:#1f6feb22;border-color:#58a6ff;color:#58a6ff}
/* ── Split / floating panes ────────────────────────────────────── */
.split-divider{background:#21262d;flex-shrink:0;transition:background .15s}
.split-divider:hover{background:#58a6ff}
.split-divider-h{width:4px;cursor:col-resize}
.split-divider-v{height:4px;cursor:row-resize}
.log-pane{display:flex;flex-direction:column;flex:1;min-width:0;min-height:0;overflow:hidden;padding:12px}
.floating-pane{position:fixed;z-index:200;background:#161b22;border:1px solid #30363d;border-radius:8px;box-shadow:0 12px 40px rgba(0,0,0,.8);display:flex;flex-direction:column;resize:both;overflow:hidden;min-width:420px;min-height:280px}
.floating-title{background:#21262d;border-bottom:1px solid #30363d;padding:6px 10px;display:flex;align-items:center;justify-content:space-between;cursor:move;user-select:none;flex-shrink:0;font-size:12px;color:#c9d1d9}
.floating-body{flex:1;min-height:0;overflow:hidden;display:flex;flex-direction:column}
";

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
    Start,
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
    pub router_cmd:        Coroutine<RouterCmd>,
    pub cmd:               Coroutine<DashCmd>,
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
    let mut error_msg: Signal<Option<String>> = use_signal(|| None);
    let mut current_view:   Signal<View>                      = use_signal(|| View::Overview);
    let mut show_onboarding: Signal<bool>                     = use_signal(|| !is_onboarded());

    // ── Router management coroutine ──────────────────────────────────────────
    // Owns the RouterProc, watches for process exit, drains log lines.
    let router_cmd = use_coroutine(move |mut rx: UnboundedReceiver<RouterCmd>| async move {
        let mut proc: Option<router_proc::RouterProc> = None;
        let mut check = tokio::time::interval(Duration::from_millis(500));

        loop {
            tokio::select! {
                _ = check.tick() => {
                    if let Some(ref mut p) = proc {
                        if !p.is_running() {
                            proc = None;
                            *ROUTER_RUNNING.write() = false;
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
                        RouterCmd::Start => {
                            if proc.is_none() {
                                match router_proc::find_binary() {
                                    Some(bin) => {
                                        match router_proc::RouterProc::start(&bin).await {
                                            Ok(p) => {
                                                *ROUTER_RUNNING.write() = true;
                                                proc = Some(p);
                                            }
                                            Err(e) => tracing::error!("start router: {e}"),
                                        }
                                    }
                                    None => tracing::warn!("ndn-router binary not found in PATH"),
                                }
                            }
                        }
                        RouterCmd::Stop => {
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
    });

    // ── Tray polling coroutine ───────────────────────────────────────────────
    // Updates the tray icon colour and forwards menu events.
    use_coroutine(move |_: UnboundedReceiver<()>| async move {
        let mut interval = tokio::time::interval(Duration::from_millis(200));
        loop {
            interval.tick().await;

            // Sync icon/tooltip with current state.
            let connected = matches!(*conn_state.read(), ConnState::Connected);
            let running   = *ROUTER_RUNNING.read();
            tray::update_state(connected, running);

            // Forward tray-menu events.
            while let Some(tc) = tray::poll_menu_event() {
                match tc {
                    tray::TrayCmd::StartRouter   => router_cmd.send(RouterCmd::Start),
                    tray::TrayCmd::StopRouter    => router_cmd.send(RouterCmd::Stop),
                    tray::TrayCmd::OpenDashboard => { /* window is always open */ }
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

            if let Err(e) = poll_all(&client, status, faces, routes, cs, strategies, counters, measurements, config_toml, throughput, prev_counters, neighbors, security_keys, security_anchors, ca_info).await {
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
                        if let Err(e) = poll_all(&client, status, faces, routes, cs, strategies, counters, measurements, config_toml, throughput, prev_counters, neighbors, security_keys, security_anchors, ca_info).await {
                            conn_state.set(ConnState::Disconnected);
                            error_msg.set(Some(e));
                            break 'session;
                        }
                    }
                    Some(cmd_msg) = rx.next() => {
                        if matches!(cmd_msg, DashCmd::Reconnect) {
                            break 'session;
                        }
                        run_cmd(cmd_msg, &client, status, faces, routes, cs, strategies, counters, measurements, error_msg, config_toml, throughput, prev_counters, session_log, recording, neighbors, security_keys, security_anchors, ca_info, yubikey_status).await;
                    }
                }
            }
        }
    });

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
        router_cmd,
        cmd,
    };
    use_context_provider(move || ctx);

    rsx! {
        document::Style { "{CSS}" }

        // First-time onboarding overlay (shown until ~/.ndn/dashboard-onboarded exists).
        if *show_onboarding.read() {
            Onboarding {
                on_complete: move |_| show_onboarding.set(false),
            }
        }

        div { class: "layout",
            // ── Sidebar navigation ─────────────────────────────────────────
            nav { class: "sidebar",
                div { class: "sidebar-logo", "NDN Dashboard" }
                for view in View::ALL {
                    {
                        let view = *view;
                        let is_active = *current_view.read() == view;
                        rsx! {
                            div {
                                class: if is_active { "nav-item active" } else { "nav-item" },
                                onclick: move |_| current_view.set(view),
                                "{view.label()}"
                            }
                        }
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
                }

                // Content — Logs gets a full-height flex container; other views
                // use the padded scrollable .content div.
                if *current_view.read() == View::Logs {
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
                        {render_view(*current_view.read())}
                    }
                }
            }
        }
    }
}

fn render_view(view: View) -> Element {
    match view {
        View::Overview     => rsx! { Overview {} },
        View::Faces        => rsx! { Faces {} },
        View::Routes       => rsx! { Routes {} },
        View::ContentStore => rsx! { ContentStore {} },
        View::Strategy     => rsx! { Strategy {} },
        View::Traffic      => rsx! { Traffic {} },
        View::Logs         => rsx! { },  // rendered via full-height branch in App
        View::Config       => rsx! { Config {} },
        View::Session      => rsx! { Session {} },
        View::Security     => rsx! { Security {} },
        View::Fleet        => rsx! { Fleet {} },
        View::Radio        => rsx! { Radio {} },
    }
}

fn default_socket_path() -> String {
    #[cfg(windows)]
    return r"\\.\pipe\ndn-faces".to_string();
    #[cfg(not(windows))]
    "/tmp/ndn-faces.sock".to_string()
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
    // Throughput history — compute per-second rates from counter deltas.
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
) {
    // Session recording: log before dispatch.
    if *recording.read()
        && let Some(entry) = cmd_to_session_entry(&cmd)
    {
        session_log.write().push(entry);
    }

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
                    Box::pin(run_cmd(replay_cmd, client, status, faces, routes, cs, strategies, counters, measurements, error_msg, config_toml, throughput, prev_counters, session_log, recording, neighbors, security_keys, security_anchors, ca_info, yubikey_status)).await;
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
            let _ = poll_all(client, status, faces, routes, cs, strategies, counters, measurements, config_toml, throughput, prev_counters, neighbors, security_keys, security_anchors, ca_info).await;
        }
        Err(e) => error_msg.set(Some(e)),
    }
}
