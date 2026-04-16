//! Web variant of the dashboard App component.
//!
//! Uses [`WsMgmtClient`] over WebSocket instead of `ndn_ipc::MgmtClient`
//! over Unix sockets.  Omits desktop-only features: system tray, subprocess
//! management, and embedded tool servers.

#![cfg(feature = "web")]

use std::collections::{HashMap, VecDeque};
use std::time::Duration;

use dioxus::prelude::*;
use futures::StreamExt as _;

use crate::{
    settings::DASH_SETTINGS,
    styles::CSS,
    types::*,
    views::{
        View,
        config::Config,
        dashboard_config::DashboardConfig,
        fleet::Fleet,
        logs::Logs,
        modals::StartRouterModal,
        onboarding::{Onboarding, is_onboarded},
        overview::Overview,
        radio::Radio,
        routing::Routing,
        security::Security,
        session::Session,
        strategy::Strategy,
    },
    ws_mgmt::WsMgmtClient,
};

// Re-export shared types from the desktop app module so views can reference them.
pub use crate::app::{
    AppCtx, ConnState, DashCmd, ACTIVE_VIEW, CONFIG_PRESETS, DARK_MODE,
    LAST_LOG_SEQ, LOG_FILTER, LOG_SPLIT_MODE, LOG_SPLIT_RATIO,
    PENDING_LOG_FILTER, ROUTER_LOG, ROUTER_RUNNING, TOASTS, Toast, ToastLevel,
    push_toast,
};

// Stub types for desktop-only features that views may reference.
pub struct ToolCmd;
pub static TOOL_INSTANCES: once_cell::sync::Lazy<std::sync::RwLock<HashMap<u32, ()>>> =
    once_cell::sync::Lazy::new(|| std::sync::RwLock::new(HashMap::new()));
pub static TOOL_RESULTS: once_cell::sync::Lazy<std::sync::RwLock<Vec<()>>> =
    once_cell::sync::Lazy::new(|| std::sync::RwLock::new(Vec::new()));

fn default_ws_url() -> String {
    "ws://localhost:9696".to_string()
}

/// Web-specific App component.
///
/// Identical sidebar + view layout to the desktop app, but:
/// - Connects via WebSocket instead of Unix socket
/// - No "Start/Stop Router" controls
/// - No embedded tool servers
/// - No system tray
/// - Settings persisted to localStorage
#[component]
pub fn AppWeb() -> Element {
    let mut conn_state: Signal<ConnState> = use_signal(|| ConnState::Disconnected);
    let mut ws_url: Signal<String> = use_signal(default_ws_url);
    let status: Signal<Option<ForwarderStatus>> = use_signal(|| None);
    let faces: Signal<Vec<FaceInfo>> = use_signal(Vec::new);
    let routes: Signal<Vec<FibEntry>> = use_signal(Vec::new);
    let rib_entries: Signal<Vec<RibEntryInfo>> = use_signal(Vec::new);
    let cs: Signal<Option<CsInfo>> = use_signal(|| None);
    let strategies: Signal<Vec<StrategyEntry>> = use_signal(Vec::new);
    let counters: Signal<Vec<FaceCounter>> = use_signal(Vec::new);
    let measurements: Signal<Vec<MeasurementEntry>> = use_signal(Vec::new);
    let config_toml: Signal<String> = use_signal(String::new);
    let throughput: Signal<VecDeque<ThroughputSample>> = use_signal(VecDeque::new);
    let prev_counters: Signal<ThroughputSample> = use_signal(ThroughputSample::default);
    let session_log: Signal<Vec<SessionEntry>> = use_signal(Vec::new);
    let recording: Signal<bool> = use_signal(|| false);
    let neighbors: Signal<Vec<NeighborInfo>> = use_signal(Vec::new);
    let security_keys: Signal<Vec<SecurityKeyInfo>> = use_signal(Vec::new);
    let security_anchors: Signal<Vec<AnchorInfo>> = use_signal(Vec::new);
    let ca_info: Signal<Option<CaInfo>> = use_signal(|| None);
    let schema_rules: Signal<Vec<SchemaRuleInfo>> = use_signal(Vec::new);
    let yubikey_status: Signal<Option<String>> = use_signal(|| None);
    let identity_name: Signal<String> = use_signal(String::new);
    let identity_is_ephemeral: Signal<bool> = use_signal(|| false);
    let identity_pib_path: Signal<Option<String>> = use_signal(|| None);
    let cs_hit_history: Signal<VecDeque<f64>> = use_signal(VecDeque::new);
    let face_throughput: Signal<HashMap<u64, VecDeque<ThroughputSample>>> =
        use_signal(HashMap::new);
    let discovery_status: Signal<Option<DiscoveryStatus>> = use_signal(|| None);
    let dvr_status: Signal<Option<DvrStatus>> = use_signal(|| None);
    let mut error_msg: Signal<Option<String>> = use_signal(|| None);
    let mut show_onboarding: Signal<bool> = use_signal(|| !is_onboarded());
    let mut show_gear_menu: Signal<bool> = use_signal(|| false);

    // Theme
    use_effect(move || {
        let dark = *DARK_MODE.read();
        if dark {
            let _ = document::eval("document.documentElement.classList.remove('light-mode')");
        } else {
            let _ = document::eval("document.documentElement.classList.add('light-mode')");
        }
    });

    // ── WebSocket management coroutine ──────────────────────────────────────
    // Mirrors the desktop cmd coroutine but uses WsMgmtClient over WebSocket.
    let cmd = use_coroutine(move |mut rx: UnboundedReceiver<DashCmd>| async move {
        loop {
            conn_state.set(ConnState::Connecting);
            let url = ws_url.peek().clone();

            let mut client = WsMgmtClient::new(&url);
            match client.connect().await {
                Ok(()) => {}
                Err(e) => {
                    conn_state.set(ConnState::Error(e.to_string()));
                    // Wait before retry; Reconnect skips the wait
                    let sleep = gloo_timers::future::TimeoutFuture::new(3_000);
                    futures::pin_mut!(sleep);
                    loop {
                        futures::select! {
                            _ = sleep => break,
                            cmd = rx.next() => {
                                if cmd.map_or(false, |c| matches!(c, DashCmd::Reconnect)) { break }
                            }
                        }
                    }
                    continue;
                }
            };

            conn_state.set(ConnState::Connected);
            error_msg.set(None);
            *LAST_LOG_SEQ.write() = 0;

            // Initial poll
            if let Err(e) = poll_all_web(&mut client, &status, &faces, &routes, &cs, &strategies).await {
                conn_state.set(ConnState::Disconnected);
                error_msg.set(Some(e));
                continue;
            }

            // Poll loop
            let mut tick = 0u32;
            'session: loop {
                // Use gloo timer for web-compatible sleep
                gloo_timers::future::TimeoutFuture::new(3_000).await;
                tick += 1;

                // Check for commands (non-blocking drain)
                while let Ok(Some(cmd_msg)) = rx.try_next() {
                    if matches!(cmd_msg, DashCmd::Reconnect) {
                        break 'session;
                    }
                    run_cmd_web(cmd_msg, &mut client, &error_msg).await;
                }

                // Poll
                if let Err(e) = poll_all_web(&mut client, &status, &faces, &routes, &cs, &strategies).await {
                    conn_state.set(ConnState::Disconnected);
                    error_msg.set(Some(e));
                    break 'session;
                }
            }
        }
    });

    // Stub coroutines for features not available on web
    let router_cmd = use_coroutine(|mut _rx: UnboundedReceiver<crate::app::RouterCmd>| async move {
        // No subprocess management on web — coroutine exists only to satisfy AppCtx type
        futures::future::pending::<()>().await;
    });

    let tool_cmd = use_coroutine(|mut _rx: UnboundedReceiver<crate::app::ToolCmd>| async move {
        // No embedded tools on web
        futures::future::pending::<()>().await;
    });

    let ctx = AppCtx {
        conn: conn_state,
        status,
        faces,
        routes,
        rib_entries,
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
        schema_rules,
        yubikey_status,
        identity_name,
        identity_is_ephemeral,
        identity_pib_path,
        cs_hit_history,
        face_throughput,
        discovery_status,
        dvr_status,
        router_cmd,
        cmd,
        tool_cmd,
    };
    use_context_provider(move || ctx);

    // Sidebar security dot
    let sec_dot_class = {
        let keys = security_keys.read();
        if keys.is_empty() { "sec-dot sec-dot-gray" } else { "sec-dot sec-dot-green" }
    };

    // Views that are NOT available on web
    let web_hidden_views = [View::Tools, View::Session];

    rsx! {
        document::Style { "{CSS}" }

        if *show_onboarding.read() {
            Onboarding {
                on_complete: move |_| show_onboarding.set(false),
            }
        }

        div { class: "layout",
            // ── Sidebar ───────────────────────────────────────────────────
            nav { class: "sidebar",
                div { class: "sidebar-logo",
                    style: "display:flex;align-items:center;justify-content:space-between;",
                    span { "NDN Dashboard" }
                    span { class: "badge badge-sm", style: "font-size:0.6rem;", "WEB" }
                    span { class: "{sec_dot_class}" }
                }
                for view in View::NAV {
                    {
                        let view = *view;
                        // Skip desktop-only views
                        if web_hidden_views.contains(&view) {
                            return rsx! {};
                        }
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

                div { class: "sidebar-spacer" }

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

            // ── Main area ─────────────────────────────────────────────────
            div { class: "main",
                // Connection bar — WebSocket URL instead of socket path
                div { class: "conn-bar",
                    span {
                        class: "{conn_state.read().badge_class()}",
                        "{conn_state.read().label()}"
                    }
                    input {
                        r#type: "text",
                        placeholder: "WebSocket URL (ws://host:port)",
                        value: "{ws_url}",
                        oninput: move |e| ws_url.set(e.value()),
                        style: "min-width:200px;",
                    }
                    button {
                        class: "btn btn-secondary",
                        onclick: move |_| cmd.send(DashCmd::Reconnect),
                        "Connect"
                    }
                    button {
                        class: "icon-btn",
                        title: "Refresh",
                        onclick: move |_| cmd.send(DashCmd::Reconnect),
                        "⟳"
                    }
                    div { style: "flex:1;" }
                    // Theme toggle
                    button {
                        class: "theme-toggle",
                        title: if *DARK_MODE.read() { "Switch to Light Mode" } else { "Switch to Dark Mode" },
                        onclick: move |_| {
                            let next = !*DARK_MODE.read();
                            *DARK_MODE.write() = next;
                        },
                        if *DARK_MODE.read() { "☀" } else { "🌙" }
                    }
                    // No router start/stop on web — just connection status
                }

                // View content
                div { class: "content-area",
                    if let Some(err) = error_msg.read().as_ref() {
                        div { class: "alert alert-error",
                            strong { "Connection error: " }
                            "{err}"
                        }
                    }
                    { render_view_web(*ACTIVE_VIEW.read()) }
                }
            }
        }
    }
}

/// Render a view component (web variant — omits Tools and Session).
fn render_view_web(view: View) -> Element {
    match view {
        View::Overview => rsx! { Overview {} },
        View::Routes => rsx! { crate::views::routes::Routes {} },
        View::Strategy => rsx! { Strategy {} },
        View::Faces => rsx! { crate::views::faces::Faces {} },
        View::Fleet => rsx! { Fleet {} },
        View::Routing => rsx! { Routing {} },
        View::Security => rsx! { Security {} },
        View::Logs => rsx! { Logs {} },
        View::RouterConfig => rsx! { Config {} },
        View::DashboardConfig => rsx! { DashboardConfig {} },
        View::Radio => rsx! { Radio {} },
        // Desktop-only views render a placeholder on web
        View::Tools | View::Session => rsx! {
            div { class: "placeholder",
                style: "padding:2rem;color:var(--text2);",
                "This feature requires the desktop version of the dashboard."
            }
        },
    }
}

// ── Simplified polling for web ──────────────────────────────────────────────

async fn poll_all_web(
    client: &mut WsMgmtClient,
    status: &Signal<Option<ForwarderStatus>>,
    faces: &Signal<Vec<FaceInfo>>,
    routes: &Signal<Vec<FibEntry>>,
    cs: &Signal<Option<CsInfo>>,
    strategies: &Signal<Vec<StrategyEntry>>,
) -> Result<(), String> {
    // Each call goes through the WebSocket as a TLV-encoded management Interest.
    // The WsMgmtClient returns raw response bytes; full response parsing will be
    // added incrementally as the web build matures.

    if let Ok(resp) = client.status_general().await {
        if resp.is_ok() {
            // TODO: parse ForwarderStatus from resp.body
        }
    }

    if let Ok(resp) = client.list_faces().await {
        if resp.is_ok() {
            // TODO: parse Vec<FaceInfo> from resp.body
        }
    }

    if let Ok(resp) = client.list_fib().await {
        if resp.is_ok() {
            // TODO: parse Vec<FibEntry> from resp.body
        }
    }

    if let Ok(resp) = client.cs_info().await {
        if resp.is_ok() {
            // TODO: parse CsInfo from resp.body
        }
    }

    if let Ok(resp) = client.list_strategy().await {
        if resp.is_ok() {
            // TODO: parse Vec<StrategyEntry> from resp.body
        }
    }

    Ok(())
}

async fn run_cmd_web(
    cmd: DashCmd,
    client: &mut WsMgmtClient,
    error_msg: &Signal<Option<String>>,
) {
    let result = match cmd {
        DashCmd::FaceCreate(uri) => {
            client.send_cmd("faces", "create", Some(uri.as_bytes())).await
        }
        DashCmd::FaceDestroy(id) => {
            let params = id.to_string();
            client.send_cmd("faces", "destroy", Some(params.as_bytes())).await
        }
        DashCmd::RouteAdd { prefix, face_id, cost } => {
            let params = format!("{}\0{}\0{}", prefix, face_id, cost);
            client.send_cmd("rib", "register", Some(params.as_bytes())).await
        }
        DashCmd::RouteRemove { prefix, face_id } => {
            let params = format!("{}\0{}", prefix, face_id);
            client.send_cmd("rib", "unregister", Some(params.as_bytes())).await
        }
        DashCmd::StrategySet { prefix, strategy } => {
            let params = format!("{}\0{}", prefix, strategy);
            client.send_cmd("strategy-choice", "set", Some(params.as_bytes())).await
        }
        DashCmd::Shutdown => {
            client.send_cmd("status", "shutdown", None).await
        }
        DashCmd::Reconnect => return, // Handled by the coroutine loop
        _ => {
            // Other commands not yet implemented for web
            tracing::warn!("Command not yet supported on web: {:?}", cmd);
            return;
        }
    };

    if let Err(e) = result {
        error_msg.to_owned().set(Some(e.to_string()));
    }
}
