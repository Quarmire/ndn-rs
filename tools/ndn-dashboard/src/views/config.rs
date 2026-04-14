use dioxus::prelude::*;
use ndn_config::{
    CsConfig, DiscoveryTomlConfig, EngineConfig, FaceConfig, ForwarderConfig, LoggingConfig,
    ManagementConfig, RouteConfig, SecurityConfig,
};

use crate::app::{AppCtx, DashCmd, ROUTER_RUNNING, RouterCmd, ToastLevel, push_toast};
use crate::forwarder_proc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConfigSection {
    Engine,
    ContentStore,
    Management,
    Security,
    Discovery,
    Logging,
}

#[component]
pub fn Config() -> Element {
    let ctx = use_context::<AppCtx>();
    let config_toml = ctx.config_toml.read().clone();

    let parsed: Option<ForwarderConfig> = if config_toml.is_empty() {
        None
    } else {
        config_toml.parse().ok()
    };

    // Export panel state
    let mut show_export = use_signal(|| false);
    let mut import_text = use_signal(String::new);
    let mut import_error = use_signal(|| Option::<String>::None);
    let mut export_text = use_signal(String::new);

    // Current editing section
    let mut editing: Signal<Option<ConfigSection>> = use_signal(|| None);
    let mut edu_dismissed = use_signal(|| false);

    // Local editable faces/routes — initialized from loaded config, editable until restart
    let local_faces: Signal<Vec<FaceConfig>> =
        use_signal(|| parsed.as_ref().map(|c| c.faces.clone()).unwrap_or_default());
    let local_routes: Signal<Vec<RouteConfig>> = use_signal(|| {
        parsed
            .as_ref()
            .map(|c| c.routes.clone())
            .unwrap_or_default()
    });

    rsx! {
        // ── Education snippet (B7): identity IS address ──────────────────────
        if !*edu_dismissed.read() {
            div { class: "edu-card",
                div { style: "display:flex;gap:12px;align-items:flex-start;",
                    div { style: "flex-shrink:0;padding-top:2px;",
                        div { class: "signed-packet", "did:ndn:/your/name" }
                    }
                    div { style: "flex:1;",
                        div { style: "display:flex;justify-content:space-between;align-items:flex-start;",
                            div { style: "font-size:13px;font-weight:600;color:var(--purple);margin-bottom:4px;",
                                "Your identity IS your address"
                            }
                            button {
                                style: "background:none;border:none;color:var(--text-muted);cursor:pointer;font-size:13px;padding:0;",
                                onclick: move |_| edu_dismissed.set(true),
                                "✕"
                            }
                        }
                        div { style: "font-size:12px;color:var(--text-muted);line-height:1.6;",
                            "In NDN, "
                            strong { style: "color:var(--text);", "packets are addressed by name, not IP." }
                            " Your router's NDN name (configured below under "
                            span { style: "color:var(--purple);", "Security → router_name" }
                            ") becomes your DID — a globally unique, portable identity "
                            "that moves with you across networks."
                        }
                    }
                }
            }
        }

        if config_toml.is_empty() {
            div { class: "section",
                div { class: "empty",
                    "Config not loaded. "
                    button {
                        class: "btn btn-secondary btn-sm",
                        onclick: move |_| ctx.cmd.send(DashCmd::RefreshConfig),
                        "Load Config"
                    }
                }
            }
        } else if parsed.is_none() {
            div { class: "section",
                div { class: "empty", style: "color:var(--red);",
                    "Failed to parse config TOML. Raw:"
                }
                pre { style: "font-size:11px;color:var(--text-muted);overflow:auto;max-height:200px;", "{config_toml}" }
            }
        } else {
            {
                let cfg = parsed.unwrap();

                // ── Toolbar ───────────────────────────────────────────────
                rsx! {
                    div { style: "display:flex;gap:8px;margin-bottom:16px;align-items:center;flex-wrap:wrap;",
                        button {
                            class: "btn btn-secondary",
                            onclick: move |_| ctx.cmd.send(DashCmd::RefreshConfig),
                            "↻ Reload"
                        }
                        button {
                            class: "btn btn-primary",
                            onclick: {
                                let toml = config_toml.clone();
                                move |_| {
                                    export_text.set(toml.clone());
                                    show_export.set(true);
                                }
                            },
                            "Export TOML"
                        }
                        button {
                            class: "btn btn-secondary",
                            onclick: move |_| {
                                import_text.set(String::new());
                                import_error.set(None);
                                show_export.set(false);
                            },
                            "Import TOML"
                        }
                        // Restart with current config (managed router only)
                        button {
                            class: "btn btn-secondary",
                            title: "Rebuild config TOML from current settings + edited faces/routes, write to temp file and restart the managed router",
                            onclick: {
                                let base_toml = config_toml.clone();
                                move |_| {
                                    // Merge local face/route edits into the base config
                                    let toml = if let Ok(mut c) = base_toml.parse::<ForwarderConfig>() {
                                        c.faces = local_faces.read().clone();
                                        c.routes = local_routes.read().clone();
                                        c.to_toml_string().unwrap_or_else(|_| base_toml.clone())
                                    } else {
                                        base_toml.clone()
                                    };
                                    match forwarder_proc::write_temp_config(&toml) {
                                        Ok(path) => {
                                            let path_str = path.to_string_lossy().to_string();
                                            ctx.router_cmd.send(RouterCmd::Stop);
                                            ctx.router_cmd.send(RouterCmd::Start(Some(path_str)));
                                            push_toast("Router restart queued with updated config", ToastLevel::Info);
                                        }
                                        Err(e) => push_toast(format!("Failed to write config: {e}"), ToastLevel::Error),
                                    }
                                }
                            },
                            "↺ Restart with Config"
                        }
                        span { style: "font-size:11px;color:var(--text-muted);margin-left:auto;",
                            if *ROUTER_RUNNING.read() {
                                "Managed router is running."
                            } else {
                                "Changes require router restart."
                            }
                        }
                    }

                    // ── Restart-required banner ───────────────────────────
                    if editing.read().is_some() {
                        div { class: "restart-banner",
                            span { style: "font-size:14px;", "⚠" }
                            span {
                                "Settings are being edited. "
                                strong { "Export TOML or use ↺ Restart with Config" }
                                " to apply — live config editing is not supported."
                            }
                            button {
                                class: "btn btn-secondary btn-sm",
                                style: "margin-left:auto;",
                                onclick: move |_| { editing.set(None); },
                                "Dismiss"
                            }
                        }
                    }

                    // ── Export panel ──────────────────────────────────────
                    if *show_export.read() {
                        div { class: "section",
                            div { style: "display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;",
                                div { class: "section-title", "TOML Export" }
                                button {
                                    class: "btn btn-secondary btn-sm",
                                    onclick: move |_| show_export.set(false),
                                    "✕ Close"
                                }
                            }
                            textarea {
                                style: "width:100%;height:300px;font-family:'SF Mono',monospace;font-size:12px;padding:10px;border-radius:4px;resize:vertical;",
                                readonly: true,
                                value: "{export_text}",
                            }
                            div { style: "margin-top:8px;font-size:12px;color:var(--text-muted);",
                                "Save this TOML to a file and launch ndn-fwd with: "
                                code { style: "color:var(--accent);", "ndn-fwd --config /path/to/config.toml" }
                            }
                        }
                    }

                    // ── Import panel ──────────────────────────────────────
                    if !*show_export.read() {
                        div { class: "section",
                            div { class: "section-title", "Import Config" }
                            textarea {
                                style: "width:100%;height:200px;font-family:'SF Mono',monospace;font-size:12px;padding:10px;border-radius:4px;resize:vertical;",
                                placeholder: "Paste TOML config here to preview and validate…",
                                value: "{import_text}",
                                oninput: move |e| {
                                    let text = e.value();
                                    import_text.set(text.clone());
                                    let result: Result<ForwarderConfig, _> = text.parse();
                                    import_error.set(result.err().map(|e| e.to_string()));
                                },
                            }
                            if let Some(ref err) = *import_error.read() {
                                div { style: "color:var(--red);font-size:12px;margin-top:6px;",
                                    "Parse error: {err}"
                                }
                            } else if !import_text.read().is_empty() {
                                div { style: "color:var(--green);font-size:12px;margin-top:6px;",
                                    "✓ Valid TOML config — use ↺ Restart with Config or save to file."
                                }
                            }
                        }
                    }

                    // ── Engine section ────────────────────────────────────
                    {render_engine_section(cfg.engine.clone(), editing)}

                    // ── Content Store section ─────────────────────────────
                    {render_cs_section(cfg.cs.clone(), editing)}

                    // ── Management section ────────────────────────────────
                    {render_management_section(cfg.management.clone(), editing)}

                    // ── Security section ──────────────────────────────────
                    {render_security_section(cfg.security.clone(), editing)}

                    // ── Discovery section ─────────────────────────────────
                    {render_discovery_section(cfg.discovery.clone(), editing)}

                    // ── Logging section ───────────────────────────────────
                    {render_logging_section(cfg.logging.clone(), ctx, editing)}

                    // ── Faces section (editable) ──────────────────────────
                    FacesSection { faces: local_faces }

                    // ── Static Routes section (editable) ──────────────────
                    RoutesSection { routes: local_routes, n_faces: local_faces.read().len() }
                }
            }
        }
    }
}

// ── Section helpers ───────────────────────────────────────────────────────────

fn section_header(
    title: &str,
    section: ConfigSection,
    mut editing: Signal<Option<ConfigSection>>,
) -> Element {
    let is_open = *editing.read() == Some(section);
    rsx! {
        div { style: "display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;",
            div { class: "section-title", "{title}" }
            button {
                class: "btn btn-secondary btn-sm",
                onclick: move |_| {
                    if *editing.read() == Some(section) {
                        editing.set(None);
                    } else {
                        editing.set(Some(section));
                    }
                },
                if is_open { "▲ Collapse" } else { "▼ Edit" }
            }
        }
    }
}

fn restart_badge() -> Element {
    rsx! { span { class: "badge badge-yellow", style: "font-size:10px;margin-left:6px;", "restart required" } }
}

fn live_badge() -> Element {
    rsx! { span { class: "badge badge-green", style: "font-size:10px;margin-left:6px;", "live" } }
}

fn kv_row(key: &str, val: impl std::fmt::Display, badge: Element) -> Element {
    let val = val.to_string();
    rsx! {
        tr {
            td { style: "color:var(--text-muted);font-size:12px;padding:5px 12px;width:220px;", "{key}" }
            td { class: "mono", style: "padding:5px 12px;", "{val}" }
            td { style: "padding:5px 12px;", {badge} }
        }
    }
}

// ── Engine ────────────────────────────────────────────────────────────────────

fn render_engine_section(engine: EngineConfig, editing: Signal<Option<ConfigSection>>) -> Element {
    let is_open = *editing.read() == Some(ConfigSection::Engine);

    let mut threads = use_signal(|| engine.pipeline_threads.to_string());
    let mut chan_cap = use_signal(|| engine.pipeline_channel_cap.to_string());

    rsx! {
        div { class: "section",
            {section_header("Engine", ConfigSection::Engine, editing)}

            table { style: "width:100%;",
                tbody {
                    {kv_row("Pipeline threads", if engine.pipeline_threads == 0 { "0 (auto)".to_string() } else { engine.pipeline_threads.to_string() }, restart_badge())}
                    {kv_row("Pipeline channel depth", engine.pipeline_channel_cap, restart_badge())}
                }
            }

            if is_open {
                div { class: "form-row", style: "margin-top:14px;",
                    div { class: "form-group",
                        label { "Pipeline threads (0 = auto)" }
                        input {
                            r#type: "number", min: "0", max: "64", style: "width:100px;",
                            value: "{threads}",
                            oninput: move |e| threads.set(e.value()),
                        }
                    }
                    div { class: "form-group",
                        label { "Channel depth" }
                        input {
                            r#type: "number", min: "64", max: "65536", style: "width:120px;",
                            value: "{chan_cap}",
                            oninput: move |e| chan_cap.set(e.value()),
                        }
                    }
                    div { style: "display:flex;align-items:flex-end;",
                        span { style: "font-size:12px;color:var(--text-muted);",
                            "Changes take effect after router restart."
                        }
                    }
                }
            }
        }
    }
}

// ── Content Store ─────────────────────────────────────────────────────────────

fn render_cs_section(cs: CsConfig, editing: Signal<Option<ConfigSection>>) -> Element {
    let is_open = *editing.read() == Some(ConfigSection::ContentStore);

    rsx! {
        div { class: "section",
            {section_header("Content Store", ConfigSection::ContentStore, editing)}

            table { style: "width:100%;",
                tbody {
                    {kv_row("Variant", &cs.variant, restart_badge())}
                    {kv_row("Capacity", format!("{} MB", cs.capacity_mb), restart_badge())}
                    if let Some(shards) = cs.shards {
                        {kv_row("Shards", shards, restart_badge())}
                    }
                    {kv_row("Admission policy", &cs.admission_policy, restart_badge())}
                }
            }

            if is_open {
                div { class: "form-row", style: "margin-top:14px;",
                    div { class: "form-group",
                        label { "Variant" }
                        select {
                            option { value: "lru",         selected: cs.variant == "lru",         "LRU" }
                            option { value: "sharded-lru", selected: cs.variant == "sharded-lru", "Sharded LRU" }
                            option { value: "null",        selected: cs.variant == "null",        "Null (disabled)" }
                        }
                    }
                    div { class: "form-group",
                        label { "Capacity (MB)" }
                        input {
                            r#type: "number", min: "0", max: "65536", style: "width:120px;",
                            value: "{cs.capacity_mb}",
                        }
                    }
                    div { class: "form-group",
                        label { "Admission policy" }
                        select {
                            option { value: "default",   selected: cs.admission_policy == "default",   "Satisfy PIT only" }
                            option { value: "admit-all", selected: cs.admission_policy == "admit-all", "Admit all Data" }
                        }
                    }
                    div { style: "display:flex;align-items:flex-end;",
                        span { style: "font-size:12px;color:var(--text-muted);", "Requires restart." }
                    }
                }
            }
        }
    }
}

// ── Management ────────────────────────────────────────────────────────────────

fn render_management_section(
    mgmt: ManagementConfig,
    editing: Signal<Option<ConfigSection>>,
) -> Element {
    let is_open = *editing.read() == Some(ConfigSection::Management);

    rsx! {
        div { class: "section",
            {section_header("Management", ConfigSection::Management, editing)}

            table { style: "width:100%;",
                tbody {
                    {kv_row("Socket", &mgmt.face_socket, restart_badge())}
                }
            }

            if is_open {
                div { class: "form-row", style: "margin-top:14px;",
                    div { class: "form-group", style: "flex:1;",
                        label { "Router socket path" }
                        input { r#type: "text", value: "{mgmt.face_socket}", }
                    }
                }
            }
        }
    }
}

// ── Security ──────────────────────────────────────────────────────────────────

fn render_security_section(sec: SecurityConfig, editing: Signal<Option<ConfigSection>>) -> Element {
    let is_open = *editing.read() == Some(ConfigSection::Security);

    rsx! {
        div { class: "section",
            {section_header("Security", ConfigSection::Security, editing)}

            table { style: "width:100%;",
                tbody {
                    {kv_row("Identity", sec.identity.as_deref().unwrap_or("(none)"), restart_badge())}
                    {kv_row("PIB path", sec.pib_path.as_deref().unwrap_or("(default)"), restart_badge())}
                    {kv_row("Trust anchor", sec.trust_anchor.as_deref().unwrap_or("(none)"), restart_badge())}
                    {kv_row("Profile", &sec.profile, restart_badge())}
                    {kv_row("Require signed", sec.require_signed, restart_badge())}
                    {kv_row("Auto-init", sec.auto_init, restart_badge())}
                }
            }

            if is_open {
                div { class: "form-row", style: "margin-top:14px;",
                    div { class: "form-group", style: "flex:1;",
                        label { "Identity name" }
                        input { r#type: "text", placeholder: "/ndn/site/router1",
                            value: "{sec.identity.clone().unwrap_or_default()}",
                        }
                    }
                    div { class: "form-group", style: "flex:1;",
                        label { "PIB path" }
                        input { r#type: "text", placeholder: "~/.ndn/pib",
                            value: "{sec.pib_path.clone().unwrap_or_default()}",
                        }
                    }
                }
                div { class: "form-row",
                    div { class: "form-group", style: "flex:1;",
                        label { "Trust anchor file" }
                        input { r#type: "text", placeholder: "/etc/ndn/trust-anchor.cert",
                            value: "{sec.trust_anchor.clone().unwrap_or_default()}",
                        }
                    }
                    div { class: "form-group",
                        label { "Profile" }
                        select {
                            option { value: "default",       selected: sec.profile == "default",       "Default (chain validation)" }
                            option { value: "accept-signed", selected: sec.profile == "accept-signed", "Accept signed (no chain)" }
                            option { value: "disabled",      selected: sec.profile == "disabled",      "Disabled (lab only)" }
                        }
                    }
                    div { class: "form-group",
                        label { "Require signed" }
                        input { r#type: "checkbox", checked: sec.require_signed, }
                    }
                    div { class: "form-group",
                        label { "Auto-init" }
                        input { r#type: "checkbox", checked: sec.auto_init, }
                    }
                }
            }
        }
    }
}

// ── Discovery ─────────────────────────────────────────────────────────────────

fn render_discovery_section(
    disc: DiscoveryTomlConfig,
    editing: Signal<Option<ConfigSection>>,
) -> Element {
    let is_open = *editing.read() == Some(ConfigSection::Discovery);
    let enabled = disc.enabled();

    rsx! {
        div { class: "section",
            {section_header("Discovery", ConfigSection::Discovery, editing)}

            if !enabled {
                div { style: "color:var(--text-muted);font-size:13px;margin-bottom:8px;",
                    "Discovery is disabled. Set "
                    code { "node_name" }
                    " to enable."
                }
            }

            table { style: "width:100%;",
                tbody {
                    {kv_row("Node name", disc.node_name.as_deref().unwrap_or("(disabled)"), restart_badge())}
                    {kv_row("Profile", disc.profile.as_deref().unwrap_or("(default)"), restart_badge())}
                    {kv_row("Transport", disc.discovery_transport.as_deref().unwrap_or("udp"), restart_badge())}
                    {kv_row("Hello base interval", disc.hello_interval_base_ms.map(|v| format!("{v} ms")).unwrap_or("(default)".into()), restart_badge())}
                    {kv_row("Hello max interval", disc.hello_interval_max_ms.map(|v| format!("{v} ms")).unwrap_or("(default)".into()), restart_badge())}
                    {kv_row("Liveness miss count", disc.liveness_miss_count.map(|v| v.to_string()).unwrap_or("(default)".into()), restart_badge())}
                    {kv_row("Gossip fanout", disc.gossip_fanout.map(|v| v.to_string()).unwrap_or("(default)".into()), restart_badge())}
                    {kv_row("Relay records", disc.relay_records.map(|v| v.to_string()).unwrap_or("(default)".into()), restart_badge())}
                    {kv_row("Auto-FIB cost", disc.auto_fib_cost.map(|v| v.to_string()).unwrap_or("(default)".into()), restart_badge())}
                    {kv_row("Served prefixes", disc.served_prefixes.join(", "), restart_badge())}
                }
            }

            if is_open {
                div { class: "form-row", style: "margin-top:14px;",
                    div { class: "form-group", style: "flex:1;",
                        label { "Node name (empty = disable discovery)" }
                        input { r#type: "text", placeholder: "/ndn/site/router1",
                            value: "{disc.node_name.clone().unwrap_or_default()}",
                        }
                    }
                    div { class: "form-group",
                        label { "Profile" }
                        select {
                            option { value: "static",        selected: disc.profile.as_deref() == Some("static"),        "Static" }
                            option { value: "lan",           selected: disc.profile.as_deref() == Some("lan") || disc.profile.is_none(), "LAN" }
                            option { value: "campus",        selected: disc.profile.as_deref() == Some("campus"),        "Campus" }
                            option { value: "mobile",        selected: disc.profile.as_deref() == Some("mobile"),        "Mobile" }
                            option { value: "high-mobility", selected: disc.profile.as_deref() == Some("high-mobility"), "High-mobility" }
                            option { value: "asymmetric",    selected: disc.profile.as_deref() == Some("asymmetric"),    "Asymmetric" }
                        }
                    }
                    div { class: "form-group",
                        label { "Transport" }
                        select {
                            option { value: "udp",   selected: disc.discovery_transport.as_deref() != Some("ether") && disc.discovery_transport.as_deref() != Some("both"), "UDP multicast" }
                            option { value: "ether", selected: disc.discovery_transport.as_deref() == Some("ether"), "Ethernet multicast" }
                            option { value: "both",  selected: disc.discovery_transport.as_deref() == Some("both"),  "Both" }
                        }
                    }
                }
                div { class: "form-row",
                    div { class: "form-group",
                        label { "Hello base interval (ms)" }
                        input { r#type: "number", min: "100", style: "width:120px;",
                            value: "{disc.hello_interval_base_ms.map(|v| v.to_string()).unwrap_or_default()}",
                            placeholder: "(profile default)",
                        }
                    }
                    div { class: "form-group",
                        label { "Hello max interval (ms)" }
                        input { r#type: "number", min: "1000", style: "width:120px;",
                            value: "{disc.hello_interval_max_ms.map(|v| v.to_string()).unwrap_or_default()}",
                            placeholder: "(profile default)",
                        }
                    }
                    div { class: "form-group",
                        label { "Liveness miss count" }
                        input { r#type: "number", min: "1", max: "20", style: "width:80px;",
                            value: "{disc.liveness_miss_count.map(|v| v.to_string()).unwrap_or_default()}",
                            placeholder: "(profile default)",
                        }
                    }
                    div { class: "form-group",
                        label { "Gossip fanout (0=off)" }
                        input { r#type: "number", min: "0", max: "10", style: "width:80px;",
                            value: "{disc.gossip_fanout.map(|v| v.to_string()).unwrap_or_default()}",
                            placeholder: "(profile default)",
                        }
                    }
                    div { class: "form-group",
                        label { "Auto-FIB cost" }
                        input { r#type: "number", min: "0", style: "width:80px;",
                            value: "{disc.auto_fib_cost.map(|v| v.to_string()).unwrap_or_default()}",
                            placeholder: "(profile default)",
                        }
                    }
                }
            }
        }
    }
}

// ── Logging ───────────────────────────────────────────────────────────────────

fn render_logging_section(
    log: LoggingConfig,
    _ctx: AppCtx,
    editing: Signal<Option<ConfigSection>>,
) -> Element {
    let is_open = *editing.read() == Some(ConfigSection::Logging);

    let mut threads = use_signal(|| log.level.clone());
    let mut log_file = use_signal(|| log.file.clone().unwrap_or_default());

    rsx! {
        div { class: "section",
            {section_header("Logging", ConfigSection::Logging, editing)}

            table { style: "width:100%;",
                tbody {
                    {kv_row("Level", &log.level, live_badge())}
                    {kv_row("Log file", log.file.as_deref().unwrap_or("(stderr only)"), restart_badge())}
                }
            }

            if is_open {
                div { class: "form-row", style: "margin-top:14px;",
                    div { class: "form-group",
                        label { "Log level " {live_badge()} }
                        select {
                            onchange: move |e| threads.set(e.value()),
                            option { value: "error", selected: log.level == "error", "error" }
                            option { value: "warn",  selected: log.level == "warn",  "warn" }
                            option { value: "info",  selected: log.level == "info",  "info" }
                            option { value: "debug", selected: log.level == "debug", "debug" }
                            option { value: "trace", selected: log.level == "trace", "trace" }
                        }
                    }
                    div { class: "form-group", style: "flex:1;",
                        label { "Custom filter (overrides level)" }
                        input { r#type: "text", placeholder: "info,ndn_engine=debug",
                            value: if log.level.contains(',') || log.level.contains('=') { log.level.clone() } else { String::new() },
                        }
                    }
                    div { class: "form-group", style: "flex:1;",
                        label { "Log file " {restart_badge()} }
                        input { r#type: "text", placeholder: "/var/log/ndn/router.log",
                            value: "{log_file}",
                            oninput: move |e| log_file.set(e.value()),
                        }
                    }
                    div { style: "display:flex;align-items:flex-end;gap:8px;",
                        div { style: "font-size:12px;color:var(--text-muted);",
                            "Log level applies live. File path requires restart."
                        }
                    }
                }
            }
        }
    }
}

// ── Editable Faces section ────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq)]
enum AddFaceKind {
    Udp,
    Tcp,
    Multicast,
    Unix,
    WebSocket,
    EtherMulticast,
}

impl AddFaceKind {
    #[allow(dead_code)]
    fn label(&self) -> &'static str {
        match self {
            AddFaceKind::Udp => "UDP",
            AddFaceKind::Tcp => "TCP",
            AddFaceKind::Multicast => "UDP Multicast",
            AddFaceKind::Unix => "Unix Socket",
            AddFaceKind::WebSocket => "WebSocket",
            AddFaceKind::EtherMulticast => "Ether Multicast",
        }
    }
}

fn face_config_label(face: &FaceConfig) -> (&'static str, String) {
    match face {
        FaceConfig::Udp { bind, remote } => (
            "UDP",
            format!(
                "bind={} remote={}",
                bind.as_deref().unwrap_or("any"),
                remote.as_deref().unwrap_or("(listen)")
            ),
        ),
        FaceConfig::Tcp { bind, remote } => (
            "TCP",
            format!(
                "bind={} remote={}",
                bind.as_deref().unwrap_or("any"),
                remote.as_deref().unwrap_or("(listen)")
            ),
        ),
        FaceConfig::Multicast {
            group,
            port,
            interface,
        } => (
            "Multicast",
            format!(
                "group={}:{} iface={}",
                group,
                port,
                interface.as_deref().unwrap_or("any")
            ),
        ),
        FaceConfig::Unix { path } => (
            "Unix",
            format!("path={}", path.as_deref().unwrap_or("/run/nfd/nfd.sock")),
        ),
        FaceConfig::WebSocket { bind, url } => (
            "WS",
            format!(
                "bind={} url={}",
                bind.as_deref().unwrap_or("any"),
                url.as_deref().unwrap_or("")
            ),
        ),
        FaceConfig::Serial { path, baud } => ("Serial", format!("path={path} baud={baud}")),
        FaceConfig::EtherMulticast { interface } => ("EtherMC", format!("iface={interface}")),
    }
}

#[component]
fn FacesSection(faces: Signal<Vec<FaceConfig>>) -> Element {
    let mut show_add = use_signal(|| false);
    let mut add_kind = use_signal(|| AddFaceKind::Udp);
    let mut add_bind = use_signal(String::new);
    let mut add_remote = use_signal(String::new);
    let mut add_group = use_signal(|| "224.0.23.170".to_string());
    let mut add_port = use_signal(|| "56363".to_string());
    let mut add_iface = use_signal(String::new);
    let mut add_path = use_signal(|| "/run/nfd/nfd.sock".to_string());
    let mut add_ws_url = use_signal(String::new);

    let n_faces = faces.read().len();
    let show_face_form = *show_add.read();

    rsx! {
        div { class: "section",
            div { style: "display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;",
                div {
                    div { class: "section-title", style: "display:inline;",
                        "Startup Faces "
                    }
                    {restart_badge()}
                }
                div { style: "display:flex;gap:6px;",
                    button {
                        class: "btn btn-primary btn-sm",
                        onclick: move |_| show_add.set(!show_face_form),
                        if show_face_form { "▲ Cancel" } else { "+ Add Face" }
                    }
                }
            }

            if faces.read().is_empty() {
                div { class: "empty", style: "padding:12px 0;",
                    "No startup faces configured."
                }
            } else {
                div { style: "display:flex;flex-direction:column;gap:6px;margin-bottom:10px;",
                    for (i, face) in faces.read().iter().enumerate() {
                        {
                            let (kind_label, details) = face_config_label(face);
                            rsx! {
                                div { style: "display:flex;align-items:center;gap:8px;background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:8px 12px;",
                                    span { class: "badge badge-blue", style: "font-size:10px;", "face[{i}]" }
                                    span { class: "badge badge-gray", style: "font-size:10px;", "{kind_label}" }
                                    span { class: "mono", style: "flex:1;font-size:11px;color:var(--text-muted);", "{details}" }
                                    button {
                                        class: "btn btn-danger btn-sm",
                                        onclick: move |_| { faces.write().remove(i); },
                                        "✕"
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Add face form
            if show_face_form {
                div { style: "background:var(--bg);border:1px solid var(--border-subtle);border-radius:6px;padding:12px;margin-top:6px;",
                    div { style: "font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.4px;margin-bottom:10px;font-weight:600;",
                        "New Face"
                    }
                    div { style: "display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px;",
                        div { class: "form-group",
                            label { "Face Kind" }
                            select {
                                onchange: move |e| {
                                    add_kind.set(match e.value().as_str() {
                                        "tcp"   => AddFaceKind::Tcp,
                                        "mcast" => AddFaceKind::Multicast,
                                        "unix"  => AddFaceKind::Unix,
                                        "ws"    => AddFaceKind::WebSocket,
                                        "ether" => AddFaceKind::EtherMulticast,
                                        _       => AddFaceKind::Udp,
                                    });
                                },
                                option { value: "udp",   "UDP" }
                                option { value: "tcp",   "TCP" }
                                option { value: "mcast", "UDP Multicast" }
                                option { value: "unix",  "Unix Socket" }
                                option { value: "ws",    "WebSocket" }
                                option { value: "ether", "Ether Multicast" }
                            }
                        }

                        // UDP / TCP fields
                        if *add_kind.read() == AddFaceKind::Udp || *add_kind.read() == AddFaceKind::Tcp {
                            div { class: "form-group", style: "flex:1;min-width:160px;",
                                label { "Remote (host:port, empty = listen)" }
                                input {
                                    r#type: "text",
                                    placeholder: "192.168.1.1:6363",
                                    value: "{add_remote}",
                                    oninput: move |e| add_remote.set(e.value()),
                                }
                            }
                            div { class: "form-group", style: "flex:1;min-width:140px;",
                                label { "Bind (optional)" }
                                input {
                                    r#type: "text",
                                    placeholder: "0.0.0.0:6363",
                                    value: "{add_bind}",
                                    oninput: move |e| add_bind.set(e.value()),
                                }
                            }
                        }

                        // Multicast fields
                        if *add_kind.read() == AddFaceKind::Multicast {
                            div { class: "form-group",
                                label { "Multicast Group" }
                                input {
                                    r#type: "text",
                                    value: "{add_group}",
                                    style: "width:150px;",
                                    oninput: move |e| add_group.set(e.value()),
                                }
                            }
                            div { class: "form-group",
                                label { "Port" }
                                input {
                                    r#type: "number",
                                    value: "{add_port}",
                                    style: "width:90px;",
                                    oninput: move |e| add_port.set(e.value()),
                                }
                            }
                            div { class: "form-group", style: "flex:1;",
                                label { "Interface (optional)" }
                                input {
                                    r#type: "text",
                                    placeholder: "eth0",
                                    value: "{add_iface}",
                                    oninput: move |e| add_iface.set(e.value()),
                                }
                            }
                        }

                        // Unix fields
                        if *add_kind.read() == AddFaceKind::Unix {
                            div { class: "form-group", style: "flex:1;",
                                label { "Socket Path" }
                                input {
                                    r#type: "text",
                                    value: "{add_path}",
                                    oninput: move |e| add_path.set(e.value()),
                                }
                            }
                        }

                        // WebSocket fields
                        if *add_kind.read() == AddFaceKind::WebSocket {
                            div { class: "form-group", style: "flex:1;",
                                label { "Bind (optional)" }
                                input {
                                    r#type: "text",
                                    placeholder: "0.0.0.0:9696",
                                    value: "{add_bind}",
                                    oninput: move |e| add_bind.set(e.value()),
                                }
                            }
                            div { class: "form-group", style: "flex:1;",
                                label { "URL (optional)" }
                                input {
                                    r#type: "text",
                                    placeholder: "ws://0.0.0.0:9696/",
                                    value: "{add_ws_url}",
                                    oninput: move |e| add_ws_url.set(e.value()),
                                }
                            }
                        }

                        // EtherMulticast fields
                        if *add_kind.read() == AddFaceKind::EtherMulticast {
                            div { class: "form-group", style: "flex:1;",
                                label { "Interface" }
                                input {
                                    r#type: "text",
                                    placeholder: "eth0",
                                    value: "{add_iface}",
                                    oninput: move |e| add_iface.set(e.value()),
                                }
                            }
                        }
                    }
                    div { style: "display:flex;justify-content:flex-end;gap:6px;",
                        button {
                            class: "btn btn-primary btn-sm",
                            onclick: move |_| {
                                let opt = |s: &str| -> Option<String> {
                                    let s = s.trim();
                                    if s.is_empty() { None } else { Some(s.to_string()) }
                                };
                                let new_face = match *add_kind.read() {
                                    AddFaceKind::Udp => FaceConfig::Udp {
                                        bind: opt(&add_bind.read()),
                                        remote: opt(&add_remote.read()),
                                    },
                                    AddFaceKind::Tcp => FaceConfig::Tcp {
                                        bind: opt(&add_bind.read()),
                                        remote: opt(&add_remote.read()),
                                    },
                                    AddFaceKind::Multicast => FaceConfig::Multicast {
                                        group: add_group.read().trim().to_string(),
                                        port: add_port.read().trim().parse().unwrap_or(56363),
                                        interface: opt(&add_iface.read()),
                                    },
                                    AddFaceKind::Unix => FaceConfig::Unix {
                                        path: opt(&add_path.read()),
                                    },
                                    AddFaceKind::WebSocket => FaceConfig::WebSocket {
                                        bind: opt(&add_bind.read()),
                                        url: opt(&add_ws_url.read()),
                                    },
                                    AddFaceKind::EtherMulticast => FaceConfig::EtherMulticast {
                                        interface: add_iface.read().trim().to_string(),
                                    },
                                };
                                faces.write().push(new_face);
                                // Reset form
                                add_bind.set(String::new());
                                add_remote.set(String::new());
                                add_group.set("224.0.23.170".to_string());
                                add_port.set("56363".to_string());
                                add_iface.set(String::new());
                                add_ws_url.set(String::new());
                                show_add.set(false);
                            },
                            "+ Add face[{n_faces}]"
                        }
                    }
                }
            }

            div { style: "margin-top:8px;font-size:12px;color:var(--text-muted);",
                "Startup faces are created in order (face[0], face[1], …) when the router starts. Routes reference faces by this index."
            }
        }
    }
}

// ── Editable Routes section ───────────────────────────────────────────────────

#[component]
fn RoutesSection(routes: Signal<Vec<RouteConfig>>, n_faces: usize) -> Element {
    let mut show_add = use_signal(|| false);
    let mut add_prefix = use_signal(String::new);
    let mut add_face = use_signal(|| 0u32);
    let mut add_cost = use_signal(|| 10u32);
    let mut add_err: Signal<Option<String>> = use_signal(|| None);

    let show_route_form = *show_add.read();

    rsx! {
        div { class: "section",
            div { style: "display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;",
                div {
                    div { class: "section-title", style: "display:inline;",
                        "Startup Routes "
                    }
                    {restart_badge()}
                }
                button {
                    class: "btn btn-primary btn-sm",
                    onclick: move |_| show_add.set(!show_route_form),
                    if show_route_form { "▲ Cancel" } else { "+ Add Route" }
                }
            }

            if routes.read().is_empty() {
                div { class: "empty", style: "padding:12px 0;",
                    "No startup routes configured."
                }
            } else {
                table { style: "width:100%;margin-bottom:10px;",
                    thead {
                        tr {
                            th { "Prefix" }
                            th { "Face Index" }
                            th { "Cost" }
                            th { style: "width:50px;" }
                        }
                    }
                    tbody {
                        for (i, route) in routes.read().iter().enumerate() {
                            tr {
                                td { class: "mono", "{route.prefix}" }
                                td { class: "mono",
                                    "face[{route.face}]"
                                    if route.face >= n_faces && n_faces > 0 {
                                        span { class: "badge badge-red", style: "font-size:9px;margin-left:4px;", "out of range" }
                                    }
                                }
                                td { class: "mono", "{route.cost}" }
                                td {
                                    button {
                                        class: "btn btn-danger btn-sm",
                                        onclick: move |_| { routes.write().remove(i); },
                                        "✕"
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if show_route_form {
                div { style: "background:var(--bg);border:1px solid var(--border-subtle);border-radius:6px;padding:12px;",
                    div { style: "font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.4px;margin-bottom:10px;font-weight:600;",
                        "New Route"
                    }
                    div { style: "display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px;",
                        div { class: "form-group", style: "flex:2;min-width:180px;",
                            label { "Name Prefix" }
                            input {
                                r#type: "text",
                                placeholder: "/ndn",
                                value: "{add_prefix}",
                                oninput: move |e| {
                                    let mut v = e.value();
                                    if !v.is_empty() && !v.starts_with('/') { v = format!("/{v}"); }
                                    add_prefix.set(v);
                                    add_err.set(None);
                                },
                            }
                        }
                        div { class: "form-group",
                            label {
                                "Face Index"
                                if n_faces > 0 {
                                    span { style: "color:var(--text-faint);margin-left:4px;", "(0–{n_faces-1})" }
                                } else {
                                    span { style: "color:var(--text-faint);margin-left:4px;", "(add faces above)" }
                                }
                            }
                            input {
                                r#type: "number",
                                min: "0",
                                max: if n_faces > 0 { (n_faces - 1).to_string() } else { "99".to_string() },
                                value: "{add_face}",
                                style: "width:90px;",
                                oninput: move |e| {
                                    if let Ok(v) = e.value().parse::<u32>() { add_face.set(v); }
                                    add_err.set(None);
                                },
                            }
                        }
                        div { class: "form-group",
                            div { style: "display:flex;justify-content:space-between;",
                                label { "Cost" }
                                span { style: "font-size:11px;color:var(--accent);", "{add_cost}" }
                            }
                            input {
                                r#type: "range", min: "0", max: "255",
                                value: "{add_cost}",
                                style: "width:120px;margin-top:6px;",
                                oninput: move |e| {
                                    if let Ok(v) = e.value().parse::<u32>() { add_cost.set(v); }
                                },
                            }
                        }
                    }
                    if let Some(ref err) = *add_err.read() {
                        div { style: "color:var(--red);font-size:12px;margin-bottom:6px;", "{err}" }
                    }
                    div { style: "display:flex;justify-content:flex-end;",
                        button {
                            class: "btn btn-primary btn-sm",
                            onclick: move |_| {
                                let p = add_prefix.read().trim().to_string();
                                if p.is_empty() {
                                    add_err.set(Some("Prefix is required".into()));
                                    return;
                                }
                                routes.write().push(RouteConfig {
                                    prefix: p,
                                    face: *add_face.read() as usize,
                                    cost: *add_cost.read(),
                                });
                                add_prefix.set(String::new());
                                add_face.set(0);
                                add_cost.set(10);
                                show_add.set(false);
                            },
                            "+ Add Route"
                        }
                    }
                }
            }
        }
    }
}
