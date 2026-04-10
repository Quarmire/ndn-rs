use dioxus::prelude::*;
use ndn_config::{
    CsConfig, DiscoveryTomlConfig, EngineConfig, FaceConfig, ForwarderConfig,
    LoggingConfig, ManagementConfig, RouteConfig, SecurityConfig,
};

use crate::app::{AppCtx, DashCmd, RouterCmd, push_toast, ToastLevel, CONFIG_PRESETS};

// ── BuildConfig helpers ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
enum BuildFaceKind {
    Udp,
    Tcp,
    Multicast,
    Unix,
    WebSocket,
    EtherMulticast,
}

impl BuildFaceKind {
    #[allow(dead_code)]
    fn label(self) -> &'static str {
        match self {
            BuildFaceKind::Udp          => "UDP",
            BuildFaceKind::Tcp          => "TCP",
            BuildFaceKind::Multicast    => "UDP Multicast",
            BuildFaceKind::Unix         => "Unix Socket",
            BuildFaceKind::WebSocket    => "WebSocket",
            BuildFaceKind::EtherMulticast => "Ether Multicast",
        }
    }
}

#[derive(Debug, Clone)]
struct BuildFaceEntry {
    kind: BuildFaceKind,
    bind: String,
    remote: String,
    group: String,
    port: u16,
    interface: String,
    path: String,
    ws_url: String,
}

impl BuildFaceEntry {
    fn label(&self) -> String {
        match self.kind {
            BuildFaceKind::Udp => format!(
                "UDP {}",
                if self.remote.is_empty() { "(listen)".into() } else { format!("→ {}", self.remote) }
            ),
            BuildFaceKind::Tcp => format!(
                "TCP {}",
                if self.remote.is_empty() { "(listen)".into() } else { format!("→ {}", self.remote) }
            ),
            BuildFaceKind::Multicast => format!("Multicast {}:{}", self.group, self.port),
            BuildFaceKind::Unix => format!("Unix {}", if self.path.is_empty() { "/tmp/ndn.sock" } else { &self.path }),
            BuildFaceKind::WebSocket => format!("WS {}", if self.ws_url.is_empty() { "0.0.0.0:9696" } else { &self.ws_url }),
            BuildFaceKind::EtherMulticast => format!("EtherMC iface={}", self.interface),
        }
    }

    fn to_face_config(&self) -> FaceConfig {
        let opt = |s: &str| -> Option<String> {
            let t = s.trim();
            if t.is_empty() { None } else { Some(t.to_string()) }
        };
        match self.kind {
            BuildFaceKind::Udp => FaceConfig::Udp {
                bind: opt(&self.bind),
                remote: opt(&self.remote),
            },
            BuildFaceKind::Tcp => FaceConfig::Tcp {
                bind: opt(&self.bind),
                remote: opt(&self.remote),
            },
            BuildFaceKind::Multicast => FaceConfig::Multicast {
                group: self.group.clone(),
                port: self.port,
                interface: opt(&self.interface),
            },
            BuildFaceKind::Unix => FaceConfig::Unix {
                path: opt(&self.path),
            },
            BuildFaceKind::WebSocket => FaceConfig::WebSocket {
                bind: opt(&self.bind),
                url: opt(&self.ws_url),
            },
            BuildFaceKind::EtherMulticast => FaceConfig::EtherMulticast {
                interface: self.interface.trim().to_string(),
            },
        }
    }
}

#[derive(Debug, Clone)]
struct BuildRouteEntry {
    prefix: String,
    face_idx: usize,
    cost: u32,
}

#[allow(clippy::too_many_arguments)]
fn assemble_config(
    socket: &str,
    cs_variant: &str,
    cs_cap: u32,
    cs_shards: Option<usize>,
    log_level: &str,
    threads: u32,
    faces: &[BuildFaceEntry],
    routes: &[BuildRouteEntry],
    security: SecurityConfig,
    discovery: DiscoveryTomlConfig,
) -> String {
    let cfg = ForwarderConfig {
        engine: EngineConfig {
            pipeline_threads: threads as usize,
            ..Default::default()
        },
        management: ManagementConfig {
            face_socket: socket.trim().to_string(),
        },
        cs: CsConfig {
            variant: cs_variant.to_string(),
            capacity_mb: if cs_variant == "null" { 0 } else { cs_cap as usize },
            shards: cs_shards,
            ..Default::default()
        },
        logging: LoggingConfig {
            level: log_level.to_string(),
            ..Default::default()
        },
        faces: faces.iter().map(|f| f.to_face_config()).collect(),
        routes: routes.iter().map(|r| RouteConfig {
            prefix: r.prefix.clone(),
            face: r.face_idx,
            cost: r.cost,
        }).collect(),
        security,
        discovery,
    };
    cfg.to_toml_string().unwrap_or_default()
}

// ── StartRouterModal ──────────────────────────────────────────────────────────

#[component]
pub fn StartRouterModal(on_close: EventHandler<()>, config_toml: Signal<String>) -> Element {
    let ctx = use_context::<AppCtx>();
    // Tab order: 0=Quick Start, 1=Build Config, 2=Load File, 3=Presets, 4=Current Config
    let mut active_tab = use_signal(|| 0u8);
    let mut file_path = use_signal(String::new);
    let mut preset_name = use_signal(String::new);
    let toml_preview = config_toml.read().clone();
    let has_config = !toml_preview.is_empty();

    // ── Build Config state ────────────────────────────────────────────────────
    let mut bc_socket    = use_signal(|| "/tmp/ndn.sock".to_string());
    let mut bc_cs_variant = use_signal(|| "lru".to_string());
    let mut bc_cs_cap    = use_signal(|| 64u32);
    let mut bc_log_level = use_signal(|| "info".to_string());
    let mut bc_threads   = use_signal(|| 0u32);
    let mut bc_faces: Signal<Vec<BuildFaceEntry>> = use_signal(Vec::new);
    let mut bc_routes: Signal<Vec<BuildRouteEntry>> = use_signal(Vec::new);
    let mut bc_show_face_form = use_signal(|| false);
    let mut bc_show_route_form = use_signal(|| false);
    let mut bc_face_kind = use_signal(|| BuildFaceKind::Udp);
    let mut bc_face_bind = use_signal(String::new);
    let mut bc_face_remote = use_signal(String::new);
    let mut bc_face_group = use_signal(|| "224.0.23.170".to_string());
    let mut bc_face_port = use_signal(|| 56363u16);
    let mut bc_face_iface = use_signal(String::new);
    let mut bc_face_path = use_signal(|| "/tmp/ndn.sock".to_string());
    let mut bc_face_ws_url = use_signal(String::new);
    let mut bc_route_prefix = use_signal(String::new);
    let mut bc_route_face = use_signal(|| 0u32);
    let mut bc_route_cost = use_signal(|| 10u32);
    let mut bc_show_preview = use_signal(|| false);

    // Security settings
    let mut bc_sec_identity      = use_signal(String::new);
    let mut bc_sec_pib_path      = use_signal(String::new);
    let mut bc_sec_trust_anchor  = use_signal(String::new);
    let mut bc_sec_profile       = use_signal(|| "default".to_string());
    let mut bc_sec_require_signed = use_signal(|| false);
    let mut bc_sec_auto_init     = use_signal(|| false);

    // Discovery settings
    let mut bc_disc_node_name       = use_signal(String::new);
    let mut bc_disc_profile         = use_signal(|| "lan".to_string());
    let mut bc_disc_transport       = use_signal(|| "udp".to_string());
    let mut bc_disc_hello_base      = use_signal(String::new);
    let mut bc_disc_hello_max       = use_signal(String::new);
    let mut bc_disc_liveness_miss   = use_signal(String::new);
    let mut bc_disc_gossip_fanout   = use_signal(String::new);
    let mut bc_disc_served_prefixes = use_signal(String::new);

    // CS shards (sharded-lru only)
    let mut bc_cs_shards = use_signal(|| 4u32);

    // Pre-compute display/validation state before rsx!
    let modal_width = if *active_tab.read() == 1 { "max-width:660px;" } else { "max-width:480px;" };
    let show_face_form = *bc_show_face_form.read();
    let show_route_form = *bc_show_route_form.read();
    let sec_identity_err = { let v = bc_sec_identity.read(); !v.is_empty() && !v.starts_with('/') };
    let sec_auto_init_disabled = bc_sec_identity.read().trim().is_empty();
    let disc_node_err = { let v = bc_disc_node_name.read(); !v.is_empty() && !v.starts_with('/') };
    let disc_enabled = { let v = bc_disc_node_name.read(); !v.is_empty() && v.starts_with('/') };
    let cs_var = bc_cs_variant.read().clone();
    let cs_is_null = cs_var == "null";
    let cs_is_sharded = cs_var == "sharded-lru";

    rsx! {
        div { class: "modal-overlay", onclick: move |_| on_close.call(()),
            div {
                class: "modal-card",
                style: "{modal_width}",
                onclick: move |e| e.stop_propagation(),

                div { class: "modal-header",
                    span { class: "modal-title", "Start Router" }
                    button { class: "modal-close", onclick: move |_| on_close.call(()), "✕" }
                }

                // Tab selector
                div { class: "tab-pills",
                    button {
                        class: if *active_tab.read() == 0 { "tab-pill active" } else { "tab-pill" },
                        onclick: move |_| active_tab.set(0),
                        "Quick Start"
                    }
                    button {
                        class: if *active_tab.read() == 1 { "tab-pill active" } else { "tab-pill" },
                        onclick: move |_| active_tab.set(1),
                        "Build Config"
                    }
                    button {
                        class: if *active_tab.read() == 2 { "tab-pill active" } else { "tab-pill" },
                        onclick: move |_| active_tab.set(2),
                        "Load Config File"
                    }
                    button {
                        class: if *active_tab.read() == 3 { "tab-pill active" } else { "tab-pill" },
                        onclick: move |_| active_tab.set(3),
                        "Saved Presets"
                    }
                    if has_config {
                        button {
                            class: if *active_tab.read() == 4 { "tab-pill active" } else { "tab-pill" },
                            onclick: move |_| active_tab.set(4),
                            "Current Config"
                        }
                    }
                }

                match *active_tab.read() {
                    // ── Build Config tab ──────────────────────────────────
                    1 => rsx! {
                        div {
                            // Basic Settings
                            div { class: "bc-section",
                                div { class: "bc-section-title", "Router Settings" }
                                div { style: "display:grid;grid-template-columns:1fr 1fr;gap:10px;",
                                    div { class: "form-group",
                                        label { "Management Socket" }
                                        input {
                                            r#type: "text",
                                            value: "{bc_socket}",
                                            style: "width:100%;",
                                            oninput: move |e| bc_socket.set(e.value()),
                                        }
                                    }
                                    div { class: "form-group",
                                        label { "Log Level" }
                                        select {
                                            style: "width:100%;",
                                            onchange: move |e| bc_log_level.set(e.value()),
                                            option { value: "error", "error" }
                                            option { value: "warn",  "warn" }
                                            option { value: "info",  selected: true, "info" }
                                            option { value: "debug", "debug" }
                                            option { value: "trace", "trace" }
                                        }
                                    }
                                    div { class: "form-group",
                                        label { "Content Store" }
                                        select {
                                            style: "width:100%;",
                                            onchange: move |e| bc_cs_variant.set(e.value()),
                                            option { value: "lru",          selected: true, "LRU" }
                                            option { value: "sharded-lru",  "Sharded LRU" }
                                            option { value: "null",         "Null (disabled)" }
                                        }
                                    }
                                    div { class: "form-group",
                                        label { "CS Capacity (MB)" }
                                        input {
                                            r#type: "number", min: "0", max: "65536",
                                            value: "{bc_cs_cap}",
                                            style: if cs_is_null { "width:100%;opacity:0.4;" } else { "width:100%;" },
                                            disabled: cs_is_null,
                                            oninput: move |e| { if let Ok(v) = e.value().parse::<u32>() { bc_cs_cap.set(v); } },
                                        }
                                        if cs_is_null {
                                            span { style: "font-size:11px;color:var(--text-muted);", "Caching disabled" }
                                        }
                                    }
                                    if cs_is_sharded {
                                        div { class: "form-group",
                                            label { "CS Shards" }
                                            input {
                                                r#type: "number", min: "2", max: "64",
                                                value: "{bc_cs_shards}",
                                                style: "width:100%;",
                                                oninput: move |e| { if let Ok(v) = e.value().parse::<u32>() { bc_cs_shards.set(v); } },
                                            }
                                        }
                                    }
                                    div { class: "form-group",
                                        label { "Pipeline Threads (0 = auto)" }
                                        input {
                                            r#type: "number", min: "0", max: "64",
                                            value: "{bc_threads}",
                                            style: "width:100%;",
                                            oninput: move |e| { if let Ok(v) = e.value().parse::<u32>() { bc_threads.set(v); } },
                                        }
                                    }
                                }
                            }

                            // Security Settings
                            div { class: "bc-section",
                                div { class: "bc-section-title", "Security" }
                                div { style: "display:grid;grid-template-columns:1fr 1fr;gap:10px;",
                                    div { class: "form-group",
                                        label { "Identity Name" }
                                        input {
                                            r#type: "text", placeholder: "/ndn/router1",
                                            value: "{bc_sec_identity}", style: "width:100%;",
                                            oninput: move |e| bc_sec_identity.set(e.value()),
                                        }
                                        if sec_identity_err {
                                            span { style: "font-size:11px;color:var(--red);margin-top:2px;",
                                                "Must start with /"
                                            }
                                        }
                                    }
                                    div { class: "form-group",
                                        label { "Security Profile" }
                                        select {
                                            style: "width:100%;",
                                            onchange: move |e| bc_sec_profile.set(e.value()),
                                            option { value: "default",
                                                selected: *bc_sec_profile.read() == "default",
                                                "default (full validation)"
                                            }
                                            option { value: "accept-signed",
                                                selected: *bc_sec_profile.read() == "accept-signed",
                                                "accept-signed (no chain)"
                                            }
                                            option { value: "disabled",
                                                selected: *bc_sec_profile.read() == "disabled",
                                                "disabled (lab/bench only)"
                                            }
                                        }
                                    }
                                    div { class: "form-group",
                                        label { "PIB Path (optional)" }
                                        input {
                                            r#type: "text", placeholder: "~/.ndn/pib.db",
                                            value: "{bc_sec_pib_path}", style: "width:100%;",
                                            oninput: move |e| bc_sec_pib_path.set(e.value()),
                                        }
                                    }
                                    div { class: "form-group",
                                        label { "Trust Anchor File (optional)" }
                                        input {
                                            r#type: "text", placeholder: "/etc/ndn/trust-anchor.cert",
                                            value: "{bc_sec_trust_anchor}", style: "width:100%;",
                                            oninput: move |e| bc_sec_trust_anchor.set(e.value()),
                                        }
                                    }
                                    div { style: "display:flex;align-items:center;gap:6px;padding-top:12px;",
                                        input {
                                            r#type: "checkbox",
                                            checked: *bc_sec_require_signed.read(),
                                            oninput: move |e| bc_sec_require_signed.set(e.checked()),
                                        }
                                        label { style: "font-size:12px;color:var(--text);cursor:pointer;",
                                            "Require signed data"
                                        }
                                    }
                                    div {
                                        style: if sec_auto_init_disabled {
                                            "display:flex;align-items:center;gap:6px;padding-top:12px;opacity:0.4;pointer-events:none;"
                                        } else {
                                            "display:flex;align-items:center;gap:6px;padding-top:12px;"
                                        },
                                        input {
                                            r#type: "checkbox",
                                            checked: *bc_sec_auto_init.read(),
                                            oninput: move |e| bc_sec_auto_init.set(e.checked()),
                                        }
                                        label { style: "font-size:12px;color:var(--text);cursor:pointer;",
                                            "Auto-init identity on first start"
                                        }
                                    }
                                }
                            }

                            // Discovery Settings
                            div { class: "bc-section",
                                div { class: "bc-section-title",
                                    "Discovery"
                                    if disc_enabled {
                                        span { style: "font-size:10px;color:var(--green);font-weight:400;margin-left:6px;",
                                            "enabled"
                                        }
                                    }
                                }
                                // Node name — controls whether discovery is on
                                div { class: "form-group", style: "margin-bottom:10px;",
                                    label { "Node Name (required to enable discovery)" }
                                    input {
                                        r#type: "text", placeholder: "/ndn/site/myrouter",
                                        value: "{bc_disc_node_name}", style: "width:100%;",
                                        oninput: move |e| bc_disc_node_name.set(e.value()),
                                    }
                                    if disc_node_err {
                                        span { style: "font-size:11px;color:var(--red);margin-top:2px;", "Must start with /" }
                                    } else if bc_disc_node_name.read().is_empty() {
                                        span { style: "font-size:11px;color:var(--text-muted);margin-top:2px;",
                                            "Leave empty to disable discovery"
                                        }
                                    }
                                }
                                // All fields below disabled when discovery is off
                                div { style: if disc_enabled { "" } else { "opacity:0.4;pointer-events:none;" },
                                    div { style: "display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:10px;",
                                        div { class: "form-group",
                                            label { "Profile" }
                                            select {
                                                style: "width:100%;",
                                                onchange: move |e| bc_disc_profile.set(e.value()),
                                                option { value: "static",        selected: *bc_disc_profile.read() == "static",        "static" }
                                                option { value: "lan",           selected: *bc_disc_profile.read() == "lan",           "lan (default)" }
                                                option { value: "campus",        selected: *bc_disc_profile.read() == "campus",        "campus" }
                                                option { value: "mobile",        selected: *bc_disc_profile.read() == "mobile",        "mobile" }
                                                option { value: "high-mobility", selected: *bc_disc_profile.read() == "high-mobility", "high-mobility" }
                                                option { value: "asymmetric",    selected: *bc_disc_profile.read() == "asymmetric",    "asymmetric" }
                                            }
                                        }
                                        div { class: "form-group",
                                            label { "Discovery Transport" }
                                            select {
                                                style: "width:100%;",
                                                onchange: move |e| bc_disc_transport.set(e.value()),
                                                option { value: "udp",   selected: *bc_disc_transport.read() == "udp",   "UDP multicast" }
                                                option { value: "ether", selected: *bc_disc_transport.read() == "ether", "Ethernet" }
                                                option { value: "both",  selected: *bc_disc_transport.read() == "both",  "Both" }
                                            }
                                        }
                                    }
                                    div { style: "display:grid;grid-template-columns:1fr 1fr 1fr 1fr;gap:8px;margin-bottom:10px;",
                                        div { class: "form-group",
                                            label { "Hello Base (ms)" }
                                            input {
                                                r#type: "number", min: "100", placeholder: "5000",
                                                value: "{bc_disc_hello_base}", style: "width:100%;",
                                                oninput: move |e| bc_disc_hello_base.set(e.value()),
                                            }
                                        }
                                        div { class: "form-group",
                                            label { "Hello Max (ms)" }
                                            input {
                                                r#type: "number", min: "100", placeholder: "60000",
                                                value: "{bc_disc_hello_max}", style: "width:100%;",
                                                oninput: move |e| bc_disc_hello_max.set(e.value()),
                                            }
                                        }
                                        div { class: "form-group",
                                            label { "Liveness Misses" }
                                            input {
                                                r#type: "number", min: "1", max: "20", placeholder: "3",
                                                value: "{bc_disc_liveness_miss}", style: "width:100%;",
                                                oninput: move |e| bc_disc_liveness_miss.set(e.value()),
                                            }
                                        }
                                        div { class: "form-group",
                                            label { "Gossip Fanout" }
                                            input {
                                                r#type: "number", min: "1", max: "20", placeholder: "3",
                                                value: "{bc_disc_gossip_fanout}", style: "width:100%;",
                                                oninput: move |e| bc_disc_gossip_fanout.set(e.value()),
                                            }
                                        }
                                    }
                                    div { class: "form-group",
                                        label { "Served Prefixes (one per line)" }
                                        textarea {
                                            rows: "3",
                                            placeholder: "/ndn/site/sensors\n/ndn/myapp",
                                            value: "{bc_disc_served_prefixes}",
                                            style: "width:100%;resize:vertical;",
                                            oninput: move |e| bc_disc_served_prefixes.set(e.value()),
                                        }
                                    }
                                }
                            }

                            // Startup Faces
                            div { class: "bc-section",
                                div { style: "display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;",
                                    div { class: "bc-section-title", style: "margin-bottom:0;", "Startup Faces" }
                                    button {
                                        class: "btn btn-primary btn-sm",
                                        onclick: move |_| bc_show_face_form.set(!show_face_form),
                                        if show_face_form { "▲ Cancel" } else { "+ Add" }
                                    }
                                }

                                if bc_faces.read().is_empty() {
                                    div { style: "font-size:12px;color:var(--text-muted);padding:6px 0;",
                                        "No startup faces. Router will start with management face only."
                                    }
                                } else {
                                    div { style: "display:flex;flex-direction:column;gap:4px;margin-bottom:8px;",
                                        for (i, face) in bc_faces.read().iter().enumerate() {
                                            {
                                                let lbl = face.label();
                                                rsx! {
                                                    div { class: "bc-face-row",
                                                        span { style: "color:var(--accent-solid);", "face[{i}]" }
                                                        span { style: "flex:1;color:var(--text-muted);", "{lbl}" }
                                                        button {
                                                            class: "btn btn-danger btn-sm",
                                                            onclick: move |_| { bc_faces.write().remove(i); },
                                                            "✕"
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }

                                if show_face_form {
                                    div { style: "background:var(--surface2);border-radius:4px;padding:10px;",
                                        div { style: "display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px;",
                                            div { class: "form-group",
                                                label { "Kind" }
                                                select {
                                                    onchange: move |e| {
                                                        bc_face_kind.set(match e.value().as_str() {
                                                            "tcp"   => BuildFaceKind::Tcp,
                                                            "mcast" => BuildFaceKind::Multicast,
                                                            "unix"  => BuildFaceKind::Unix,
                                                            "ws"    => BuildFaceKind::WebSocket,
                                                            "ether" => BuildFaceKind::EtherMulticast,
                                                            _       => BuildFaceKind::Udp,
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

                                            if *bc_face_kind.read() == BuildFaceKind::Udp || *bc_face_kind.read() == BuildFaceKind::Tcp {
                                                div { class: "form-group", style: "flex:1;min-width:140px;",
                                                    label { "Remote host:port (empty=listen)" }
                                                    input { r#type: "text", placeholder: "192.168.1.1:6363",
                                                        value: "{bc_face_remote}",
                                                        oninput: move |e| bc_face_remote.set(e.value()),
                                                    }
                                                }
                                                div { class: "form-group", style: "flex:1;min-width:120px;",
                                                    label { "Bind (optional)" }
                                                    input { r#type: "text", placeholder: "0.0.0.0:6363",
                                                        value: "{bc_face_bind}",
                                                        oninput: move |e| bc_face_bind.set(e.value()),
                                                    }
                                                }
                                            }

                                            if *bc_face_kind.read() == BuildFaceKind::Multicast {
                                                div { class: "form-group",
                                                    label { "Group" }
                                                    input { r#type: "text", value: "{bc_face_group}", style: "width:140px;",
                                                        oninput: move |e| bc_face_group.set(e.value()),
                                                    }
                                                }
                                                div { class: "form-group",
                                                    label { "Port" }
                                                    input { r#type: "number", value: "{bc_face_port}", style: "width:80px;",
                                                        oninput: move |e| { if let Ok(v) = e.value().parse::<u16>() { bc_face_port.set(v); } },
                                                    }
                                                }
                                                div { class: "form-group", style: "flex:1;",
                                                    label { "Interface (optional)" }
                                                    input { r#type: "text", placeholder: "eth0",
                                                        value: "{bc_face_iface}",
                                                        oninput: move |e| bc_face_iface.set(e.value()),
                                                    }
                                                }
                                            }

                                            if *bc_face_kind.read() == BuildFaceKind::Unix {
                                                div { class: "form-group", style: "flex:1;",
                                                    label { "Socket Path" }
                                                    input { r#type: "text", value: "{bc_face_path}",
                                                        oninput: move |e| bc_face_path.set(e.value()),
                                                    }
                                                }
                                            }

                                            if *bc_face_kind.read() == BuildFaceKind::WebSocket {
                                                div { class: "form-group", style: "flex:1;",
                                                    label { "Bind" }
                                                    input { r#type: "text", placeholder: "0.0.0.0:9696",
                                                        value: "{bc_face_bind}",
                                                        oninput: move |e| bc_face_bind.set(e.value()),
                                                    }
                                                }
                                                div { class: "form-group", style: "flex:1;",
                                                    label { "URL (optional)" }
                                                    input { r#type: "text", placeholder: "ws://0.0.0.0:9696/",
                                                        value: "{bc_face_ws_url}",
                                                        oninput: move |e| bc_face_ws_url.set(e.value()),
                                                    }
                                                }
                                            }

                                            if *bc_face_kind.read() == BuildFaceKind::EtherMulticast {
                                                div { class: "form-group", style: "flex:1;",
                                                    label { "Interface" }
                                                    input { r#type: "text", placeholder: "eth0",
                                                        value: "{bc_face_iface}",
                                                        oninput: move |e| bc_face_iface.set(e.value()),
                                                    }
                                                }
                                            }
                                        }
                                        button {
                                            class: "btn btn-primary btn-sm",
                                            onclick: move |_| {
                                                let entry = BuildFaceEntry {
                                                    kind: *bc_face_kind.read(),
                                                    bind: bc_face_bind.read().trim().to_string(),
                                                    remote: bc_face_remote.read().trim().to_string(),
                                                    group: bc_face_group.read().trim().to_string(),
                                                    port: *bc_face_port.read(),
                                                    interface: bc_face_iface.read().trim().to_string(),
                                                    path: bc_face_path.read().trim().to_string(),
                                                    ws_url: bc_face_ws_url.read().trim().to_string(),
                                                };
                                                bc_faces.write().push(entry);
                                                bc_face_bind.set(String::new());
                                                bc_face_remote.set(String::new());
                                                bc_face_iface.set(String::new());
                                                bc_show_face_form.set(false);
                                            },
                                            "+ Add face[{bc_faces.read().len()}]"
                                        }
                                    }
                                }
                            }

                            // Startup Routes
                            div { class: "bc-section",
                                div { style: "display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;",
                                    div { class: "bc-section-title", style: "margin-bottom:0;", "Startup Routes" }
                                    button {
                                        class: "btn btn-primary btn-sm",
                                        onclick: move |_| bc_show_route_form.set(!show_route_form),
                                        if show_route_form { "▲ Cancel" } else { "+ Add" }
                                    }
                                }

                                if bc_routes.read().is_empty() {
                                    div { style: "font-size:12px;color:var(--text-muted);padding:6px 0;",
                                        "No startup routes."
                                    }
                                } else {
                                    div { style: "display:flex;flex-direction:column;gap:3px;margin-bottom:8px;",
                                        for (i, route) in bc_routes.read().iter().enumerate() {
                                            {
                                                let prefix = route.prefix.clone();
                                                let face_i = route.face_idx;
                                                let cost   = route.cost;
                                                rsx! {
                                                    div { class: "bc-face-row",
                                                        span { class: "mono", style: "flex:1;", "{prefix}" }
                                                        span { style: "color:var(--accent-solid);", "→ face[{face_i}]" }
                                                        span { style: "color:var(--text-muted);margin-left:6px;", "cost={cost}" }
                                                        button {
                                                            class: "btn btn-danger btn-sm",
                                                            onclick: move |_| { bc_routes.write().remove(i); },
                                                            "✕"
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }

                                if *bc_show_route_form.read() {
                                    div { style: "background:var(--surface2);border-radius:4px;padding:10px;",
                                        div { style: "display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px;",
                                            div { class: "form-group", style: "flex:2;min-width:140px;",
                                                label { "Name Prefix" }
                                                input { r#type: "text", placeholder: "/ndn",
                                                    value: "{bc_route_prefix}",
                                                    oninput: move |e| {
                                                        let mut v = e.value();
                                                        if !v.is_empty() && !v.starts_with('/') { v = format!("/{v}"); }
                                                        bc_route_prefix.set(v);
                                                    },
                                                }
                                            }
                                            div { class: "form-group",
                                                label {
                                                    "Face Index"
                                                    if !bc_faces.read().is_empty() {
                                                        span { style: "color:var(--text-faint);margin-left:4px;",
                                                            "(0–{bc_faces.read().len()-1})"
                                                        }
                                                    }
                                                }
                                                input { r#type: "number", min: "0", value: "{bc_route_face}", style: "width:80px;",
                                                    oninput: move |e| { if let Ok(v) = e.value().parse::<u32>() { bc_route_face.set(v); } },
                                                }
                                            }
                                            div { class: "form-group",
                                                div { style: "display:flex;justify-content:space-between;",
                                                    label { "Cost" }
                                                    span { style: "font-size:11px;color:var(--accent);", "{bc_route_cost}" }
                                                }
                                                input { r#type: "range", min: "0", max: "255", value: "{bc_route_cost}", style: "width:100px;margin-top:6px;",
                                                    oninput: move |e| { if let Ok(v) = e.value().parse::<u32>() { bc_route_cost.set(v); } },
                                                }
                                            }
                                        }
                                        button {
                                            class: "btn btn-primary btn-sm",
                                            disabled: bc_route_prefix.read().is_empty(),
                                            onclick: move |_| {
                                                let p = bc_route_prefix.read().trim().to_string();
                                                if p.is_empty() { return; }
                                                bc_routes.write().push(BuildRouteEntry {
                                                    prefix: p,
                                                    face_idx: *bc_route_face.read() as usize,
                                                    cost: *bc_route_cost.read(),
                                                });
                                                bc_route_prefix.set(String::new());
                                                bc_route_face.set(0);
                                                bc_route_cost.set(10);
                                                bc_show_route_form.set(false);
                                            },
                                            "+ Add Route"
                                        }
                                    }
                                }
                            }

                            // TOML preview toggle
                            {
                                let show = *bc_show_preview.read();
                                rsx! {
                                    button {
                                        class: "btn btn-secondary btn-sm",
                                        style: "margin-bottom:10px;",
                                        onclick: move |_| bc_show_preview.set(!show),
                                        if show { "▲ Hide TOML preview" } else { "▼ Show TOML preview" }
                                    }
                                    if show {
                                        {
                                            let preview = {
                                                let sock = bc_socket.read().trim().to_string();
                                                let csv  = bc_cs_variant.read().clone();
                                                let csc  = *bc_cs_cap.read();
                                                let css  = if csv == "sharded-lru" { Some(*bc_cs_shards.read() as usize) } else { None };
                                                let ll   = bc_log_level.read().clone();
                                                let thr  = *bc_threads.read();
                                                let fcs  = bc_faces.read().clone();
                                                let rts  = bc_routes.read().clone();
                                                let opt  = |s: String| -> Option<String> { if s.trim().is_empty() { None } else { Some(s.trim().to_string()) } };
                                                let sec  = SecurityConfig {
                                                    identity:      opt(bc_sec_identity.read().clone()),
                                                    pib_path:      opt(bc_sec_pib_path.read().clone()),
                                                    trust_anchor:  opt(bc_sec_trust_anchor.read().clone()),
                                                    profile:       bc_sec_profile.read().clone(),
                                                    require_signed: *bc_sec_require_signed.read(),
                                                    auto_init:     *bc_sec_auto_init.read(),
                                                    ..Default::default()
                                                };
                                                let dnn  = bc_disc_node_name.read().trim().to_string();
                                                let disc = if dnn.is_empty() { DiscoveryTomlConfig::default() } else {
                                                    let dtr = bc_disc_transport.read().clone();
                                                    DiscoveryTomlConfig {
                                                        node_name:               Some(dnn),
                                                        profile:                 Some(bc_disc_profile.read().clone()),
                                                        discovery_transport:     if dtr == "udp" { None } else { Some(dtr) },
                                                        hello_interval_base_ms:  bc_disc_hello_base.read().trim().parse().ok(),
                                                        hello_interval_max_ms:   bc_disc_hello_max.read().trim().parse().ok(),
                                                        liveness_miss_count:     bc_disc_liveness_miss.read().trim().parse().ok(),
                                                        gossip_fanout:           bc_disc_gossip_fanout.read().trim().parse().ok(),
                                                        served_prefixes:         bc_disc_served_prefixes.read().lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect(),
                                                        ..Default::default()
                                                    }
                                                };
                                                assemble_config(&sock, &csv, csc, css, &ll, thr, &fcs, &rts, sec, disc)
                                            };
                                            rsx! {
                                                pre {
                                                    style: "background:var(--bg);border:1px solid var(--border-subtle);border-radius:4px;padding:10px;font-size:11px;color:var(--text-muted);max-height:160px;overflow-y:auto;margin-bottom:10px;white-space:pre-wrap;word-break:break-all;",
                                                    "{preview}"
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            div { class: "modal-footer",
                                button {
                                    class: "btn btn-secondary",
                                    onclick: move |_| on_close.call(()),
                                    "Cancel"
                                }
                                button {
                                    class: "btn btn-secondary",
                                    title: "Save this configuration as a preset",
                                    onclick: move |_| {
                                        let toml = {
                                            let sock = bc_socket.read().trim().to_string();
                                            let csv  = bc_cs_variant.read().clone();
                                            let csc  = *bc_cs_cap.read();
                                            let css  = if csv == "sharded-lru" { Some(*bc_cs_shards.read() as usize) } else { None };
                                            let ll   = bc_log_level.read().clone();
                                            let thr  = *bc_threads.read();
                                            let fcs  = bc_faces.read().clone();
                                            let rts  = bc_routes.read().clone();
                                            let opt  = |s: String| -> Option<String> { if s.trim().is_empty() { None } else { Some(s.trim().to_string()) } };
                                            let sec  = SecurityConfig {
                                                identity:       opt(bc_sec_identity.read().clone()),
                                                pib_path:       opt(bc_sec_pib_path.read().clone()),
                                                trust_anchor:   opt(bc_sec_trust_anchor.read().clone()),
                                                profile:        bc_sec_profile.read().clone(),
                                                require_signed: *bc_sec_require_signed.read(),
                                                auto_init:      *bc_sec_auto_init.read(),
                                                ..Default::default()
                                            };
                                            let dnn  = bc_disc_node_name.read().trim().to_string();
                                            let disc = if dnn.is_empty() { DiscoveryTomlConfig::default() } else {
                                                let dtr = bc_disc_transport.read().clone();
                                                DiscoveryTomlConfig {
                                                    node_name:              Some(dnn),
                                                    profile:                Some(bc_disc_profile.read().clone()),
                                                    discovery_transport:    if dtr == "udp" { None } else { Some(dtr) },
                                                    hello_interval_base_ms: bc_disc_hello_base.read().trim().parse().ok(),
                                                    hello_interval_max_ms:  bc_disc_hello_max.read().trim().parse().ok(),
                                                    liveness_miss_count:    bc_disc_liveness_miss.read().trim().parse().ok(),
                                                    gossip_fanout:          bc_disc_gossip_fanout.read().trim().parse().ok(),
                                                    served_prefixes:        bc_disc_served_prefixes.read().lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect(),
                                                    ..Default::default()
                                                }
                                            };
                                            assemble_config(&sock, &csv, csc, css, &ll, thr, &fcs, &rts, sec, disc)
                                        };
                                        let name = format!(
                                            "Custom ({} faces, {} routes)",
                                            bc_faces.read().len(),
                                            bc_routes.read().len()
                                        );
                                        CONFIG_PRESETS.write().push((name, toml));
                                        push_toast("Config saved as preset", ToastLevel::Success);
                                    },
                                    "Save as Preset"
                                }
                                button {
                                    class: "btn btn-primary",
                                    onclick: move |_| {
                                        let toml = {
                                            let sock = bc_socket.read().trim().to_string();
                                            let csv  = bc_cs_variant.read().clone();
                                            let csc  = *bc_cs_cap.read();
                                            let css  = if csv == "sharded-lru" { Some(*bc_cs_shards.read() as usize) } else { None };
                                            let ll   = bc_log_level.read().clone();
                                            let thr  = *bc_threads.read();
                                            let fcs  = bc_faces.read().clone();
                                            let rts  = bc_routes.read().clone();
                                            let opt  = |s: String| -> Option<String> { if s.trim().is_empty() { None } else { Some(s.trim().to_string()) } };
                                            let sec  = SecurityConfig {
                                                identity:       opt(bc_sec_identity.read().clone()),
                                                pib_path:       opt(bc_sec_pib_path.read().clone()),
                                                trust_anchor:   opt(bc_sec_trust_anchor.read().clone()),
                                                profile:        bc_sec_profile.read().clone(),
                                                require_signed: *bc_sec_require_signed.read(),
                                                auto_init:      *bc_sec_auto_init.read(),
                                                ..Default::default()
                                            };
                                            let dnn  = bc_disc_node_name.read().trim().to_string();
                                            let disc = if dnn.is_empty() { DiscoveryTomlConfig::default() } else {
                                                let dtr = bc_disc_transport.read().clone();
                                                DiscoveryTomlConfig {
                                                    node_name:              Some(dnn),
                                                    profile:                Some(bc_disc_profile.read().clone()),
                                                    discovery_transport:    if dtr == "udp" { None } else { Some(dtr) },
                                                    hello_interval_base_ms: bc_disc_hello_base.read().trim().parse().ok(),
                                                    hello_interval_max_ms:  bc_disc_hello_max.read().trim().parse().ok(),
                                                    liveness_miss_count:    bc_disc_liveness_miss.read().trim().parse().ok(),
                                                    gossip_fanout:          bc_disc_gossip_fanout.read().trim().parse().ok(),
                                                    served_prefixes:        bc_disc_served_prefixes.read().lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect(),
                                                    ..Default::default()
                                                }
                                            };
                                            assemble_config(&sock, &csv, csc, css, &ll, thr, &fcs, &rts, sec, disc)
                                        };
                                        match crate::router_proc::write_temp_config(&toml) {
                                            Ok(path) => {
                                                ctx.router_cmd.send(RouterCmd::Start(Some(path.to_string_lossy().to_string())));
                                                on_close.call(());
                                            }
                                            Err(e) => push_toast(format!("Failed to write config: {e}"), ToastLevel::Error),
                                        }
                                    },
                                    "▶ Start with this Config"
                                }
                            }
                        }
                    },

                    // ── Load Config File tab ──────────────────────────────
                    2 => rsx! {
                        div {
                            div { style: "font-size:13px;color:var(--text-muted);margin-bottom:12px;",
                                "Enter the path to a TOML configuration file."
                            }
                            div { class: "form-group", style: "margin-bottom:12px;",
                                label { "Config File Path" }
                                input {
                                    r#type: "text",
                                    placeholder: "/etc/ndn/router.toml",
                                    value: "{file_path}",
                                    style: "width:100%;",
                                    oninput: move |e| file_path.set(e.value()),
                                }
                            }
                            div { class: "modal-footer",
                                button {
                                    class: "btn btn-secondary",
                                    onclick: move |_| on_close.call(()),
                                    "Cancel"
                                }
                                button {
                                    class: "btn btn-primary",
                                    disabled: file_path.read().trim().is_empty(),
                                    onclick: move |_| {
                                        let path = file_path.read().trim().to_string();
                                        if !path.is_empty() {
                                            ctx.router_cmd.send(RouterCmd::Start(Some(path)));
                                            on_close.call(());
                                        }
                                    },
                                    "▶ Start with File"
                                }
                            }
                        }
                    },

                    // ── Saved Presets tab ─────────────────────────────────
                    3 => rsx! {
                        div {
                            {
                                let presets = CONFIG_PRESETS.read();
                                if presets.is_empty() {
                                    rsx! {
                                        div { class: "empty", style: "margin-bottom:16px;",
                                            "No saved presets yet. Use \"Build Config\" or load a config and save it as a preset."
                                        }
                                    }
                                } else {
                                    rsx! {
                                        div { style: "display:flex;flex-direction:column;gap:8px;margin-bottom:16px;",
                                            for (idx, (name, toml)) in presets.iter().enumerate() {
                                                {
                                                    let name = name.clone();
                                                    let toml = toml.clone();
                                                    rsx! {
                                                        div {
                                                            style: "display:flex;align-items:center;justify-content:space-between;background:var(--bg);border:1px solid var(--border-subtle);border-radius:6px;padding:8px 12px;",
                                                            span { style: "font-size:13px;color:var(--text);", "{name}" }
                                                            div { style: "display:flex;gap:6px;",
                                                                button {
                                                                    class: "btn btn-primary btn-sm",
                                                                    onclick: move |_| {
                                                                        match crate::router_proc::write_temp_config(&toml) {
                                                                            Ok(path) => {
                                                                                ctx.router_cmd.send(RouterCmd::Start(Some(path.to_string_lossy().to_string())));
                                                                                on_close.call(());
                                                                            }
                                                                            Err(e) => push_toast(format!("Failed to write config: {e}"), ToastLevel::Error),
                                                                        }
                                                                    },
                                                                    "▶ Start"
                                                                }
                                                                button {
                                                                    class: "btn btn-danger btn-sm",
                                                                    onclick: move |_| {
                                                                        CONFIG_PRESETS.write().remove(idx);
                                                                    },
                                                                    "✕"
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            div { class: "modal-footer",
                                button {
                                    class: "btn btn-secondary",
                                    onclick: move |_| on_close.call(()),
                                    "Cancel"
                                }
                            }
                        }
                    },

                    // ── Current Config tab ────────────────────────────────
                    4 if has_config => rsx! {
                        div {
                            div { style: "font-size:13px;color:var(--text-muted);margin-bottom:8px;",
                                "Start the router using the currently loaded configuration."
                            }
                            div {
                                style: "background:var(--bg);border:1px solid var(--border-subtle);border-radius:4px;padding:8px 10px;font-family:monospace;font-size:11px;color:var(--text-muted);max-height:120px;overflow-y:auto;margin-bottom:12px;",
                                "{toml_preview}"
                            }
                            div { style: "font-size:11px;color:var(--yellow);margin-bottom:12px;",
                                "⚠ The current config will be written to a temporary file and passed via --config."
                            }
                            // Save as preset
                            div { style: "display:flex;gap:6px;margin-bottom:12px;align-items:flex-end;",
                                div { class: "form-group", style: "flex:1;",
                                    label { "Save as Preset" }
                                    input {
                                        r#type: "text",
                                        placeholder: "Preset name…",
                                        value: "{preset_name}",
                                        style: "width:100%;",
                                        oninput: move |e| preset_name.set(e.value()),
                                    }
                                }
                                button {
                                    class: "btn btn-secondary btn-sm",
                                    style: "align-self:flex-end;",
                                    disabled: preset_name.read().trim().is_empty(),
                                    onclick: move |_| {
                                        let name = preset_name.read().trim().to_string();
                                        if !name.is_empty() {
                                            let toml = config_toml.read().clone();
                                            CONFIG_PRESETS.write().push((name, toml));
                                            preset_name.set(String::new());
                                            push_toast("Preset saved", ToastLevel::Success);
                                        }
                                    },
                                    "Save"
                                }
                            }
                            div { class: "modal-footer",
                                button {
                                    class: "btn btn-secondary",
                                    onclick: move |_| on_close.call(()),
                                    "Cancel"
                                }
                                button {
                                    class: "btn btn-primary",
                                    onclick: move |_| {
                                        let toml = config_toml.read().clone();
                                        match crate::router_proc::write_temp_config(&toml) {
                                            Ok(path) => {
                                                ctx.router_cmd.send(RouterCmd::Start(Some(path.to_string_lossy().to_string())));
                                                on_close.call(());
                                            }
                                            Err(e) => push_toast(format!("Failed to write config: {e}"), ToastLevel::Error),
                                        }
                                    },
                                    "▶ Start with Config"
                                }
                            }
                        }
                    },

                    // ── Quick Start tab (default) ─────────────────────────
                    _ => rsx! {
                        div {
                            div { style: "font-size:13px;color:var(--text-muted);margin-bottom:16px;line-height:1.6;",
                                "Start the router with built-in defaults. You can adjust settings after startup using the dashboard controls."
                            }
                            div { style: "background:var(--bg);border:1px solid var(--border-subtle);border-radius:6px;padding:12px;margin-bottom:16px;",
                                div { style: "font-size:11px;color:var(--text-muted);margin-bottom:6px;text-transform:uppercase;letter-spacing:.5px;", "Defaults include" }
                                div { style: "font-size:12px;color:var(--text);line-height:1.8;",
                                    "• Content store: 64 MB LRU" br{}
                                    "• Best-route forwarding strategy" br{}
                                    "• Management socket: /tmp/ndn.sock" br{}
                                    "• Log level: INFO"
                                }
                            }
                            div { class: "modal-footer",
                                button {
                                    class: "btn btn-secondary",
                                    onclick: move |_| on_close.call(()),
                                    "Cancel"
                                }
                                button {
                                    class: "btn btn-primary",
                                    onclick: move |_| {
                                        ctx.router_cmd.send(RouterCmd::Start(None));
                                        on_close.call(());
                                    },
                                    "▶ Start with Defaults"
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

// ── FaceCreateModal ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
enum FaceKind {
    Udp,
    Tcp,
    WebSocket,
    Ethernet,
}

impl FaceKind {
    fn label(self) -> &'static str {
        match self {
            FaceKind::Udp       => "UDP",
            FaceKind::Tcp       => "TCP",
            FaceKind::WebSocket => "WebSocket",
            FaceKind::Ethernet  => "Ethernet",
        }
    }
    fn placeholder_host(self) -> &'static str {
        match self {
            FaceKind::Udp | FaceKind::Tcp | FaceKind::WebSocket => "192.168.1.1",
            FaceKind::Ethernet => "eth0",
        }
    }
    fn default_port(self) -> &'static str {
        match self {
            FaceKind::Udp | FaceKind::Tcp => "6363",
            FaceKind::WebSocket           => "9696",
            FaceKind::Ethernet            => "",
        }
    }
    fn has_port(self) -> bool {
        matches!(self, FaceKind::Udp | FaceKind::Tcp | FaceKind::WebSocket)
    }
    fn build_uri(self, host: &str, port: &str, mac: &str) -> String {
        match self {
            FaceKind::Udp       => format!("udp4://{}:{}", host.trim(), port.trim()),
            FaceKind::Tcp       => format!("tcp4://{}:{}", host.trim(), port.trim()),
            FaceKind::WebSocket => format!("ws://{}:{}/", host.trim(), port.trim()),
            FaceKind::Ethernet  => {
                let mac = mac.trim();
                if mac.is_empty() {
                    format!("ether://{}", host.trim())
                } else {
                    format!("ether://{}/{}", host.trim(), mac)
                }
            }
        }
    }
}

#[component]
pub fn FaceCreateModal(on_close: EventHandler<()>) -> Element {
    let ctx = use_context::<AppCtx>();
    let mut advanced = use_signal(|| false);
    let mut face_kind = use_signal(|| FaceKind::Udp);
    let mut host = use_signal(String::new);
    let mut port = use_signal(|| "6363".to_string());
    let mut mac = use_signal(String::new);
    let mut raw_uri = use_signal(String::new);
    let mut validation_err: Signal<Option<String>> = use_signal(|| None);

    // Computed URI preview
    let uri_preview = {
        let k = *face_kind.read();
        let h = host.read().clone();
        let p = port.read().clone();
        let m = mac.read().clone();
        if h.is_empty() { String::new() } else { k.build_uri(&h, &p, &m) }
    };

    rsx! {
        div { class: "modal-overlay", onclick: move |_| on_close.call(()),
            div {
                class: "modal-card",
                style: "max-width:500px;",
                onclick: move |e| e.stop_propagation(),

                div { class: "modal-header",
                    span { class: "modal-title", "Add Face" }
                    button { class: "modal-close", onclick: move |_| on_close.call(()), "✕" }
                }

                // Mode toggle
                div { style: "display:flex;gap:8px;margin-bottom:16px;",
                    button {
                        class: if !*advanced.read() { "tab-pill active" } else { "tab-pill" },
                        onclick: move |_| advanced.set(false),
                        "Guided"
                    }
                    button {
                        class: if *advanced.read() { "tab-pill active" } else { "tab-pill" },
                        onclick: move |_| advanced.set(true),
                        "Advanced (Raw URI)"
                    }
                }

                if *advanced.read() {
                    div {
                        div { class: "form-group", style: "margin-bottom:12px;",
                            label { "Face URI" }
                            input {
                                r#type: "text",
                                placeholder: "udp4://192.168.1.1:6363",
                                value: "{raw_uri}",
                                style: "width:100%;",
                                oninput: move |e| raw_uri.set(e.value()),
                            }
                        }
                        div { style: "font-size:11px;color:var(--text-muted);margin-bottom:12px;",
                            "Supported schemes: udp4://, udp6://, tcp4://, tcp6://, ws://, unix://, shm://, ether://"
                        }
                    }
                } else {
                    div {
                        // Face templates
                        div { class: "face-templates",
                            button {
                                class: "face-tpl-btn",
                                onclick: move |_| {
                                    face_kind.set(FaceKind::Udp);
                                    host.set("suns.cs.ucla.edu".to_string());
                                    port.set("6363".to_string());
                                    validation_err.set(None);
                                },
                                "NDN Testbed"
                            }
                            button {
                                class: "face-tpl-btn",
                                onclick: move |_| {
                                    face_kind.set(FaceKind::Udp);
                                    host.set("127.0.0.1".to_string());
                                    port.set("6363".to_string());
                                    validation_err.set(None);
                                },
                                "Loopback"
                            }
                            button {
                                class: "face-tpl-btn",
                                onclick: move |_| {
                                    face_kind.set(FaceKind::Udp);
                                    host.set("224.0.23.170".to_string());
                                    port.set("56363".to_string());
                                    validation_err.set(None);
                                },
                                "UDP Multicast"
                            }
                        }

                        // Face type grid
                        div { class: "face-type-grid",
                            for kind in [FaceKind::Udp, FaceKind::Tcp, FaceKind::WebSocket, FaceKind::Ethernet] {
                                {
                                    let is_sel = *face_kind.read() == kind;
                                    rsx! {
                                        button {
                                            class: if is_sel { "face-type-btn selected" } else { "face-type-btn" },
                                            onclick: move |_| {
                                                face_kind.set(kind);
                                                host.set(String::new());
                                                port.set(kind.default_port().to_string());
                                                mac.set(String::new());
                                                validation_err.set(None);
                                            },
                                            "{kind.label()}"
                                        }
                                    }
                                }
                            }
                        }

                        // Host/path field
                        div { class: "form-group", style: "margin-bottom:10px;",
                            label {
                                {
                                    match *face_kind.read() {
                                        FaceKind::Ethernet => "Network Interface",
                                        _                  => "Host / IP Address",
                                    }
                                }
                            }
                            input {
                                r#type: "text",
                                placeholder: "{face_kind.read().placeholder_host()}",
                                value: "{host}",
                                style: "width:100%;",
                                oninput: move |e| host.set(e.value()),
                            }
                        }

                        // Port field (UDP/TCP/WS only)
                        if face_kind.read().has_port() {
                            div { class: "form-group", style: "margin-bottom:10px;",
                                label { "Port" }
                                input {
                                    r#type: "number",
                                    value: "{port}",
                                    style: "width:120px;",
                                    oninput: move |e| port.set(e.value()),
                                }
                            }
                        }

                        // MAC field (Ethernet only)
                        if *face_kind.read() == FaceKind::Ethernet {
                            div { class: "form-group", style: "margin-bottom:10px;",
                                label { "Destination MAC (optional, leave blank for multicast)" }
                                input {
                                    r#type: "text",
                                    placeholder: "01:00:5e:00:17:aa",
                                    value: "{mac}",
                                    style: "width:100%;",
                                    oninput: move |e| mac.set(e.value()),
                                }
                            }
                        }

                        // URI preview
                        if !uri_preview.is_empty() {
                            div { style: "background:var(--bg);border:1px solid var(--border-subtle);border-radius:4px;padding:6px 10px;font-family:monospace;font-size:12px;color:var(--green);margin-bottom:10px;",
                                "URI: {uri_preview}"
                            }
                        }
                    }
                }

                // Validation error
                if let Some(ref err) = *validation_err.read() {
                    div { style: "color:var(--red);font-size:12px;margin-bottom:8px;", "{err}" }
                }

                div { class: "modal-footer",
                    button {
                        class: "btn btn-secondary",
                        onclick: move |_| on_close.call(()),
                        "Cancel"
                    }
                    button {
                        class: "btn btn-primary",
                        onclick: move |_| {
                            let uri = if *advanced.read() {
                                raw_uri.read().trim().to_string()
                            } else {
                                let k = *face_kind.read();
                                let h = host.read().trim().to_string();
                                let p = port.read().trim().to_string();
                                let m = mac.read().trim().to_string();
                                if h.is_empty() {
                                    validation_err.set(Some("Host/path is required.".into()));
                                    return;
                                }
                                k.build_uri(&h, &p, &m)
                            };
                            if uri.is_empty() {
                                validation_err.set(Some("URI cannot be empty.".into()));
                                return;
                            }
                            ctx.cmd.send(DashCmd::FaceCreate(uri));
                            on_close.call(());
                        },
                        "Create Face"
                    }
                }
            }
        }
    }
}

// ── RouteAddModal ─────────────────────────────────────────────────────────────

#[component]
pub fn RouteAddModal(on_close: EventHandler<()>) -> Element {
    let ctx = use_context::<AppCtx>();
    let faces = ctx.faces.read();
    let mut prefix = use_signal(String::new);
    let mut face_id = use_signal(String::new);
    let mut cost = use_signal(|| 10u32);
    let mut validation_err: Signal<Option<String>> = use_signal(|| None);

    // Autocomplete suggestions
    const COMMON_PREFIXES: &[&str] = &[
        "/ndn", "/localhop", "/localhost", "/localhop/nfd", "/localhop/ndnd",
    ];

    rsx! {
        div { class: "modal-overlay", onclick: move |_| on_close.call(()),
            div {
                class: "modal-card",
                style: "max-width:420px;",
                onclick: move |e| e.stop_propagation(),

                div { class: "modal-header",
                    span { class: "modal-title", "Add Route" }
                    button { class: "modal-close", onclick: move |_| on_close.call(()), "✕" }
                }

                // Prefix with autocomplete
                div { class: "form-group autocomplete-wrap", style: "margin-bottom:12px;",
                    label { "Name Prefix" }
                    input {
                        r#type: "text",
                        placeholder: "/ndn",
                        value: "{prefix}",
                        style: "width:100%;",
                        oninput: move |e| {
                            let mut v = e.value();
                            if !v.is_empty() && !v.starts_with('/') {
                                v = format!("/{}", v);
                            }
                            prefix.set(v);
                        },
                    }
                    {
                        let current = prefix.read().clone();
                        if !current.is_empty() {
                            let lower = current.to_lowercase();
                            let route_prefixes: Vec<String> = ctx.routes.read()
                                .iter()
                                .map(|r| r.prefix.clone())
                                .collect();
                            let suggestions: Vec<String> = COMMON_PREFIXES.iter()
                                .map(|s| s.to_string())
                                .chain(route_prefixes)
                                .filter(|s| s.to_lowercase().starts_with(&lower) && *s != current)
                                .collect::<std::collections::BTreeSet<_>>()
                                .into_iter()
                                .take(6)
                                .collect();
                            if !suggestions.is_empty() {
                                rsx! {
                                    div { class: "autocomplete-list",
                                        for sug in suggestions {
                                            {
                                                let sug2 = sug.clone();
                                                rsx! {
                                                    div {
                                                        class: "autocomplete-item",
                                                        onclick: move |_| prefix.set(sug2.clone()),
                                                        "{sug}"
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            } else {
                                rsx! {}
                            }
                        } else {
                            rsx! {}
                        }
                    }
                }

                // Face selector
                div { class: "form-group", style: "margin-bottom:12px;",
                    label { "Face" }
                    if faces.is_empty() {
                        div { style: "font-size:12px;color:var(--text-muted);", "No faces available. Create a face first." }
                    } else {
                        select {
                            style: "width:100%;",
                            value: "{face_id}",
                            oninput: move |e| face_id.set(e.value()),
                            option { value: "", "— Select face —" }
                            for f in faces.iter() {
                                {
                                    let label = format!(
                                        "Face {} — {} {}",
                                        f.face_id,
                                        f.kind_label(),
                                        f.remote_uri.as_deref().unwrap_or("")
                                    );
                                    let id_str = f.face_id.to_string();
                                    rsx! {
                                        option { value: "{id_str}", "{label}" }
                                    }
                                }
                            }
                        }
                    }
                }

                // Cost slider
                div { class: "form-group", style: "margin-bottom:16px;",
                    div { style: "display:flex;justify-content:space-between;margin-bottom:4px;",
                        label { "Cost" }
                        span { style: "font-size:12px;color:var(--accent);font-family:monospace;", "{cost}" }
                    }
                    input {
                        r#type: "range",
                        min: "0", max: "100",
                        value: "{cost}",
                        style: "width:100%;",
                        oninput: move |e| {
                            if let Ok(v) = e.value().parse::<u32>() {
                                cost.set(v);
                            }
                        },
                    }
                }

                if let Some(ref err) = *validation_err.read() {
                    div { style: "color:var(--red);font-size:12px;margin-bottom:8px;", "{err}" }
                }

                div { class: "modal-footer",
                    button {
                        class: "btn btn-secondary",
                        onclick: move |_| on_close.call(()),
                        "Cancel"
                    }
                    button {
                        class: "btn btn-primary",
                        onclick: move |_| {
                            let p = prefix.read().trim().to_string();
                            let fid_str = face_id.read().trim().to_string();
                            if p.is_empty() {
                                validation_err.set(Some("Name prefix is required.".into()));
                                return;
                            }
                            if fid_str.is_empty() {
                                validation_err.set(Some("Please select a face.".into()));
                                return;
                            }
                            if let Ok(fid) = fid_str.parse::<u64>() {
                                ctx.cmd.send(DashCmd::RouteAdd {
                                    prefix: p,
                                    face_id: fid,
                                    cost: *cost.read() as u64,
                                });
                                on_close.call(());
                            } else {
                                validation_err.set(Some("Invalid face ID.".into()));
                            }
                        },
                        "Add Route"
                    }
                }
            }
        }
    }
}
