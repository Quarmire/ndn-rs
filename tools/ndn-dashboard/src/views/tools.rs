//! Tools view — multi-instance NDN diagnostic tools with shared results table.

use std::collections::HashSet;

use dioxus::prelude::*;
use ndn_tools_core::common::EventLevel;

use crate::app::{AppCtx, ACTIVE_VIEW};
use crate::tool_runner::{
    ToolCmd, ToolParams, ToolTab,
    TOOL_INSTANCES, TOOL_RESULTS,
    TOOLS_ACTIVE_TAB, PING_IDS, IPERF_IDS, PEEK_IDS, PUT_IDS,
    next_tool_instance_id, fmt_bps, fmt_bytes_short,
};

// ─── Root component ──────────────────────────────────────────────────────────
// All navigation + panel-ID state lives in GlobalSignals (tool_runner.rs) so
// it persists across tab switches without losing running tool state.

#[component]
pub fn Tools() -> Element {
    rsx! {
        div { class: "section",
            div { class: "section-title", "Tools" }
            div { style: "font-size:13px;color:var(--text-muted);margin-bottom:16px;",
                "Diagnostic and measurement tools. Multiple instances can run simultaneously."
            }

            // ── Tab bar ────────────────────────────────────────────────────────
            div { style: "display:flex;align-items:center;gap:0;margin-bottom:20px;border-bottom:1px solid var(--border);",
                for (tab, label) in [
                    (ToolTab::Ping,  "Ping"),
                    (ToolTab::Iperf, "Iperf"),
                    (ToolTab::Peek,  "Peek"),
                    (ToolTab::Put,   "Put"),
                ] {
                    button {
                        style: if *TOOLS_ACTIVE_TAB.read() == tab {
                            "background:none;border:none;color:var(--accent);font-size:13px;padding:6px 18px;cursor:pointer;border-bottom:2px solid var(--accent);margin-bottom:-1px;"
                        } else {
                            "background:none;border:none;color:var(--text-muted);font-size:13px;padding:6px 18px;cursor:pointer;border-bottom:2px solid transparent;margin-bottom:-1px;"
                        },
                        onclick: move |_| *TOOLS_ACTIVE_TAB.write() = tab,
                        "{label}"
                    }
                }
                div { style: "flex:1;" }
                button {
                    style: "background:none;border:1px solid var(--border);color:var(--text-muted);font-size:11px;padding:4px 10px;border-radius:6px;cursor:pointer;margin-bottom:4px;",
                    onclick: move |_| { *ACTIVE_VIEW.write() = crate::views::View::DashboardConfig; },
                    "\u{2699} Tool Server Settings"
                }
            }

            // ── Tab content ────────────────────────────────────────────────────
            match *TOOLS_ACTIVE_TAB.read() {
                ToolTab::Ping  => rsx! { PingTab {} },
                ToolTab::Iperf => rsx! { IperfTab {} },
                ToolTab::Peek  => rsx! { PeekTab {} },
                ToolTab::Put   => rsx! { PutTab {} },
            }

            // ── Shared results table (always visible) ──────────────────────────
            ResultsTable {}
        }
    }
}

// ─── Ping tab ────────────────────────────────────────────────────────────────

#[component]
fn PingTab() -> Element {
    rsx! {
        div { style: "margin-bottom:24px;",
            div { style: "display:flex;flex-wrap:wrap;gap:16px;margin-bottom:12px;",
                for id in PING_IDS.read().clone() {
                    PingCard { key: "{id}", panel_id: id }
                }
            }
            button {
                class: "btn btn-secondary",
                style: "font-size:12px;",
                onclick: move |_| PING_IDS.write().push(next_tool_instance_id()),
                "\u{ff0b} New Ping"
            }
        }
    }
}

#[component]
fn PingCard(panel_id: u32) -> Element {
    let ctx          = use_context::<AppCtx>();
    let mut prefix   = use_signal(|| "/ping".to_string());
    let mut count    = use_signal(|| "20".to_string());
    let mut interval = use_signal(|| "1000".to_string());
    let lifetime     = use_signal(|| "4000".to_string());

    let (running, current_rtt) = {
        let insts = TOOL_INSTANCES.read();
        let s = insts.get(&panel_id);
        (s.map(|x| x.running).unwrap_or(false),
         s.and_then(|x| x.current_rtt_us))
    };

    rsx! {
        div { style: "background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:14px;min-width:220px;flex:1;max-width:320px;",

            div { style: "display:flex;align-items:center;justify-content:space-between;margin-bottom:10px;",
                span { style: "font-size:11px;font-weight:600;color:var(--accent);letter-spacing:.5px;", "PING" }
                button {
                    class: "icon-btn",
                    style: "font-size:11px;padding:2px 6px;",
                    onclick: move |_| {
                        if running { ctx.tool_cmd.send(ToolCmd::Stop { id: panel_id }); }
                        PING_IDS.write().retain(|&x| x != panel_id);
                        TOOL_INSTANCES.write().remove(&panel_id);
                    },
                    "\u{2715}"
                }
            }

            if running {
                div { style: "text-align:center;margin-bottom:12px;padding:10px 0;background:var(--green-bg);border-radius:6px;",
                    div { style: "font-size:10px;color:var(--text-muted);margin-bottom:4px;letter-spacing:.5px;", "LATENCY" }
                    div { style: "font-size:36px;font-weight:700;color:var(--green);line-height:1;",
                        if let Some(rtt) = current_rtt { "{rtt / 1000} ms" } else { "\u{2026}" }
                    }
                    if let Some(rtt) = current_rtt {
                        div { style: "font-size:10px;color:var(--text-faint);margin-top:2px;", "{rtt} \u{b5}s" }
                    }
                }
            }

            if !running {
                div { class: "form-group", style: "margin-bottom:8px;",
                    label { "Prefix" }
                    input {
                        r#type: "text", value: "{prefix}", placeholder: "/ping",
                        oninput: move |e| prefix.set(e.value()),
                    }
                }
                // min-width:0 on grid children prevents inputs from overflowing the card
                div { style: "display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:8px;",
                    div { class: "form-group", style: "min-width:0;",
                        label { "Count (0=\u{221e})" }
                        input { r#type: "number", value: "{count}", min: "0",
                            oninput: move |e| count.set(e.value()) }
                    }
                    div { class: "form-group", style: "min-width:0;",
                        label { "Interval (ms)" }
                        input { r#type: "number", value: "{interval}", min: "100",
                            oninput: move |e| interval.set(e.value()) }
                    }
                }
            }

            button {
                class: if running { "btn btn-danger" } else { "btn btn-primary" },
                style: "width:100%;margin-top:4px;",
                onclick: move |_| {
                    if running {
                        ctx.tool_cmd.send(ToolCmd::Stop { id: panel_id });
                    } else {
                        ctx.tool_cmd.send(ToolCmd::Run {
                            id: panel_id,
                            params: ToolParams::PingClient {
                                prefix:      prefix.read().clone(),
                                count:       count.read().parse().unwrap_or(20),
                                interval_ms: interval.read().parse().unwrap_or(1000),
                                lifetime_ms: lifetime.read().parse().unwrap_or(4000),
                            },
                        });
                    }
                },
                if running { "\u{25a0} Stop" } else { "\u{25b6} Run" }
            }

            {
                let insts = TOOL_INSTANCES.read();
                let output: Vec<_> = insts.get(&panel_id)
                    .map(|s| s.output.iter().rev().take(4).collect())
                    .unwrap_or_default();
                if !output.is_empty() {
                    rsx! {
                        div { style: "margin-top:8px;background:var(--bg);border:1px solid var(--border-subtle);border-radius:4px;padding:6px 8px;font-family:monospace;font-size:11px;max-height:72px;overflow:hidden;",
                            for ev in output.into_iter().rev() {
                                div { style: match ev.level {
                                    EventLevel::Error   => "color:var(--red);",
                                    EventLevel::Warn    => "color:var(--yellow);",
                                    EventLevel::Summary => "color:var(--accent);",
                                    EventLevel::Info    => "color:var(--text-muted);",
                                }, "{ev.text}" }
                            }
                        }
                    }
                } else { rsx! {} }
            }
        }
    }
}

// ─── Iperf tab ────────────────────────────────────────────────────────────────

#[component]
fn IperfTab() -> Element {
    rsx! {
        div { style: "margin-bottom:24px;",
            div { style: "display:flex;flex-wrap:wrap;gap:16px;margin-bottom:12px;",
                for id in IPERF_IDS.read().clone() {
                    IperfCard { key: "{id}", panel_id: id }
                }
            }
            button {
                class: "btn btn-secondary",
                style: "font-size:12px;",
                onclick: move |_| IPERF_IDS.write().push(next_tool_instance_id()),
                "\u{ff0b} New Iperf"
            }
        }
    }
}

#[component]
fn IperfCard(panel_id: u32) -> Element {
    let ctx           = use_context::<AppCtx>();
    let mut prefix    = use_signal(|| "/iperf".to_string());
    let mut duration  = use_signal(|| "10".to_string());
    let mut window    = use_signal(|| "64".to_string());
    let mut cc        = use_signal(|| "aimd".to_string());
    let mut reverse   = use_signal(|| false);
    let mut sign_mode = use_signal(|| "none".to_string());
    let mut face_type = use_signal(|| "shm".to_string());

    let (server_prefix, node_prefix_set) = {
        let s = crate::settings::DASH_SETTINGS.read();
        let pfx = if s.iperf_use_custom_name && !s.iperf_custom_name.is_empty() {
            s.iperf_custom_name.clone()
        } else if !s.node_prefix.is_empty() {
            format!("{}{}", s.node_prefix.trim_end_matches('/'), s.iperf_prefix)
        } else {
            s.iperf_prefix.clone()
        };
        (pfx, !s.node_prefix.is_empty())
    };
    // Destructure so closures can capture each independently.
    let (server_prefix, node_prefix_set) = (server_prefix, node_prefix_set);

    let (running, tp_data, elapsed) = {
        let insts = TOOL_INSTANCES.read();
        let s = insts.get(&panel_id);
        (
            s.map(|x| x.running).unwrap_or(false),
            s.map(|x| x.tp_history.clone()).unwrap_or_default(),
            s.map(|x| x.elapsed_secs).unwrap_or(0.0),
        )
    };

    let cur_tp = tp_data.last().copied().unwrap_or(0.0);

    rsx! {
        div { style: "background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:14px;min-width:300px;flex:1;max-width:420px;",

            div { style: "display:flex;align-items:center;justify-content:space-between;margin-bottom:10px;",
                span { style: "font-size:11px;font-weight:600;color:var(--accent);letter-spacing:.5px;", "IPERF" }
                button {
                    class: "icon-btn",
                    style: "font-size:11px;padding:2px 6px;",
                    onclick: move |_| {
                        if running { ctx.tool_cmd.send(ToolCmd::Stop { id: panel_id }); }
                        IPERF_IDS.write().retain(|&x| x != panel_id);
                        TOOL_INSTANCES.write().remove(&panel_id);
                    },
                    "\u{2715}"
                }
            }

            // Live throughput plot (Catmull-Rom smooth bezier)
            {
                let data = tp_data.clone();
                let max = data.iter().cloned().fold(0.0f64, f64::max).max(1.0);
                let n   = data.len();
                let pts_xy: Vec<(f64, f64)> = data.iter().enumerate().map(|(i, &v)| {
                    let x = if n > 1 { i as f64 / (n - 1) as f64 * 360.0 } else { 0.0 };
                    let y = 53.0 - (v / max) * 50.0;
                    (x, y)
                }).collect();
                let smooth_path = if pts_xy.len() >= 2 {
                    let mut d = format!("M{:.1},{:.1}", pts_xy[0].0, pts_xy[0].1);
                    for i in 1..pts_xy.len() {
                        let p0 = if i >= 2 { pts_xy[i - 2] } else { pts_xy[0] };
                        let p1 = pts_xy[i - 1];
                        let p2 = pts_xy[i];
                        let p3 = if i + 1 < pts_xy.len() { pts_xy[i + 1] } else { pts_xy[i] };
                        let cp1x = p1.0 + (p2.0 - p0.0) / 6.0;
                        let cp1y = p1.1 + (p2.1 - p0.1) / 6.0;
                        let cp2x = p2.0 - (p3.0 - p1.0) / 6.0;
                        let cp2y = p2.1 - (p3.1 - p1.1) / 6.0;
                        d.push_str(&format!(" C{:.1},{:.1} {:.1},{:.1} {:.1},{:.1}", cp1x, cp1y, cp2x, cp2y, p2.0, p2.1));
                    }
                    d
                } else { String::new() };
                let tp_label = if running || !tp_data.is_empty() { fmt_bps(cur_tp) } else { "\u{2014}".to_string() };
                rsx! {
                    div { style: "margin-bottom:10px;",
                        div { style: "display:flex;align-items:baseline;justify-content:space-between;margin-bottom:4px;",
                            span { style: "font-size:10px;color:var(--text-muted);letter-spacing:.5px;", "THROUGHPUT" }
                            span { style: "font-size:16px;font-weight:700;color:var(--green);", "{tp_label}" }
                            if running { span { style: "font-size:10px;color:var(--text-faint);", "{elapsed:.1}s" } }
                        }
                        svg {
                            width: "100%", height: "56", view_box: "0 0 360 56", preserve_aspect_ratio: "none",
                            rect { x: "0", y: "0", width: "360", height: "56", fill: "var(--green-bg)", rx: "4" }
                            if running && n == 0 {
                                text { x: "180", y: "32", text_anchor: "middle", font_size: "10", fill: "var(--text-faint)", "Waiting for data\u{2026}" }
                            }
                            if n >= 2 {
                                path { d: "{smooth_path}", fill: "none", stroke: "var(--green)", stroke_width: "1.5", stroke_linejoin: "round", stroke_linecap: "round" }
                            }
                        }
                    }
                }
            }

            // Prefix row with self-test button
            div { class: "form-group", style: "margin-bottom:8px;",
                label { "Prefix" }
                div { style: "display:flex;gap:4px;",
                    input {
                        r#type: "text", value: "{prefix}", placeholder: "/iperf",
                        disabled: running, style: "flex:1;",
                        oninput: move |e| prefix.set(e.value()),
                    }
                    button {
                        class: "btn btn-secondary",
                        style: "font-size:11px;padding:4px 8px;white-space:nowrap;",
                        disabled: running,
                        title: "Self-test: run iperf against the local server prefix",
                        onclick: move |_| {
                            prefix.set(server_prefix.clone());
                            ctx.tool_cmd.send(ToolCmd::Run {
                                id: panel_id,
                                params: ToolParams::IperfClient {
                                    prefix:        server_prefix.clone(),
                                    duration_secs: duration.read().parse().unwrap_or(10),
                                    window:        window.read().parse().unwrap_or(64),
                                    cc:            cc.read().clone(),
                                    reverse:       *reverse.read(),
                                    sign_mode:     sign_mode.read().clone(),
                                    face_type:     face_type.read().clone(),
                                },
                            });
                        },
                        "Self-test"
                    }
                }
            }

            if !running {
                div { style: "display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:8px;",
                    div { class: "form-group", style: "min-width:0;",
                        label { "Duration (s)" }
                        input { r#type: "number", value: "{duration}", min: "1",
                            oninput: move |e| duration.set(e.value()) }
                    }
                    div { class: "form-group", style: "min-width:0;",
                        label { "Window" }
                        input { r#type: "number", value: "{window}", min: "1",
                            oninput: move |e| window.set(e.value()) }
                    }
                }
                div { style: "display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:8px;",
                    div { class: "form-group", style: "min-width:0;",
                        label { "CC algorithm" }
                        select {
                            oninput: move |e| cc.set(e.value()),
                            option { value: "aimd",  selected: *cc.read() == "aimd",  "AIMD" }
                            option { value: "cubic", selected: *cc.read() == "cubic", "CUBIC" }
                            option { value: "fixed", selected: *cc.read() == "fixed", "Fixed" }
                        }
                    }
                    div { class: "form-group", style: "min-width:0;",
                        label { "Face type" }
                        select {
                            oninput: move |e| face_type.set(e.value()),
                            option { value: "shm",  selected: *face_type.read() == "shm",  "Shared memory (SHM)" }
                            option { value: "unix", selected: *face_type.read() == "unix", "Unix socket" }
                        }
                    }
                }
                div { style: "margin-bottom:10px;",
                    div { style: "font-size:11px;color:var(--text-muted);margin-bottom:6px;", "AUTH MODE" }
                    div { style: "display:flex;gap:14px;",
                        for (val, lbl) in [("none", "None"), ("hmac", "HMAC"), ("ed25519", "Ed25519")] {
                            label { style: "display:flex;align-items:center;gap:5px;font-size:12px;cursor:pointer;",
                                input {
                                    r#type: "radio",
                                    name: "iperf-auth-{panel_id}",
                                    value: val,
                                    checked: *sign_mode.read() == val,
                                    onchange: move |_| sign_mode.set(val.to_string()),
                                }
                                "{lbl}"
                            }
                        }
                    }
                }
                label { style: "display:flex;align-items:center;gap:6px;font-size:12px;cursor:pointer;margin-bottom:4px;",
                    input {
                        r#type: "checkbox",
                        checked: *reverse.read(),
                        onchange: move |e| reverse.set(e.checked()),
                    }
                    "Reverse (server fetches from client)"
                }
                if *reverse.read() && !node_prefix_set {
                    div { style: "font-size:11px;color:var(--yellow);margin-bottom:8px;padding:4px 8px;background:var(--yellow-bg);border:1px solid var(--yellow-bg);border-radius:4px;",
                        "\u{26a0} Reverse mode requires a Node prefix — set it in Dashboard Settings."
                    }
                }
            }

            button {
                class: if running { "btn btn-danger" } else { "btn btn-primary" },
                style: "width:100%;margin-top:4px;",
                disabled: !running && *reverse.read() && !node_prefix_set,
                onclick: move |_| {
                    if running {
                        ctx.tool_cmd.send(ToolCmd::Stop { id: panel_id });
                    } else {
                        ctx.tool_cmd.send(ToolCmd::Run {
                            id: panel_id,
                            params: ToolParams::IperfClient {
                                prefix:        prefix.read().clone(),
                                duration_secs: duration.read().parse().unwrap_or(10),
                                window:        window.read().parse().unwrap_or(64),
                                cc:            cc.read().clone(),
                                reverse:       *reverse.read(),
                                sign_mode:     sign_mode.read().clone(),
                                face_type:     face_type.read().clone(),
                            },
                        });
                    }
                },
                if running { "\u{25a0} Stop" } else { "\u{25b6} Run" }
            }

            {
                let insts = TOOL_INSTANCES.read();
                let output: Vec<_> = insts.get(&panel_id)
                    .map(|s| s.output.iter().rev().take(3).collect())
                    .unwrap_or_default();
                if !output.is_empty() {
                    rsx! {
                        div { style: "margin-top:8px;background:var(--bg);border:1px solid var(--border-subtle);border-radius:4px;padding:6px 8px;font-family:monospace;font-size:11px;max-height:60px;overflow:hidden;",
                            for ev in output.into_iter().rev() {
                                div { style: match ev.level {
                                    EventLevel::Error   => "color:var(--red);",
                                    EventLevel::Warn    => "color:var(--yellow);",
                                    EventLevel::Summary => "color:var(--accent);",
                                    EventLevel::Info    => "color:var(--text-muted);",
                                }, "{ev.text}" }
                            }
                        }
                    }
                } else { rsx! {} }
            }
        }
    }
}

// ─── Peek tab ────────────────────────────────────────────────────────────────

#[component]
fn PeekTab() -> Element {
    rsx! {
        div { style: "margin-bottom:24px;",
            div { style: "display:flex;flex-wrap:wrap;gap:16px;margin-bottom:12px;",
                for id in PEEK_IDS.read().clone() {
                    PeekCard { key: "{id}", panel_id: id }
                }
            }
            button {
                class: "btn btn-secondary",
                style: "font-size:12px;",
                onclick: move |_| PEEK_IDS.write().push(next_tool_instance_id()),
                "\u{ff0b} New Peek"
            }
        }
    }
}

#[component]
fn PeekCard(panel_id: u32) -> Element {
    let ctx          = use_context::<AppCtx>();
    let mut name     = use_signal(|| String::new());
    let mut out_file = use_signal(|| String::new());
    let mut pipeline = use_signal(|| String::new());

    let running = TOOL_INSTANCES.read().get(&panel_id).map(|s| s.running).unwrap_or(false);

    rsx! {
        div { style: "background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:14px;min-width:260px;flex:1;max-width:380px;",

            div { style: "display:flex;align-items:center;justify-content:space-between;margin-bottom:10px;",
                span { style: "font-size:11px;font-weight:600;color:var(--accent);letter-spacing:.5px;", "PEEK" }
                button {
                    class: "icon-btn",
                    style: "font-size:11px;padding:2px 6px;",
                    onclick: move |_| {
                        if running { ctx.tool_cmd.send(ToolCmd::Stop { id: panel_id }); }
                        PEEK_IDS.write().retain(|&x| x != panel_id);
                        TOOL_INSTANCES.write().remove(&panel_id);
                    },
                    "\u{2715}"
                }
            }

            div { class: "form-group", style: "margin-bottom:8px;",
                label { "NDN name" }
                input {
                    r#type: "text", value: "{name}", placeholder: "/example/data",
                    disabled: running, oninput: move |e| name.set(e.value()),
                }
            }
            div { class: "form-group", style: "margin-bottom:8px;",
                label { "Save to file (optional)" }
                input {
                    r#type: "text", value: "{out_file}", placeholder: "/path/to/output.bin",
                    disabled: running, oninput: move |e| out_file.set(e.value()),
                }
            }
            div { class: "form-group", style: "margin-bottom:10px;",
                label { "Pipeline size (optional)" }
                input {
                    r#type: "number", value: "{pipeline}", placeholder: "1", min: "1",
                    disabled: running, oninput: move |e| pipeline.set(e.value()),
                }
            }

            button {
                class: if running { "btn btn-danger" } else { "btn btn-primary" },
                style: "width:100%;",
                disabled: name.read().is_empty() && !running,
                onclick: move |_| {
                    if running {
                        ctx.tool_cmd.send(ToolCmd::Stop { id: panel_id });
                    } else {
                        let of = out_file.read().clone();
                        ctx.tool_cmd.send(ToolCmd::Run {
                            id: panel_id,
                            params: ToolParams::PeekClient {
                                name:        name.read().clone(),
                                output_file: if of.is_empty() { None } else { Some(of) },
                                pipeline:    pipeline.read().parse().ok(),
                            },
                        });
                    }
                },
                if running { "\u{25a0} Stop" } else { "\u{25b6} Peek" }
            }

            {
                let insts = TOOL_INSTANCES.read();
                let output: Vec<_> = insts.get(&panel_id)
                    .map(|s| s.output.iter().rev().take(4).collect())
                    .unwrap_or_default();
                if !output.is_empty() {
                    rsx! {
                        div { style: "margin-top:8px;background:var(--bg);border:1px solid var(--border-subtle);border-radius:4px;padding:6px 8px;font-family:monospace;font-size:11px;max-height:80px;overflow:hidden;",
                            for ev in output.into_iter().rev() {
                                div { style: match ev.level {
                                    EventLevel::Error   => "color:var(--red);",
                                    EventLevel::Warn    => "color:var(--yellow);",
                                    EventLevel::Summary => "color:var(--accent);",
                                    EventLevel::Info    => "color:var(--text-muted);",
                                }, "{ev.text}" }
                            }
                        }
                    }
                } else { rsx! {} }
            }
        }
    }
}

// ─── Put tab ─────────────────────────────────────────────────────────────────

#[component]
fn PutTab() -> Element {
    rsx! {
        div { style: "margin-bottom:24px;",
            div { style: "display:flex;flex-wrap:wrap;gap:16px;margin-bottom:12px;",
                for id in PUT_IDS.read().clone() {
                    PutCard { key: "{id}", panel_id: id }
                }
            }
            button {
                class: "btn btn-secondary",
                style: "font-size:12px;",
                onclick: move |_| PUT_IDS.write().push(next_tool_instance_id()),
                "\u{ff0b} New Put"
            }
        }
    }
}

#[component]
fn PutCard(panel_id: u32) -> Element {
    let ctx            = use_context::<AppCtx>();
    let mut name       = use_signal(|| String::new());
    let mut text_data  = use_signal(|| String::new());
    let mut file_path  = use_signal(|| String::new());
    let mut use_file   = use_signal(|| false);
    let mut sign       = use_signal(|| false);
    let mut freshness  = use_signal(|| "0".to_string());

    let running = TOOL_INSTANCES.read().get(&panel_id).map(|s| s.running).unwrap_or(false);

    rsx! {
        div { style: "background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:14px;min-width:280px;flex:1;max-width:420px;",

            div { style: "display:flex;align-items:center;justify-content:space-between;margin-bottom:10px;",
                span { style: "font-size:11px;font-weight:600;color:var(--accent);letter-spacing:.5px;", "PUT" }
                button {
                    class: "icon-btn",
                    style: "font-size:11px;padding:2px 6px;",
                    onclick: move |_| {
                        if running { ctx.tool_cmd.send(ToolCmd::Stop { id: panel_id }); }
                        PUT_IDS.write().retain(|&x| x != panel_id);
                        TOOL_INSTANCES.write().remove(&panel_id);
                    },
                    "\u{2715}"
                }
            }

            div { class: "form-group", style: "margin-bottom:8px;",
                label { "NDN name" }
                input {
                    r#type: "text", value: "{name}", placeholder: "/example/data",
                    disabled: running, oninput: move |e| name.set(e.value()),
                }
            }

            div { style: "display:flex;gap:0;margin-bottom:8px;",
                button {
                    style: if !*use_file.read() {
                        "flex:1;padding:4px;border:1px solid var(--accent);border-radius:4px 0 0 4px;background:var(--accent-dim);color:var(--accent);font-size:12px;cursor:pointer;"
                    } else {
                        "flex:1;padding:4px;border:1px solid var(--border);border-radius:4px 0 0 4px;background:transparent;color:var(--text-muted);font-size:12px;cursor:pointer;"
                    },
                    onclick: move |_| use_file.set(false),
                    "Text"
                }
                button {
                    style: if *use_file.read() {
                        "flex:1;padding:4px;border:1px solid var(--accent);border-radius:0 4px 4px 0;background:var(--accent-dim);color:var(--accent);font-size:12px;cursor:pointer;"
                    } else {
                        "flex:1;padding:4px;border:1px solid var(--border);border-radius:0 4px 4px 0;background:transparent;color:var(--text-muted);font-size:12px;cursor:pointer;"
                    },
                    onclick: move |_| use_file.set(true),
                    "File"
                }
            }

            if *use_file.read() {
                div { class: "form-group", style: "margin-bottom:8px;",
                    label { "File path" }
                    input {
                        r#type: "text", value: "{file_path}", placeholder: "/path/to/file.bin",
                        disabled: running, oninput: move |e| file_path.set(e.value()),
                    }
                }
            } else {
                div { class: "form-group", style: "margin-bottom:8px;",
                    label { "Text data" }
                    textarea {
                        style: "background:var(--bg);border:1px solid var(--border);color:var(--text);padding:6px 10px;border-radius:4px;font-size:12px;font-family:monospace;width:100%;min-height:80px;resize:vertical;",
                        disabled: running,
                        value: "{text_data}",
                        oninput: move |e| text_data.set(e.value()),
                    }
                }
            }

            div { style: "display:flex;align-items:center;gap:14px;margin-bottom:10px;",
                label { style: "display:flex;align-items:center;gap:6px;font-size:12px;cursor:pointer;",
                    input {
                        r#type: "checkbox",
                        checked: *sign.read(),
                        disabled: running,
                        onchange: move |e| sign.set(e.checked()),
                    }
                    "Sign (Ed25519)"
                }
                div { class: "form-group", style: "flex:1;",
                    label { "Freshness (ms)" }
                    input { r#type: "number", value: "{freshness}", min: "0",
                        disabled: running, oninput: move |e| freshness.set(e.value()) }
                }
            }

            button {
                class: if running { "btn btn-danger" } else { "btn btn-primary" },
                style: "width:100%;",
                disabled: name.read().is_empty() && !running,
                onclick: move |_| {
                    if running {
                        ctx.tool_cmd.send(ToolCmd::Stop { id: panel_id });
                    } else {
                        let data: Vec<u8> = if *use_file.read() {
                            let path = file_path.read().clone();
                            std::fs::read(&path).unwrap_or_else(|e| {
                                tracing::warn!("put: cannot read {path}: {e}");
                                Vec::new()
                            })
                        } else {
                            text_data.read().as_bytes().to_vec()
                        };
                        ctx.tool_cmd.send(ToolCmd::Run {
                            id: panel_id,
                            params: ToolParams::PutClient {
                                name:         name.read().clone(),
                                data,
                                sign:         *sign.read(),
                                freshness_ms: freshness.read().parse().unwrap_or(0),
                            },
                        });
                    }
                },
                if running { "\u{25a0} Stop" } else { "\u{25b6} Put" }
            }

            {
                let insts = TOOL_INSTANCES.read();
                let output: Vec<_> = insts.get(&panel_id)
                    .map(|s| s.output.iter().rev().take(4).collect())
                    .unwrap_or_default();
                if !output.is_empty() {
                    rsx! {
                        div { style: "margin-top:8px;background:var(--bg);border:1px solid var(--border-subtle);border-radius:4px;padding:6px 8px;font-family:monospace;font-size:11px;max-height:80px;overflow:hidden;",
                            for ev in output.into_iter().rev() {
                                div { style: match ev.level {
                                    EventLevel::Error   => "color:var(--red);",
                                    EventLevel::Warn    => "color:var(--yellow);",
                                    EventLevel::Summary => "color:var(--accent);",
                                    EventLevel::Info    => "color:var(--text-muted);",
                                }, "{ev.text}" }
                            }
                        }
                    }
                } else { rsx! {} }
            }
        }
    }
}

// ─── Results table ────────────────────────────────────────────────────────────

#[component]
fn ResultsTable() -> Element {
    let mut filter       = use_signal(|| "all".to_string());
    let mut max_show     = use_signal(|| crate::settings::DASH_SETTINGS.peek().results_max_entries);
    let mut select_mode  = use_signal(|| false);
    let mut selected:     Signal<HashSet<u64>> = use_signal(HashSet::new);

    let results = TOOL_RESULTS.read();
    let filtered: Vec<_> = results.iter()
        .filter(|r| *filter.read() == "all" || r.tool == *filter.read())
        .take(*max_show.read())
        .collect();

    let selected_count = selected.read().len();

    rsx! {
        div { style: "margin-top:24px;border-top:1px solid var(--border);padding-top:16px;",

            div { style: "display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:12px;",
                span { style: "font-size:12px;font-weight:600;color:var(--text);text-transform:uppercase;letter-spacing:.5px;", "Results" }
                span { style: "font-size:12px;color:var(--text-faint);", "({results.len()} total)" }

                select {
                    style: "font-size:12px;padding:2px 6px;",
                    oninput: move |e| filter.set(e.value()),
                    option { value: "all",          "All" }
                    option { value: "ping",         "Ping" }
                    option { value: "iperf",        "Iperf (client)" }
                    option { value: "iperf-server", "Iperf (server)" }
                    option { value: "peek",         "Peek" }
                    option { value: "put",          "Put" }
                }

                div { style: "display:flex;align-items:center;gap:4px;font-size:12px;color:var(--text-muted);",
                    "Show"
                    input {
                        r#type: "number", value: "{max_show}", min: "10", max: "500",
                        style: "width:56px;padding:2px 6px;font-size:12px;",
                        oninput: move |e| { if let Ok(v) = e.value().parse() { max_show.set(v); } },
                    }
                }

                div { style: "flex:1;" }

                button {
                    class: "btn btn-secondary btn-sm",
                    style: if *select_mode.read() { "border-color:var(--accent);color:var(--accent);" } else { "" },
                    onclick: move |_| { select_mode.toggle(); selected.write().clear(); },
                    if *select_mode.read() { "Cancel select" } else { "Select" }
                }

                if *select_mode.read() && selected_count > 0 {
                    span { style: "font-size:12px;color:var(--text-muted);", "{selected_count} selected" }
                    button {
                        class: "btn btn-secondary btn-sm",
                        onclick: move |_| {
                            let ids = selected.read().clone();
                            let entries: Vec<_> = TOOL_RESULTS.read().iter()
                                .filter(|r| ids.contains(&r.id))
                                .map(result_to_json)
                                .collect();
                            let json = serde_json::to_string_pretty(&entries).unwrap_or_default();
                            eprintln!("[results JSON]\n{json}");
                            crate::app::push_toast("JSON written to console", crate::app::ToastLevel::Info);
                        },
                        "\u{2b07} JSON"
                    }
                    button {
                        class: "btn btn-secondary btn-sm",
                        onclick: move |_| {
                            let ids = selected.read().clone();
                            let mut csv = "id,tool,ts,label,throughput_bps,rtt_avg_us,loss_pct,duration_secs,bytes\n".to_string();
                            for r in TOOL_RESULTS.read().iter().filter(|r| ids.contains(&r.id)) {
                                csv.push_str(&result_to_csv_row(r));
                            }
                            eprintln!("[results CSV]\n{csv}");
                            crate::app::push_toast("CSV written to console", crate::app::ToastLevel::Info);
                        },
                        "\u{2b07} CSV"
                    }
                }

                if !results.is_empty() {
                    button {
                        class: "btn btn-secondary btn-sm",
                        onclick: move |_| { TOOL_RESULTS.write().clear(); selected.write().clear(); },
                        "Clear all"
                    }
                }
            }

            if filtered.is_empty() {
                div { style: "color:var(--text-faint);font-size:13px;padding:20px 0;text-align:center;",
                    "No results yet \u{2014} run a tool to see results here."
                }
            }

            for entry in filtered {
                ResultRow {
                    key:            "{entry.id}",
                    entry_id:       entry.id,
                    tool:           entry.tool,
                    ts:             entry.ts.clone(),
                    label:          entry.label.clone(),
                    run_summary:    entry.run_summary.clone(),
                    throughput_bps: entry.throughput_bps,
                    rtt_avg_us:     entry.rtt_avg_us,
                    loss_pct:       entry.loss_pct,
                    duration_secs:  entry.duration_secs,
                    bytes:          entry.bytes,
                    intervals:      entry.intervals.clone(),
                    ping_rtts:      entry.ping_rtts.clone(),
                    summary_lines:  entry.summary_lines.clone(),
                    select_mode,
                    selected,
                }
            }
        }
    }
}

// ─── Result row ───────────────────────────────────────────────────────────────

#[component]
#[allow(clippy::too_many_arguments)]
fn ResultRow(
    entry_id:       u64,
    tool:           &'static str,
    ts:             String,
    label:          String,
    run_summary:    String,
    throughput_bps: Option<f64>,
    rtt_avg_us:     Option<u64>,
    loss_pct:       Option<f64>,
    duration_secs:  Option<f64>,
    bytes:          Option<u64>,
    intervals:      Vec<f64>,
    ping_rtts:      Vec<u64>,
    summary_lines:  Vec<String>,
    select_mode:    Signal<bool>,
    selected:       Signal<HashSet<u64>>,
) -> Element {
    let mut expanded = use_signal(|| false);
    let is_selected  = selected.read().contains(&entry_id);

    let tool_badge_style = match tool {
        "ping"         => "background:var(--accent-bg);color:var(--accent);",
        "iperf"        => "background:var(--green-bg);color:var(--green);",
        "iperf-server" => "background:var(--green-dark);color:var(--green);border:1px solid var(--green);",
        "peek"         => "background:var(--purple-bg);color:var(--purple);",
        "put"          => "background:var(--yellow-bg);color:var(--orange);",
        _              => "background:var(--border-subtle);color:var(--text-muted);",
    };

    rsx! {
        div {
            style: if is_selected {
                "border:1px solid var(--accent)44;border-radius:6px;margin-bottom:6px;overflow:hidden;background:var(--accent-solid)0a;"
            } else {
                "border:1px solid var(--border);border-radius:6px;margin-bottom:6px;overflow:hidden;"
            },

            div {
                style: "display:flex;align-items:center;padding:8px 10px;gap:10px;cursor:pointer;background:var(--surface);",

                if *select_mode.read() {
                    input {
                        r#type: "checkbox",
                        checked: is_selected,
                        onclick: move |e| e.stop_propagation(),
                        onchange: move |e| {
                            if e.checked() { selected.write().insert(entry_id); }
                            else { selected.write().remove(&entry_id); }
                        },
                    }
                }

                span {
                    style: "padding:2px 7px;border-radius:3px;font-size:10px;font-weight:600;{tool_badge_style}",
                    onclick: move |_| expanded.toggle(),
                    "{tool}"
                }

                span { style: "color:var(--text-faint);font-size:11px;flex-shrink:0;", onclick: move |_| expanded.toggle(), "{ts}" }

                // Label + run params subtitle
                div {
                    style: "overflow:hidden;flex:1;",
                    onclick: move |_| expanded.toggle(),
                    span {
                        style: "font-family:monospace;font-size:12px;color:var(--text-muted);display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;",
                        "{label}"
                    }
                    if !run_summary.is_empty() {
                        span { style: "font-size:10px;color:var(--text-faint);", "{run_summary}" }
                    }
                }

                div { style: "display:flex;gap:12px;flex-shrink:0;", onclick: move |_| expanded.toggle(),
                    if let Some(tp) = throughput_bps {
                        span { style: "font-size:12px;font-weight:600;color:var(--green);", "{fmt_bps(tp)}" }
                    }
                    if let Some(rtt) = rtt_avg_us {
                        span { style: "font-size:12px;color:var(--accent);", "{rtt / 1000} ms avg" }
                    }
                    if let Some(b) = bytes {
                        span { style: "font-size:12px;color:var(--text-muted);", "{fmt_bytes_short(b)}" }
                    }
                    if let Some(loss) = loss_pct {
                        span {
                            style: if loss > 1.0 { "font-size:12px;color:var(--red);" } else { "font-size:12px;color:var(--green);" },
                            "{loss:.1}% loss"
                        }
                    }
                }

                div { style: "display:flex;gap:4px;flex-shrink:0;",
                    button {
                        class: "icon-btn",
                        style: "font-size:11px;padding:3px 6px;",
                        title: "Copy to clipboard",
                        onclick: move |e| {
                            e.stop_propagation();
                            let text = format_result_text(entry_id);
                            let eval = document::eval(&format!(
                                "navigator.clipboard.writeText({:?}).catch(()=>{{}})",
                                text
                            ));
                            let _ = eval;
                            crate::app::push_toast("Copied to clipboard", crate::app::ToastLevel::Success);
                        },
                        "\u{1f4cb}"
                    }
                    button {
                        class: "icon-btn",
                        style: "font-size:11px;padding:3px 6px;",
                        title: "Download as JSON",
                        onclick: move |e| {
                            e.stop_propagation();
                            if let Some(r) = TOOL_RESULTS.read().iter().find(|r| r.id == entry_id) {
                                let json = serde_json::to_string_pretty(&result_to_json(r)).unwrap_or_default();
                                eprintln!("[result JSON id={entry_id}]\n{json}");
                                crate::app::push_toast("JSON written to console", crate::app::ToastLevel::Info);
                            }
                        },
                        "JSON"
                    }
                    button {
                        class: "icon-btn",
                        style: "font-size:11px;padding:3px 6px;",
                        onclick: move |_| expanded.toggle(),
                        if *expanded.read() { "\u{25b2}" } else { "\u{25bc}" }
                    }
                }
            }

            if *expanded.read() {
                div { style: "padding:12px 14px;background:var(--bg);",
                    div { style: "display:flex;gap:24px;",
                        div { style: "flex:1;",
                            for line in summary_lines.iter() {
                                div { style: "font-size:12px;color:var(--text);margin-bottom:3px;font-family:monospace;",
                                    "{line}"
                                }
                            }
                        }

                        if !intervals.is_empty() {
                            div { style: "flex-shrink:0;",
                                div { style: "font-size:10px;color:var(--text-muted);margin-bottom:4px;", "THROUGHPUT" }
                                {
                                    let data = &intervals;
                                    let max = data.iter().cloned().fold(0.0f64, f64::max).max(1.0);
                                    let n   = data.len();
                                    let pts: String = data.iter().enumerate().map(|(i, &v)| {
                                        let x = if n > 1 { i as f64 / (n - 1) as f64 * 120.0 } else { 0.0 };
                                        let y = 36.0 - (v / max) * 32.0 - 2.0;
                                        format!("{x:.1},{y:.1}")
                                    }).collect::<Vec<_>>().join(" ");
                                    rsx! {
                                        svg {
                                            width: "120", height: "38", view_box: "0 0 120 38",
                                            rect { x: "0", y: "0", width: "120", height: "38", fill: "var(--green-bg)", rx: "3" }
                                            if n > 1 {
                                                polyline {
                                                    points: "{pts}", fill: "none",
                                                    stroke: "var(--green)", stroke_width: "1.5",
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        if !ping_rtts.is_empty() {
                            div { style: "flex-shrink:0;",
                                div { style: "font-size:10px;color:var(--text-muted);margin-bottom:4px;", "RTT (ms)" }
                                {
                                    let data = &ping_rtts;
                                    let max_us = data.iter().copied().max().unwrap_or(1).max(1) as f64;
                                    let n   = data.len().min(30);
                                    let bar_w = 120.0 / n.max(1) as f64;
                                    let bars: Vec<(usize, u64)> = data.iter().rev().take(n)
                                        .enumerate()
                                        .map(|(i, &v)| (n.saturating_sub(1) - i, v))
                                        .collect();
                                    rsx! {
                                        svg {
                                            width: "120", height: "38", view_box: "0 0 120 38",
                                            rect { x: "0", y: "0", width: "120", height: "38", fill: "var(--bg)", rx: "3" }
                                            for (i, rtt) in bars {
                                                {
                                                    let bh = ((rtt as f64 / max_us) * 34.0).max(2.0);
                                                    let bx = i as f64 * bar_w;
                                                    let by = 38.0 - bh;
                                                    rsx! {
                                                        rect {
                                                            x: "{bx:.1}", y: "{by:.1}",
                                                            width: "{(bar_w - 1.0).max(1.0):.1}",
                                                            height: "{bh:.1}",
                                                            fill: "var(--accent)", rx: "1",
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
                }
            }
        }
    }
}

// ─── JSON / CSV helpers ───────────────────────────────────────────────────────

fn result_to_json(r: &crate::tool_runner::ToolResultEntry) -> serde_json::Value {
    serde_json::json!({
        "id":             r.id,
        "tool":           r.tool,
        "ts":             r.ts,
        "label":          r.label,
        "run_summary":    r.run_summary,
        "throughput_bps": r.throughput_bps,
        "rtt_avg_us":     r.rtt_avg_us,
        "loss_pct":       r.loss_pct,
        "duration_secs":  r.duration_secs,
        "bytes":          r.bytes,
        "summary":        r.summary_lines,
    })
}

fn result_to_csv_row(r: &crate::tool_runner::ToolResultEntry) -> String {
    format!(
        "{},{},{},{},{},{},{},{},{}\n",
        r.id, r.tool, r.ts, r.label,
        r.throughput_bps.map(|v| v.to_string()).unwrap_or_default(),
        r.rtt_avg_us.map(|v| v.to_string()).unwrap_or_default(),
        r.loss_pct.map(|v| format!("{v:.2}")).unwrap_or_default(),
        r.duration_secs.map(|v| format!("{v:.2}")).unwrap_or_default(),
        r.bytes.map(|v| v.to_string()).unwrap_or_default(),
    )
}

fn format_result_text(entry_id: u64) -> String {
    let results = TOOL_RESULTS.read();
    if let Some(r) = results.iter().find(|r| r.id == entry_id) {
        serde_json::to_string_pretty(&result_to_json(r)).unwrap_or_default()
    } else {
        String::new()
    }
}
