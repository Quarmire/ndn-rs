use std::collections::HashSet;
use std::collections::VecDeque;
use dioxus::prelude::*;
use crate::app::{AppCtx, DashCmd};
use crate::tool_runner::fmt_bytes;
use crate::types::ThroughputSample;
use crate::views::modals::{FaceCreateModal, RouteAddModal};
use crate::views::traffic::{render_throughput_bars, render_pps_bars, sum_face_histories};

const KNOWN_STRATEGIES: &[(&str, &str)] = &[
    ("/ndn/strategy/best-route/v5", "Best Route"),
    ("/ndn/strategy/multicast/v5",  "Multicast"),
    ("/ndn/strategy/ncc/v1",        "NCC"),
    ("/ndn/strategy/access/v1",     "Access"),
    ("/ndn/strategy/self-learning", "Self-Learning"),
];

// ── Main component ────────────────────────────────────────────────────────────

#[component]
pub fn Overview() -> Element {
    let ctx = use_context::<AppCtx>();

    // Expansion state
    let mut faces_open   = use_signal(|| false);
    let mut routes_open  = use_signal(|| false);
    let mut cs_open      = use_signal(|| false);
    let mut traffic_open = use_signal(|| false);

    // Modal state
    let mut show_face_modal  = use_signal(|| false);
    let mut show_route_modal = use_signal(|| false);

    // Per-face traffic filter (empty = show all)
    let mut monitored: Signal<HashSet<u64>> = use_signal(HashSet::new);

    // CS form state (kept here so it persists while expanded)
    let mut cs_cap_mb:    Signal<String> = use_signal(String::new);
    let mut cs_erase_pfx: Signal<String> = use_signal(String::new);

    // Education card
    let mut edu_dismissed = use_signal(|| false);

    // Derived data
    let status         = ctx.status.read();
    let faces          = ctx.faces.read();
    let routes         = ctx.routes.read();
    let cs             = ctx.cs.read();
    let counters       = ctx.counters.read();
    let measurements   = ctx.measurements.read();
    let throughput     = ctx.throughput.read();
    let strategies     = ctx.strategies.read();
    let cs_hit_history    = ctx.cs_hit_history.read();
    let face_throughput   = ctx.face_throughput.read();

    let n_faces  = status.as_ref().map(|s| s.n_faces).unwrap_or(0);
    let n_routes = status.as_ref().map(|s| s.n_fib).unwrap_or(0);
    let n_cs     = status.as_ref().map(|s| s.n_cs).unwrap_or(0);
    let n_pit    = status.as_ref().map(|s| s.n_pit).unwrap_or(0);

    // Throughput summary from last sample
    let (tp_in, tp_out) = throughput.back()
        .map(|s| (fmt_bytes(s.in_bytes), fmt_bytes(s.out_bytes)))
        .unwrap_or_else(|| ("0 B".to_string(), "0 B".to_string()));

    rsx! {
        // ── Modals ────────────────────────────────────────────────────────────
        if *show_face_modal.read() {
            FaceCreateModal { on_close: move |_| show_face_modal.set(false) }
        }
        if *show_route_modal.read() {
            RouteAddModal { on_close: move |_| show_route_modal.set(false) }
        }

        // ── Education card ────────────────────────────────────────────────────
        if !*edu_dismissed.read() {
            div { class: "edu-card",
                div { style: "display:flex;gap:12px;align-items:flex-start;",
                    div { style: "flex-shrink:0;width:60px;text-align:center;padding-top:4px;",
                        div { class: "drop-packet", "Interest /ndn/…" }
                        div { style: "font-size:9px;color:var(--red);margin-top:4px;", "✕ unsigned" }
                    }
                    div { style: "flex:1;",
                        div { style: "display:flex;justify-content:space-between;align-items:flex-start;",
                            div { style: "font-size:13px;font-weight:600;color:var(--accent);margin-bottom:4px;",
                                "Zero Trust by Default"
                            }
                            button {
                                style: "background:none;border:none;color:var(--text-muted);cursor:pointer;font-size:13px;padding:0;",
                                onclick: move |_| edu_dismissed.set(true),
                                "✕"
                            }
                        }
                        div { style: "font-size:12px;color:var(--text-muted);line-height:1.6;",
                            "Every NDN packet carries a "
                            strong { style: "color:var(--text);", "cryptographic signature." }
                            " Configure your identity and trust anchor in the "
                            span { style: "color:var(--accent);", "Security" }
                            " tab."
                        }
                    }
                }
            }
        }

        // ── Stat header cards (clickable toggles) ─────────────────────────────
        div { class: "overview-cards",

            // Faces card
            {
                let open = *faces_open.read();
                rsx! {
                    div {
                        class: if open { "ov-card ov-card-active" } else { "ov-card" },
                        onclick: move |_| { let v = *faces_open.read(); faces_open.set(!v); },
                        div { class: "ov-card-label", "FACES" }
                        div { class: "ov-card-value", "{n_faces}" }
                        div { class: "ov-card-hint", if open { "▲ collapse" } else { "▼ expand" } }
                    }
                }
            }

            // Routes card
            {
                let open = *routes_open.read();
                rsx! {
                    div {
                        class: if open { "ov-card ov-card-active" } else { "ov-card" },
                        onclick: move |_| { let v = *routes_open.read(); routes_open.set(!v); },
                        div { class: "ov-card-label", "ROUTES" }
                        div { class: "ov-card-value", "{n_routes}" }
                        div { class: "ov-card-hint", if open { "▲ collapse" } else { "▼ expand" } }
                    }
                }
            }

            // PIT card (static, not expandable)
            div { class: "ov-card ov-card-static",
                div { class: "ov-card-label", "PIT" }
                div { class: "ov-card-value", "{n_pit}" }
                div { class: "ov-card-hint", "pending interests" }
            }

            // Content Store card
            {
                let open = *cs_open.read();
                let cs_val = cs.as_ref()
                    .map(|c| format!("{} items", c.n_entries))
                    .unwrap_or_else(|| n_cs.to_string());
                rsx! {
                    div {
                        class: if open { "ov-card ov-card-active" } else { "ov-card" },
                        onclick: move |_| { let v = *cs_open.read(); cs_open.set(!v); },
                        div { class: "ov-card-label", "CONTENT STORE" }
                        div { class: "ov-card-value", "{cs_val}" }
                        div { class: "ov-card-hint", if open { "▲ collapse" } else { "▼ expand" } }
                    }
                }
            }

            // Traffic card
            {
                let open = *traffic_open.read();
                rsx! {
                    div {
                        class: if open { "ov-card ov-card-active" } else { "ov-card" },
                        onclick: move |_| { let v = *traffic_open.read(); traffic_open.set(!v); },
                        div { class: "ov-card-label", "TRAFFIC" }
                        div { style: "font-size:13px;color:var(--text);margin:2px 0;font-family:monospace;",
                            "↓ {tp_in}/s  ↑ {tp_out}/s"
                        }
                        div { class: "ov-card-hint", if open { "▲ collapse" } else { "▼ expand" } }
                    }
                }
            }
        }

        // ── Expanded: Faces ───────────────────────────────────────────────────
        if *faces_open.read() {
            div { class: "section",
                div { class: "section-hdr",
                    span { class: "section-title", "Active Faces" }
                    button {
                        class: "btn btn-primary btn-sm",
                        onclick: move |_| show_face_modal.set(true),
                        "+ Add Face"
                    }
                }
                if faces.is_empty() {
                    div { class: "empty", "No faces. Click + Add Face to create one." }
                } else {
                    table {
                        thead {
                            tr {
                                th { "ID" }
                                th { "Kind" }
                                th { "Remote URI" }
                                th { "Local URI" }
                                th { "Persistency" }
                                th { "" }
                            }
                        }
                        tbody {
                            for face in faces.iter() {
                                {
                                    let fid = face.face_id;
                                    rsx! {
                                        tr {
                                            td { class: "mono", "{face.face_id}" }
                                            td { span { class: "{face.kind_badge_class()}", "{face.kind_label()}" } }
                                            td { class: "mono", "{face.remote_uri.as_deref().unwrap_or(\"—\")}" }
                                            td { class: "mono", "{face.local_uri.as_deref().unwrap_or(\"—\")}" }
                                            td { "{face.persistency}" }
                                            td {
                                                button {
                                                    class: "btn btn-danger btn-sm",
                                                    onclick: move |_| ctx.cmd.send(DashCmd::FaceDestroy(fid)),
                                                    "Destroy"
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

        // ── Expanded: Routes ──────────────────────────────────────────────────
        if *routes_open.read() {
            div { class: "section",
                div { class: "section-hdr",
                    span { class: "section-title", "FIB Routes" }
                    button {
                        class: "btn btn-primary btn-sm",
                        onclick: move |_| show_route_modal.set(true),
                        "+ Add Route"
                    }
                }
                if routes.is_empty() {
                    div { class: "empty", "No routes. Click + Add Route to register one." }
                } else {
                    table {
                        thead {
                            tr {
                                th { "Prefix" }
                                th { "Nexthops" }
                                th { "Strategy" }
                                th { "" }
                            }
                        }
                        tbody {
                            for entry in routes.iter() {
                                {
                                    let prefix = entry.prefix.clone();
                                    let nexthop_str = entry.nexthops.iter()
                                        .map(|nh| format!("face {} (cost {})", nh.face_id, nh.cost))
                                        .collect::<Vec<_>>()
                                        .join("  |  ");
                                    let first_fid = entry.nexthops.first().map(|n| n.face_id).unwrap_or(0);
                                    let pfx2 = prefix.clone();
                                    let strat_pfx = prefix.clone();
                                    let _strat_pfx2 = prefix.clone();
                                    let current_strat = strategies
                                        .iter()
                                        .find(|s| s.prefix == entry.prefix)
                                        .map(|s| s.strategy.clone());
                                    let current_strat2 = current_strat.clone();
                                    rsx! {
                                        tr {
                                            td { class: "mono", "{prefix}" }
                                            td { class: "mono", style: "font-size:11px;", "{nexthop_str}" }
                                            td {
                                                select {
                                                    style: "background:var(--bg);border:1px solid var(--border-subtle);border-radius:4px;color:var(--text-muted);font-size:11px;padding:2px 6px;cursor:pointer;",
                                                    onchange: move |e| {
                                                        let val = e.value();
                                                        if val == "__unset__" || val.is_empty() {
                                                            ctx.cmd.send(DashCmd::StrategyUnset(strat_pfx.clone()));
                                                        } else {
                                                            ctx.cmd.send(DashCmd::StrategySet { prefix: strat_pfx.clone(), strategy: val });
                                                        }
                                                    },
                                                    option { value: "__unset__",
                                                        selected: current_strat2.is_none(),
                                                        "— default —"
                                                    }
                                                    for (uri, name) in KNOWN_STRATEGIES {
                                                        {
                                                            let sel = current_strat.as_deref() == Some(*uri);
                                                            rsx! {
                                                                option { value: "{uri}", selected: sel, "{name}" }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                            td {
                                                button {
                                                    class: "btn btn-danger btn-sm",
                                                    onclick: move |_| ctx.cmd.send(DashCmd::RouteRemove {
                                                        prefix: pfx2.clone(),
                                                        face_id: first_fid,
                                                    }),
                                                    "Remove"
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

        // ── Expanded: Content Store ───────────────────────────────────────────
        if *cs_open.read() {
            div { class: "section",
                div { class: "section-hdr",
                    span { class: "section-title", "Content Store" }
                }
                if let Some(ref info) = *cs {
                    // Stats row
                    div { style: "display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:16px;",
                        div { class: "mini-stat",
                            div { class: "mini-stat-label", "Capacity" }
                            div { class: "mini-stat-value", "{info.capacity_mb():.0} MB" }
                            div { class: "mini-stat-sub", "{info.variant}" }
                        }
                        div { class: "mini-stat",
                            div { class: "mini-stat-label", "Entries" }
                            div { class: "mini-stat-value", "{info.n_entries}" }
                            div { class: "mini-stat-sub", "{info.used_mb():.2} MB used" }
                        }
                        div { class: "mini-stat",
                            div { class: "mini-stat-label", "Hit Rate" }
                            div { class: "mini-stat-value", "{info.hit_rate_pct():.1}%" }
                            div { class: "mini-stat-sub", "{info.hits}h / {info.misses}m" }
                        }
                    }
                } else {
                    div { class: "empty", style: "margin-bottom:16px;", "Content store data unavailable." }
                }

                {render_cs_sparkline(&cs_hit_history)}

                // Controls
                div { style: "display:flex;gap:16px;flex-wrap:wrap;padding-top:12px;border-top:1px solid var(--border-subtle);",
                    // Set capacity
                    div { class: "form-group",
                        label { "Set Capacity (MB)" }
                        div { style: "display:flex;gap:6px;",
                            input {
                                r#type: "number",
                                placeholder: "64",
                                value: "{cs_cap_mb}",
                                style: "width:100px;",
                                oninput: move |e| cs_cap_mb.set(e.value()),
                            }
                            button {
                                class: "btn btn-primary btn-sm",
                                onclick: move |_| {
                                    let val = cs_cap_mb.read().trim().to_string();
                                    if let Ok(mb) = val.parse::<f64>() {
                                        ctx.cmd.send(DashCmd::CsCapacity((mb * 1_048_576.0) as u64));
                                        cs_cap_mb.set(String::new());
                                    }
                                },
                                "Apply"
                            }
                        }
                    }
                    // Erase prefix
                    div { class: "form-group", style: "flex:1;",
                        label { "Erase by Prefix" }
                        div { style: "display:flex;gap:6px;",
                            input {
                                r#type: "text",
                                placeholder: "/prefix/to/erase",
                                value: "{cs_erase_pfx}",
                                style: "flex:1;",
                                oninput: move |e| cs_erase_pfx.set(e.value()),
                            }
                            button {
                                class: "btn btn-danger btn-sm",
                                onclick: move |_| {
                                    let p = cs_erase_pfx.read().trim().to_string();
                                    if !p.is_empty() {
                                        ctx.cmd.send(DashCmd::CsErase(p));
                                        cs_erase_pfx.set(String::new());
                                    }
                                },
                                "Erase"
                            }
                        }
                    }
                }
            }
        }

        // ── Expanded: Traffic ─────────────────────────────────────────────────
        if *traffic_open.read() {
            div { class: "section",
                div { class: "section-hdr",
                    span { class: "section-title", "Traffic" }
                }

                // Per-face toggle chips
                if !counters.is_empty() {
                    div { style: "margin-bottom:12px;",
                        div { style: "font-size:11px;color:var(--text-muted);margin-bottom:6px;text-transform:uppercase;letter-spacing:.5px;", "Monitor faces" }
                        div { class: "face-toggle-row",
                            for c in counters.iter() {
                                {
                                    let fid = c.face_id;
                                    let mon = monitored.read().contains(&fid);
                                    let label = format!("face {}", fid);
                                    rsx! {
                                        button {
                                            class: if mon { "face-toggle on" } else { "face-toggle" },
                                            onclick: move |_| {
                                                let mut m = monitored.write();
                                                if m.contains(&fid) { m.remove(&fid); } else { m.insert(fid); }
                                            },
                                            "{label}"
                                        }
                                    }
                                }
                            }
                            if !monitored.read().is_empty() {
                                button {
                                    class: "face-toggle",
                                    style: "color:var(--red);border-color:var(--red);",
                                    onclick: move |_| monitored.write().clear(),
                                    "✕ clear"
                                }
                            }
                        }
                        if monitored.read().is_empty() {
                            div { style: "font-size:11px;color:var(--text-muted);", "Showing all faces. Select faces above to filter." }
                        } else {
                            div { style: "font-size:11px;color:var(--text-muted);",
                                "Showing {monitored.read().len()} selected face(s)."
                            }
                        }
                    }
                }

                // Charts — filtered by selected faces when any are toggled
                {
                    let filtered: VecDeque<ThroughputSample> = {
                        let mon = monitored.read();
                        if mon.is_empty() {
                            throughput.clone()
                        } else {
                            sum_face_histories(&face_throughput, Some(&mon))
                        }
                    };
                    let last = filtered.back();
                    let (tp_in_f, tp_out_f) = last
                        .map(|s| (fmt_bytes(s.in_bytes), fmt_bytes(s.out_bytes)))
                        .unwrap_or_else(|| ("0 B".to_string(), "0 B".to_string()));
                    let (in_pps, out_pps) = last
                        .map(|s| (s.in_interests, s.out_interests))
                        .unwrap_or((0, 0));
                    rsx! {
                        div { class: "section", style: "margin-bottom:0;padding:12px 16px;",
                            div { style: "display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;",
                                div { style: "font-size:12px;color:var(--text);font-family:monospace;",
                                    "↓ {tp_in_f}/s  ↑ {tp_out_f}/s"
                                }
                                div { style: "font-size:11px;color:var(--text-muted);",
                                    "{in_pps} pkt/s ↓ / {out_pps} pkt/s ↑"
                                }
                            }
                            div { style: "margin-bottom:4px;",
                                div { style: "font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px;", "Bytes / s" }
                                {render_throughput_bars(&filtered, 48)}
                            }
                            div { style: "margin-top:12px;",
                                div { style: "font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px;", "Interests / s" }
                                {render_pps_bars(&filtered, 36)}
                            }
                        }
                    }
                }

                // Counter table (filtered by monitored)
                div { style: "margin-top:16px;",
                    div { style: "font-size:11px;color:var(--text-muted);margin-bottom:6px;text-transform:uppercase;letter-spacing:.5px;", "Face Counters" }
                    if counters.is_empty() {
                        div { class: "empty", "No counter data." }
                    } else {
                        table {
                            thead {
                                tr {
                                    th { "Face" }
                                    th { "↓ Interests" }
                                    th { "↓ Data" }
                                    th { "↑ Interests" }
                                    th { "↑ Data" }
                                    th { "↓ Bytes" }
                                    th { "↑ Bytes" }
                                }
                            }
                            tbody {
                                for c in counters.iter().filter(|c| {
                                    monitored.read().is_empty() || monitored.read().contains(&c.face_id)
                                }) {
                                    tr {
                                        td { class: "mono", "{c.face_id}" }
                                        td { class: "mono", "{c.in_interests}" }
                                        td { class: "mono", "{c.in_data}" }
                                        td { class: "mono", "{c.out_interests}" }
                                        td { class: "mono", "{c.out_data}" }
                                        td { class: "mono", "{fmt_bytes(c.in_bytes)}" }
                                        td { class: "mono", "{fmt_bytes(c.out_bytes)}" }
                                    }
                                }
                            }
                        }
                    }
                }

                // Prefix measurements (if any)
                if !measurements.is_empty() {
                    div { style: "margin-top:16px;",
                        div { style: "font-size:11px;color:var(--text-muted);margin-bottom:6px;text-transform:uppercase;letter-spacing:.5px;", "Prefix Measurements" }
                        table {
                            thead {
                                tr {
                                    th { "Prefix" }
                                    th { "Sat. Rate" }
                                    th { "RTT per Face" }
                                }
                            }
                            tbody {
                                for m in measurements.iter() {
                                    tr {
                                        td { class: "mono", "{m.prefix}" }
                                        td {
                                            span { class: "{m.sat_rate_class()}",
                                                "{(m.satisfaction_rate * 100.0):.1}%"
                                            }
                                        }
                                        td { class: "mono", style: "font-size:11px;",
                                            {
                                                if m.face_rtts.is_empty() {
                                                    "—".to_string()
                                                } else {
                                                    m.face_rtts.iter()
                                                        .map(|r| format!("face{}={:.1}ms", r.face_id, r.srtt_ms))
                                                        .collect::<Vec<_>>()
                                                        .join("  |  ")
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

fn render_cs_sparkline(hist: &VecDeque<f64>) -> Element {
    if hist.len() < 2 {
        return rsx! {};
    }
    let n = hist.len();
    const LABEL_W: f64 = 36.0;
    const LINE_W:  f64 = 200.0;
    let total_w = LABEL_W + LINE_W;
    let h = 40.0f64;
    let mid_h = h / 2.0;
    let last = hist.back().copied().unwrap_or(0.0);
    let color = if last >= 75.0 { "var(--green)" } else if last >= 40.0 { "var(--yellow)" } else { "var(--red)" };

    let step = LINE_W / (n - 1).max(1) as f64;
    let points: String = hist.iter().enumerate()
        .map(|(i, &v)| format!("{:.1},{:.1}", LABEL_W + i as f64 * step, h - (v / 100.0 * h).max(0.0).min(h)))
        .collect::<Vec<_>>()
        .join(" ");
    let first_x = LABEL_W;
    let last_x  = LABEL_W + (n - 1) as f64 * step;
    let area_pts = format!("{first_x:.1},{h} {points} {last_x:.1},{h}");

    let svg = format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {total_w:.0} {h:.0}\" style=\"width:100%;height:{h:.0}px;display:block;\">\
          <line x1=\"{LABEL_W}\" y1=\"0.5\" x2=\"{total_w:.0}\" y2=\"0.5\" stroke=\"var(--border)\" stroke-width=\"0.5\"/>\
          <line x1=\"{LABEL_W}\" y1=\"{mid_h:.1}\" x2=\"{total_w:.0}\" y2=\"{mid_h:.1}\" stroke=\"var(--border)\" stroke-width=\"0.5\" stroke-dasharray=\"3,3\"/>\
          <line x1=\"{LABEL_W}\" y1=\"{h:.0}\" x2=\"{total_w:.0}\" y2=\"{h:.0}\" stroke=\"var(--border)\" stroke-width=\"0.5\"/>\
          <line x1=\"{LABEL_W}\" y1=\"0\" x2=\"{LABEL_W}\" y2=\"{h:.0}\" stroke=\"var(--border)\" stroke-width=\"0.5\"/>\
          <text x=\"{:.1}\" y=\"9\" fill=\"var(--text-faint)\" font-size=\"9\" text-anchor=\"end\" font-family=\"monospace\">100%</text>\
          <text x=\"{:.1}\" y=\"{:.1}\" fill=\"var(--text-faint)\" font-size=\"9\" text-anchor=\"end\" font-family=\"monospace\">50%</text>\
          <text x=\"{:.1}\" y=\"{h:.0}\" fill=\"var(--text-faint)\" font-size=\"9\" text-anchor=\"end\" font-family=\"monospace\">0%</text>\
          <polygon points=\"{area_pts}\" fill=\"{color}\" fill-opacity=\"0.12\"/>\
          <polyline points=\"{points}\" fill=\"none\" stroke=\"{color}\" stroke-width=\"1.5\" stroke-linejoin=\"round\"/>\
        </svg>",
        LABEL_W - 3.0,
        LABEL_W - 3.0, mid_h + 4.0,
        LABEL_W - 3.0,
    );

    rsx! {
        div { style: "margin-bottom:12px;",
            div { style: "font-size:10px;color:var(--text-muted);margin-bottom:4px;text-transform:uppercase;letter-spacing:.5px;",
                "CS Hit Rate  ({last:.1}%)"
            }
            div { dangerous_inner_html: "{svg}" }
        }
    }
}

