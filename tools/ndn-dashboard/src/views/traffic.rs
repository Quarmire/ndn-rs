#![allow(dead_code)]
use std::collections::{HashMap, HashSet, VecDeque};
use dioxus::prelude::*;
use crate::app::AppCtx;
use crate::tool_runner::fmt_bytes;
use crate::types::ThroughputSample;

// ── Shared helpers ────────────────────────────────────────────────────────────

/// Sum selected face throughput histories into one aggregated VecDeque.
/// `filter = None` means include all faces.
pub fn sum_face_histories(
    face_throughput: &HashMap<u64, VecDeque<ThroughputSample>>,
    filter: Option<&HashSet<u64>>,
) -> VecDeque<ThroughputSample> {
    let sources: Vec<&VecDeque<ThroughputSample>> = face_throughput.iter()
        .filter(|(fid, _)| filter.map_or(true, |f| f.contains(fid)))
        .map(|(_, h)| h)
        .collect();

    if sources.is_empty() { return VecDeque::new(); }

    let max_len = sources.iter().map(|h| h.len()).max().unwrap_or(0);
    let mut result = VecDeque::with_capacity(max_len);
    for i in 0..max_len {
        let mut sample = ThroughputSample::default();
        for hist in &sources {
            let offset = max_len.saturating_sub(hist.len());
            if i >= offset {
                let s = &hist[i - offset];
                sample.in_bytes      = sample.in_bytes.saturating_add(s.in_bytes);
                sample.out_bytes     = sample.out_bytes.saturating_add(s.out_bytes);
                sample.in_interests  = sample.in_interests.saturating_add(s.in_interests);
                sample.out_interests = sample.out_interests.saturating_add(s.out_interests);
            }
        }
        result.push_back(sample);
    }
    result
}

/// Determine a human-friendly unit label and byte divisor for a bytes/s max value.
pub fn bytes_unit(max_val: u64) -> (&'static str, f64) {
    if max_val >= 1_073_741_824 { ("GB/s", 1_073_741_824.0) }
    else if max_val >= 1_048_576 { ("MB/s", 1_048_576.0) }
    else if max_val >= 1024      { ("KB/s", 1024.0) }
    else                         { ("B/s",  1.0) }
}

/// Determine a human-friendly unit label and divisor for a packets/s max value.
pub fn pkt_unit(max_val: u64) -> (&'static str, f64) {
    if max_val >= 1_000_000 { ("Mpkt/s", 1_000_000.0) }
    else if max_val >= 1_000 { ("Kpkt/s", 1_000.0) }
    else                     { ("pkt/s",  1.0) }
}

/// Render an in/out bytes-per-second bar chart with a Y-axis showing the scale.
pub fn render_throughput_bars(hist: &VecDeque<ThroughputSample>, height_px: u32) -> Element {
    if hist.len() < 2 {
        return rsx! {
            div { class: "empty", "Collecting throughput data… (updates every 3 s)" }
        };
    }

    let max_bytes = hist.iter()
        .map(|s| s.in_bytes.max(s.out_bytes))
        .max().unwrap_or(1).max(1);

    let (unit, divisor) = bytes_unit(max_bytes);
    let max_label = format!("{:.1} {unit}", max_bytes as f64 / divisor);
    let mid_label = format!("{:.1}", (max_bytes as f64 / divisor) / 2.0);

    const LABEL_W: f64 = 48.0;
    const BAR_W:   f64 = 320.0;
    let total_w = LABEL_W + BAR_W;
    let h = height_px as f64;
    let mid_h = h / 2.0;

    let n = hist.len();
    let slot_w = BAR_W / n as f64;

    let color_in  = "var(--accent-solid)";
    let color_out = "var(--green)";
    let mut bars = String::new();
    for (i, s) in hist.iter().enumerate() {
        let x = LABEL_W + i as f64 * slot_w;
        let hw = ((slot_w - 1.5) / 2.0).max(0.5);
        let in_h  = ((s.in_bytes  as f64 / max_bytes as f64) * h).ceil().max(1.0);
        let out_h = ((s.out_bytes as f64 / max_bytes as f64) * h).ceil().max(1.0);
        bars.push_str(&format!(
            "<rect x=\"{:.1}\" y=\"{:.1}\" width=\"{hw:.1}\" height=\"{in_h:.1}\" fill=\"{color_in}\"/>\
             <rect x=\"{:.1}\" y=\"{:.1}\" width=\"{hw:.1}\" height=\"{out_h:.1}\" fill=\"{color_out}\"/>",
            x,          h - in_h,
            x + hw + 0.5, h - out_h,
        ));
    }

    let svg = format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {total_w:.0} {h:.0}\" style=\"width:100%;height:{h:.0}px;display:block;\">\
          <line x1=\"{LABEL_W}\" y1=\"0.5\" x2=\"{total_w:.0}\" y2=\"0.5\" stroke=\"var(--border)\" stroke-width=\"0.5\"/>\
          <line x1=\"{LABEL_W}\" y1=\"{mid_h:.1}\" x2=\"{total_w:.0}\" y2=\"{mid_h:.1}\" stroke=\"var(--border)\" stroke-width=\"0.5\" stroke-dasharray=\"3,3\"/>\
          <line x1=\"{LABEL_W}\" y1=\"{h:.0}\" x2=\"{total_w:.0}\" y2=\"{h:.0}\" stroke=\"var(--border)\" stroke-width=\"0.5\"/>\
          <line x1=\"{LABEL_W}\" y1=\"0\" x2=\"{LABEL_W}\" y2=\"{h:.0}\" stroke=\"var(--border)\" stroke-width=\"0.5\"/>\
          <text x=\"{:.1}\" y=\"9\" fill=\"var(--text-faint)\" font-size=\"9\" text-anchor=\"end\" font-family=\"monospace\">{max_label}</text>\
          <text x=\"{:.1}\" y=\"{:.1}\" fill=\"var(--text-faint)\" font-size=\"9\" text-anchor=\"end\" font-family=\"monospace\">{mid_label}</text>\
          <text x=\"{:.1}\" y=\"{h:.0}\" fill=\"var(--text-faint)\" font-size=\"9\" text-anchor=\"end\" font-family=\"monospace\">0</text>\
          {bars}\
        </svg>",
        LABEL_W - 3.0,
        LABEL_W - 3.0, mid_h + 4.0,
        LABEL_W - 3.0,
    );

    rsx! {
        div {
            div { dangerous_inner_html: "{svg}" }
            div { style: "font-size:10px;color:var(--text-muted);margin-top:4px;display:flex;gap:14px;flex-wrap:wrap;",
                span { style: "display:flex;align-items:center;gap:4px;",
                    span { style: "width:10px;height:4px;background:{color_in};display:inline-block;border-radius:1px;" }
                    "in"
                }
                span { style: "display:flex;align-items:center;gap:4px;",
                    span { style: "width:10px;height:4px;background:{color_out};display:inline-block;border-radius:1px;" }
                    "out"
                }
                span { style: "color:var(--text-faint);", "60 samples × 3 s = 3 min window" }
            }
        }
    }
}

/// Render an in/out interests-per-second bar chart with a Y-axis showing the scale.
pub fn render_pps_bars(hist: &VecDeque<ThroughputSample>, height_px: u32) -> Element {
    if hist.len() < 2 {
        return rsx! { div { class: "empty", "Collecting packet rate data…" } };
    }

    let max_pps = hist.iter()
        .map(|s| s.in_interests.max(s.out_interests))
        .max().unwrap_or(1).max(1);

    let (unit, divisor) = pkt_unit(max_pps);
    let max_label = format!("{:.1} {unit}", max_pps as f64 / divisor);
    let mid_label = format!("{:.1}", (max_pps as f64 / divisor) / 2.0);

    const LABEL_W: f64 = 48.0;
    const BAR_W:   f64 = 320.0;
    let total_w = LABEL_W + BAR_W;
    let h = height_px as f64;
    let mid_h = h / 2.0;

    let n = hist.len();
    let slot_w = BAR_W / n as f64;

    let color_in  = "var(--purple)";  // purple for in interests
    let color_out = "var(--orange)";  // orange-red for out interests
    let mut bars = String::new();
    for (i, s) in hist.iter().enumerate() {
        let x = LABEL_W + i as f64 * slot_w;
        let hw = ((slot_w - 1.5) / 2.0).max(0.5);
        let in_h  = ((s.in_interests  as f64 / max_pps as f64) * h).ceil().max(1.0);
        let out_h = ((s.out_interests as f64 / max_pps as f64) * h).ceil().max(1.0);
        bars.push_str(&format!(
            "<rect x=\"{:.1}\" y=\"{:.1}\" width=\"{hw:.1}\" height=\"{in_h:.1}\" fill=\"{color_in}\"/>\
             <rect x=\"{:.1}\" y=\"{:.1}\" width=\"{hw:.1}\" height=\"{out_h:.1}\" fill=\"{color_out}\"/>",
            x,          h - in_h,
            x + hw + 0.5, h - out_h,
        ));
    }

    let svg = format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {total_w:.0} {h:.0}\" style=\"width:100%;height:{h:.0}px;display:block;\">\
          <line x1=\"{LABEL_W}\" y1=\"0.5\" x2=\"{total_w:.0}\" y2=\"0.5\" stroke=\"var(--border)\" stroke-width=\"0.5\"/>\
          <line x1=\"{LABEL_W}\" y1=\"{mid_h:.1}\" x2=\"{total_w:.0}\" y2=\"{mid_h:.1}\" stroke=\"var(--border)\" stroke-width=\"0.5\" stroke-dasharray=\"3,3\"/>\
          <line x1=\"{LABEL_W}\" y1=\"{h:.0}\" x2=\"{total_w:.0}\" y2=\"{h:.0}\" stroke=\"var(--border)\" stroke-width=\"0.5\"/>\
          <line x1=\"{LABEL_W}\" y1=\"0\" x2=\"{LABEL_W}\" y2=\"{h:.0}\" stroke=\"var(--border)\" stroke-width=\"0.5\"/>\
          <text x=\"{:.1}\" y=\"9\" fill=\"var(--text-faint)\" font-size=\"9\" text-anchor=\"end\" font-family=\"monospace\">{max_label}</text>\
          <text x=\"{:.1}\" y=\"{:.1}\" fill=\"var(--text-faint)\" font-size=\"9\" text-anchor=\"end\" font-family=\"monospace\">{mid_label}</text>\
          <text x=\"{:.1}\" y=\"{h:.0}\" fill=\"var(--text-faint)\" font-size=\"9\" text-anchor=\"end\" font-family=\"monospace\">0</text>\
          {bars}\
        </svg>",
        LABEL_W - 3.0,
        LABEL_W - 3.0, mid_h + 4.0,
        LABEL_W - 3.0,
    );

    rsx! {
        div {
            div { dangerous_inner_html: "{svg}" }
            div { style: "font-size:10px;color:var(--text-muted);margin-top:4px;display:flex;gap:14px;flex-wrap:wrap;",
                span { style: "display:flex;align-items:center;gap:4px;",
                    span { style: "width:10px;height:4px;background:{color_in};display:inline-block;border-radius:1px;" }
                    "interests in"
                }
                span { style: "display:flex;align-items:center;gap:4px;",
                    span { style: "width:10px;height:4px;background:{color_out};display:inline-block;border-radius:1px;" }
                    "interests out"
                }
            }
        }
    }
}

// ── Traffic view ──────────────────────────────────────────────────────────────

#[derive(Clone, PartialEq)]
enum MonitorMode { All, Faces, Prefix }

#[component]
pub fn Traffic() -> Element {
    let ctx = use_context::<AppCtx>();

    let counters        = ctx.counters.read();
    let measurements    = ctx.measurements.read();
    let face_throughput = ctx.face_throughput.read();
    let throughput      = ctx.throughput.read();
    let routes          = ctx.routes.read();
    let faces           = ctx.faces.read();

    let mut mode:        Signal<MonitorMode>   = use_signal(|| MonitorMode::All);
    let mut sel_faces:   Signal<HashSet<u64>>  = use_signal(HashSet::new);
    let mut sel_prefixes: Signal<HashSet<String>> = use_signal(HashSet::new);

    // Compute the filtered history to display
    let plot_history: VecDeque<ThroughputSample> = match *mode.read() {
        MonitorMode::All   => throughput.clone(),
        MonitorMode::Faces => {
            let f = sel_faces.read();
            if f.is_empty() { throughput.clone() }
            else { sum_face_histories(&face_throughput, Some(&f)) }
        }
        MonitorMode::Prefix => {
            let pfxs = sel_prefixes.read();
            if pfxs.is_empty() {
                throughput.clone()
            } else {
                let filter: HashSet<u64> = routes.iter()
                    .filter(|r| pfxs.contains(&r.prefix))
                    .flat_map(|r| r.nexthops.iter().map(|nh| nh.face_id))
                    .collect();
                sum_face_histories(&face_throughput, Some(&filter))
            }
        }
    };

    let last = plot_history.back();
    let (in_str, out_str) = match last {
        Some(s) => (fmt_bytes(s.in_bytes), fmt_bytes(s.out_bytes)),
        None    => ("0 B".to_string(), "0 B".to_string()),
    };
    let (in_pps, out_pps) = match last {
        Some(s) => (s.in_interests, s.out_interests),
        None    => (0, 0),
    };

    rsx! {
        // ── Monitor mode + filter controls ────────────────────────────────
        div { class: "section",
            div { class: "section-hdr",
                span { class: "section-title", "Traffic Monitor" }
                div { style: "display:flex;gap:6px;",
                    {
                        let m = mode.read().clone();
                        rsx! {
                            button {
                                class: if m == MonitorMode::All { "btn btn-primary btn-sm" } else { "btn btn-sm" },
                                onclick: move |_| {
                                    mode.set(MonitorMode::All);
                                    sel_faces.write().clear();
                                    sel_prefixes.write().clear();
                                },
                                "All Faces"
                            }
                            button {
                                class: if m == MonitorMode::Faces { "btn btn-primary btn-sm" } else { "btn btn-sm" },
                                onclick: move |_| mode.set(MonitorMode::Faces),
                                "By Face"
                            }
                            button {
                                class: if m == MonitorMode::Prefix { "btn btn-primary btn-sm" } else { "btn btn-sm" },
                                onclick: move |_| mode.set(MonitorMode::Prefix),
                                "By Prefix"
                            }
                        }
                    }
                }
            }

            // Face selector chips
            if *mode.read() == MonitorMode::Faces && !counters.is_empty() {
                div { style: "margin-top:10px;",
                    div { class: "face-toggle-row",
                        for c in counters.iter() {
                            {
                                let fid = c.face_id;
                                let on = sel_faces.read().contains(&fid);
                                // Prefer remote URI as label, fall back to face ID
                                let label = faces.iter()
                                    .find(|f| f.face_id == fid)
                                    .and_then(|f| f.remote_uri.as_deref())
                                    .map(|u| format!("{fid} {u}"))
                                    .unwrap_or_else(|| format!("face {fid}"));
                                rsx! {
                                    button {
                                        class: if on { "face-toggle on" } else { "face-toggle" },
                                        onclick: move |_| {
                                            let mut f = sel_faces.write();
                                            if f.contains(&fid) { f.remove(&fid); } else { f.insert(fid); }
                                        },
                                        "{label}"
                                    }
                                }
                            }
                        }
                        if !sel_faces.read().is_empty() {
                            button {
                                class: "face-toggle",
                                style: "color:var(--red);border-color:var(--red);",
                                onclick: move |_| sel_faces.write().clear(),
                                "✕ clear"
                            }
                        }
                    }
                    div { style: "font-size:11px;color:var(--text-muted);margin-top:4px;",
                        if sel_faces.read().is_empty() {
                            "No faces selected — showing all faces."
                        } else {
                            "Showing {sel_faces.read().len()} face(s)."
                        }
                    }
                }
            }

            // Prefix selector chips (multi-select)
            if *mode.read() == MonitorMode::Prefix {
                div { style: "margin-top:10px;",
                    if routes.is_empty() {
                        div { class: "empty", "No FIB routes available." }
                    } else {
                        div {
                            div { style: "font-size:11px;color:var(--text-muted);margin-bottom:6px;",
                                "Select one or more prefixes to filter traffic by their nexthop faces:"
                            }
                            div { class: "face-toggle-row",
                                for r in routes.iter() {
                                    {
                                        let pfx = r.prefix.clone();
                                        let on = sel_prefixes.read().contains(&pfx);
                                        let nexthop_str = r.nexthops.iter()
                                            .map(|nh| format!("→f{}", nh.face_id))
                                            .collect::<Vec<_>>().join(" ");
                                        let pfx2 = pfx.clone();
                                        rsx! {
                                            button {
                                                class: if on { "face-toggle on" } else { "face-toggle" },
                                                title: "nexthops: {nexthop_str}",
                                                onclick: move |_| {
                                                    let mut s = sel_prefixes.write();
                                                    if s.contains(&pfx) { s.remove(&pfx); } else { s.insert(pfx.clone()); }
                                                },
                                                span { style: "font-family:monospace;", "{pfx2}" }
                                                span { style: "color:var(--text-muted);margin-left:4px;font-size:10px;", "{nexthop_str}" }
                                            }
                                        }
                                    }
                                }
                                if !sel_prefixes.read().is_empty() {
                                    button {
                                        class: "face-toggle",
                                        style: "color:var(--red);border-color:var(--red);",
                                        onclick: move |_| sel_prefixes.write().clear(),
                                        "✕ clear"
                                    }
                                }
                            }
                            if sel_prefixes.read().is_empty() {
                                div { style: "font-size:11px;color:var(--text-muted);margin-top:4px;",
                                    "No prefixes selected — showing all traffic."
                                }
                            } else {
                                {
                                    let active_faces: HashSet<u64> = routes.iter()
                                        .filter(|r| sel_prefixes.read().contains(&r.prefix))
                                        .flat_map(|r| r.nexthops.iter().map(|nh| nh.face_id))
                                        .collect();
                                    let face_list = active_faces.iter()
                                        .map(|f| format!("face {f}"))
                                        .collect::<Vec<_>>().join(", ");
                                    rsx! {
                                        div { style: "font-size:11px;color:var(--text-muted);margin-top:4px;",
                                            "{sel_prefixes.read().len()} prefix(es) selected — monitoring nexthop faces: {face_list}"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // ── Throughput charts ─────────────────────────────────────────────
        div { class: "section",
            div { class: "section-hdr",
                span { style: "font-size:13px;color:var(--text);font-family:monospace;",
                    "↓ {in_str}/s  ↑ {out_str}/s"
                }
                span { style: "font-size:11px;color:var(--text-muted);",
                    "{in_pps} pkt/s ↓ / {out_pps} pkt/s ↑"
                }
            }

            // Bytes/s chart
            div { style: "margin-bottom:4px;",
                div { style: "font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px;",
                    "Bytes / s"
                }
                {render_throughput_bars(&plot_history, 72)}
            }

            // Packets/s chart
            div { style: "margin-top:14px;",
                div { style: "font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px;",
                    "Interests / s"
                }
                {render_pps_bars(&plot_history, 48)}
            }
        }

        // ── Per-face counters ─────────────────────────────────────────────
        div { class: "section",
            div { class: "section-title", "Face Traffic Counters" }
            if counters.is_empty() {
                div { class: "empty", "No counter data." }
            } else {
                table {
                    thead {
                        tr {
                            th { "Face" }
                            th { "URI" }
                            th { "↓ Interests" }
                            th { "↓ Data pkts" }
                            th { "↑ Interests" }
                            th { "↑ Data pkts" }
                            th { "↓ Bytes" }
                            th { "↑ Bytes" }
                        }
                    }
                    tbody {
                        for c in counters.iter() {
                            {
                                let fid = c.face_id;
                                let uri = faces.iter()
                                    .find(|f| f.face_id == fid)
                                    .and_then(|f| f.remote_uri.as_deref())
                                    .unwrap_or("—")
                                    .to_string();
                                rsx! {
                                    tr {
                                        td { class: "mono", "{c.face_id}" }
                                        td { class: "mono", style: "font-size:10px;color:var(--text-muted);max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;", "{uri}" }
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
            }
        }

        // ── Prefix measurements ───────────────────────────────────────────
        div { class: "section",
            div { class: "section-title", "Prefix Measurements" }
            if measurements.is_empty() {
                div { class: "empty", "No measurements yet. Accumulates as Interests are forwarded." }
            } else {
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
                                td { class: "mono",
                                    if m.face_rtts.is_empty() {
                                        "—"
                                    } else {
                                        {
                                            let s = m.face_rtts.iter()
                                                .map(|r| format!("face{}={:.1}ms", r.face_id, r.srtt_ms))
                                                .collect::<Vec<_>>().join("  |  ");
                                            rsx! { "{s}" }
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
