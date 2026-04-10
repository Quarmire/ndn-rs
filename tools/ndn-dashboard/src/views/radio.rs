use dioxus::prelude::*;
use crate::app::AppCtx;
use crate::types::FaceInfo;

#[component]
pub fn Radio() -> Element {
    let ctx = use_context::<AppCtx>();
    let faces = ctx.faces.read();
    let counters = ctx.counters.read();

    // Show wireless-relevant faces: ether-multicast, WFB (wifibroadcast), multicast UDP
    let wireless_faces: Vec<&FaceInfo> = faces.iter()
        .filter(|f| {
            let uri = f.remote_uri.as_deref().unwrap_or("");
            let kind = f.kind.as_deref().unwrap_or("");
            uri.starts_with("ether://")
                || kind.eq_ignore_ascii_case("wfb")
                || kind.eq_ignore_ascii_case("EtherMulticast")
                || uri.starts_with("ether-multicast://")
        })
        .collect();

    rsx! {
        div { class: "section",
            div { class: "section-title", "Radio / Wireless Faces" }
            if wireless_faces.is_empty() {
                div { class: "empty",
                    "No wireless faces detected. Radio view is relevant when Ethernet multicast or WFB (Wifibroadcast) faces are active."
                }
            } else {
                table {
                    thead {
                        tr {
                            th { "Face" }
                            th { "Kind" }
                            th { "URI" }
                            th { "In ↓ Interests" }
                            th { "In ↓ Data" }
                            th { "Out ↑ Interests" }
                            th { "Out ↑ Data" }
                            th { "Quality Est." }
                        }
                    }
                    tbody {
                        for face in &wireless_faces {
                            {
                                let fid = face.face_id;
                                let counter = counters.iter().find(|c| c.face_id == fid);
                                let (in_i, in_d, out_i, out_d) = match counter {
                                    Some(c) => (c.in_interests, c.in_data, c.out_interests, c.out_data),
                                    None    => (0, 0, 0, 0),
                                };
                                // Estimate link quality from data satisfaction: in_data / in_interests
                                let quality_pct = if in_i > 0 {
                                    ((in_d as f64 / in_i as f64) * 100.0).min(100.0)
                                } else {
                                    0.0
                                };
                                let quality_class = if quality_pct >= 80.0 {
                                    "badge badge-green"
                                } else if quality_pct >= 50.0 {
                                    "badge badge-yellow"
                                } else if in_i == 0 {
                                    "badge badge-gray"
                                } else {
                                    "badge badge-red"
                                };
                                rsx! {
                                    tr {
                                        td { class: "mono", "{fid}" }
                                        td {
                                            span { class: "{face.kind_badge_class()}", "{face.kind_label()}" }
                                        }
                                        td { class: "mono", style: "font-size:11px;",
                                            "{face.remote_uri.as_deref().unwrap_or(\"—\")}"
                                        }
                                        td { class: "mono", "{in_i}" }
                                        td { class: "mono", "{in_d}" }
                                        td { class: "mono", "{out_i}" }
                                        td { class: "mono", "{out_d}" }
                                        td {
                                            span { class: "{quality_class}",
                                                if in_i == 0 {
                                                    "—"
                                                } else {
                                                    "{quality_pct:.0}%"
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                div { style: "font-size:11px;color:var(--text-muted);margin-top:8px;",
                    "Quality estimate = Data satisfied / Interests received (from face counters). "
                    "Full RSSI and SNR data requires "
                    span { class: "mono", "faces/link-quality" }
                    " (Phase 4.3)."
                }
            }
        }

        // ── All faces link overview ───────────────────────────────────────────
        div { class: "section",
            div { class: "section-title", "All Faces — Link Overview" }
            if counters.is_empty() {
                div { class: "empty", "No counter data available." }
            } else {
                div { style: "display:flex;flex-wrap:wrap;gap:12px;",
                    for c in counters.iter() {
                        {
                            let face_info = faces.iter().find(|f| f.face_id == c.face_id);
                            let kind = face_info.map(|f| f.kind_label()).unwrap_or("?");
                            let total_in = c.in_interests + c.in_data;
                            let total_out = c.out_interests + c.out_data;
                            rsx! {
                                div { style: "background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:12px;min-width:160px;",
                                    div { style: "font-size:11px;color:var(--text-muted);margin-bottom:6px;",
                                        "Face "
                                        span { class: "mono", "{c.face_id}" }
                                        " · "
                                        span { class: "badge badge-gray", "{kind}" }
                                    }
                                    div { style: "font-size:12px;color:var(--accent);", "↓ {total_in} pkts" }
                                    div { style: "font-size:12px;color:var(--green);", "↑ {total_out} pkts" }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
