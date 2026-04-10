//! Dashboard Settings view — server toggles and experimental features.

use dioxus::prelude::*;

use crate::app::{ROUTER_RUNNING, push_toast, ToastLevel};
use crate::settings::{DASH_SETTINGS, save_settings};

#[component]
pub fn DashboardConfig() -> Element {
    // Local draft — edits don't apply until saved.
    let mut draft = use_signal(|| DASH_SETTINGS.peek().clone());
    let mut dirty = use_signal(|| false);

    rsx! {
        div { class: "section",
            div { class: "section-title", "Dashboard Settings" }

            // ── Node Identity ─────────────────────────────────────────────────
            div { style: "margin-bottom:28px;",
                div { style: "font-size:12px;font-weight:600;color:var(--text);text-transform:uppercase;letter-spacing:.5px;margin-bottom:14px;border-bottom:1px solid var(--border-subtle);padding-bottom:8px;",
                    "Node Identity"
                }
                div { class: "form-group", style: "max-width:340px;",
                    label { "Node prefix" }
                    input {
                        r#type: "text",
                        value: "{draft.read().node_prefix}",
                        placeholder: "/alice/home",
                        oninput: move |e| { draft.write().node_prefix = e.value(); dirty.set(true); },
                    }
                }
                div { style: "font-size:11px;color:var(--text-faint);margin-top:4px;",
                    "Used as base for server names (e.g. \u{3008}node-prefix\u{3009}/iperf). Leave empty to use raw prefixes."
                }
            }

            // ── Ping Server ───────────────────────────────────────────────────
            div { style: "margin-bottom:28px;",
                div { style: "font-size:12px;font-weight:600;color:var(--text);text-transform:uppercase;letter-spacing:.5px;margin-bottom:14px;border-bottom:1px solid var(--border-subtle);padding-bottom:8px;",
                    "Ping Server"
                }
                label { style: "display:flex;align-items:center;gap:8px;font-size:13px;cursor:pointer;margin-bottom:12px;",
                    input {
                        r#type: "checkbox",
                        checked: draft.read().ping_server_auto,
                        onchange: move |e| { draft.write().ping_server_auto = e.checked(); dirty.set(true); },
                    }
                    "Auto-start when router starts"
                }
                label { style: "display:flex;align-items:center;gap:8px;font-size:13px;cursor:pointer;margin-bottom:12px;",
                    input {
                        r#type: "checkbox",
                        checked: draft.read().ping_notify_connections,
                        onchange: move |e| { draft.write().ping_notify_connections = e.checked(); dirty.set(true); },
                    }
                    "Show notification when a client pings"
                }
                div { class: "form-group", style: "max-width:340px;",
                    label { "Name prefix (suffix after node prefix)" }
                    input {
                        r#type: "text",
                        value: "{draft.read().ping_prefix}",
                        placeholder: "/ping",
                        oninput: move |e| { draft.write().ping_prefix = e.value(); dirty.set(true); },
                    }
                }
            }

            // ── Iperf Server ──────────────────────────────────────────────────
            div { style: "margin-bottom:28px;",
                div { style: "font-size:12px;font-weight:600;color:var(--text);text-transform:uppercase;letter-spacing:.5px;margin-bottom:14px;border-bottom:1px solid var(--border-subtle);padding-bottom:8px;",
                    "Iperf Server"
                }
                label { style: "display:flex;align-items:center;gap:8px;font-size:13px;cursor:pointer;margin-bottom:12px;",
                    input {
                        r#type: "checkbox",
                        checked: draft.read().iperf_server_auto,
                        onchange: move |e| { draft.write().iperf_server_auto = e.checked(); dirty.set(true); },
                    }
                    "Auto-start when router starts"
                }
                label { style: "display:flex;align-items:center;gap:8px;font-size:13px;cursor:pointer;margin-bottom:16px;",
                    input {
                        r#type: "checkbox",
                        checked: draft.read().iperf_notify_connections,
                        onchange: move |e| { draft.write().iperf_notify_connections = e.checked(); dirty.set(true); },
                    }
                    "Show notification when a client connects"
                }

                label { style: "display:flex;align-items:center;gap:8px;font-size:13px;cursor:pointer;margin-bottom:10px;",
                    input {
                        r#type: "checkbox",
                        checked: draft.read().iperf_use_custom_name,
                        onchange: move |e| { draft.write().iperf_use_custom_name = e.checked(); dirty.set(true); },
                    }
                    "Override name (default: \u{3008}node-prefix\u{3009}/iperf)"
                }

                if draft.read().iperf_use_custom_name {
                    div { class: "form-group", style: "max-width:340px;margin-bottom:16px;",
                        label { "Custom prefix" }
                        input {
                            r#type: "text",
                            value: "{draft.read().iperf_custom_name}",
                            placeholder: "/my-node/iperf",
                            oninput: move |e| { draft.write().iperf_custom_name = e.value(); dirty.set(true); },
                        }
                    }
                } else {
                    div { class: "form-group", style: "max-width:340px;margin-bottom:16px;",
                        label { "Default prefix" }
                        input {
                            r#type: "text",
                            value: "{draft.read().iperf_prefix}",
                            placeholder: "/iperf",
                            oninput: move |e| { draft.write().iperf_prefix = e.value(); dirty.set(true); },
                        }
                    }
                }

                div { style: "display:grid;grid-template-columns:160px 200px;gap:12px;",
                    div { class: "form-group",
                        label { "Payload size (bytes)" }
                        input {
                            r#type: "number",
                            value: "{draft.read().iperf_size}",
                            min: "64",
                            max: "65536",
                            oninput: move |e| {
                                if let Ok(v) = e.value().parse::<u32>() {
                                    draft.write().iperf_size = v;
                                    dirty.set(true);
                                }
                            },
                        }
                    }
                    div { class: "form-group",
                        label { "Face type" }
                        select {
                            oninput: move |e| { draft.write().iperf_face_type = e.value(); dirty.set(true); },
                            option { value: "shm",  selected: draft.read().iperf_face_type == "shm",  "Shared memory (SHM)" }
                            option { value: "unix", selected: draft.read().iperf_face_type == "unix", "Unix socket" }
                            option { value: "app",  selected: draft.read().iperf_face_type == "app",  "App face" }
                        }
                    }
                }
            }

            // ── Results Table ─────────────────────────────────────────────────
            div { style: "margin-bottom:28px;",
                div { style: "font-size:12px;font-weight:600;color:var(--text);text-transform:uppercase;letter-spacing:.5px;margin-bottom:14px;border-bottom:1px solid var(--border-subtle);padding-bottom:8px;",
                    "Results Table"
                }
                div { class: "form-group", style: "max-width:220px;",
                    label { "Max entries to keep" }
                    input {
                        r#type: "number",
                        value: "{draft.read().results_max_entries}",
                        min: "10",
                        max: "1000",
                        oninput: move |e| {
                            if let Ok(v) = e.value().parse::<usize>() {
                                draft.write().results_max_entries = v;
                                dirty.set(true);
                            }
                        },
                    }
                }
            }

            // ── Save ──────────────────────────────────────────────────────────
            div { style: "display:flex;align-items:center;gap:12px;margin-bottom:32px;",
                button {
                    class: "btn btn-primary",
                    disabled: !*dirty.read(),
                    onclick: move |_| {
                        let s = draft.read().clone();
                        match save_settings(&s) {
                            Ok(()) => {
                                *DASH_SETTINGS.write() = s;
                                dirty.set(false);
                                push_toast("Settings saved", ToastLevel::Success);
                                if *ROUTER_RUNNING.read() {
                                    push_toast(
                                        "Restart the router for server changes to take effect",
                                        ToastLevel::Info,
                                    );
                                }
                            }
                            Err(e) => push_toast(format!("Save failed: {e}"), ToastLevel::Error),
                        }
                    },
                    "Save"
                }
                if *dirty.read() {
                    span { style: "font-size:12px;color:var(--yellow);", "Unsaved changes" }
                }
            }

            // ── Experimental Features ─────────────────────────────────────────
            div { style: "border-top:1px solid var(--border);padding-top:20px;",
                div { style: "font-size:12px;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:.5px;margin-bottom:14px;",
                    "Experimental Features"
                }
                div { style: "display:flex;flex-direction:column;gap:10px;",

                    label { style: "display:flex;align-items:center;gap:8px;font-size:13px;cursor:pointer;",
                        input {
                            r#type: "checkbox",
                            checked: draft.read().exp_benchmarks,
                            onchange: move |e| { draft.write().exp_benchmarks = e.checked(); dirty.set(true); },
                        }
                        "Benchmarks"
                        span { class: "badge badge-yellow", style: "font-size:10px;", "experimental" }
                    }
                    label { style: "display:flex;align-items:center;gap:8px;font-size:13px;cursor:pointer;",
                        input {
                            r#type: "checkbox",
                            checked: draft.read().exp_wasm_strategy,
                            onchange: move |e| { draft.write().exp_wasm_strategy = e.checked(); dirty.set(true); },
                        }
                        "WASM strategy engine"
                        span { class: "badge badge-yellow", style: "font-size:10px;", "experimental" }
                    }
                    label { style: "display:flex;align-items:center;gap:8px;font-size:13px;cursor:pointer;",
                        input {
                            r#type: "checkbox",
                            checked: draft.read().exp_did,
                            onchange: move |e| { draft.write().exp_did = e.checked(); dirty.set(true); },
                        }
                        "DID (Decentralized Identity)"
                        span { class: "badge badge-yellow", style: "font-size:10px;", "experimental" }
                    }
                    label { style: "display:flex;align-items:center;gap:8px;font-size:13px;cursor:pointer;",
                        input {
                            r#type: "checkbox",
                            checked: draft.read().exp_sync,
                            onchange: move |e| { draft.write().exp_sync = e.checked(); dirty.set(true); },
                        }
                        "Sync protocol"
                        span { class: "badge badge-yellow", style: "font-size:10px;", "experimental" }
                    }
                    label { style: "display:flex;align-items:center;gap:8px;font-size:13px;cursor:pointer;",
                        input {
                            r#type: "checkbox",
                            checked: draft.read().exp_embedded_tools,
                            onchange: move |e| { draft.write().exp_embedded_tools = e.checked(); dirty.set(true); },
                        }
                        "Embedded tools (no subprocess)"
                        span { class: "badge badge-yellow", style: "font-size:10px;", "experimental" }
                    }
                }
            }
        }
    }
}
