use dioxus::prelude::*;

use crate::app::{AppCtx, DashCmd};

#[component]
pub fn Session() -> Element {
    let ctx = use_context::<AppCtx>();
    let log = ctx.session_log.read();

    rsx! {
        div { class: "section",
            div { style: "display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;",
                div { class: "section-title", "Command Session" }
                div { style: "display:flex;gap:8px;",
                    if *ctx.recording.read() {
                        button {
                            class: "btn btn-danger btn-sm",
                            onclick: move |_| ctx.cmd.send(DashCmd::RecordStop),
                            "■ Stop Recording"
                        }
                    } else {
                        button {
                            class: "btn btn-primary btn-sm",
                            onclick: move |_| ctx.cmd.send(DashCmd::RecordStart),
                            "● Record"
                        }
                    }
                    button {
                        class: "btn btn-secondary btn-sm",
                        disabled: log.is_empty(),
                        onclick: move |_| ctx.cmd.send(DashCmd::RecordClear),
                        "Clear"
                    }
                    button {
                        class: "btn btn-secondary btn-sm",
                        disabled: log.is_empty(),
                        onclick: move |_| ctx.cmd.send(DashCmd::ReplaySession),
                        "▶ Replay"
                    }
                }
            }

            if *ctx.recording.read() {
                div { style: "background:var(--green-bg);border:1px solid var(--green);border-radius:4px;padding:8px 12px;margin-bottom:12px;font-size:12px;color:var(--green);",
                    "● Recording — management commands are being logged"
                }
            }

            if log.is_empty() {
                div { class: "empty", "No commands recorded yet. Press Record, then perform operations in other tabs." }
            } else {
                table {
                    thead {
                        tr {
                            th { "#" }
                            th { "Command" }
                            th { "Parameters" }
                        }
                    }
                    tbody {
                        for (i, entry) in log.iter().enumerate() {
                            tr {
                                td { class: "mono", style: "color:var(--text-muted);", "{i + 1}" }
                                td { class: "mono", "{entry.kind}" }
                                td { class: "mono", style: "color:var(--text-muted);", "{entry.params}" }
                            }
                        }
                    }
                }

                // Export JSON
                div { style: "margin-top:12px;",
                    details {
                        summary { style: "cursor:pointer;font-size:12px;color:var(--text-muted);", "Export as JSON" }
                        textarea {
                            style: "width:100%;height:200px;background:var(--bg);border:1px solid var(--border);color:var(--text);font-family:'SF Mono',monospace;font-size:11px;padding:8px;border-radius:4px;margin-top:8px;",
                            readonly: true,
                            value: "{session_to_json(&log)}",
                        }
                    }
                }
            }

            div { style: "margin-top:12px;font-size:12px;color:var(--text-muted);",
                "Recorded sessions can be replayed to restore router configuration after a restart."
            }
        }
    }
}

fn session_to_json(log: &[crate::types::SessionEntry]) -> String {
    let entries: Vec<String> = log.iter().map(|e| {
        format!("  {{\"cmd\": {:?}, \"params\": {:?}}}", e.kind, e.params)
    }).collect();
    format!("{{\n  \"version\": 1,\n  \"commands\": [\n{}\n  ]\n}}", entries.join(",\n"))
}
