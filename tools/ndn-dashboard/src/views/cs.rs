use dioxus::prelude::*;

use crate::app::{AppCtx, DashCmd};

#[component]
pub fn ContentStore() -> Element {
    let ctx = use_context::<AppCtx>();
    let cs = ctx.cs.read();

    let mut new_cap_mb:    Signal<String> = use_signal(String::new);
    let mut erase_prefix:  Signal<String> = use_signal(String::new);

    rsx! {
        // ── Stats ────────────────────────────────────────────────────────────
        if let Some(ref info) = *cs {
            div { class: "cards",
                div { class: "card",
                    div { class: "card-label", "Capacity" }
                    div { class: "card-value", "{info.capacity_mb():.0} MB" }
                    div { class: "card-sub", "Backend: {info.variant}" }
                }
                div { class: "card",
                    div { class: "card-label", "Entries" }
                    div { class: "card-value", "{info.n_entries}" }
                    div { class: "card-sub", "{info.used_mb():.2} MB used" }
                }
                div { class: "card",
                    div { class: "card-label", "Hit Rate" }
                    div { class: "card-value", "{info.hit_rate_pct():.1}%" }
                    div { class: "card-sub", "{info.hits} hits  /  {info.misses} misses" }
                }
            }
        } else {
            div { class: "empty", "No Content Store data." }
        }

        // ── Set capacity ─────────────────────────────────────────────────────
        div { class: "section",
            div { class: "section-title", "Set Capacity" }
            div { class: "form-row",
                div { class: "form-group",
                    label { r#for: "cs-cap", "Capacity (MB)" }
                    input {
                        id: "cs-cap",
                        r#type: "number",
                        placeholder: "64",
                        value: "{new_cap_mb}",
                        style: "width:120px",
                        oninput: move |e| new_cap_mb.set(e.value()),
                    }
                }
                button {
                    class: "btn btn-primary",
                    onclick: move |_| {
                        let cap_str = new_cap_mb.read().trim().to_string();
                        if let Ok(mb) = cap_str.parse::<f64>() {
                            let bytes = (mb * 1_048_576.0) as u64;
                            ctx.cmd.send(DashCmd::CsCapacity(bytes));
                            new_cap_mb.set(String::new());
                        }
                    },
                    "Apply"
                }
            }
        }

        // ── Erase by prefix ──────────────────────────────────────────────────
        div { class: "section",
            div { class: "section-title", "Erase Entries" }
            div { class: "form-row",
                div { class: "form-group", style: "flex:1;",
                    label { r#for: "cs-erase", "Name Prefix" }
                    input {
                        id: "cs-erase",
                        r#type: "text",
                        placeholder: "/prefix/to/erase",
                        value: "{erase_prefix}",
                        oninput: move |e| erase_prefix.set(e.value()),
                    }
                }
                button {
                    class: "btn btn-danger",
                    onclick: move |_| {
                        let prefix = erase_prefix.read().trim().to_string();
                        if !prefix.is_empty() {
                            ctx.cmd.send(DashCmd::CsErase(prefix));
                            erase_prefix.set(String::new());
                        }
                    },
                    "Erase"
                }
            }
            div { style: "margin-top:8px;font-size:12px;color:var(--text-muted);",
                "Erases all cached Data packets whose name starts with the given prefix."
            }
        }
    }
}
