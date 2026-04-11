use dioxus::prelude::*;
use crate::app::{AppCtx, DashCmd};

// ── Routing view ──────────────────────────────────────────────────────────────
//
// Shows routing protocol status and runtime configuration.
// Currently supports the DVR (Distance Vector Routing) protocol.

#[component]
pub fn Routing() -> Element {
    let ctx = use_context::<AppCtx>();
    let dvr_status = ctx.dvr_status.read();

    // DVR config form state (initialise from live status when available)
    let mut dvr_update_ms: Signal<String> = use_signal(|| {
        dvr_status.as_ref().map(|d| d.update_interval_ms.to_string()).unwrap_or_default()
    });
    let mut dvr_ttl_ms: Signal<String> = use_signal(|| {
        dvr_status.as_ref().map(|d| d.route_ttl_ms.to_string()).unwrap_or_default()
    });
    let mut dvr_error: Signal<Option<String>> = use_signal(|| None);

    rsx! {
        // ── DVR Protocol ────────────────────────────────────────────────────
        div { class: "section",
            div { class: "section-title", "Distance Vector Routing (DVR)" }

            if let Some(ref dvr) = *dvr_status {
                // Status cards
                div { style: "display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:12px;margin-bottom:20px;",
                    div { class: "stat-card",
                        div { class: "stat-label", "DVR Routes" }
                        div { class: "stat-value", "{dvr.route_count}" }
                    }
                    div { class: "stat-card",
                        div { class: "stat-label", "Update Interval" }
                        div { class: "stat-value",
                            {
                                let s = dvr.update_interval_ms / 1000;
                                rsx! { "{s} s" }
                            }
                        }
                    }
                    div { class: "stat-card",
                        div { class: "stat-label", "Route TTL" }
                        div { class: "stat-value",
                            {
                                let s = dvr.route_ttl_ms / 1000;
                                rsx! { "{s} s" }
                            }
                        }
                    }
                }

                // DVR config form
                div { class: "form-row",
                    label { class: "form-label",
                        "Update interval (ms)"
                        span { class: "form-hint", " — how often DVR broadcasts its distance vector" }
                    }
                    input {
                        r#type: "number",
                        class: "form-input",
                        min: "1000",
                        step: "1000",
                        value: "{dvr_update_ms}",
                        oninput: move |e| dvr_update_ms.set(e.value()),
                    }
                }
                div { class: "form-row",
                    label { class: "form-label",
                        "Route TTL (ms)"
                        span { class: "form-hint", " — time before a DVR-learned route expires if not refreshed" }
                    }
                    input {
                        r#type: "number",
                        class: "form-input",
                        min: "1000",
                        step: "1000",
                        value: "{dvr_ttl_ms}",
                        oninput: move |e| dvr_ttl_ms.set(e.value()),
                    }
                }

                if let Some(ref err) = *dvr_error.read() {
                    div { class: "error-banner", style: "margin-bottom:8px;", "{err}" }
                }

                button {
                    class: "btn btn-primary btn-sm",
                    onclick: move |_| {
                        let update_ms = dvr_update_ms.read().trim().to_string();
                        let ttl_ms    = dvr_ttl_ms.read().trim().to_string();
                        if update_ms.is_empty() || ttl_ms.is_empty() {
                            dvr_error.set(Some("Both fields are required".into()));
                            return;
                        }
                        match (update_ms.parse::<u64>(), ttl_ms.parse::<u64>()) {
                            (Ok(u), Ok(t)) if u >= 1000 && t >= 1000 => {
                                dvr_error.set(None);
                                ctx.cmd.send(DashCmd::DvrConfigSet(
                                    format!("update_interval_ms={u}&route_ttl_ms={t}")
                                ));
                            }
                            _ => dvr_error.set(Some("Values must be positive integers ≥ 1000".into())),
                        }
                    },
                    "Apply DVR Config"
                }
            } else {
                div { class: "empty",
                    "DVR routing is not active. Enable [routing] dvr = true in the router config."
                }
            }
        }

        // ── Static / other protocols ──────────────────────────────────────────
        div { class: "section",
            div { class: "section-title", "Static Routes" }
            div { style: "font-size:13px;color:var(--text-muted);",
                "Static routes are configured at startup via the router config file. "
                "To add or remove them at runtime use the "
                strong { "Overview → Routes" }
                " tab."
            }
        }
    }
}
