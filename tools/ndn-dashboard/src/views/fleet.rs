use dioxus::prelude::*;
use crate::app::{AppCtx, DashCmd};

// ── Challenge type IDs ────────────────────────────────────────────────────────

const CHALLENGE_TOKEN:      &str = "token";
const CHALLENGE_PIN:        &str = "pin";
const CHALLENGE_POSSESSION: &str = "possession";
const CHALLENGE_YUBIKEY:    &str = "yubikey-hotp";

// ── Root component ────────────────────────────────────────────────────────────

#[component]
pub fn Fleet() -> Element {
    let ctx      = use_context::<AppCtx>();
    let neighbors = ctx.neighbors.read();
    let anchors   = ctx.security_anchors.read();

    // Bootstrap form state
    let mut bootstrap_name:   Signal<String> = use_signal(String::new);
    let mut bootstrap_uri:    Signal<String> = use_signal(String::new);
    let mut bootstrap_prefix: Signal<String> = use_signal(String::new);

    // Enrollment form state
    let mut enroll_ca:        Signal<String> = use_signal(String::new);
    let mut enroll_challenge: Signal<String> = use_signal(|| CHALLENGE_TOKEN.to_string());
    let mut enroll_param:     Signal<String> = use_signal(String::new);
    // Enrollment progress: None = idle, Some(0..4) = step, Some(255) = done, Some(254) = error
    let mut enroll_step:      Signal<Option<u8>> = use_signal(|| None);
    let mut enroll_result_did: Signal<Option<String>> = use_signal(|| None);

    // Education card dismissed?
    let mut edu_dismissed: Signal<bool> = use_signal(|| false);

    rsx! {
        // ── Education snippet (B7) ───────────────────────────────────────────
        if !*edu_dismissed.read() {
            div { class: "edu-card",
                div { style: "display:flex;gap:12px;align-items:flex-start;",
                    // Animated challenge-flow snippet
                    div { class: "edu-anim", style: "flex-shrink:0;width:64px;",
                        div { class: "edu-flow-row",
                            div { class: "edu-router", "R1" }
                            div { class: "edu-arrow edu-arrow-right", "→" }
                            div { class: "edu-router edu-router-ca", "CA" }
                        }
                        div { class: "edu-flow-label", "PROBE" }
                        div { class: "edu-flow-row",
                            div { class: "edu-router", "R1" }
                            div { class: "edu-arrow edu-arrow-right edu-anim-delay1", "→" }
                            div { class: "edu-router edu-router-ca edu-cert-glow", "✓" }
                        }
                        div { class: "edu-flow-label", "CERT" }
                    }
                    div { style: "flex:1;",
                        div { style: "display:flex;justify-content:space-between;align-items:flex-start;",
                            div { style: "font-size:13px;font-weight:600;color:var(--green);margin-bottom:4px;",
                                "Bootstrap trust before routing"
                            }
                            button {
                                style: "background:none;border:none;color:var(--text-muted);cursor:pointer;font-size:13px;padding:0;",
                                onclick: move |_| edu_dismissed.set(true),
                                "✕"
                            }
                        }
                        div { style: "font-size:12px;color:var(--text-muted);line-height:1.6;",
                            "Before NDN packets can flow, both routers must "
                            strong { style: "color:var(--text);", "verify each other's identity." }
                            " Use NDNCERT to enroll your router with a CA — the CA issues a certificate "
                            "that proves your router belongs to the network. Only then will signed packets be accepted."
                        }
                    }
                }
            }
        }

        // ── Discovered Neighbors ─────────────────────────────────────────────
        div { class: "section",
            div { class: "section-title", "Discovered Neighbors" }
            if neighbors.is_empty() {
                div { class: "empty",
                    "No neighbors discovered. Enable [discovery] in the router config to use neighbor discovery."
                }
            } else {
                table {
                    thead {
                        tr {
                            th { "Node Name" }
                            th { "State" }
                            th { "RTT" }
                            th { "Last Seen" }
                            th { "Faces" }
                            th {
                                span {
                                    "data-tooltip": "Whether this neighbor's NDN name is covered by one of your trust anchors.\nTrusted neighbors can exchange signed packets that will be verified.\nUntrusted neighbors require manual trust anchor configuration.",
                                    "Trust"
                                }
                            }
                        }
                    }
                    tbody {
                        for n in neighbors.iter() {
                            {
                                let node_name = n.node_name.clone();
                                let trusted = anchors.iter().any(|a| {
                                    node_name.starts_with(&a.name) || a.name.starts_with(&node_name)
                                });
                                rsx! {
                                    tr {
                                        td { class: "mono", "{n.node_name}" }
                                        td {
                                            span { class: "{n.state_badge_class()}", "{n.state}" }
                                        }
                                        td { class: "mono",
                                            if let Some(us) = n.rtt_us {
                                                if us < 1000 {
                                                    "{us} µs"
                                                } else {
                                                    {
                                                        let ms = us as f64 / 1000.0;
                                                        rsx! { "{ms:.1} ms" }
                                                    }
                                                }
                                            } else {
                                                "—"
                                            }
                                        }
                                        td { class: "mono",
                                            if let Some(s) = n.last_seen_s {
                                                "{s:.1}s ago"
                                            } else {
                                                "—"
                                            }
                                        }
                                        td { class: "mono",
                                            {n.face_ids.iter().map(|id| id.to_string()).collect::<Vec<_>>().join(", ")}
                                        }
                                        td {
                                            if trusted {
                                                span {
                                                    class: "badge badge-green",
                                                    "data-tooltip": "This neighbor's name prefix is covered by a trust anchor.\nPackets from this node will be verified.",
                                                    "trusted"
                                                }
                                            } else {
                                                span {
                                                    class: "badge badge-gray",
                                                    "data-tooltip": "No trust anchor covers this neighbor's name.\nAdd a trust anchor in the Security tab to verify their packets.",
                                                    "untrusted"
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

        // ── Enroll with CA (B5) ──────────────────────────────────────────────
        div { class: "section",
            div { class: "section-title",
                span {
                    "data-tooltip": "Use NDNCERT to request a certificate from a Certificate Authority.\nThe CA verifies your identity via a challenge (token, PIN, possession, or YubiKey OTP)\nthen issues a certificate that lets other routers verify your signed packets.",
                    "Enroll with CA"
                }
            }

            // Enrollment progress view
            if let Some(step) = *enroll_step.read() {
                {
                    let did = enroll_result_did.read().clone();
                    rsx! {
                        EnrollProgress {
                            step,
                            result_did: did,
                            on_reset: move |_| {
                                enroll_step.set(None);
                                enroll_result_did.set(None);
                            },
                        }
                    }
                }
            } else {
                // Enrollment form
                div { style: "color:var(--text-muted);font-size:13px;margin-bottom:14px;",
                    "Request an identity certificate from an NDNCERT CA. The CA will challenge you to prove "
                    "ownership before issuing the certificate."
                }

                // CA prefix
                div { class: "form-row",
                    div { class: "form-group",
                        label {
                            span {
                                "data-tooltip": "The NDN name of the Certificate Authority.\nExample: /ndn/edu/ucla — this is where the router will send PROBE and NEW Interests.",
                                "CA Prefix (NDN name)"
                            }
                        }
                        input {
                            r#type: "text",
                            placeholder: "/ndn/edu/ucla",
                            value: "{enroll_ca}",
                            oninput: move |e| enroll_ca.set(e.value()),
                            style: "width:280px;",
                        }
                    }
                }

                // Challenge type selector
                div { style: "margin-bottom:14px;",
                    div { style: "font-size:12px;color:var(--text-muted);margin-bottom:8px;",
                        span {
                            "data-tooltip": "How the CA will verify your identity:\n• Token — pre-shared token the CA gives you out-of-band\n• PIN — numeric code (works with YubiKey HOTP)\n• Possession — prove you own an existing key\n• YubiKey HOTP — one-press OTP from a YubiKey slot 2",
                            "Challenge Type"
                        }
                    }
                    div { style: "display:flex;gap:8px;flex-wrap:wrap;",
                        for (ctype, clabel, tooltip) in [
                            (CHALLENGE_TOKEN,      "Token",       "Pre-shared token. CA operator gives you a token out-of-band."),
                            (CHALLENGE_PIN,        "PIN",         "Numeric PIN code. Works with YubiKey HOTP (slot 2 press)."),
                            (CHALLENGE_POSSESSION, "Possession",  "Prove ownership of an existing key already trusted by the CA."),
                            (CHALLENGE_YUBIKEY,    "YubiKey OTP", "One-press HMAC-SHA1 OTP from YubiKey slot 2. For headless routers."),
                        ] {
                            {
                                let ctype_s = ctype;
                                let is_active = *enroll_challenge.read() == ctype_s;
                                rsx! {
                                    button {
                                        class: if is_active { "btn btn-primary btn-sm" } else { "btn btn-secondary btn-sm" },
                                        "data-tooltip": "{tooltip}",
                                        onclick: move |_| {
                                            enroll_challenge.set(ctype_s.to_string());
                                            enroll_param.set(String::new());
                                        },
                                        "{clabel}"
                                    }
                                }
                            }
                        }
                    }
                }

                // Challenge-specific param field
                {
                    let ctype = enroll_challenge.read().clone();
                    rsx! {
                        div { class: "form-row",
                            match ctype.as_str() {
                                CHALLENGE_TOKEN => rsx! {
                                    div { class: "form-group",
                                        label { "Token (from CA operator)" }
                                        input {
                                            r#type: "text",
                                            placeholder: "e.g. abc123-token",
                                            value: "{enroll_param}",
                                            oninput: move |e| enroll_param.set(e.value()),
                                            style: "width:260px;",
                                        }
                                    }
                                },
                                CHALLENGE_PIN | CHALLENGE_YUBIKEY => rsx! {
                                    div { class: "form-group",
                                        label {
                                            if ctype == CHALLENGE_YUBIKEY {
                                                "YubiKey OTP (press button or enter 6-digit code)"
                                            } else {
                                                "PIN / OTP Code"
                                            }
                                        }
                                        input {
                                            r#type: "text",
                                            placeholder: if ctype == CHALLENGE_YUBIKEY { "Press YubiKey button…" } else { "123456" },
                                            value: "{enroll_param}",
                                            oninput: move |e| enroll_param.set(e.value()),
                                            style: "width:220px;font-family:monospace;",
                                        }
                                        if ctype == CHALLENGE_YUBIKEY {
                                            div { style: "font-size:11px;color:var(--text-muted);margin-top:4px;",
                                                "Plug in YubiKey and long-press to emit the OTP. The OTP is entered above automatically if stdin is a YubiKey HID device."
                                            }
                                        }
                                    }
                                },
                                _ => rsx! {
                                    div { class: "form-group",
                                        label { "Possession Key Name (NDN name of key to prove ownership of)" }
                                        input {
                                            r#type: "text",
                                            placeholder: "/ndn/myrouter/KEY/...",
                                            value: "{enroll_param}",
                                            oninput: move |e| enroll_param.set(e.value()),
                                            style: "width:300px;",
                                        }
                                    }
                                },
                            }
                        }
                    }
                }

                // Submit button
                div { style: "display:flex;gap:10px;align-items:center;",
                    button {
                        class: "btn btn-primary",
                        onclick: move |_| {
                            let ca = enroll_ca.read().trim().to_string();
                            if ca.is_empty() { return; }
                            let challenge = enroll_challenge.read().clone();
                            let param = enroll_param.read().clone();
                            // Start animated progress
                            enroll_step.set(Some(0));
                            ctx.cmd.send(DashCmd::SecurityEnroll {
                                ca_prefix: ca,
                                challenge_type: challenge,
                                challenge_param: param,
                            });
                            // Simulate protocol steps (real IPC is async; for now advance UI)
                            // When real IPC lands, this becomes a coroutine watching for status.
                        },
                        "Enroll →"
                    }
                    div { style: "font-size:11px;color:var(--text-muted);",
                        "Sends PROBE → NEW → CHALLENGE to the CA prefix via the NDN router."
                    }
                }
            }
        }

        // ── Bootstrap New Device ─────────────────────────────────────────────
        div { class: "section",
            div { class: "section-title", "Bootstrap New Device" }
            div { style: "color:var(--text-muted);font-size:13px;margin-bottom:14px;",
                "Create a face to a peer and register a route — bootstraps a new router into the network."
            }
            div { class: "form-row",
                div { class: "form-group",
                    label { "Peer Face URI (e.g. udp4://192.168.1.5:6363)" }
                    input {
                        r#type: "text",
                        placeholder: "udp4://192.168.1.5:6363",
                        value: "{bootstrap_uri}",
                        oninput: move |e| bootstrap_uri.set(e.value()),
                        style: "width:280px;",
                    }
                }
                div { class: "form-group",
                    label { "Route Prefix (NDN name, e.g. /ndn/site)" }
                    input {
                        r#type: "text",
                        placeholder: "/ndn/site",
                        value: "{bootstrap_prefix}",
                        oninput: move |e| bootstrap_prefix.set(e.value()),
                        style: "width:220px;",
                    }
                }
                div { class: "form-group",
                    label { "Node Name (optional label)" }
                    input {
                        r#type: "text",
                        placeholder: "/ndn/site/router-A",
                        value: "{bootstrap_name}",
                        oninput: move |e| bootstrap_name.set(e.value()),
                        style: "width:220px;",
                    }
                }
                button {
                    class: "btn btn-primary",
                    onclick: move |_| {
                        let uri = bootstrap_uri.read().trim().to_string();
                        let prefix = bootstrap_prefix.read().trim().to_string();
                        if !uri.is_empty() {
                            ctx.cmd.send(DashCmd::FaceCreate(uri.clone()));
                        }
                        if !prefix.is_empty() && !uri.is_empty() {
                            ctx.cmd.send(DashCmd::RouteAdd { prefix: prefix.clone(), face_id: 0, cost: 0 });
                        }
                        bootstrap_uri.set(String::new());
                        bootstrap_prefix.set(String::new());
                        bootstrap_name.set(String::new());
                    },
                    "Bootstrap"
                }
            }
            div { style: "color:var(--text-muted);font-size:11px;margin-top:10px;",
                "Note: Creates the face first, then registers the route. Face ID is resolved automatically from the management connection."
            }
        }
    }
}

// ── Enrollment progress component ─────────────────────────────────────────────

#[component]
fn EnrollProgress(
    step: u8,
    result_did: Option<String>,
    on_reset: EventHandler<()>,
) -> Element {
    let is_done  = step == 255;
    let is_error = step == 254;

    rsx! {
        div { style: "background:var(--bg);border:1px solid var(--border-subtle);border-radius:8px;padding:16px;",
            // Protocol steps
            div { style: "display:flex;gap:0;margin-bottom:16px;",
                EnrollStepDot { i: 0, current: step, is_done, is_error, label: "PROBE",     desc: "Discover CA capabilities" }
                EnrollStepDot { i: 1, current: step, is_done, is_error, label: "NEW",       desc: "ECDH key exchange" }
                EnrollStepDot { i: 2, current: step, is_done, is_error, label: "CHALLENGE", desc: "Submit challenge response" }
                EnrollStepDot { i: 3, current: step, is_done, is_error, label: "DONE",      desc: "Certificate issued" }
            }

            if is_done {
                div { style: "text-align:center;padding:16px 0;",
                    div { style: "font-size:28px;margin-bottom:8px;", "✅" }
                    div { style: "font-size:14px;font-weight:600;color:var(--green);margin-bottom:6px;",
                        "Certificate Issued!"
                    }
                    if let Some(ref did) = result_did {
                        div { style: "font-size:11px;color:var(--purple);font-family:monospace;margin-bottom:12px;",
                            "{did}"
                        }
                    }
                    div { style: "font-size:12px;color:var(--text-muted);margin-bottom:14px;",
                        "Your identity certificate has been installed in the PIB. "
                        "Other routers can now verify your signed packets."
                    }
                    button {
                        class: "btn btn-secondary btn-sm",
                        onclick: move |_| on_reset.call(()),
                        "Enroll Another"
                    }
                }
            } else if is_error {
                div { style: "text-align:center;padding:12px 0;",
                    div { style: "font-size:28px;margin-bottom:8px;", "❌" }
                    div { style: "font-size:13px;color:var(--red);margin-bottom:10px;",
                        "Enrollment failed. Check the CA prefix and challenge parameters."
                    }
                    button {
                        class: "btn btn-secondary btn-sm",
                        onclick: move |_| on_reset.call(()),
                        "Try Again"
                    }
                }
            } else {
                div { style: "text-align:center;padding:8px 0;",
                    {
                        let step_label = ["PROBE", "NEW", "CHALLENGE", "DONE"]
                            .get(step as usize).copied().unwrap_or("");
                        rsx! {
                            div { style: "font-size:12px;color:var(--text-muted);",
                                "Step {step + 1} of 4 — {step_label} in progress…"
                            }
                        }
                    }
                    div { style: "font-size:11px;color:var(--text-muted);margin-top:4px;",
                        "Note: enrollment IPC is pending — this UI preview shows the protocol flow."
                    }
                    button {
                        class: "btn btn-secondary btn-sm",
                        style: "margin-top:10px;",
                        onclick: move |_| on_reset.call(()),
                        "Cancel"
                    }
                }
            }
        }
    }
}

#[component]
fn EnrollStepDot(
    i: u8,
    current: u8,
    is_done: bool,
    is_error: bool,
    label: &'static str,
    desc: &'static str,
) -> Element {
    let done_color  = "var(--green)";
    let idle_color  = "var(--border)";

    let left_color  = if i > 0 && (i <= current || is_done) { done_color } else { idle_color };
    let right_color = if i < 3 && (i < current || is_done)  { done_color } else { idle_color };

    let dot_class = if is_done || i < current {
        "enroll-step-dot done"
    } else if is_error && i == current {
        "enroll-step-dot error"
    } else if i == current {
        "enroll-step-dot active"
    } else {
        "enroll-step-dot"
    };

    rsx! {
        div { style: "flex:1;text-align:center;",
            div { style: "display:flex;align-items:center;",
                if i > 0 {
                    div { style: "flex:1;height:1px;background:{left_color};" }
                }
                div { class: "{dot_class}", style: "margin:0 auto;" }
                if i < 3 {
                    div { style: "flex:1;height:1px;background:{right_color};" }
                }
            }
            div { style: "font-size:10px;font-weight:600;color:var(--text);margin-top:4px;", "{label}" }
            div { style: "font-size:9px;color:var(--text-muted);margin-top:2px;max-width:80px;margin-left:auto;margin-right:auto;", "{desc}" }
        }
    }
}
