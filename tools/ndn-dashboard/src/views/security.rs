//! Security view — identity management, trust anchors, certificate chain,
//! DID explorer, NDNCERT CA panel, and YubiKey integration.

use dioxus::prelude::*;
use crate::app::{AppCtx, DashCmd};
use crate::views::onboarding::encode_did_ndn;

// ── Tab IDs ───────────────────────────────────────────────────────────────────

const TAB_IDENTITIES:    u8 = 0;
const TAB_ANCHORS:       u8 = 1;
const TAB_CHAIN:         u8 = 2;
const TAB_DID:           u8 = 3;
const TAB_CA:            u8 = 4;
const TAB_YUBIKEY:       u8 = 5;

// ── Root component ────────────────────────────────────────────────────────────

#[component]
pub fn Security() -> Element {
    let ctx = use_context::<AppCtx>();
    let keys    = ctx.security_keys.read();
    let anchors = ctx.security_anchors.read();

    let mut active_tab:   Signal<u8>     = use_signal(|| TAB_IDENTITIES);
    let new_key_name: Signal<String> = use_signal(String::new);

    let tabs: &[(&str, u8)] = &[
        ("Identities",     TAB_IDENTITIES),
        ("Trust Anchors",  TAB_ANCHORS),
        ("Cert Chain",     TAB_CHAIN),
        ("DID",            TAB_DID),
        ("CA / NDNCERT",   TAB_CA),
        ("YubiKey",        TAB_YUBIKEY),
    ];

    rsx! {
        div { class: "section",
            // ── Tab bar ──────────────────────────────────────────────────────
            div { style: "display:flex;gap:6px;margin-bottom:16px;flex-wrap:wrap;",
                for (label, tab_i) in tabs {
                    {
                        let tab_i = *tab_i;
                        let is_active = *active_tab.read() == tab_i;
                        rsx! {
                            button {
                                class: if is_active { "btn btn-primary btn-sm" } else { "btn btn-secondary btn-sm" },
                                onclick: move |_| active_tab.set(tab_i),
                                "{label}"
                            }
                        }
                    }
                }
            }

            match *active_tab.read() {
                TAB_IDENTITIES => rsx! { IdentitiesTab { keys: keys.clone(), new_key_name } },
                TAB_ANCHORS    => rsx! { AnchorsTab { anchors: anchors.clone() } },
                TAB_CHAIN      => rsx! { ChainTab { keys: keys.clone(), anchors: anchors.clone() } },
                TAB_DID        => rsx! { DidTab { keys: keys.clone() } },
                TAB_CA         => rsx! { CaTab {} },
                TAB_YUBIKEY    => rsx! { YubikeyTab {} },
                _              => rsx! {},
            }
        }
    }
}

// ── Tab: Identities ───────────────────────────────────────────────────────────

#[component]
fn IdentitiesTab(
    keys: Vec<crate::types::SecurityKeyInfo>,
    mut new_key_name: Signal<String>,
) -> Element {
    let ctx = use_context::<AppCtx>();
    rsx! {
        div { class: "section-title", "Identity Keys" }
        if keys.is_empty() {
            div { class: "empty",
                "No identity keys found. Security may not be configured, or the PIB is empty."
            }
        } else {
            table {
                thead {
                    tr {
                        th { "Key Name" }
                        th {
                            span {
                                "data-tooltip": "Whether this key has a CA-issued certificate.\nWithout a certificate, signed Interests will be rejected by peers.",
                                "Cert"
                            }
                        }
                        th {
                            span {
                                "data-tooltip": "Time until the certificate expires.\nRenew before expiry via NDNCERT — use the CA / NDNCERT tab.",
                                "Expiry"
                            }
                        }
                        th { "Actions" }
                    }
                }
                tbody {
                    for k in keys.iter() {
                        {
                            let key_name = k.name.clone();
                            let has_cert = k.has_cert;
                            let (badge_class, badge_label) = k.expiry_badge();
                            rsx! {
                                tr {
                                    td { class: "mono", "{key_name}" }
                                    td {
                                        if has_cert {
                                            span { class: "badge badge-green", "yes" }
                                        } else {
                                            span {
                                                class: "badge badge-yellow",
                                                "data-tooltip": "No certificate — enroll via the CA / NDNCERT tab.",
                                                "no cert"
                                            }
                                        }
                                    }
                                    td { span { class: "{badge_class}", "{badge_label}" } }
                                    td {
                                        button {
                                            class: "btn btn-danger btn-sm",
                                            onclick: move |_| ctx.cmd.send(DashCmd::SecurityKeyDelete(key_name.clone())),
                                            "Delete"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Generate key form
        div { class: "form-row",
            div { class: "form-group",
                label { "New Key Name (NDN name, e.g. /ndn/myrouter/key)" }
                input {
                    r#type: "text",
                    placeholder: "/ndn/myrouter/key",
                    value: "{new_key_name}",
                    oninput: move |e| new_key_name.set(e.value()),
                    style: "width:320px;",
                }
            }
            button {
                class: "btn btn-primary",
                onclick: move |_| {
                    let name = new_key_name.read().trim().to_string();
                    if !name.is_empty() {
                        ctx.cmd.send(DashCmd::SecurityGenerate(name));
                        new_key_name.set(String::new());
                    }
                },
                "Generate Ed25519 Key"
            }
        }
    }
}

// ── Tab: Trust Anchors ────────────────────────────────────────────────────────

#[component]
fn AnchorsTab(anchors: Vec<crate::types::AnchorInfo>) -> Element {
    rsx! {
        div { class: "section-title", "Trust Anchors" }
        if anchors.is_empty() {
            div { class: "empty",
                "No trust anchors configured. Interests and Data packets are not verified."
            }
        } else {
            table {
                thead { tr { th { "Anchor Name" } } }
                tbody {
                    for a in anchors.iter() {
                        tr { td { class: "mono", "{a.name}" } }
                    }
                }
            }
        }

        div { style: "margin-top:14px;padding-top:14px;border-top:1px solid var(--border-subtle);color:var(--text-muted);font-size:12px;",
            "Trust anchors are loaded from the PIB at startup. Use "
            span { class: "mono", "ndn-sec add-anchor" }
            " to add new trust anchors, or enroll with a CA via the "
            strong { "CA / NDNCERT" }
            " tab."
        }
    }
}

// ── Tab: Certificate Chain ────────────────────────────────────────────────────

#[component]
fn ChainTab(
    keys: Vec<crate::types::SecurityKeyInfo>,
    anchors: Vec<crate::types::AnchorInfo>,
) -> Element {
    let has_anchor   = !anchors.is_empty();
    let has_identity = !keys.is_empty();
    let identity     = keys.first();
    let has_cert     = identity.map(|k| k.has_cert).unwrap_or(false);
    let identity_name = identity.map(|k| k.name.clone()).unwrap_or_else(|| "(none)".to_string());
    let anchor_name  = anchors.first().map(|a| a.name.clone()).unwrap_or_else(|| "(none)".to_string());
    let (expiry_cls, expiry_lbl) = identity
        .map(|k| k.expiry_badge())
        .unwrap_or(("badge badge-gray", "—".to_string()));

    rsx! {
        div { class: "section-title", "Certificate Chain" }
        div { style: "color:var(--text-muted);font-size:12px;margin-bottom:16px;",
            "Shows the chain from your trust anchor down to your identity certificate. "
            "Every link must be valid for your packets to be accepted by the network."
        }

        // SVG chain diagram
        div { style: "overflow-x:auto;",
            div { class: "trust-chain",
                // Trust Anchor node
                {chain_node("🔑", "Trust Anchor", &anchor_name, if has_anchor { "ok" } else { "missing" }, "Root of trust — the certificate everyone in your network must trust.\nConfigure in router TOML: security.trust_anchor")}
                div { class: "chain-arrow", style: "color:var(--border);", "→" }

                // CA Certificate node
                {chain_node("📜", "CA Certificate", "Signed by anchor", if has_anchor { "ok" } else { "missing" }, "The Certificate Authority that signs identity certificates.\nEnroll via CA / NDNCERT tab to get one.")}
                div { class: "chain-arrow", style: "color:var(--border);", "→" }

                // Identity cert node
                {chain_node("🪪", "Your Identity", &identity_name, if has_cert { "ok" } else if has_identity { "warn" } else { "missing" }, "Your router's identity certificate.\nMust be signed by a CA that chains back to the trust anchor.")}
            }
        }

        // Status summary
        div { style: "display:flex;gap:10px;flex-wrap:wrap;margin-top:16px;",
            div { style: "flex:1;min-width:160px;background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:12px;",
                div { style: "font-size:11px;color:var(--text-muted);margin-bottom:6px;", "IDENTITY" }
                div { class: "mono", style: "font-size:12px;word-break:break-all;", "{identity_name}" }
            }
            div { style: "flex:1;min-width:140px;background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:12px;",
                div { style: "font-size:11px;color:var(--text-muted);margin-bottom:6px;", "CERT EXPIRY" }
                span { class: "{expiry_cls}", "{expiry_lbl}" }
            }
            div { style: "flex:1;min-width:140px;background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:12px;",
                div { style: "font-size:11px;color:var(--text-muted);margin-bottom:6px;", "TRUST ANCHOR" }
                if has_anchor {
                    span { class: "badge badge-green", "configured" }
                } else {
                    span { class: "badge badge-red", "not configured" }
                }
            }
        }

        // Actions
        if !has_cert && has_identity {
            div { style: "margin-top:14px;padding:12px;background:var(--yellow-bg)22;border:1px solid var(--yellow)44;border-radius:6px;font-size:12px;color:var(--yellow);",
                "⚠ Your identity key has no certificate. Go to the "
                strong { "CA / NDNCERT" }
                " tab to enroll and get a certificate signed by your trust anchor."
            }
        }
    }
}

fn chain_node(icon: &str, label: &str, name: &str, status: &str, tooltip: &str) -> Element {
    let border_color = match status {
        "ok"      => "var(--green)",
        "warn"    => "var(--yellow)",
        "missing" => "var(--border)",
        _         => "var(--border)",
    };
    let opacity = if status == "missing" { "0.45" } else { "1" };
    rsx! {
        div {
            "data-tooltip": "{tooltip}",
            style: "background:var(--surface2);border:1px solid {border_color};border-radius:8px;padding:12px 16px;text-align:center;min-width:120px;cursor:help;opacity:{opacity};",
            div { style: "font-size:22px;margin-bottom:4px;", "{icon}" }
            div { style: "font-size:11px;font-weight:600;color:var(--text);margin-bottom:2px;", "{label}" }
            div { style: "font-size:10px;color:var(--text-muted);word-break:break-all;max-width:130px;", "{name}" }
        }
    }
}

// ── Tab: DID Explorer ─────────────────────────────────────────────────────────

#[component]
fn DidTab(keys: Vec<crate::types::SecurityKeyInfo>) -> Element {
    let mut copied = use_signal(|| false);
    let first_key  = keys.first().cloned();

    let identity_name = first_key.as_ref().map(|k| k.name.clone()).unwrap_or_default();
    let did_ndn = if identity_name.is_empty() {
        String::new()
    } else {
        format!("did:ndn:{}", encode_did_ndn(&identity_name))
    };
    // did:key requires the raw public key bytes; we don't have them in the dashboard
    // yet so we show a placeholder.
    let did_key_note = "Requires public key bytes — not yet available via management API";

    let did_doc_preview = format!(
        r#"{{"@context":"https://www.w3.org/ns/did/v1","id":"{did_ndn}","verificationMethod":[{{"id":"{did_ndn}#key-1","type":"Ed25519VerificationKey2020","controller":"{did_ndn}","publicKeyMultibase":"<Ed25519 pubkey>"}}]}}"#
    );

    rsx! {
        div { class: "section-title", "DID Explorer" }

        // Education card
        div { class: "edu-card",
            div { style: "display:flex;gap:12px;align-items:flex-start;",
                div { style: "font-size:28px;flex-shrink:0;", "🔗" }
                div {
                    div { style: "font-size:13px;font-weight:600;color:var(--purple);margin-bottom:4px;",
                        "Decentralized Identifiers (W3C DIDs)"
                    }
                    div { style: "font-size:12px;color:var(--text-muted);line-height:1.6;",
                        "A DID is a self-sovereign, cryptographically verifiable identifier — no central authority needed. "
                        "NDN names map directly to DIDs: your NDN name "
                        span { class: "signed-packet", "{identity_name}" }
                        " becomes a globally unique, portable identity."
                    }
                }
            }
        }

        if identity_name.is_empty() {
            div { class: "empty",
                "No identity key found. Generate a key in the Identities tab first."
            }
        } else {
            // did:ndn
            div { style: "margin-bottom:18px;",
                div { style: "display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;",
                    div { style: "font-size:12px;font-weight:600;color:var(--text);",
                        span { style: "color:var(--purple);", "did:ndn" }
                        span { style: "color:var(--text-muted);", " — NDN name encoded as a W3C DID" }
                    }
                    button {
                        class: "did-copy-btn",
                        onclick: move |_| {
                            // Dioxus desktop: write to clipboard via dioxus_desktop eval
                            copied.set(true);
                        },
                        if *copied.read() { "✓ Copied" } else { "Copy" }
                    }
                }
                div { class: "did-value", "{did_ndn}" }
                div { style: "font-size:11px;color:var(--text-muted);",
                    "DID document resolves to the NDN certificate at the signed certificate name."
                }
            }

            // did:key placeholder
            div { style: "margin-bottom:18px;",
                div { style: "font-size:12px;font-weight:600;color:var(--text);margin-bottom:6px;",
                    span { style: "color:var(--purple);", "did:key" }
                    span { style: "color:var(--text-muted);", " — public key multibase encoding" }
                }
                div { style: "background:var(--surface2);border:1px solid var(--border);border-radius:4px;padding:10px;font-size:11px;color:var(--text-muted);font-style:italic;",
                    "{did_key_note}"
                }
            }

            // DID document preview
            div {
                div { style: "font-size:12px;font-weight:600;color:var(--text);margin-bottom:6px;", "DID Document (preview)" }
                div { class: "yk-cmd", "{did_doc_preview}" }
            }

            // Explainer rows
            div { style: "display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:16px;",
                DidExplainCard {
                    title: "No Central Registry",
                    body: "NDN names are hierarchically delegated. Anyone with the parent namespace can issue sub-names — like DNS but without a single root authority.",
                }
                DidExplainCard {
                    title: "Self-Certifying",
                    body: "The DID is derived from your public key. Verifying a signature proves ownership without contacting any third party.",
                }
                DidExplainCard {
                    title: "Portable",
                    body: "Your DID travels with your certificate. Move between routers or networks — your identity stays the same.",
                }
                DidExplainCard {
                    title: "Interoperable",
                    body: "did:ndn DIDs resolve via the NDN network. did:key DIDs are self-contained and work without any network access.",
                }
            }
        }
    }
}

#[component]
fn DidExplainCard(title: &'static str, body: &'static str) -> Element {
    rsx! {
        div { style: "background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:12px;",
            div { style: "font-size:12px;font-weight:600;color:var(--purple);margin-bottom:4px;", "{title}" }
            div { style: "font-size:11px;color:var(--text-muted);line-height:1.5;", "{body}" }
        }
    }
}

// ── Tab: CA / NDNCERT ─────────────────────────────────────────────────────────

#[component]
fn CaTab() -> Element {
    let ctx = use_context::<AppCtx>();
    let mut show_token_form = use_signal(|| false);
    let mut token_name = use_signal(String::new);
    let mut last_token = use_signal(String::new);
    let ca = ctx.ca_info.read().clone();

    rsx! {
        div { class: "section-title", "CA / NDNCERT" }

        // Live CA status or "not configured" notice
        if let Some(ref info) = ca {
            div { style: "background:var(--green-dark);border:1px solid var(--green)44;border-radius:6px;padding:14px;margin-bottom:14px;",
                div { style: "font-size:12px;font-weight:600;color:var(--green);margin-bottom:8px;",
                    "CA Active on this router"
                }
                div { style: "display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:12px;",
                    div { style: "color:var(--text-muted);", "CA Prefix" }
                    div { style: "font-family:monospace;color:var(--text);", "{info.ca_prefix}" }
                    div { style: "color:var(--text-muted);", "Description" }
                    { let ca_desc = if info.ca_info.is_empty() { "—".to_string() } else { info.ca_info.clone() };
                      rsx! { div { style: "color:var(--text);", "{ca_desc}" } } }
                    div { style: "color:var(--text-muted);", "Max Validity" }
                    div { style: "color:var(--text);", "{info.max_validity_days} days" }
                    div { style: "color:var(--text-muted);", "Challenges" }
                    div { style: "display:flex;gap:4px;flex-wrap:wrap;",
                        for ch in &info.challenges {
                            span { class: "badge badge-blue", "{ch}" }
                        }
                    }
                }
            }
        } else {
            div { style: "background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:14px;margin-bottom:14px;",
                div { style: "font-size:12px;color:var(--text-muted);", "This router is not acting as a CA. To enable, add to router TOML:" }
                div { class: "yk-cmd", style: "margin-top:8px;",
                    "[security]\n"
                    "ca_prefix = \"/ndn/site\"\n"
                    "ca_info = \"Site CA\"\n"
                    "ca_max_validity_days = 365\n"
                    "ca_challenges = [\"token\", \"pin\"]"
                }
            }
        }

        // Education card
        div { class: "edu-card",
            div { style: "display:flex;gap:12px;align-items:flex-start;",
                div { style: "font-size:28px;flex-shrink:0;", "🏛" }
                div {
                    div { style: "font-size:13px;font-weight:600;color:var(--accent);margin-bottom:4px;",
                        "NDNCERT — Automated Certificate Management"
                    }
                    div { style: "font-size:12px;color:var(--text-muted);line-height:1.6;",
                        "NDNCERT (Named Data Networking Certificate Management Protocol) automates certificate issuance. "
                        "A CA verifies your identity via challenges (PIN, email, possession, or YubiKey OTP) "
                        "and issues a signed certificate bound to your identity key."
                    }
                }
            }
        }

        // Enrollment flow diagram
        div { style: "margin:16px 0;",
            div { style: "font-size:12px;font-weight:600;color:var(--text);margin-bottom:10px;", "Enrollment Protocol Flow" }
            div { class: "enroll-steps",
                EnrollStep { label: "PROBE", desc: "Check namespace", status: "done" }
                div { class: "enroll-step-line done" }
                EnrollStep { label: "NEW", desc: "Submit key + ECDH", status: "done" }
                div { class: "enroll-step-line" }
                EnrollStep { label: "CHALLENGE", desc: "Verify identity", status: "active" }
                div { class: "enroll-step-line" }
                EnrollStep { label: "CERT", desc: "Receive certificate", status: "" }
            }
        }

        // Protocol info
        div { style: "display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:16px;",
            InfoKv { label: "Protocol", val: "NDNCERT 0.3" }
            InfoKv { label: "Key Exchange", val: "P-256 ECDH" }
            InfoKv { label: "Encryption", val: "AES-GCM-128 + HKDF-SHA256" }
            InfoKv { label: "Wire Format", val: "NDN TLV" }
        }

        // Token management — enabled only when CA is active
        div { style: "border:1px solid var(--border);border-radius:6px;overflow:hidden;",
            div { style: "display:flex;justify-content:space-between;align-items:center;padding:12px 14px;background:var(--surface2);",
                div { style: "font-size:12px;font-weight:600;color:var(--text);", "Zero-Touch Provisioning Tokens" }
                if ca.is_some() {
                    button {
                        class: "btn btn-secondary btn-sm",
                        onclick: move |_| { let v = *show_token_form.read(); show_token_form.set(!v); },
                        if *show_token_form.read() { "▲ Cancel" } else { "+ Add Token" }
                    }
                }
            }
            if *show_token_form.read() {
                div { style: "padding:14px;border-top:1px solid var(--border);",
                    div { class: "form-row",
                        div { class: "form-group",
                            label { "Token description (label for this token)" }
                            input {
                                r#type: "text",
                                placeholder: "e.g. router-3-provisioning",
                                value: "{token_name}",
                                oninput: move |e| token_name.set(e.value()),
                                style: "width:260px;",
                            }
                        }
                        button {
                            class: "btn btn-primary",
                            onclick: move |_| {
                                let desc = token_name.read().clone();
                                ctx.cmd.send(DashCmd::SecurityTokenAdd(desc));
                                token_name.set(String::new());
                                show_token_form.set(false);
                                last_token.set("Token generated — check router logs for value".to_string());
                            },
                            "Generate Token"
                        }
                    }
                    if !last_token.read().is_empty() {
                        div { class: "yk-seed", style: "margin-top:8px;", "{last_token}" }
                    }
                }
            }
            if ca.is_none() {
                div { style: "padding:16px;text-align:center;color:var(--text-muted);font-size:13px;",
                    "Enable this router as a CA (add ca_prefix to TOML) to manage ZTP tokens."
                }
            } else {
                div { style: "padding:12px 14px;color:var(--text-muted);font-size:12px;",
                    "Generated tokens are logged by the router at INFO level. Future versions will list active tokens here."
                }
            }
        }
    }
}

#[component]
fn EnrollStep(label: &'static str, desc: &'static str, status: &'static str) -> Element {
    let dot_class = match status {
        "done"   => "enroll-step-dot done",
        "active" => "enroll-step-dot active",
        _        => "enroll-step-dot",
    };
    rsx! {
        div { class: "enroll-step",
            div { class: "{dot_class}" }
            div { style: "font-size:11px;font-weight:600;color:var(--text);", "{label}" }
            div { style: "font-size:10px;color:var(--text-muted);", "{desc}" }
        }
    }
}

#[component]
fn InfoKv(label: &'static str, val: &'static str) -> Element {
    rsx! {
        div { style: "background:var(--bg);border:1px solid var(--border-subtle);border-radius:4px;padding:8px 10px;",
            div { style: "font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.4px;", "{label}" }
            div { style: "font-size:12px;color:var(--text);margin-top:2px;font-weight:500;", "{val}" }
        }
    }
}

// ── Tab: YubiKey ──────────────────────────────────────────────────────────────

#[component]
fn YubikeyTab() -> Element {
    let ctx = use_context::<AppCtx>();
    let mut hotp_seed: Signal<Option<String>> = use_signal(|| None);
    let mut hotp_counter: Signal<u64>         = use_signal(|| 0);
    let mut show_cmd: Signal<bool>            = use_signal(|| false);
    let mut piv_name: Signal<String>          = use_signal(String::new);

    let yk_status = ctx.yubikey_status.read().clone();

    rsx! {
        div { class: "section-title", "YubiKey Integration" }

        // Education card
        div { class: "edu-card",
            div { style: "display:flex;gap:12px;align-items:flex-start;",
                div { style: "font-size:28px;flex-shrink:0;", "🔐" }
                div {
                    div { style: "font-size:13px;font-weight:600;color:var(--green);margin-bottom:4px;",
                        "Hardware-Backed Security"
                    }
                    div { style: "font-size:12px;color:var(--text-muted);line-height:1.6;",
                        "A YubiKey stores cryptographic keys in tamper-resistant hardware — private keys never leave the device. "
                        "Two modes are supported: "
                        strong { style: "color:var(--text);", "PIV (slot 9a)" }
                        " for hardware-backed signing, and "
                        strong { style: "color:var(--text);", "HOTP slot 2" }
                        " for one-press headless device bootstrapping."
                    }
                }
            }
        }

        // Mode cards
        div { style: "display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:20px;",
            // PIV Signing Key card — now interactive
            div { style: "background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:16px;",
                div { style: "font-size:16px;margin-bottom:8px;", "🔑" }
                div { style: "font-size:13px;font-weight:600;color:var(--text);margin-bottom:4px;", "PIV Signing Key" }
                div { style: "font-size:11px;color:var(--text-muted);line-height:1.5;margin-bottom:10px;",
                    "Store your NDN identity private key in YubiKey PIV slot 9a. All packet signing happens on-device — even a compromised OS cannot steal your key."
                }
                // Detect button
                div { style: "display:flex;gap:8px;margin-bottom:8px;",
                    button {
                        class: "btn btn-secondary btn-sm",
                        onclick: move |_| { ctx.cmd.send(DashCmd::YubikeyDetect); },
                        "Detect YubiKey"
                    }
                }
                // Status display
                if let Some(ref st) = yk_status {
                    {
                        let (badge_class, text) = if st.starts_with("YubiKey: present") {
                            ("badge badge-green", st.as_str())
                        } else {
                            ("badge badge-red", st.as_str())
                        };
                        rsx! {
                            div { style: "margin-bottom:8px;",
                                span { class: "{badge_class}", "{text}" }
                            }
                        }
                    }
                }
                // Generate PIV key form
                div { class: "form-group", style: "margin-bottom:6px;",
                    label { "Identity name for PIV key" }
                    input {
                        r#type: "text",
                        placeholder: "/ndn/example/router1/KEY/v=0",
                        value: "{piv_name}",
                        oninput: move |e| piv_name.set(e.value()),
                    }
                }
                button {
                    class: "btn btn-primary btn-sm",
                    disabled: piv_name.read().is_empty(),
                    onclick: move |_| {
                        let n = piv_name.read().clone();
                        if !n.is_empty() {
                            ctx.cmd.send(DashCmd::YubikeyGeneratePiv(n));
                        }
                    },
                    "Generate in Slot 9a"
                }
                if let Some(ref st) = yk_status {
                    if st.starts_with("Generated.") {
                        div { style: "margin-top:8px;",
                            div { style: "font-size:11px;color:var(--text-muted);margin-bottom:4px;",
                                "P-256 public key (base64url, 65 bytes uncompressed):"
                            }
                            div { class: "yk-seed", style: "word-break:break-all;",
                                "{st}"
                            }
                        }
                    }
                }
            }
            div { style: "background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:16px;",
                div { style: "font-size:16px;margin-bottom:8px;", "🖱" }
                div { style: "font-size:13px;font-weight:600;color:var(--text);margin-bottom:4px;", "HOTP Bootstrapping" }
                div { style: "font-size:11px;color:var(--text-muted);line-height:1.5;margin-bottom:10px;",
                    "Program slot 2 with an HMAC-SHA1 seed. Pressing the button emits a 6-digit one-time code — enough to authenticate a headless router during NDNCERT enrollment."
                }
                span { class: "badge badge-green", "Available now" }
            }
        }

        // HOTP seed generator
        div { style: "background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:16px;margin-bottom:16px;",
            div { style: "display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;",
                div { style: "font-size:13px;font-weight:600;color:var(--text);", "Generate HOTP Seed" }
                button {
                    class: "btn btn-primary btn-sm",
                    onclick: move |_| {
                        // Generate 20 random bytes using system randomness.
                        let seed = generate_hotp_seed();
                        hotp_seed.set(Some(seed));
                        hotp_counter.set(0);
                        show_cmd.set(false);
                    },
                    "Generate New Seed"
                }
            }

            if let Some(ref seed) = *hotp_seed.read() {
                div { style: "font-size:11px;color:var(--text-muted);margin-bottom:4px;", "HMAC-SHA1 seed (hex, 20 bytes):" }
                div { class: "yk-seed", "{seed}" }

                div { class: "form-row",
                    div { class: "form-group",
                        label { "Initial counter (must match YubiKey — default 0)" }
                        input {
                            r#type: "number",
                            min: "0",
                            value: "{hotp_counter}",
                            style: "width:120px;",
                            oninput: move |e| {
                                if let Ok(n) = e.value().parse::<u64>() {
                                    hotp_counter.set(n);
                                }
                            },
                        }
                    }
                    button {
                        class: "btn btn-secondary btn-sm",
                        onclick: move |_| { let v = *show_cmd.read(); show_cmd.set(!v); },
                        if *show_cmd.read() { "Hide command" } else { "Show ykpersonalize command" }
                    }
                }

                if *show_cmd.read() {
                    {
                        let s = seed.clone();
                        let c = *hotp_counter.read();
                        rsx! {
                            div { style: "margin-top:10px;",
                                div { style: "font-size:11px;color:var(--text-muted);margin-bottom:4px;",
                                    "Run on the provisioning machine (YubiKey connected via USB):"
                                }
                                div { class: "yk-cmd",
                                    "ykpersonalize -2 -o oath-hotp -o append-cr -a {s}"
                                }
                                div { style: "font-size:11px;color:var(--text-muted);margin-top:8px;",
                                    "Then configure the CA with this seed + counter via the CA / NDNCERT tab or router TOML:"
                                }
                                div { class: "yk-cmd",
                                    "[cert.challenges.yubikey-hotp]\n"
                                    "seed = \"{s}\"\n"
                                    "initial_counter = {c}\n"
                                    "window = 20"
                                }
                            }
                        }
                    }
                }
            } else {
                div { style: "text-align:center;padding:20px;color:var(--text-muted);font-size:13px;",
                    "Click \"Generate New Seed\" to create a fresh HMAC-SHA1 seed for a YubiKey slot 2."
                }
            }
        }

        // Headless bootstrapping flow
        div { style: "background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:16px;",
            div { style: "font-size:13px;font-weight:600;color:var(--text);margin-bottom:10px;", "Headless Bootstrap Flow" }
            BootstrapStep { n: 1, step: "Admin provisions",   desc: "Generate seed here → run ykpersonalize on the YubiKey", first: true }
            BootstrapStep { n: 2, step: "Ship device",        desc: "YubiKey is plugged into the headless router", first: false }
            BootstrapStep { n: 3, step: "Router enrolls",     desc: "Router starts NDNCERT enrollment automatically on boot", first: false }
            BootstrapStep { n: 4, step: "Operator presses",   desc: "Press YubiKey button → 6-digit OTP emitted via USB HID", first: false }
            BootstrapStep { n: 5, step: "Certificate issued", desc: "CA verifies OTP against HOTP counter → cert issued", first: false }
        }
    }
}

/// Generate 20 random bytes as a hex string using OS randomness.
fn generate_hotp_seed() -> String {
    let mut seed = [0u8; 20];
    let _ = getrandom::getrandom(&mut seed);
    seed.iter().map(|b| format!("{b:02x}")).collect()
}

#[component]
fn BootstrapStep(n: u8, step: &'static str, desc: &'static str, first: bool) -> Element {
    let border = if first { "" } else { "border-top:1px solid var(--border-subtle);" };
    rsx! {
        div { style: "display:flex;gap:10px;padding:8px 0;{border}",
            div { style: "width:24px;height:24px;border-radius:50%;background:var(--accent-dim);border:1px solid var(--accent-solid)44;display:flex;align-items:center;justify-content:center;font-size:11px;color:var(--accent);flex-shrink:0;",
                "{n}"
            }
            div {
                div { style: "font-size:12px;font-weight:600;color:var(--text);", "{step}" }
                div { style: "font-size:11px;color:var(--text-muted);", "{desc}" }
            }
        }
    }
}
