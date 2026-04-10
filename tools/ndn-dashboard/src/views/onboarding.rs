//! First-time onboarding wizard.
//!
//! Shows a full-screen overlay the first time the dashboard is opened.
//! Completion is persisted to `~/.ndn/dashboard-onboarded` so it only
//! appears once per machine.
//!
//! Steps:
//!   0 — Welcome (animated NDN packet flow)
//!   1 — Your Identity (Ed25519 key + DID introduction)
//!   2 — Trust Anchors (chain-of-trust diagram)
//!   3 — Done (links to next actions)

use dioxus::prelude::*;
use crate::app::AppCtx;

// ── Persistence ───────────────────────────────────────────────────────────────

fn onboarded_path() -> std::path::PathBuf {
    std::env::var("HOME")
        .map(|h| std::path::PathBuf::from(h).join(".ndn").join("dashboard-onboarded"))
        .unwrap_or_else(|_| std::path::PathBuf::from("/tmp/.ndn-dashboard-onboarded"))
}

pub fn is_onboarded() -> bool {
    onboarded_path().exists()
}

fn mark_onboarded() {
    let path = onboarded_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&path, "1");
}

// ── Component ────────────────────────────────────────────────────────────────

#[component]
pub fn Onboarding(mut on_complete: EventHandler<()>) -> Element {
    let ctx = use_context::<AppCtx>();
    let mut step: Signal<u8> = use_signal(|| 0);
    const TOTAL: u8 = 4;

    let keys = ctx.security_keys.read();
    let has_identity = !keys.is_empty();
    let identity_name = keys.first().map(|k| k.name.clone()).unwrap_or_default();

    let advance = move |_| {
        let s = *step.read();
        if s + 1 < TOTAL {
            step.set(s + 1);
        } else {
            mark_onboarded();
            on_complete.call(());
        }
    };

    let skip = move |_| {
        mark_onboarded();
        on_complete.call(());
    };

    rsx! {
        div { class: "onboarding-overlay",
            div { class: "onboarding-card",
                // Skip button
                button {
                    style: "position:absolute;top:16px;right:18px;background:none;border:none;color:var(--text-muted);cursor:pointer;font-size:13px;",
                    onclick: skip,
                    "Skip ›"
                }

                // Step content
                div { class: "onboarding-step",
                    {render_step(*step.read(), has_identity, &identity_name, advance)}
                }

                // Step dots
                div { class: "step-dots",
                    for i in 0..TOTAL {
                        div {
                            class: {
                                let s = *step.read();
                                if i == s { "step-dot active" }
                                else if i < s { "step-dot done" }
                                else { "step-dot" }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn render_step(
    step: u8,
    has_identity: bool,
    identity_name: &str,
    advance: impl FnMut(MouseEvent) + 'static,
) -> Element {
    match step {
        0 => render_welcome(advance),
        1 => render_identity(has_identity, identity_name, advance),
        2 => render_trust(advance),
        _ => render_done(advance),
    }
}

// ── Step 0: Welcome ───────────────────────────────────────────────────────────

fn render_welcome(advance: impl FnMut(MouseEvent) + 'static) -> Element {
    rsx! {
        div { style: "text-align:center;",
            // NDN logo / wordmark
            div { style: "font-size:42px;font-weight:700;color:var(--accent);letter-spacing:-1px;margin-bottom:6px;", "NDN" }
            div { style: "font-size:14px;color:var(--text-muted);margin-bottom:24px;", "Named Data Networking" }

            // Animated packet flow
            div { style: "background:var(--bg);border:1px solid var(--border-subtle);border-radius:8px;padding:16px;margin-bottom:20px;",
                div { style: "font-size:11px;color:var(--text-muted);text-align:left;margin-bottom:8px;font-family:monospace;",
                    "Interest /ndn/edu/ucla/video → → →"
                }
                div { class: "packet-lane",
                    div { class: "packet-bubble", "Interest /ndn/…" }
                    div { class: "packet-bubble data", "Data /ndn/… ✓" }
                    div { class: "packet-bubble nack", "Nack (No Route)" }
                }
                div { style: "font-size:11px;color:var(--text-muted);text-align:left;margin-top:8px;font-family:monospace;",
                    "← ← ← Data /ndn/edu/ucla/video (signed)"
                }
            }

            p { style: "color:var(--text-muted);font-size:14px;line-height:1.7;margin-bottom:24px;",
                "Welcome to the NDN Dashboard. In Named Data Networking, "
                strong { style: "color:var(--text);", "packets are identified by name, not address." }
                " Every piece of data is signed and every router verifies content authenticity."
            }

            button {
                class: "btn btn-primary",
                style: "width:100%;padding:10px;font-size:14px;",
                onclick: advance,
                "Get Started →"
            }
        }
    }
}

// ── Step 1: Your Identity ─────────────────────────────────────────────────────

fn render_identity(
    has_identity: bool,
    identity_name: &str,
    advance: impl FnMut(MouseEvent) + 'static,
) -> Element {
    let identity_name = identity_name.to_string();
    rsx! {
        div {
            div { style: "font-size:22px;font-weight:600;color:var(--text);margin-bottom:8px;", "Your Identity" }
            div { style: "color:var(--text-muted);font-size:13px;margin-bottom:20px;line-height:1.6;",
                "In NDN, your "
                strong { style: "color:var(--text);", "identity IS your address." }
                " An Ed25519 key pair is your cryptographic identity — packets you send are signed with it, and others verify your signature before forwarding."
            }

            if has_identity {
                div { style: "background:var(--green-bg);border:1px solid var(--green);border-radius:8px;padding:14px;margin-bottom:16px;",
                    div { style: "font-size:11px;color:var(--green);text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px;",
                        "Active Identity"
                    }
                    div { class: "mono", style: "color:var(--text);font-size:13px;", "{identity_name}" }
                    div { style: "font-size:11px;color:var(--text-muted);margin-top:6px;",
                        "Your DID: "
                        span { style: "color:var(--purple);", "did:ndn:{encode_did_ndn(&identity_name)}" }
                    }
                }
            } else {
                div { style: "background:var(--yellow-bg);border:1px solid var(--yellow);border-radius:8px;padding:14px;margin-bottom:16px;",
                    div { style: "font-size:11px;color:var(--yellow);text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px;",
                        "No Identity Found"
                    }
                    div { style: "font-size:13px;color:var(--text);",
                        "You don't have an identity key yet. Go to "
                        strong { "Security → Identities" }
                        " to generate your first Ed25519 key pair."
                    }
                }
            }

            // DID explanation
            div { style: "background:var(--purple-bg)33;border:1px solid var(--purple)33;border-radius:8px;padding:12px;margin-bottom:20px;font-size:12px;color:var(--text-muted);line-height:1.6;",
                "💡 "
                strong { style: "color:var(--purple);", "What is a DID?" }
                " A Decentralized Identifier (W3C DID) is a portable, self-sovereign identity. NDN names map directly to DIDs: "
                span { style: "color:var(--purple);font-family:monospace;", "did:ndn:/your/name" }
                " — no central registry required."
            }

            button {
                class: "btn btn-primary",
                style: "width:100%;padding:10px;font-size:14px;",
                onclick: advance,
                "Next: Trust Anchors →"
            }
        }
    }
}

// ── Step 2: Trust Anchors ─────────────────────────────────────────────────────

fn render_trust(advance: impl FnMut(MouseEvent) + 'static) -> Element {
    rsx! {
        div {
            div { style: "font-size:22px;font-weight:600;color:var(--text);margin-bottom:8px;", "Chain of Trust" }
            div { style: "color:var(--text-muted);font-size:13px;margin-bottom:20px;line-height:1.6;",
                "NDN builds trust from a "
                strong { style: "color:var(--text);", "root trust anchor" }
                " — a certificate you explicitly trust. Every certificate is verified back to this anchor before forwarding."
            }

            // Chain diagram
            div { style: "margin:20px 0;",
                div { class: "trust-chain",
                    // Root anchor
                    div { class: "chain-node ok",
                        div { style: "font-size:18px;margin-bottom:4px;", "🔑" }
                        div { style: "font-size:11px;color:var(--green);font-weight:600;", "Trust Anchor" }
                        div { style: "font-size:10px;color:var(--text-muted);margin-top:2px;", "/ndn" }
                    }
                    div { class: "chain-arrow", "→" }
                    // CA cert
                    div { class: "chain-node ok",
                        div { style: "font-size:18px;margin-bottom:4px;", "📜" }
                        div { style: "font-size:11px;color:var(--green);font-weight:600;", "CA Certificate" }
                        div { style: "font-size:10px;color:var(--text-muted);margin-top:2px;", "/ndn/site" }
                    }
                    div { class: "chain-arrow", "→" }
                    // Identity cert
                    div { class: "chain-node ok",
                        div { style: "font-size:18px;margin-bottom:4px;", "🪪" }
                        div { style: "font-size:11px;color:var(--green);font-weight:600;", "Your Identity" }
                        div { style: "font-size:10px;color:var(--text-muted);margin-top:2px;", "/ndn/site/router" }
                    }
                }

                // Verification arrow
                div { style: "text-align:center;font-size:11px;color:var(--text-muted);margin-top:6px;",
                    "Each certificate is signed by the one above it"
                    span { class: "trust-link" }
                    "all the way back to the anchor"
                }
            }

            div { style: "background:var(--accent-bg)22;border:1px solid var(--accent-solid)44;border-radius:8px;padding:12px;margin-bottom:20px;font-size:12px;color:var(--text-muted);line-height:1.6;",
                "💡 "
                strong { style: "color:var(--accent);", "Zero Trust by Default." }
                " Every forwarded packet is verified against the trust chain. A packet with a broken or missing chain is dropped — not forwarded. Use the "
                strong { "Security" }
                " tab to manage your anchors and enroll with a CA."
            }

            button {
                class: "btn btn-primary",
                style: "width:100%;padding:10px;font-size:14px;",
                onclick: advance,
                "Next: You're Ready →"
            }
        }
    }
}

// ── Step 3: Done ──────────────────────────────────────────────────────────────

fn render_done(advance: impl FnMut(MouseEvent) + 'static) -> Element {
    rsx! {
        div { style: "text-align:center;",
            div { style: "font-size:48px;margin-bottom:12px;", "🚀" }
            div { style: "font-size:22px;font-weight:600;color:var(--text);margin-bottom:10px;", "You're all set!" }
            div { style: "color:var(--text-muted);font-size:13px;margin-bottom:24px;line-height:1.7;",
                "The dashboard is your window into the NDN forwarder. Here's where to start:"
            }

            // Quick-start cards
            div { style: "display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:24px;text-align:left;",
                QuickCard {
                    icon: "🪪",
                    title: "Security",
                    desc: "Manage identity keys, enroll with a CA, and configure trust anchors",
                }
                QuickCard {
                    icon: "🌐",
                    title: "Fleet",
                    desc: "Bootstrap neighbor routers and monitor discovered nodes",
                }
                QuickCard {
                    icon: "🗺",
                    title: "Routes",
                    desc: "Add and remove FIB entries to control forwarding paths",
                }
                QuickCard {
                    icon: "📊",
                    title: "Traffic",
                    desc: "Real-time throughput and per-face counters",
                }
            }

            button {
                class: "btn btn-primary",
                style: "width:100%;padding:10px;font-size:14px;",
                onclick: advance,
                "Open Dashboard"
            }
        }
    }
}

#[component]
fn QuickCard(icon: &'static str, title: &'static str, desc: &'static str) -> Element {
    rsx! {
        div { style: "background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:12px;",
            div { style: "font-size:20px;margin-bottom:6px;", "{icon}" }
            div { style: "font-size:13px;font-weight:600;color:var(--text);margin-bottom:4px;", "{title}" }
            div { style: "font-size:11px;color:var(--text-muted);line-height:1.5;", "{desc}" }
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Encode an NDN name as a `did:ndn` DID suffix (percent-encode slashes → %2F).
pub fn encode_did_ndn(name: &str) -> String {
    name.replace('/', "%2F")
}
