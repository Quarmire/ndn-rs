//! NDN Dashboard — Dioxus application for managing and monitoring
//! an ndn-fwd instance.
//!
//! The dashboard communicates with the router exclusively via the NDN
//! management protocol (TLV Interest/Data on `/localhost/nfd/`).
//!
//! **Desktop** mode uses [`ndn_ipc::MgmtClient`] over Unix sockets with
//! system tray integration and subprocess management.
//!
//! **Web** mode uses a pure-Rust WebSocket client compiled to WASM,
//! demonstrating ndn-rs portability — the same TLV codec and packet types
//! run natively and in the browser.

#![allow(non_snake_case)]

mod app;
#[cfg(feature = "web")]
mod app_web;
#[cfg(feature = "desktop")]
mod forwarder_proc;
pub mod settings;
mod styles;
#[cfg(feature = "desktop")]
pub mod tool_runner;
#[cfg(feature = "desktop")]
mod tray;
mod types;
mod views;

#[cfg(feature = "web")]
mod ws_mgmt;

fn main() {
    #[cfg(feature = "desktop")]
    {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
            )
            .init();
    }

    #[cfg(feature = "desktop")]
    dioxus::launch(app::App);

    #[cfg(feature = "web")]
    dioxus::launch(app_web::AppWeb);
}
