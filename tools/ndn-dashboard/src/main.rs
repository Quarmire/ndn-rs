//! NDN Dashboard — Dioxus desktop application for managing and monitoring
//! an ndn-router instance.
//!
//! The dashboard communicates with the router exclusively via the NDN
//! management protocol (TLV Interest/Data on `/localhost/nfd/`), using the
//! same [`ndn_ipc::MgmtClient`] library as `ndn-ctl`. All UI state is driven
//! by reactive Dioxus signals polled every 3 seconds.
//!
//! Features:
//! - **Overview** — forwarder status, throughput sparklines, CS stats
//! - **Fleet** — discovered neighbors, NDNCERT enrollment, discovery config
//! - **Routing** — DVR protocol status and runtime config
//! - **Routes / Strategy / Security / Logs / Tools** — full management suite
//! - **System tray** — background presence with start/stop controls

#![allow(non_snake_case)]

mod app;
mod router_proc;
pub mod settings;
mod styles;
pub mod tool_runner;
mod tray;
mod types;
mod views;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    dioxus::launch(app::App);
}
