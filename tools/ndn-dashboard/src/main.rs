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
