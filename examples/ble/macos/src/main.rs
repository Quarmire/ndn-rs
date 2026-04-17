//! macOS BLE peripheral test — verifies `BleFace` end-to-end.
//!
//! Starts a BLE GATT peripheral using the NDNts-compatible service UUID,
//! advertises, and responds to Interests under `/ndn/ble/test` with a
//! timestamped greeting.
//!
//! # Running
//!
//! ```sh
//! cargo run -p example-ble-macos
//! ```
//!
//! Then connect from an Android or iOS BLE test app, send an Interest for
//! `/ndn/ble/test`, and verify the Data response.

use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use ndn_engine::{EngineBuilder, EngineConfig};
use ndn_faces::l2::BleFace;
use ndn_faces::local::InProcFace;
use ndn_packet::Name;
use ndn_packet::encode::DataBuilder;
use ndn_security::SecurityProfile;
use ndn_transport::FacePersistency;
use tokio_util::sync::CancellationToken;
use tracing::info;

const PREFIX: &str = "/ndn/ble/test";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("info".parse().unwrap()),
        )
        .init();

    let cancel = CancellationToken::new();

    // ── Build engine ─────────────────────────────────────────────────────
    let config = EngineConfig {
        pipeline_threads: 1,
        ..EngineConfig::default()
    };
    let builder = EngineBuilder::new(config).security_profile(SecurityProfile::Disabled);

    let ble_face_id = builder.alloc_face_id();
    info!(face_id = ble_face_id.0, "pre-allocated BLE face ID");

    let (engine, _shutdown) = builder.build().await?;

    // ── Start BLE peripheral ─────────────────────────────────────────────
    let ble_face = BleFace::bind(ble_face_id)
        .await
        .context("failed to bind BLE face — is Bluetooth enabled?")?;
    engine.add_face_with_persistency(ble_face, cancel.child_token(), FacePersistency::Permanent);
    info!("BLE face bound and advertising");

    // ── Register producer on /ndn/ble/test ───────────────────────────────
    let prefix = Name::from_str(PREFIX).unwrap();
    let app_face_id = engine.faces().alloc_id();
    let (app_face, app_handle) = InProcFace::new(app_face_id, 256);
    engine.add_face(app_face, cancel.child_token());
    engine.fib().add_nexthop(&prefix, app_face_id, 0);
    info!(prefix = PREFIX, "producer registered");

    // ── Serve loop ───────────────────────────────────────────────────────
    let producer = ndn_app::Producer::from_handle(app_handle, prefix.clone());
    info!("waiting for BLE client connections …");

    let serve = tokio::spawn(async move {
        producer
            .serve(|interest, responder| async move {
                let ts = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis();
                let content = format!("Hello from macOS! t={ts}");
                info!(
                    name = %interest.name,
                    content = %content,
                    "Interest received, responding"
                );
                let data =
                    DataBuilder::new((*interest.name).clone(), content.as_bytes()).build();
                responder.respond_bytes(data).await.ok();
            })
            .await
            .ok();
    });

    // ── Wait for Ctrl+C ──────────────────────────────────────────────────
    tokio::signal::ctrl_c().await?;
    info!("shutting down …");
    cancel.cancel();
    serve.abort();
    Ok(())
}
