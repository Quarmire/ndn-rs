//! # Implementing a Cross-Layer Context Enricher
//!
//! This example shows how to feed data from external sources (radio metrics,
//! GPS, battery, etc.) into the strategy layer via [`ContextEnricher`].
//!
//! ## Architecture
//!
//! ```text
//!  External data source          ContextEnricher           Strategy
//!  ──────────────────          ─────────────────          ────────
//!  nl80211 / GPS / sensor  →   reads shared state    →   extensions.get::<T>()
//!       (Tokio task)           inserts DTO into AnyMap    makes decisions
//! ```
//!
//! ## Key concepts
//!
//! - Implement [`ContextEnricher`] — reads your data source, inserts a DTO
//! - Register via `EngineBuilder::context_enricher()`
//! - The enricher runs once per strategy invocation (before the strategy)
//! - Strategies access the data via `ctx.extensions.get::<YourDto>()`
//! - Adding a new data source requires ZERO changes to existing code
//!
//! ## What this example does
//!
//! Simulates a GPS-based enricher that provides location data to strategies.
//! Demonstrates the full pattern: shared data source → enricher → strategy access.

use std::sync::Arc;

use anyhow::Result;
use dashmap::DashMap;

use ndn_engine::{ContextEnricher, EngineBuilder, EngineConfig};
use ndn_strategy::FibEntry;
use ndn_transport::{AnyMap, FaceId};

// ─── Step 1: Define a DTO (Data Transfer Object) ────────────────────────────
//
// This is the type that strategies will query from the extensions AnyMap.
// It should be a simple, self-contained snapshot of the data.

/// GPS location snapshot for the local node.
///
/// Strategies can use this to make location-aware forwarding decisions,
/// e.g. forwarding to the geographically closest nexthop.
#[allow(dead_code)]
#[derive(Clone, Debug)]
struct LocationSnapshot {
    latitude: f64,
    longitude: f64,
    accuracy_m: f32,
}

/// Per-face location data (if known).
#[allow(dead_code)]
#[derive(Clone, Debug)]
struct FaceLocation {
    face_id: FaceId,
    latitude: f64,
    longitude: f64,
}

/// Combined location context inserted into strategy extensions.
#[allow(dead_code)]
#[derive(Clone, Debug)]
struct LocationContext {
    local: LocationSnapshot,
    peer_locations: Vec<FaceLocation>,
}

// ─── Step 2: Create a shared data source ─────────────────────────────────────
//
// In production this would be updated by a background Tokio task reading
// from a GPS device, nl80211, or other sensor.

/// Shared GPS data updated by a background task.
struct GpsReceiver {
    /// Current local position (updated by GPS task).
    local_position: parking_lot::RwLock<LocationSnapshot>,
    /// Known peer locations (e.g. from NDN location announcements).
    peer_locations: DashMap<FaceId, FaceLocation>,
}

impl GpsReceiver {
    fn new(lat: f64, lon: f64) -> Self {
        Self {
            local_position: parking_lot::RwLock::new(LocationSnapshot {
                latitude: lat,
                longitude: lon,
                accuracy_m: 10.0,
            }),
            peer_locations: DashMap::new(),
        }
    }
}

// ─── Step 3: Implement ContextEnricher ───────────────────────────────────────

/// Enricher that populates `LocationContext` in strategy extensions.
struct LocationEnricher {
    gps: Arc<GpsReceiver>,
}

impl ContextEnricher for LocationEnricher {
    fn name(&self) -> &str {
        "location-enricher"
    }

    fn enrich(&self, _fib_entry: Option<&FibEntry>, extensions: &mut AnyMap) {
        let local = self.gps.local_position.read().clone();

        // Collect known peer locations.
        let peer_locations: Vec<FaceLocation> = self
            .gps
            .peer_locations
            .iter()
            .map(|entry| entry.value().clone())
            .collect();

        extensions.insert(LocationContext {
            local,
            peer_locations,
        });
    }
}

// ─── Step 4: Register with the engine ────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    // Create shared GPS data source.
    let gps = Arc::new(GpsReceiver::new(37.7749, -122.4194)); // San Francisco

    // Simulate some known peer locations.
    gps.peer_locations.insert(
        FaceId(1),
        FaceLocation {
            face_id: FaceId(1),
            latitude: 37.7849,
            longitude: -122.4094,
        },
    );
    gps.peer_locations.insert(
        FaceId(2),
        FaceLocation {
            face_id: FaceId(2),
            latitude: 34.0522,
            longitude: -118.2437, // Los Angeles
        },
    );

    // Register the enricher with the engine.
    let enricher = Arc::new(LocationEnricher {
        gps: Arc::clone(&gps),
    });

    let (_engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .context_enricher(enricher) // <-- register enricher
        .build()
        .await?;

    tracing::info!("Engine started with LocationEnricher");

    // Now any strategy can access location data:
    //
    //   fn decide(&self, ctx: &StrategyContext) -> ... {
    //       if let Some(loc) = ctx.extensions.get::<LocationContext>() {
    //           // Use loc.local, loc.peer_locations to make decisions
    //       }
    //   }
    //
    // In production, a background task would update gps.local_position
    // as new GPS fixes arrive. The enricher always reads the latest state.

    tracing::info!(
        peers = gps.peer_locations.len(),
        "Location data available to all strategies"
    );

    shutdown.shutdown().await;
    Ok(())
}
