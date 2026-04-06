//! LAN neighbor and service discovery example.
//!
//! Demonstrates the full discovery setup path:
//!
//! 1. Pre-allocate a `FaceId` for the multicast face via `builder.alloc_face_id()`
//! 2. Build `UdpNeighborDiscovery` (with transient Ed25519 key auto-generated)
//! 3. Build `ServiceDiscoveryProtocol` and publish a service record
//! 4. Wrap in `CompositeDiscovery` and hand to the engine builder
//! 5. Create the `MulticastUdpFace` with the pre-allocated ID and register it
//! 6. Let the engine run for 30 seconds, then print the neighbor table
//!
//! # Running
//!
//! ```sh
//! # First terminal (requires multicast on the loopback):
//! cargo run -p example-discovery-lan -- --name /ndn/lan/node-a --prefix /ndn/app/a
//!
//! # Second terminal (on the same LAN, or same host with multicast loopback):
//! cargo run -p example-discovery-lan -- --name /ndn/lan/node-b --prefix /ndn/app/b
//! ```
//!
//! Both nodes should discover each other within a few seconds.

use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use ndn_discovery::{
    CompositeDiscovery, DiscoveryConfig, DiscoveryProfile, DiscoveryProtocol,
    ServiceDiscoveryConfig, ServiceDiscoveryProtocol, ServiceRecord, UdpNeighborDiscovery,
};
use ndn_engine::{EngineBuilder, EngineConfig};
use ndn_face_net::MulticastUdpFace;
use ndn_packet::Name;
use ndn_transport::FacePersistency;
use tokio_util::sync::CancellationToken;
use tracing::info;

/// NDN standard multicast group.
const NDN_MULTICAST_GROUP: &str = "224.0.23.170";
/// NDN standard port.
const NDN_PORT: u16 = 6363;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("info".parse().unwrap()),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();
    let node_name_str =
        parse_arg(&args, "--name").unwrap_or_else(|| "/ndn/lan/example-node".to_owned());
    let prefix_str = parse_arg(&args, "--prefix").unwrap_or_else(|| "/ndn/app/example".to_owned());
    let iface_str = parse_arg(&args, "--iface").unwrap_or_else(|| "0.0.0.0".to_owned());

    let node_name = Name::from_str(&node_name_str)
        .with_context(|| format!("invalid node name: {node_name_str}"))?;
    let prefix =
        Name::from_str(&prefix_str).with_context(|| format!("invalid prefix: {prefix_str}"))?;
    let iface: Ipv4Addr = iface_str
        .parse()
        .with_context(|| format!("invalid interface address: {iface_str}"))?;
    let group: Ipv4Addr = NDN_MULTICAST_GROUP.parse().unwrap();

    info!(node = %node_name, prefix = %prefix, iface = %iface, "discovery-lan starting");

    // ── Step 1: create engine builder and pre-allocate the multicast face ID ──

    let builder = EngineBuilder::new(EngineConfig::default());
    let mcast_face_id = builder.alloc_face_id();
    info!(face_id = mcast_face_id.0, "pre-allocated multicast face ID");

    // ── Step 2: build neighbor discovery ─────────────────────────────────────

    let disc_config = DiscoveryConfig::for_profile(&DiscoveryProfile::Lan);
    let nd = UdpNeighborDiscovery::new_multi(vec![mcast_face_id], node_name.clone(), disc_config);

    // ── Step 3: build service discovery + publish a record ───────────────────

    let svc_config = ServiceDiscoveryConfig::default();
    let sd = Arc::new(ServiceDiscoveryProtocol::new(node_name.clone(), svc_config));
    sd.publish(ServiceRecord::new(prefix.clone(), node_name.clone()));
    info!(prefix = %prefix, "published service record");

    // ── Step 4: wrap in CompositeDiscovery and hand to engine ─────────────────

    let composite = CompositeDiscovery::new(vec![
        Arc::new(nd) as Arc<dyn DiscoveryProtocol>,
        Arc::clone(&sd) as Arc<dyn DiscoveryProtocol>,
    ])
    .map_err(|e| anyhow::anyhow!("discovery conflict: {e}"))?;

    let builder = builder.discovery(composite);

    // ── Step 5: build engine, create multicast face ───────────────────────────

    let cancel = CancellationToken::new();
    let (engine, _shutdown) = builder.build().await?;

    let mcast_face = MulticastUdpFace::new(iface, NDN_PORT, group, mcast_face_id)
        .await
        .with_context(|| format!("failed to create multicast face on {iface}:{NDN_PORT}"))?;
    engine.add_face_with_persistency(mcast_face, cancel.child_token(), FacePersistency::Permanent);
    info!(face_id = mcast_face_id.0, group = %group, port = NDN_PORT, "multicast face registered");

    // ── Step 6: run for 30 seconds, then print neighbor table ─────────────────

    info!("running for 30 seconds …");
    tokio::time::sleep(Duration::from_secs(30)).await;

    let neighbors = engine.neighbors().all();
    if neighbors.is_empty() {
        info!("no neighbors discovered (is another node running on the same LAN?)");
    } else {
        info!("{} neighbor(s) discovered:", neighbors.len());
        for n in &neighbors {
            let face_ids: Vec<String> = n.faces.iter().map(|(id, _, _)| id.0.to_string()).collect();
            info!(
                "  name={} faces=[{}] rtt={:?}",
                n.node_name,
                face_ids.join(","),
                n.rtt_us.map(|us| Duration::from_micros(us as u64)),
            );
        }
    }

    let services = sd.local_records();
    info!("{} local service(s):", services.len());
    for s in &services {
        info!(
            "  prefix={} node={} freshness={}ms",
            s.announced_prefix, s.node_name, s.freshness_ms
        );
    }

    cancel.cancel();
    Ok(())
}

fn parse_arg(args: &[String], flag: &str) -> Option<String> {
    args.windows(2).find(|w| w[0] == flag).map(|w| w[1].clone())
}
