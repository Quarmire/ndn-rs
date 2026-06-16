//! Per-module mgmt dispatch files. Each NFD-style module (rib, faces,
//! fib, …) implements [`crate::module::MgmtModule`] in a sibling file;
//! [`register_builtins`] installs the full set on a
//! [`crate::module::MgmtRouter`].
//!
//! Native-only modules (`routing`, `discovery`, `neighbors`, `service`,
//! `security`) are `cfg`-gated; wasm32 omits them and the router
//! returns `NOT_FOUND` for the missing names.

use std::sync::Arc;

use crate::module::MgmtRouter;

pub(crate) mod common;

pub(crate) mod ble;
pub(crate) mod ca;
pub(crate) mod coding;
pub(crate) mod compute;
pub(crate) mod config;
pub(crate) mod ext;
pub(crate) mod cs;
pub(crate) mod faces;
pub(crate) mod fib;
pub(crate) mod log;
pub(crate) mod measurements;
pub(crate) mod rate_limit;
pub(crate) mod reflexive;
pub(crate) mod rib;
pub(crate) mod status;
pub(crate) mod strategy;
pub(crate) mod webtransport;

#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod discovery;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod neighbors;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod routing;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod security;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod service;

#[cfg(not(target_arch = "wasm32"))]
pub use security::MgmtAccessPolicy;

/// Install the built-in ndn-rs module set on `router`.
pub fn register_builtins(router: &mut MgmtRouter) {
    router.register(Arc::new(rib::RibModule));
    router.register(Arc::new(faces::FacesModule));
    router.register(Arc::new(fib::FibModule));
    router.register(Arc::new(strategy::StrategyModule));
    router.register(Arc::new(cs::CsModule));
    router.register(Arc::new(status::StatusModule));
    router.register(Arc::new(measurements::MeasurementsModule));
    router.register(Arc::new(config::ConfigModule));
    router.register(Arc::new(ext::ExtModule));
    router.register(Arc::new(log::LogModule));
    router.register(Arc::new(coding::CodingModule));
    router.register(Arc::new(compute::ComputeModule));
    router.register(Arc::new(rate_limit::RateLimitModule));
    router.register(Arc::new(reflexive::ReflexiveModule));
    router.register(Arc::new(ble::BleModule));
    router.register(Arc::new(ca::CaModule));
    router.register(Arc::new(webtransport::WebTransportModule));

    #[cfg(not(target_arch = "wasm32"))]
    {
        router.register(Arc::new(routing::RoutingModule));
        router.register(Arc::new(discovery::DiscoveryModule));
        router.register(Arc::new(neighbors::NeighborsModule));
        router.register(Arc::new(service::ServiceModule));
        router.register(Arc::new(security::SecurityModule));
    }
}
