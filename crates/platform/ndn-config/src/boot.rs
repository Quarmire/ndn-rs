//! Apply a [`ForwarderConfig`] to a forwarder engine — the ONE implementation,
//! shared by `ndn-fwd`'s startup and by `ndn-sim`'s node bring-up so a
//! simulated node boots exactly the way a deployed one does.
//!
//! Every fleet bug this module's comments cite was a divergence between "what
//! the config says" and "what the running forwarder does". A second copy of
//! this logic (e.g. a simulator installing bare FIB nexthops) re-opens exactly
//! those divergences where no test can see them, so callers must go through
//! here rather than re-deriving any of it.
//!
//! Lives in `ndn-config` rather than `ndn-mgmt`: `ndn-config` already depends
//! on `ndn-mgmt` (feature `mgmt`), so the reverse edge would be a package
//! cycle, and `ndn-mgmt` is spec-scope, which may not depend on this
//! extension crate.

use std::sync::Arc;

use ndn_engine::rib::RibRoute;
use ndn_engine::{EngineBuilder, ForwarderEngine};
use ndn_mgmt_wire::control_parameters::{origin, route_flags};
use ndn_packet::Name;
use ndn_transport::{FaceId, FacePersistency};

use crate::{ForwarderConfig, RouteConfig, StrategyConfig};

/// Persistency of every face created from a statically configured `[[face]]`
/// peer entry.
///
/// PERMANENT, not Persistent. A configured peer endpoint must outlive I/O
/// errors: a Persistent face is destroyed on the first recv/send error, and
/// nothing recreates it, while the RIB routes that named its face id survive
/// and now point at a face that no longer exists. The node is then silently
/// ONE-WAY -- it still answers Interests arriving on a fresh on-demand face
/// but can never send any of its own.
///
/// Observed on the fleet: a GCS forwarder restart destroyed the UDP peer face
/// on BOTH ends of the same link. iuas-01 kept `out: interests=0` toward the
/// GCS for hours while its routes still said face 3, so its SVS sync never
/// reached the GCS and every NDNSF service call to it timed out, with
/// telemetry degraded but not dead.
///
/// Configuration sets no NDNLPv2 option on these faces: `[[face]]` has no
/// LpReliability field, so reliability is off until an operator enables it
/// at runtime (`faces/update` flag bit 1, `ndn-ctl face update <id> --flags
/// 0x2`). The datagram fragmentation MTU and the lossy-link retry profile
/// are applied by the engine's face sender to every UDP face on its own.
pub const CONFIGURED_FACE_PERSISTENCY: FacePersistency = FacePersistency::Permanent;

/// ndn-fwd's UDP port, as NFD's: the listener's when a config has no
/// `[[face]]` at all, and the local port of a peer entry that names no `bind`.
pub const DEFAULT_UDP_PORT: u16 = 6363;

/// How the socket of a `[[face]] kind = "udp"` peer entry (one with a
/// `remote`) is bound. Decided by [`udp_peer_binding`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpPeerBinding {
    /// Local port the face's datagrams leave from; `0` takes a kernel-assigned
    /// ephemeral port.
    pub local_port: u16,
    /// `connect()` the socket to the peer, so the kernel hands it that peer's
    /// datagrams (a 4-tuple match outscores a wildcard socket on the port).
    pub connected: bool,
}

/// The binding of a UDP peer entry whose `bind` is `bind`: the listener's port
/// (the entry's `bind` port, [`DEFAULT_UDP_PORT`] without one), connected to
/// the peer. ndn-fwd's face setup realises this decision and ndn-sim's UDP
/// model simulates it, so the simulator shows exactly the faces a deployed
/// forwarder ends up with.
///
/// The neighbour files our datagrams under their SOURCE endpoint. From an
/// ephemeral port (ndn-fwd's `0.0.0.0:0` until Round 16) they matched no face
/// it had, so its listener minted a second, on-demand face for us. Split
/// across two faces, a neighbour survives `nexthops_excluding(in_face)` and
/// Interests are forwarded back to their origin: 12 wire copies per Interest
/// on the fleet's 4-node mesh against NFD's 9, ~35% more packets on a shared
/// medium (nfd-divergence-findings.md §15). Connected, because the peer face
/// now shares its port with the wildcard listener, and only the 4-tuple match
/// delivers the peer's datagrams to the peer face instead of the listener.
pub fn udp_peer_binding(bind: Option<&str>) -> UdpPeerBinding {
    UdpPeerBinding {
        local_port: bind
            .and_then(|b| b.parse::<std::net::SocketAddr>().ok())
            .map_or(DEFAULT_UDP_PORT, |a| a.port()),
        connected: true,
    }
}

/// The engine configuration a `ForwarderConfig` describes.
pub fn engine_config(cfg: &ForwarderConfig) -> ndn_engine::EngineConfig {
    // Prefer [cs].capacity_mb, fall back to engine.cs_capacity_mb.
    let cs_cap_mb = if cfg.cs.capacity_mb != 0 {
        cfg.cs.capacity_mb
    } else {
        cfg.engine.cs_capacity_mb
    };

    ndn_engine::EngineConfig {
        cs_capacity_bytes: cs_cap_mb * 1024 * 1024,
        cs_admit_unverified: cfg.cs.admit_unverified,
        pipeline_channel_cap: cfg.engine.pipeline_channel_cap,
        pipeline_threads: cfg.engine.pipeline_threads,
        reflexive: ndn_engine::ReflexiveConfig {
            enabled: cfg.reflexive.enabled,
            max_per_face: cfg.reflexive.max_per_face,
            max_lifetime: std::time::Duration::from_millis(cfg.reflexive.max_lifetime_ms),
        },
        data_plane: match cfg.engine.data_plane.as_str() {
            "partitioned" => {
                let workers = if cfg.engine.workers == 0 {
                    std::thread::available_parallelism()
                        .map(|n| n.get())
                        .unwrap_or(1)
                } else {
                    cfg.engine.workers
                };
                ndn_engine::DataPlane::Partitioned { workers }
            }
            _ => ndn_engine::DataPlane::Shared,
        },
        require_local_validation: cfg.engine.require_local_validation,
        ..ndn_engine::EngineConfig::default()
    }
}

/// Apply the Data-path trust and caching policy the config selects: which
/// validator checks forwarded Data (`[security] profile` /
/// `validator_enabled`), the `[[security.rule]]` trust-schema rules it
/// enforces, and which Data the CS admits (`[cs] admission_policy`).
///
/// Identity is NOT applied here: the caller passes its `SecurityManager` (if
/// any; see [`load_identity`]) to `EngineBuilder::security` itself. `ndn-fwd`
/// always has one (PIB identity or an ephemeral key). Under `profile =
/// "default"` its anchors are the chain terminators; `"accept-signed"` only
/// requires the signature to verify against the signer's certificate. Either
/// way the engine fetches a certificate it has not cached through its own
/// faces. The fleet runs `profile = "disabled"` and validates at the
/// application layer (NDNSF, NAC-ABE; see `CsInsertStage::admit_unverified`).
pub fn configure_data_path(mut builder: EngineBuilder, cfg: &ForwarderConfig) -> EngineBuilder {
    builder = builder
        .security_profile(security_profile(cfg))
        .admission_policy(admission_policy(cfg));
    for rule_cfg in &cfg.security.rules {
        let rule_text = format!("{} => {}", rule_cfg.data, rule_cfg.key);
        match ndn_security::SchemaRule::parse(&rule_text) {
            Ok(rule) => builder = builder.schema_rule(rule),
            Err(e) => tracing::warn!(
                target: "security",
                data = %rule_cfg.data,
                key = %rule_cfg.key,
                error = %e,
                "ignoring invalid [[security.rule]] in config"
            ),
        }
    }
    builder
}

/// Load the forwarder identity `[security] identity` from the PIB at
/// `pib_path` -- its signing key, its certificate, and the PIB's trust anchors,
/// which are what a `profile = "default"` validator chains forwarded Data to.
/// With `[security] auto_init` a PIB without keys gets a generated self-signed
/// identity (also an anchor); the `bool` reports that.
///
/// `Ok(None)` when no identity is configured: the forwarder then runs on
/// [`ephemeral_identity`]. Where the PIB lives when `[security] pib_path` is
/// unset is the caller's platform policy (`ndn-fwd`: `~/.ndn/pib`), hence the
/// explicit `pib_path`.
pub fn load_identity(
    cfg: &ForwarderConfig,
    pib_path: &std::path::Path,
) -> Result<Option<(ndn_security::SecurityManager, bool)>, ndn_security::TrustError> {
    use ndn_security::{FilePib, SecurityManager, TrustError};
    let Some(uri) = &cfg.security.identity else {
        return Ok(None);
    };
    let identity: Name = uri
        .parse()
        .map_err(|e| TrustError::KeyStore(format!("invalid [security] identity {uri:?}: {e}")))?;
    if cfg.security.auto_init {
        return SecurityManager::auto_init(&identity, pib_path).map(Some);
    }
    let pib = FilePib::open(pib_path)?;
    Ok(Some((SecurityManager::from_pib(&pib, &identity)?, false)))
}

/// The identity a forwarder runs on when `[security]` configures none (and
/// what `ndn-fwd` falls back to when its PIB cannot be loaded): a fresh
/// in-memory ECDSA-P256 key named `[security] ephemeral_prefix`, else
/// `/ndn-fwd/<host>`. Its self-signed certificate is the node's only trust
/// anchor, so under `profile = "default"` key-signed Data from anyone else
/// fails closed. Returns the manager and the identity name. `host` is the
/// caller's (`ndn-fwd`: `$HOSTNAME`, else `pid-<pid>`).
///
/// ECDSA-P256 is the lowest common denominator for ndn-cxx interop: ndn-cxx's
/// `KeyType` has RSA + EC + AES + HMAC but no Ed25519, so management responses
/// signed with Ed25519 fail to verify against an ndn-cxx trust schema.
pub fn ephemeral_identity(
    cfg: &ForwarderConfig,
    host: &str,
) -> Result<(ndn_security::SecurityManager, String), ndn_security::TrustError> {
    let name = cfg
        .security
        .ephemeral_prefix
        .clone()
        .unwrap_or_else(|| format!("/ndn-fwd/{host}"));
    let keychain = ndn_security::KeyChain::ephemeral_ecdsa(&name)?;
    // `into_manager_arc` consumes the keychain so its internal `Arc::clone`
    // drops first, letting `try_unwrap` succeed and the signer survive for
    // mgmt-response signing. The fallback copies only the trust anchors and is
    // hit only when a second `Arc` leaked.
    let mgr = Arc::try_unwrap(keychain.into_manager_arc()).unwrap_or_else(|shared| {
        let m = ndn_security::SecurityManager::new();
        for n in shared.trust_anchor_names() {
            if let Some(cert) = shared.trust_anchor(&n) {
                m.add_trust_anchor(cert);
            }
        }
        m
    });
    Ok((mgr, name))
}

/// The Data-path validation profile.
///
/// A config with NO `[security]` table gets `SecurityConfig::default()`, whose
/// `validator_enabled` is `false`, so it forwards Data unvalidated -- the
/// per-field serde defaults (`validator_enabled = true`, `profile =
/// "default"`) apply only when the table is present.
fn security_profile(cfg: &ForwarderConfig) -> ndn_security::SecurityProfile {
    use ndn_security::SecurityProfile;
    if !cfg.security.validator_enabled {
        return SecurityProfile::Disabled;
    }
    match cfg.security.profile.as_str() {
        "disabled" => SecurityProfile::Disabled,
        "accept-signed" => SecurityProfile::AcceptSigned,
        "default" => SecurityProfile::Default,
        other => {
            // Full validation is the safe reading of a value we do not know,
            // but say so: `accept_signed` (underscore, as in the testbed's DV
            // config) silently meant full chain validation.
            tracing::warn!(
                target: "security",
                profile = %other,
                "unknown [security] profile; using \"default\" (full chain validation)",
            );
            SecurityProfile::Default
        }
    }
}

fn admission_policy(cfg: &ForwarderConfig) -> Arc<dyn ndn_store::CsAdmissionPolicy> {
    match cfg.cs.admission_policy.as_str() {
        "admit-all" => Arc::new(ndn_store::AdmitAllPolicy),
        _ => Arc::new(ndn_store::DefaultAdmissionPolicy),
    }
}

/// Install `[[route]]` entries as RIB routes and push them to the FIB.
///
/// `face_ids_by_index[i]` is the FaceId assigned to the `i`-th `[[face]]`
/// entry (`RouteConfig::face` indexes it). A route whose index is out of range
/// or whose prefix is not a valid NDN name is logged and skipped. Returns the
/// number of routes installed.
pub fn install_routes(
    engine: &ForwarderEngine,
    routes: &[RouteConfig],
    face_ids_by_index: &[FaceId],
) -> usize {
    let mut installed = 0;
    for route in routes {
        let Some(&face_id) = face_ids_by_index.get(route.face) else {
            tracing::error!(
                target: "engine",
                prefix = %route.prefix,
                face_index = route.face,
                faces = face_ids_by_index.len(),
                "route references a [[face]] index out of range; skipping",
            );
            continue;
        };
        let Some(name) = parse_prefix(&route.prefix, "[[route]]") else {
            continue;
        };
        // Install as a RIB route with origin STATIC, not a bare FIB nexthop.
        //
        // The RIB computes each FIB entry from the routes it tracks and writes
        // the result with `Fib::set_nexthops`, which REPLACES the entry. A
        // nexthop added straight to the FIB here is invisible to the RIB, so
        // the first recompute for this prefix — which happens as soon as a
        // local app registers the same prefix — silently drops every config
        // route. Observed on a 3-drone fleet: a `[[route]] prefix="/muas"` per
        // peer produced three FIB nexthops at startup and exactly ONE after
        // the application registered /muas, so per-node service Interests
        // could only ever reach whichever peer survived.
        //
        // Going through the RIB is also what `nfdc route add` does (origin
        // static = 255), so a config route and an operator-added route now
        // behave identically and merge instead of racing.
        // CHILD_INHERIT, matching `nfdc route add`'s default. Without it the
        // RIB does not propagate this nexthop to a descendant prefix that has
        // its own RIB entry — so as soon as an application registers, say,
        // /muas/v2/group, LPM stops there, the config route's peer nexthop is
        // invisible, and the Interest is dropped `reason=NoRoute`. Measured in
        // a two-node netns reproducer: SVS sync Interests on /muas/v2/group
        // NoRoute'd on BOTH nodes, so every NDNSF service call (which rides
        // SVS pub/sub) timed out even though /muas itself had a nexthop.
        let route_entry = RibRoute {
            face_id,
            origin: origin::STATIC,
            cost: route.cost,
            flags: route_flags::CHILD_INHERIT,
            expires_at: None,
        };
        engine.rib().add(&name, route_entry);
        engine.rib().apply_to_fib(&name, &engine.fib());
        tracing::info!(target: "engine", prefix = %route.prefix, face_index = route.face, face = face_id.0, cost = route.cost, "route added");
        installed += 1;
    }
    installed
}

/// Install `[[strategy]]` choices. Returns the number installed; an entry
/// with an invalid prefix or an unknown strategy name is logged and skipped,
/// leaving its prefix on the default strategy.
pub fn install_strategies(engine: &ForwarderEngine, choices: &[StrategyConfig]) -> usize {
    // Boot-time strategy choices, applied through the same resolver the
    // `strategy-choice/set` management verb uses so a TOML `[[strategy]]`
    // entry and an `ndn-ctl strategy set` accept exactly the same names.
    //
    // Without this the strategy table is reachable ONLY over the management
    // socket, so it lives purely in memory: a choice applied by a post-start
    // script is lost on the next forwarder restart, silently, while the
    // `[[route]]` entries survive because they are config. Measured on a
    // 3-airframe fleet (2026-09-18): `strategy list` showed only
    // `/ -> best-route` on all four nodes, so `/muas` had reverted to
    // best-route and each node's SVS sync Interest reached exactly ONE peer
    // instead of all three. That partitions the sync group -- every NDNSF
    // service call timed out at 15s with ackCount=0, while plain fetches still
    // worked because best-route retries other nexthops on nack/timeout and
    // group fan-out cannot.
    let mut installed = 0;
    for choice in choices {
        let Some(prefix) = parse_prefix(&choice.prefix, "[[strategy]]") else {
            continue;
        };
        let Some(strategy) =
            strategy_name(&choice.strategy).and_then(|n| ndn_mgmt::create_strategy_by_name(&n))
        else {
            tracing::error!(
                target: "engine",
                prefix = %choice.prefix,
                strategy = %choice.strategy,
                "unknown strategy in [[strategy]]; leaving prefix on the default strategy",
            );
            continue;
        };
        engine.strategy_table().insert(&prefix, strategy);
        tracing::info!(
            target: "engine",
            prefix = %choice.prefix,
            strategy = %choice.strategy,
            "strategy choice installed",
        );
        installed += 1;
    }
    installed
}

/// A config prefix, or `None` (logged) when it is not a valid NDN name.
///
/// Never fall back to `/`: the previous `unwrap_or(Name::root())` turned a
/// typo such as `prefix = "muas"` (no leading slash) into a DEFAULT route, or
/// into a strategy change for the whole namespace, with no error anywhere.
fn parse_prefix(uri: &str, table: &str) -> Option<Name> {
    match uri.parse() {
        Ok(name) => Some(name),
        Err(e) => {
            tracing::error!(
                target: "engine",
                prefix = %uri,
                error = %e,
                "invalid prefix in {table}; skipping",
            );
            None
        }
    }
}

/// The strategy name a `[[strategy]] strategy` value denotes. `StrategyConfig`
/// documents two forms: fully qualified (`/localhost/nfd/strategy/multicast`)
/// and the bare registry short name (`multicast`). Name's URI parser rejects
/// the bare form (no leading `/`), and ndn-fwd mapped that error to `/`, which
/// names no strategy — so the documented short form was always dropped as
/// "unknown strategy". Lift it to the one-component name the resolver accepts.
fn strategy_name(s: &str) -> Option<Name> {
    let s = s.trim();
    if s.starts_with('/') {
        s.parse().ok()
    } else {
        format!("/{s}").parse().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(uri: &str) -> Name {
        uri.parse().unwrap()
    }

    fn fib_faces(engine: &ForwarderEngine, name: &str) -> Vec<u64> {
        let mut faces: Vec<u64> = engine
            .fib()
            .lpm(&n(name))
            .map(|e| e.nexthops.iter().map(|h| h.face_id.0).collect())
            .unwrap_or_default();
        faces.sort_unstable();
        faces
    }

    /// What `rib/register` does for a local application (origin APP, no
    /// flags): add a RIB route and recompute that prefix's FIB entry.
    fn app_registers(engine: &ForwarderEngine, prefix: &str, face: u64) {
        engine.rib().add(
            &n(prefix),
            RibRoute {
                face_id: FaceId(face),
                origin: origin::APP,
                cost: 0,
                flags: 0,
                expires_at: None,
            },
        );
        engine.rib().apply_to_fib(&n(prefix), &engine.fib());
    }

    fn route(prefix: &str, face: usize) -> RouteConfig {
        RouteConfig {
            prefix: prefix.into(),
            face,
            cost: 10,
        }
    }

    /// The two fleet failures of config routes: (1) a later RIB recompute for
    /// the same prefix (an app registering /muas) must MERGE with the config
    /// routes, not replace them; (2) a descendant the app registers later
    /// (the SVS group /muas/v2/group) must still reach every configured peer.
    #[tokio::test]
    async fn config_routes_survive_app_registration_and_reach_descendants() {
        let (engine, _shutdown) = EngineBuilder::new(ndn_engine::EngineConfig::default())
            .build()
            .await
            .unwrap();
        let peers = [FaceId(101), FaceId(102), FaceId(103)];
        let routes = [
            route("/muas", 0),
            route("/muas", 1),
            route("/muas", 2),
            route("/muas", 7), // no 8th [[face]]
            route("muas", 0),  // not a name: must not become a default route
        ];

        assert_eq!(install_routes(&engine, &routes, &peers), 3);
        assert_eq!(fib_faces(&engine, "/unrelated"), Vec::<u64>::new());

        app_registers(&engine, "/muas", 9);
        assert_eq!(
            fib_faces(&engine, "/muas/node-2/svc"),
            vec![9, 101, 102, 103],
            "the app's registration merges with the config routes"
        );

        app_registers(&engine, "/muas/v2/group", 9);
        assert_eq!(
            fib_faces(&engine, "/muas/v2/group/seq=4"),
            vec![9, 101, 102, 103],
            "a descendant registered later inherits every configured peer"
        );
    }

    /// Which fleet configs validate forwarded Data. The surprise this pins: a
    /// config with NO `[security]` table does not validate at all (derived
    /// `SecurityConfig::default()`), while an empty `[security]` table turns
    /// on full chain validation (per-field serde defaults) -- under which Data
    /// signed by a peer whose certificate is not cached is dropped.
    #[test]
    fn security_table_presence_decides_data_validation() {
        use ndn_security::SecurityProfile as P;
        let profile = |toml: &str| security_profile(&toml.parse::<ForwarderConfig>().unwrap());

        assert!(matches!(profile(""), P::Disabled), "no [security] table");
        assert!(matches!(profile("[security]\n"), P::Default), "empty table");
        assert!(matches!(
            profile("[security]\nprofile = \"disabled\"\n"),
            P::Disabled
        ));
        assert!(matches!(
            profile("[security]\nprofile = \"accept-signed\"\n"),
            P::AcceptSigned
        ));
        assert!(
            matches!(
                profile("[security]\nprofile = \"accept_signed\"\n"),
                P::Default
            ),
            "an unknown spelling falls back to full validation (and is logged)"
        );
    }

    #[tokio::test]
    async fn strategy_choices_accept_both_documented_name_forms() {
        let (engine, _shutdown) = EngineBuilder::new(ndn_engine::EngineConfig::default())
            .build()
            .await
            .unwrap();
        let choice = |prefix: &str, strategy: &str| StrategyConfig {
            prefix: prefix.into(),
            strategy: strategy.into(),
        };
        let choices = [
            choice("/muas", "multicast"),
            choice("/fleet", "/localhost/nfd/strategy/multicast"),
            choice("/other", "no-such-strategy"),
            choice("typo", "multicast"), // not a name: must not retarget `/`
        ];

        assert_eq!(install_strategies(&engine, &choices), 2);
        let strategy_at = |name: &str| {
            engine
                .strategy_table()
                .lpm(&n(name))
                .map(|s| s.name().to_string())
                .unwrap()
        };
        assert!(strategy_at("/muas/v2/group").contains("/multicast"));
        assert!(strategy_at("/fleet/x").contains("/multicast"));
        assert!(
            !strategy_at("/other/x").contains("/multicast"),
            "an unknown strategy leaves the prefix on the default"
        );
        assert!(
            !strategy_at("/typo").contains("/multicast"),
            "an invalid prefix must not change the root strategy"
        );
    }
}
