//! Reusable multicast face provisioning: interface enumeration, auto-creation
//! of multicast UDP / Ethernet faces, and OS interface hotplug.
//!
//! This logic used to live in the `ndn-fwd` binary, which made it unavailable
//! to the other engines (mobile, in-browser). It is written here against
//! [`ndn_transport::FaceSink`] so any engine can opt in: the forwarder, the
//! mobile engine, and anything else embedding a `ForwarderEngine`.
//!
//! It is deliberately config-agnostic (plain fields, not `ndn-config` types) so
//! this crate needn't depend on the config crate; callers map their own
//! configuration onto [`MulticastProvisionConfig`].

use ndn_transport::{FacePersistency, FaceSink};
use tokio_util::sync::CancellationToken;

use crate::iface::{self, interface_allowed};

/// Knobs for [`provision`]. `*_whitelist`/`*_blacklist` are interface-name glob
/// patterns (`*` / `?`); an empty whitelist allows all.
#[derive(Clone, Debug, Default)]
pub struct MulticastProvisionConfig {
    /// Create a multicast UDP face per eligible interface address.
    pub udp_auto: bool,
    /// Advertise UDP multicast faces as `AdHoc` (wireless) rather than
    /// `MultiAccess` — suppresses multi-access duplicate suppression.
    pub udp_ad_hoc: bool,
    pub udp_whitelist: Vec<String>,
    pub udp_blacklist: Vec<String>,
    /// Create a multicast Ethernet face per eligible interface (Linux only).
    pub ether_auto: bool,
    pub ether_whitelist: Vec<String>,
    pub ether_blacklist: Vec<String>,
    /// Add/remove faces as interfaces appear/disappear (Linux netlink).
    pub watch_interfaces: bool,
}

/// Eligible link: up, multicast-capable, not loopback.
fn eligible(i: &iface::InterfaceInfo) -> bool {
    i.is_up && i.is_multicast && !i.is_loopback
}

/// Enumerate interfaces now and spawn the hotplug watcher (if enabled). The
/// all-in-one entry point for engines that manage their own faces entirely
/// (mobile, in-browser). Faces are installed `Permanent`. Returns once spawns
/// are issued; tasks run until `cancel` fires.
pub fn provision<S: FaceSink>(
    sink: &S,
    cfg: &MulticastProvisionConfig,
    cancel: &CancellationToken,
) {
    provision_initial(sink, cfg, cancel);
    if cfg.watch_interfaces {
        spawn_hotplug_watcher(sink.clone(), cfg.clone(), cancel.child_token());
    }
}

/// Create multicast faces for every currently-eligible interface. Split out so
/// a caller that pre-allocates face ids elsewhere (e.g. the forwarder when
/// neighbour discovery is on) can skip it and still run [`spawn_hotplug_watcher`].
pub fn provision_initial<S: FaceSink>(
    sink: &S,
    cfg: &MulticastProvisionConfig,
    cancel: &CancellationToken,
) {
    if !(cfg.udp_auto || cfg.ether_auto) {
        return;
    }
    for info in iface::list_interfaces() {
        if eligible(&info) {
            provision_interface(sink, &info.name, cfg, cancel);
        }
    }
}

/// Create the configured multicast faces for a single (already-eligible)
/// interface. Shared by initial enumeration and hotplug.
fn provision_interface<S: FaceSink>(
    sink: &S,
    iface_name: &str,
    cfg: &MulticastProvisionConfig,
    cancel: &CancellationToken,
) {
    if cfg.udp_auto && interface_allowed(iface_name, &cfg.udp_whitelist, &cfg.udp_blacklist) {
        // One multicast UDP face per IPv4 address on the interface.
        if let Some(info) = iface::list_interfaces()
            .into_iter()
            .find(|i| i.name == iface_name)
        {
            for addr in info.ipv4_addrs {
                let sink = sink.clone();
                let child = cancel.child_token();
                let ad_hoc = cfg.udp_ad_hoc;
                let name = iface_name.to_owned();
                let id = sink.alloc_face_id();
                tokio::spawn(async move {
                    match crate::net::MulticastUdpFace::ndn_default(addr, id).await {
                        Ok(face) => {
                            let face = if ad_hoc { face.ad_hoc() } else { face };
                            sink.install_transport(face, child, FacePersistency::Permanent);
                            tracing::info!(target: "face.udp", iface=%name, addr=%addr, face=%id, "auto multicast UDP face opened");
                        }
                        Err(e) => {
                            tracing::warn!(target: "face.udp", iface=%name, addr=%addr, error=%e, "auto multicast UDP face failed");
                        }
                    }
                });
            }
        }
    }

    #[cfg(all(feature = "l2", target_os = "linux"))]
    if cfg.ether_auto && interface_allowed(iface_name, &cfg.ether_whitelist, &cfg.ether_blacklist) {
        let id = sink.alloc_face_id();
        match crate::l2::MulticastEtherFace::new(id, iface_name) {
            Ok(face) => {
                sink.install_transport(face, cancel.child_token(), FacePersistency::Permanent);
                tracing::info!(target: "face.eth", iface=%iface_name, face=%id, "auto multicast ethernet face opened");
            }
            Err(e) => {
                tracing::warn!(target: "face.eth", iface=%iface_name, error=%e, "auto multicast ethernet face failed");
            }
        }
    }
}

/// Spawn the netlink interface watcher and the add/remove reactor. On `Added`
/// it provisions the (filtered) faces; on `Removed` it tears down faces whose
/// `local_uri` is `dev://<iface>`. Linux netlink; a no-op-with-warning watcher
/// elsewhere.
pub fn spawn_hotplug_watcher<S: FaceSink>(
    sink: S,
    cfg: MulticastProvisionConfig,
    cancel: CancellationToken,
) {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<crate::iface_watcher::InterfaceEvent>(64);
    tokio::spawn(crate::iface_watcher::watch_interfaces(
        tx,
        cancel.child_token(),
    ));

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                event = rx.recv() => {
                    let Some(event) = event else { break };
                    match event {
                        crate::iface_watcher::InterfaceEvent::Added(name) => {
                            provision_interface(&sink, &name, &cfg, &cancel);
                        }
                        crate::iface_watcher::InterfaceEvent::Removed(name) => {
                            let target = format!("dev://{name}");
                            for id in sink.installed_face_ids() {
                                if sink.face_local_uri(id).as_deref() == Some(&target) {
                                    sink.cancel_face(id);
                                    tracing::info!(target: "face.system", iface=%name, face=%id, "hotplug: face removed");
                                }
                            }
                        }
                    }
                }
            }
        }
    });
}
