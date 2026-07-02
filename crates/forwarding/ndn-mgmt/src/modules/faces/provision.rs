//! Pluggable face provisioning — the seam that keeps `ndn-mgmt` free of the
//! **extension** face crates.
//!
//! The standard transports (UDP/TCP/Ethernet/BLE/SHM) are built inline in
//! [`super::create`] over `ndn-face-native` (a spec crate). The extension
//! transports — raw QUIC (`quic://`) and WebTransport (`wts://`) — live in their
//! own crates outside the library closure, so `ndn-mgmt` must not construct them
//! directly. Instead the forwarder registers a [`FaceProvisioner`] per extension
//! scheme via [`MgmtHandles::face_provisioners`](crate::MgmtHandles); when
//! `faces/create` sees a URI no built-in arm handles, it falls through to the
//! first provisioner that claims it.

use async_trait::async_trait;
use ndn_engine::ForwarderEngine;
use ndn_mgmt_wire::ControlParameters;
use ndn_transport::{FaceId, FacePersistency};

/// A face a provisioner built and registered with the engine, described back to
/// the `faces/create` client. The dispatcher turns this into the NFD echo.
pub struct ProvisionedFace {
    pub face_id: FaceId,
    /// Canonical remote URI to echo (e.g. `quic://host:port`).
    pub remote_uri: String,
    pub local_uri: Option<String>,
    pub persistency: FacePersistency,
}

/// Why provisioning failed — maps to the control-response status code.
pub enum ProvisionError {
    /// Malformed client input → `400 BAD_PARAMS`.
    BadParams(String),
    /// Backend / dialing failure → `500 SERVER_ERROR`.
    Server(String),
}

/// Inputs for one `faces/create` provisioning attempt.
pub struct ProvisionRequest<'a> {
    /// The full request URI (e.g. `quic://host:port?cert=…`).
    pub uri: &'a str,
    pub params: &'a ControlParameters,
    /// The face the command arrived on, for child-cancel scoping where relevant.
    pub source_face: Option<FaceId>,
    pub engine: &'a ForwarderEngine,
}

/// Builds and registers a face for one or more URI schemes. The forwarder
/// supplies one per **extension** transport it links; `ndn-mgmt` depends on no
/// extension face crate. Registered via
/// [`MgmtHandles::face_provisioners`](crate::MgmtHandles).
#[async_trait]
pub trait FaceProvisioner: Send + Sync {
    /// Whether this provisioner handles `uri` (typically a scheme-prefix test).
    fn handles(&self, uri: &str) -> bool;

    /// Build the face, register it with `req.engine`, and return its identity.
    async fn provision(&self, req: ProvisionRequest<'_>)
    -> Result<ProvisionedFace, ProvisionError>;
}
