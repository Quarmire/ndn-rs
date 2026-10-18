//! Enrollment by an admin's approval through an engine — the calls the
//! `ndn-fwd` daemon and an app's embedded engine (ndn-mobile) both make:
//!
//! - the **requester** waits on its request's held status
//!   ([`request_status_via_engine`]) and, once an admin approved it, asks
//!   the CA with a fresh NDNCERT exchange ([`poll_approval_via_engine`]),
//!   which issues the certificate;
//! - an **admin device** lists what is pending ([`fetch_pending_via_engine`])
//!   and pushes its signed decision ([`push_decision_via_engine`]).
//!
//! The protocol is [`ndn_cert::approval`]; this binds it to an engine:
//! Interests go out on a short-lived in-process consumer face, so the
//! engine's FIB forwards them toward the CA. Persisting the requester's
//! outgoing request ([`ndn_cert::RequestStore`]) and storing an issued
//! certificate are the caller's.

use std::sync::Arc;

use bytes::Bytes;
use ndn_app::ForwarderEngine;
use ndn_cert::{
    ApprovalEnrollError, ApprovalPoll, ApprovalRecord, ApproverError, Decision, RequestStatus,
};
use ndn_packet::Name;
use ndn_security::{Keyring, Signer};

use crate::engine_exchange::EngineExchange;

/// The longest [`poll_approval_via_engine`] can take: every exchange it may
/// make ([`ndn_cert::approval::POLL_MAX_EXCHANGES`]) timing out at the
/// engine consumer's per-Interest timeout.
pub fn poll_via_engine_budget() -> std::time::Duration {
    ndn_app::DEFAULT_TIMEOUT * ndn_cert::approval::POLL_MAX_EXCHANGES
}

/// One poll of the CA at `ca_prefix` (of `namespace`, whose trust context
/// `keyring` holds) for `device_key`, through `engine`: see
/// [`ndn_cert::poll_approval`].
pub async fn poll_approval_via_engine(
    engine: &ForwarderEngine,
    keyring: &Arc<Keyring>,
    namespace: &Name,
    ca_prefix: &Name,
    device_key: Arc<dyn Signer>,
    resume: Option<&str>,
    token: Option<&str>,
) -> Result<ApprovalPoll, ApprovalEnrollError> {
    let mut exchange = EngineExchange::new(engine);
    ndn_cert::poll_approval(
        &mut exchange,
        keyring,
        namespace,
        ca_prefix,
        device_key,
        resume,
        token,
    )
    .await
}

/// Wait for request `request_id` (made for `key_name`) at the CA
/// `ca_prefix` of `namespace` with one status Interest of `lifetime`,
/// through `engine`: see [`ndn_cert::request_status`]. Returns when the CA
/// answers — at once when the request is decided or expired, else shortly
/// before `lifetime` ends — or when the Interest times out.
pub async fn request_status_via_engine(
    engine: &ForwarderEngine,
    keyring: &Arc<Keyring>,
    namespace: &Name,
    ca_prefix: &Name,
    request_id: &str,
    key_name: &str,
    lifetime: std::time::Duration,
) -> Result<RequestStatus, ApprovalEnrollError> {
    let mut exchange = EngineExchange::new(engine);
    ndn_cert::request_status(
        &mut exchange,
        keyring,
        namespace,
        ca_prefix,
        request_id,
        key_name,
        lifetime,
    )
    .await
}

/// The pending requests at the CA `ca_prefix` of `namespace`, asked as the
/// admin key `admin` (with its certificate chain `admin_chain`), through
/// `engine`: see [`ndn_cert::fetch_pending`].
pub async fn fetch_pending_via_engine(
    engine: &ForwarderEngine,
    keyring: &Arc<Keyring>,
    namespace: &Name,
    ca_prefix: &Name,
    admin: &Arc<dyn Signer>,
    admin_chain: &[Bytes],
) -> Result<Vec<ApprovalRecord>, ApproverError> {
    let mut exchange = EngineExchange::new(engine);
    ndn_cert::fetch_pending(&mut exchange, keyring, namespace, ca_prefix, admin, admin_chain).await
}

/// Decide `record` as the admin key `admin`, through `engine`: see
/// [`ndn_cert::push_decision`].
pub async fn push_decision_via_engine(
    engine: &ForwarderEngine,
    keyring: &Arc<Keyring>,
    namespace: &Name,
    record: &ApprovalRecord,
    decision: &Decision,
    admin: &Arc<dyn Signer>,
    admin_chain: &[Bytes],
) -> Result<ApprovalRecord, ApproverError> {
    let mut exchange = EngineExchange::new(engine);
    ndn_cert::push_decision(
        &mut exchange,
        keyring,
        namespace,
        record,
        decision,
        admin,
        admin_chain,
    )
    .await
}
