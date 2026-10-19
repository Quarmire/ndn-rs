//! Adopting a namespace's trust context from an `ndn-trust://anchor` link,
//! and refreshing a held one, through an engine — the calls both the
//! `ndn-fwd` daemon and an app's embedded engine (ndn-mobile) make.
//!
//! The protocol logic is [`ndn_cert::adopt_anchor_link`] and
//! [`ndn_cert::refresh_context`]; this module binds it to an engine: the
//! context is fetched on a short-lived in-process consumer face (so the
//! Interests are forwarded by the engine's FIB toward the namespace), and the
//! engine's own data-path validator is told to expect that context, so it
//! admits the context Data — and drops a forged one, recording why — even
//! when it does not hold the context itself.

use bytes::Bytes;
use ndn_app::ForwarderEngine;
use ndn_cert::{
    AdoptError, AnchorLink, CaExchange, CertError, ContextRefresh, LinkAdoption, RefreshError,
};
use ndn_packet::{Data, Name};
use ndn_security::Keyring;

use crate::engine_exchange::EngineExchange;

/// Adopt the namespace `link` names into `keyring`, fetching the context
/// through `engine` when the link carries only a fingerprint (see
/// [`ndn_cert::adopt_anchor_link`] for the checks). The consumer face lives
/// only for this call (its fetches are bounded by the Interest timeout).
/// Persisting and publishing the adopted context are the caller's.
pub async fn adopt_anchor_link_via_engine(
    engine: &ForwarderEngine,
    keyring: &Keyring,
    link: &AnchorLink,
) -> Result<LinkAdoption, AdoptError> {
    if link.context_data.is_some() {
        // Inline: no network, no consumer face.
        return ndn_cert::adopt_anchor_link(keyring, None, &mut NoNetwork, link).await;
    }
    let validator = engine.validator();
    let mut exchange = EngineExchange::new(engine);
    ndn_cert::adopt_anchor_link(keyring, validator.as_deref(), &mut exchange, link).await
}

/// Check `namespace` for a newer version of the context held in `keyring`
/// and adopt it if it is signed by an anchor of the held version and newer
/// — or, when it is not, if the versions in between lead to it, each signed
/// by an anchor of the one before (see [`ndn_cert::refresh_context`]). The
/// Interests go out through `engine`'s FIB — the caller makes sure they
/// reach the forwarders upstream rather than a local publisher of the
/// versions already held. Persisting and publishing an adopted update, and
/// the versions it walked through (`ContextUpdate::walked`), are the
/// caller's.
pub async fn refresh_context_via_engine(
    engine: &ForwarderEngine,
    keyring: &Keyring,
    namespace: &Name,
) -> Result<ContextRefresh, RefreshError> {
    let validator = engine.validator();
    let mut exchange = EngineExchange::new(engine);
    ndn_cert::refresh_context(keyring, validator.as_deref(), &mut exchange, namespace).await
}

/// The exchange for an inline link, which never expresses an Interest.
struct NoNetwork;

impl CaExchange for NoNetwork {
    async fn express(&mut self, _interest: Bytes) -> Result<Data, CertError> {
        Err(CertError::Transport(
            "inline adoption does not fetch".into(),
        ))
    }
}
