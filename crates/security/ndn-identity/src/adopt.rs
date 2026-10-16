//! Adopting a network from an `ndn-trust://anchor` link through an engine —
//! the one call both the `ndn-fwd` daemon and an app's embedded engine
//! (ndn-mobile) make.
//!
//! The protocol logic is [`ndn_cert::adopt_anchor_link`]; this module binds
//! it to an engine: the context is fetched on a short-lived in-process
//! consumer face (so the Interests are forwarded by the engine's FIB toward
//! the network), and the engine's own data-path validator is told to expect
//! that context, so it admits the not-yet-trusted context Data — and drops a
//! forged one — instead of dropping it for lack of an anchor.

use bytes::Bytes;
use ndn_app::{Consumer, EngineAppExt, ForwarderEngine};
use ndn_cert::{AdoptError, AnchorLink, CaExchange, CertError, LinkAdoption};
use ndn_packet::Data;
use ndn_security::Keyring;
use tokio_util::sync::CancellationToken;

/// A [`CaExchange`] over an engine app consumer.
struct EngineExchange(Consumer);

impl CaExchange for EngineExchange {
    async fn express(&mut self, interest: Bytes) -> Result<Data, CertError> {
        self.0
            .fetch_wire(interest, ndn_app::DEFAULT_TIMEOUT)
            .await
            .map_err(|e| CertError::Transport(e.to_string()))
    }
}

/// Adopt the network `link` names into `keyring`, fetching the context
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
    let face_cancel = CancellationToken::new();
    let _teardown = face_cancel.clone().drop_guard();
    let mut exchange = EngineExchange(engine.app_consumer(face_cancel));
    ndn_cert::adopt_anchor_link(keyring, validator.as_deref(), &mut exchange, link).await
}

/// The exchange for an inline link, which never expresses an Interest.
struct NoNetwork;

impl CaExchange for NoNetwork {
    async fn express(&mut self, _interest: Bytes) -> Result<Data, CertError> {
        Err(CertError::Transport("inline adoption does not fetch".into()))
    }
}
