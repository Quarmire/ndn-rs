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
use ndn_security::{Keyring, ScopedContext};

use crate::engine_exchange::EngineExchange;

/// Adopt the namespace `link` names into `keyring`, fetching through
/// `engine` whatever the adoption needs from the network
/// ([`AnchorLink::fetches`]): the context of a link carrying only a
/// fingerprint or a name, and — whatever the link carries — a
/// self-certifying namespace not held, adopted by name from its fetched
/// genesis, a version 1 inline only compared with it (see
/// [`ndn_cert::adopt_anchor_link`] for the checks). An engine is a network
/// bound, so an inline version 1 is never taken alone here. The consumer
/// face lives only for this call (each fetch waits the Interest timeout, and
/// one unanswered or answered by a copy that does not verify is asked again,
/// a bounded number of times). Persisting and publishing the adopted context are the
/// caller's.
pub async fn adopt_anchor_link_via_engine(
    engine: &ForwarderEngine,
    keyring: &Keyring,
    link: &AnchorLink,
) -> Result<LinkAdoption, AdoptError> {
    if !link.fetches(keyring) {
        // Inline, and checked against the link and what is held alone
        // (another kind of namespace, or a held one moving on by
        // continuity): no consumer face.
        return ndn_cert::adopt_anchor_link(keyring, None, &mut NoNetwork, link).await;
    }
    let validator = engine.validator();
    let mut exchange = EngineExchange::fetching(engine);
    ndn_cert::adopt_anchor_link(keyring, validator.as_deref(), &mut exchange, link).await
}

/// Adopt the self-certifying namespace `namespace` by its name alone for
/// one scope of the caller's ([`ndn_cert::adopt_scoped`]): fetched through
/// `engine`, whose validator is told to expect its versions, and adopted
/// into no keyring — the engine's validator keeps refusing the namespace's
/// data as one not held. `held`, the scoped version held before, is
/// refreshed from by continuity. What the scope judges with it, and
/// carrying its data to the caller, are the caller's.
pub async fn adopt_scoped_via_engine(
    engine: &ForwarderEngine,
    namespace: &Name,
    held: Option<&ScopedContext>,
) -> Result<ScopedContext, AdoptError> {
    let validator = engine.validator();
    let mut exchange = EngineExchange::fetching(engine);
    ndn_cert::adopt_scoped(validator.as_deref(), &mut exchange, namespace, held).await
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
    let mut exchange = EngineExchange::fetching(engine);
    ndn_cert::refresh_context(keyring, validator.as_deref(), &mut exchange, namespace).await
}

/// The exchange for an inline link that fetches nothing
/// (`!AnchorLink::fetches`), which never expresses an Interest.
struct NoNetwork;

impl CaExchange for NoNetwork {
    async fn express(&mut self, _interest: Bytes) -> Result<Data, CertError> {
        Err(CertError::Transport(
            "inline adoption does not fetch".into(),
        ))
    }
}
