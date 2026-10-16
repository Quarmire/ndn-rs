//! Enrolling a device key with an `ndn-trust://invite` link through an
//! engine — the one call both the `ndn-fwd` daemon (`security/enroll`) and an
//! app's embedded engine (ndn-mobile) make.
//!
//! The protocol logic is [`ndn_cert::enroll_with_invite`]; this binds it to
//! an engine: Interests go out on a short-lived in-process consumer face (so
//! the engine's FIB forwards them toward the CA), and the engine's own
//! data-path validator is told to expect the trust context while it is
//! adopted.

use std::sync::Arc;

use ndn_app::ForwarderEngine;
use ndn_cert::{InviteEnrollFailure, InviteEnrollment, InviteLink};
use ndn_security::{Keyring, Signer};

use crate::engine_exchange::EngineExchange;

/// Enroll `device_key` with the CA `invite` names, through `engine`: adopt
/// the invite's trust context into `keyring` if it is not held, run NDNCERT
/// with the invite's token, fetch and check the issued certificate (its
/// chain is checked against `keyring`). Storing the key's certificate,
/// persisting an adopted context and selecting the identity are the
/// caller's. See [`ndn_cert::enroll_with_invite`].
pub async fn enroll_with_invite_via_engine(
    engine: &ForwarderEngine,
    keyring: &Arc<Keyring>,
    invite: &InviteLink,
    device_key: Arc<dyn Signer>,
    validity_secs: u64,
) -> Result<InviteEnrollment, InviteEnrollFailure> {
    let validator = engine.validator();
    let mut exchange = EngineExchange::new(engine);
    ndn_cert::enroll_with_invite(
        keyring,
        validator.as_deref(),
        &mut exchange,
        invite,
        device_key,
        validity_secs,
    )
    .await
}
