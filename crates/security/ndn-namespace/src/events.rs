//! The trust events this crate tells the host of ([`crate::Participant::events`]),
//! built here from what the operations already hold, so each source tells
//! of its change in one line. Membership changes are built in
//! [`crate::membership`].

use ndn_cert::OutgoingRequest;
use ndn_cert::OutgoingState;
use ndn_cert::report::{ContextChange, EnrollmentEnd, RenewalFailure, TrustEvent};
use ndn_packet::Name;

use crate::{Participant, RenewalState};

/// This device now holds `version` of `namespace`, reached `how`.
pub(crate) fn context_kept(
    p: &Participant,
    namespace: &Name,
    held_version: Option<u64>,
    version: u64,
    how: ContextChange,
    revoked: Vec<String>,
) {
    p.emit(TrustEvent::ContextUpdated {
        namespace: namespace.to_string(),
        held_version,
        version,
        how,
        revoked,
    });
}

/// `request` ended without a certificate (denied, expired, failed); nothing
/// for one still pending or issued (an issued one is told of as a
/// membership change when it is installed).
pub(crate) fn request_ended(p: &Participant, request: &OutgoingRequest) {
    let state = match request.state {
        OutgoingState::Denied { .. } => EnrollmentEnd::Denied,
        OutgoingState::Expired { .. } => EnrollmentEnd::Expired,
        OutgoingState::Failed { .. } => EnrollmentEnd::Failed,
        OutgoingState::Pending | OutgoingState::Issued { .. } => return,
    };
    p.emit(TrustEvent::EnrollmentEnded {
        namespace: request.namespace.clone(),
        identity: request.identity.clone(),
        request: request.request_id.clone(),
        state,
    });
}

/// The renewal of `key`'s certificate failed (`state`, detail `code`).
pub(crate) fn renewal_failed(p: &Participant, key: &Name, state: RenewalState, code: Option<&str>) {
    p.emit(TrustEvent::RenewalFailed {
        key: key.to_string(),
        state: match state {
            RenewalState::Refused => RenewalFailure::Refused,
            _ => RenewalFailure::Failed,
        },
        code: code.map(str::to_owned),
    });
}
