//! Reading the structured refusals of management verbs.
//!
//! A trust-admin, approval, invite or link verb that refuses answers a
//! ControlResponse whose status code is the refusal's and whose status text
//! is a [`TrustRefusal`] as JSON (`ndn-rs/docs/specs/mgmt-trust.md`). These
//! helpers turn such an answer back into the refusal, so a client words its
//! own message from the code and parameters.

use ndn_mgmt_wire::ControlResponse;

pub use ndn_cert::report::{Detail, NextStep, TrustRefusal};

use crate::ForwarderError;

/// The structured refusal `resp` carries: `Some` when its status code is an
/// error (≥ 400) and its status text is a [`TrustRefusal`] as JSON; `None`
/// for a success or an untyped error text.
pub fn trust_refusal(resp: &ControlResponse) -> Option<TrustRefusal> {
    trust_refusal_of(resp.status_code, &resp.status_text)
}

/// As [`trust_refusal`], from an answer's status code and text (e.g. those
/// of a [`ForwarderError::Command`]).
pub fn trust_refusal_of(status_code: u64, status_text: &str) -> Option<TrustRefusal> {
    if status_code < 400 {
        return None;
    }
    serde_json::from_str(status_text).ok()
}

/// The structured refusal a [`ForwarderError::Command`] carries (as
/// [`trust_refusal`]); `None` for any other error.
pub fn trust_refusal_in(err: &ForwarderError) -> Option<TrustRefusal> {
    match err {
        ForwarderError::Command { code, text } => trust_refusal_of(*code, text),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_cert::report::code;

    #[test]
    fn a_refusal_round_trips_through_a_control_response() {
        let refusal =
            TrustRefusal::new(code::NOT_AT_RUNTIME, "not here").with("operation", "enroll");
        let resp = ControlResponse::error(
            refusal.status_code,
            serde_json::to_string(&refusal).unwrap(),
        );
        assert_eq!(trust_refusal(&resp), Some(refusal));
    }

    #[test]
    fn success_and_untyped_errors_are_no_refusal() {
        assert_eq!(trust_refusal_of(200, "{}"), None);
        assert_eq!(trust_refusal_of(500, "something broke"), None);
    }
}
