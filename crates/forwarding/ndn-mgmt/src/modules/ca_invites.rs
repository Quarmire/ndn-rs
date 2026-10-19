//! `/localhost/nfd/ca/{invite-create,invite-list,invite-withdraw,issued-list}`
//! — the invites of this node's CAs and the certificates they issued,
//! through its [`InviteMgmtBackend`].
//!
//! Every verb is a trust change (`auth::TRUST_ADMIN_VERBS`): it reaches this
//! module only from a local operator on the management socket, never over
//! `/localhop`. The operator the kernel attests is recorded as the invite's
//! maker.
//!
//! `ControlParameters.name` names the CA by its namespace or prefix (absent:
//! the node's only CA; `invite-list` and `issued-list` then list every
//! CA's). `invite-create` takes a JSON [`ndn_cert::InviteRequest`] in `Uri`
//! and answers the JSON [`ndn_cert::CreatedInvite`] (the only time the token
//! is shown); `invite-list` answers a JSON list of
//! [`ndn_cert::CaInviteListing`]; `invite-withdraw` takes the invite id in
//! `Uri` and answers the withdrawn [`ndn_cert::InviteEntry`]; `issued-list`
//! answers a JSON list of [`ndn_cert::CaIssuedListing`]. A refusal is a
//! [`crate::TrustRefusal`] as JSON ([`crate::refusal_response`]).

use std::sync::Arc;

use ndn_cert::report::code;
use ndn_mgmt_wire::{
    ControlParameters, ControlResponse, control_response::status, nfd_command::verb,
};

use crate::{InviteMgmtBackend, MgmtResponse, TrustRefusal, refusal_response};

/// Whether `verb_name` is one of this module's verbs.
pub(crate) fn is_invite_verb(verb_name: &[u8]) -> bool {
    [
        verb::INVITE_CREATE,
        verb::INVITE_LIST,
        verb::INVITE_WITHDRAW,
        verb::ISSUED_LIST,
    ]
    .contains(&verb_name)
}

pub(crate) fn handle_invites(
    verb_name: &[u8],
    params: ControlParameters,
    handler: Option<&Arc<dyn InviteMgmtBackend>>,
    operator: &str,
) -> MgmtResponse {
    answer(verb_name, params, handler, operator)
        .unwrap_or_else(|refusal| refusal_response(&refusal))
        .into()
}

fn answer(
    verb_name: &[u8],
    params: ControlParameters,
    handler: Option<&Arc<dyn InviteMgmtBackend>>,
    operator: &str,
) -> Result<ControlResponse, TrustRefusal> {
    let Some(handler) = handler else {
        return Err(if verb_name == verb::ISSUED_LIST {
            TrustRefusal::new(
                code::ISSUED_NO_CA,
                "this node runs no CA, so it issued no certificates",
            )
        } else {
            TrustRefusal::new(
                code::INVITE_NO_CA,
                "this node runs no CA, so it makes no invites",
            )
        });
    };
    let ca = params.name.as_ref();
    let uri = params
        .uri
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    match verb_name {
        v if v == verb::INVITE_CREATE => {
            let raw = uri.ok_or_else(|| {
                missing(
                    "invite-create",
                    "a JSON invite request: role, ttl_secs, device",
                )
            })?;
            let request: ndn_cert::InviteRequest = serde_json::from_str(raw).map_err(|e| {
                TrustRefusal::new(
                    code::INVITE_REQUEST_INVALID,
                    format!("the invite request is not readable: {e}"),
                )
                .with("error", e)
            })?;
            json(&handler.create(ca, &request, operator)?)
        }
        v if v == verb::INVITE_LIST => json(&handler.list(ca)?),
        v if v == verb::INVITE_WITHDRAW => {
            let id = uri.ok_or_else(|| missing("invite-withdraw", "the invite id"))?;
            json(&handler.withdraw(ca, id)?)
        }
        v if v == verb::ISSUED_LIST => json(&handler.issued_list(ca)?),
        _ => Ok(ControlResponse::error(status::NOT_FOUND, "unknown ca verb")),
    }
}

/// The refusal of a verb whose `Uri` is missing.
fn missing(operation: &str, expects: &str) -> TrustRefusal {
    TrustRefusal::new(
        code::MISSING_PARAMETER,
        format!("{operation} needs {expects} in Uri"),
    )
    .with("operation", operation)
    .with("parameter", "Uri")
    .with("expects", expects)
}

/// A success carrying `value` as JSON in the status text.
fn json<T: serde::Serialize>(value: &T) -> Result<ControlResponse, TrustRefusal> {
    Ok(match serde_json::to_string(value) {
        Ok(text) => ControlResponse::ok_empty(text),
        // Strings, numbers and lists of them always serialize.
        Err(e) => ControlResponse::error(status::SERVER_ERROR, format!("encode: {e}")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_cert::{
        CaInvites, CaIssuedListing, HostCas, HostInvites, HostIssued, InviteIssuer, IssuedEntry,
        TokenStore,
    };
    use ndn_packet::Name;

    /// A host with the invites of the CAs of `namespaces`, and no CA state
    /// to list issued certificates from.
    fn host(namespaces: &[&str]) -> Arc<dyn InviteMgmtBackend> {
        let invites = HostInvites::new(
            namespaces
                .iter()
                .map(|ns| {
                    let ns: Name = ns.parse().unwrap();
                    CaInvites::new(
                        TokenStore::new(),
                        InviteIssuer {
                            ca_prefix: ns.clone(),
                            namespace: ns,
                            expected_fingerprint: Some([1; 32]),
                        },
                    )
                })
                .collect(),
        );
        let issued = HostIssued::new(Vec::new(), Arc::new(ndn_security::Keyring::new()));
        Arc::new(HostCas::new(invites, issued))
    }

    fn call(
        verb_name: &[u8],
        ca: Option<&str>,
        uri: Option<&str>,
        handler: Option<&Arc<dyn InviteMgmtBackend>>,
    ) -> ControlResponse {
        let params = ControlParameters {
            name: ca.map(|c| c.parse().unwrap()),
            uri: uri.map(str::to_owned),
            ..Default::default()
        };
        match handle_invites(verb_name, params, handler, "uid 1000 (alice)") {
            MgmtResponse::Control(resp) => *resp,
            _ => panic!("invite verbs answer at once"),
        }
    }

    fn refusal_code(resp: &ControlResponse) -> String {
        let refusal: TrustRefusal = serde_json::from_str(&resp.status_text).unwrap();
        assert_eq!(resp.status_code, refusal.status_code);
        refusal.code
    }

    /// Create, list and withdraw answer typed JSON; the maker is the
    /// operator; the list shows no token.
    #[test]
    fn create_list_withdraw() {
        let backend = host(&["/home/bob"]);
        let made = call(
            verb::INVITE_CREATE,
            None,
            Some(r#"{"role":"guest","ttl_secs":3600,"device":"tv"}"#),
            Some(&backend),
        );
        assert!(made.is_ok(), "{}", made.status_text);
        let made: ndn_cert::CreatedInvite = serde_json::from_str(&made.status_text).unwrap();
        assert_eq!(made.info.role.as_deref(), Some("guest"));
        assert_eq!(made.info.device.as_deref(), Some("tv"));
        assert_eq!(made.info.created_by, "uid 1000 (alice)");
        assert!(made.link.starts_with("ndn-trust://invite"));

        let listed = call(verb::INVITE_LIST, None, None, Some(&backend));
        assert!(!listed.status_text.contains(&made.token));
        let listed: Vec<ndn_cert::CaInviteListing> =
            serde_json::from_str(&listed.status_text).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].invites[0].id, made.id);

        let gone = call(
            verb::INVITE_WITHDRAW,
            Some("/home/bob"),
            Some(&made.id),
            Some(&backend),
        );
        let gone: ndn_cert::InviteEntry = serde_json::from_str(&gone.status_text).unwrap();
        assert_eq!(gone.info.state, ndn_cert::InviteState::Withdrawn);
        let again = call(verb::INVITE_WITHDRAW, None, Some(&made.id), Some(&backend));
        assert_eq!(refusal_code(&again), code::INVITE_ALREADY_WITHDRAWN.code);
    }

    /// Every refusal is coded: no CA, several CAs unnamed, a bad request, a
    /// missing parameter.
    #[test]
    fn refusals_are_coded() {
        let none = call(verb::INVITE_LIST, None, None, None);
        assert_eq!(refusal_code(&none), code::INVITE_NO_CA.code);
        let two = host(&["/home/bob", "/work/acme"]);
        let member = Some(r#"{"role":"member"}"#);
        let several = call(verb::INVITE_CREATE, None, member, Some(&two));
        assert_eq!(refusal_code(&several), code::INVITE_SEVERAL_CAS.code);
        let unknown = call(verb::INVITE_CREATE, Some("/nope"), member, Some(&two));
        assert_eq!(refusal_code(&unknown), code::INVITE_CA_UNKNOWN.code);
        assert!(call(verb::INVITE_CREATE, Some("/work/acme"), member, Some(&two)).is_ok());
        let bad = call(
            verb::INVITE_CREATE,
            Some("/work/acme"),
            Some("member"),
            Some(&two),
        );
        assert_eq!(refusal_code(&bad), code::INVITE_REQUEST_INVALID.code);
        let admin = call(
            verb::INVITE_CREATE,
            Some("/work/acme"),
            Some(r#"{"role":"admin"}"#),
            Some(&two),
        );
        assert_eq!(refusal_code(&admin), code::INVITE_ROLE_NEEDS_APPROVAL.code);
        for v in [verb::INVITE_CREATE, verb::INVITE_WITHDRAW] {
            let missing = call(v, Some("/work/acme"), None, Some(&two));
            assert_eq!(refusal_code(&missing), code::MISSING_PARAMETER.code);
        }
        let listed = call(verb::INVITE_LIST, None, None, Some(&two));
        let listed: Vec<ndn_cert::CaInviteListing> =
            serde_json::from_str(&listed.status_text).unwrap();
        assert_eq!(listed.len(), 2, "a listing names every CA");
    }

    /// A backend whose one CA, `/home/bob`, issued the phone's certificate.
    struct IssuedPhone;

    impl InviteMgmtBackend for IssuedPhone {
        fn create(
            &self,
            _: Option<&Name>,
            _: &ndn_cert::InviteRequest,
            _: &str,
        ) -> Result<ndn_cert::CreatedInvite, TrustRefusal> {
            unreachable!("issued-list only")
        }
        fn list(&self, _: Option<&Name>) -> Result<Vec<ndn_cert::CaInviteListing>, TrustRefusal> {
            unreachable!("issued-list only")
        }
        fn withdraw(
            &self,
            _: Option<&Name>,
            _: &str,
        ) -> Result<ndn_cert::InviteEntry, TrustRefusal> {
            unreachable!("issued-list only")
        }
        fn issued_list(&self, ca: Option<&Name>) -> Result<Vec<CaIssuedListing>, TrustRefusal> {
            if ca.is_some_and(|ca| ca.to_string() != "/home/bob") {
                return Err(TrustRefusal::new(code::ISSUED_CA_UNKNOWN, "not this CA"));
            }
            Ok(vec![CaIssuedListing {
                ca: "/home/bob".into(),
                namespace: "/home/bob".into(),
                certificates: vec![IssuedEntry {
                    certificate: "/home/bob/member/phone/KEY/p/NDNCERT/v=1".into(),
                    key: "/home/bob/member/phone/KEY/p".into(),
                    identity: "/home/bob/member/phone".into(),
                    role: Some("member".into()),
                    device: Some("phone".into()),
                    valid_from: "20261017T120000Z".into(),
                    valid_until: "20271017T120000Z".into(),
                    revoked: false,
                }],
            }])
        }
    }

    /// `issued-list` answers the backend's listing as JSON; no CA, and a CA
    /// the node does not run, are refused with their codes.
    #[test]
    fn issued_list_answers_json_and_coded_refusals() {
        let none = call(verb::ISSUED_LIST, None, None, None);
        assert_eq!(refusal_code(&none), code::ISSUED_NO_CA.code);
        let nothing_issued = call(verb::ISSUED_LIST, None, None, Some(&host(&[])));
        assert_eq!(refusal_code(&nothing_issued), code::ISSUED_NO_CA.code);

        let phone: Arc<dyn InviteMgmtBackend> = Arc::new(IssuedPhone);
        let listed = call(verb::ISSUED_LIST, Some("/home/bob"), None, Some(&phone));
        assert!(listed.is_ok(), "{}", listed.status_text);
        let listed: Vec<CaIssuedListing> = serde_json::from_str(&listed.status_text).unwrap();
        assert_eq!(listed, phone.issued_list(None).unwrap());
        let unknown = call(verb::ISSUED_LIST, Some("/work/acme"), None, Some(&phone));
        assert_eq!(refusal_code(&unknown), code::ISSUED_CA_UNKNOWN.code);
    }

    /// The observer publishes created, redeemed and withdrawn events naming
    /// the CA, the id and the role, never the token.
    #[test]
    fn invite_changes_reach_the_trust_stream() {
        use crate::TrustEvent;
        use ndn_mgmt_wire::events::EventSink;

        #[derive(Default)]
        struct Seen(parking_lot::Mutex<Vec<TrustEvent>>);
        impl EventSink<TrustEvent> for Seen {
            fn publish(&self, event: TrustEvent) {
                self.0.lock().push(event);
            }
        }
        let seen = Arc::new(Seen::default());
        let ns: Name = "/home/bob".parse().unwrap();
        let tokens = TokenStore::new();
        tokens.set_observer(crate::events::invite_observer(ns.to_string(), seen.clone()));
        let ca = CaInvites::new(
            tokens,
            InviteIssuer {
                ca_prefix: ns.clone(),
                namespace: ns.clone(),
                expected_fingerprint: None,
            },
        );
        let request = |role: &str| ndn_cert::InviteRequest {
            role: role.into(),
            ..Default::default()
        };
        let used = ca.create(&request("member"), "").unwrap();
        let gone = ca.create(&request("guest"), "").unwrap();
        let device: Name = "/home/bob/member/phone".parse().unwrap();
        assert_eq!(
            ca.tokens().consume_for(&used.token, &device),
            ndn_cert::TokenCheck::Ok
        );
        ca.withdraw(&gone.id).unwrap();
        let bob = || "/home/bob".to_owned();
        let member = Some("member".to_owned());
        assert_eq!(
            *seen.0.lock(),
            [
                TrustEvent::InviteCreated {
                    ca: bob(),
                    id: used.id.clone(),
                    role: member.clone()
                },
                TrustEvent::InviteCreated {
                    ca: bob(),
                    id: gone.id.clone(),
                    role: Some("guest".into())
                },
                TrustEvent::InviteRedeemed {
                    ca: bob(),
                    id: used.id.clone(),
                    role: member
                },
                TrustEvent::InviteWithdrawn {
                    ca: bob(),
                    id: gone.id.clone()
                },
            ]
        );
        let json = serde_json::to_string(&*seen.0.lock()).unwrap();
        assert!(!json.contains(&used.token) && !json.contains(&gone.token));
    }
}
