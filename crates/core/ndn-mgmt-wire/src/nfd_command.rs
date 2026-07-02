//! NFD management command name shape:
//! `/{localhost|localhop}/nfd/<module>/<verb>/<ControlParameters>`,
//! where `<ControlParameters>` is the full 0x68 TLV block embedded as
//! a generic name component.
use bytes::Bytes;
use ndn_foundation_types::{Name, NameComponent};

use crate::control_parameters::ControlParameters;

/// `/localhost/nfd`.
pub const NFD_PREFIX: &[&[u8]] = &[b"localhost", b"nfd"];

pub mod module {
    pub const FACES: &[u8] = b"faces";
    pub const FIB: &[u8] = b"fib";
    pub const RIB: &[u8] = b"rib";
    pub const ROUTING: &[u8] = b"routing";
    pub const DISCOVERY: &[u8] = b"discovery";
    pub const CS: &[u8] = b"cs";
    pub const STRATEGY: &[u8] = b"strategy-choice";
    pub const STATUS: &[u8] = b"status";
    pub const NEIGHBORS: &[u8] = b"neighbors";
    pub const SERVICE: &[u8] = b"service";
    pub const MEASUREMENTS: &[u8] = b"measurements";
    pub const CONFIG: &[u8] = b"config";
    pub const SECURITY: &[u8] = b"security";
    pub const LOG: &[u8] = b"log";
    /// `crates/ndn-coding`.
    pub const CODING: &[u8] = b"coding";
    /// `crates/ndn-ratelimit`.
    pub const RATE_LIMIT: &[u8] = b"rate-limit";
    /// `crates/ndn-compute` — read-only function introspection.
    pub const COMPUTE: &[u8] = b"compute";
    /// BLE peripheral listener control + status (`ndn-face-native` bluetooth).
    pub const BLE: &[u8] = b"ble";
    /// NDNCERT CA introspection — read-only pending device-approvals.
    pub const CA: &[u8] = b"ca";
    /// WebTransport listener introspection — read-only TLS cert status.
    pub const WEBTRANSPORT: &[u8] = b"webtransport";
}

pub mod verb {
    pub const GET: &[u8] = b"get";

    pub const CREATE: &[u8] = b"create";
    pub const UPDATE: &[u8] = b"update";
    pub const DESTROY: &[u8] = b"destroy";
    /// Start the BLE peripheral listener (begin advertising).
    pub const START: &[u8] = b"start";
    /// Stop the BLE peripheral listener.
    pub const STOP: &[u8] = b"stop";
    pub const LIST: &[u8] = b"list";
    /// `ca` module — list pending device-approval requests.
    pub const LIST_APPROVALS: &[u8] = b"list-approvals";
    /// `ca/approve` — approve a pending request. Signed-command gated
    /// (SECURITY-extended-module rule); the signer's cert name is
    /// recorded as the approver. v1 dashboard surface for the §5.5
    /// device-approval flow.
    pub const APPROVE: &[u8] = b"approve";
    /// `ca/deny` — deny a pending request with a reason. Same gating
    /// as `approve`.
    pub const DENY: &[u8] = b"deny";

    pub const ADD_NEXTHOP: &[u8] = b"add-nexthop";
    pub const REMOVE_NEXTHOP: &[u8] = b"remove-nexthop";
    pub const REGISTER: &[u8] = b"register";
    pub const UNREGISTER: &[u8] = b"unregister";
    pub const SET: &[u8] = b"set";
    pub const UNSET: &[u8] = b"unset";
    pub const CONFIG: &[u8] = b"config";
    pub const INFO: &[u8] = b"info";
    pub const ERASE: &[u8] = b"erase";
    pub const ANNOUNCE: &[u8] = b"announce";
    pub const WITHDRAW: &[u8] = b"withdraw";
    pub const BROWSE: &[u8] = b"browse";
    pub const COUNTERS: &[u8] = b"counters";
    /// ndn-rs-local read dataset: per-face cross-layer link signals
    /// (RSSI/SNR/congestion). Not an NFD verb — observability only.
    pub const LINK_QUALITY: &[u8] = b"link-quality";
    pub const IDENTITY_LIST: &[u8] = b"identity-list";
    pub const IDENTITY_GENERATE: &[u8] = b"identity-generate";
    pub const IDENTITY_DID: &[u8] = b"identity-did";
    pub const IDENTITY_STATUS: &[u8] = b"identity-status";
    pub const ANCHOR_LIST: &[u8] = b"anchor-list";
    pub const NLSR_STATUS: &[u8] = b"nlsr-status";
    pub const NLSR_NEIGHBORS: &[u8] = b"nlsr-neighbors";
    pub const NLSR_LSDB: &[u8] = b"nlsr-lsdb";
    /// Runtime trust-anchor install (signed-command gated).
    pub const ANCHOR_ADD: &[u8] = b"anchor-add";
    pub const ANCHOR_REMOVE: &[u8] = b"anchor-remove";
    /// Install an ndn-cxx-compatible identity export (TLV 0x80 wrapping
    /// cert Data + EncryptedKey) into the PIB.
    pub const SAFEBAG_IMPORT: &[u8] = b"safebag-import";
    pub const KEY_DELETE: &[u8] = b"key-delete";
    pub const CA_INFO: &[u8] = b"ca-info";
    pub const CA_ENROLL: &[u8] = b"ca-enroll";
    pub const CA_TOKEN_ADD: &[u8] = b"ca-token-add";
    pub const CA_REQUESTS: &[u8] = b"ca-requests";
    pub const YUBIKEY_DETECT: &[u8] = b"yubikey-detect";
    pub const YUBIKEY_GENERATE: &[u8] = b"yubikey-generate";
    pub const SCHEMA_RULE_ADD: &[u8] = b"schema-rule-add";
    pub const SCHEMA_RULE_REMOVE: &[u8] = b"schema-rule-remove";
    pub const SCHEMA_LIST: &[u8] = b"schema-list";
    pub const SCHEMA_SET: &[u8] = b"schema-set";
    pub const GET_FILTER: &[u8] = b"get-filter";
    pub const SET_FILTER: &[u8] = b"set-filter";
    pub const GET_RECENT: &[u8] = b"get-recent";
    pub const MODULES: &[u8] = b"modules";
    pub const DVR_STATUS: &[u8] = b"dvr-status";
    pub const DVR_CONFIG: &[u8] = b"dvr-config";
    /// `policy-set` body is free-form JSON in `ControlParameters.uri`;
    /// the dashboard bridges policy mutations into its local
    /// `AuditLogChain` so policy history stays reconstructable.
    pub const POLICY_GET: &[u8] = b"policy-get";
    pub const POLICY_SET: &[u8] = b"policy-set";
    pub const VALIDATION_STATS: &[u8] = b"validation-stats";
    pub const VALIDATE: &[u8] = b"validate";
}

/// `/localhost/nfd/<module>/<verb>/<full-0x68-TLV>`.
pub fn command_name(module: &[u8], verb: &[u8], params: &ControlParameters) -> Name {
    let params_tlv = params.encode();
    Name::from_components([
        NameComponent::generic(Bytes::from_static(b"localhost")),
        NameComponent::generic(Bytes::from_static(b"nfd")),
        NameComponent::generic(Bytes::copy_from_slice(module)),
        NameComponent::generic(Bytes::copy_from_slice(verb)),
        NameComponent::generic(params_tlv),
    ])
}

/// `/localhost/nfd/<module>/<verb>` (no parameter component).
pub fn dataset_name(module: &[u8], verb: &[u8]) -> Name {
    Name::from_components([
        NameComponent::generic(Bytes::from_static(b"localhost")),
        NameComponent::generic(Bytes::from_static(b"nfd")),
        NameComponent::generic(Bytes::copy_from_slice(module)),
        NameComponent::generic(Bytes::copy_from_slice(verb)),
    ])
}

#[derive(Debug)]
pub struct ParsedCommand {
    pub module: Bytes,
    pub verb: Bytes,
    pub params: Option<ControlParameters>,
}

/// Accepts both `/localhost/nfd/...` (loopback) and `/localhop/nfd/...`
/// (cert-authenticated remote management, NFD
/// `daemon/mgmt/rib-manager.cpp:60-89`). Shape-only; callers select
/// the validator based on the top component before dispatch.
pub fn parse_command_name(name: &Name) -> Option<ParsedCommand> {
    let comps = name.components();
    if comps.len() < 4 {
        return None;
    }

    let top = comps[0].value.as_ref();
    if (top != b"localhost" && top != b"localhop") || comps[1].value.as_ref() != b"nfd" {
        return None;
    }

    let module = comps[2].value.clone();
    let verb = comps[3].value.clone();

    let params = if comps.len() >= 5 {
        ControlParameters::decode(comps[4].value.clone()).ok()
    } else {
        None
    };

    Some(ParsedCommand {
        module,
        verb,
        params,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::borrow::ToOwned;

    #[test]
    fn command_name_structure() {
        let params = ControlParameters {
            name: Some(Name::from_components([NameComponent::generic(
                Bytes::from_static(b"test"),
            )])),
            cost: Some(10),
            ..Default::default()
        };
        let name = command_name(module::RIB, verb::REGISTER, &params);
        let comps = name.components();
        assert_eq!(comps.len(), 5);
        assert_eq!(comps[0].value.as_ref(), b"localhost");
        assert_eq!(comps[1].value.as_ref(), b"nfd");
        assert_eq!(comps[2].value.as_ref(), b"rib");
        assert_eq!(comps[3].value.as_ref(), b"register");
        let decoded = ControlParameters::decode(comps[4].value.clone()).unwrap();
        assert_eq!(decoded.cost, Some(10));
    }

    #[test]
    fn dataset_name_structure() {
        let name = dataset_name(module::FACES, verb::LIST);
        let comps = name.components();
        assert_eq!(comps.len(), 4);
        assert_eq!(comps[2].value.as_ref(), b"faces");
        assert_eq!(comps[3].value.as_ref(), b"list");
    }

    #[test]
    fn parse_command_roundtrip() {
        let params = ControlParameters {
            uri: Some("shm://myapp".to_owned()),
            ..Default::default()
        };
        let name = command_name(module::FACES, verb::CREATE, &params);
        let parsed = parse_command_name(&name).unwrap();
        assert_eq!(parsed.module.as_ref(), b"faces");
        assert_eq!(parsed.verb.as_ref(), b"create");
        let p = parsed.params.unwrap();
        assert_eq!(p.uri.as_deref(), Some("shm://myapp"));
    }

    #[test]
    fn parse_command_too_short() {
        let name = Name::from_components([
            NameComponent::generic(Bytes::from_static(b"localhost")),
            NameComponent::generic(Bytes::from_static(b"nfd")),
        ]);
        assert!(parse_command_name(&name).is_none());
    }

    #[test]
    fn parse_command_wrong_prefix() {
        let name = Name::from_components([
            NameComponent::generic(Bytes::from_static(b"ndn")),
            NameComponent::generic(Bytes::from_static(b"nfd")),
            NameComponent::generic(Bytes::from_static(b"rib")),
            NameComponent::generic(Bytes::from_static(b"register")),
        ]);
        assert!(parse_command_name(&name).is_none());
    }

    #[test]
    fn parse_command_localhop_accepted() {
        let name = Name::from_components([
            NameComponent::generic(Bytes::from_static(b"localhop")),
            NameComponent::generic(Bytes::from_static(b"nfd")),
            NameComponent::generic(Bytes::from_static(b"rib")),
            NameComponent::generic(Bytes::from_static(b"register")),
        ]);
        let parsed = parse_command_name(&name).expect("/localhop/nfd is a valid mgmt top");
        assert_eq!(parsed.module.as_ref(), b"rib");
        assert_eq!(parsed.verb.as_ref(), b"register");
    }

    #[test]
    fn parse_command_no_params() {
        let name = dataset_name(module::FACES, verb::LIST);
        let parsed = parse_command_name(&name).unwrap();
        assert_eq!(parsed.module.as_ref(), b"faces");
        assert_eq!(parsed.verb.as_ref(), b"list");
        assert!(parsed.params.is_none());
    }
}
