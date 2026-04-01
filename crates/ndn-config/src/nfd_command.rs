/// NFD management command name builder and parser.
///
/// Management command Interests use the name structure:
/// ```text
/// /localhost/nfd/<module>/<verb>/<ControlParameters>
/// ```
///
/// where `<ControlParameters>` is a generic name component containing the
/// binary TLV-encoded ControlParameters block (the value bytes only, without
/// the outer type 0x68 and length — those are implicit in the name component).
use bytes::Bytes;
use ndn_packet::{Name, NameComponent};

use crate::control_parameters::ControlParameters;

/// The standard NFD management prefix: `/localhost/nfd`.
pub const NFD_PREFIX: &[&[u8]] = &[b"localhost", b"nfd"];

// ─── Command modules and verbs ───────────────────────────────────────────────

/// Management module names.
pub mod module {
    pub const FACES: &[u8] = b"faces";
    pub const FIB:   &[u8] = b"fib";
    pub const RIB:   &[u8] = b"rib";
    pub const CS:    &[u8] = b"cs";
    pub const STRATEGY: &[u8] = b"strategy-choice";
    pub const STATUS: &[u8] = b"status";
}

/// Command verbs per module.
pub mod verb {
    // faces
    pub const CREATE:  &[u8] = b"create";
    pub const UPDATE:  &[u8] = b"update";
    pub const DESTROY: &[u8] = b"destroy";
    pub const LIST:    &[u8] = b"list";

    // fib
    pub const ADD_NEXTHOP:    &[u8] = b"add-nexthop";
    pub const REMOVE_NEXTHOP: &[u8] = b"remove-nexthop";

    // rib
    pub const REGISTER:   &[u8] = b"register";
    pub const UNREGISTER: &[u8] = b"unregister";

    // strategy-choice
    pub const SET:   &[u8] = b"set";
    pub const UNSET: &[u8] = b"unset";

    // cs
    pub const CONFIG: &[u8] = b"config";
    pub const INFO:   &[u8] = b"info";
}

// ─── Name builder ────────────────────────────────────────────────────────────

/// Build a management command name with embedded ControlParameters.
///
/// Result: `/localhost/nfd/<module>/<verb>/<params-component>`
pub fn command_name(module: &[u8], verb: &[u8], params: &ControlParameters) -> Name {
    let params_value = params.encode_value();
    Name::from_components([
        NameComponent::generic(Bytes::from_static(b"localhost")),
        NameComponent::generic(Bytes::from_static(b"nfd")),
        NameComponent::generic(Bytes::copy_from_slice(module)),
        NameComponent::generic(Bytes::copy_from_slice(verb)),
        NameComponent::generic(params_value),
    ])
}

/// Build a dataset (status) name without parameters.
///
/// Result: `/localhost/nfd/<module>/<verb>`
pub fn dataset_name(module: &[u8], verb: &[u8]) -> Name {
    Name::from_components([
        NameComponent::generic(Bytes::from_static(b"localhost")),
        NameComponent::generic(Bytes::from_static(b"nfd")),
        NameComponent::generic(Bytes::copy_from_slice(module)),
        NameComponent::generic(Bytes::copy_from_slice(verb)),
    ])
}

// ─── Name parser ─────────────────────────────────────────────────────────────

/// Parsed management command extracted from an Interest name.
#[derive(Debug)]
pub struct ParsedCommand {
    pub module: Bytes,
    pub verb:   Bytes,
    pub params: Option<ControlParameters>,
}

/// Parse a management command from an Interest name.
///
/// Expects: `/localhost/nfd/<module>/<verb>[/<params>][/<signed-interest-components>]`
///
/// Returns `None` if the name doesn't match the management prefix or has
/// too few components.
pub fn parse_command_name(name: &Name) -> Option<ParsedCommand> {
    let comps = name.components();
    if comps.len() < 4 {
        return None;
    }

    // Check /localhost/nfd prefix.
    if comps[0].value.as_ref() != b"localhost" || comps[1].value.as_ref() != b"nfd" {
        return None;
    }

    let module = comps[2].value.clone();
    let verb = comps[3].value.clone();

    // The 5th component (index 4), if present, is the ControlParameters.
    let params = if comps.len() >= 5 {
        ControlParameters::decode_value(comps[4].value.clone()).ok()
    } else {
        None
    };

    Some(ParsedCommand { module, verb, params })
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_name_structure() {
        let params = ControlParameters {
            name: Some(Name::from_components([
                NameComponent::generic(Bytes::from_static(b"test")),
            ])),
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
        // 5th component is the encoded ControlParameters value.
        let decoded = ControlParameters::decode_value(comps[4].value.clone()).unwrap();
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
            NameComponent::generic(Bytes::from_static(b"localhop")),
            NameComponent::generic(Bytes::from_static(b"nfd")),
            NameComponent::generic(Bytes::from_static(b"rib")),
            NameComponent::generic(Bytes::from_static(b"register")),
        ]);
        assert!(parse_command_name(&name).is_none());
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
