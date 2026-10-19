//! The `links/list` dataset (`/localhost/nfd/links/list`): this device's QUIC
//! links, the paths that reach each linked device, and the state of each
//! device's direct path. The host daemon encodes it from the link library's
//! report; `ndn-ctl link list` decodes it through here.
//!
//! Whatever the report says in words is a [`LinkDetail`]: a stable code
//! ([`link_code`]) with parameters and a neutral default sentence that names
//! no host's commands or configuration. A client words the codes it knows
//! ([`LinkDetail::render`]) and shows the neutral sentence for the others.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_tlv::{TlvReader, TlvWriter};

use crate::{ControlParameters, DecodeError, nni_bytes, read_nni};

/// `links/list` TLV-TYPE codes.
///
/// An ndn-rs extension (no NFD analogue) in the application range
/// 0x04A0–0x04F3, clear of the trust context (0x0410–0x042F), the link
/// messages (0x0440–0x046F) and the trust envelope (0x0470–0x049F). All
/// codes are even (non-critical): a decoder skips the ones it does not know.
/// A code's meaning depends on the entry it sits in (`KEY`, `HELD` and
/// `WAKES` appear at the top level and nested). 0x04BC, 0x04CC, 0x04DA and
/// 0x04DC carried sentences before the details replaced them; they are
/// retired, not reused.
pub mod link_tlv {
    /// 32 bytes, a link key fingerprint: at the top level this device's, in
    /// a [`LINK`] the linked device's.
    pub const KEY: u64 = 0x04A0;
    /// NonNegativeInteger, top level.
    pub const PROBES_SENT: u64 = 0x04A2;
    /// NonNegativeInteger, top level.
    pub const PUNCHES_REFUSED: u64 = 0x04A4;
    /// Nested entry, one per linked device.
    pub const LINK: u64 = 0x04A6;
    /// UTF-8 string.
    pub const LABEL: u64 = 0x04A8;
    /// The device name's components (a Name TLV's value), optional.
    pub const DEVICE: u64 = 0x04AA;
    /// Nested entry in a [`LINK`], one per path.
    pub const PATH: u64 = 0x04AC;
    /// UTF-8 string: `direct`, `link` or `relay`.
    pub const PATH_KIND: u64 = 0x04AE;
    /// NonNegativeInteger.
    pub const FACE_ID: u64 = 0x04B0;
    /// UTF-8 string `ip:port`, optional.
    pub const REMOTE: u64 = 0x04B2;
    /// NonNegativeInteger, microseconds, optional.
    pub const RTT_MICROS: u64 = 0x04B4;
    /// NonNegativeInteger, seconds.
    pub const AGE_SECS: u64 = 0x04B6;
    /// UTF-8 string, optional: the relay's label.
    pub const VIA: u64 = 0x04B8;
    /// UTF-8 string: `none`, `off`, `trying`, `up`, `not-possible` or
    /// `refused`.
    pub const DIRECT_STATE: u64 = 0x04BA;
    /// NonNegativeInteger, seconds, optional: when the next punch is due.
    pub const RETRY_IN_SECS: u64 = 0x04BE;
    /// UTF-8 string in a [`LINK`], optional: `always`, `on-demand` or `off`.
    pub const MODE: u64 = 0x04C0;
    /// NonNegativeInteger, seconds, in a [`LINK`] with mode `on-demand`:
    /// the idle close.
    pub const IDLE_SECS: u64 = 0x04C2;
    /// Nested in a [`LINK`], optional: the link is to a relay this device uses.
    pub const RELAY: u64 = 0x04C4;
    /// UTF-8 string in a [`RELAY`]: `user` or `namespace:<namespace>`.
    pub const RELAY_SOURCE: u64 = 0x04C6;
    /// NonNegativeInteger in a [`RELAY`]: lower is preferred.
    pub const PREFERENCE: u64 = 0x04C8;
    /// UTF-8 string in a [`RELAY`]: `linked`, `trying`, `down`, `standby`
    /// or `off`.
    pub const RELAY_STATE: u64 = 0x04CA;
    /// Nested in a [`LINK`], optional (relay side): the device is asleep here.
    pub const ASLEEP: u64 = 0x04CE;
    /// NonNegativeInteger, seconds, in an [`ASLEEP`]: how long it has been.
    pub const SINCE_SECS: u64 = 0x04D0;
    /// NonNegativeInteger: Interests held — in an [`ASLEEP`] for that device,
    /// at the top level for all.
    pub const HELD: u64 = 0x04D2;
    /// Empty, in an [`ASLEEP`]: the device asked for its Interests to be held.
    pub const HOLD: u64 = 0x04D4;
    /// Empty, in an [`ASLEEP`]: the device registered a wake token.
    pub const WAKE: u64 = 0x04D6;
    /// NonNegativeInteger: wakes sent — in an [`ASLEEP`] to that device, at
    /// the top level to all.
    pub const WAKES: u64 = 0x04D8;
    /// UTF-8 string in a detail: its code.
    pub const DETAIL_CODE: u64 = 0x04E0;
    /// Nested in a detail, one per parameter: [`PARAM_NAME`], [`PARAM_VALUE`].
    pub const DETAIL_PARAM: u64 = 0x04E2;
    /// UTF-8 string in a [`DETAIL_PARAM`].
    pub const PARAM_NAME: u64 = 0x04E4;
    /// UTF-8 string in a [`DETAIL_PARAM`].
    pub const PARAM_VALUE: u64 = 0x04E6;
    /// UTF-8 string in a detail: its neutral sentence.
    pub const DETAIL_TEXT: u64 = 0x04E8;
    /// Nested detail in a detail, one per cause, in the order their
    /// sentences appear in its sentence.
    pub const DETAIL_CAUSE: u64 = 0x04EA;
    /// Nested detail in a [`LINK`], optional: why the direct path is in its
    /// state, and what to do if anything.
    pub const DIRECT_DETAIL: u64 = 0x04EC;
    /// Nested detail in a [`RELAY`], optional: why it is in its state.
    pub const RELAY_DETAIL: u64 = 0x04EE;
    /// Nested detail in a [`LINK`], optional: why a configured device is not
    /// linked now.
    pub const DOWN: u64 = 0x04F0;
    /// Nested detail, top level, optional: this device's relay serving
    /// policy.
    pub const SERVE: u64 = 0x04F2;
}

/// The codes of [`LinkDetail`]s, documented with their parameters in
/// `ndn-rs/docs/specs/mgmt-trust.md` ("Links"). Stable: clients key their
/// wording on them.
pub mod link_code {
    // --- direct-path state (`LinkEntry::direct`)
    pub const DIRECT_UP: &str = "direct-up";
    pub const DIRECT_ENDED: &str = "direct-ended";
    pub const DIRECT_ENDED_PEER_PUNCHES: &str = "direct-ended-peer-punches";
    pub const DIRECT_LINKED: &str = "direct-linked";
    pub const DIRECT_WAITING_FOR_RELAY: &str = "direct-waiting-for-relay";
    pub const DIRECT_OFF_PEER_ENTRY: &str = "direct-off-peer-entry";
    pub const DIRECT_OFF_POLICY: &str = "direct-off-policy";
    pub const DIRECT_OFF_ROLES: &str = "direct-off-roles";
    pub const DIRECT_FULL: &str = "direct-full";
    pub const DIRECT_MEMBERS_FIRST: &str = "direct-members-first";
    pub const DIRECT_PUNCHING: &str = "direct-punching";
    pub const DIRECT_PEER_PUNCHING: &str = "direct-peer-punching";
    pub const DIRECT_PEER_PUNCHES_AGAIN: &str = "direct-peer-punches-again";
    pub const DIRECT_REPUNCHING: &str = "direct-repunching";

    // --- why a punch made no direct path
    pub const PUNCH_RELAY_DOWN: &str = "punch-relay-down";
    pub const PUNCH_NO_SOCKET: &str = "punch-no-socket";
    pub const PUNCH_NO_KEY: &str = "punch-no-key";
    pub const PUNCH_ANSWER_NOT_VALIDATED: &str = "punch-answer-not-validated";
    pub const PUNCH_UNROUTED: &str = "punch-unrouted";
    pub const PUNCH_UNANSWERED: &str = "punch-unanswered";
    pub const PUNCH_REFUSED_BY_PEER: &str = "punch-refused-by-peer";
    pub const PUNCH_ANSWER_UNUSABLE: &str = "punch-answer-unusable";
    pub const PUNCH_SOCKET_UNBOUND: &str = "punch-socket-unbound";
    pub const PUNCH_UNREACHABLE: &str = "punch-unreachable";
    pub const PUNCH_BUSY: &str = "punch-busy";
    pub const PUNCH_ENDED: &str = "punch-ended";
    pub const PUNCH_NO_PROBE: &str = "punch-no-probe";
    pub const PUNCH_NO_HANDSHAKE: &str = "punch-no-handshake";
    pub const PUNCH_NOTHING_TO_DIAL: &str = "punch-nothing-to-dial";
    pub const PUNCH_DIALS_FAILED: &str = "punch-dials-failed";
    pub const PUNCH_DIAL_FAILED: &str = "punch-dial-failed";

    // --- why a punch answer is not usable (causes of PUNCH_ANSWER_UNUSABLE)
    pub const ANSWER_EMPTY: &str = "answer-empty";
    pub const ANSWER_MALFORMED: &str = "answer-malformed";
    pub const ANSWER_BAD_KEY: &str = "answer-bad-key";
    pub const ANSWER_BAD_SIGNATURE: &str = "answer-bad-signature";
    pub const ANSWER_WRONG_KEY: &str = "answer-wrong-key";
    pub const ANSWER_UNCONFIRMED: &str = "answer-unconfirmed";
    pub const ANSWER_WRONG_DEVICE: &str = "answer-wrong-device";

    // --- why a punch request was refused here (sent to the punching device)
    pub const PUNCH_CLOCK: &str = "punch-clock";
    pub const PUNCH_REPLAY: &str = "punch-replay";
    pub const PUNCH_RATE: &str = "punch-rate";
    pub const PUNCH_ENROLLMENT_ONLY: &str = "punch-enrollment-only";
    pub const PUNCH_SESSIONS_FULL: &str = "punch-sessions-full";
    pub const PUNCH_NO_CANDIDATE: &str = "punch-no-candidate";
    pub const PUNCH_NO_SOCKET_FOR: &str = "punch-no-socket-for";

    // --- relay state (`LinkRelayEntry::detail`)
    pub const RELAY_LINKED: &str = "relay-linked";
    pub const RELAY_OFF: &str = "relay-off";
    pub const RELAY_DOWN: &str = "relay-down";
    pub const RELAY_CHOSEN: &str = "relay-chosen";
    pub const RELAY_CHOSEN_ON_DEMAND: &str = "relay-chosen-on-demand";
    pub const RELAY_DOWN_NOT_NEEDED: &str = "relay-down-not-needed";
    pub const RELAY_STANDBY: &str = "relay-standby";

    // --- why a configured device is not linked (`LinkEntry::down`)
    pub const DOWN_LINKS_IN: &str = "down-links-in";
    pub const DOWN_STANDBY_RELAY: &str = "down-standby-relay";
    pub const DOWN_OFF: &str = "down-off";
    pub const DOWN_ON_DEMAND: &str = "down-on-demand";
    pub const DOWN_DIALLING: &str = "down-dialling";
    pub const DIAL_FAILED: &str = "dial-failed";
    pub const PEER_SHUTTING_DOWN: &str = "peer-shutting-down";

    // --- why a link did not come up, or ended
    pub const LINK_NO_KEY: &str = "link-no-key";
    pub const LINK_TLS: &str = "link-tls";
    pub const LINK_CONNECT: &str = "link-connect";
    pub const LINK_UNEXPECTED_KEY: &str = "link-unexpected-key";
    pub const LINK_CLOSED_BY_PEER: &str = "link-closed-by-peer";
    pub const LINK_CLOSED_HERE: &str = "link-closed-here";
    pub const LINK_PROTOCOL: &str = "link-protocol";
    pub const LINK_TIMEOUT: &str = "link-timeout";
    pub const LINK_IO: &str = "link-io";

    // --- why this device refused a link (sent to the other device as the
    //     close sentence; causes of LINK_CLOSED_HERE)
    pub const CERTIFICATE_UNDECODABLE: &str = "certificate-undecodable";
    pub const CERTIFICATE_FOR_ANOTHER_KEY: &str = "certificate-for-another-key";
    pub const MEMBERSHIP_UNDECODABLE: &str = "membership-undecodable";
    pub const MEMBERSHIP_NOT_BOUND: &str = "membership-not-bound";
    pub const BINDING_UNAVAILABLE: &str = "binding-unavailable";
    pub const ISSUER_UNDECODABLE: &str = "issuer-undecodable";
    pub const KEY_REVOKED: &str = "key-revoked";
    pub const ISSUER_REVOKED: &str = "issuer-revoked";
    pub const ROOT_COLLIDES: &str = "root-collides";
    pub const NOT_EXPECTED_KEY: &str = "not-expected-key";
    pub const NOT_EXPECTED_DEVICE: &str = "not-expected-device";
    pub const EXPECTED_DEVICE_UNCONFIRMED: &str = "expected-device-unconfirmed";
    pub const ROLE_MAY_NOT_LINK: &str = "role-may-not-link";
    pub const ROLE_MAY_NOT_RELAY: &str = "role-may-not-relay";
    pub const NOT_SERVED_NO_CERTIFICATE: &str = "not-served-no-certificate";
    pub const UNRECOGNIZED_KEY: &str = "unrecognized-key";
    pub const NAMESPACE_COLLIDES: &str = "namespace-collides";
    pub const QUOTA_NAMESPACE_LINKS: &str = "quota-namespace-links";
    pub const QUOTA_LINKS: &str = "quota-links";
    pub const NOT_SERVED_UNCERTIFIED: &str = "not-served-uncertified";
    pub const NOT_SERVED_UNLISTED: &str = "not-served-unlisted";
    pub const NOT_SERVED_OWN: &str = "not-served-own";
    pub const ENROLLMENT_LINKS_FULL: &str = "enrollment-links-full";
    pub const ENROLLMENT_POSSIBLE: &str = "enrollment-possible";
    pub const PATH_NOT_TAKEN: &str = "path-not-taken";
    pub const PATH_NO_PUNCH: &str = "path-no-punch";
    pub const PATH_ENROLLMENT_ONLY: &str = "path-enrollment-only";
    pub const DIRECT_REFUSED_PEER_ENTRY: &str = "direct-refused-peer-entry";
    pub const PATH_TAKEN: &str = "path-taken";
    pub const LINK_EXISTS: &str = "link-exists";

    // --- why a certificate identifies nobody here
    pub const NO_CERTIFICATE: &str = "no-certificate";
    pub const NOT_DEVICE_CERTIFICATE: &str = "not-device-certificate";
    pub const CERTIFICATE_EXPIRED: &str = "certificate-expired";
    pub const CERTIFICATE_UNAUTHENTICATED: &str = "certificate-unauthenticated";
    pub const CERTIFICATE_INVALID: &str = "certificate-invalid";
    pub const CERTIFICATE_CHAIN_UNKNOWN: &str = "certificate-chain-unknown";
    pub const FOREIGN_NO_ROOT: &str = "foreign-no-root";
    pub const FOREIGN_ROOT_NO_NAMESPACE: &str = "foreign-root-no-namespace";
    pub const FOREIGN_NOT_DEVICE_CERTIFICATE: &str = "foreign-not-device-certificate";
    pub const FOREIGN_ROOT_INVALID_NAMESPACE: &str = "foreign-root-invalid-namespace";
    pub const FOREIGN_ROOT_EXPIRED: &str = "foreign-root-expired";
    pub const FOREIGN_CERTIFICATE_INVALID: &str = "foreign-certificate-invalid";
    pub const FOREIGN_CHAIN_INCOMPLETE: &str = "foreign-chain-incomplete";
    pub const NAMESPACE_NOT_HELD: &str = "namespace-not-held";

    // --- why a relay admits no enrollment link
    pub const NO_ENROLLMENT_LINK: &str = "no-enrollment-link";
    pub const ENROLLMENT_LINKS_OFF: &str = "enrollment-links-off";
    pub const ENROLLMENT_NO_CA: &str = "enrollment-no-ca";
    pub const ENROLLMENT_ROLE_MAY_NOT_RELAY: &str = "enrollment-role-may-not-relay";
    pub const ENROLLMENT_NO_CERTIFICATE: &str = "enrollment-no-certificate";
    pub const ENROLLMENT_NO_NAMESPACE: &str = "enrollment-no-namespace";

    // --- serving policy (`LinkListing::serve`)
    pub const SERVE_OWN: &str = "serve-own";
    pub const SERVE_LISTED: &str = "serve-listed";
    pub const SERVE_OPEN: &str = "serve-open";

    // --- link command answers (`links/connect`, `links/disconnect`,
    //     `links/mode`), as a Detail in the ControlResponse status text
    pub const LINKING: &str = "linking";
    pub const LINK_RELEASED: &str = "link-released";
    pub const LINK_MODE_SET: &str = "link-mode-set";

    /// Every code above.
    pub const ALL: &[&str] = &[
        DIRECT_UP,
        DIRECT_ENDED,
        DIRECT_ENDED_PEER_PUNCHES,
        DIRECT_LINKED,
        DIRECT_WAITING_FOR_RELAY,
        DIRECT_OFF_PEER_ENTRY,
        DIRECT_OFF_POLICY,
        DIRECT_OFF_ROLES,
        DIRECT_FULL,
        DIRECT_MEMBERS_FIRST,
        DIRECT_PUNCHING,
        DIRECT_PEER_PUNCHING,
        DIRECT_PEER_PUNCHES_AGAIN,
        DIRECT_REPUNCHING,
        PUNCH_RELAY_DOWN,
        PUNCH_NO_SOCKET,
        PUNCH_NO_KEY,
        PUNCH_ANSWER_NOT_VALIDATED,
        PUNCH_UNROUTED,
        PUNCH_UNANSWERED,
        PUNCH_REFUSED_BY_PEER,
        PUNCH_ANSWER_UNUSABLE,
        PUNCH_SOCKET_UNBOUND,
        PUNCH_UNREACHABLE,
        PUNCH_BUSY,
        PUNCH_ENDED,
        PUNCH_NO_PROBE,
        PUNCH_NO_HANDSHAKE,
        PUNCH_NOTHING_TO_DIAL,
        PUNCH_DIALS_FAILED,
        PUNCH_DIAL_FAILED,
        ANSWER_EMPTY,
        ANSWER_MALFORMED,
        ANSWER_BAD_KEY,
        ANSWER_BAD_SIGNATURE,
        ANSWER_WRONG_KEY,
        ANSWER_UNCONFIRMED,
        ANSWER_WRONG_DEVICE,
        PUNCH_CLOCK,
        PUNCH_REPLAY,
        PUNCH_RATE,
        PUNCH_ENROLLMENT_ONLY,
        PUNCH_SESSIONS_FULL,
        PUNCH_NO_CANDIDATE,
        PUNCH_NO_SOCKET_FOR,
        RELAY_LINKED,
        RELAY_OFF,
        RELAY_DOWN,
        RELAY_CHOSEN,
        RELAY_CHOSEN_ON_DEMAND,
        RELAY_DOWN_NOT_NEEDED,
        RELAY_STANDBY,
        DOWN_LINKS_IN,
        DOWN_STANDBY_RELAY,
        DOWN_OFF,
        DOWN_ON_DEMAND,
        DOWN_DIALLING,
        DIAL_FAILED,
        PEER_SHUTTING_DOWN,
        LINK_NO_KEY,
        LINK_TLS,
        LINK_CONNECT,
        LINK_UNEXPECTED_KEY,
        LINK_CLOSED_BY_PEER,
        LINK_CLOSED_HERE,
        LINK_PROTOCOL,
        LINK_TIMEOUT,
        LINK_IO,
        CERTIFICATE_UNDECODABLE,
        CERTIFICATE_FOR_ANOTHER_KEY,
        MEMBERSHIP_UNDECODABLE,
        MEMBERSHIP_NOT_BOUND,
        BINDING_UNAVAILABLE,
        ISSUER_UNDECODABLE,
        KEY_REVOKED,
        ISSUER_REVOKED,
        ROOT_COLLIDES,
        NOT_EXPECTED_KEY,
        NOT_EXPECTED_DEVICE,
        EXPECTED_DEVICE_UNCONFIRMED,
        ROLE_MAY_NOT_LINK,
        ROLE_MAY_NOT_RELAY,
        NOT_SERVED_NO_CERTIFICATE,
        UNRECOGNIZED_KEY,
        NAMESPACE_COLLIDES,
        QUOTA_NAMESPACE_LINKS,
        QUOTA_LINKS,
        NOT_SERVED_UNCERTIFIED,
        NOT_SERVED_UNLISTED,
        NOT_SERVED_OWN,
        ENROLLMENT_LINKS_FULL,
        ENROLLMENT_POSSIBLE,
        PATH_NOT_TAKEN,
        PATH_NO_PUNCH,
        PATH_ENROLLMENT_ONLY,
        DIRECT_REFUSED_PEER_ENTRY,
        PATH_TAKEN,
        LINK_EXISTS,
        NO_CERTIFICATE,
        NOT_DEVICE_CERTIFICATE,
        CERTIFICATE_EXPIRED,
        CERTIFICATE_UNAUTHENTICATED,
        CERTIFICATE_INVALID,
        CERTIFICATE_CHAIN_UNKNOWN,
        FOREIGN_NO_ROOT,
        FOREIGN_ROOT_NO_NAMESPACE,
        FOREIGN_NOT_DEVICE_CERTIFICATE,
        FOREIGN_ROOT_INVALID_NAMESPACE,
        FOREIGN_ROOT_EXPIRED,
        FOREIGN_CERTIFICATE_INVALID,
        FOREIGN_CHAIN_INCOMPLETE,
        NAMESPACE_NOT_HELD,
        NO_ENROLLMENT_LINK,
        ENROLLMENT_LINKS_OFF,
        ENROLLMENT_NO_CA,
        ENROLLMENT_ROLE_MAY_NOT_RELAY,
        ENROLLMENT_NO_CERTIFICATE,
        ENROLLMENT_NO_NAMESPACE,
        SERVE_OWN,
        SERVE_LISTED,
        SERVE_OPEN,
        LINKING,
        LINK_RELEASED,
        LINK_MODE_SET,
    ];
}

/// A fact the link report states in words, as structured data: a stable
/// [`code`](Self::code) ([`link_code`]) with its parameters, the neutral
/// default sentence, and the details that sentence quotes (its causes:
/// each cause's sentence appears verbatim in [`text`](Self::text), in
/// order).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LinkDetail {
    pub code: String,
    /// Named facts (names, keys, addresses, counts) a client words its own
    /// sentence from.
    pub params: BTreeMap<String, String>,
    /// The neutral default sentence, in no host's terms.
    pub text: String,
    pub causes: Vec<LinkDetail>,
}

impl LinkDetail {
    /// A detail of `code` with the neutral sentence `text`.
    pub fn new(code: &str, text: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            params: BTreeMap::new(),
            text: text.into(),
            causes: Vec::new(),
        }
    }

    /// With the parameter `key` = `value`.
    pub fn with(mut self, key: &str, value: impl core::fmt::Display) -> Self {
        self.params.insert(key.into(), value.to_string());
        self
    }

    /// With `cause`, whose sentence the caller put in [`text`](Self::text).
    pub fn caused_by(mut self, cause: LinkDetail) -> Self {
        self.causes.push(cause);
        self
    }

    /// Append `cause`'s sentence to this one after `separator`, as a cause.
    pub fn append(&mut self, separator: &str, cause: LinkDetail) {
        self.text.push_str(separator);
        self.text.push_str(&cause.text);
        self.causes.push(cause);
    }

    /// Whether this detail has code `code`.
    pub fn is(&self, code: &str) -> bool {
        self.code == code
    }

    /// The parameter `key`, if set.
    pub fn param(&self, key: &str) -> Option<&str> {
        self.params.get(key).map(String::as_str)
    }

    /// The sentence a client shows: `words` gives the client's own sentence
    /// for the codes it words (it gets the detail and its causes, rendered);
    /// any other detail shows its neutral sentence with its causes, as
    /// rendered, in place of their sentences.
    pub fn render(&self, words: &dyn Fn(&LinkDetail, &[String]) -> Option<String>) -> String {
        let causes: Vec<String> = self.causes.iter().map(|c| c.render(words)).collect();
        if let Some(own) = words(self, &causes) {
            return own;
        }
        let mut out = String::with_capacity(self.text.len());
        let mut rest = self.text.as_str();
        for (cause, rendered) in self.causes.iter().zip(&causes) {
            if cause.text.is_empty() {
                continue;
            }
            if let Some(at) = rest.find(cause.text.as_str()) {
                out.push_str(&rest[..at]);
                out.push_str(rendered);
                rest = &rest[at + cause.text.len()..];
            }
        }
        out.push_str(rest);
        out
    }

    fn encode_into(&self, w: &mut TlvWriter) {
        w.write_tlv(link_tlv::DETAIL_CODE, self.code.as_bytes());
        for (name, value) in &self.params {
            w.write_nested(link_tlv::DETAIL_PARAM, |w| {
                w.write_tlv(link_tlv::PARAM_NAME, name.as_bytes());
                w.write_tlv(link_tlv::PARAM_VALUE, value.as_bytes());
            });
        }
        write_text(w, link_tlv::DETAIL_TEXT, &self.text);
        for cause in &self.causes {
            w.write_nested(link_tlv::DETAIL_CAUSE, |w| cause.encode_into(w));
        }
    }

    fn decode(bytes: Bytes) -> Result<LinkDetail, DecodeError> {
        let mut out = LinkDetail::default();
        let mut code = false;
        for tlv in tlvs(bytes) {
            let (typ, v) = tlv?;
            match typ {
                link_tlv::DETAIL_CODE => {
                    out.code = text(&v)?;
                    code = true;
                }
                link_tlv::DETAIL_PARAM => {
                    let (mut name, mut value) = (None, None);
                    for tlv in tlvs(v) {
                        let (typ, v) = tlv?;
                        match typ {
                            link_tlv::PARAM_NAME => name = Some(text(&v)?),
                            link_tlv::PARAM_VALUE => value = Some(text(&v)?),
                            _ => {}
                        }
                    }
                    let name = name.ok_or(DecodeError::MissingField(link_tlv::PARAM_NAME))?;
                    out.params.insert(name, value.unwrap_or_default());
                }
                link_tlv::DETAIL_TEXT => out.text = text(&v)?,
                link_tlv::DETAIL_CAUSE => out.causes.push(LinkDetail::decode(v)?),
                _ => {}
            }
        }
        if !code {
            return Err(DecodeError::MissingField(link_tlv::DETAIL_CODE));
        }
        Ok(out)
    }
}

/// A client's words for the details whose sentence names something the
/// host configures or does: a peer entry, renewing a certificate, having
/// another device expect a key. The library says these in neutral terms; a
/// client passes [`word`](Self::word) to [`LinkDetail::render`] to say them
/// in its own.
#[derive(Debug, Clone, Copy)]
pub struct LinkWords<'a> {
    /// What the client calls the entry that configures a device to link
    /// with (e.g. `[[peer]]`).
    pub peer_entry: &'a str,
    /// How this device renews its certificate.
    pub renew: &'a str,
    /// How the other device comes to expect a key; `{key}` stands for the
    /// key fingerprint.
    pub expect_key: &'a str,
}

impl LinkWords<'_> {
    /// The client's sentence for `detail` (its causes rendered as `causes`)
    /// when its code is one these words say: [`DIRECT_OFF_PEER_ENTRY`],
    /// [`DIRECT_REFUSED_PEER_ENTRY`], [`EXPECTED_DEVICE_UNCONFIRMED`],
    /// [`UNRECOGNIZED_KEY`], [`NOT_SERVED_NO_CERTIFICATE`] and
    /// [`CERTIFICATE_EXPIRED`]; `None` for any other, or one missing its
    /// parameters.
    ///
    /// [`DIRECT_OFF_PEER_ENTRY`]: link_code::DIRECT_OFF_PEER_ENTRY
    /// [`DIRECT_REFUSED_PEER_ENTRY`]: link_code::DIRECT_REFUSED_PEER_ENTRY
    /// [`EXPECTED_DEVICE_UNCONFIRMED`]: link_code::EXPECTED_DEVICE_UNCONFIRMED
    /// [`UNRECOGNIZED_KEY`]: link_code::UNRECOGNIZED_KEY
    /// [`NOT_SERVED_NO_CERTIFICATE`]: link_code::NOT_SERVED_NO_CERTIFICATE
    /// [`CERTIFICATE_EXPIRED`]: link_code::CERTIFICATE_EXPIRED
    pub fn word(&self, detail: &LinkDetail, causes: &[String]) -> Option<String> {
        let peer_entry = self.peer_entry;
        let expect_key = |key: &str| self.expect_key.replace("{key}", key);
        // The sentence of the "no enrollment link either" cause at `at`,
        // set off as the neutral sentence sets it off.
        let no_enrollment = |at: usize| {
            detail
                .causes
                .get(at)
                .filter(|c| c.is(link_code::NO_ENROLLMENT_LINK))
                .and(causes.get(at))
                .map(|c| alloc::format!(" {c}"))
                .unwrap_or_default()
        };
        match detail.code.as_str() {
            link_code::DIRECT_OFF_PEER_ENTRY => {
                let peer = detail.param("peer")?;
                Some(alloc::format!(
                    "this device's {peer_entry} for {peer} says direct = false"
                ))
            }
            link_code::DIRECT_REFUSED_PEER_ENTRY => {
                let peer = detail.param("peer")?;
                Some(alloc::format!(
                    "this device's {peer_entry} for {peer} turns direct paths off (direct = false)"
                ))
            }
            link_code::EXPECTED_DEVICE_UNCONFIRMED => {
                let device = detail.param("device")?;
                let why = causes.first()?;
                Some(alloc::format!(
                    "this device expects {device} here and cannot confirm you are it: {why}. It \
                     links once it holds {device}'s namespace, or once its {peer_entry} names your key"
                ))
            }
            link_code::UNRECOGNIZED_KEY => {
                let key = detail.param("key")?;
                let held = detail.param("held").unwrap_or("none");
                let why = causes.first()?;
                Some(alloc::format!(
                    "this device links with devices of the namespaces it holds ({held}) and with \
                     the keys its {peer_entry} entries expect; your key {key} is neither ({why}).{} \
                     Enroll this device in the namespace, or {}",
                    no_enrollment(1),
                    expect_key(key)
                ))
            }
            link_code::NOT_SERVED_NO_CERTIFICATE => {
                let key = detail.param("key")?;
                let serves = match detail.param("policy")? {
                    "listed" => "this relay serves devices of its own and of listed namespaces",
                    "open" => "an open relay serves devices of namespaces",
                    _ => return None,
                };
                Some(alloc::format!(
                    "{serves}: it routes your device name from your certificate, and your hello \
                     carries none.{} Enroll this device in a namespace, or {}",
                    no_enrollment(0),
                    expect_key(key)
                ))
            }
            link_code::CERTIFICATE_EXPIRED => {
                let certificate = detail.param("certificate")?;
                Some(alloc::format!(
                    "its certificate {certificate} is outside its validity period (renew it: {})",
                    self.renew
                ))
            }
            _ => None,
        }
    }
}

/// The `links/list` answer.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LinkListing {
    /// The fingerprint of the key this device links with now.
    pub key: Option<[u8; 32]>,
    /// Probe datagrams sent for direct-path punches, in total.
    pub probes_sent: u64,
    /// Punch requests this device refused, in total.
    pub punches_refused: u64,
    pub links: Vec<LinkEntry>,
    /// This device's relay serving policy (`None`: not reported).
    pub serve: Option<LinkDetail>,
    /// Interests this device holds for sleeping devices now, in total.
    pub held_total: u64,
    /// Wakes this device has sent, in total.
    pub wakes_sent: u64,
}

/// One device this device links with (or is configured to, or punched with).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LinkEntry {
    /// Its peer entry's label, else its device name, else its key.
    pub label: String,
    /// Its key fingerprint, once known.
    pub key: Option<[u8; 32]>,
    /// Its device name, once known.
    pub device: Option<Name>,
    /// The ways it is reached now; empty when it is not.
    pub paths: Vec<LinkPathEntry>,
    /// `none`, `off`, `trying`, `up`, `not-possible` or `refused`.
    pub direct_state: String,
    /// Why the direct path is in its state (`None`: nothing to say).
    pub direct: Option<LinkDetail>,
    /// When the next punch is due.
    pub retry_in_secs: Option<u64>,
    /// `always`, `on-demand` or `off`, for a configured link.
    pub mode: Option<String>,
    /// With mode `on-demand`: the idle close, in seconds.
    pub idle_secs: Option<u64>,
    /// Set when the device is a relay this device uses.
    pub relay: Option<LinkRelayEntry>,
    /// Set (relay side) when the device is asleep here.
    pub asleep: Option<LinkAsleepEntry>,
    /// Why a configured device is not linked now.
    pub down: Option<LinkDetail>,
}

/// A relay this device uses.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LinkRelayEntry {
    /// `user` or `namespace:<namespace>`.
    pub source: String,
    /// Lower is preferred.
    pub preference: u64,
    /// `linked`, `trying`, `down`, `standby` or `off`.
    pub state: String,
    /// Why it is in that state (`None`: nothing to say).
    pub detail: Option<LinkDetail>,
}

/// A device asleep at this relay.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LinkAsleepEntry {
    /// How long it has been asleep.
    pub since_secs: u64,
    /// Interests held for it now.
    pub held: u64,
    /// It asked for its Interests to be held.
    pub hold: bool,
    /// It registered a wake token.
    pub wake: bool,
    /// Wakes sent to it.
    pub wakes: u64,
}

/// A link mode as `links/mode` carries it (in `ControlParameters.local_uri`,
/// the link's label in `uri`) and `ndn-ctl link mode` takes it: `always`,
/// `on-demand`, `on-demand:<idle seconds>` or `off`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkModeArg {
    Always,
    /// `idle_secs = None`: keep the link's current (or configured) idle close.
    OnDemand {
        idle_secs: Option<u64>,
    },
    Off,
}

impl core::str::FromStr for LinkModeArg {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "always" => Ok(Self::Always),
            "on-demand" => Ok(Self::OnDemand { idle_secs: None }),
            "off" => Ok(Self::Off),
            _ => match s.strip_prefix("on-demand:").map(str::parse::<u64>) {
                Some(Ok(secs)) => Ok(Self::OnDemand {
                    idle_secs: Some(secs),
                }),
                _ => Err(alloc::format!(
                    "{s:?} is not a link mode: use always, on-demand, on-demand:<idle seconds> \
                     (e.g. on-demand:60) or off"
                )),
            },
        }
    }
}

impl core::fmt::Display for LinkModeArg {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Always => f.write_str("always"),
            Self::OnDemand { idle_secs: None } => f.write_str("on-demand"),
            Self::OnDemand { idle_secs: Some(s) } => write!(f, "on-demand:{s}"),
            Self::Off => f.write_str("off"),
        }
    }
}

/// The parameters of a `links/connect`, `links/disconnect` or (with `mode`)
/// `links/mode` command for the link labelled `label`.
pub fn link_command(label: &str, mode: Option<LinkModeArg>) -> ControlParameters {
    ControlParameters {
        uri: Some(label.into()),
        local_uri: mode.map(|m| m.to_string()),
        ..Default::default()
    }
}

/// What is wrong with a links command's parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkCommandError {
    /// Uri names no link.
    NoLabel,
    /// LocalUri is not a link mode (it is carried).
    BadMode(String),
}

/// The label (and, if carried, the mode) of a links command.
pub fn parse_link_command(
    params: &ControlParameters,
) -> Result<(String, Option<LinkModeArg>), LinkCommandError> {
    let label = params
        .uri
        .clone()
        .filter(|l| !l.is_empty())
        .ok_or(LinkCommandError::NoLabel)?;
    let mode = params
        .local_uri
        .as_deref()
        .map(|m| m.parse().map_err(|_| LinkCommandError::BadMode(m.into())))
        .transpose()?;
    Ok((label, mode))
}

/// One path to a device.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LinkPathEntry {
    /// `direct`, `link` or `relay`.
    pub kind: String,
    /// The face carrying it (for a relay path, the relay's link face).
    pub face_id: u64,
    /// The address the QUIC connection reaches, `ip:port`.
    pub remote: Option<String>,
    /// The connection's round-trip time estimate.
    pub rtt_micros: Option<u64>,
    /// How long it has been up.
    pub age_secs: u64,
    /// For a relay path: the relay's label.
    pub via: Option<String>,
}

fn write_nni(w: &mut TlvWriter, typ: u64, v: u64) {
    let (b, n) = nni_bytes(v);
    w.write_tlv(typ, &b[..n]);
}

fn write_text(w: &mut TlvWriter, typ: u64, s: &str) {
    if !s.is_empty() {
        w.write_tlv(typ, s.as_bytes());
    }
}

fn write_detail(w: &mut TlvWriter, typ: u64, detail: Option<&LinkDetail>) {
    if let Some(d) = detail {
        w.write_nested(typ, |w| d.encode_into(w));
    }
}

fn nni(v: &[u8]) -> Result<u64, DecodeError> {
    read_nni(v).ok_or(DecodeError::Malformed)
}

fn text(v: &[u8]) -> Result<String, DecodeError> {
    String::from_utf8(v.to_vec()).map_err(|_| DecodeError::Malformed)
}

fn key(v: &[u8]) -> Result<[u8; 32], DecodeError> {
    v.try_into().map_err(|_| DecodeError::Malformed)
}

/// The TLVs in `bytes`, refusing a malformed one.
fn tlvs(bytes: Bytes) -> impl Iterator<Item = Result<(u64, Bytes), DecodeError>> {
    let mut reader = TlvReader::new(bytes);
    core::iter::from_fn(move || {
        (!reader.is_empty()).then(|| reader.read_tlv().map_err(|_| DecodeError::Malformed))
    })
}

impl LinkListing {
    /// Encode into the `links/list` dataset body. Empty and absent optional
    /// fields are omitted.
    pub fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        if let Some(k) = &self.key {
            w.write_tlv(link_tlv::KEY, k);
        }
        write_nni(&mut w, link_tlv::PROBES_SENT, self.probes_sent);
        write_nni(&mut w, link_tlv::PUNCHES_REFUSED, self.punches_refused);
        for link in &self.links {
            w.write_nested(link_tlv::LINK, |w| link.encode_into(w));
        }
        write_detail(&mut w, link_tlv::SERVE, self.serve.as_ref());
        write_nni(&mut w, link_tlv::HELD, self.held_total);
        write_nni(&mut w, link_tlv::WAKES, self.wakes_sent);
        w.finish()
    }

    /// Decode the dataset body. Unknown TLVs are skipped (evolvability); a
    /// malformed TLV, or an entry missing a required field, is an error.
    pub fn decode(bytes: Bytes) -> Result<LinkListing, DecodeError> {
        let mut out = LinkListing::default();
        for tlv in tlvs(bytes) {
            let (typ, v) = tlv?;
            match typ {
                link_tlv::KEY => out.key = Some(key(&v)?),
                link_tlv::PROBES_SENT => out.probes_sent = nni(&v)?,
                link_tlv::PUNCHES_REFUSED => out.punches_refused = nni(&v)?,
                link_tlv::LINK => out.links.push(LinkEntry::decode(v)?),
                link_tlv::SERVE => out.serve = Some(LinkDetail::decode(v)?),
                link_tlv::HELD => out.held_total = nni(&v)?,
                link_tlv::WAKES => out.wakes_sent = nni(&v)?,
                _ => {}
            }
        }
        Ok(out)
    }
}

impl LinkEntry {
    fn encode_into(&self, w: &mut TlvWriter) {
        w.write_tlv(link_tlv::LABEL, self.label.as_bytes());
        if let Some(k) = &self.key {
            w.write_tlv(link_tlv::KEY, k);
        }
        if let Some(device) = &self.device {
            w.write_nested(link_tlv::DEVICE, |w| {
                for c in device.components() {
                    w.write_tlv(c.typ, &c.value);
                }
            });
        }
        for path in &self.paths {
            w.write_nested(link_tlv::PATH, |w| path.encode_into(w));
        }
        w.write_tlv(link_tlv::DIRECT_STATE, self.direct_state.as_bytes());
        write_detail(w, link_tlv::DIRECT_DETAIL, self.direct.as_ref());
        if let Some(s) = self.retry_in_secs {
            write_nni(w, link_tlv::RETRY_IN_SECS, s);
        }
        if let Some(mode) = &self.mode {
            w.write_tlv(link_tlv::MODE, mode.as_bytes());
        }
        if let Some(s) = self.idle_secs {
            write_nni(w, link_tlv::IDLE_SECS, s);
        }
        if let Some(relay) = &self.relay {
            w.write_nested(link_tlv::RELAY, |w| relay.encode_into(w));
        }
        if let Some(asleep) = &self.asleep {
            w.write_nested(link_tlv::ASLEEP, |w| asleep.encode_into(w));
        }
        write_detail(w, link_tlv::DOWN, self.down.as_ref());
    }

    fn decode(bytes: Bytes) -> Result<LinkEntry, DecodeError> {
        let mut out = LinkEntry::default();
        let (mut label, mut state) = (false, false);
        for tlv in tlvs(bytes) {
            let (typ, v) = tlv?;
            match typ {
                link_tlv::LABEL => {
                    out.label = text(&v)?;
                    label = true;
                }
                link_tlv::KEY => out.key = Some(key(&v)?),
                link_tlv::DEVICE => {
                    out.device = Some(Name::decode(v).map_err(|_| DecodeError::Malformed)?)
                }
                link_tlv::PATH => out.paths.push(LinkPathEntry::decode(v)?),
                link_tlv::DIRECT_STATE => {
                    out.direct_state = text(&v)?;
                    state = true;
                }
                link_tlv::DIRECT_DETAIL => out.direct = Some(LinkDetail::decode(v)?),
                link_tlv::RETRY_IN_SECS => out.retry_in_secs = Some(nni(&v)?),
                link_tlv::MODE => out.mode = Some(text(&v)?),
                link_tlv::IDLE_SECS => out.idle_secs = Some(nni(&v)?),
                link_tlv::RELAY => out.relay = Some(LinkRelayEntry::decode(v)?),
                link_tlv::ASLEEP => out.asleep = Some(LinkAsleepEntry::decode(v)?),
                link_tlv::DOWN => out.down = Some(LinkDetail::decode(v)?),
                _ => {}
            }
        }
        if !label {
            return Err(DecodeError::MissingField(link_tlv::LABEL));
        }
        if !state {
            return Err(DecodeError::MissingField(link_tlv::DIRECT_STATE));
        }
        Ok(out)
    }
}

impl LinkRelayEntry {
    fn encode_into(&self, w: &mut TlvWriter) {
        w.write_tlv(link_tlv::RELAY_SOURCE, self.source.as_bytes());
        write_nni(w, link_tlv::PREFERENCE, self.preference);
        w.write_tlv(link_tlv::RELAY_STATE, self.state.as_bytes());
        write_detail(w, link_tlv::RELAY_DETAIL, self.detail.as_ref());
    }

    fn decode(bytes: Bytes) -> Result<LinkRelayEntry, DecodeError> {
        let mut out = LinkRelayEntry::default();
        let (mut source, mut state) = (false, false);
        for tlv in tlvs(bytes) {
            let (typ, v) = tlv?;
            match typ {
                link_tlv::RELAY_SOURCE => {
                    out.source = text(&v)?;
                    source = true;
                }
                link_tlv::PREFERENCE => out.preference = nni(&v)?,
                link_tlv::RELAY_STATE => {
                    out.state = text(&v)?;
                    state = true;
                }
                link_tlv::RELAY_DETAIL => out.detail = Some(LinkDetail::decode(v)?),
                _ => {}
            }
        }
        if !source {
            return Err(DecodeError::MissingField(link_tlv::RELAY_SOURCE));
        }
        if !state {
            return Err(DecodeError::MissingField(link_tlv::RELAY_STATE));
        }
        Ok(out)
    }
}

impl LinkAsleepEntry {
    fn encode_into(&self, w: &mut TlvWriter) {
        write_nni(w, link_tlv::SINCE_SECS, self.since_secs);
        write_nni(w, link_tlv::HELD, self.held);
        if self.hold {
            w.write_tlv(link_tlv::HOLD, &[]);
        }
        if self.wake {
            w.write_tlv(link_tlv::WAKE, &[]);
        }
        write_nni(w, link_tlv::WAKES, self.wakes);
    }

    fn decode(bytes: Bytes) -> Result<LinkAsleepEntry, DecodeError> {
        let mut out = LinkAsleepEntry::default();
        for tlv in tlvs(bytes) {
            let (typ, v) = tlv?;
            match typ {
                link_tlv::SINCE_SECS => out.since_secs = nni(&v)?,
                link_tlv::HELD => out.held = nni(&v)?,
                link_tlv::HOLD => out.hold = true,
                link_tlv::WAKE => out.wake = true,
                link_tlv::WAKES => out.wakes = nni(&v)?,
                _ => {}
            }
        }
        Ok(out)
    }
}

impl LinkPathEntry {
    fn encode_into(&self, w: &mut TlvWriter) {
        w.write_tlv(link_tlv::PATH_KIND, self.kind.as_bytes());
        write_nni(w, link_tlv::FACE_ID, self.face_id);
        if let Some(r) = &self.remote {
            w.write_tlv(link_tlv::REMOTE, r.as_bytes());
        }
        if let Some(rtt) = self.rtt_micros {
            write_nni(w, link_tlv::RTT_MICROS, rtt);
        }
        write_nni(w, link_tlv::AGE_SECS, self.age_secs);
        if let Some(via) = &self.via {
            w.write_tlv(link_tlv::VIA, via.as_bytes());
        }
    }

    fn decode(bytes: Bytes) -> Result<LinkPathEntry, DecodeError> {
        let mut out = LinkPathEntry::default();
        let (mut kind, mut face) = (false, false);
        for tlv in tlvs(bytes) {
            let (typ, v) = tlv?;
            match typ {
                link_tlv::PATH_KIND => {
                    out.kind = text(&v)?;
                    kind = true;
                }
                link_tlv::FACE_ID => {
                    out.face_id = nni(&v)?;
                    face = true;
                }
                link_tlv::REMOTE => out.remote = Some(text(&v)?),
                link_tlv::RTT_MICROS => out.rtt_micros = Some(nni(&v)?),
                link_tlv::AGE_SECS => out.age_secs = nni(&v)?,
                link_tlv::VIA => out.via = Some(text(&v)?),
                _ => {}
            }
        }
        if !kind {
            return Err(DecodeError::MissingField(link_tlv::PATH_KIND));
        }
        if !face {
            return Err(DecodeError::MissingField(link_tlv::FACE_ID));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn link_codes_are_unique_and_kebab_case() {
        let mut seen = alloc::collections::BTreeSet::new();
        for code in link_code::ALL {
            assert!(seen.insert(*code), "{code} is listed twice");
            assert!(
                !code.is_empty()
                    && code
                        .split('-')
                        .all(|w| !w.is_empty() && w.bytes().all(|b| b.is_ascii_lowercase())),
                "{code} is not kebab-case"
            );
        }
    }

    #[test]
    fn link_listing_round_trips() {
        let refused_here = LinkDetail::new(
            link_code::LINK_CLOSED_HERE,
            "this device closed the link: x",
        )
        .with("reason", "0x10")
        .caused_by(
            LinkDetail::new(link_code::UNRECOGNIZED_KEY, "x")
                .with("key", "ab")
                .caused_by(LinkDetail::new(
                    link_code::NO_CERTIFICATE,
                    "it sent no certificate",
                )),
        );
        let listing = LinkListing {
            key: Some([0xab; 32]),
            probes_sent: 40,
            punches_refused: 1,
            links: vec![
                LinkEntry {
                    label: "phone".into(),
                    key: Some([0x01; 32]),
                    device: Some("/home/bob/node/phone".parse().unwrap()),
                    paths: vec![
                        LinkPathEntry {
                            kind: "direct".into(),
                            face_id: 7,
                            remote: Some("203.0.113.5:6367".into()),
                            rtt_micros: Some(12_345),
                            age_secs: 90,
                            via: None,
                        },
                        LinkPathEntry {
                            kind: "relay".into(),
                            face_id: 3,
                            remote: Some("[2001:db8::1]:6367".into()),
                            rtt_micros: None,
                            age_secs: 3_600,
                            via: Some("vps".into()),
                        },
                    ],
                    direct_state: "up".into(),
                    direct: Some(
                        LinkDetail::new(link_code::DIRECT_UP, "direct path to 203.0.113.5:6367")
                            .with("remote", "203.0.113.5:6367"),
                    ),
                    retry_in_secs: None,
                    mode: Some("on-demand".into()),
                    idle_secs: Some(60),
                    relay: None,
                    asleep: Some(LinkAsleepEntry {
                        since_secs: 300,
                        held: 4,
                        hold: true,
                        wake: true,
                        wakes: 2,
                    }),
                    down: None,
                },
                LinkEntry {
                    label: "laptop".into(),
                    direct_state: "not-possible".into(),
                    direct: Some(
                        LinkDetail::new(link_code::PUNCH_NO_PROBE, "no probe came back")
                            .with("peer", "laptop"),
                    ),
                    retry_in_secs: Some(20),
                    down: Some(
                        LinkDetail::new(link_code::DIAL_FAILED, "its last dial failed")
                            .with("retry_secs", "5.0")
                            .caused_by(refused_here),
                    ),
                    ..Default::default()
                },
                LinkEntry {
                    label: "/home/node/vps".into(),
                    direct_state: "none".into(),
                    mode: Some("always".into()),
                    relay: Some(LinkRelayEntry {
                        source: "namespace:/home".into(),
                        preference: 0,
                        state: "standby".into(),
                        detail: Some(
                            LinkDetail::new(link_code::RELAY_STANDBY, "not needed")
                                .with("chosen", 1)
                                .with("count", 1),
                        ),
                    }),
                    ..Default::default()
                },
            ],
            serve: Some(LinkDetail::new(link_code::SERVE_OPEN, "open").with("links_total", 256)),
            held_total: 4,
            wakes_sent: 2,
        };
        assert_eq!(LinkListing::decode(listing.encode()).unwrap(), listing);
        assert_eq!(
            LinkListing::decode(LinkListing::default().encode()).unwrap(),
            LinkListing::default()
        );
    }

    #[test]
    fn link_entry_without_label_is_refused() {
        let mut w = TlvWriter::new();
        w.write_nested(link_tlv::LINK, |w| {
            w.write_tlv(link_tlv::DIRECT_STATE, b"none");
        });
        assert_eq!(
            LinkListing::decode(w.finish()),
            Err(DecodeError::MissingField(link_tlv::LABEL))
        );
    }

    #[test]
    fn detail_without_code_is_refused() {
        let mut w = TlvWriter::new();
        w.write_nested(link_tlv::SERVE, |w| {
            w.write_tlv(link_tlv::DETAIL_TEXT, b"own namespaces");
        });
        assert_eq!(
            LinkListing::decode(w.finish()),
            Err(DecodeError::MissingField(link_tlv::DETAIL_CODE))
        );
    }

    /// A client's words for a cause replace that cause's sentence in its
    /// parent's; details it does not word keep their sentence.
    #[test]
    fn render_puts_worded_causes_in_place() {
        let inner = LinkDetail::new("inner", "B");
        let other = LinkDetail::new("other", "C");
        let outer = LinkDetail::new("outer", "A B, C B")
            .caused_by(inner)
            .caused_by(other);
        let words = |d: &LinkDetail, _: &[String]| d.is("inner").then(|| String::from("b"));
        assert_eq!(outer.render(&words), "A b, C B");
        assert_eq!(outer.render(&|_, _| None), outer.text);
    }

    /// A client's words cover exactly the codes whose neutral sentence
    /// stands in for host terms, take every parameter they name, and leave
    /// a detail missing its parameters to its neutral sentence.
    #[test]
    fn link_words_cover_the_host_codes() {
        let words = LinkWords {
            peer_entry: "P",
            renew: "R",
            expect_key: "E({key})",
        };
        let word = |d: &LinkDetail| d.render(&|d, c| words.word(d, c));
        let why = LinkDetail::new(link_code::NO_CERTIFICATE, "x");
        let worded = [
            LinkDetail::new(link_code::DIRECT_OFF_PEER_ENTRY, "n").with("peer", "vps"),
            LinkDetail::new(link_code::DIRECT_REFUSED_PEER_ENTRY, "n").with("peer", "vps"),
            LinkDetail::new(link_code::EXPECTED_DEVICE_UNCONFIRMED, "n x")
                .with("device", "/a/node/vps")
                .caused_by(why.clone()),
            LinkDetail::new(link_code::UNRECOGNIZED_KEY, "n x")
                .with("key", "ab")
                .caused_by(why.clone()),
            LinkDetail::new(link_code::NOT_SERVED_NO_CERTIFICATE, "n")
                .with("policy", "open")
                .with("key", "ab"),
            LinkDetail::new(link_code::CERTIFICATE_EXPIRED, "n").with("certificate", "/a/c"),
        ];
        for detail in &worded {
            let said = word(detail);
            assert_ne!(said, detail.text, "{}", detail.code);
            assert!(!said.contains("{key}"), "{said}");
        }
        assert!(word(&worded[3]).contains("E(ab)"));
        for code in link_code::ALL {
            if worded.iter().any(|d| d.is(code)) {
                assert_eq!(
                    word(&LinkDetail::new(code, "n")),
                    "n",
                    "{code} without params"
                );
            } else {
                assert!(
                    words.word(&LinkDetail::new(code, "n"), &[]).is_none(),
                    "{code}"
                );
            }
        }
    }

    #[test]
    fn link_commands_carry_label_and_mode() {
        for mode in [
            LinkModeArg::Always,
            LinkModeArg::OnDemand { idle_secs: None },
            LinkModeArg::OnDemand {
                idle_secs: Some(120),
            },
            LinkModeArg::Off,
        ] {
            let params =
                ControlParameters::decode(link_command("vps", Some(mode)).encode()).unwrap();
            assert_eq!(parse_link_command(&params), Ok(("vps".into(), Some(mode))));
        }
        let params = link_command("vps", None);
        assert_eq!(parse_link_command(&params), Ok(("vps".into(), None)));
        assert!("sometimes".parse::<LinkModeArg>().is_err());
        let params = ControlParameters {
            local_uri: Some("sometimes".into()),
            ..link_command("vps", None)
        };
        assert_eq!(
            parse_link_command(&params),
            Err(LinkCommandError::BadMode("sometimes".into()))
        );
        assert_eq!(
            parse_link_command(&ControlParameters::default()),
            Err(LinkCommandError::NoLabel)
        );
    }
}
