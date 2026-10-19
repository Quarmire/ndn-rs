//! Change notifications a management client subscribes to instead of
//! polling: what changed in this node's trust (approvals, invites,
//! enrollments, trust-context versions, memberships, renewals) and in its
//! links.
//!
//! Each stream is an NFD-style notification stream
//! (`/localhost/nfd/<module>/notifications/seq=<N>`, see ndn-mgmt's
//! `NotificationStream`) whose Data content is one JSON object tagged by
//! `"kind"`:
//!
//! | stream | prefix | events |
//! |---|---|---|
//! | trust | `/localhost/nfd/security/notifications` | `ndn_cert::report::TrustEvent` |
//! | links | `/localhost/nfd/links/notifications` | [`LinkEvent`] |
//!
//! Besides the events, a stream answers [`RESYNC_KIND`]
//! (`{"kind":"resync","next":N}`) to a subscriber that asked for an event it
//! no longer holds (or one from before the daemon started): the client lists
//! the state again through the management verbs and continues at `N`.
//!
//! Evolution: a kind's fields are only ever added (clients ignore fields
//! they do not know); a change of meaning takes a new kind, and a client
//! skips kinds it does not know (`TrustEvent::Unknown`,
//! [`LinkEvent::Unknown`]). The kind is the version.
//!
//! Events carry identifiers and states only — never a verification code,
//! an invite token, a key's secret or a denial's free text. The streams are
//! served to every local face (the forwarder answers every Interest for
//! the name with the same Data, so a producer cannot hold one subscriber's
//! events back from another), so they carry nothing a local user who is
//! not a trust administrator may not read: the details are fetched through
//! the gated verbs (`ca/list-approvals`, `security/enroll-status`,
//! `ca/invite-list`, `links/list`).

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

/// Module of the trust stream: `/localhost/nfd/security/notifications`.
pub const TRUST_STREAM: &[u8] = b"security";
/// Module of the links stream: `/localhost/nfd/links/notifications`.
pub const LINKS_STREAM: &[u8] = b"links";
/// The `"kind"` a stream answers with instead of an event the subscriber
/// asked for and that the stream no longer holds: `{"kind":"resync","next":N}`.
pub const RESYNC_KIND: &str = "resync";

/// Where a subsystem publishes the events it makes: the host hands each
/// subsystem the stream (ndn-mgmt's `NotificationStream` implements it).
pub trait EventSink<E>: Send + Sync {
    fn publish(&self, event: E);
}

/// One change in this node's links.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum LinkEvent {
    /// A link appeared or its state changed: its state now. Paths, timers
    /// and counters: `links/list`.
    LinkChanged(LinkState),
    /// A link is no longer listed (a device that linked in went away).
    LinkGone {
        label: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        key: Option<String>,
    },
    #[serde(other)]
    Unknown,
}

/// The state of one link, as `links/list` lists it, without its timers,
/// counters, addresses and texts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkState {
    pub label: String,
    /// Hex SHA-256 fingerprint of the linked device's key, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    /// The kinds of the paths up now (`direct`, `link`, `relay`).
    #[serde(default)]
    pub paths: Vec<String>,
    /// The direct path's state (`none`, `off`, `trying`, `up`,
    /// `not-possible`, `refused`).
    pub direct: String,
    /// The link's mode, for a configured device.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// The relay's state, when the device is reached through one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<String>,
    /// The device sleeps behind this relay.
    #[serde(default)]
    pub asleep: bool,
    /// Why the link is down and not retried (its `links/list` code); `None`
    /// while it is not down.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub down: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn events_are_tagged_by_kebab_kind() {
        let link = LinkEvent::LinkChanged(LinkState {
            label: "phone".into(),
            key: None,
            device: None,
            paths: vec!["link".into()],
            direct: "trying".into(),
            mode: Some("always".into()),
            relay: None,
            asleep: false,
            down: None,
        });
        let json: serde_json::Value = serde_json::to_value(&link).unwrap();
        assert_eq!(json["kind"], "link-changed");
        assert_eq!(json["label"], "phone");
        let back: LinkEvent = serde_json::from_value(json).unwrap();
        assert_eq!(back, link);
    }

    #[test]
    fn unknown_kinds_are_skippable() {
        let later: LinkEvent = serde_json::from_str(r#"{"kind":"link-moved"}"#).unwrap();
        assert_eq!(later, LinkEvent::Unknown);
    }
}
