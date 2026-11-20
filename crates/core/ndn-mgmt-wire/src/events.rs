//! Change notifications a management client subscribes to instead of
//! polling: what changed in this node's trust (approvals, invites,
//! enrollments, trust-context versions, memberships, renewals), in its
//! links, and in its routes.
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
//! | rib | `/localhost/nfd/rib/notifications` | [`RibEvent`] |
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

/// One change in this node's routes (`/localhost/nfd/rib/notifications`).
///
/// Names are URIs (`/alice/32=sync`). The stream is served to local faces
/// only (`/localhost`), and tells a route that came up on a face that is
/// not always local — a link, a tunnel, a radio — never one of a local
/// application or management socket: those routes carry no far end to tell
/// anything to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum RibEvent {
    /// A route was registered through the management interface
    /// (`rib/register`), on any face.
    Register {
        face_id: u64,
        origin: u64,
        name: String,
    },
    /// A route was removed through the management interface
    /// (`rib/unregister`), on any face.
    Unregister {
        face_id: u64,
        origin: u64,
        name: String,
    },
    /// A route toward `name` now puts face `face_id` into the forwarder's
    /// FIB, however it got there (a link layer, configuration, a routing
    /// protocol, `rib/register`), and did not before: what the engine RIB's
    /// `route_events` tells. Told after the route is installed; never for a
    /// route that was already there or was removed.
    RouteUp { face_id: u64, name: String },
    /// The daemon's feed of routes fell behind and lost some: any route may
    /// have come up. A client that acts on routes coming up acts as if
    /// every one had.
    RoutesMissed,
    #[serde(other)]
    Unknown,
}

/// Module of the rib stream: `/localhost/nfd/rib/notifications`.
pub const RIB_STREAM: &[u8] = b"rib";

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

    #[test]
    fn rib_events_are_tagged_by_kebab_kind() {
        let up = RibEvent::RouteUp {
            face_id: 9,
            name: "/alice/32=sync".into(),
        };
        let json: serde_json::Value = serde_json::to_value(&up).unwrap();
        assert_eq!(json["kind"], "route-up");
        assert_eq!(json["face_id"], 9);
        assert_eq!(json["name"], "/alice/32=sync");
        assert_eq!(serde_json::from_value::<RibEvent>(json).unwrap(), up);
        let missed = serde_json::to_value(RibEvent::RoutesMissed).unwrap();
        assert_eq!(missed["kind"], "routes-missed");
        let later: RibEvent = serde_json::from_str(r#"{"kind":"route-moved"}"#).unwrap();
        assert_eq!(later, RibEvent::Unknown);
    }
}
