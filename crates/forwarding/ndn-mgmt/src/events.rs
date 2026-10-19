//! The trust and links change-notification streams
//! (`/localhost/nfd/security/notifications`,
//! `/localhost/nfd/links/notifications`): JSON events
//! ([`ndn_mgmt_wire::events`]) a management client subscribes to instead of
//! polling the listing verbs.
//!
//! The host creates the streams ([`MgmtEvents::default`]) before its
//! subsystems, hands each subsystem the stream it publishes to (both
//! implement [`EventSink`]), and gives them to [`crate::mount_management`]
//! in [`crate::MgmtHandles::events`], which serves them.

use std::sync::Arc;

use bytes::Bytes;
use ndn_cert::report::TrustEvent;
use ndn_mgmt_wire::events::{EventSink, LINKS_STREAM, LinkEvent, RESYNC_KIND, TRUST_STREAM};

use crate::notification::{NotificationEvent, NotificationStream};

impl NotificationEvent for TrustEvent {
    fn encode(&self) -> Bytes {
        json(self)
    }

    fn resync(next: u64) -> Option<Bytes> {
        Some(resync_content(next))
    }
}

impl NotificationEvent for LinkEvent {
    fn encode(&self) -> Bytes {
        json(self)
    }

    fn resync(next: u64) -> Option<Bytes> {
        Some(resync_content(next))
    }
}

impl<T: NotificationEvent> EventSink<T> for NotificationStream<T> {
    fn publish(&self, event: T) {
        NotificationStream::publish(self, event);
    }
}

fn json<T: serde::Serialize>(event: &T) -> Bytes {
    // The event types serialize infallibly (strings, numbers, enums).
    Bytes::from(serde_json::to_vec(event).unwrap_or_default())
}

/// `{"kind":"resync","next":N}`.
fn resync_content(next: u64) -> Bytes {
    Bytes::from(format!(r#"{{"kind":"{RESYNC_KIND}","next":{next}}}"#))
}

/// The trust and links event streams of one daemon run. Cheap to clone:
/// clones share the streams.
#[derive(Clone)]
pub struct MgmtEvents {
    pub trust: Arc<NotificationStream<TrustEvent>>,
    pub links: Arc<NotificationStream<LinkEvent>>,
}

impl Default for MgmtEvents {
    /// Fresh streams numbered after the start time in microseconds, so a
    /// subscriber resuming with a number from an earlier run is told to
    /// resync rather than handed a new event under an old number.
    fn default() -> Self {
        let start = web_time::SystemTime::now()
            .duration_since(web_time::SystemTime::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX / 2));
        Self {
            trust: NotificationStream::starting_after(
                crate::notifications_prefix(TRUST_STREAM),
                start,
            ),
            links: NotificationStream::starting_after(
                crate::notifications_prefix(LINKS_STREAM),
                start,
            ),
        }
    }
}

impl MgmtEvents {
    /// The trust stream as the sink subsystems publish to.
    pub fn trust_sink(&self) -> Arc<dyn EventSink<TrustEvent>> {
        Arc::clone(&self.trust) as Arc<dyn EventSink<TrustEvent>>
    }

    /// The links stream as the sink subsystems publish to.
    pub fn links_sink(&self) -> Arc<dyn EventSink<LinkEvent>> {
        Arc::clone(&self.links) as Arc<dyn EventSink<LinkEvent>>
    }
}

/// The trust event a CA's approval record tells of: opened (pending) or
/// decided. Never its verification code, key or device — those are read
/// through `ca/list-approvals`.
pub fn approval_event(record: &ndn_cert::approval::ApprovalRecord) -> TrustEvent {
    use ndn_cert::approval::ApprovalState;
    use ndn_cert::report::Decision;
    let decided = |decision| TrustEvent::ApprovalDecided {
        ca: record.ca_prefix.clone(),
        request: record.request_id.clone(),
        decision,
    };
    match record.state {
        ApprovalState::Pending => TrustEvent::ApprovalRequested {
            ca: record.ca_prefix.clone(),
            request: record.request_id.clone(),
            role: record.role.clone(),
        },
        ApprovalState::Approved { .. } => decided(Decision::Approved),
        ApprovalState::Denied { .. } => decided(Decision::Denied),
    }
}

/// An observer for [`ndn_cert::approval::ApprovalStore::set_observer`]
/// publishing [`approval_event`]s to `sink`.
pub fn approval_observer(
    sink: Arc<dyn EventSink<TrustEvent>>,
) -> ndn_cert::approval::ApprovalObserver {
    Arc::new(move |record| sink.publish(approval_event(record)))
}

/// The trust event of a change of an invite of the CA `ca` (its prefix):
/// made, withdrawn or redeemed. Never its token — the invite is read through
/// `ca/invite-list`.
pub fn invite_event(ca: &str, event: &ndn_cert::InviteEvent) -> TrustEvent {
    use ndn_cert::InviteEventKind as Kind;
    let (ca, id, role) = (
        ca.to_owned(),
        event.invite.id.clone(),
        event.invite.info.role.clone(),
    );
    match event.kind {
        Kind::Created => TrustEvent::InviteCreated { ca, id, role },
        Kind::Withdrawn => TrustEvent::InviteWithdrawn { ca, id },
        Kind::Redeemed => TrustEvent::InviteRedeemed { ca, id, role },
    }
}

/// An observer for [`ndn_cert::TokenStore::set_observer`] of the CA `ca`
/// (its prefix) publishing [`invite_event`]s to `sink`.
pub fn invite_observer(
    ca: String,
    sink: Arc<dyn EventSink<TrustEvent>>,
) -> ndn_cert::InviteObserver {
    Arc::new(move |event| sink.publish(invite_event(&ca, event)))
}

/// The trust event of a certificate the CA `ca` (its prefix) of namespace
/// `namespace` issued: its name and, when it follows the namespace layout,
/// the role it certifies.
pub fn issued_event(
    ca: &str,
    namespace: &ndn_packet::Name,
    certificate: &ndn_packet::Name,
) -> TrustEvent {
    let key = ndn_security::cert_name::key_name_of(certificate);
    TrustEvent::CertificateIssued {
        ca: ca.to_owned(),
        certificate: certificate.to_string(),
        role: ndn_cert::roles::parse_device_key(namespace, &key)
            .map(|d| d.role.as_str().to_owned()),
    }
}

/// An observer for [`ndn_cert::CaState::set_issued_observer`] of the CA
/// `ca` (its prefix) of `namespace`, publishing [`issued_event`]s to `sink`.
pub fn issued_observer(
    ca: String,
    namespace: ndn_packet::Name,
    sink: Arc<dyn EventSink<TrustEvent>>,
) -> ndn_cert::IssuedObserver {
    Arc::new(move |cert| sink.publish(issued_event(&ca, &namespace, &cert.name)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_cert::approval::{ApprovalRecord, ApprovalState, Approver};

    fn record(state: ApprovalState) -> ApprovalRecord {
        ApprovalRecord {
            request_id: "00112233aabbccdd".into(),
            ca_prefix: "/home/bob".into(),
            key_name: "/home/bob/node/pi/KEY/%01".into(),
            public_key_sha256: "ab".repeat(32),
            role: Some("node".into()),
            device: Some("pi".into()),
            code: "482 913".into(),
            created_secs: 1,
            expires_secs: 2,
            invite: false,
            state,
        }
    }

    #[test]
    fn approval_events_carry_ids_and_states_never_codes_keys_or_reasons() {
        let by = Approver::LocalOperator {
            who: "uid 1000 (alice)".into(),
        };
        for (state, kind) in [
            (ApprovalState::Pending, "approval-requested"),
            (
                ApprovalState::Approved {
                    by: by.clone(),
                    at_secs: 3,
                },
                "approval-decided",
            ),
            (
                ApprovalState::Denied {
                    by,
                    at_secs: 3,
                    reason: "secret-reason".into(),
                },
                "approval-decided",
            ),
        ] {
            let rec = record(state);
            let wire = approval_event(&rec).encode();
            let json: serde_json::Value = serde_json::from_slice(&wire).unwrap();
            assert_eq!(json["kind"], kind);
            assert_eq!(json["request"], "00112233aabbccdd");
            let text = String::from_utf8(wire.to_vec()).unwrap();
            for secret in [
                "482 913",
                "482913",
                "KEY",
                "/pi",
                "secret-reason",
                "alice",
                &rec.public_key_sha256,
            ] {
                assert!(
                    !text.contains(secret),
                    "{kind} event carries {secret:?}: {text}"
                );
            }
        }
    }

    #[test]
    fn an_issued_certificate_is_told_with_its_role() {
        let ns: ndn_packet::Name = "/home/bob".parse().unwrap();
        let cert: ndn_packet::Name = "/home/bob/node/pi/KEY/%01/NDNCERT/v=1".parse().unwrap();
        let json: serde_json::Value =
            serde_json::from_slice(&issued_event("/home/bob", &ns, &cert).encode()).unwrap();
        assert_eq!(json["kind"], "certificate-issued");
        assert_eq!(json["ca"], "/home/bob");
        assert_eq!(json["role"], "node");
        assert!(json["certificate"].as_str().unwrap().contains("NDNCERT"));
    }

    #[test]
    fn resync_names_the_next_event() {
        let content = <TrustEvent as NotificationEvent>::resync(17).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&content).unwrap();
        assert_eq!(json["kind"], RESYNC_KIND);
        assert_eq!(json["next"], 17);
    }
}
