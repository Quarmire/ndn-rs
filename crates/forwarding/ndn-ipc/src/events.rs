//! Subscribing to the daemon's change notifications — the trust stream
//! (`/localhost/nfd/security/notifications`, [`TrustEvent`]) and the links
//! stream (`/localhost/nfd/links/notifications`, [`LinkEvent`]) — instead
//! of polling the listing verbs.
//!
//! A subscriber asks for events by sequence number and gets them in order;
//! when the stream no longer holds the one it asks for (it fell behind the
//! ring, or the daemon restarted) — and on its very first request — it gets
//! a [`Notice::Resync`] instead: list the state again (`ca/list-approvals`,
//! `security/enroll-status`, `security/identity-status`, `ca/invite-list`,
//! `links/list`, …), then keep following from the number it carries.
//! Events only say what changed, by identifier and state; anything more is
//! read through those (gated) verbs.
//!
//! A long-poll holds its [`MgmtClient`]'s receive lock, so a subscription
//! uses a management connection of its own
//! ([`EventSubscription::connect`]), not the one commands go over:
//!
//! ```no_run
//! # async fn run(socket: &str) -> Result<(), ndn_ipc::ForwarderError> {
//! use ndn_ipc::events::{EventSubscription, Notice};
//! use ndn_cert::report::TrustEvent;
//! use std::time::Duration;
//!
//! let mut trust = EventSubscription::<TrustEvent>::connect(socket).await?;
//! loop {
//!     match trust.next(Duration::from_secs(30)).await? {
//!         None => continue, // nothing happened; ask again
//!         Some(Notice::Resync { .. }) => { /* list the state again */ }
//!         Some(Notice::Event { event, .. }) => { /* apply it */ let _ = event; }
//!     }
//! }
//! # }
//! ```

use std::marker::PhantomData;
use std::time::Duration;

use ndn_cert::report::TrustEvent;
use ndn_mgmt_wire::events::{LINKS_STREAM, LinkEvent, RESYNC_KIND, TRUST_STREAM};
use serde::de::DeserializeOwned;

use crate::forwarder_client::ForwarderError;
use crate::mgmt_client::MgmtClient;

/// An event type with its stream.
pub trait StreamEvent: DeserializeOwned {
    /// The stream's module: `/localhost/nfd/<module>/notifications`.
    const MODULE: &'static [u8];
}

impl StreamEvent for TrustEvent {
    const MODULE: &'static [u8] = TRUST_STREAM;
}

impl StreamEvent for LinkEvent {
    const MODULE: &'static [u8] = LINKS_STREAM;
}

/// What a stream answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Notice<E> {
    /// Event number `seq`. An event of a kind this client does not know is
    /// the event type's `Unknown`: skip it.
    Event { seq: u64, event: E },
    /// The stream does not hold the event asked for (or this was the first
    /// request): list the state again, then continue at `next`.
    Resync { next: u64 },
}

/// Parse the content of event number `seq`.
pub fn parse_notice<E: DeserializeOwned>(
    seq: u64,
    content: &[u8],
) -> Result<Notice<E>, ForwarderError> {
    let value: serde_json::Value =
        serde_json::from_slice(content).map_err(|_| ForwarderError::MalformedResponse)?;
    if value.get("kind").and_then(serde_json::Value::as_str) == Some(RESYNC_KIND) {
        let next = value
            .get("next")
            .and_then(serde_json::Value::as_u64)
            .ok_or(ForwarderError::MalformedResponse)?;
        return Ok(Notice::Resync { next });
    }
    let event = serde_json::from_value(value).map_err(|_| ForwarderError::MalformedResponse)?;
    Ok(Notice::Event { seq, event })
}

impl MgmtClient {
    /// Event number `seq` of `E`'s stream, waiting up to `timeout` for it
    /// to happen; `Ok(None)` when it did not (ask again). Holds this
    /// client's receive lock meanwhile — see [`EventSubscription`].
    pub async fn event<E: StreamEvent>(
        &self,
        seq: u64,
        timeout: Duration,
    ) -> Result<Option<Notice<E>>, ForwarderError> {
        let module = String::from_utf8_lossy(E::MODULE);
        match self.notification(&module, Some(seq), timeout).await? {
            None => Ok(None),
            Some((got, content)) => parse_notice(got, &content).map(Some),
        }
    }

    /// [`event`](Self::event) of the trust stream.
    pub async fn trust_event(
        &self,
        seq: u64,
        timeout: Duration,
    ) -> Result<Option<Notice<TrustEvent>>, ForwarderError> {
        self.event(seq, timeout).await
    }

    /// [`event`](Self::event) of the links stream.
    pub async fn link_event(
        &self,
        seq: u64,
        timeout: Duration,
    ) -> Result<Option<Notice<LinkEvent>>, ForwarderError> {
        self.event(seq, timeout).await
    }
}

/// Following one stream in order on a management connection of its own.
pub struct EventSubscription<E> {
    client: MgmtClient,
    next: u64,
    _event: PhantomData<fn() -> E>,
}

impl<E: StreamEvent> EventSubscription<E> {
    /// Open a connection of its own to the daemon's management socket. The
    /// first notice is a [`Notice::Resync`]: list, then follow.
    pub async fn connect(face_socket: impl AsRef<str>) -> Result<Self, ForwarderError> {
        Ok(Self::resume(MgmtClient::connect(face_socket).await?, 0))
    }

    /// Follow from event number `next` on `client` (which then serves only
    /// this subscription). `0`: from a resync.
    pub fn resume(client: MgmtClient, next: u64) -> Self {
        Self {
            client,
            next,
            _event: PhantomData,
        }
    }

    /// The number of the event asked for next.
    pub fn next_seq(&self) -> u64 {
        self.next
    }

    /// The next notice, waiting up to `timeout`; `Ok(None)` when nothing
    /// happened meanwhile.
    pub async fn next(&mut self, timeout: Duration) -> Result<Option<Notice<E>>, ForwarderError> {
        let notice = self.client.event::<E>(self.next, timeout).await?;
        match &notice {
            Some(Notice::Event { seq, .. }) => self.next = seq + 1,
            Some(Notice::Resync { next }) => self.next = *next,
            None => {}
        }
        Ok(notice)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_cert::report::Decision;

    #[test]
    fn resync_events_and_unknown_kinds_parse() {
        let resync: Notice<TrustEvent> =
            parse_notice(7, br#"{"kind":"resync","next":42}"#).unwrap();
        assert_eq!(resync, Notice::Resync { next: 42 });

        let event: Notice<TrustEvent> = parse_notice(
            9,
            br#"{"kind":"approval-decided","ca":"/a/CA","request":"r","decision":"denied"}"#,
        )
        .unwrap();
        assert_eq!(
            event,
            Notice::Event {
                seq: 9,
                event: TrustEvent::ApprovalDecided {
                    ca: "/a/CA".into(),
                    request: "r".into(),
                    decision: Decision::Denied,
                },
            }
        );

        let later: Notice<LinkEvent> = parse_notice(3, br#"{"kind":"link-renamed"}"#).unwrap();
        assert_eq!(
            later,
            Notice::Event {
                seq: 3,
                event: LinkEvent::Unknown
            }
        );

        assert!(parse_notice::<TrustEvent>(1, b"not json").is_err());
    }
}
