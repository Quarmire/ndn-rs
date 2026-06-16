//! NFD-style management notification streams. Publishes events on
//! `/localhost/nfd/<module>/notifications/<seq>` where each
//! notification is a Data packet whose Content carries a TLV-encoded
//! event payload (e.g. `FaceEventNotification`). Reference: ndn-cxx
//! `mgmt/dispatcher.cpp:299-329`.
//!
//! Publishing primitive only; wiring to event sources lives in the
//! management dispatcher.

use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use ndn_packet::{Name, encode::DataBuilder};

/// Each [`publish`] call increments the sequence counter and emits a
/// self-signed Data on `<prefix>/<seq>` with the event payload as
/// Content.
pub struct NotificationStream {
    prefix: Name,
    next_seq: AtomicU64,
}

impl NotificationStream {
    /// `base` is the module root (e.g. `/localhost/nfd/faces`); the
    /// stream prefix becomes `<base>/notifications`.
    pub fn new(base: Name) -> Self {
        let prefix = base.append("notifications");
        Self {
            prefix,
            next_seq: AtomicU64::new(0),
        }
    }

    pub fn prefix(&self) -> &Name {
        &self.prefix
    }

    /// Allocate the next sequence without publishing — for callers
    /// that build the Data name themselves.
    pub fn alloc_sequence(&self) -> u64 {
        self.next_seq.fetch_add(1, Ordering::Relaxed)
    }

    /// Returns `(notification_name, wire)`. The wire is a `DigestSha256`
    /// Data. Sequence numbers use `SequenceNumberComponent`
    /// (TLV 0x3A) per ndn-cxx `dispatcher.cpp:324`.
    pub fn publish(&self, payload: &[u8]) -> (Name, Bytes) {
        let seq = self.alloc_sequence();
        let name = self.prefix.clone().append_sequence_num(seq);
        let wire = DataBuilder::new(name.clone(), payload).build();
        (name, wire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_packet::{Data, tlv_type};

    #[test]
    fn stream_prefix_appends_notifications_segment() {
        let base: Name = "/localhost/nfd/faces".parse().unwrap();
        let s = NotificationStream::new(base);
        assert_eq!(s.prefix().to_string(), "/localhost/nfd/faces/notifications");
    }

    #[test]
    fn publish_increments_sequence_per_call() {
        let base: Name = "/localhost/nfd/faces".parse().unwrap();
        let s = NotificationStream::new(base);
        let (n0, _) = s.publish(b"event-0");
        let (n1, _) = s.publish(b"event-1");
        let (n2, _) = s.publish(b"event-2");

        let last0 = n0.components().last().expect("last component");
        let last1 = n1.components().last().expect("last component");
        let last2 = n2.components().last().expect("last component");

        assert_eq!(last0.typ, tlv_type::SEQUENCE_NUM);
        assert_eq!(last1.typ, tlv_type::SEQUENCE_NUM);
        assert_eq!(last2.typ, tlv_type::SEQUENCE_NUM);

        assert_eq!(last0.value.as_ref(), &[0u8]);
        assert_eq!(last1.value.as_ref(), &[1u8]);
        assert_eq!(last2.value.as_ref(), &[2u8]);
    }

    #[test]
    fn published_wire_decodes_with_payload() {
        let base: Name = "/localhost/nfd/rib".parse().unwrap();
        let s = NotificationStream::new(base);
        let payload: &[u8] = b"route-added:/example/foo:42";
        let (notif_name, wire) = s.publish(payload);

        let data = Data::decode(wire).expect("notification must decode");
        assert_eq!(*data.name, notif_name);
        assert_eq!(data.content().map(|b| b.as_ref()), Some(payload));
    }
}
