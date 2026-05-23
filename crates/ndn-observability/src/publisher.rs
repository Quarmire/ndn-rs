//! Keyed cache of OTLP `Span` Data wires, served under a configurable
//! NDN prefix as a long-lived in-process Producer.
//!
//! Wire shape: `<prefix>/traces/<trace-id-hex>/spans/<span-id-hex>`
//! where `<prefix>` is operator-configured (e.g.
//! `/localhost/nfd/observability`), trace-id is 32 hex chars (16 bytes,
//! W3C), span-id is 16 hex chars.
//!
//! Recent spans live in a bounded ring per [`SpanRetention`]; older
//! spans drop out and Interests for them go unanswered. Operators who
//! want longer retention layer a persistent CS over the same prefix.

use std::sync::Arc;

use bytes::Bytes;
use ndn_engine::ForwarderEngine;
use ndn_packet::encode::encode_data_unsigned;
use ndn_packet::{Interest, Name, NameComponent};
use parking_lot::Mutex;
use tokio_util::sync::CancellationToken;

use crate::otlp::Span;

/// FIFO eviction bounds for the publisher's in-memory span cache.
/// A persistent CS over the same prefix extends the effective window.
#[derive(Clone, Debug)]
pub struct SpanRetention {
    /// Max age of a cached span (default 1 hour).
    pub window: std::time::Duration,
    /// Soft byte cap on the ring (default 8 MiB).
    pub max_bytes: u64,
    /// Hard cap on span count (default 10_000); trips before `max_bytes`
    /// when individual spans are tiny.
    pub max_spans: usize,
}

impl Default for SpanRetention {
    fn default() -> Self {
        Self {
            window: std::time::Duration::from_secs(60 * 60),
            max_bytes: 8 * 1024 * 1024,
            max_spans: 10_000,
        }
    }
}

#[derive(Clone)]
struct CachedSpan {
    trace_id: [u8; 16],
    span_id: [u8; 8],
    data_wire: Bytes,
    inserted: web_time::Instant,
    bytes_len: u64,
}

pub struct SpanPublisher {
    prefix: Name,
    retention: SpanRetention,
    ring: Mutex<std::collections::VecDeque<CachedSpan>>,
    total_bytes: Mutex<u64>,
}

impl SpanPublisher {
    /// The producer is not mounted until [`Self::install`].
    pub fn new(prefix: Name, retention: SpanRetention) -> Arc<Self> {
        Arc::new(Self {
            prefix,
            retention,
            ring: Mutex::new(std::collections::VecDeque::new()),
            total_bytes: Mutex::new(0),
        })
    }

    pub fn prefix(&self) -> &Name {
        &self.prefix
    }

    /// Encode `span` as OTLP protobuf, wrap it in a DigestSha256 Data
    /// named per the wire shape, and insert into the ring. The Data is
    /// immediately fetchable; eviction applies per [`SpanRetention`].
    pub fn publish(&self, span: &Span) {
        let body = span.encode();
        let name = self.span_name(&span.trace_id, &span.span_id);
        let data_wire = encode_data_unsigned(&name, &body);
        let bytes_len = data_wire.len() as u64;

        let mut ring = self.ring.lock();
        let mut total = self.total_bytes.lock();
        ring.push_back(CachedSpan {
            trace_id: span.trace_id,
            span_id: span.span_id,
            data_wire,
            inserted: web_time::Instant::now(),
            bytes_len,
        });
        *total += bytes_len;

        let now = web_time::Instant::now();
        while let Some(front) = ring.front() {
            let too_old = now.duration_since(front.inserted) > self.retention.window;
            let over_bytes = *total > self.retention.max_bytes;
            let over_count = ring.len() > self.retention.max_spans;
            if !(too_old || over_bytes || over_count) {
                break;
            }
            let evicted = ring.pop_front().expect("ring not empty");
            *total = total.saturating_sub(evicted.bytes_len);
        }
    }

    pub fn len(&self) -> usize {
        self.ring.lock().len()
    }

    /// Cached `(trace_id, span_id)` pairs, newest first. Used to drive
    /// the `<prefix>/recent` enumeration (newline-separated
    /// `<trace-id-hex>/<span-id-hex>` lines, lowercase hex).
    pub fn recent_span_ids(&self, limit: usize) -> Vec<([u8; 16], [u8; 8])> {
        self.ring
            .lock()
            .iter()
            .rev()
            .take(limit)
            .map(|s| (s.trace_id, s.span_id))
            .collect()
    }

    pub fn is_empty(&self) -> bool {
        self.ring.lock().is_empty()
    }

    /// Most recently published span Data wire, if any.
    pub fn latest_wire(&self) -> Option<Bytes> {
        self.ring.lock().back().map(|s| s.data_wire.clone())
    }

    pub fn lookup(&self, trace_id: &[u8; 16], span_id: &[u8; 8]) -> Option<Bytes> {
        self.ring
            .lock()
            .iter()
            .rev()
            .find(|s| s.trace_id == *trace_id && s.span_id == *span_id)
            .map(|s| s.data_wire.clone())
    }

    pub fn span_name(&self, trace_id: &[u8; 16], span_id: &[u8; 8]) -> Name {
        let mut name = self.prefix.clone();
        name = name.append_component(NameComponent::generic(Bytes::from_static(b"traces")));
        name = name.append_component(NameComponent::generic(Bytes::from(hex_lower(trace_id))));
        name = name.append_component(NameComponent::generic(Bytes::from_static(b"spans")));
        name = name.append_component(NameComponent::generic(Bytes::from(hex_lower(span_id))));
        name
    }

    /// Decode `(trace_id, span_id)` from an Interest name matching the
    /// publisher's wire shape. Returns `None` for any other name.
    pub fn parse_name(&self, interest_name: &Name) -> Option<([u8; 16], [u8; 8])> {
        let prefix_comps = self.prefix.components();
        let comps = interest_name.components();
        let pref_len = prefix_comps.len();
        if comps.len() < pref_len + 4 {
            return None;
        }
        for (i, want) in prefix_comps.iter().enumerate() {
            if comps[i].value != want.value || comps[i].typ != want.typ {
                return None;
            }
        }
        let tail = &comps[pref_len..];
        if tail[0].value.as_ref() != b"traces" {
            return None;
        }
        if tail[2].value.as_ref() != b"spans" {
            return None;
        }
        let trace_hex = std::str::from_utf8(tail[1].value.as_ref()).ok()?;
        let span_hex = std::str::from_utf8(tail[3].value.as_ref()).ok()?;
        let trace = decode_hex_16(trace_hex)?;
        let span = decode_hex_8(span_hex)?;
        Some((trace, span))
    }

    /// Allocate an internal in-process face, register the prefix in
    /// the FIB, and spawn the serve loop that turns Interests into
    /// cached Data wires.
    pub fn install(self: Arc<Self>, engine: &ForwarderEngine, cancel: CancellationToken) {
        use ndn_engine::FibNexthop;
        let face_id = engine.faces().alloc_id();
        let (face, handle) = ndn_face_local::InProcFace::new_kind(
            face_id,
            64,
            ndn_transport::face::FaceKind::Internal,
        );
        engine.add_face(face, cancel.child_token());
        engine
            .fib()
            .set_nexthops(&self.prefix, vec![FibNexthop { face_id, cost: 0 }]);

        let pub_ = self;
        let task_cancel = cancel.clone();
        tokio::spawn(async move {
            serve(pub_, handle, task_cancel).await;
        });
    }
}

/// Max `(trace_id, span_id)` pairs per `/recent` enumeration; chosen
/// to keep response Data under typical MTU.
const RECENT_ENUM_LIMIT: usize = 256;

async fn serve(
    publisher: Arc<SpanPublisher>,
    handle: ndn_face_local::InProcHandle,
    cancel: CancellationToken,
) {
    loop {
        let tagged = tokio::select! {
            _ = cancel.cancelled() => break,
            r = handle.recv_tagged() => match r {
                Some(t) => t,
                None    => break,
            },
        };
        let Ok(interest) = Interest::decode(tagged.wire) else {
            continue;
        };
        if is_recent_query(&publisher.prefix, &interest.name) {
            let body = encode_recent(&publisher.recent_span_ids(RECENT_ENUM_LIMIT));
            let data = encode_data_unsigned(&interest.name, &body);
            let _ = handle.send(data).await;
            continue;
        }
        let Some((trace_id, span_id)) = publisher.parse_name(&interest.name) else {
            continue;
        };
        if let Some(wire) = publisher.lookup(&trace_id, &span_id) {
            let _ = handle.send(wire).await;
        }
    }
}

fn is_recent_query(prefix: &Name, interest_name: &Name) -> bool {
    let pref_len = prefix.components().len();
    let comps = interest_name.components();
    comps.len() == pref_len + 1
        && comps
            .iter()
            .take(pref_len)
            .zip(prefix.components().iter())
            .all(|(a, b)| a.value == b.value && a.typ == b.typ)
        && comps[pref_len].value.as_ref() == b"recent"
}

fn encode_recent(pairs: &[([u8; 16], [u8; 8])]) -> Bytes {
    let mut out = String::with_capacity(pairs.len() * 50);
    for (trace, span) in pairs {
        for b in trace {
            out.push_str(&format!("{:02x}", b));
        }
        out.push('/');
        for b in span {
            out.push_str(&format!("{:02x}", b));
        }
        out.push('\n');
    }
    Bytes::from(out.into_bytes())
}

fn hex_lower(bytes: &[u8]) -> Vec<u8> {
    let lut = b"0123456789abcdef";
    let mut out = Vec::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(lut[(b >> 4) as usize]);
        out.push(lut[(b & 0x0F) as usize]);
    }
    out
}

fn decode_hex_16(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn decode_hex_8(s: &str) -> Option<[u8; 8]> {
    if s.len() != 16 {
        return None;
    }
    let mut out = [0u8; 8];
    for i in 0..8 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::otlp::{Span, SpanKind, StatusCode};

    fn sample_span(trace: u8, sp: u8) -> Span {
        Span {
            trace_id: [trace; 16],
            span_id: [sp; 8],
            parent_span_id: None,
            name: "fwd.pipeline".into(),
            kind: SpanKind::Internal,
            start_unix_nano: 1,
            end_unix_nano: 2,
            attributes: vec![],
            status_code: StatusCode::Ok,
            status_message: String::new(),
        }
    }

    #[test]
    fn publish_then_lookup_roundtrip() {
        let prefix = Name::from_components([NameComponent::generic(Bytes::from_static(
            b"obs",
        ))]);
        let pub_ = SpanPublisher::new(prefix.clone(), SpanRetention::default());
        let span = sample_span(0xAA, 0xBB);
        pub_.publish(&span);
        let wire = pub_
            .lookup(&[0xAA; 16], &[0xBB; 8])
            .expect("cached span lookup");
        assert!(!wire.is_empty());
    }

    #[test]
    fn name_round_trips_through_parse() {
        let prefix = Name::from_components([NameComponent::generic(Bytes::from_static(b"obs"))]);
        let pub_ = SpanPublisher::new(prefix, SpanRetention::default());
        let n = pub_.span_name(&[0x11; 16], &[0x22; 8]);
        let (t, s) = pub_.parse_name(&n).expect("parse own name");
        assert_eq!(t, [0x11; 16]);
        assert_eq!(s, [0x22; 8]);
    }

    #[test]
    fn retention_evicts_old_by_count() {
        let prefix = Name::from_components([NameComponent::generic(Bytes::from_static(b"obs"))]);
        let pub_ = SpanPublisher::new(
            prefix,
            SpanRetention {
                window: std::time::Duration::from_secs(60),
                max_bytes: u64::MAX,
                max_spans: 3,
            },
        );
        for i in 0..5 {
            pub_.publish(&sample_span(0xAA, i as u8));
        }
        assert_eq!(pub_.len(), 3);
        assert!(pub_.lookup(&[0xAA; 16], &[0; 8]).is_none());
        assert!(pub_.lookup(&[0xAA; 16], &[4; 8]).is_some());
    }

    #[test]
    fn retention_evicts_by_byte_cap() {
        let prefix = Name::from_components([NameComponent::generic(Bytes::from_static(b"obs"))]);
        let pub_ = SpanPublisher::new(
            prefix,
            SpanRetention {
                window: std::time::Duration::from_secs(60),
                max_bytes: 200,
                max_spans: 10_000,
            },
        );
        for i in 0..20 {
            pub_.publish(&sample_span(0xAA, i as u8));
        }
        assert!(pub_.len() < 20);
    }

    #[test]
    fn parse_name_rejects_wrong_prefix() {
        let prefix = Name::from_components([NameComponent::generic(Bytes::from_static(b"obs"))]);
        let pub_ = SpanPublisher::new(prefix, SpanRetention::default());
        let bogus = Name::from_components([
            NameComponent::generic(Bytes::from_static(b"different")),
            NameComponent::generic(Bytes::from_static(b"traces")),
            NameComponent::generic(Bytes::from(hex_lower(&[0; 16]))),
            NameComponent::generic(Bytes::from_static(b"spans")),
            NameComponent::generic(Bytes::from(hex_lower(&[0; 8]))),
        ]);
        assert!(pub_.parse_name(&bogus).is_none());
    }
}
