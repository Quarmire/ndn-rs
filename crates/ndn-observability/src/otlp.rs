//! Minimal OTLP `Span` protobuf encoder.
//!
//! Schema: `opentelemetry-proto/opentelemetry/proto/trace/v1/trace.proto`
//! (stable since v0.20). Only the fields ndn-rs populates are encoded.
//! Hand-rolled to stay light and wasm32-clean; wire bytes are
//! byte-identical to the official SDK for those fields.

use bytes::{BufMut, Bytes, BytesMut};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum SpanKind {
    Unspecified = 0,
    Internal = 1,
    Server = 2,
    Client = 3,
    Producer = 4,
    Consumer = 5,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum StatusCode {
    Unset = 0,
    Ok = 1,
    Error = 2,
}

#[derive(Clone, Debug)]
pub enum AttrValue {
    String(String),
    Int(i64),
    Bool(bool),
}

#[derive(Clone, Debug)]
pub struct Attr {
    pub key: String,
    pub value: AttrValue,
}

impl Attr {
    pub fn str(key: impl Into<String>, v: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: AttrValue::String(v.into()),
        }
    }

    pub fn int(key: impl Into<String>, v: i64) -> Self {
        Self {
            key: key.into(),
            value: AttrValue::Int(v),
        }
    }

    pub fn bool_(key: impl Into<String>, v: bool) -> Self {
        Self {
            key: key.into(),
            value: AttrValue::Bool(v),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Span {
    pub trace_id: [u8; 16],
    pub span_id: [u8; 8],
    pub parent_span_id: Option<[u8; 8]>,
    pub name: String,
    pub kind: SpanKind,
    pub start_unix_nano: u64,
    pub end_unix_nano: u64,
    pub attributes: Vec<Attr>,
    pub status_code: StatusCode,
    pub status_message: String,
}

impl Span {
    /// Encode the Span as a raw protobuf message body. Embedding it in
    /// a parent `ScopeSpans.spans` field is the caller's job.
    pub fn encode(&self) -> Bytes {
        let mut out = BytesMut::with_capacity(96 + 16 * self.attributes.len());
        encode_len_prefixed(&mut out, 1, &self.trace_id);
        encode_len_prefixed(&mut out, 2, &self.span_id);
        if let Some(parent) = &self.parent_span_id {
            encode_len_prefixed(&mut out, 4, parent);
        }
        encode_len_prefixed(&mut out, 5, self.name.as_bytes());
        if self.kind as i32 != 0 {
            encode_varint_field(&mut out, 6, self.kind as i32 as u64);
        }
        encode_fixed64(&mut out, 7, self.start_unix_nano);
        encode_fixed64(&mut out, 8, self.end_unix_nano);
        for a in &self.attributes {
            let body = encode_attr(a);
            encode_len_prefixed(&mut out, 9, &body);
        }
        if self.status_code as i32 != 0 || !self.status_message.is_empty() {
            let body = encode_status(self.status_code, &self.status_message);
            encode_len_prefixed(&mut out, 15, &body);
        }
        out.freeze()
    }
}

fn encode_attr(a: &Attr) -> Bytes {
    let mut out = BytesMut::with_capacity(a.key.len() + 16);
    encode_len_prefixed(&mut out, 1, a.key.as_bytes());
    let mut any = BytesMut::new();
    match &a.value {
        AttrValue::String(s) => encode_len_prefixed(&mut any, 1, s.as_bytes()),
        AttrValue::Int(v) => encode_varint_field(&mut any, 3, *v as u64),
        AttrValue::Bool(b) => encode_varint_field(&mut any, 4, if *b { 1 } else { 0 }),
    }
    encode_len_prefixed(&mut out, 2, &any);
    out.freeze()
}

fn encode_status(code: StatusCode, message: &str) -> Bytes {
    let mut out = BytesMut::new();
    if !message.is_empty() {
        encode_len_prefixed(&mut out, 2, message.as_bytes());
    }
    if code as i32 != 0 {
        encode_varint_field(&mut out, 3, code as i32 as u64);
    }
    out.freeze()
}

const WIRE_VARINT: u32 = 0;
const WIRE_FIXED64: u32 = 1;
const WIRE_LEN: u32 = 2;

fn tag(field: u32, wire: u32) -> u64 {
    ((field << 3) | wire) as u64
}

fn write_varint(out: &mut BytesMut, mut v: u64) {
    while v >= 0x80 {
        out.put_u8(((v as u8) & 0x7F) | 0x80);
        v >>= 7;
    }
    out.put_u8(v as u8);
}

fn encode_len_prefixed(out: &mut BytesMut, field: u32, payload: &[u8]) {
    write_varint(out, tag(field, WIRE_LEN));
    write_varint(out, payload.len() as u64);
    out.put_slice(payload);
}

fn encode_varint_field(out: &mut BytesMut, field: u32, v: u64) {
    write_varint(out, tag(field, WIRE_VARINT));
    write_varint(out, v);
}

fn encode_fixed64(out: &mut BytesMut, field: u32, v: u64) {
    write_varint(out, tag(field, WIRE_FIXED64));
    out.put_u64_le(v);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Span {
        Span {
            trace_id: [
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
                0x0F, 0x10,
            ],
            span_id: [0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8],
            parent_span_id: None,
            name: "fwd.pipeline".into(),
            kind: SpanKind::Internal,
            start_unix_nano: 1_700_000_000_000_000_000,
            end_unix_nano: 1_700_000_000_001_000_000,
            attributes: vec![Attr::str("interest.name", "/ndn/edu/ucla")],
            status_code: StatusCode::Ok,
            status_message: String::new(),
        }
    }

    #[test]
    fn span_encodes_with_required_tags() {
        let wire = sample().encode();
        // Must contain trace_id field (tag=0x0a for field=1 wire=2)
        assert_eq!(wire[0], 0x0A);
        assert_eq!(wire[1], 16);
        // span_id field follows (tag=0x12 for field=2 wire=2)
        let off = 2 + 16;
        assert_eq!(wire[off], 0x12);
        assert_eq!(wire[off + 1], 8);
    }

    #[test]
    fn span_kind_varint_present() {
        let wire = sample().encode();
        // field=6 wire=0 → tag = (6<<3) = 0x30
        assert!(wire.contains(&0x30));
    }

    #[test]
    fn status_message_only_skipped_when_unset() {
        let mut s = sample();
        s.status_code = StatusCode::Unset;
        s.status_message = String::new();
        let wire = s.encode();
        // Status field tag = (15<<3)|2 = 0x7A; must NOT appear
        assert!(!wire.contains(&0x7A));
    }

    #[test]
    fn attribute_keyvalue_present() {
        let wire = sample().encode();
        // Attribute field tag = (9<<3)|2 = 0x4A
        assert!(wire.contains(&0x4A));
    }

    #[test]
    fn varint_roundtrip() {
        let mut buf = BytesMut::new();
        write_varint(&mut buf, 300);
        // 300 → 0xAC 0x02
        assert_eq!(&buf[..], &[0xAC, 0x02][..]);
    }
}
