/// NFD Management ControlResponse TLV encoding and decoding.
///
/// ControlResponse (TLV type 0x65) carries the result of a management command.
/// It contains a StatusCode (HTTP-style), StatusText, and an optional body
/// (typically the echoed ControlParameters on success).
///
/// Wire format follows the NFD Management Protocol specification:
/// <https://redmine.named-data.net/projects/nfd/wiki/ControlCommand>
use bytes::Bytes;
use ndn_tlv::{TlvReader, TlvWriter};

use crate::control_parameters::ControlParameters;

// ─── TLV type constants ──────────────────────────────────────────────────────

pub mod tlv {
    pub const CONTROL_RESPONSE: u64 = 0x65;
    pub const STATUS_CODE:      u64 = 0x66;
    pub const STATUS_TEXT:       u64 = 0x67;
}

// ─── Status codes ────────────────────────────────────────────────────────────

pub mod status {
    pub const OK:            u64 = 200;
    pub const BAD_PARAMS:    u64 = 400;
    pub const UNAUTHORIZED:  u64 = 403;
    pub const NOT_FOUND:     u64 = 404;
    pub const CONFLICT:      u64 = 409;
    pub const SERVER_ERROR:  u64 = 500;
}

// ─── ControlResponse ─────────────────────────────────────────────────────────

/// NFD ControlResponse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlResponse {
    pub status_code: u64,
    pub status_text: String,
    /// Optional body — typically echoed ControlParameters on success.
    pub body: Option<ControlParameters>,
}

impl ControlResponse {
    /// Create a 200 OK response with echoed parameters.
    pub fn ok(text: impl Into<String>, body: ControlParameters) -> Self {
        Self {
            status_code: status::OK,
            status_text: text.into(),
            body: Some(body),
        }
    }

    /// Create a 200 OK response with no body.
    pub fn ok_empty(text: impl Into<String>) -> Self {
        Self {
            status_code: status::OK,
            status_text: text.into(),
            body: None,
        }
    }

    /// Create an error response.
    pub fn error(code: u64, text: impl Into<String>) -> Self {
        Self {
            status_code: code,
            status_text: text.into(),
            body: None,
        }
    }

    /// Whether the response indicates success (2xx).
    pub fn is_ok(&self) -> bool {
        (200..300).contains(&self.status_code)
    }

    /// Encode to wire format as a complete ControlResponse TLV (type 0x65).
    pub fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(tlv::CONTROL_RESPONSE, |w| {
            write_non_neg_int(w, tlv::STATUS_CODE, self.status_code);
            w.write_tlv(tlv::STATUS_TEXT, self.status_text.as_bytes());
            if let Some(ref body) = self.body {
                // Encode ControlParameters inline (with outer 0x68 wrapper).
                let body_bytes = body.encode();
                w.write_raw(&body_bytes);
            }
        });
        w.finish()
    }

    /// Decode from a complete ControlResponse TLV (type 0x65).
    pub fn decode(wire: Bytes) -> Result<Self, ControlResponseError> {
        let mut r = TlvReader::new(wire);
        let (typ, value) = r.read_tlv()
            .map_err(|_| ControlResponseError::MalformedTlv)?;
        if typ != tlv::CONTROL_RESPONSE {
            return Err(ControlResponseError::WrongType(typ));
        }
        Self::decode_value(value)
    }

    /// Decode from the inner value bytes (without the outer 0x65 wrapper).
    pub fn decode_value(value: Bytes) -> Result<Self, ControlResponseError> {
        let mut r = TlvReader::new(value);
        let mut status_code = None;
        let mut status_text = None;
        let mut body = None;

        while !r.is_empty() {
            let (typ, val) = r.read_tlv()
                .map_err(|_| ControlResponseError::MalformedTlv)?;
            match typ {
                tlv::STATUS_CODE => {
                    status_code = Some(read_non_neg_int(&val)?);
                }
                tlv::STATUS_TEXT => {
                    status_text = Some(
                        std::str::from_utf8(&val)
                            .map_err(|_| ControlResponseError::InvalidUtf8)?
                            .to_owned(),
                    );
                }
                crate::control_parameters::tlv::CONTROL_PARAMETERS => {
                    body = Some(
                        ControlParameters::decode_value(val)
                            .map_err(|_| ControlResponseError::MalformedTlv)?,
                    );
                }
                _ => {} // skip unknown
            }
        }

        Ok(ControlResponse {
            status_code: status_code.ok_or(ControlResponseError::MissingField("StatusCode"))?,
            status_text: status_text.ok_or(ControlResponseError::MissingField("StatusText"))?,
            body,
        })
    }
}

// ─── Errors ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ControlResponseError {
    #[error("malformed TLV")]
    MalformedTlv,
    #[error("unexpected TLV type {0:#x}")]
    WrongType(u64),
    #[error("invalid NonNegativeInteger length")]
    InvalidNonNegInt,
    #[error("invalid UTF-8 in string field")]
    InvalidUtf8,
    #[error("missing required field: {0}")]
    MissingField(&'static str),
}

// ─── NonNegativeInteger helpers ──────────────────────────────────────────────

fn encode_non_neg_int(value: u64) -> Vec<u8> {
    if value <= 0xFF {
        vec![value as u8]
    } else if value <= 0xFFFF {
        (value as u16).to_be_bytes().to_vec()
    } else if value <= 0xFFFF_FFFF {
        (value as u32).to_be_bytes().to_vec()
    } else {
        value.to_be_bytes().to_vec()
    }
}

fn write_non_neg_int(w: &mut TlvWriter, typ: u64, value: u64) {
    w.write_tlv(typ, &encode_non_neg_int(value));
}

fn read_non_neg_int(buf: &[u8]) -> Result<u64, ControlResponseError> {
    match buf.len() {
        1 => Ok(buf[0] as u64),
        2 => Ok(u16::from_be_bytes([buf[0], buf[1]]) as u64),
        4 => Ok(u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as u64),
        8 => Ok(u64::from_be_bytes([
            buf[0], buf[1], buf[2], buf[3],
            buf[4], buf[5], buf[6], buf[7],
        ])),
        _ => Err(ControlResponseError::InvalidNonNegInt),
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_parameters::ControlParameters;
    use ndn_packet::{Name, NameComponent};

    fn name(components: &[&[u8]]) -> Name {
        Name::from_components(
            components.iter().map(|c| NameComponent::generic(Bytes::copy_from_slice(c)))
        )
    }

    #[test]
    fn encode_decode_ok_empty() {
        let resp = ControlResponse::ok_empty("OK");
        let wire = resp.encode();
        let decoded = ControlResponse::decode(wire).unwrap();
        assert_eq!(decoded.status_code, 200);
        assert_eq!(decoded.status_text, "OK");
        assert!(decoded.body.is_none());
        assert!(decoded.is_ok());
    }

    #[test]
    fn encode_decode_ok_with_body() {
        let params = ControlParameters {
            name: Some(name(&[b"ndn", b"test"])),
            face_id: Some(5),
            cost: Some(10),
            ..Default::default()
        };
        let resp = ControlResponse::ok("OK", params.clone());
        let wire = resp.encode();
        let decoded = ControlResponse::decode(wire).unwrap();
        assert_eq!(decoded.status_code, 200);
        assert_eq!(decoded.body, Some(params));
    }

    #[test]
    fn encode_decode_error() {
        let resp = ControlResponse::error(status::NOT_FOUND, "face not found");
        let wire = resp.encode();
        let decoded = ControlResponse::decode(wire).unwrap();
        assert_eq!(decoded.status_code, 404);
        assert_eq!(decoded.status_text, "face not found");
        assert!(decoded.body.is_none());
        assert!(!decoded.is_ok());
    }

    #[test]
    fn decode_wrong_type_errors() {
        let mut w = TlvWriter::new();
        w.write_nested(0x05, |_| {});
        let result = ControlResponse::decode(w.finish());
        assert!(matches!(result, Err(ControlResponseError::WrongType(0x05))));
    }

    #[test]
    fn decode_missing_status_code_errors() {
        let mut w = TlvWriter::new();
        w.write_nested(tlv::CONTROL_RESPONSE, |w| {
            w.write_tlv(tlv::STATUS_TEXT, b"oops");
        });
        let result = ControlResponse::decode(w.finish());
        assert!(matches!(result, Err(ControlResponseError::MissingField("StatusCode"))));
    }

    #[test]
    fn status_code_ranges() {
        assert!(ControlResponse::ok_empty("OK").is_ok());
        assert!(!ControlResponse::error(400, "bad").is_ok());
        assert!(!ControlResponse::error(500, "err").is_ok());
    }
}
