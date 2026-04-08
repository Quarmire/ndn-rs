//! NDNCERT 0.3 TLV wire format.
//!
//! Replaces the Phase 1A/1B JSON encoding with full NDN TLV for complete
//! interoperability with the reference C++ implementation
//! (`ndncert-ca-server` / `ndncert-client`).
//!
//! # Type assignments (NDNCERT 0.3)
//!
//! ```text
//! ca-prefix          0x81 (129)
//! ca-info            0x83 (131)
//! parameter-key      0x85 (133)
//! parameter-value    0x87 (135)
//! ca-certificate     0x89 (137)
//! max-validity       0x8B (139)
//! probe-response     0x8D (141)
//! max-suffix-length  0x8F (143)
//! ecdh-pub           0x91 (145)
//! cert-request       0x93 (147)
//! salt               0x95 (149)
//! request-id         0x97 (151)
//! challenge          0x99 (153)
//! status             0x9B (155)
//! iv                 0x9D (157)
//! encrypted-payload  0x9F (159)
//! selected-challenge 0xA1 (161)
//! challenge-status   0xA3 (163)
//! remaining-tries    0xA5 (165)
//! remaining-time     0xA7 (167)
//! issued-cert-name   0xA9 (169)
//! error-code         0xAB (171)
//! error-info         0xAD (173)
//! auth-tag           0xAF (175)
//! ```

use bytes::Bytes;
use ndn_tlv::{TlvReader, TlvWriter};

use crate::error::CertError;

// ── TLV type constants ────────────────────────────────────────────────────────

pub const TLV_CA_PREFIX: u64 = 0x81;
pub const TLV_CA_INFO: u64 = 0x83;
pub const TLV_PARAMETER_KEY: u64 = 0x85;
pub const TLV_PARAMETER_VALUE: u64 = 0x87;
pub const TLV_CA_CERTIFICATE: u64 = 0x89;
pub const TLV_MAX_VALIDITY: u64 = 0x8B;
pub const TLV_PROBE_RESPONSE: u64 = 0x8D;
pub const TLV_MAX_SUFFIX_LENGTH: u64 = 0x8F;
pub const TLV_ECDH_PUB: u64 = 0x91;
pub const TLV_CERT_REQUEST: u64 = 0x93;
pub const TLV_SALT: u64 = 0x95;
pub const TLV_REQUEST_ID: u64 = 0x97;
pub const TLV_CHALLENGE: u64 = 0x99;
pub const TLV_STATUS: u64 = 0x9B;
pub const TLV_IV: u64 = 0x9D;
pub const TLV_ENCRYPTED_PAYLOAD: u64 = 0x9F;
pub const TLV_SELECTED_CHALLENGE: u64 = 0xA1;
pub const TLV_CHALLENGE_STATUS: u64 = 0xA3;
pub const TLV_REMAINING_TRIES: u64 = 0xA5;
pub const TLV_REMAINING_TIME: u64 = 0xA7;
pub const TLV_ISSUED_CERT_NAME: u64 = 0xA9;
pub const TLV_ERROR_CODE: u64 = 0xAB;
pub const TLV_ERROR_INFO: u64 = 0xAD;
pub const TLV_AUTH_TAG: u64 = 0xAF;

// ── TLV-encoded protocol messages ─────────────────────────────────────────────

/// TLV-encoded CA profile (content of `/<ca>/CA/INFO` Data packet).
pub struct CaProfileTlv {
    pub ca_prefix: String,
    pub ca_info: String,
    pub ca_certificate: Bytes,
    pub max_validity_secs: u64,
    pub challenges: Vec<String>,
}

impl CaProfileTlv {
    pub fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_tlv(TLV_CA_PREFIX, self.ca_prefix.as_bytes());
        w.write_tlv(TLV_CA_INFO, self.ca_info.as_bytes());
        w.write_tlv(TLV_CA_CERTIFICATE, &self.ca_certificate);
        w.write_tlv(TLV_MAX_VALIDITY, &self.max_validity_secs.to_be_bytes());
        for challenge in &self.challenges {
            w.write_tlv(TLV_CHALLENGE, challenge.as_bytes());
        }
        w.finish()
    }

    pub fn decode(buf: Bytes) -> Result<Self, CertError> {
        let mut r = TlvReader::new(buf);
        let mut ca_prefix = None;
        let mut ca_info = None;
        let mut ca_certificate = Bytes::new();
        let mut max_validity_secs = 86400u64;
        let mut challenges = Vec::new();

        while !r.is_empty() {
            let (typ, val) = r
                .read_tlv()
                .map_err(|e| CertError::InvalidRequest(format!("TLV parse error: {e}")))?;
            match typ {
                TLV_CA_PREFIX => {
                    ca_prefix = Some(
                        std::str::from_utf8(&val)
                            .map_err(|_| CertError::InvalidRequest("invalid ca-prefix UTF-8".into()))?
                            .to_string(),
                    );
                }
                TLV_CA_INFO => {
                    ca_info = Some(
                        std::str::from_utf8(&val)
                            .map_err(|_| CertError::InvalidRequest("invalid ca-info UTF-8".into()))?
                            .to_string(),
                    );
                }
                TLV_CA_CERTIFICATE => {
                    ca_certificate = val;
                }
                TLV_MAX_VALIDITY => {
                    if val.len() >= 8 {
                        max_validity_secs = u64::from_be_bytes(val[..8].try_into().unwrap());
                    }
                }
                TLV_CHALLENGE => {
                    let s = std::str::from_utf8(&val)
                        .map_err(|_| CertError::InvalidRequest("invalid challenge UTF-8".into()))?
                        .to_string();
                    challenges.push(s);
                }
                _ => {} // unknown TLV — skip (forward compatibility)
            }
        }

        Ok(Self {
            ca_prefix: ca_prefix
                .ok_or_else(|| CertError::InvalidRequest("missing ca-prefix".into()))?,
            ca_info: ca_info.unwrap_or_default(),
            ca_certificate,
            max_validity_secs,
            challenges,
        })
    }
}

/// TLV-encoded NEW request (ApplicationParameters of `/<ca>/CA/NEW`).
///
/// Per NDNCERT 0.3 the request carries an ECDH ephemeral public key (65 bytes,
/// uncompressed P-256 point) instead of the raw Ed25519 public key from Phase 1A.
/// The cert request bytes (name + not-before + not-after + Ed25519 pubkey) are
/// nested under `TLV_CERT_REQUEST`.
pub struct NewRequestTlv {
    /// Uncompressed P-256 ephemeral public key (65 bytes).
    pub ecdh_pub: Bytes,
    /// DER/TLV-encoded self-signed certificate of the requester.
    pub cert_request: Bytes,
}

impl NewRequestTlv {
    pub fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_tlv(TLV_ECDH_PUB, &self.ecdh_pub);
        w.write_tlv(TLV_CERT_REQUEST, &self.cert_request);
        w.finish()
    }

    pub fn decode(buf: Bytes) -> Result<Self, CertError> {
        let mut r = TlvReader::new(buf);
        let mut ecdh_pub = None;
        let mut cert_request = None;

        while !r.is_empty() {
            let (typ, val) = r
                .read_tlv()
                .map_err(|e| CertError::InvalidRequest(format!("TLV parse error: {e}")))?;
            match typ {
                TLV_ECDH_PUB => ecdh_pub = Some(val),
                TLV_CERT_REQUEST => cert_request = Some(val),
                _ => {}
            }
        }

        Ok(Self {
            ecdh_pub: ecdh_pub
                .ok_or_else(|| CertError::InvalidRequest("missing ecdh-pub".into()))?,
            cert_request: cert_request
                .ok_or_else(|| CertError::InvalidRequest("missing cert-request".into()))?,
        })
    }
}

/// TLV-encoded NEW response.
pub struct NewResponseTlv {
    /// CA's ECDH ephemeral public key (65 bytes).
    pub ecdh_pub: Bytes,
    /// Random 32-byte salt for HKDF.
    pub salt: [u8; 32],
    /// 8-byte request identifier.
    pub request_id: [u8; 8],
    /// Supported challenge type names.
    pub challenges: Vec<String>,
}

impl NewResponseTlv {
    pub fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_tlv(TLV_ECDH_PUB, &self.ecdh_pub);
        w.write_tlv(TLV_SALT, &self.salt);
        w.write_tlv(TLV_REQUEST_ID, &self.request_id);
        for challenge in &self.challenges {
            w.write_tlv(TLV_CHALLENGE, challenge.as_bytes());
        }
        w.finish()
    }

    pub fn decode(buf: Bytes) -> Result<Self, CertError> {
        let mut r = TlvReader::new(buf);
        let mut ecdh_pub = None;
        let mut salt = None;
        let mut request_id = None;
        let mut challenges = Vec::new();

        while !r.is_empty() {
            let (typ, val) = r
                .read_tlv()
                .map_err(|e| CertError::InvalidRequest(format!("TLV parse error: {e}")))?;
            match typ {
                TLV_ECDH_PUB => ecdh_pub = Some(val),
                TLV_SALT => {
                    if val.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&val);
                        salt = Some(arr);
                    }
                }
                TLV_REQUEST_ID => {
                    if val.len() == 8 {
                        let mut arr = [0u8; 8];
                        arr.copy_from_slice(&val);
                        request_id = Some(arr);
                    }
                }
                TLV_CHALLENGE => {
                    if let Ok(s) = std::str::from_utf8(&val) {
                        challenges.push(s.to_string());
                    }
                }
                _ => {}
            }
        }

        Ok(Self {
            ecdh_pub: ecdh_pub
                .ok_or_else(|| CertError::InvalidRequest("missing ecdh-pub".into()))?,
            salt: salt.ok_or_else(|| CertError::InvalidRequest("missing salt".into()))?,
            request_id: request_id
                .ok_or_else(|| CertError::InvalidRequest("missing request-id".into()))?,
            challenges,
        })
    }
}

/// TLV-encoded CHALLENGE request (encrypted).
///
/// The `parameters` field from Phase 1B is replaced by an AES-GCM-128
/// ciphertext. The plaintext is the JSON-encoded parameters map.
pub struct ChallengeRequestTlv {
    /// 8-byte request identifier (must match NewResponse).
    pub request_id: [u8; 8],
    /// Selected challenge type name.
    pub selected_challenge: String,
    /// 12-byte AES-GCM initialization vector.
    pub iv: [u8; 12],
    /// AES-GCM-128 ciphertext of the JSON parameters.
    pub encrypted_payload: Bytes,
    /// 16-byte AES-GCM authentication tag.
    pub auth_tag: [u8; 16],
}

impl ChallengeRequestTlv {
    pub fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_tlv(TLV_REQUEST_ID, &self.request_id);
        w.write_tlv(TLV_SELECTED_CHALLENGE, self.selected_challenge.as_bytes());
        w.write_tlv(TLV_IV, &self.iv);
        w.write_tlv(TLV_ENCRYPTED_PAYLOAD, &self.encrypted_payload);
        w.write_tlv(TLV_AUTH_TAG, &self.auth_tag);
        w.finish()
    }

    pub fn decode(buf: Bytes) -> Result<Self, CertError> {
        let mut r = TlvReader::new(buf);
        let mut request_id = None;
        let mut selected_challenge = None;
        let mut iv = None;
        let mut encrypted_payload = None;
        let mut auth_tag = None;

        while !r.is_empty() {
            let (typ, val) = r
                .read_tlv()
                .map_err(|e| CertError::InvalidRequest(format!("TLV parse error: {e}")))?;
            match typ {
                TLV_REQUEST_ID => {
                    if val.len() == 8 {
                        let mut arr = [0u8; 8];
                        arr.copy_from_slice(&val);
                        request_id = Some(arr);
                    }
                }
                TLV_SELECTED_CHALLENGE => {
                    selected_challenge = Some(
                        std::str::from_utf8(&val)
                            .map_err(|_| {
                                CertError::InvalidRequest("invalid challenge type UTF-8".into())
                            })?
                            .to_string(),
                    );
                }
                TLV_IV => {
                    if val.len() == 12 {
                        let mut arr = [0u8; 12];
                        arr.copy_from_slice(&val);
                        iv = Some(arr);
                    }
                }
                TLV_ENCRYPTED_PAYLOAD => encrypted_payload = Some(val),
                TLV_AUTH_TAG => {
                    if val.len() == 16 {
                        let mut arr = [0u8; 16];
                        arr.copy_from_slice(&val);
                        auth_tag = Some(arr);
                    }
                }
                _ => {}
            }
        }

        Ok(Self {
            request_id: request_id
                .ok_or_else(|| CertError::InvalidRequest("missing request-id".into()))?,
            selected_challenge: selected_challenge
                .ok_or_else(|| CertError::InvalidRequest("missing selected-challenge".into()))?,
            iv: iv.ok_or_else(|| CertError::InvalidRequest("missing iv".into()))?,
            encrypted_payload: encrypted_payload
                .ok_or_else(|| CertError::InvalidRequest("missing encrypted-payload".into()))?,
            auth_tag: auth_tag
                .ok_or_else(|| CertError::InvalidRequest("missing auth-tag".into()))?,
        })
    }
}

/// TLV-encoded CHALLENGE response.
pub struct ChallengeResponseTlv {
    /// Numeric status code per NDNCERT 0.3 §3.3.
    pub status: u8,
    // Fields present on Processing status:
    pub challenge_status: Option<String>,
    pub remaining_tries: Option<u8>,
    pub remaining_time_secs: Option<u32>,
    // Fields present on Approved status:
    pub issued_cert_name: Option<String>,
    // Fields present on Denied status:
    pub error_code: Option<u8>,
    pub error_info: Option<String>,
    // Encrypted payload for processing status (challenge data):
    pub iv: Option<[u8; 12]>,
    pub encrypted_payload: Option<Bytes>,
    pub auth_tag: Option<[u8; 16]>,
}

/// Status codes per NDNCERT 0.3.
pub const STATUS_BEFORE_CHALLENGE: u8 = 0;
pub const STATUS_CHALLENGE: u8 = 1;
pub const STATUS_PENDING: u8 = 2;
pub const STATUS_SUCCESS: u8 = 3;
pub const STATUS_FAILURE: u8 = 4;

impl ChallengeResponseTlv {
    pub fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_tlv(TLV_STATUS, &[self.status]);

        if let Some(ref cs) = self.challenge_status {
            w.write_tlv(TLV_CHALLENGE_STATUS, cs.as_bytes());
        }
        if let Some(rt) = self.remaining_tries {
            w.write_tlv(TLV_REMAINING_TRIES, &[rt]);
        }
        if let Some(rt) = self.remaining_time_secs {
            w.write_tlv(TLV_REMAINING_TIME, &rt.to_be_bytes());
        }
        if let Some(ref cn) = self.issued_cert_name {
            w.write_tlv(TLV_ISSUED_CERT_NAME, cn.as_bytes());
        }
        if let Some(ec) = self.error_code {
            w.write_tlv(TLV_ERROR_CODE, &[ec]);
        }
        if let Some(ref ei) = self.error_info {
            w.write_tlv(TLV_ERROR_INFO, ei.as_bytes());
        }
        if let Some(ref iv) = self.iv {
            w.write_tlv(TLV_IV, iv);
        }
        if let Some(ref ep) = self.encrypted_payload {
            w.write_tlv(TLV_ENCRYPTED_PAYLOAD, ep);
        }
        if let Some(ref at) = self.auth_tag {
            w.write_tlv(TLV_AUTH_TAG, at);
        }
        w.finish()
    }

    pub fn decode(buf: Bytes) -> Result<Self, CertError> {
        let mut r = TlvReader::new(buf);
        let mut status = None;
        let mut challenge_status = None;
        let mut remaining_tries = None;
        let mut remaining_time_secs = None;
        let mut issued_cert_name = None;
        let mut error_code = None;
        let mut error_info = None;
        let mut iv = None;
        let mut encrypted_payload = None;
        let mut auth_tag = None;

        while !r.is_empty() {
            let (typ, val) = r
                .read_tlv()
                .map_err(|e| CertError::InvalidRequest(format!("TLV parse error: {e}")))?;
            match typ {
                TLV_STATUS => {
                    status = val.first().copied();
                }
                TLV_CHALLENGE_STATUS => {
                    challenge_status = std::str::from_utf8(&val).ok().map(str::to_string);
                }
                TLV_REMAINING_TRIES => {
                    remaining_tries = val.first().copied();
                }
                TLV_REMAINING_TIME => {
                    if val.len() >= 4 {
                        remaining_time_secs =
                            Some(u32::from_be_bytes(val[..4].try_into().unwrap()));
                    }
                }
                TLV_ISSUED_CERT_NAME => {
                    issued_cert_name = std::str::from_utf8(&val).ok().map(str::to_string);
                }
                TLV_ERROR_CODE => {
                    error_code = val.first().copied();
                }
                TLV_ERROR_INFO => {
                    error_info = std::str::from_utf8(&val).ok().map(str::to_string);
                }
                TLV_IV => {
                    if val.len() == 12 {
                        let mut arr = [0u8; 12];
                        arr.copy_from_slice(&val);
                        iv = Some(arr);
                    }
                }
                TLV_ENCRYPTED_PAYLOAD => encrypted_payload = Some(val),
                TLV_AUTH_TAG => {
                    if val.len() == 16 {
                        let mut arr = [0u8; 16];
                        arr.copy_from_slice(&val);
                        auth_tag = Some(arr);
                    }
                }
                _ => {}
            }
        }

        Ok(Self {
            status: status
                .ok_or_else(|| CertError::InvalidRequest("missing status".into()))?,
            challenge_status,
            remaining_tries,
            remaining_time_secs,
            issued_cert_name,
            error_code,
            error_info,
            iv,
            encrypted_payload,
            auth_tag,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ca_profile_tlv_roundtrip() {
        let profile = CaProfileTlv {
            ca_prefix: "/com/acme/CA".to_string(),
            ca_info: "ACME CA".to_string(),
            ca_certificate: Bytes::from_static(b"\x01\x02\x03"),
            max_validity_secs: 86400,
            challenges: vec!["pin".to_string(), "email".to_string()],
        };
        let encoded = profile.encode();
        let decoded = CaProfileTlv::decode(encoded).unwrap();
        assert_eq!(decoded.ca_prefix, "/com/acme/CA");
        assert_eq!(decoded.ca_info, "ACME CA");
        assert_eq!(decoded.max_validity_secs, 86400);
        assert_eq!(decoded.challenges, vec!["pin", "email"]);
    }

    #[test]
    fn new_request_tlv_roundtrip() {
        let req = NewRequestTlv {
            ecdh_pub: Bytes::from(vec![0x04u8; 65]),
            cert_request: Bytes::from_static(b"cert-data"),
        };
        let encoded = req.encode();
        let decoded = NewRequestTlv::decode(encoded).unwrap();
        assert_eq!(decoded.ecdh_pub.len(), 65);
        assert_eq!(&decoded.cert_request[..], b"cert-data");
    }

    #[test]
    fn new_response_tlv_roundtrip() {
        let resp = NewResponseTlv {
            ecdh_pub: Bytes::from(vec![0x04u8; 65]),
            salt: [0xABu8; 32],
            request_id: [0x01u8; 8],
            challenges: vec!["possession".to_string()],
        };
        let encoded = resp.encode();
        let decoded = NewResponseTlv::decode(encoded).unwrap();
        assert_eq!(decoded.salt, [0xABu8; 32]);
        assert_eq!(decoded.request_id, [0x01u8; 8]);
        assert_eq!(decoded.challenges, vec!["possession"]);
    }

    #[test]
    fn challenge_response_tlv_success_roundtrip() {
        let resp = ChallengeResponseTlv {
            status: STATUS_SUCCESS,
            challenge_status: None,
            remaining_tries: None,
            remaining_time_secs: None,
            issued_cert_name: Some("/com/acme/alice/KEY/v=0".to_string()),
            error_code: None,
            error_info: None,
            iv: None,
            encrypted_payload: None,
            auth_tag: None,
        };
        let encoded = resp.encode();
        let decoded = ChallengeResponseTlv::decode(encoded).unwrap();
        assert_eq!(decoded.status, STATUS_SUCCESS);
        assert_eq!(
            decoded.issued_cert_name.as_deref(),
            Some("/com/acme/alice/KEY/v=0")
        );
    }
}
