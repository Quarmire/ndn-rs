//! NDNCERT v0.3 TLV wire codec. Type assignments per the NDNCERT v0.3 spec
//! (named-data/ndncert wiki, "NDNCERT-Protocol-0.3"); ref impl is
//! `named-data/ndncert` (`ndncert-ca-server` / `ndncert-client`).

use bytes::Bytes;
use ndn_packet::Name;
use ndn_tlv::{TlvReader, TlvWriter};

use crate::error::CertError;

const TLV_NAME: u64 = 0x07;

/// `IssuedCertName` / `ForwardingHint` carry a nested Name TLV (0x07)
/// inside the outer TLV value (ref: ndncert challenge-encoder.cpp:43).
fn encode_name_value(uri: &str) -> Result<Vec<u8>, CertError> {
    let name: Name = uri
        .parse()
        .map_err(|_| CertError::InvalidRequest(format!("invalid name uri: {uri}")))?;
    let mut w = TlvWriter::new();
    w.write_nested(TLV_NAME, |w| {
        for comp in name.components() {
            w.write_tlv(comp.typ, &comp.value);
        }
    });
    Ok(w.finish().to_vec())
}

/// Parse a nested Name TLV from the value bytes of an outer TLV.
fn decode_name_value(val: &[u8]) -> Result<String, CertError> {
    let mut r = TlvReader::new(Bytes::copy_from_slice(val));
    let (typ, name_val) = r
        .read_tlv()
        .map_err(|e| CertError::InvalidRequest(format!("nested Name TLV: {e}")))?;
    if typ != TLV_NAME {
        return Err(CertError::InvalidRequest(format!(
            "expected Name TLV (0x07), got 0x{typ:X}"
        )));
    }
    let name = Name::decode(name_val)
        .map_err(|e| CertError::InvalidRequest(format!("Name decode: {e}")))?;
    Ok(name.to_string())
}

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

/// CHALLENGE parameter codec — NDNCERT v0.3 §2.4.3. Non-string JSON values
/// are written as compact JSON text so they round-trip.
pub fn encode_challenge_parameters(
    parameters: &serde_json::Map<String, serde_json::Value>,
) -> Vec<u8> {
    let mut w = TlvWriter::new();
    for (key, value) in parameters {
        w.write_tlv(TLV_PARAMETER_KEY, key.as_bytes());
        let value_bytes: Vec<u8> = match value {
            serde_json::Value::String(s) => s.as_bytes().to_vec(),
            other => other.to_string().into_bytes(),
        };
        w.write_tlv(TLV_PARAMETER_VALUE, &value_bytes);
    }
    w.finish().to_vec()
}

/// ParameterValue bytes are interpreted as UTF-8 (no current NDNCERT
/// challenge defines binary parameter values).
pub fn decode_challenge_parameters(
    bytes: &[u8],
) -> Result<serde_json::Map<String, serde_json::Value>, CertError> {
    let mut reader = TlvReader::new(bytes::Bytes::copy_from_slice(bytes));
    let mut out = serde_json::Map::new();
    while !reader.is_empty() {
        let (key_typ, key_val) = reader
            .read_tlv()
            .map_err(|_| CertError::InvalidRequest("malformed CHALLENGE plaintext".into()))?;
        if key_typ != TLV_PARAMETER_KEY {
            return Err(CertError::InvalidRequest(format!(
                "expected ParameterKey (0x{TLV_PARAMETER_KEY:x}), got 0x{key_typ:x}"
            )));
        }
        let key = std::str::from_utf8(&key_val)
            .map_err(|_| CertError::InvalidRequest("ParameterKey not UTF-8".into()))?
            .to_string();

        let (val_typ, val_val) = reader
            .read_tlv()
            .map_err(|_| CertError::InvalidRequest("ParameterKey without ParameterValue".into()))?;
        if val_typ != TLV_PARAMETER_VALUE {
            return Err(CertError::InvalidRequest(format!(
                "expected ParameterValue (0x{TLV_PARAMETER_VALUE:x}), got 0x{val_typ:x}"
            )));
        }
        let value = std::str::from_utf8(&val_val)
            .map_err(|_| CertError::InvalidRequest("ParameterValue not UTF-8".into()))?
            .to_string();

        out.insert(key, serde_json::Value::String(value));
    }
    Ok(out)
}

#[cfg(test)]
mod challenge_parameter_tests {
    use super::*;

    #[test]
    fn challenge_parameters_roundtrip_strings() {
        let mut params = serde_json::Map::new();
        params.insert("code".into(), serde_json::Value::String("ABC123".into()));
        params.insert("email".into(), serde_json::Value::String("a@b.com".into()));

        let wire = encode_challenge_parameters(&params);
        assert_eq!(wire.first().copied(), Some(0x85));

        let recovered = decode_challenge_parameters(&wire).unwrap();
        assert_eq!(recovered, params);
    }

    #[test]
    fn challenge_parameters_decode_rejects_unpaired_key() {
        let mut w = TlvWriter::new();
        w.write_tlv(TLV_PARAMETER_KEY, b"orphan");
        let wire = w.finish();
        assert!(decode_challenge_parameters(&wire).is_err());
    }

    #[test]
    fn challenge_parameters_decode_rejects_non_parameter_tlv() {
        let mut w = TlvWriter::new();
        w.write_tlv(TLV_CA_PREFIX, b"not-a-parameter");
        let wire = w.finish();
        assert!(decode_challenge_parameters(&wire).is_err());
    }
}

/// Content of the `/<ca>/CA/INFO` Data packet.
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
                            .map_err(|_| {
                                CertError::InvalidRequest("invalid ca-prefix UTF-8".into())
                            })?
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
                TLV_MAX_VALIDITY if val.len() >= 8 => {
                    max_validity_secs = u64::from_be_bytes(val[..8].try_into().unwrap());
                }
                TLV_CHALLENGE => {
                    let s = std::str::from_utf8(&val)
                        .map_err(|_| CertError::InvalidRequest("invalid challenge UTF-8".into()))?
                        .to_string();
                    challenges.push(s);
                }
                _ => {}
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

/// ApplicationParameters of `/<ca>/CA/NEW`. `ecdh_pub` is an uncompressed
/// P-256 point (65 bytes); `cert_request` is the requester's self-signed cert.
pub struct NewRequestTlv {
    pub ecdh_pub: Bytes,
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

pub struct NewResponseTlv {
    /// CA's ECDH ephemeral public key (65 bytes).
    pub ecdh_pub: Bytes,
    /// HKDF salt.
    pub salt: [u8; 32],
    pub request_id: [u8; 8],
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
        let mut error_code: Option<u64> = None;
        let mut error_info: Option<String> = None;

        while !r.is_empty() {
            let (typ, val) = r
                .read_tlv()
                .map_err(|e| CertError::InvalidRequest(format!("TLV parse error: {e}")))?;
            match typ {
                TLV_ECDH_PUB => ecdh_pub = Some(val),
                TLV_SALT if val.len() == 32 => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&val);
                    salt = Some(arr);
                }
                TLV_REQUEST_ID if val.len() == 8 => {
                    let mut arr = [0u8; 8];
                    arr.copy_from_slice(&val);
                    request_id = Some(arr);
                }
                TLV_CHALLENGE => {
                    if let Ok(s) = std::str::from_utf8(&val) {
                        challenges.push(s.to_string());
                    }
                }
                TLV_ERROR_CODE => {
                    error_code = Some(match val.len() {
                        1 => val[0] as u64,
                        2 => u16::from_be_bytes([val[0], val[1]]) as u64,
                        4 => u32::from_be_bytes([val[0], val[1], val[2], val[3]]) as u64,
                        8 => u64::from_be_bytes([
                            val[0], val[1], val[2], val[3], val[4], val[5], val[6], val[7],
                        ]),
                        _ => 0,
                    });
                }
                TLV_ERROR_INFO => {
                    error_info = std::str::from_utf8(&val).ok().map(str::to_string);
                }
                _ => {}
            }
        }

        if error_code.is_some() || error_info.is_some() {
            let msg = format!(
                "CA rejected NEW request (code {}): {}",
                error_code.unwrap_or(0),
                error_info.as_deref().unwrap_or("(no info)")
            );
            return Err(CertError::ChallengeFailed(msg));
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

/// AES-GCM-128 envelope `{IV (0x9D), AuthTag (0xAF), EncryptedPayload (0x9F)}`
/// used for both the CHALLENGE Interest's ApplicationParameters and the
/// CHALLENGE Data's Content (ref: ndncert crypto-helpers.cpp:406-409).
pub struct ChallengeRequestTlv {
    pub iv: [u8; 12],
    pub auth_tag: [u8; 16],
    pub encrypted_payload: Bytes,
}

impl ChallengeRequestTlv {
    pub fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_tlv(TLV_IV, &self.iv);
        w.write_tlv(TLV_AUTH_TAG, &self.auth_tag);
        w.write_tlv(TLV_ENCRYPTED_PAYLOAD, &self.encrypted_payload);
        w.finish()
    }

    pub fn decode(buf: Bytes) -> Result<Self, CertError> {
        let mut r = TlvReader::new(buf);
        let mut iv = None;
        let mut auth_tag = None;
        let mut encrypted_payload = None;

        while !r.is_empty() {
            let (typ, val) = r
                .read_tlv()
                .map_err(|e| CertError::InvalidRequest(format!("TLV parse error: {e}")))?;
            match typ {
                TLV_IV if val.len() == 12 => {
                    let mut arr = [0u8; 12];
                    arr.copy_from_slice(&val);
                    iv = Some(arr);
                }
                TLV_AUTH_TAG if val.len() == 16 => {
                    let mut arr = [0u8; 16];
                    arr.copy_from_slice(&val);
                    auth_tag = Some(arr);
                }
                TLV_ENCRYPTED_PAYLOAD => encrypted_payload = Some(val),
                _ => {}
            }
        }

        Ok(Self {
            iv: iv.ok_or_else(|| CertError::InvalidRequest("missing iv".into()))?,
            auth_tag: auth_tag
                .ok_or_else(|| CertError::InvalidRequest("missing auth-tag".into()))?,
            encrypted_payload: encrypted_payload
                .ok_or_else(|| CertError::InvalidRequest("missing encrypted-payload".into()))?,
        })
    }
}

/// Plaintext layout: `SelectedChallenge (0xA1)` then ParameterKey/Value pairs
/// (ref: ndncert challenge-pin.cpp:115-130, ca-module.cpp:417).
pub fn decode_challenge_plaintext(
    plaintext: &[u8],
) -> Result<(String, serde_json::Map<String, serde_json::Value>), CertError> {
    let mut reader = TlvReader::new(bytes::Bytes::copy_from_slice(plaintext));
    let mut challenge_type = None;
    let mut params = serde_json::Map::new();

    while !reader.is_empty() {
        let (typ, val) = reader
            .read_tlv()
            .map_err(|_| CertError::InvalidRequest("malformed CHALLENGE plaintext".into()))?;
        match typ {
            TLV_SELECTED_CHALLENGE => {
                challenge_type = Some(
                    std::str::from_utf8(&val)
                        .map_err(|_| {
                            CertError::InvalidRequest("SelectedChallenge not UTF-8".into())
                        })?
                        .to_string(),
                );
            }
            TLV_PARAMETER_KEY => {
                let key = std::str::from_utf8(&val)
                    .map_err(|_| CertError::InvalidRequest("ParameterKey not UTF-8".into()))?
                    .to_string();
                let (val_typ, val_val) = reader.read_tlv().map_err(|_| {
                    CertError::InvalidRequest("ParameterKey without ParameterValue".into())
                })?;
                if val_typ != TLV_PARAMETER_VALUE {
                    return Err(CertError::InvalidRequest(format!(
                        "expected ParameterValue (0x{TLV_PARAMETER_VALUE:x}), got 0x{val_typ:x}"
                    )));
                }
                let value = std::str::from_utf8(&val_val)
                    .map_err(|_| CertError::InvalidRequest("ParameterValue not UTF-8".into()))?
                    .to_string();
                params.insert(key, serde_json::Value::String(value));
            }
            _ => {}
        }
    }

    let challenge_type = challenge_type.ok_or_else(|| {
        CertError::InvalidRequest("CHALLENGE plaintext missing SelectedChallenge".into())
    })?;
    Ok((challenge_type, params))
}

/// CHALLENGE response plaintext, sealed by the CA via
/// [`crate::ecdh::SessionKey::seal_envelope`] (ref: ndncert
/// challenge-encoder.cpp:25-46).
pub struct ChallengeResponseTlv {
    /// Per NDNCERT v0.3 §3.3.
    pub status: u8,
    pub challenge_status: Option<String>,
    pub remaining_tries: Option<u8>,
    pub remaining_time_secs: Option<u32>,
    /// NDN URI string; the client fetches the cert separately.
    pub issued_cert_name: Option<String>,
    pub error_code: Option<u8>,
    pub error_info: Option<String>,
}

/// NDNCERT v0.3 status codes.
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
        if let Some(ref cn) = self.issued_cert_name
            && let Ok(name_tlv) = encode_name_value(cn)
        {
            w.write_tlv(TLV_ISSUED_CERT_NAME, &name_tlv);
        }
        if let Some(ec) = self.error_code {
            w.write_tlv(TLV_ERROR_CODE, &[ec]);
        }
        if let Some(ref ei) = self.error_info {
            w.write_tlv(TLV_ERROR_INFO, ei.as_bytes());
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
                TLV_REMAINING_TIME if val.len() >= 4 => {
                    remaining_time_secs = Some(u32::from_be_bytes(val[..4].try_into().unwrap()));
                }
                TLV_ISSUED_CERT_NAME => {
                    issued_cert_name = decode_name_value(&val).ok();
                }
                TLV_ERROR_CODE => {
                    error_code = val.first().copied();
                }
                TLV_ERROR_INFO => {
                    error_info = std::str::from_utf8(&val).ok().map(str::to_string);
                }
                _ => {}
            }
        }

        Ok(Self {
            status: status.ok_or_else(|| CertError::InvalidRequest("missing status".into()))?,
            challenge_status,
            remaining_tries,
            remaining_time_secs,
            issued_cert_name,
            error_code,
            error_info,
        })
    }
}

/// Content of the `/<ca>/CA/PROBE` Data packet.
pub struct ProbeResponseTlv {
    pub allowed: bool,
    pub reason: Option<String>,
    pub max_suffix_length: Option<u8>,
}

impl ProbeResponseTlv {
    pub fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_tlv(TLV_STATUS, &[if self.allowed { 1u8 } else { 0u8 }]);
        if let Some(ref reason) = self.reason {
            w.write_tlv(TLV_ERROR_INFO, reason.as_bytes());
        }
        if let Some(msl) = self.max_suffix_length {
            w.write_tlv(TLV_MAX_SUFFIX_LENGTH, &[msl]);
        }
        w.finish()
    }

    pub fn decode(buf: Bytes) -> Result<Self, CertError> {
        let mut r = TlvReader::new(buf);
        let mut allowed = None;
        let mut reason = None;
        let mut max_suffix_length = None;

        while !r.is_empty() {
            let (typ, val) = r
                .read_tlv()
                .map_err(|e| CertError::InvalidRequest(format!("TLV parse error: {e}")))?;
            match typ {
                TLV_STATUS => {
                    allowed = val.first().map(|&b| b != 0);
                }
                TLV_ERROR_INFO => {
                    reason = std::str::from_utf8(&val).ok().map(str::to_string);
                }
                TLV_MAX_SUFFIX_LENGTH => {
                    max_suffix_length = val.first().copied();
                }
                _ => {}
            }
        }

        Ok(Self {
            allowed: allowed.unwrap_or(false),
            reason,
            max_suffix_length,
        })
    }
}

/// ApplicationParameters of `/<ca>/CA/REVOKE`.
pub struct RevokeRequestTlv {
    pub cert_name: String,
    /// Ed25519 signature of `cert_name` bytes (possession proof).
    pub signature: Bytes,
}

pub const REVOKE_STATUS_REVOKED: u8 = 0;
pub const REVOKE_STATUS_NOT_FOUND: u8 = 1;
pub const REVOKE_STATUS_UNAUTHORIZED: u8 = 2;

impl RevokeRequestTlv {
    pub fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_tlv(TLV_ISSUED_CERT_NAME, self.cert_name.as_bytes());
        w.write_tlv(TLV_AUTH_TAG, &self.signature);
        w.finish()
    }

    pub fn decode(buf: Bytes) -> Result<Self, CertError> {
        let mut r = TlvReader::new(buf);
        let mut cert_name = None;
        let mut signature = None;

        while !r.is_empty() {
            let (typ, val) = r
                .read_tlv()
                .map_err(|e| CertError::InvalidRequest(format!("TLV parse error: {e}")))?;
            match typ {
                TLV_ISSUED_CERT_NAME => {
                    cert_name = Some(
                        std::str::from_utf8(&val)
                            .map_err(|_| {
                                CertError::InvalidRequest("invalid cert-name UTF-8".into())
                            })?
                            .to_string(),
                    );
                }
                TLV_AUTH_TAG => {
                    signature = Some(val);
                }
                _ => {}
            }
        }

        Ok(Self {
            cert_name: cert_name
                .ok_or_else(|| CertError::InvalidRequest("missing cert-name".into()))?,
            signature: signature
                .ok_or_else(|| CertError::InvalidRequest("missing signature".into()))?,
        })
    }
}

pub struct RevokeResponseTlv {
    /// One of the `REVOKE_STATUS_*` constants.
    pub status: u8,
    pub reason: Option<String>,
}

impl RevokeResponseTlv {
    pub fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_tlv(TLV_STATUS, &[self.status]);
        if let Some(ref reason) = self.reason {
            w.write_tlv(TLV_ERROR_INFO, reason.as_bytes());
        }
        w.finish()
    }

    pub fn decode(buf: Bytes) -> Result<Self, CertError> {
        let mut r = TlvReader::new(buf);
        let mut status = None;
        let mut reason = None;

        while !r.is_empty() {
            let (typ, val) = r
                .read_tlv()
                .map_err(|e| CertError::InvalidRequest(format!("TLV parse error: {e}")))?;
            match typ {
                TLV_STATUS => {
                    status = val.first().copied();
                }
                TLV_ERROR_INFO => {
                    reason = std::str::from_utf8(&val).ok().map(str::to_string);
                }
                _ => {}
            }
        }

        Ok(Self {
            status: status.ok_or_else(|| CertError::InvalidRequest("missing status".into()))?,
            reason,
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
        };
        let encoded = resp.encode();
        let decoded = ChallengeResponseTlv::decode(encoded).unwrap();
        assert_eq!(decoded.status, STATUS_SUCCESS);
        assert_eq!(
            decoded.issued_cert_name.as_deref(),
            Some("/com/acme/alice/KEY/v=0")
        );
    }

    #[test]
    fn challenge_request_tlv_envelope_roundtrip() {
        let tlv = ChallengeRequestTlv {
            iv: [0x11u8; 12],
            auth_tag: [0x22u8; 16],
            encrypted_payload: Bytes::from_static(b"ciphertext"),
        };
        let encoded = tlv.encode();
        let decoded = ChallengeRequestTlv::decode(encoded).unwrap();
        assert_eq!(decoded.iv, [0x11u8; 12]);
        assert_eq!(decoded.auth_tag, [0x22u8; 16]);
        assert_eq!(&decoded.encrypted_payload[..], b"ciphertext");
    }

    #[test]
    fn decode_challenge_plaintext_extracts_type_and_params() {
        use super::encode_challenge_parameters;
        let mut params = serde_json::Map::new();
        params.insert("code".into(), serde_json::Value::String("ABC123".into()));
        let param_bytes = encode_challenge_parameters(&params);

        let mut w = TlvWriter::new();
        w.write_tlv(TLV_SELECTED_CHALLENGE, b"pin");
        w.write_raw(&param_bytes);
        let plaintext = w.finish();

        let (ctype, recovered) = decode_challenge_plaintext(&plaintext).unwrap();
        assert_eq!(ctype, "pin");
        assert_eq!(
            recovered.get("code").and_then(|v| v.as_str()),
            Some("ABC123")
        );
    }
}
