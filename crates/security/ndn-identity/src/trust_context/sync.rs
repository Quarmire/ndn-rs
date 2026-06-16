//! [`SyncBundle`] — what a sibling device needs to mirror the verify-only
//! side of a [`TrustContext`]. Phase 2's `ndn-sync::context_sync` module rides
//! this payload over a per-context SVS group.
//!
//! Wire shape (block `0x0420..=0x042F`, see
//! `ndn-security::trust_context::sync_tlv`):
//!
//! ```text
//! TC_SYNC_BUNDLE ( 0x0420 )
//!   Name (0x07)                        — context_name
//!   AnchorSet (0x0411)                 — reuses the TrustContext block
//!     Data (0x06) ...
//!   TrustSchemaBlob (0x0413)           — reuses the TrustContext block
//!   TC_SYNC_CA_ENDPOINT_DELTA (0x0424) — repeatable
//!     Name (0x07)
//! ```

use bytes::Bytes;
use ndn_packet::{Data, Name, tlv_type};
use ndn_security::trust_context::tlv::{ANCHOR_SET, SCHEMA_BODY, SCHEMA_FORMAT, TRUST_SCHEMA_BLOB};
use ndn_security::{Certificate, SchemaBlob, SchemaFormat, TrustSchema};
use ndn_tlv::{TlvWriter, read_varu64};

use super::sync_tlv::{TC_SYNC_BUNDLE, TC_SYNC_CA_ENDPOINT_DELTA};

#[derive(Debug, thiserror::Error)]
pub enum SyncBundleError {
    #[error("truncated bundle TLV")]
    Truncated,
    #[error("missing required field: {0}")]
    MissingField(&'static str),
    #[error("bad name: {0}")]
    BadName(String),
    #[error("bad anchor: {0}")]
    BadAnchor(String),
    #[error("unsupported schema format byte: {0}")]
    BadSchemaFormat(u8),
    #[error("schema parse: {0}")]
    SchemaParse(String),
}

#[derive(Debug, Clone)]
pub struct SyncBundle {
    pub context_name: Name,
    pub anchors: Vec<Certificate>,
    pub schema: TrustSchema,
    pub ca_endpoints: Vec<Name>,
}

impl SyncBundle {
    /// Whether this bundle carries any private-key material. Phase 1: always
    /// false — only Phase 4 introduces wrapped-key payloads. Witness
    /// `tcs07_context_sync_no_private_keys.sh` asserts this stays false on
    /// the wire for the base bundle.
    pub fn carries_private_keys(&self) -> bool {
        false
    }

    /// Encode the bundle as a single `TC_SYNC_BUNDLE` TLV. Anchors with no
    /// retained signed-region (test-only) are skipped, matching the
    /// `TrustContext` encoder in `ndn-security`.
    pub fn encode_wire(&self) -> Bytes {
        let schema_blob = derive_blob(&self.schema);
        let mut w = TlvWriter::new();
        w.write_nested(TC_SYNC_BUNDLE, |w| {
            w.write_raw(&self.context_name.encode_to_tlv());
            w.write_nested(ANCHOR_SET, |w| {
                for cert in &self.anchors {
                    if let Some(wire) = cert_to_data_wire(cert) {
                        w.write_raw(&wire);
                    }
                }
            });
            w.write_nested(TRUST_SCHEMA_BLOB, |w| {
                w.write_tlv(SCHEMA_FORMAT, &[schema_format_byte(schema_blob.format)]);
                w.write_tlv(SCHEMA_BODY, &schema_blob.body);
            });
            for ca in &self.ca_endpoints {
                w.write_tlv(TC_SYNC_CA_ENDPOINT_DELTA, &ca.encode_to_tlv());
            }
        });
        w.finish()
    }

    /// Decode the bundle from a single outer `TC_SYNC_BUNDLE` TLV.
    pub fn decode_wire(input: &[u8]) -> Result<Self, SyncBundleError> {
        let (t, value, _) = read_tlv(input)?;
        if t != TC_SYNC_BUNDLE {
            return Err(SyncBundleError::MissingField("TC_SYNC_BUNDLE"));
        }

        let mut context_name: Option<Name> = None;
        let mut anchors: Vec<Certificate> = Vec::new();
        let mut schema: Option<TrustSchema> = None;
        let mut ca_endpoints: Vec<Name> = Vec::new();

        let mut cur = value;
        while !cur.is_empty() {
            let (ft, fval, rest) = read_tlv(cur)?;
            cur = rest;
            match ft {
                tlv_type::NAME => {
                    context_name = Some(
                        Name::decode(Bytes::copy_from_slice(fval))
                            .map_err(|e| SyncBundleError::BadName(e.to_string()))?,
                    );
                }
                ANCHOR_SET => {
                    let mut acur = fval;
                    while !acur.is_empty() {
                        let (at, aval, arest) = read_tlv(acur)?;
                        acur = arest;
                        if at != tlv_type::DATA {
                            continue;
                        }
                        let mut dw = TlvWriter::new();
                        dw.write_tlv(tlv_type::DATA, aval);
                        let data = Data::decode(dw.finish())
                            .map_err(|e| SyncBundleError::BadAnchor(e.to_string()))?;
                        let cert = Certificate::decode(&data)
                            .map_err(|e| SyncBundleError::BadAnchor(e.to_string()))?;
                        anchors.push(cert);
                    }
                }
                TRUST_SCHEMA_BLOB => {
                    let mut format_byte: Option<u8> = None;
                    let mut body: Option<Bytes> = None;
                    let mut scur = fval;
                    while !scur.is_empty() {
                        let (st, sval, srest) = read_tlv(scur)?;
                        scur = srest;
                        match st {
                            SCHEMA_FORMAT => format_byte = sval.first().copied(),
                            SCHEMA_BODY => body = Some(Bytes::copy_from_slice(sval)),
                            _ => {}
                        }
                    }
                    let fmt =
                        match format_byte.ok_or(SyncBundleError::MissingField("SchemaFormat"))? {
                            1 => SchemaFormat::NativeText,
                            2 => SchemaFormat::Lvs,
                            other => return Err(SyncBundleError::BadSchemaFormat(other)),
                        };
                    let blob = SchemaBlob {
                        format: fmt,
                        body: body.ok_or(SyncBundleError::MissingField("SchemaBody"))?,
                    };
                    schema = Some(
                        decode_schema(&blob)
                            .map_err(|e| SyncBundleError::SchemaParse(e.to_string()))?,
                    );
                }
                TC_SYNC_CA_ENDPOINT_DELTA => {
                    ca_endpoints.push(
                        Name::decode_from_tlv(Bytes::copy_from_slice(fval))
                            .map_err(|e| SyncBundleError::BadName(e.to_string()))?,
                    );
                }
                _ => {}
            }
        }

        Ok(Self {
            context_name: context_name.ok_or(SyncBundleError::MissingField("Name"))?,
            anchors,
            schema: schema.ok_or(SyncBundleError::MissingField("TrustSchemaBlob"))?,
            ca_endpoints,
        })
    }
}

fn schema_format_byte(f: SchemaFormat) -> u8 {
    match f {
        SchemaFormat::NativeText => 1,
        SchemaFormat::Lvs => 2,
    }
}

fn derive_blob(schema: &TrustSchema) -> SchemaBlob {
    let text = schema
        .rules()
        .iter()
        .map(|r| r.to_string())
        .collect::<Vec<_>>()
        .join("\n");
    SchemaBlob {
        format: SchemaFormat::NativeText,
        body: Bytes::from(text.into_bytes()),
    }
}

fn decode_schema(blob: &SchemaBlob) -> Result<TrustSchema, String> {
    use ndn_security::SchemaRule;
    match blob.format {
        SchemaFormat::Lvs => TrustSchema::from_lvs_binary(&blob.body).map_err(|e| e.to_string()),
        SchemaFormat::NativeText => {
            let mut schema = TrustSchema::new();
            for line in std::str::from_utf8(&blob.body)
                .map_err(|_| "schema body not UTF-8".to_string())?
                .lines()
            {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                schema.add_rule(SchemaRule::parse(line).map_err(|e| e.to_string())?);
            }
            Ok(schema)
        }
    }
}

fn cert_to_data_wire(cert: &Certificate) -> Option<Bytes> {
    let sr = cert.signed_region.as_ref()?;
    let sv = cert.sig_value.as_ref()?;
    let mut w = TlvWriter::new();
    w.write_nested(tlv_type::DATA, |w| {
        w.write_raw(sr);
        w.write_tlv(tlv_type::SIGNATURE_VALUE, sv);
    });
    Some(w.finish())
}

fn read_tlv(input: &[u8]) -> Result<(u64, &[u8], &[u8]), SyncBundleError> {
    let (t, tn) = read_varu64(input).map_err(|_| SyncBundleError::Truncated)?;
    let (l, ln) = read_varu64(&input[tn..]).map_err(|_| SyncBundleError::Truncated)?;
    let header = tn + ln;
    let total = header
        .checked_add(l as usize)
        .ok_or(SyncBundleError::Truncated)?;
    if total > input.len() {
        return Err(SyncBundleError::Truncated);
    }
    Ok((t, &input[header..total], &input[total..]))
}
