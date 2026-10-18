//! The `links/list` dataset (`/localhost/nfd/links/list`): this device's QUIC
//! links, the paths that reach each linked device, and the state of each
//! device's direct path. The host daemon encodes it from the link library's
//! report; `ndn-ctl link list` decodes it through here.

use alloc::string::String;
use alloc::vec::Vec;
use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_tlv::{TlvReader, TlvWriter};

use crate::{DecodeError, nni_bytes, read_nni};

/// `links/list` TLV-TYPE codes.
///
/// An ndn-rs extension (no NFD analogue) in the application range
/// 0x04A0–0x04BF, clear of the trust context (0x0410–0x041F), the link
/// messages (0x0450–0x046F) and the trust envelope (0x0470–0x049F). All
/// codes are even (non-critical): a decoder skips the ones it does not know.
pub mod link_tlv {
    /// 32 bytes, a link key fingerprint: at the top level this device's, in
    /// a [`LINK`] the linked device's.
    pub const KEY: u64 = 0x04A0;
    /// NonNegativeInteger, top level.
    pub const PROBES_SENT: u64 = 0x04A2;
    /// NonNegativeInteger, top level.
    pub const PUNCHES_REFUSED: u64 = 0x04A4;
    /// Nested entry, one per linked device.
    pub const LINK: u64 = 0x04A6;
    /// UTF-8 string.
    pub const LABEL: u64 = 0x04A8;
    /// The device name's components (a Name TLV's value), optional.
    pub const DEVICE: u64 = 0x04AA;
    /// Nested entry in a [`LINK`], one per path.
    pub const PATH: u64 = 0x04AC;
    /// UTF-8 string: `direct`, `link` or `relay`.
    pub const PATH_KIND: u64 = 0x04AE;
    /// NonNegativeInteger.
    pub const FACE_ID: u64 = 0x04B0;
    /// UTF-8 string `ip:port`, optional.
    pub const REMOTE: u64 = 0x04B2;
    /// NonNegativeInteger, microseconds, optional.
    pub const RTT_MICROS: u64 = 0x04B4;
    /// NonNegativeInteger, seconds.
    pub const AGE_SECS: u64 = 0x04B6;
    /// UTF-8 string, optional: the relay's label.
    pub const VIA: u64 = 0x04B8;
    /// UTF-8 string: `none`, `off`, `trying`, `up`, `not-possible` or
    /// `refused`.
    pub const DIRECT_STATE: u64 = 0x04BA;
    /// UTF-8 string, optional: why, and what to do if anything.
    pub const DIRECT_TEXT: u64 = 0x04BC;
    /// NonNegativeInteger, seconds, optional: when the next punch is due.
    pub const RETRY_IN_SECS: u64 = 0x04BE;
}

/// The `links/list` answer.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LinkListing {
    /// The fingerprint of the key this device links with now.
    pub key: Option<[u8; 32]>,
    /// Probe datagrams sent for direct-path punches, in total.
    pub probes_sent: u64,
    /// Punch requests this device refused, in total.
    pub punches_refused: u64,
    pub links: Vec<LinkEntry>,
}

/// One device this device links with (or is configured to, or punched with).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LinkEntry {
    /// Its peer entry's label, else its device name, else its key.
    pub label: String,
    /// Its key fingerprint, once known.
    pub key: Option<[u8; 32]>,
    /// Its device name, once known.
    pub device: Option<Name>,
    /// The ways it is reached now; empty when it is not.
    pub paths: Vec<LinkPathEntry>,
    /// `none`, `off`, `trying`, `up`, `not-possible` or `refused`.
    pub direct_state: String,
    /// Why, for a person (empty when there is nothing to say).
    pub direct_text: String,
    /// When the next punch is due.
    pub retry_in_secs: Option<u64>,
}

/// One path to a device.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LinkPathEntry {
    /// `direct`, `link` or `relay`.
    pub kind: String,
    /// The face carrying it (for a relay path, the relay's link face).
    pub face_id: u64,
    /// The address the QUIC connection reaches, `ip:port`.
    pub remote: Option<String>,
    /// The connection's round-trip time estimate.
    pub rtt_micros: Option<u64>,
    /// How long it has been up.
    pub age_secs: u64,
    /// For a relay path: the relay's label.
    pub via: Option<String>,
}

fn write_nni(w: &mut TlvWriter, typ: u64, v: u64) {
    let (b, n) = nni_bytes(v);
    w.write_tlv(typ, &b[..n]);
}

fn write_text(w: &mut TlvWriter, typ: u64, s: &str) {
    if !s.is_empty() {
        w.write_tlv(typ, s.as_bytes());
    }
}

fn nni(v: &[u8]) -> Result<u64, DecodeError> {
    read_nni(v).ok_or(DecodeError::Malformed)
}

fn text(v: &[u8]) -> Result<String, DecodeError> {
    String::from_utf8(v.to_vec()).map_err(|_| DecodeError::Malformed)
}

fn key(v: &[u8]) -> Result<[u8; 32], DecodeError> {
    v.try_into().map_err(|_| DecodeError::Malformed)
}

/// The TLVs in `bytes`, refusing a malformed one.
fn tlvs(bytes: Bytes) -> impl Iterator<Item = Result<(u64, Bytes), DecodeError>> {
    let mut reader = TlvReader::new(bytes);
    core::iter::from_fn(move || {
        (!reader.is_empty()).then(|| reader.read_tlv().map_err(|_| DecodeError::Malformed))
    })
}

impl LinkListing {
    /// Encode into the `links/list` dataset body. Empty and absent optional
    /// fields are omitted.
    pub fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        if let Some(k) = &self.key {
            w.write_tlv(link_tlv::KEY, k);
        }
        write_nni(&mut w, link_tlv::PROBES_SENT, self.probes_sent);
        write_nni(&mut w, link_tlv::PUNCHES_REFUSED, self.punches_refused);
        for link in &self.links {
            w.write_nested(link_tlv::LINK, |w| link.encode_into(w));
        }
        w.finish()
    }

    /// Decode the dataset body. Unknown TLVs are skipped (evolvability); a
    /// malformed TLV, or an entry missing a required field, is an error.
    pub fn decode(bytes: Bytes) -> Result<LinkListing, DecodeError> {
        let mut out = LinkListing::default();
        for tlv in tlvs(bytes) {
            let (typ, v) = tlv?;
            match typ {
                link_tlv::KEY => out.key = Some(key(&v)?),
                link_tlv::PROBES_SENT => out.probes_sent = nni(&v)?,
                link_tlv::PUNCHES_REFUSED => out.punches_refused = nni(&v)?,
                link_tlv::LINK => out.links.push(LinkEntry::decode(v)?),
                _ => {}
            }
        }
        Ok(out)
    }
}

impl LinkEntry {
    fn encode_into(&self, w: &mut TlvWriter) {
        w.write_tlv(link_tlv::LABEL, self.label.as_bytes());
        if let Some(k) = &self.key {
            w.write_tlv(link_tlv::KEY, k);
        }
        if let Some(device) = &self.device {
            w.write_nested(link_tlv::DEVICE, |w| {
                for c in device.components() {
                    w.write_tlv(c.typ, &c.value);
                }
            });
        }
        for path in &self.paths {
            w.write_nested(link_tlv::PATH, |w| path.encode_into(w));
        }
        w.write_tlv(link_tlv::DIRECT_STATE, self.direct_state.as_bytes());
        write_text(w, link_tlv::DIRECT_TEXT, &self.direct_text);
        if let Some(s) = self.retry_in_secs {
            write_nni(w, link_tlv::RETRY_IN_SECS, s);
        }
    }

    fn decode(bytes: Bytes) -> Result<LinkEntry, DecodeError> {
        let mut out = LinkEntry::default();
        let (mut label, mut state) = (false, false);
        for tlv in tlvs(bytes) {
            let (typ, v) = tlv?;
            match typ {
                link_tlv::LABEL => {
                    out.label = text(&v)?;
                    label = true;
                }
                link_tlv::KEY => out.key = Some(key(&v)?),
                link_tlv::DEVICE => {
                    out.device = Some(Name::decode(v).map_err(|_| DecodeError::Malformed)?)
                }
                link_tlv::PATH => out.paths.push(LinkPathEntry::decode(v)?),
                link_tlv::DIRECT_STATE => {
                    out.direct_state = text(&v)?;
                    state = true;
                }
                link_tlv::DIRECT_TEXT => out.direct_text = text(&v)?,
                link_tlv::RETRY_IN_SECS => out.retry_in_secs = Some(nni(&v)?),
                _ => {}
            }
        }
        if !label {
            return Err(DecodeError::MissingField(link_tlv::LABEL));
        }
        if !state {
            return Err(DecodeError::MissingField(link_tlv::DIRECT_STATE));
        }
        Ok(out)
    }
}

impl LinkPathEntry {
    fn encode_into(&self, w: &mut TlvWriter) {
        w.write_tlv(link_tlv::PATH_KIND, self.kind.as_bytes());
        write_nni(w, link_tlv::FACE_ID, self.face_id);
        if let Some(r) = &self.remote {
            w.write_tlv(link_tlv::REMOTE, r.as_bytes());
        }
        if let Some(rtt) = self.rtt_micros {
            write_nni(w, link_tlv::RTT_MICROS, rtt);
        }
        write_nni(w, link_tlv::AGE_SECS, self.age_secs);
        if let Some(via) = &self.via {
            w.write_tlv(link_tlv::VIA, via.as_bytes());
        }
    }

    fn decode(bytes: Bytes) -> Result<LinkPathEntry, DecodeError> {
        let mut out = LinkPathEntry::default();
        let (mut kind, mut face) = (false, false);
        for tlv in tlvs(bytes) {
            let (typ, v) = tlv?;
            match typ {
                link_tlv::PATH_KIND => {
                    out.kind = text(&v)?;
                    kind = true;
                }
                link_tlv::FACE_ID => {
                    out.face_id = nni(&v)?;
                    face = true;
                }
                link_tlv::REMOTE => out.remote = Some(text(&v)?),
                link_tlv::RTT_MICROS => out.rtt_micros = Some(nni(&v)?),
                link_tlv::AGE_SECS => out.age_secs = nni(&v)?,
                link_tlv::VIA => out.via = Some(text(&v)?),
                _ => {}
            }
        }
        if !kind {
            return Err(DecodeError::MissingField(link_tlv::PATH_KIND));
        }
        if !face {
            return Err(DecodeError::MissingField(link_tlv::FACE_ID));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn link_listing_round_trips() {
        let listing = LinkListing {
            key: Some([0xab; 32]),
            probes_sent: 40,
            punches_refused: 1,
            links: vec![
                LinkEntry {
                    label: "phone".into(),
                    key: Some([0x01; 32]),
                    device: Some("/home/bob/node/phone".parse().unwrap()),
                    paths: vec![
                        LinkPathEntry {
                            kind: "direct".into(),
                            face_id: 7,
                            remote: Some("203.0.113.5:6367".into()),
                            rtt_micros: Some(12_345),
                            age_secs: 90,
                            via: None,
                        },
                        LinkPathEntry {
                            kind: "relay".into(),
                            face_id: 3,
                            remote: Some("[2001:db8::1]:6367".into()),
                            rtt_micros: None,
                            age_secs: 3_600,
                            via: Some("vps".into()),
                        },
                    ],
                    direct_state: "up".into(),
                    direct_text: String::new(),
                    retry_in_secs: None,
                },
                LinkEntry {
                    label: "laptop".into(),
                    direct_state: "not-possible".into(),
                    direct_text: "no probe came back".into(),
                    retry_in_secs: Some(20),
                    ..Default::default()
                },
            ],
        };
        assert_eq!(LinkListing::decode(listing.encode()).unwrap(), listing);
        assert_eq!(
            LinkListing::decode(LinkListing::default().encode()).unwrap(),
            LinkListing::default()
        );
    }

    #[test]
    fn link_entry_without_label_is_refused() {
        let mut w = TlvWriter::new();
        w.write_nested(link_tlv::LINK, |w| {
            w.write_tlv(link_tlv::DIRECT_STATE, b"none");
        });
        assert_eq!(
            LinkListing::decode(w.finish()),
            Err(DecodeError::MissingField(link_tlv::LABEL))
        );
    }
}
