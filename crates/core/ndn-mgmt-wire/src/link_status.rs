//! The `links/list` dataset (`/localhost/nfd/links/list`): this device's QUIC
//! links, the paths that reach each linked device, and the state of each
//! device's direct path. The host daemon encodes it from the link library's
//! report; `ndn-ctl link list` decodes it through here.

use alloc::string::String;
use alloc::vec::Vec;
use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_tlv::{TlvReader, TlvWriter};

use crate::{ControlParameters, DecodeError, nni_bytes, read_nni};

/// `links/list` TLV-TYPE codes.
///
/// An ndn-rs extension (no NFD analogue) in the application range
/// 0x04A0–0x04DF, clear of the trust context (0x0410–0x042F), the link
/// messages (0x0440–0x046F) and the trust envelope (0x0470–0x049F). All
/// codes are even (non-critical): a decoder skips the ones it does not know.
/// A code's meaning depends on the entry it sits in (`KEY`, `HELD` and
/// `WAKES` appear at the top level and nested).
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
    /// UTF-8 string in a [`LINK`], optional: `always`, `on-demand` or `off`.
    pub const MODE: u64 = 0x04C0;
    /// NonNegativeInteger, seconds, in a [`LINK`] with mode `on-demand`:
    /// the idle close.
    pub const IDLE_SECS: u64 = 0x04C2;
    /// Nested in a [`LINK`], optional: the link is to a relay this device uses.
    pub const RELAY: u64 = 0x04C4;
    /// UTF-8 string in a [`RELAY`]: `user` or `namespace:<namespace>`.
    pub const RELAY_SOURCE: u64 = 0x04C6;
    /// NonNegativeInteger in a [`RELAY`]: lower is preferred.
    pub const PREFERENCE: u64 = 0x04C8;
    /// UTF-8 string in a [`RELAY`]: `linked`, `trying`, `down`, `standby`
    /// or `off`.
    pub const RELAY_STATE: u64 = 0x04CA;
    /// UTF-8 string in a [`RELAY`], optional: why, and what to do if
    /// anything.
    pub const RELAY_TEXT: u64 = 0x04CC;
    /// Nested in a [`LINK`], optional (relay side): the device is asleep here.
    pub const ASLEEP: u64 = 0x04CE;
    /// NonNegativeInteger, seconds, in an [`ASLEEP`]: how long it has been.
    pub const SINCE_SECS: u64 = 0x04D0;
    /// NonNegativeInteger: Interests held — in an [`ASLEEP`] for that device,
    /// at the top level for all.
    pub const HELD: u64 = 0x04D2;
    /// Empty, in an [`ASLEEP`]: the device asked for its Interests to be held.
    pub const HOLD: u64 = 0x04D4;
    /// Empty, in an [`ASLEEP`]: the device registered a wake token.
    pub const WAKE: u64 = 0x04D6;
    /// NonNegativeInteger: wakes sent — in an [`ASLEEP`] to that device, at
    /// the top level to all.
    pub const WAKES: u64 = 0x04D8;
    /// UTF-8 string in a [`LINK`], optional: why a configured device is not
    /// linked now.
    pub const DOWN: u64 = 0x04DA;
    /// UTF-8 string, top level, optional: this device's relay serving policy.
    pub const SERVE: u64 = 0x04DC;
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
    /// This device's relay serving policy, one line (empty: not reported).
    pub serve: String,
    /// Interests this device holds for sleeping devices now, in total.
    pub held_total: u64,
    /// Wakes this device has sent, in total.
    pub wakes_sent: u64,
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
    /// `always`, `on-demand` or `off`, for a configured link.
    pub mode: Option<String>,
    /// With mode `on-demand`: the idle close, in seconds.
    pub idle_secs: Option<u64>,
    /// Set when the device is a relay this device uses.
    pub relay: Option<LinkRelayEntry>,
    /// Set (relay side) when the device is asleep here.
    pub asleep: Option<LinkAsleepEntry>,
    /// Why a configured device is not linked now.
    pub down: Option<String>,
}

/// A relay this device uses.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LinkRelayEntry {
    /// `user` or `namespace:<namespace>`.
    pub source: String,
    /// Lower is preferred.
    pub preference: u64,
    /// `linked`, `trying`, `down`, `standby` or `off`.
    pub state: String,
    /// Why, for a person (empty when there is nothing to say).
    pub text: String,
}

/// A device asleep at this relay.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LinkAsleepEntry {
    /// How long it has been asleep.
    pub since_secs: u64,
    /// Interests held for it now.
    pub held: u64,
    /// It asked for its Interests to be held.
    pub hold: bool,
    /// It registered a wake token.
    pub wake: bool,
    /// Wakes sent to it.
    pub wakes: u64,
}

/// A link mode as `links/mode` carries it (in `ControlParameters.local_uri`,
/// the link's label in `uri`) and `ndn-ctl link mode` takes it: `always`,
/// `on-demand`, `on-demand:<idle seconds>` or `off`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkModeArg {
    Always,
    /// `idle_secs = None`: keep the link's current (or configured) idle close.
    OnDemand { idle_secs: Option<u64> },
    Off,
}

impl core::str::FromStr for LinkModeArg {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "always" => Ok(Self::Always),
            "on-demand" => Ok(Self::OnDemand { idle_secs: None }),
            "off" => Ok(Self::Off),
            _ => match s.strip_prefix("on-demand:").map(str::parse::<u64>) {
                Some(Ok(secs)) => Ok(Self::OnDemand { idle_secs: Some(secs) }),
                _ => Err(alloc::format!(
                    "{s:?} is not a link mode: use always, on-demand, on-demand:<idle seconds> \
                     (e.g. on-demand:60) or off"
                )),
            },
        }
    }
}

impl core::fmt::Display for LinkModeArg {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Always => f.write_str("always"),
            Self::OnDemand { idle_secs: None } => f.write_str("on-demand"),
            Self::OnDemand { idle_secs: Some(s) } => write!(f, "on-demand:{s}"),
            Self::Off => f.write_str("off"),
        }
    }
}

/// The parameters of a `links/connect`, `links/disconnect` or (with `mode`)
/// `links/mode` command for the link labelled `label`.
pub fn link_command(label: &str, mode: Option<LinkModeArg>) -> ControlParameters {
    ControlParameters {
        uri: Some(label.into()),
        local_uri: mode.map(|m| alloc::string::ToString::to_string(&m)),
        ..Default::default()
    }
}

/// The label (and, if carried, the mode) of a links command; the error says
/// what is missing.
pub fn parse_link_command(
    params: &ControlParameters,
) -> Result<(String, Option<LinkModeArg>), String> {
    let label = params
        .uri
        .clone()
        .filter(|l| !l.is_empty())
        .ok_or_else(|| String::from("name the link (its label in `ndn-ctl link list`) in Uri"))?;
    let mode = params.local_uri.as_deref().map(str::parse).transpose()?;
    Ok((label, mode))
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
        write_text(&mut w, link_tlv::SERVE, &self.serve);
        write_nni(&mut w, link_tlv::HELD, self.held_total);
        write_nni(&mut w, link_tlv::WAKES, self.wakes_sent);
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
                link_tlv::SERVE => out.serve = text(&v)?,
                link_tlv::HELD => out.held_total = nni(&v)?,
                link_tlv::WAKES => out.wakes_sent = nni(&v)?,
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
        if let Some(mode) = &self.mode {
            w.write_tlv(link_tlv::MODE, mode.as_bytes());
        }
        if let Some(s) = self.idle_secs {
            write_nni(w, link_tlv::IDLE_SECS, s);
        }
        if let Some(relay) = &self.relay {
            w.write_nested(link_tlv::RELAY, |w| relay.encode_into(w));
        }
        if let Some(asleep) = &self.asleep {
            w.write_nested(link_tlv::ASLEEP, |w| asleep.encode_into(w));
        }
        if let Some(down) = &self.down {
            w.write_tlv(link_tlv::DOWN, down.as_bytes());
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
                link_tlv::MODE => out.mode = Some(text(&v)?),
                link_tlv::IDLE_SECS => out.idle_secs = Some(nni(&v)?),
                link_tlv::RELAY => out.relay = Some(LinkRelayEntry::decode(v)?),
                link_tlv::ASLEEP => out.asleep = Some(LinkAsleepEntry::decode(v)?),
                link_tlv::DOWN => out.down = Some(text(&v)?),
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

impl LinkRelayEntry {
    fn encode_into(&self, w: &mut TlvWriter) {
        w.write_tlv(link_tlv::RELAY_SOURCE, self.source.as_bytes());
        write_nni(w, link_tlv::PREFERENCE, self.preference);
        w.write_tlv(link_tlv::RELAY_STATE, self.state.as_bytes());
        write_text(w, link_tlv::RELAY_TEXT, &self.text);
    }

    fn decode(bytes: Bytes) -> Result<LinkRelayEntry, DecodeError> {
        let mut out = LinkRelayEntry::default();
        let (mut source, mut state) = (false, false);
        for tlv in tlvs(bytes) {
            let (typ, v) = tlv?;
            match typ {
                link_tlv::RELAY_SOURCE => {
                    out.source = text(&v)?;
                    source = true;
                }
                link_tlv::PREFERENCE => out.preference = nni(&v)?,
                link_tlv::RELAY_STATE => {
                    out.state = text(&v)?;
                    state = true;
                }
                link_tlv::RELAY_TEXT => out.text = text(&v)?,
                _ => {}
            }
        }
        if !source {
            return Err(DecodeError::MissingField(link_tlv::RELAY_SOURCE));
        }
        if !state {
            return Err(DecodeError::MissingField(link_tlv::RELAY_STATE));
        }
        Ok(out)
    }
}

impl LinkAsleepEntry {
    fn encode_into(&self, w: &mut TlvWriter) {
        write_nni(w, link_tlv::SINCE_SECS, self.since_secs);
        write_nni(w, link_tlv::HELD, self.held);
        if self.hold {
            w.write_tlv(link_tlv::HOLD, &[]);
        }
        if self.wake {
            w.write_tlv(link_tlv::WAKE, &[]);
        }
        write_nni(w, link_tlv::WAKES, self.wakes);
    }

    fn decode(bytes: Bytes) -> Result<LinkAsleepEntry, DecodeError> {
        let mut out = LinkAsleepEntry::default();
        for tlv in tlvs(bytes) {
            let (typ, v) = tlv?;
            match typ {
                link_tlv::SINCE_SECS => out.since_secs = nni(&v)?,
                link_tlv::HELD => out.held = nni(&v)?,
                link_tlv::HOLD => out.hold = true,
                link_tlv::WAKE => out.wake = true,
                link_tlv::WAKES => out.wakes = nni(&v)?,
                _ => {}
            }
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
                    mode: Some("on-demand".into()),
                    idle_secs: Some(60),
                    relay: None,
                    asleep: Some(LinkAsleepEntry {
                        since_secs: 300,
                        held: 4,
                        hold: true,
                        wake: true,
                        wakes: 2,
                    }),
                    down: None,
                },
                LinkEntry {
                    label: "laptop".into(),
                    direct_state: "not-possible".into(),
                    direct_text: "no probe came back".into(),
                    retry_in_secs: Some(20),
                    down: Some("off: links when asked".into()),
                    ..Default::default()
                },
                LinkEntry {
                    label: "/home/node/vps".into(),
                    direct_state: "none".into(),
                    mode: Some("always".into()),
                    relay: Some(LinkRelayEntry {
                        source: "namespace:/home".into(),
                        preference: 0,
                        state: "standby".into(),
                        text: "a preferred relay is linked".into(),
                    }),
                    ..Default::default()
                },
            ],
            serve: "listed: 2 namespaces, quotas 256 links".into(),
            held_total: 4,
            wakes_sent: 2,
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

    #[test]
    fn link_commands_carry_label_and_mode() {
        for mode in [
            LinkModeArg::Always,
            LinkModeArg::OnDemand { idle_secs: None },
            LinkModeArg::OnDemand { idle_secs: Some(120) },
            LinkModeArg::Off,
        ] {
            let params = ControlParameters::decode(link_command("vps", Some(mode)).encode()).unwrap();
            assert_eq!(parse_link_command(&params), Ok(("vps".into(), Some(mode))));
        }
        let params = link_command("vps", None);
        assert_eq!(parse_link_command(&params), Ok(("vps".into(), None)));
        assert!("sometimes".parse::<LinkModeArg>().unwrap_err().contains("on-demand:<idle seconds>"));
        assert!(parse_link_command(&ControlParameters::default()).is_err());
    }
}
