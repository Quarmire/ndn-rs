//! SWIM direct and indirect liveness probe packets.
//!
//! SWIM probes use standard NDN Interest/Data so they traverse the normal
//! forwarding pipeline.  The PIT handles rendezvous for indirect probes — no
//! special routing is needed.
//!
//! ## Packet formats
//!
//! **Direct probe** (node A → node B):
//! ```text
//! Interest: /ndn/local/nd/probe/direct/<B-name>/<nonce-u32>
//! ```
//!
//! **Indirect probe** (node A asks node C to probe node B):
//! ```text
//! Interest: /ndn/local/nd/probe/via/<C-name>/<B-name>/<nonce-u32>
//! ```
//!
//! **Probe ACK** (node B or C → node A via PIT reverse path):
//! ```text
//! Data: same name as the Interest
//!       Content: empty (the ACK is the Data itself)
//! ```
//!
//! ## Usage pattern
//!
//! 1. A detects B is `STALE`; sends `build_direct_probe(b, nonce)` on B's face.
//! 2. If no ACK within `probe_timeout`, A sends
//!    `build_indirect_probe(c, b, nonce)` for K randomly chosen intermediaries.
//! 3. Only if all K indirect probes time out does A declare B `ABSENT`.
//!
//! The SWIM fanout K is set by [`DiscoveryConfig::swim_indirect_fanout`].
//! K = 0 disables indirect probing entirely (use [`BackoffScheduler`] instead).
//!
//! [`DiscoveryConfig::swim_indirect_fanout`]: crate::config::DiscoveryConfig::swim_indirect_fanout
//! [`BackoffScheduler`]: crate::strategy::BackoffScheduler

use bytes::Bytes;
use ndn_packet::{Name, tlv_type};
use ndn_tlv::TlvWriter;

use crate::scope::{probe_direct, probe_via};
use crate::wire::{parse_raw_data, parse_raw_interest, write_name_tlv, write_nni};

// ─── Packet builders ──────────────────────────────────────────────────────────

/// Build a direct probe Interest.
///
/// Name: `/ndn/local/nd/probe/direct/<target>/<nonce>`
pub fn build_direct_probe(target: &Name, nonce: u32) -> Bytes {
    let mut w = TlvWriter::new();
    w.write_nested(tlv_type::INTEREST, |w: &mut TlvWriter| {
        w.write_nested(tlv_type::NAME, |w: &mut TlvWriter| {
            for comp in probe_direct().components() {
                w.write_tlv(comp.typ, &comp.value);
            }
            for comp in target.components() {
                w.write_tlv(comp.typ, &comp.value);
            }
            w.write_tlv(tlv_type::NAME_COMPONENT, &nonce.to_be_bytes());
        });
        w.write_tlv(tlv_type::NONCE, &nonce.to_be_bytes());
        write_nni(w, tlv_type::INTEREST_LIFETIME, 2000);
    });
    w.finish()
}

/// Build an indirect probe Interest.
///
/// Name: `/ndn/local/nd/probe/via/<intermediary>/<target>/<nonce>`
///
/// The intermediary receives this Interest, looks up the target in its FIB, and
/// forwards a direct probe on the caller's behalf.
pub fn build_indirect_probe(intermediary: &Name, target: &Name, nonce: u32) -> Bytes {
    let mut w = TlvWriter::new();
    w.write_nested(tlv_type::INTEREST, |w: &mut TlvWriter| {
        w.write_nested(tlv_type::NAME, |w: &mut TlvWriter| {
            for comp in probe_via().components() {
                w.write_tlv(comp.typ, &comp.value);
            }
            for comp in intermediary.components() {
                w.write_tlv(comp.typ, &comp.value);
            }
            for comp in target.components() {
                w.write_tlv(comp.typ, &comp.value);
            }
            w.write_tlv(tlv_type::NAME_COMPONENT, &nonce.to_be_bytes());
        });
        w.write_tlv(tlv_type::NONCE, &nonce.to_be_bytes());
        write_nni(w, tlv_type::INTEREST_LIFETIME, 4000);
    });
    w.finish()
}

/// Build a probe ACK Data packet.
///
/// The name is echoed verbatim from the Interest; content is empty.
pub fn build_probe_ack(interest_name: &Name) -> Bytes {
    let mut w = TlvWriter::new();
    w.write_nested(tlv_type::DATA, |w: &mut TlvWriter| {
        write_name_tlv(w, interest_name);
        w.write_nested(tlv_type::META_INFO, |w: &mut TlvWriter| {
            write_nni(w, tlv_type::FRESHNESS_PERIOD, 0);
        });
        // Empty content — the ACK is the Data itself.
        w.write_tlv(tlv_type::CONTENT, &[]);
        w.write_nested(tlv_type::SIGNATURE_INFO, |w: &mut TlvWriter| {
            w.write_tlv(tlv_type::SIGNATURE_TYPE, &[0u8]);
        });
        w.write_tlv(tlv_type::SIGNATURE_VALUE, &[0u8; 32]);
    });
    w.finish()
}

// ─── Packet parsers ───────────────────────────────────────────────────────────

/// Parse a direct probe Interest name.
///
/// Returns `(target_name, nonce)` if the name matches
/// `/ndn/local/nd/probe/direct/<target...>/<nonce>`, `None` otherwise.
pub fn parse_direct_probe(raw: &Bytes) -> Option<DirectProbe> {
    let parsed = parse_raw_interest(raw)?;
    let name = &parsed.name;
    let prefix = probe_direct();

    if !name.has_prefix(prefix) {
        return None;
    }

    let comps = name.components();
    let prefix_len = prefix.components().len();

    // At minimum: prefix + 1 target component + nonce = prefix_len + 2
    if comps.len() < prefix_len + 2 {
        return None;
    }

    let nonce_comp = &comps[comps.len() - 1];
    if nonce_comp.value.len() != 4 {
        return None;
    }
    let nonce = u32::from_be_bytes(nonce_comp.value[..4].try_into().ok()?);

    // Target name = all components between prefix and nonce.
    let target_comps = &comps[prefix_len..comps.len() - 1];
    let target = Name::from_components(target_comps.iter().cloned());

    Some(DirectProbe { target, nonce })
}

/// Parse an indirect probe Interest name.
///
/// Returns `(intermediary_name, target_name, nonce)` if the name matches
/// `/ndn/local/nd/probe/via/<intermediary...>/<target...>/<nonce>`.
///
/// **Encoding convention**: the intermediary name length is encoded as a
/// single `NameComponent` carrying a 1-byte count before the intermediary
/// components.  This is the same convention used by NFD for parameterised
/// Interest names — the length is explicit so there is no ambiguity between
/// the end of the intermediary and the start of the target.
///
/// Format: `probe/via/<n:u8>/<intermediary×n>/<target...>/<nonce>`
pub fn parse_indirect_probe(raw: &Bytes) -> Option<IndirectProbe> {
    let parsed = parse_raw_interest(raw)?;
    let name = &parsed.name;
    let prefix = probe_via();

    if !name.has_prefix(prefix) {
        return None;
    }

    let comps = name.components();
    let prefix_len = prefix.components().len();

    // Need at least: prefix + length-byte + 1 intermediary + 1 target + nonce
    if comps.len() < prefix_len + 4 {
        return None;
    }

    // First component after prefix: intermediary component count.
    let count_comp = &comps[prefix_len];
    if count_comp.value.len() != 1 {
        return None;
    }
    let intermediary_len = count_comp.value[0] as usize;

    let inter_start = prefix_len + 1;
    let inter_end = inter_start + intermediary_len;
    let target_end = comps.len() - 1; // last is nonce

    if inter_end >= target_end {
        return None; // target would be empty or overlap nonce
    }

    let nonce_comp = &comps[comps.len() - 1];
    if nonce_comp.value.len() != 4 {
        return None;
    }
    let nonce = u32::from_be_bytes(nonce_comp.value[..4].try_into().ok()?);

    let intermediary = Name::from_components(comps[inter_start..inter_end].iter().cloned());
    let target = Name::from_components(comps[inter_end..target_end].iter().cloned());

    Some(IndirectProbe { intermediary, target, nonce })
}

/// Build an indirect probe with the length-prefix encoding.
///
/// Encodes: `probe/via/<intermediary-len:u8>/<intermediary...>/<target...>/<nonce>`
pub fn build_indirect_probe_encoded(intermediary: &Name, target: &Name, nonce: u32) -> Bytes {
    let inter_len = intermediary.components().len();
    assert!(inter_len <= 255, "intermediary name too long");

    let mut w = TlvWriter::new();
    w.write_nested(tlv_type::INTEREST, |w: &mut TlvWriter| {
        w.write_nested(tlv_type::NAME, |w: &mut TlvWriter| {
            for comp in probe_via().components() {
                w.write_tlv(comp.typ, &comp.value);
            }
            // Length prefix.
            w.write_tlv(tlv_type::NAME_COMPONENT, &[inter_len as u8]);
            for comp in intermediary.components() {
                w.write_tlv(comp.typ, &comp.value);
            }
            for comp in target.components() {
                w.write_tlv(comp.typ, &comp.value);
            }
            w.write_tlv(tlv_type::NAME_COMPONENT, &nonce.to_be_bytes());
        });
        w.write_tlv(tlv_type::NONCE, &nonce.to_be_bytes());
        write_nni(w, tlv_type::INTEREST_LIFETIME, 4000);
    });
    w.finish()
}

/// Parsed fields from a direct probe Interest.
#[derive(Debug, Clone)]
pub struct DirectProbe {
    pub target: Name,
    pub nonce: u32,
}

/// Parsed fields from an indirect probe Interest.
#[derive(Debug, Clone)]
pub struct IndirectProbe {
    pub intermediary: Name,
    pub target: Name,
    pub nonce: u32,
}

/// Check whether the raw packet is a probe ACK Data (empty-content reply).
pub fn is_probe_ack(raw: &Bytes) -> bool {
    let Some(parsed) = parse_raw_data(raw) else { return false };
    let name = &parsed.name;
    name.has_prefix(probe_direct()) || name.has_prefix(probe_via())
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    fn n(s: &str) -> Name { Name::from_str(s).unwrap() }

    #[test]
    fn direct_probe_roundtrip() {
        let target = n("/ndn/site/nodeB");
        let nonce = 0xABCD_1234;
        let pkt = build_direct_probe(&target, nonce);

        let parsed = parse_direct_probe(&pkt).unwrap();
        assert_eq!(parsed.target, target);
        assert_eq!(parsed.nonce, nonce);
    }

    #[test]
    fn indirect_probe_roundtrip() {
        let intermediary = n("/ndn/site/nodeC");
        let target = n("/ndn/site/nodeB");
        let nonce = 0xDEAD_BEEF;
        let pkt = build_indirect_probe_encoded(&intermediary, &target, nonce);

        let parsed = parse_indirect_probe(&pkt).unwrap();
        assert_eq!(parsed.intermediary, intermediary);
        assert_eq!(parsed.target, target);
        assert_eq!(parsed.nonce, nonce);
    }

    #[test]
    fn probe_ack_is_detected() {
        let probe_name = n("/ndn/local/nd/probe/direct/ndn/site/nodeB/00000001");
        let ack = build_probe_ack(&probe_name);
        assert!(is_probe_ack(&ack));
    }

    #[test]
    fn direct_probe_rejects_wrong_prefix() {
        let other = build_indirect_probe_encoded(&n("/ndn/site/c"), &n("/ndn/site/b"), 1);
        // parse_direct_probe should reject a via-prefix packet
        assert!(parse_direct_probe(&other).is_none());
    }
}
