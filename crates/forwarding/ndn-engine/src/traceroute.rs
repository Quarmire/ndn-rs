//! Forwarder-side **traceroute hop responder** (G9 per-hop identity).
//!
//! NDN forwarders drop a hop-limited Interest silently and don't self-identify, so
//! `ndn-traceroute` can measure distance but not name each hop. This opt-in responder
//! closes that: when an Interest *marked as a trace probe* would be dropped because its
//! `HopLimit` reached 0 at this node, the node instead answers with its own name — the
//! NDN analogue of IP's TTL-exceeded ICMP.
//!
//! The reply is a Data named exactly like the probe, so it satisfies the consumer's
//! pending Interest, and is sent back out the **in-face**: this node has no PIT entry for
//! the probe (it never forwarded it), but the upstream hop that forwarded the probe does,
//! so the reply walks back along that trail to the consumer. Ramping the probe's `HopLimit`
//! therefore draws each successive hop's identity until the producer itself answers.
//!
//! Identity here is **advisory** (digest-signed, like IP traceroute is unauthenticated) —
//! it aids diagnosis, it is not a trust statement. Opt-in: a node without a responder keeps
//! dropping hop-limited probes silently.

use bytes::Bytes;
use ndn_packet::encode::DataBuilder;
use ndn_packet::{Name, NameComponent};

/// Keyword name component (`32=TRH`) marking an Interest as a traceroute probe whose hop
/// limit expiry should draw a hop-identity reply (vs a normal silent drop).
pub const TRACEROUTE_KEYWORD: &[u8] = b"TRH";

/// Magic prefix on a hop-identity reply's Content, so the prober tells an intermediate
/// hop's identity reply apart from the destination producer's own answer.
pub const HOP_IDENTITY_MAGIC: &[u8] = b"\xF0HOP";

/// Whether `name` carries the traceroute probe marker (`32=TRH`).
pub fn is_trace_probe(name: &Name) -> bool {
    let kw_typ = NameComponent::keyword(Bytes::new()).typ;
    name.components()
        .iter()
        .any(|c| c.typ == kw_typ && c.value.as_ref() == TRACEROUTE_KEYWORD)
}

/// Build the hop-identity reply for `probe_name` from this `node_name`: a Data named like
/// the probe (so it satisfies the consumer) whose Content is `HOP_IDENTITY_MAGIC` followed
/// by the node's name URI. Digest-signed (advisory).
pub fn identity_reply(probe_name: &Name, node_name: &Name) -> Bytes {
    let mut content = Vec::with_capacity(HOP_IDENTITY_MAGIC.len() + 64);
    content.extend_from_slice(HOP_IDENTITY_MAGIC);
    content.extend_from_slice(node_name.to_string().as_bytes());
    DataBuilder::new(probe_name.clone(), &content).sign_digest_sha256()
}

/// Parse a hop-identity reply's Content back to the responding node's name. `None` if the
/// magic prefix is absent (i.e. it's the destination producer's own answer, not a hop).
pub fn parse_identity(content: &[u8]) -> Option<Name> {
    let rest = content.strip_prefix(HOP_IDENTITY_MAGIC)?;
    std::str::from_utf8(rest).ok()?.parse().ok()
}

/// An opt-in hop responder: this node's name, used to answer marked trace probes whose
/// hop limit expires here. Installed via
/// [`EngineBuilder::with_traceroute_responder`](crate::EngineBuilder::with_traceroute_responder).
#[derive(Clone, Debug)]
pub struct TracerouteResponder {
    pub node_name: Name,
}

impl TracerouteResponder {
    pub fn new(node_name: Name) -> Self {
        Self { node_name }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_packet::encode::InterestBuilder;

    #[test]
    fn marker_detected_and_identity_round_trips() {
        let probe: Name = "/svc/ping/7".parse().unwrap();
        let marked = probe
            .clone()
            .append_component(NameComponent::keyword(Bytes::from_static(TRACEROUTE_KEYWORD)));
        assert!(is_trace_probe(&marked));
        assert!(!is_trace_probe(&probe), "an unmarked probe is a normal drop");

        // A built marked Interest is recognized after a wire round-trip.
        let wire = InterestBuilder::new(marked.clone()).hop_limit(1).build();
        let decoded = ndn_packet::Interest::decode(wire).unwrap();
        assert!(is_trace_probe(&decoded.name));

        let node: Name = "/router/edge-1".parse().unwrap();
        let reply = identity_reply(&marked, &node);
        let data = ndn_packet::Data::decode(reply).unwrap();
        assert_eq!(*data.name, marked, "reply satisfies the probe name");
        let content = data.content().expect("reply has content");
        assert_eq!(parse_identity(content), Some(node), "node identity recovered");
        // The producer's own answer (no magic) is not mistaken for a hop.
        assert!(parse_identity(b"\x00\x00\x00\x05").is_none());
    }
}
