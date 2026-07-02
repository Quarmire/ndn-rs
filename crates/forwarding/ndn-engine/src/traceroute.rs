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
//!
//! ## Security: topology disclosure (deployment note)
//!
//! A node with a responder installed **discloses its name to any unauthenticated prober** —
//! a marked hop-limited Interest from anyone draws this node's identity, so a walk of
//! ramping hop limits maps the path's node names (the same exposure IP traceroute has). Two
//! mitigations are built in: (1) it is **opt-in** (no responder ⇒ silent drop, as before),
//! and (2) the probe marker is **position-anchored** (below), so an ordinary application
//! Interest that merely contains a `32=TRH` component somewhere is *not* mistaken for a
//! probe and answered. Operators who treat their topology as sensitive should leave the
//! responder off on edge/untrusted-facing nodes, or gate it (e.g. only enable it inside an
//! administrative trust zone).

use bytes::Bytes;
use ndn_packet::encode::DataBuilder;
use ndn_packet::{Name, NameComponent};

/// Keyword name component (`32=TRH`) marking an Interest as a traceroute probe whose hop
/// limit expiry should draw a hop-identity reply (vs a normal silent drop). The wire value
/// is the shared [`ndn_packet::traceroute_wire`] constant (single source of truth across
/// the responder and the `ndn-traceroute` prober — G9.3).
pub use ndn_packet::traceroute_wire::{HOP_IDENTITY_MAGIC, TRACEROUTE_KEYWORD};

/// TLV-TYPE of a `ParametersSha256DigestComponent` — the only component that legitimately
/// trails the marker on a *signed* probe.
const PARAMS_SHA256_TYPE: u64 = 0x02;

/// Whether `name` carries the traceroute probe marker (`32=TRH`) **in the anchored
/// position**: the last component, or the second-to-last when the last is a
/// ParametersSha256Digest (a signed probe). Anchoring (rather than matching the keyword
/// anywhere) stops an ordinary application Interest that happens to contain a `32=TRH`
/// component from being intercepted and answered as a probe.
pub fn is_trace_probe(name: &Name) -> bool {
    let kw_typ = NameComponent::keyword(Bytes::new()).typ;
    let comps = name.components();
    let is_marker = |c: &NameComponent| c.typ == kw_typ && c.value.as_ref() == TRACEROUTE_KEYWORD;
    let n = comps.len();
    if n >= 1 && is_marker(&comps[n - 1]) {
        return true;
    }
    // Signed probe: marker immediately before the ParametersSha256Digest tail.
    n >= 2 && comps[n - 1].typ == PARAMS_SHA256_TYPE && is_marker(&comps[n - 2])
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
            .append_component(NameComponent::keyword(Bytes::from_static(
                TRACEROUTE_KEYWORD,
            )));
        assert!(is_trace_probe(&marked));
        assert!(
            !is_trace_probe(&probe),
            "an unmarked probe is a normal drop"
        );

        // Anchored: a `32=TRH` component buried mid-name (an ordinary app Interest that
        // merely contains the keyword) is NOT treated as a probe.
        let buried = probe
            .clone()
            .append_component(NameComponent::keyword(Bytes::from_static(
                TRACEROUTE_KEYWORD,
            )))
            .append("more")
            .append("components");
        assert!(
            !is_trace_probe(&buried),
            "a non-tail TRH marker must not match"
        );

        // A signed probe (marker immediately before a ParametersSha256Digest) still matches.
        let signed = marked.clone().append_component(NameComponent::new(
            PARAMS_SHA256_TYPE,
            Bytes::from_static(&[0u8; 32]),
        ));
        assert!(
            is_trace_probe(&signed),
            "marker before the params tail matches"
        );

        // A built marked Interest is recognized after a wire round-trip.
        let wire = InterestBuilder::new(marked.clone()).hop_limit(1).build();
        let decoded = ndn_packet::Interest::decode(wire).unwrap();
        assert!(is_trace_probe(&decoded.name));

        let node: Name = "/router/edge-1".parse().unwrap();
        let reply = identity_reply(&marked, &node);
        let data = ndn_packet::Data::decode(reply).unwrap();
        assert_eq!(*data.name, marked, "reply satisfies the probe name");
        let content = data.content().expect("reply has content");
        assert_eq!(
            parse_identity(content),
            Some(node),
            "node identity recovered"
        );
        // The producer's own answer (no magic) is not mistaken for a hop.
        assert!(parse_identity(b"\x00\x00\x00\x05").is_none());
    }
}
