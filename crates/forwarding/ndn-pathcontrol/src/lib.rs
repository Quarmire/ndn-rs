//! **PathControl** — a signed, sequence-numbered, loop-safe control signal that walks
//! a path mutating per-hop forwarding/session state (G3).
//!
//! It is the single primitive under two mechanisms that NDN research has historically
//! built as separate point solutions:
//! - **MAP-Me producer mobility** — the [`PathOp::Redirect`] op *is* MAP-Me's Interest
//!   Update: it walks toward a prefix's previous attachment, and each forwarder rewrites
//!   its next-hop to point back where the update arrived (a breadcrumb trail to the new
//!   location).
//! - **Pipe/session lifecycle** — [`PathOp::Teardown`] / [`PathOp::Refresh`] walk a live
//!   pipe's path to tear it down or extend its soft state.
//!
//! ## Shape on the wire
//!
//! A PathControl message is carried as a **signed Interest** named
//! `<target-prefix> / 32=PC / <op> / <seq>` (the keyword component `32=PC` marks it;
//! `op` and `seq` are the two generic components after it). Encoding `op`/`seq` *in the
//! name* puts them inside the signed region, so a forwarder that verifies the signature
//! trusts the op and sequence number as much as the target. The signature itself
//! (producer's key, verified against the prefix's trust) is what authorizes the in-transit
//! state mutation — without it this would be a prefix-hijack primitive.
//!
//! This crate is crypto-agnostic: it builds the *unsigned* name/Interest shape and parses
//! it back; signing is the caller's (`ndn-security` `SignWith`), and verification is the
//! forwarder's (`Validator`). The [`SeqStore`] provides the loop/staleness guard.

use bytes::Bytes;
use ndn_foundation_types::{Name, NameComponent};

/// Keyword component value (`32=PC`) that marks a name as a PathControl message.
pub const PATHCTL_KEYWORD: &[u8] = b"PC";

/// What a PathControl message asks each forwarder on the path to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PathOp {
    /// MAP-Me Interest Update: rewrite the next-hop for `target` toward where this
    /// arrived (the producer's new location), then propagate along the old trail.
    Redirect = 1,
    /// Tear down forwarding/session state for `target` along the path.
    Teardown = 2,
    /// Extend the soft-state lifetime for `target` along the path (keepalive).
    Refresh = 3,
}

impl PathOp {
    fn from_u8(b: u8) -> Option<Self> {
        match b {
            1 => Some(PathOp::Redirect),
            2 => Some(PathOp::Teardown),
            3 => Some(PathOp::Refresh),
            _ => None,
        }
    }
}

/// A decoded PathControl message: an op on `target` carrying a per-prefix sequence
/// number for ordering and loop prevention.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathControl {
    /// The prefix whose forwarding/session state this controls.
    pub target: Name,
    pub op: PathOp,
    /// Monotonic per-`target` sequence number — newer wins; not-newer is dropped.
    pub seq: u64,
}

impl PathControl {
    pub fn new(target: Name, op: PathOp, seq: u64) -> Self {
        Self { target, op, seq }
    }

    /// The Interest **name** for this message: `<target> / 32=PC / <op:1> / <seq:8 BE>`.
    /// Sign an Interest with this name (the op/seq ride in the signed region); the
    /// forwarder recognizes it via [`parse`](Self::parse).
    pub fn to_name(&self) -> Name {
        self.target
            .clone()
            .append_component(NameComponent::keyword(Bytes::from_static(PATHCTL_KEYWORD)))
            .append_component(NameComponent::generic(Bytes::copy_from_slice(&[self.op as u8])))
            .append_component(NameComponent::generic(Bytes::copy_from_slice(
                &self.seq.to_be_bytes(),
            )))
    }

    /// Recognize + decode a PathControl from an Interest name. Returns `None` if the
    /// `32=PC` keyword component is absent or the op/seq are malformed. Tolerates
    /// trailing components after `seq` (e.g. a signed Interest's
    /// `ParametersSha256DigestComponent`), so it parses the name *as signed*.
    pub fn parse(name: &Name) -> Option<Self> {
        let comps = name.components();
        // Find the keyword marker (type 32, value "PC").
        let kw = comps.iter().position(|c| {
            c.typ == NameComponent::keyword(Bytes::new()).typ && c.value.as_ref() == PATHCTL_KEYWORD
        })?;
        let op_comp = comps.get(kw + 1)?;
        let seq_comp = comps.get(kw + 2)?;
        // op: a single byte.
        let op = match op_comp.value.as_ref() {
            [b] => PathOp::from_u8(*b)?,
            _ => return None,
        };
        // seq: 8 big-endian bytes.
        let seq_bytes: [u8; 8] = seq_comp.value.as_ref().try_into().ok()?;
        let seq = u64::from_be_bytes(seq_bytes);
        // target: the components before the keyword.
        let target = Name::from_components(comps[..kw].iter().cloned());
        Some(Self { target, op, seq })
    }
}

/// Per-target last-seen sequence number — the **loop and staleness guard**. A
/// PathControl is admitted (and forwarded onward) only if its `seq` is strictly newer
/// than the last admitted one for the same target; a not-newer message has already
/// been processed (a loop, a duplicate, or a stale move) and is dropped. This is what
/// makes the path-walk terminate and survive concurrent/rapid moves.
#[derive(Default)]
pub struct SeqStore {
    seen: dashmap::DashMap<Name, u64>,
}

impl SeqStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Admit `seq` for `target` iff it is strictly newer than the last admitted one,
    /// recording it. Returns `true` to process+forward, `false` to drop.
    pub fn admit(&self, target: &Name, seq: u64) -> bool {
        use dashmap::mapref::entry::Entry;
        match self.seen.entry(target.clone()) {
            Entry::Occupied(mut e) => {
                if seq > *e.get() {
                    *e.get_mut() = seq;
                    true
                } else {
                    false
                }
            }
            Entry::Vacant(e) => {
                e.insert(seq);
                true
            }
        }
    }

    /// The last admitted sequence number for `target`, if any (diagnostics).
    pub fn last(&self, target: &Name) -> Option<u64> {
        self.seen.get(target).map(|r| *r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    #[test]
    fn name_round_trips_target_op_seq() {
        let pc = PathControl::new(n("/alice/video"), PathOp::Redirect, 42);
        let name = pc.to_name();
        let parsed = PathControl::parse(&name).expect("parse");
        assert_eq!(parsed, pc);
        assert_eq!(parsed.target, n("/alice/video"));
        assert_eq!(parsed.op, PathOp::Redirect);
        assert_eq!(parsed.seq, 42);
    }

    #[test]
    fn parse_tolerates_trailing_components() {
        // Simulate a signed Interest: a ParametersSha256Digest component after seq.
        let pc = PathControl::new(n("/bob/pipe"), PathOp::Teardown, 7);
        let signed_name = pc
            .to_name()
            .append_component(NameComponent::new(0x02, Bytes::from_static(&[0xAB; 32])));
        let parsed = PathControl::parse(&signed_name).expect("parse signed");
        assert_eq!(parsed, pc);
    }

    #[test]
    fn parse_rejects_non_pathcontrol_names() {
        assert!(PathControl::parse(&n("/just/a/name")).is_none());
    }

    #[test]
    fn all_ops_round_trip() {
        for op in [PathOp::Redirect, PathOp::Teardown, PathOp::Refresh] {
            let pc = PathControl::new(n("/x"), op, 1);
            assert_eq!(PathControl::parse(&pc.to_name()).unwrap().op, op);
        }
    }

    #[test]
    fn seq_store_admits_only_newer() {
        let store = SeqStore::new();
        let t = n("/alice/video");
        assert!(store.admit(&t, 5), "first is admitted");
        assert!(!store.admit(&t, 5), "equal is a duplicate/loop — dropped");
        assert!(!store.admit(&t, 3), "older is stale — dropped");
        assert!(store.admit(&t, 6), "newer is admitted");
        assert_eq!(store.last(&t), Some(6));
        // Independent per target.
        let t2 = n("/bob/pipe");
        assert!(store.admit(&t2, 1));
    }
}
