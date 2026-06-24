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

/// NDN `ParametersSha256DigestComponent` TLV-TYPE (0x02) — the trailing name component a
/// signed Interest appends; [`PathControl::parse`] anchors the marker relative to it.
const PARAMS_SHA256_TYPE: u64 = 0x02;

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
    /// `32=PC` keyword component is absent or the op/seq are malformed.
    ///
    /// The marker is **position-anchored**: it must be the third-from-last component
    /// (`…/PC/op/seq`), or the fourth-from-last when a signed Interest has appended a
    /// trailing `ParametersSha256DigestComponent` (`…/PC/op/seq/Params`). This prevents an
    /// ordinary application Interest that merely happens to carry a `32=PC` keyword
    /// component somewhere in its name from being mis-intercepted as in-transit control
    /// (a namespace-collision / control-DoS vector if the scan were unanchored).
    pub fn parse(name: &Name) -> Option<Self> {
        let comps = name.components();
        let n = comps.len();
        let is_pc = |c: &NameComponent| {
            c.typ == NameComponent::keyword(Bytes::new()).typ && c.value.as_ref() == PATHCTL_KEYWORD
        };
        // Anchor: PC at n-3 (unsigned `to_name`), or n-4 with a trailing
        // ParametersSha256DigestComponent (TLV-TYPE 0x02) as the last component (signed).
        let kw = if n >= 3 && is_pc(&comps[n - 3]) {
            n - 3
        } else if n >= 4 && is_pc(&comps[n - 4]) && comps[n - 1].typ == PARAMS_SHA256_TYPE {
            n - 4
        } else {
            return None;
        };
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

/// Per-`(target, op)` last-seen sequence number — the **loop and staleness guard**. A
/// PathControl is admitted (and forwarded onward) only if its `seq` is strictly newer
/// than the last admitted one for the same `(target, op)`; a not-newer message has already
/// been processed (a loop, a duplicate, or a stale move) and is dropped. This is what
/// makes the path-walk terminate and survive concurrent/rapid moves.
///
/// The key includes the **op**, not just the target: independent mechanisms emit on the
/// same prefix with independent sequence schemes (MAP-Me `Redirect` uses a per-emitter
/// counter; pipe `Teardown` uses a wall-clock seq). Sharing one sequence space per target
/// would let whichever ran first jam the other's later messages as "stale". Keying by
/// `(target, op)` gives each op its own monotonic space so they can coexist on one name.
#[derive(Default)]
pub struct SeqStore {
    seen: dashmap::DashMap<(Name, u8), u64>,
}

impl SeqStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Admit `seq` for `(target, op)` iff it is strictly newer than the last admitted one,
    /// recording it. Returns `true` to process+forward, `false` to drop.
    pub fn admit(&self, target: &Name, op: PathOp, seq: u64) -> bool {
        use dashmap::mapref::entry::Entry;
        match self.seen.entry((target.clone(), op as u8)) {
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

    /// The last admitted sequence number for `(target, op)`, if any (diagnostics).
    pub fn last(&self, target: &Name, op: PathOp) -> Option<u64> {
        self.seen.get(&(target.clone(), op as u8)).map(|r| *r)
    }
}

/// Signed-emitter side (feature `sign`): build the signed PathControl Interest a
/// producer (mobility) or a pipe endpoint (lifecycle) sends out its face.
#[cfg(feature = "sign")]
pub mod emit {
    use crate::{PathControl, PathOp};
    use bytes::Bytes;
    use ndn_foundation_types::Name;
    use ndn_packet::encode::InterestBuilder;
    use ndn_security::{SignWith, Signer, TrustError};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Emits signed PathControl messages for one `target`, with a monotonic per-emitter
    /// sequence number. Hold one per moving prefix / live pipe; on a point-of-attachment
    /// change (mobility) or a close/keepalive (pipe), call the matching method and send
    /// the returned Interest wire out your (new) face — the network walks and applies it.
    pub struct PathControlEmitter {
        target: Name,
        signer: Arc<dyn Signer>,
        seq: AtomicU64,
    }

    impl PathControlEmitter {
        pub fn new(target: Name, signer: Arc<dyn Signer>) -> Self {
            Self {
                target,
                signer,
                seq: AtomicU64::new(0),
            }
        }

        /// Build a signed message for `op` with the next sequence number. The signature
        /// (the producer's key, over the name that carries op+seq) is what authorizes
        /// the in-transit state mutation at each forwarder.
        pub fn emit(&self, op: PathOp) -> Result<Bytes, TrustError> {
            let seq = self.seq.fetch_add(1, Ordering::Relaxed) + 1;
            let pc = PathControl::new(self.target.clone(), op, seq);
            InterestBuilder::new(pc.to_name())
                .app_parameters(Vec::new())
                .sign_with_sync(self.signer.as_ref())
        }

        /// MAP-Me Interest Update — emit on a point-of-attachment change.
        pub fn redirect(&self) -> Result<Bytes, TrustError> {
            self.emit(PathOp::Redirect)
        }
        /// Tear down the pipe/session along its path.
        pub fn teardown(&self) -> Result<Bytes, TrustError> {
            self.emit(PathOp::Teardown)
        }
        /// Extend the pipe/session soft state (keepalive).
        pub fn refresh(&self) -> Result<Bytes, TrustError> {
            self.emit(PathOp::Refresh)
        }

        /// The last sequence number emitted.
        pub fn current_seq(&self) -> u64 {
            self.seq.load(Ordering::Relaxed)
        }
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

    #[cfg(feature = "sign")]
    #[test]
    fn emitter_builds_parseable_signed_messages_with_rising_seq() {
        use crate::emit::PathControlEmitter;
        use ndn_security::signer::Ed25519Signer;
        use std::sync::Arc;

        let signer = Ed25519Signer::from_seed(&[3u8; 32], n("/alice/KEY/k1"));
        let em = PathControlEmitter::new(n("/alice/video"), Arc::new(signer));

        let wire = em.redirect().expect("emit redirect");
        let interest = ndn_packet::Interest::decode(wire).expect("decode");
        assert!(interest.sig_info().is_some(), "the IU must be signed");
        let pc = PathControl::parse(&interest.name).expect("parse emitted IU");
        assert_eq!(pc.target, n("/alice/video"));
        assert_eq!(pc.op, PathOp::Redirect);
        assert_eq!(pc.seq, 1);

        // Sequence rises per emit; ops map correctly.
        let teardown = em.teardown().unwrap();
        let pc2 = PathControl::parse(&ndn_packet::Interest::decode(teardown).unwrap().name).unwrap();
        assert_eq!(pc2.op, PathOp::Teardown);
        assert_eq!(pc2.seq, 2);
    }

    #[test]
    fn seq_store_admits_only_newer() {
        let store = SeqStore::new();
        let t = n("/alice/video");
        let r = PathOp::Redirect;
        assert!(store.admit(&t, r, 5), "first is admitted");
        assert!(!store.admit(&t, r, 5), "equal is a duplicate/loop — dropped");
        assert!(!store.admit(&t, r, 3), "older is stale — dropped");
        assert!(store.admit(&t, r, 6), "newer is admitted");
        assert_eq!(store.last(&t, r), Some(6));
        // Independent per target.
        let t2 = n("/bob/pipe");
        assert!(store.admit(&t2, r, 1));
    }

    #[test]
    fn seq_store_keys_by_op_not_just_target() {
        // MAP-Me (Redirect, counter) and pipe (Teardown, wall-clock) share a name but
        // must not jam each other: each op has its own monotonic space.
        let store = SeqStore::new();
        let t = n("/site/thing");
        assert!(store.admit(&t, PathOp::Teardown, 1_700_000_000_000), "wall-clock teardown");
        assert!(store.admit(&t, PathOp::Redirect, 5), "small Redirect seq still admitted");
        assert!(store.admit(&t, PathOp::Redirect, 6));
        assert!(!store.admit(&t, PathOp::Teardown, 1_699_999_999_999), "older teardown dropped");
    }
}
